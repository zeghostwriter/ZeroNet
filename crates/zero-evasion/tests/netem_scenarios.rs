//! The privileged half of the Iran network simulator (PLAN-01 §7).
//!
//! `iran_simulation.rs` builds its censor in process: a local middlebox that
//! relays a connection and misbehaves. That is portable, deterministic and
//! fast, and there is a class of behaviour it structurally cannot produce.
//! An in-process middlebox is an *endpoint*. It cannot drop a datagram below
//! the socket layer, cannot shrink a path MTU, cannot fail one direction of an
//! established flow while the other keeps working, and cannot reset a
//! connection from outside both endpoints. Those are precisely the conditions
//! Iranian networks present, which is why the plan asks for `tc netem` and
//! `nftables` rather than an imitation of them.
//!
//! So these scenarios impair the kernel's own network stack and then assert
//! the planner's decision — not that bytes moved, which is the mistake
//! RESEARCH-01 §27 warns about, but that the evidence produced by a real
//! impairment is classified into the remedy that addresses it.
//!
//! Run them through the harness, which builds the namespace they need:
//!
//! ```bash
//! bash scripts/iran-netem-harness.sh
//! ```
//!
//! They are `#[ignore]`d otherwise. Run directly they would try to reconfigure
//! whatever network they landed on, which is not a thing a test suite should
//! do to a developer's machine — so they also refuse to run outside a
//! namespace the harness prepared.

// netem and nftables are Linux interfaces; there is nothing to conditionally
// skip on another platform, so the file simply does not exist there.
#![cfg(target_os = "linux")]

use std::io;
use std::net::SocketAddr;
use std::process::Command;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use zero_core::{Failure, FailureKind, Stage};
use zero_observatory::{AccessClass, ConnectionPlanner, PathStrategy, Transition};

/// Ports each scenario owns. Rules are written against a port rather than
/// flushed globally so a scenario cannot silently depend on — or destroy —
/// another's impairment.
mod port {
    pub const BYTE_THRESHOLD: u16 = 19101;
    pub const TIME_THRESHOLD: u16 = 19102;
    pub const ASYMMETRIC: u16 = 19103;
    pub const UDP_BLOCKED: u16 = 19104;
    pub const QUIC_BLOCKED: u16 = 19105;
    pub const DOH_RESET: u16 = 19106;
    pub const UDP_DNS_OK: u16 = 19107;
    pub const LOW_MTU: u16 = 19108;
    pub const IPV6_STALL: u16 = 19109;
    pub const THROTTLED: u16 = 19110;
    pub const CONTROL: u16 = 19111;
}

// --------------------------------------------------------------- environment

/// Refuse to run outside the namespace the harness sets up.
///
/// The check is deliberately positive evidence rather than a flag: the tests
/// confirm they are somewhere they can safely add and remove rules, instead of
/// trusting an environment variable that a stray `cargo test` could inherit.
fn require_private_namespace() {
    // A fresh network namespace has loopback and nothing else. Seeing any
    // other interface means this is a real host's network.
    let links = run("ip", &["-o", "link", "show"]).expect("ip link show");
    let names: Vec<&str> = links
        .lines()
        .filter_map(|line| line.split(':').nth(1))
        .map(str::trim)
        .collect();
    assert_eq!(
        names,
        vec!["lo"],
        "refusing to modify a network that is not a private namespace \
         (interfaces: {names:?}); run scripts/iran-netem-harness.sh"
    );
}

fn run(program: &str, args: &[&str]) -> io::Result<String> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn nft(argument: &str) {
    run("nft", &argument.split(' ').collect::<Vec<_>>())
        .unwrap_or_else(|error| panic!("nft {argument}: {error}"));
}

/// Create the rule table, replacing any left by an earlier run.
fn reset_firewall() {
    let _ = run("nft", &["delete", "table", "inet", "zray"]);
    nft("add table inet zray");
    nft("add chain inet zray out { type filter hook output priority 0; policy accept; }");
    nft("add chain inet zray in { type filter hook input priority 0; policy accept; }");
}

struct Namespace;

impl Namespace {
    fn enter() -> Self {
        require_private_namespace();
        reset_firewall();
        // Start from a known qdisc and MTU, whatever an earlier scenario left.
        let _ = run("tc", &["qdisc", "del", "dev", "lo", "root"]);
        let _ = run("ip", &["link", "set", "lo", "mtu", "65536"]);
        Namespace
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        // The namespace dies with the process, so this is tidiness rather than
        // safety — but a scenario that panics should not leave the next one
        // debugging someone else's rules.
        let _ = run("nft", &["delete", "table", "inet", "zray"]);
        let _ = run("tc", &["qdisc", "del", "dev", "lo", "root"]);
        let _ = run("ip", &["link", "set", "lo", "mtu", "65536"]);
    }
}

// ------------------------------------------------------------------ services

/// A loopback echo server on a fixed port.
async fn echo_server(port: u16) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buffer[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(address)
}

/// A loopback UDP echo server on a fixed port.
async fn udp_echo_server(port: u16) -> io::Result<SocketAddr> {
    let socket = UdpSocket::bind(("127.0.0.1", port)).await?;
    let address = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 2048];
        while let Ok((n, peer)) = socket.recv_from(&mut buffer).await {
            if socket.send_to(&buffer[..n], peer).await.is_err() {
                return;
            }
        }
    });
    Ok(address)
}

/// Push payload through a TCP connection until it fails, reporting the
/// classified failure with the evidence the planner needs.
async fn drive_until_failure(
    address: SocketAddr,
    chunk: usize,
    limit: Duration,
) -> Option<Failure> {
    let started = Instant::now();
    let mut stream = match TcpStream::connect(address).await {
        Ok(stream) => stream,
        Err(error) => {
            return Some(
                Failure::from_io(&error, Stage::SocketConnected).with_elapsed(started.elapsed()),
            )
        }
    };
    let _ = stream.set_nodelay(true);
    let payload = vec![0x5au8; chunk];
    let mut moved = 0u64;
    let mut buffer = vec![0u8; chunk];
    let mut stage = Stage::SocketConnected;

    while started.elapsed() < limit {
        if let Err(error) = stream.write_all(&payload).await {
            return Some(
                Failure::from_io(&error, stage)
                    .with_bytes(moved)
                    .with_elapsed(started.elapsed()),
            );
        }
        stage = Stage::RequestSent;
        match tokio::time::timeout(Duration::from_millis(500), stream.read_exact(&mut buffer)).await
        {
            Ok(Ok(_)) => {
                moved += chunk as u64;
                // A completed exchange in both directions is the only thing
                // that justifies calling the path usable.
                stage = Stage::BidirectionalConfirmed;
            }
            Ok(Err(error)) => {
                return Some(
                    Failure::from_io(&error, stage)
                        .with_bytes(moved)
                        .with_elapsed(started.elapsed()),
                )
            }
            Err(_) => {
                return Some(
                    Failure::new(FailureKind::TcpTimeout, stage)
                        .with_bytes(moved)
                        .with_elapsed(started.elapsed()),
                )
            }
        }
    }
    None
}

// ----------------------------------------------------------------- scenarios

/// Reset once a flow has carried a byte threshold — throughput-based DPI.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the namespace from scripts/iran-netem-harness.sh"]
async fn a_kernel_byte_threshold_reset_argues_for_fragmentation() {
    let _namespace = Namespace::enter();
    let echo = echo_server(port::BYTE_THRESHOLD).await.unwrap();
    nft(&format!(
        "add rule inet zray out tcp dport {} ct original bytes gt 4096 reject with tcp reset",
        port::BYTE_THRESHOLD
    ));

    let failure = drive_until_failure(echo, 1024, Duration::from_secs(10))
        .await
        .expect("a byte-threshold rule must eventually kill the flow");
    assert_eq!(failure.kind, FailureKind::TcpReset);
    assert!(
        failure.bytes_at_failure > 0,
        "the reset should arrive after payload has moved, not before"
    );
    assert!(
        failure.elapsed_at_failure < Duration::from_secs(5),
        "a byte threshold on loopback is reached in well under the \
         flow-timeout floor; {:?} would be read as a time threshold instead",
        failure.elapsed_at_failure
    );

    let mut planner = ConnectionPlanner::new(b"netem-bytes");
    assert_eq!(
        planner.record_failure(&failure),
        Transition::Climb {
            to: PathStrategy::ClientHelloFragment
        }
    );
}

/// Reset once a flow has lived long enough — flow-timeout policy.
///
/// The distinction from the scenario above is the whole point of PLAN-01
/// §5.2: identical `FailureKind`, opposite remedies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the namespace from scripts/iran-netem-harness.sh"]
async fn a_kernel_time_threshold_reset_argues_for_keepalive_shaping() {
    let _namespace = Namespace::enter();
    let echo = echo_server(port::TIME_THRESHOLD).await.unwrap();

    // Let the flow establish and carry traffic, then reset it from outside.
    // The rule is added mid-flow rather than matching on a counter, so what
    // kills this connection is genuinely its age and not its volume.
    let driver =
        tokio::spawn(async move { drive_until_failure(echo, 256, Duration::from_secs(20)).await });
    tokio::time::sleep(Duration::from_millis(400)).await;
    nft(&format!(
        "add rule inet zray out tcp dport {} reject with tcp reset",
        port::TIME_THRESHOLD
    ));

    let failure = driver
        .await
        .unwrap()
        .expect("the flow must die once the reset rule is installed");
    assert_eq!(failure.kind, FailureKind::TcpReset);
    assert!(
        failure.bytes_at_failure > 0,
        "the connection carried traffic before it was reset"
    );

    // Scale the observation to the timescale a real flow-timeout policy runs
    // on. The kernel reset is real; the *clock* is compressed so the suite
    // finishes, and the planner's credibility floor is measured in seconds.
    let observed = Duration::from_secs(90);
    let mut planner = ConnectionPlanner::new(b"netem-time");
    let aged = Failure::new(FailureKind::TcpReset, Stage::BidirectionalConfirmed)
        .with_bytes(failure.bytes_at_failure)
        .with_elapsed(observed);
    assert_eq!(
        planner.record_failure(&aged),
        Transition::Climb {
            to: PathStrategy::KeepaliveShaping
        }
    );
    assert_eq!(planner.observed_flow_lifetime(), Some(observed));

    let policy = zero_evasion::KeepalivePolicy::from_observed_reset(observed)
        .expect("a minute-scale reset is credible flow-timeout evidence");
    assert!(policy.max_flow_lifetime.unwrap() < observed);
}

/// One direction of an established flow fails while the other keeps working.
///
/// No in-process middlebox can produce this: it is the conntrack reply
/// direction being dropped beneath both endpoints.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the namespace from scripts/iran-netem-harness.sh"]
async fn asymmetric_loss_is_not_mistaken_for_a_working_path() {
    let _namespace = Namespace::enter();
    let echo = echo_server(port::ASYMMETRIC).await.unwrap();

    // Establish and *prove* the flow works before impairing it.
    //
    // The rule has to go on after the handshake, because `ct direction reply`
    // matches the SYN-ACK too: installed first, it produces a connect that
    // never completes — a different failure, reached after two minutes of SYN
    // retries, that satisfies the same assertions for the wrong reason. The
    // scenario is one direction of an *established* flow going away, so the
    // flow has to be established first.
    let mut stream = TcpStream::connect(echo).await.unwrap();
    stream.set_nodelay(true).unwrap();
    stream.write_all(b"established").await.unwrap();
    let mut buffer = [0u8; 11];
    stream.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"established");

    nft(&format!(
        "add rule inet zray in tcp sport {} ct direction reply drop",
        port::ASYMMETRIC
    ));

    // Writes keep succeeding into the send buffer; nothing comes back.
    let started = Instant::now();
    let payload = vec![0x5au8; 512];
    let mut reply = [0u8; 512];
    let outcome = loop {
        if started.elapsed() > Duration::from_secs(5) {
            panic!("a half-open path must not keep answering");
        }
        if let Err(error) = stream.write_all(&payload).await {
            break Failure::from_io(&error, Stage::RequestSent).with_elapsed(started.elapsed());
        }
        match tokio::time::timeout(Duration::from_millis(500), stream.read_exact(&mut reply)).await
        {
            Ok(Ok(_)) => continue,
            Ok(Err(error)) => {
                break Failure::from_io(&error, Stage::RequestSent).with_elapsed(started.elapsed())
            }
            Err(_) => {
                break Failure::new(FailureKind::TcpTimeout, Stage::RequestSent)
                    .with_elapsed(started.elapsed())
            }
        }
    };

    assert_eq!(
        outcome.kind,
        FailureKind::TcpTimeout,
        "uploads still succeed, so the evidence is a missing reply rather \
         than a refused connection"
    );
    assert!(
        outcome.stage < Stage::BidirectionalConfirmed,
        "nothing came back after the impairment, so the path is not \
         bidirectionally confirmed — reporting otherwise is the \
         ghost-connectivity mistake RESEARCH-01 §27 describes"
    );
}

/// UDP dropped entirely while TCP still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the namespace from scripts/iran-netem-harness.sh"]
async fn udp_loss_with_working_tcp_escapes_to_the_cdn_class() {
    let _namespace = Namespace::enter();
    let udp_echo = udp_echo_server(port::UDP_BLOCKED).await.unwrap();
    let tcp_echo = echo_server(port::CONTROL).await.unwrap();
    // Dropped on *input*, matching the reply, rather than on output.
    //
    // A `drop` verdict on the output hook is reported back to the sender as
    // EPERM from `sendmsg`, which is a local policy refusal and not what a
    // censored network looks like at all. A datagram lost in the network
    // leaves successfully and is simply never answered, so the reply is what
    // has to disappear for this to be the scenario it claims to be.
    nft(&format!(
        "add rule inet zray in udp sport {} drop",
        port::UDP_BLOCKED
    ));

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(udp_echo).await.unwrap();
    socket.send(b"probe").await.unwrap();
    let mut buffer = [0u8; 64];
    let result = tokio::time::timeout(Duration::from_millis(600), socket.recv(&mut buffer)).await;
    assert!(
        result.is_err(),
        "the datagram left the host but its reply must never arrive"
    );

    // TCP on the same stack is untouched, which is what makes this a UDP
    // policy rather than an unreachable host.
    assert!(
        drive_until_failure(tcp_echo, 256, Duration::from_millis(800))
            .await
            .is_none(),
        "TCP must still work, or this scenario is testing a dead network"
    );

    let mut planner = ConnectionPlanner::new(b"netem-udp");
    assert_eq!(
        planner.record_failure(&Failure::new(FailureKind::UdpTimeout, Stage::RequestSent)),
        Transition::ClassChange {
            to: AccessClass::CdnFronted,
            at: PathStrategy::CdnWebSocket,
        }
    );
}

/// QUIC-shaped UDP dropped while TCP works — the HTTP/3 case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the namespace from scripts/iran-netem-harness.sh"]
async fn quic_loss_with_working_tcp_escapes_to_the_cdn_class() {
    let _namespace = Namespace::enter();
    let udp_echo = udp_echo_server(port::QUIC_BLOCKED).await.unwrap();
    // Again on input: the initial goes out, the response never comes back,
    // which is how a QUIC-blocking network behaves. See the UDP scenario.
    nft(&format!(
        "add rule inet zray in udp sport {} drop",
        port::QUIC_BLOCKED
    ));

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(udp_echo).await.unwrap();
    // A QUIC Initial-shaped datagram: long header, version 1.
    let mut initial = vec![0u8; 1200];
    initial[0] = 0xc0;
    initial[1..5].copy_from_slice(&1u32.to_be_bytes());
    socket.send(&initial).await.unwrap();
    let mut buffer = [0u8; 1500];
    assert!(
        tokio::time::timeout(Duration::from_millis(600), socket.recv(&mut buffer))
            .await
            .is_err(),
        "the QUIC initial should have been dropped"
    );

    let mut planner = ConnectionPlanner::new(b"netem-quic");
    assert_eq!(
        planner.record_failure(&Failure::new(
            FailureKind::QuicHandshakeTimeout,
            Stage::TlsStarted
        )),
        Transition::ClassChange {
            to: AccessClass::CdnFronted,
            at: PathStrategy::CdnWebSocket,
        }
    );
}

/// Encrypted DNS over TCP reset while plain UDP DNS still answers.
///
/// This is the shape that makes the DoH bootstrap a trap: the encrypted
/// resolver is the one being blocked, and falling back to the plaintext one is
/// exactly what the censor wants.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the namespace from scripts/iran-netem-harness.sh"]
async fn an_encrypted_dns_reset_leaves_plain_udp_dns_working() {
    let _namespace = Namespace::enter();
    let doh = echo_server(port::DOH_RESET).await.unwrap();
    let plain = udp_echo_server(port::UDP_DNS_OK).await.unwrap();
    nft(&format!(
        "add rule inet zray out tcp dport {} reject with tcp reset",
        port::DOH_RESET
    ));

    let refused = TcpStream::connect(doh).await;
    assert!(
        refused.is_err(),
        "the encrypted-DNS shaped port should be reset"
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(plain).await.unwrap();
    socket.send(b"query").await.unwrap();
    let mut buffer = [0u8; 64];
    let answered = tokio::time::timeout(Duration::from_millis(600), socket.recv(&mut buffer)).await;
    assert!(
        matches!(answered, Ok(Ok(_))),
        "plain UDP DNS must still answer, or this is not the scenario"
    );
}

/// A path MTU below a whole write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the namespace from scripts/iran-netem-harness.sh"]
async fn a_low_path_mtu_still_carries_bounded_fragments() {
    let _namespace = Namespace::enter();
    let echo = echo_server(port::LOW_MTU).await.unwrap();
    run("ip", &["link", "set", "lo", "mtu", "1280"]).expect("lower the loopback MTU");

    let reported = run("ip", &["-o", "link", "show", "lo"]).unwrap();
    assert!(
        reported.contains("mtu 1280"),
        "the MTU change did not take effect: {reported}"
    );

    // Writes comfortably under the MTU still complete, which is what the
    // fragmentation strategy relies on being true.
    assert!(
        drive_until_failure(echo, 512, Duration::from_millis(800))
            .await
            .is_none(),
        "bounded fragments must survive a low MTU"
    );
}

/// IPv6 reachable at the socket layer but stalling afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the namespace from scripts/iran-netem-harness.sh"]
async fn an_ipv6_path_that_connects_then_stalls_is_confirmed_before_failover() {
    let _namespace = Namespace::enter();
    let listener = TcpListener::bind(("::1", port::IPV6_STALL)).await.unwrap();
    let address = listener.local_addr().unwrap();
    // Accept and then say nothing: the connection completes, the exchange
    // never does.
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let failure = drive_until_failure(address, 256, Duration::from_secs(4))
        .await
        .expect("a stalled IPv6 path must produce a failure");
    assert_eq!(failure.kind, FailureKind::TcpTimeout);
    assert!(failure.stage < Stage::BidirectionalConfirmed);

    // One stall is not a dead address family. The planner requires
    // corroboration before spending a class change on it.
    let mut planner = ConnectionPlanner::new(b"netem-ipv6");
    assert_eq!(planner.record_failure(&failure), Transition::Hold);
    assert_eq!(planner.record_failure(&failure), Transition::Hold);
    assert_eq!(
        planner.record_failure(&failure),
        Transition::ClassChange {
            to: AccessClass::CdnFronted,
            at: PathStrategy::CdnWebSocket,
        }
    );
}

/// A throttled but complete path must not be treated as a failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the namespace from scripts/iran-netem-harness.sh"]
async fn a_throttled_path_is_slow_rather_than_broken() {
    let _namespace = Namespace::enter();
    let echo = echo_server(port::THROTTLED).await.unwrap();
    // Real delay from the kernel scheduler, not a sleep in the relay.
    run(
        "tc",
        &[
            "qdisc", "add", "dev", "lo", "root", "netem", "delay", "40ms",
        ],
    )
    .expect("apply netem delay");

    let started = Instant::now();
    let outcome = drive_until_failure(echo, 256, Duration::from_millis(900)).await;
    assert!(
        outcome.is_none(),
        "a slow path is still a working path; climbing the ladder here would \
         spend an expensive disguise on latency"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(80),
        "the delay qdisc did not take effect, so nothing was throttled"
    );
}

/// A mid-session interface change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the namespace from scripts/iran-netem-harness.sh"]
async fn an_interface_change_needs_corroboration_before_a_class_failover() {
    let _namespace = Namespace::enter();
    let echo = echo_server(port::CONTROL + 1).await.unwrap();
    let mut stream = TcpStream::connect(echo).await.unwrap();
    stream.write_all(b"before").await.unwrap();
    let mut buffer = [0u8; 6];
    stream.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"before");

    // The interface goes away under the live flow.
    run("ip", &["link", "set", "lo", "down"]).expect("bring loopback down");
    let after = stream.write_all(b"after").await;
    let read = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buffer)).await;
    assert!(
        after.is_err() || !matches!(read, Ok(Ok(n)) if n > 0),
        "the flow should not keep working across an interface teardown"
    );
    run("ip", &["link", "set", "lo", "up"]).expect("bring loopback back up");

    let failure = Failure::new(FailureKind::NetworkChanged, Stage::PayloadTransferred);
    let mut planner = ConnectionPlanner::new(b"netem-ifchange");
    assert_eq!(planner.record_failure(&failure), Transition::Hold);
    assert_eq!(planner.record_failure(&failure), Transition::Hold);
    assert_eq!(
        planner.record_failure(&failure),
        Transition::ClassChange {
            to: AccessClass::CdnFronted,
            at: PathStrategy::CdnWebSocket,
        }
    );
}

/// The control: with no rules in place, everything works.
///
/// Without this, a scenario that fails because the namespace is broken looks
/// exactly like a scenario that fails because the impairment worked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the namespace from scripts/iran-netem-harness.sh"]
async fn an_unimpaired_namespace_carries_traffic() {
    let _namespace = Namespace::enter();
    let echo = echo_server(port::CONTROL + 2).await.unwrap();
    assert!(
        drive_until_failure(echo, 4096, Duration::from_millis(800))
            .await
            .is_none(),
        "the unimpaired control path failed, so every other result in this \
         file is suspect"
    );
}
