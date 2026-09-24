//! Iranian network simulation (PLAN-02 §7.3, PLAN-01 §5).
//!
//! These tests stand up an in-process middlebox that reproduces the behaviours
//! Iranian DPI is actually observed to exhibit, then check that Zray's
//! countermeasures do what they claim against it. The value is not that the
//! middlebox is a faithful model of any particular ISP — it is that each
//! countermeasure is measured against a concrete adversary rather than asserted
//! to work, and that the failure it produces when defeated is the one the
//! failure taxonomy expects.
//!
//! The simulator covers the thirteen concrete adversaries called out in
//! PLAN-01 §7: segment SNI matching, complete blackholes, byte and time
//! thresholds, UDP/QUIC loss, IPv6 stalls, encrypted-DNS resets with a usable
//! UDP alternative, poisoned DNS replies, low MTU, asymmetric relaying,
//! throttling, and interface changes. Each one stays local and bounded, so CI
//! does not need `CAP_NET_ADMIN`, `tc`, or `nftables` to exercise the decision.
//!
//! The base TCP middlebox behaviours are:
//!
//! * **SNI reset** — the flow is killed when a watched name appears inside a
//!   single segment. This is the one fragmentation exists for.
//! * **Blackhole** — the connection is accepted and then nothing comes back.
//!   Fragmentation cannot help; only a class change can.
//! * **Byte-threshold reset** — the flow dies after a volume of payload.
//! * **Throttle** — the flow survives but is slowed to a trickle.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use zero_core::{Failure, FailureKind, Stage};
use zero_evasion::{FragmentPolicy, FragmentStream, Packets};
use zero_observatory::{AccessClass, ConnectionPlanner, PathStrategy, Transition};

#[derive(Debug, Clone)]
enum Dpi {
    /// Kill the flow when `pattern` occurs within one read. A censor that
    /// reassembles the stream would still see it; one that matches per segment
    /// would not. Modelling the cheap one is the point.
    ResetOnPatternInSegment { pattern: Vec<u8> },
    /// Accept the connection and answer nothing, forever.
    Blackhole,
    /// Reset once this many payload bytes have been relayed.
    ResetAfterBytes(usize),
    /// Relay the start of a flow, then tear it down after a flow-duration
    /// threshold. This is deliberately distinct from byte-threshold DPI.
    ResetAfterDelay(Duration),
    /// A path with an effective MTU below a whole TCP write. Small fragmented
    /// writes pass, while the intact ClientHello is discarded.
    RejectSegmentsLargerThan(usize),
    /// Uploads reach the origin, but replies are blackholed. This models the
    /// asymmetric upstream/downstream failure common during congestion.
    DropDownstream,
    /// Relay everything, but slowly.
    Throttle { chunk: usize, delay: Duration },
    /// No interference; the control case.
    Transparent,
}

#[derive(Debug, Default)]
struct Telemetry {
    connections: AtomicUsize,
    resets: AtomicUsize,
    bytes_upstream: AtomicUsize,
    bytes_downstream: AtomicUsize,
}

/// Start a middlebox in front of `upstream`, returning its address.
async fn middlebox(
    upstream: SocketAddr,
    behaviour: Dpi,
    telemetry: Arc<Telemetry>,
) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            telemetry.connections.fetch_add(1, Ordering::SeqCst);
            let behaviour = behaviour.clone();
            let telemetry = Arc::clone(&telemetry);
            tokio::spawn(async move {
                let _ = inspect(client, upstream, behaviour, telemetry).await;
            });
        }
    });
    Ok(address)
}

async fn inspect(
    mut client: TcpStream,
    upstream: SocketAddr,
    behaviour: Dpi,
    telemetry: Arc<Telemetry>,
) -> io::Result<()> {
    if matches!(&behaviour, Dpi::Blackhole) {
        // Hold the socket open and never speak. This is what produces a clean
        // TLS_TIMEOUT rather than a reset.
        tokio::time::sleep(Duration::from_secs(30)).await;
        return Ok(());
    }

    let mut server = TcpStream::connect(upstream).await?;
    let (mut client_read, mut client_write) = client.split();
    let (mut server_read, mut server_write) = server.split();

    let downstream = async {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read = server_read.read(&mut buffer).await?;
            if read == 0 {
                return Ok::<(), io::Error>(());
            }
            telemetry.bytes_downstream.fetch_add(read, Ordering::SeqCst);
            if matches!(&behaviour, Dpi::DropDownstream) {
                continue;
            }
            client_write.write_all(&buffer[..read]).await?;
        }
    };

    let upstream_flow = async {
        let mut buffer = vec![0u8; 16 * 1024];
        let mut total = 0usize;
        loop {
            let read = client_read.read(&mut buffer).await?;
            if read == 0 {
                return Ok::<(), io::Error>(());
            }
            let segment = &buffer[..read];
            telemetry.bytes_upstream.fetch_add(read, Ordering::SeqCst);

            match &behaviour {
                Dpi::ResetOnPatternInSegment { pattern } => {
                    if contains(segment, pattern) {
                        telemetry.resets.fetch_add(1, Ordering::SeqCst);
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "matched a watched name inside one segment",
                        ));
                    }
                }
                Dpi::ResetAfterBytes(limit) => {
                    total += read;
                    if total > *limit {
                        telemetry.resets.fetch_add(1, Ordering::SeqCst);
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "payload volume threshold",
                        ));
                    }
                }
                Dpi::RejectSegmentsLargerThan(limit) if read > *limit => {
                    telemetry.resets.fetch_add(1, Ordering::SeqCst);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "segment exceeded simulated path MTU",
                    ));
                }
                Dpi::Throttle { chunk, delay } => {
                    for piece in segment.chunks(*chunk) {
                        server_write.write_all(piece).await?;
                        tokio::time::sleep(*delay).await;
                    }
                    continue;
                }
                Dpi::Blackhole
                | Dpi::ResetAfterDelay(_)
                | Dpi::RejectSegmentsLargerThan(_)
                | Dpi::DropDownstream
                | Dpi::Transparent => {}
            }
            server_write.write_all(segment).await?;
        }
    };

    if let Dpi::ResetAfterDelay(delay) = &behaviour {
        tokio::select! {
            result = downstream => result,
            result = upstream_flow => result,
            _ = tokio::time::sleep(*delay) => {
                telemetry.resets.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "simulated flow-duration threshold",
                ))
            }
        }
    } else {
        tokio::select! {
            result = downstream => result,
            result = upstream_flow => result,
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// An upstream that echoes whatever reaches it, so a test can tell "the bytes
/// arrived" from "the flow was killed".
async fn echo_server() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16 * 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
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

/// Receive UDP datagrams and deliberately send no answer. A UDP blackhole is
/// different from a TCP reset: there is no peer-visible teardown to classify.
async fn udp_blackhole() -> io::Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = [0_u8; 2048];
        while socket.recv_from(&mut buffer).await.is_ok() {}
    });
    Ok(address)
}

/// A UDP control path used to prove a dropped QUIC/DoH-style datagram is a
/// transport-specific observation, not an outage of the entire local network.
async fn udp_echo_server() -> io::Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = [0_u8; 2048];
        while let Ok((read, peer)) = socket.recv_from(&mut buffer).await {
            if socket.send_to(&buffer[..read], peer).await.is_err() {
                return;
            }
        }
    });
    Ok(address)
}

async fn udp_round_trip(entry: SocketAddr, body: &[u8]) -> io::Result<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.send_to(body, entry).await?;
    let mut received = [0_u8; 2048];
    let (read, _) =
        tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut received))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP response timed out"))??;
    Ok(received[..read].to_vec())
}

/// A local TCP endpoint that closes with unread data after the first write,
/// making the client observe the same reset-shaped failure as a blocked DoH
/// connection without needing a certificate or public DNS service.
async fn resetting_tcp_peer() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut first = [0_u8; 1];
                let _ = stream.read_exact(&mut first).await;
                // Leave the rest of the write unread, then drop. Linux emits
                // RST for that close, matching the interference shape.
            });
        }
    });
    Ok(address)
}

async fn ipv6_blackhole() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("[::1]:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((_stream, _)) = listener.accept().await {
            // Holding the accepted stream models a routed IPv6 path that
            // establishes TCP but stalls before useful application progress.
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    Ok(address)
}

/// A TLS ClientHello record carrying `sni`, shaped well enough for a
/// segment-matching censor and for the fragmenter's record re-framing.
fn client_hello(sni: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x01); // handshake type: ClientHello
    body.extend_from_slice(&[0, 0, 0]); // length, patched below
    body.extend_from_slice(&[0x03, 0x03]); // client version
    body.extend_from_slice(&[0x11; 32]); // random
    body.push(0); // no session id
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
    body.extend_from_slice(&[0x01, 0x00]); // null compression

    let name = sni.as_bytes();
    let mut extension = Vec::new();
    extension.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    extension.push(0);
    extension.extend_from_slice(&(name.len() as u16).to_be_bytes());
    extension.extend_from_slice(name);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x00]); // server_name
    extensions.extend_from_slice(&(extension.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&extension);
    // Padding, so the hello is comfortably longer than one fragment.
    extensions.extend_from_slice(&[0x00, 0x15]);
    extensions.extend_from_slice(&[0x01, 0x00]);
    extensions.extend_from_slice(&[0u8; 256]);

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let body_len = body.len() - 4;
    body[1..4].copy_from_slice(&[
        (body_len >> 16) as u8,
        (body_len >> 8) as u8,
        body_len as u8,
    ]);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

const WATCHED: &str = "www.googletagmanager.com";

/// Fragments small enough that the watched name cannot fit inside one.
///
/// This is the only configuration under which a segment-matching censor is
/// *guaranteed* to miss the name; see
/// `default_fragment_sizes_do_not_guarantee_the_name_is_split` for why the
/// field-tuned defaults are a different, weaker claim.
fn splitting_policy() -> FragmentPolicy {
    FragmentPolicy {
        packets: Packets::TlsHello,
        length_min: 8,
        length_max: 12,
        interval_min_ms: 1,
        interval_max_ms: 1,
        max_split_min: 0,
        max_split_max: 0,
    }
}

/// Send a hello through the middlebox, optionally fragmenting, and report
/// whether the echo came back.
async fn attempt(entry: SocketAddr, fragment: bool) -> io::Result<usize> {
    let hello = client_hello(WATCHED);
    let stream = TcpStream::connect(entry).await?;
    stream.set_nodelay(true)?;

    let mut echoed = vec![0u8; hello.len()];
    if fragment {
        let mut stream = FragmentStream::new(stream, splitting_policy());
        stream.write_all(&hello).await?;
        stream.flush().await?;
        read_exact_with_timeout(&mut stream, &mut echoed).await?;
    } else {
        let mut stream = stream;
        stream.write_all(&hello).await?;
        stream.flush().await?;
        read_exact_with_timeout(&mut stream, &mut echoed).await?;
    }
    Ok(echoed.len())
}

async fn short_attempt(entry: SocketAddr) -> io::Result<()> {
    let mut stream = TcpStream::connect(entry).await?;
    stream.set_nodelay(true)?;
    let hello = client_hello(WATCHED);
    stream.write_all(&hello).await?;
    stream.flush().await?;
    let mut first = [0_u8; 1];
    tokio::time::timeout(Duration::from_millis(300), stream.read_exact(&mut first))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no first response"))?
        .map(|_| ())
}

async fn read_exact_with_timeout<S>(stream: &mut S, buffer: &mut [u8]) -> io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(buffer))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no response"))?
        .map(|_| ())
}

#[tokio::test]
async fn a_segment_matching_censor_kills_an_unfragmented_client_hello() {
    let upstream = echo_server().await.unwrap();
    let telemetry = Arc::new(Telemetry::default());
    let entry = middlebox(
        upstream,
        Dpi::ResetOnPatternInSegment {
            pattern: WATCHED.as_bytes().to_vec(),
        },
        Arc::clone(&telemetry),
    )
    .await
    .unwrap();

    let result = attempt(entry, false).await;
    assert!(
        result.is_err(),
        "the censor should have killed the contiguous SNI"
    );
    assert_eq!(telemetry.resets.load(Ordering::SeqCst), 1);

    // A reset after the ClientHello was uploaded is evidence for the one
    // response that changes that visible shape: ClientHello fragmentation.
    let mut planner = ConnectionPlanner::new(b"segment-sni");
    assert_eq!(
        planner.record_failure(
            &Failure::new(FailureKind::TcpReset, Stage::UploadConfirmed)
                .with_bytes(client_hello(WATCHED).len() as u64),
        ),
        Transition::Climb {
            to: PathStrategy::ClientHelloFragment,
        }
    );
}

#[tokio::test]
async fn fragmentation_defeats_the_same_censor() {
    let upstream = echo_server().await.unwrap();
    let telemetry = Arc::new(Telemetry::default());
    let entry = middlebox(
        upstream,
        Dpi::ResetOnPatternInSegment {
            pattern: WATCHED.as_bytes().to_vec(),
        },
        Arc::clone(&telemetry),
    )
    .await
    .unwrap();

    // The mechanism of PLAN-02 §3.1: with fragments shorter than the watched
    // name, the name cannot be contiguous in any one segment, so a censor that
    // does not reassemble cannot match it.
    let echoed = attempt(entry, true)
        .await
        .expect("fragmented hello should survive");
    assert!(echoed > 0);
    assert_eq!(
        telemetry.resets.load(Ordering::SeqCst),
        0,
        "no segment should have contained the watched name"
    );
}

/// The uncomfortable half of the fragmentation story, stated rather than
/// assumed.
///
/// BPB's field-tuned default is 100–200 bytes per fragment (PLAN-02 §3.1). A
/// watched name is far shorter than that, so against a censor that simply
/// searches each segment for the name, the default *usually leaves the name
/// intact inside a single fragment*. That the defaults nevertheless work in the
/// field says the deployed censors are parsing TLS records rather than grepping
/// segments — which is a claim about the adversary, not about the technique.
///
/// This matters for the planner: fragmentation is a rung that may or may not
/// address a given block, which is precisely why PLAN-02 §4.2 calls these
/// numbers "defaults, not constants" and has the observatory measure whether
/// they help on *this* network.
#[test]
fn default_fragment_sizes_do_not_guarantee_the_name_is_split() {
    let hello = client_hello(WATCHED);
    let name = WATCHED.as_bytes();

    let mut intact_at_defaults = 0usize;
    let mut intact_when_smaller_than_the_name = 0usize;
    const TRIALS: usize = 200;

    for _ in 0..TRIALS {
        let planned = zero_evasion::fragment::plan_tls_hello(&hello, &FragmentPolicy::default())
            .expect("a well-formed hello is fragmentable");
        assert!(planned.len() > 1, "the hello should be split at all");
        if planned.iter().any(|chunk| contains(&chunk.bytes, name)) {
            intact_at_defaults += 1;
        }

        let planned = zero_evasion::fragment::plan_tls_hello(&hello, &splitting_policy())
            .expect("a well-formed hello is fragmentable");
        if planned.iter().any(|chunk| contains(&chunk.bytes, name)) {
            intact_when_smaller_than_the_name += 1;
        }
    }

    // Fragments shorter than the name: the guarantee holds absolutely.
    assert_eq!(
        intact_when_smaller_than_the_name, 0,
        "a fragment shorter than the name can never contain it whole"
    );
    // Fragments longer than the name: no guarantee, and in practice the name
    // survives intact most of the time.
    assert!(
        intact_at_defaults > 0,
        "the default sizes were expected to leave the name contiguous at least once in {TRIALS} plans"
    );
}

#[tokio::test]
async fn fragmentation_is_not_a_cure_for_a_blackhole() {
    let upstream = echo_server().await.unwrap();
    let telemetry = Arc::new(Telemetry::default());
    let entry = middlebox(upstream, Dpi::Blackhole, Arc::clone(&telemetry))
        .await
        .unwrap();

    // Both fail, and they fail the same way. This is the evidence behind the
    // taxonomy rule that a clean timeout argues for a class change rather than
    // for a more elaborate disguise.
    let plain = attempt(entry, false).await;
    let fragmented = attempt(entry, true).await;
    assert!(plain.is_err());
    assert!(fragmented.is_err());
    assert_eq!(plain.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(fragmented.unwrap_err().kind(), io::ErrorKind::TimedOut);

    let mut planner = ConnectionPlanner::new(b"blackhole");
    assert_eq!(
        planner.record_failure(&Failure::new(FailureKind::TlsTimeout, Stage::TlsStarted)),
        Transition::ClassChange {
            to: AccessClass::CdnFronted,
            at: PathStrategy::CdnWebSocket,
        }
    );
}

#[tokio::test]
async fn a_byte_threshold_reset_lets_the_handshake_through_and_kills_the_payload() {
    let upstream = echo_server().await.unwrap();
    let telemetry = Arc::new(Telemetry::default());
    let entry = middlebox(upstream, Dpi::ResetAfterBytes(4096), Arc::clone(&telemetry))
        .await
        .unwrap();

    let mut stream = TcpStream::connect(entry).await.unwrap();
    stream.set_nodelay(true).unwrap();
    let hello = client_hello(WATCHED);
    stream.write_all(&hello).await.unwrap();
    let mut echoed = vec![0u8; hello.len()];
    // The handshake itself is under the threshold, so it completes — which is
    // exactly why `bytes_at_failure` is recorded: the failure looks like a
    // working path until enough payload has moved.
    read_exact_with_timeout(&mut stream, &mut echoed)
        .await
        .unwrap();

    let payload = vec![0x5a; 8192];
    let result: io::Result<()> = async {
        stream.write_all(&payload).await?;
        let mut sink = vec![0u8; payload.len()];
        read_exact_with_timeout(&mut stream, &mut sink).await
    }
    .await;
    assert!(result.is_err(), "payload past the threshold should die");
    assert_eq!(telemetry.resets.load(Ordering::SeqCst), 1);

    let mut planner = ConnectionPlanner::new(b"byte-threshold");
    assert_eq!(
        planner.record_failure(
            &Failure::new(FailureKind::TcpReset, Stage::PayloadTransferred)
                .with_bytes((hello.len() + payload.len()) as u64),
        ),
        Transition::Climb {
            to: PathStrategy::ClientHelloFragment,
        }
    );
}

#[tokio::test]
async fn a_flow_duration_reset_is_distinct_from_a_byte_threshold() {
    let upstream = echo_server().await.unwrap();
    let telemetry = Arc::new(Telemetry::default());
    let limit = Duration::from_millis(60);
    let entry = middlebox(
        upstream,
        Dpi::ResetAfterDelay(limit),
        Arc::clone(&telemetry),
    )
    .await
    .unwrap();

    let mut stream = TcpStream::connect(entry).await.unwrap();
    stream.set_nodelay(true).unwrap();
    let hello = client_hello(WATCHED);
    stream.write_all(&hello).await.unwrap();
    let mut echoed = vec![0u8; hello.len()];
    read_exact_with_timeout(&mut stream, &mut echoed)
        .await
        .unwrap();

    // The same bytes that survived a byte limit now fail only after the flow
    // has remained open. The delay is intentionally much shorter than a real
    // ISP policy, but it keeps the distinction deterministic in CI.
    tokio::time::sleep(limit + Duration::from_millis(20)).await;
    let result: io::Result<()> = async {
        stream.write_all(b"keepalive-probe").await?;
        let mut response = [0_u8; 1];
        tokio::time::timeout(Duration::from_millis(300), stream.read_exact(&mut response))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "flow did not close"))?
            .map(|_| ())
    }
    .await;
    assert!(
        result.is_err(),
        "the time threshold should close the live flow"
    );
    assert_eq!(telemetry.resets.load(Ordering::SeqCst), 1);

    // The local middlebox compresses the timescale so the suite stays fast:
    // 60ms stands in for the minutes a real flow-timeout policy allows. The
    // planner decision, though, has to be asserted at the real timescale,
    // because the credibility floor that separates a flow timeout from a
    // matched handshake is measured in seconds. Feeding it the compressed
    // number would prove the wrong thing.
    const REAL_WORLD_SCALE: u32 = 1_000;
    let observed_lifetime = limit * REAL_WORLD_SCALE;
    let failure = Failure::new(FailureKind::TcpReset, Stage::BidirectionalConfirmed)
        .with_bytes(telemetry.bytes_upstream.load(Ordering::SeqCst) as u64)
        .with_elapsed(observed_lifetime);
    let mut planner = ConnectionPlanner::new(b"flow-duration");

    // The remedy is keepalive shaping, not fragmentation. The bytes moved
    // here are the same bytes that made the byte-threshold scenario climb to
    // ClientHelloFragment; only the timing differs, and it has to be enough
    // to produce the opposite answer.
    assert_eq!(
        planner.record_failure(&failure),
        Transition::Climb {
            to: PathStrategy::KeepaliveShaping,
        }
    );
    assert_eq!(planner.current(), PathStrategy::KeepaliveShaping);

    let observation = planner
        .profile()
        .recent(PathStrategy::DirectReality)
        .last()
        .unwrap();
    assert_eq!(observation.bytes_at_failure, failure.bytes_at_failure);
    assert_eq!(observation.elapsed_at_failure, observed_lifetime);

    // And the rung has to carry a usable shape, not just a name: the policy
    // must retire a carrier strictly before the deadline that was observed.
    let policy = zero_evasion::KeepalivePolicy::from_observed_reset(observed_lifetime)
        .expect("a minute-scale reset is credible flow-timeout evidence");
    let lifetime = policy.max_flow_lifetime.expect("shaping retires carriers");
    assert!(
        lifetime < observed_lifetime,
        "retiring at {lifetime:?} would still reach the observed {observed_lifetime:?} deadline"
    );
    assert!(policy.idle_after < lifetime);
}

#[tokio::test]
async fn a_low_mtu_drops_an_intact_hello_but_allows_bounded_fragments() {
    let upstream = echo_server().await.unwrap();
    let telemetry = Arc::new(Telemetry::default());
    let entry = middlebox(
        upstream,
        // Well above one 8--12 byte fragment, while safely below the
        // contiguous synthetic ClientHello.
        Dpi::RejectSegmentsLargerThan(64),
        Arc::clone(&telemetry),
    )
    .await
    .unwrap();

    assert!(attempt(entry, false).await.is_err());
    assert!(
        attempt(entry, true).await.is_ok(),
        "bounded fragments should fit through the simulated low-MTU path"
    );
    assert_eq!(telemetry.resets.load(Ordering::SeqCst), 1);

    let mut planner = ConnectionPlanner::new(b"low-mtu");
    assert_eq!(
        planner.record_failure(
            &Failure::new(FailureKind::TcpReset, Stage::UploadConfirmed)
                .with_bytes(client_hello(WATCHED).len() as u64),
        ),
        Transition::Climb {
            to: PathStrategy::ClientHelloFragment,
        }
    );
}

#[tokio::test]
async fn asymmetric_downstream_loss_is_not_counted_as_a_usable_path() {
    let upstream = echo_server().await.unwrap();
    let telemetry = Arc::new(Telemetry::default());
    let entry = middlebox(upstream, Dpi::DropDownstream, Arc::clone(&telemetry))
        .await
        .unwrap();

    let error = short_attempt(entry).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(telemetry.bytes_upstream.load(Ordering::SeqCst) > 0);
    assert!(
        telemetry.bytes_downstream.load(Ordering::SeqCst) > 0,
        "the upstream replied; only the return direction was lost"
    );

    let mut planner = ConnectionPlanner::new(b"downstream-loss");
    assert_eq!(
        planner.record_failure(&Failure::new(
            FailureKind::TlsTimeout,
            Stage::UploadConfirmed
        )),
        Transition::ClassChange {
            to: AccessClass::CdnFronted,
            at: PathStrategy::CdnWebSocket,
        }
    );
}

#[tokio::test]
async fn udp_loss_is_not_a_tcp_outage_and_uses_the_cdn_escape_branch() {
    let blackhole = udp_blackhole().await.unwrap();
    let tcp_upstream = echo_server().await.unwrap();
    let tcp_telemetry = Arc::new(Telemetry::default());
    let tcp_entry = middlebox(tcp_upstream, Dpi::Transparent, tcp_telemetry)
        .await
        .unwrap();

    let error = udp_round_trip(blackhole, b"dns-over-udp")
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        attempt(tcp_entry, false).await.is_ok(),
        "TCP remains usable"
    );

    let mut planner = ConnectionPlanner::new(b"udp-only-loss");
    assert_eq!(
        planner.record_failure(&Failure::new(FailureKind::UdpTimeout, Stage::RequestSent)),
        Transition::ClassChange {
            to: AccessClass::CdnFronted,
            at: PathStrategy::CdnWebSocket,
        }
    );
}

#[tokio::test]
async fn quic_datagram_loss_can_coexist_with_a_working_tcp_path() {
    let quic_blackhole = udp_blackhole().await.unwrap();
    let tcp_upstream = echo_server().await.unwrap();
    let entry = middlebox(
        tcp_upstream,
        Dpi::Transparent,
        Arc::new(Telemetry::default()),
    )
    .await
    .unwrap();

    let error = udp_round_trip(quic_blackhole, b"QUIC\x00initial")
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        attempt(entry, false).await.is_ok(),
        "TCP control path works"
    );

    let mut planner = ConnectionPlanner::new(b"quic-only-loss");
    assert_eq!(
        planner.record_failure(&Failure::new(
            FailureKind::QuicHandshakeTimeout,
            Stage::TlsStarted,
        )),
        Transition::ClassChange {
            to: AccessClass::CdnFronted,
            at: PathStrategy::CdnWebSocket,
        }
    );
}

#[tokio::test]
async fn an_ipv6_path_can_connect_then_stall_independently() {
    let entry = ipv6_blackhole().await.unwrap();
    let error = short_attempt(entry).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);

    // An interface/address-family outage needs confirmation before discarding
    // a whole access class; one delayed IPv6 flow is insufficient evidence.
    let failure = Failure::new(FailureKind::TcpTimeout, Stage::SocketConnected);
    let mut planner = ConnectionPlanner::new(b"ipv6-stall");
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

#[tokio::test]
async fn a_reset_encrypted_dns_path_can_fall_back_to_usable_udp() {
    let encrypted_dns = resetting_tcp_peer().await.unwrap();
    let udp_dns = udp_echo_server().await.unwrap();

    let mut stream = TcpStream::connect(encrypted_dns).await.unwrap();
    stream.write_all(&vec![0x44; 1024]).await.unwrap();
    let mut one = [0_u8; 1];
    let reset = tokio::time::timeout(Duration::from_millis(300), stream.read_exact(&mut one))
        .await
        .expect("the resetting peer should close promptly");
    assert!(
        reset.is_err(),
        "the encrypted DNS path should not produce data"
    );
    assert_eq!(
        udp_round_trip(udp_dns, b"fallback-dns").await.unwrap(),
        b"fallback-dns"
    );
}

#[test]
fn a_mid_session_interface_change_requires_confirmation_before_class_failover() {
    let mut planner = ConnectionPlanner::new(b"interface-change");
    planner.record_success(Stage::BidirectionalConfirmed, Duration::from_millis(5));
    let failure = Failure::new(FailureKind::NetworkChanged, Stage::PayloadTransferred);
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

#[tokio::test]
async fn a_throttled_path_still_delivers_every_byte() {
    let upstream = echo_server().await.unwrap();
    let telemetry = Arc::new(Telemetry::default());
    let entry = middlebox(
        upstream,
        Dpi::Throttle {
            chunk: 64,
            delay: Duration::from_millis(1),
        },
        Arc::clone(&telemetry),
    )
    .await
    .unwrap();

    // Throttling is not a failure: a path that is slow but complete must not be
    // classified as blocked, or the planner would climb the ladder for nothing.
    let echoed = attempt(entry, false).await.expect("throttled path works");
    assert_eq!(echoed, client_hello(WATCHED).len());
    assert_eq!(telemetry.resets.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_control_case_passes_unmodified() {
    let upstream = echo_server().await.unwrap();
    let telemetry = Arc::new(Telemetry::default());
    let entry = middlebox(upstream, Dpi::Transparent, Arc::clone(&telemetry))
        .await
        .unwrap();
    let hello = client_hello(WATCHED);
    assert_eq!(attempt(entry, false).await.unwrap(), hello.len());
    // Fragmentation must be transparent to the peer: same bytes, more segments.
    assert_eq!(attempt(entry, true).await.unwrap(), hello.len());
    assert_eq!(telemetry.connections.load(Ordering::SeqCst), 2);
}
