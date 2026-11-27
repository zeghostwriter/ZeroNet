//! The no-root SNI decoy and the TTL probe, over a real (virtual) network.
//!
//! Unit tests can check what the decoy puts in a buffer; only a path with
//! routers on it can show what a filter in the middle sees and what the server
//! at the end receives. `netns/testbed.sh` builds one without privileges (user
//! and network namespaces): a client, four routers and a server in a line, a
//! sniffer on every router, an echo server at the end. This file is the client
//! half, run inside the client's namespace; the script reads the sniffers and
//! checks the other half. Run it with:
//!
//! ```bash
//! cargo test -p zero-evasion --test decoy_netns --no-run   # builds the client
//! crates/zero-evasion/tests/netns/testbed.sh               # runs it in the bed
//! ```
//!
//! The tests do nothing (and say so) outside the testbed, so a plain
//! `cargo test --ignored` cannot pass or fail them by accident.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zero_evasion::decoy::{DecoyPolicy, DecoyStream, Fooling};

/// The name the client really asks for. Longer than the decoy's base name, so
/// the decoy gets a random label in front and keeps the hello the same length.
const REAL_NAME: &str = "real.hidden-server.example.net";

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// A ClientHello with `name` in its server_name extension: just enough for the
/// decoy's parser and a server that only echoes.
fn hello(name: &str) -> Vec<u8> {
    let mut extensions = vec![0xff, 0x01, 0, 1, 0];
    extensions.extend_from_slice(&[0, 0]);
    extensions.extend_from_slice(&(name.len() as u16 + 5).to_be_bytes());
    extensions.extend_from_slice(&(name.len() as u16 + 3).to_be_bytes());
    extensions.push(0);
    extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
    extensions.extend_from_slice(name.as_bytes());
    extensions.extend_from_slice(&[0, 0x17, 0, 0]);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.extend_from_slice(&[4, 1, 2, 3, 4]);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    // Pad the body so the hello is a few hundred bytes, like a browser's.
    let mut record = vec![0x16, 3, 1];
    record.extend_from_slice(&(body.len() as u16 + 4).to_be_bytes());
    record.extend_from_slice(&[1, 0]);
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

/// `ZRAY_NETNS_TARGET=10.0.5.2:443`, or `None` outside the testbed.
fn target() -> Option<SocketAddr> {
    env("ZRAY_NETNS_TARGET")?.parse().ok()
}

fn policy() -> DecoyPolicy {
    let fooling = match env("ZRAY_DECOY_FOOLING").as_deref() {
        Some("md5") => Fooling::Md5,
        Some("ttl") => Fooling::Ttl,
        _ => Fooling::Auto,
    };
    DecoyPolicy {
        fooling,
        ttl: match env("ZRAY_DECOY_TTL").as_deref() {
            // The way the runtime does it: ask the probe, which answers on a
            // later call, and use what it learned.
            Some("auto") => learn_ttl(),
            other => other.and_then(|v| v.parse().ok()).unwrap_or(0),
        },
        ..DecoyPolicy::default()
    }
}

/// The hop limit [`zero_evasion::autottl`] learns for the testbed's server.
fn learn_ttl() -> u8 {
    let ip = target().expect("target").ip();
    let _ = zero_evasion::autottl::fake_ttl(ip);
    for _ in 0..80 {
        if let Some(ttl) = zero_evasion::autottl::fake_ttl(ip) {
            return ttl;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the probe never produced a TTL");
}

/// Send the hello behind a decoy (or plain, when `ZRAY_DECOY_FOOLING=none`) and
/// read it back from the echo server. The server only echoes what its kernel
/// handed it, so getting the real hello back whole is the proof that the decoy
/// segment never reached it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "runs only inside tests/netns/testbed.sh"]
async fn the_server_receives_only_the_real_hello_behind_a_decoy() {
    let Some(target) = target() else {
        eprintln!("skipped: not inside the netns testbed (ZRAY_NETNS_TARGET unset)");
        return;
    };
    let real = hello(REAL_NAME);
    let tcp = TcpStream::connect(target).await.expect("connect");
    tcp.set_nodelay(true).unwrap();
    let mode = env("ZRAY_DECOY_FOOLING").unwrap_or_default();
    let started = Instant::now();
    if mode == "none" {
        let mut plain = tcp;
        plain.write_all(&real).await.unwrap();
        echo_and_check(&mut plain, &real).await;
    } else {
        let mut stream = DecoyStream::new(tcp, policy());
        stream.write_all(&real).await.expect("write");
        stream.flush().await.unwrap();
        echo_and_check(&mut stream, &real).await;
    }
    eprintln!("hello echoed in {:?} (mode {mode})", started.elapsed());
}

async fn echo_and_check<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, real: &[u8]) {
    let mut echoed = vec![0u8; real.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("the server never echoed the hello")
        .expect("echo failed");
    assert_eq!(
        echoed,
        real,
        "the server received something other than the real hello (decoy name leaked: {})",
        String::from_utf8_lossy(&echoed).contains("speedtest")
    );
}

/// The ICMP probe measures the distance through the routers, and the TTL it
/// derives is the one that dies before the last of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "runs only inside tests/netns/testbed.sh"]
async fn autottl_measures_the_distance_through_four_routers() {
    let Some(target) = target() else {
        eprintln!("skipped: not inside the netns testbed (ZRAY_NETNS_TARGET unset)");
        return;
    };
    assert!(
        zero_evasion::autottl::supported(),
        "no unprivileged ICMP ping socket in the testbed"
    );
    let ip: IpAddr = target.ip();
    // The first ask starts the probe and answers nothing; a later one has it.
    assert_eq!(zero_evasion::autottl::fake_ttl(ip), None);
    let deadline = Instant::now() + Duration::from_secs(8);
    let learned = loop {
        if let Some(ttl) = zero_evasion::autottl::fake_ttl(ip) {
            break ttl;
        }
        assert!(Instant::now() < deadline, "the probe never produced a TTL");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    // Four routers: the reply arrives with TTL 60, so the server is four hops
    // away and the decoy is sent with three, which expires at the third router.
    assert_eq!(learned, 3, "the distance through four routers is four hops");
    println!("LEARNED_TTL={learned}");
}
