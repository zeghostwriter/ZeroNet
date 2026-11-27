//! The Tor outbound.
//!
//! Without the `tor` feature the outbound must still parse and then refuse to
//! connect with a sentence that says why; a silent hang or a vague "no
//! endpoint" would send the user hunting in the wrong place. With the feature,
//! the live test (ignored by default: it needs the real Tor network and can
//! take minutes on a cold start) opens a circuit to Tor Project's own check
//! site through the outbound and reads the answer back. The site now answers
//! plain HTTP with a redirect to HTTPS, and a redirect that names the site is
//! proof enough that the stream reached it over a real circuit.

use zero_core::{Address, Destination};

fn tor_outbound() -> zero_config::Outbound {
    zero_config::parse_link("tor://#Tor").unwrap().outbound
}

#[cfg(not(feature = "tor"))]
#[tokio::test]
async fn a_build_without_tor_support_says_so() {
    let destination = Destination::tcp(Address::domain("example.com"), 443);
    let error = zero_runtime::outbound::connect(&tor_outbound(), &destination)
        .await
        .err()
        .expect("connecting through Tor cannot work in this build");
    let text = error.to_string();
    assert!(text.contains("without Tor support"), "{text}");
}

#[cfg(feature = "tor")]
#[tokio::test]
async fn tor_refuses_udp() {
    let destination = Destination::new(Address::domain("example.com"), 53, zero_core::Network::Udp);
    let error = zero_runtime::outbound::connect(&tor_outbound(), &destination)
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("TCP only"), "{error}");
}

/// `cargo test -p zero-runtime --features tor --test tor_outbound -- --ignored --nocapture`
#[cfg(feature = "tor")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the real Tor network"]
async fn live_check_reports_we_are_on_tor() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // `ZRAY_TEST_LOG=tor_chanmgr=debug,tor_circmgr=debug` shows why circuits fail.
    if let Ok(filter) = std::env::var("ZRAY_TEST_LOG") {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_test_writer()
            .try_init();
    }

    let dir = std::env::temp_dir().join("zray-tor-live-test");
    let mut outbound = tor_outbound();
    if let zero_config::OutboundProtocol::Tor(tor) = &mut outbound.protocol {
        tor.data_dir = Some(dir.to_string_lossy().into());
    }
    let started = std::time::Instant::now();
    let destination = Destination::tcp(Address::domain("check.torproject.org"), 80);
    let mut stream = zero_runtime::outbound::connect(&outbound, &destination)
        .await
        .unwrap_or_else(|error| panic!("could not reach Tor: {error}"));
    println!("stream open after {:?}", started.elapsed());
    stream
        .write_all(
            b"GET /api/ip HTTP/1.1\r\nHost: check.torproject.org\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    // Arti buffers writes until they are flushed; without this the request
    // never leaves and the read below sees an empty reply.
    stream.flush().await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    println!("{text}");
    assert!(
        text.starts_with("HTTP/1.1 301")
            && text.contains("Location: https://check.torproject.org/"),
        "{text}"
    );
}
