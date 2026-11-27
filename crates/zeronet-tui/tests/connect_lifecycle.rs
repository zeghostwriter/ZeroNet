//! End-to-end coverage for the connect / disconnect / switch lifecycle.
//!
//! These exercise the bug that made the connect button appear not to work:
//! the engine's inbound listeners are opened with `SO_REUSEPORT`, so a
//! "disconnect" that only aborted the run task left them bound. The next
//! connect then bound the *same* ports alongside the stale engine and the
//! kernel load-balanced traffic between them — meaning the node the user
//! selected only carried some of their traffic, and disconnecting carried on
//! proxying.

use std::time::Duration;

use zeronet_tui::daemon::{ConnectionStatus, EngineOptions, ZeroNetDaemon};

/// A port block that the kernel will not hand out to somebody else.
///
/// The first version of these tests used fixed ports in the 39000s, which
/// sits inside Linux's default ephemeral range (32768-60999). Any outbound
/// connection made anywhere on the machine — including by other tests in the
/// same `cargo test --workspace` run — can transiently occupy one, and the
/// engine then fails to bind with "address already in use" for reasons that
/// have nothing to do with the code under test.
///
/// Ports are therefore taken from below the ephemeral range, and spread by
/// process id so two test binaries running concurrently never overlap.
fn port_base() -> u16 {
    const WINDOW_START: u16 = 20_000;
    const WINDOW_SLOTS: u16 = 600;
    const PORTS_PER_TEST: u16 = 16;

    let slot = (std::process::id() % WINDOW_SLOTS as u32) as u16;
    WINDOW_START + slot * PORTS_PER_TEST
}

/// Ports for one test, clear of the 10808/10809 defaults a developer's
/// running client would be using.
fn ports(offset: u16) -> (u16, u16) {
    let base = port_base() + offset;
    (base, base + 1)
}

fn options_at(offset: u16) -> EngineOptions {
    let (socks_port, http_port) = ports(offset);
    EngineOptions {
        socks_port,
        http_port,
        ..EngineOptions::default()
    }
}

/// A minimal but complete profile: one reachable-looking outbound, no TUN.
fn sample_profile() -> String {
    serde_json::json!({
        "outbounds": [{
            "tag": "proxy",
            "protocol": "freedom"
        }]
    })
    .to_string()
}

async fn port_is_accepting(port: u16) -> bool {
    tokio::time::timeout(
        Duration::from_millis(400),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

/// Poll until the daemon reaches `wanted`, or give up.
async fn await_status(
    daemon: &ZeroNetDaemon,
    wanted: ConnectionStatus,
    timeout: Duration,
) -> ConnectionStatus {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let status = daemon.status();
        if status == wanted || tokio::time::Instant::now() >= deadline {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_reports_connected_only_once_listeners_are_bound() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let daemon = ZeroNetDaemon::spawn();

    daemon
        .connect(sample_profile(), "test-node".into(), options_at(0))
        .await
        .expect("connect command accepted");

    let status = await_status(
        &daemon,
        ConnectionStatus::Connected,
        Duration::from_secs(15),
    )
    .await;
    assert_eq!(
        status,
        ConnectionStatus::Connected,
        "daemon never reached Connected; last error: {:?}",
        daemon.status_receiver().borrow().error_msg
    );

    // "Connected" has to mean the proxy is actually usable, not merely that a
    // task was spawned.
    assert!(
        port_is_accepting(ports(0).0).await,
        "status said Connected but the SOCKS port is not accepting"
    );

    let stats = daemon.status_receiver().borrow().clone();
    assert_eq!(stats.active_node_name, "test-node");
    assert!(stats.error_msg.is_none());

    daemon.disconnect().await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnect_actually_releases_the_listeners() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let daemon = ZeroNetDaemon::spawn();

    let opts = options_at(2);

    daemon
        .connect(sample_profile(), "test-node".into(), opts.clone())
        .await
        .unwrap();
    let status = await_status(
        &daemon,
        ConnectionStatus::Connected,
        Duration::from_secs(15),
    )
    .await;
    assert_eq!(status, ConnectionStatus::Connected);
    assert!(port_is_accepting(opts.socks_port).await);

    daemon.disconnect().await.unwrap();
    let status = await_status(
        &daemon,
        ConnectionStatus::Disconnected,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(status, ConnectionStatus::Disconnected);

    // This is the regression. Aborting the run task used to leave the accept
    // loops alive and the socket bound; the engine now owns a runtime that is
    // shut down, which closes every listener it opened.
    let mut released = false;
    for _ in 0..40 {
        if !port_is_accepting(opts.socks_port).await {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        released,
        "port {} was still accepting after disconnect — the old engine's listeners leaked",
        opts.socks_port
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn switching_nodes_retires_the_previous_engine() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let daemon = ZeroNetDaemon::spawn();

    let opts = options_at(4);

    daemon
        .connect(sample_profile(), "node-a".into(), opts.clone())
        .await
        .unwrap();
    assert_eq!(
        await_status(
            &daemon,
            ConnectionStatus::Connected,
            Duration::from_secs(15)
        )
        .await,
        ConnectionStatus::Connected
    );

    daemon
        .switch_node(sample_profile(), "node-b".into(), opts.clone())
        .await
        .unwrap();

    // Wait for the switch to settle on the new node's name.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let stats = daemon.status_receiver().borrow().clone();
        if (stats.status == ConnectionStatus::Connected && stats.active_node_name == "node-b")
            || tokio::time::Instant::now() >= deadline
        {
            assert_eq!(stats.status, ConnectionStatus::Connected, "{stats:?}");
            assert_eq!(stats.active_node_name, "node-b");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Exactly one engine should hold the port after the switch. If the old
    // one had leaked, both would be bound via SO_REUSEPORT and the kernel
    // would split traffic between the node the user left and the one they
    // chose — the symptom that made switching look like it did nothing.
    assert!(port_is_accepting(opts.socks_port).await);

    daemon.disconnect().await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnecting_to_the_same_ports_succeeds() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let daemon = ZeroNetDaemon::spawn();

    let opts = options_at(6);

    for round in 0..3 {
        daemon
            .connect(sample_profile(), format!("node-{round}"), opts.clone())
            .await
            .unwrap();
        let status = await_status(
            &daemon,
            ConnectionStatus::Connected,
            Duration::from_secs(15),
        )
        .await;
        assert_eq!(
            status,
            ConnectionStatus::Connected,
            "round {round} failed to connect: {:?}",
            daemon.status_receiver().borrow().error_msg
        );
        assert!(
            port_is_accepting(opts.socks_port).await,
            "round {round}: proxy not reachable"
        );

        daemon.disconnect().await.unwrap();
        await_status(
            &daemon,
            ConnectionStatus::Disconnected,
            Duration::from_secs(5),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(600)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_broken_profile_reports_an_error_instead_of_claiming_success() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let daemon = ZeroNetDaemon::spawn();

    daemon
        .connect("this is not a config".into(), "bad".into(), options_at(0))
        .await
        .unwrap();

    let status = await_status(&daemon, ConnectionStatus::Error, Duration::from_secs(10)).await;
    assert_eq!(status, ConnectionStatus::Error);

    // The reason has to reach the UI, or the user sees a connect that simply
    // does nothing.
    let stats = daemon.status_receiver().borrow().clone();
    assert!(
        stats.error_msg.is_some(),
        "a failed connect must carry an explanation"
    );
    assert!(stats.revision > 0, "the transition must bump the revision");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_port_already_taken_is_reported_rather_than_silently_shared() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Hold the SOCKS port with a plain listener that does *not* set
    // SO_REUSEPORT, so the engine's bind genuinely fails.
    let blocker = tokio::net::TcpListener::bind(("127.0.0.1", ports(8).0))
        .await
        .expect("test listener binds");
    let blocked_port = blocker.local_addr().unwrap().port();

    let daemon = ZeroNetDaemon::spawn();
    daemon
        .connect(
            sample_profile(),
            "blocked".into(),
            EngineOptions {
                socks_port: blocked_port,
                http_port: ports(8).1,
                ..options_at(8)
            },
        )
        .await
        .unwrap();

    let status = await_status(&daemon, ConnectionStatus::Error, Duration::from_secs(15)).await;
    assert_eq!(
        status,
        ConnectionStatus::Error,
        "binding an occupied port must fail loudly, not report Connected"
    );
    drop(blocker);
}
