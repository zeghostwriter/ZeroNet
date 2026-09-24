//! The connect / select / switch flow, end to end against a real engine.
//!
//! The reported bug: after disconnecting, switching to another profile and
//! back reconnected on its own, without the connect control ever being
//! pressed. These drive the same [`ConnectionManager`] the app does, and
//! carry its decisions through to the real daemon, so a regression shows up
//! as an actual listener appearing on a port.

use std::time::Duration;

use zeronet_tui::connection::{ConnectionManager, EngineAction, Intent};
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

fn options(offset: u16) -> EngineOptions {
    let base = port_base() + offset;
    EngineOptions {
        socks_port: base,
        http_port: base + 1,
        ..EngineOptions::default()
    }
}

fn profile() -> String {
    serde_json::json!({
        "outbounds": [{"tag": "proxy", "protocol": "freedom"}]
    })
    .to_string()
}

async fn port_accepting(port: u16) -> bool {
    tokio::time::timeout(
        Duration::from_millis(300),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

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

/// Drive one decision through to the daemon, the way the app does.
async fn perform(daemon: &ZeroNetDaemon, action: EngineAction, opts: &EngineOptions) {
    match action {
        EngineAction::None => {}
        EngineAction::Connect(id) => {
            daemon
                .connect(profile(), format!("node-{id}"), opts.clone())
                .await
                .unwrap();
        }
        EngineAction::Switch(id) => {
            daemon
                .switch_node(profile(), format!("node-{id}"), opts.clone())
                .await
                .unwrap();
        }
        EngineAction::Disconnect => daemon.disconnect().await.unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browsing_profiles_while_offline_never_dials() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let daemon = ZeroNetDaemon::spawn();
    let opts = options(0);
    let mut cm = ConnectionManager::new();

    // The exact sequence from the report: connect, disconnect, switch away,
    // switch back.
    perform(&daemon, cm.select(1), &opts).await;
    perform(&daemon, cm.connect(), &opts).await;
    assert_eq!(
        await_status(
            &daemon,
            ConnectionStatus::Connected,
            Duration::from_secs(15)
        )
        .await,
        ConnectionStatus::Connected
    );
    assert!(port_accepting(opts.socks_port).await);

    perform(&daemon, cm.disconnect(), &opts).await;
    assert_eq!(
        await_status(
            &daemon,
            ConnectionStatus::Disconnected,
            Duration::from_secs(5)
        )
        .await,
        ConnectionStatus::Disconnected
    );

    // Switch to another profile and back. Neither may start an engine.
    perform(&daemon, cm.select(2), &opts).await;
    perform(&daemon, cm.select(1), &opts).await;
    perform(&daemon, cm.select(3), &opts).await;

    // Give any stray connect attempt time to bind before checking.
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert_eq!(
        daemon.status(),
        ConnectionStatus::Disconnected,
        "browsing the profile list reconnected on its own"
    );
    assert!(
        !port_accepting(opts.socks_port).await,
        "a proxy listener came back without the connect control being pressed"
    );
    assert_eq!(cm.intent(), Intent::Disconnected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn switching_while_connected_moves_the_tunnel() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let daemon = ZeroNetDaemon::spawn();
    let opts = options(2);
    let mut cm = ConnectionManager::new();

    perform(&daemon, cm.select(1), &opts).await;
    perform(&daemon, cm.connect(), &opts).await;
    assert_eq!(
        await_status(
            &daemon,
            ConnectionStatus::Connected,
            Duration::from_secs(15)
        )
        .await,
        ConnectionStatus::Connected
    );

    // Selecting a different profile while online is a server switch.
    let action = cm.select(2);
    assert_eq!(action, EngineAction::Switch(2));
    perform(&daemon, action, &opts).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let stats = daemon.status_receiver().borrow().clone();
        if stats.status == ConnectionStatus::Connected && stats.active_node_name == "node-2" {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "switch never settled: {stats:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(port_accepting(opts.socks_port).await);

    perform(&daemon, cm.disconnect(), &opts).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reselecting_the_running_profile_does_not_drop_the_tunnel() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let daemon = ZeroNetDaemon::spawn();
    let opts = options(4);
    let mut cm = ConnectionManager::new();

    perform(&daemon, cm.select(1), &opts).await;
    perform(&daemon, cm.connect(), &opts).await;
    assert_eq!(
        await_status(
            &daemon,
            ConnectionStatus::Connected,
            Duration::from_secs(15)
        )
        .await,
        ConnectionStatus::Connected
    );

    // Clicking the row you are already on is inert — no teardown, no redial.
    assert_eq!(cm.select(1), EngineAction::None);
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(daemon.status(), ConnectionStatus::Connected);
    assert!(
        port_accepting(opts.socks_port).await,
        "re-selecting the active profile tore the tunnel down"
    );

    perform(&daemon, cm.disconnect(), &opts).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_settings_change_while_offline_does_not_dial() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let daemon = ZeroNetDaemon::spawn();
    let opts = options(6);
    let mut cm = ConnectionManager::new();

    cm.select(1);
    // Toggling TUN or editing a port while offline must stay offline.
    perform(&daemon, cm.reapply(), &opts).await;
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert_eq!(daemon.status(), ConnectionStatus::Disconnected);
    assert!(!port_accepting(opts.socks_port).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_the_active_profile_takes_the_tunnel_down() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let daemon = ZeroNetDaemon::spawn();
    let opts = options(8);
    let mut cm = ConnectionManager::new();

    perform(&daemon, cm.select(7), &opts).await;
    perform(&daemon, cm.connect(), &opts).await;
    assert_eq!(
        await_status(
            &daemon,
            ConnectionStatus::Connected,
            Duration::from_secs(15)
        )
        .await,
        ConnectionStatus::Connected
    );

    // The user can no longer see this profile, so proxying through it would
    // be invisible traffic.
    let action = cm.on_profile_removed(7);
    assert_eq!(action, EngineAction::Disconnect);
    perform(&daemon, action, &opts).await;

    assert_eq!(
        await_status(
            &daemon,
            ConnectionStatus::Disconnected,
            Duration::from_secs(5)
        )
        .await,
        ConnectionStatus::Disconnected
    );

    let mut released = false;
    for _ in 0..40 {
        if !port_accepting(opts.socks_port).await {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(released, "the deleted profile's listener stayed up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn toggling_twice_leaves_no_engine_running() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let daemon = ZeroNetDaemon::spawn();
    let opts = options(10);
    let mut cm = ConnectionManager::new();

    cm.select(1);
    perform(&daemon, cm.toggle(), &opts).await;
    assert_eq!(
        await_status(
            &daemon,
            ConnectionStatus::Connected,
            Duration::from_secs(15)
        )
        .await,
        ConnectionStatus::Connected
    );

    perform(&daemon, cm.toggle(), &opts).await;
    assert_eq!(
        await_status(
            &daemon,
            ConnectionStatus::Disconnected,
            Duration::from_secs(5)
        )
        .await,
        ConnectionStatus::Disconnected
    );

    let mut released = false;
    for _ in 0..40 {
        if !port_accepting(opts.socks_port).await {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(released, "toggling off left a listener behind");
    assert!(!cm.wants_connection());
}
