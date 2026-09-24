//! Headless networking daemon orchestrator for ZeroNet TUI.
//!
//! Owns the lifetime of the Zray-Core engine: starting it, proving it is
//! actually listening before claiming to be connected, hot-swapping nodes,
//! and — the part that used to be broken — genuinely tearing it down.
//!
//! ## Why each engine gets its own runtime
//!
//! `Server::run` spawns a detached task per inbound listener. Aborting the
//! handle that `run` returns drops only the outer future; the accept loops it
//! spawned keep running and keep their sockets bound. Because the listeners
//! are opened with `SO_REUSEPORT`, the *next* connect then binds the same
//! ports successfully and the kernel load-balances new connections across
//! both engines — so roughly half the traffic keeps flowing through the node
//! the user just switched away from, and "disconnect" disconnects nothing.
//!
//! Each engine therefore runs on its own Tokio runtime on its own thread.
//! Shutting that runtime down drops every task it owns, listeners included,
//! which is the only reliable way to release the ports without reaching into
//! `zero-runtime`'s internals.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, watch};
use zero_core::GenerationId;

/// How long to wait for every inbound listener to bind before reporting the
/// connection as failed.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);
/// Grace period given to a retiring engine's runtime to wind down.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Error,
}

#[derive(Debug, Clone)]
pub struct DaemonStats {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub upload_speed_bps: u64,
    pub download_speed_bps: u64,
    pub active_connections: u64,
    pub active_node_name: String,
    pub latency_ms: Option<f64>,
    pub status: ConnectionStatus,
    pub error_msg: Option<String>,
    /// Whether the TUN interface came up. A connection can be live in proxy
    /// mode while TUN failed for want of privileges, and the UI needs to say
    /// so rather than implying the whole system is tunnelled.
    pub tun_active: bool,
    /// Incremented on every status transition, so the UI can tell a new
    /// failure from a stale one it has already reported.
    pub revision: u64,
}

impl Default for DaemonStats {
    fn default() -> Self {
        Self {
            upload_bytes: 0,
            download_bytes: 0,
            upload_speed_bps: 0,
            download_speed_bps: 0,
            active_connections: 0,
            active_node_name: "None".into(),
            latency_ms: None,
            status: ConnectionStatus::Disconnected,
            error_msg: None,
            tun_active: false,
            revision: 0,
        }
    }
}

/// Runtime knobs that the engine config is built from.
///
/// These used to be hard-coded to 10808/10809/1500 inside the config builder,
/// so changing a port in Settings had no effect on what actually got bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineOptions {
    pub tun_mode: bool,
    pub socks_port: u16,
    pub http_port: u16,
    pub tun_mtu: u16,
    /// Interface name for the TUN inbound.
    pub tun_device_name: String,
    pub tun_auto_route: bool,
    pub tun_strict_route: bool,
    /// Bind the local inbounds to every interface rather than loopback.
    pub allow_lan: bool,
    /// Offer UDP associate on the SOCKS inbound.
    pub udp_enabled: bool,
    pub sniffing_enabled: bool,
    /// A sniffed domain steers routing without rewriting the destination.
    pub sniffing_route_only: bool,
    pub log_level: String,
    /// uTLS ClientHello shape for TLS and REALITY outbounds. Empty leaves
    /// whatever the profile itself asked for.
    pub utls_fingerprint: String,
    pub mux_enabled: bool,
    pub mux_concurrency: u16,
    /// Split the ClientHello across packets.
    pub fragment_enabled: bool,
    /// Bytes per fragment. Clamped into a range the engine accepts at the
    /// boundary; see [`EngineOptions::fragment_length_range`].
    pub tls_fragment_size: u16,
    /// Seconds of silence before a carrier no-op is emitted. `0` is off.
    pub keepalive_interval_secs: u64,
    /// Named TCP congestion algorithm. Empty leaves the system default.
    pub tcp_congestion: String,
    /// Resolver placed ahead of every other. Empty leaves the preset's set.
    pub custom_dns: String,
    /// Rank scanner-clean CDN edges through the observatory.
    pub clean_ip_rotation: bool,
    /// Scanner-measured edge candidates as `ip:port`.
    pub clean_ip_candidates: Vec<String>,
    pub domain_strategy: String,
    pub ipv6_enabled: bool,
    /// Whether a TUN device can actually be created for this engine — either
    /// the process holds `CAP_NET_ADMIN`, or a privileged helper has already
    /// handed a descriptor over (see `crate::elevate`).
    ///
    /// Carried here so the daemon can report `tun_active` honestly. Guessing
    /// it from the engine's failure counter meant an unprivileged run showed
    /// a green "TUN ON" while nothing was tunnelled.
    pub tun_ready: bool,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            tun_mode: false,
            socks_port: 10808,
            http_port: 10809,
            tun_mtu: 1500,
            tun_device_name: "zeronet0".into(),
            tun_auto_route: true,
            tun_strict_route: false,
            allow_lan: false,
            udp_enabled: true,
            sniffing_enabled: true,
            sniffing_route_only: false,
            log_level: "warning".into(),
            utls_fingerprint: String::new(),
            mux_enabled: false,
            mux_concurrency: 8,
            fragment_enabled: false,
            tls_fragment_size: 150,
            keepalive_interval_secs: 30,
            tcp_congestion: String::new(),
            custom_dns: String::new(),
            clean_ip_rotation: false,
            clean_ip_candidates: Vec::new(),
            domain_strategy: "IPIfNonMatch".into(),
            ipv6_enabled: true,
            tun_ready: false,
        }
    }
}

impl EngineOptions {
    pub fn with_tun(mut self, tun_mode: bool) -> Self {
        self.tun_mode = tun_mode;
        self
    }

    /// Whether strict routing can actually be asked for.
    ///
    /// The engine refuses `strictRoute` without `autoRoute` — strict routing
    /// blocks traffic that tries to leave around the tunnel, which is
    /// meaningless when no routes were installed. Clamping here keeps that
    /// combination from reaching the compiler as a hard error the user would
    /// see as "connect failed" with no clue which toggle caused it.
    pub fn strict_route_effective(&self) -> bool {
        self.tun_auto_route && self.tun_strict_route
    }

    /// Address the local inbounds bind to.
    ///
    /// Loopback unless the user asked for LAN access: binding a wide-open
    /// proxy to every interface by default would hand anyone on the same
    /// network a free exit node.
    pub fn listen_address(&self) -> &'static str {
        if self.allow_lan {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        }
    }

    /// The fragment length range in force, in bytes.
    ///
    /// The row stores one number but the engine wants a range, so the range
    /// is centred on it (`size ± size/3`, which turns the historic 150 into
    /// exactly "100-200"). Clamped here, at the boundary, rather than trusted
    /// from the dialog: an out-of-range value would make the whole config
    /// fail to parse, and the user would see only "connect failed".
    pub fn fragment_length_range(&self) -> (u32, u32) {
        let size = u32::from(self.tls_fragment_size).clamp(20, 1500);
        let min = (size - size / 3).min(1400);
        let max = (size + size / 3).min(1400);
        (min.max(1), max.max(min))
    }

    /// Keepalive `(idle, lifetime)` in seconds, or `None` when off.
    ///
    /// The engine refuses `lifetime <= idle` — the carrier would retire before
    /// it ever probed — so the lifetime is always at least `2 × idle` and at
    /// least 120s.
    pub fn keepalive_shape(&self) -> Option<(u64, u64)> {
        if self.keepalive_interval_secs == 0 {
            return None;
        }
        let idle = self.keepalive_interval_secs;
        Some((idle, std::cmp::max(120, idle * 2)))
    }
}

pub struct ZeroNetDaemon {
    status_receiver: watch::Receiver<DaemonStats>,
    command_sender: mpsc::Sender<DaemonCommand>,
    running: Arc<AtomicBool>,
}

pub enum DaemonCommand {
    Connect {
        config_json: String,
        node_name: String,
        options: EngineOptions,
    },
    Disconnect,
    SwitchNode {
        config_json: String,
        node_name: String,
        options: EngineOptions,
    },
    /// Stop the engine, wait until its ports and TUN are released, then
    /// acknowledge and end the daemon.
    Shutdown(tokio::sync::oneshot::Sender<()>),
    /// Stop the engine, wait until its ports and TUN are released, then
    /// acknowledge. The daemon keeps running.
    Stop(tokio::sync::oneshot::Sender<()>),
}

/// A live engine and the runtime that owns every task it spawned.
struct RunningEngine {
    server: Arc<zero_runtime::Server>,
    /// `None` once handed to [`RunningEngine::stop`].
    runtime: Option<tokio::runtime::Runtime>,
    /// Fires when `Server::run` returns — which, after the listeners are up,
    /// means the engine died underneath a connection shown as live.
    exited: tokio::sync::oneshot::Receiver<Option<String>>,
}

impl RunningEngine {
    /// Shut the engine down for real, releasing every bound port.
    ///
    /// The runtime is handed to a plain OS thread because dropping a Tokio
    /// runtime from inside an async context panics, and the daemon loop that
    /// calls this is itself async. The returned receiver fires once the
    /// shutdown has finished, so the next engine is only started after the
    /// previous one's listeners (bound with `SO_REUSEPORT`) and TUN device
    /// are gone — starting it earlier split traffic across both engines for
    /// the length of the grace period and could collide on the device name.
    fn stop(mut self) -> tokio::sync::oneshot::Receiver<()> {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        if let Some(runtime) = self.runtime.take() {
            std::thread::spawn(move || {
                runtime.shutdown_timeout(SHUTDOWN_GRACE);
                let _ = done_tx.send(());
            });
        } else {
            let _ = done_tx.send(());
        }
        done_rx
    }

    /// [`stop`](Self::stop), and wait for it (bounded).
    async fn stop_and_wait(self) {
        let done = self.stop();
        let _ = tokio::time::timeout(SHUTDOWN_GRACE + Duration::from_secs(1), done).await;
    }

    /// Whether `Server::run` has returned, and why.
    fn exit_reason(&mut self) -> Option<String> {
        match self.exited.try_recv() {
            Ok(Some(reason)) => Some(reason),
            Ok(None) => Some("the engine stopped unexpectedly".to_string()),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                Some("the engine task ended unexpectedly".to_string())
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => None,
        }
    }
}

impl Drop for RunningEngine {
    /// Dropped without [`stop`](Self::stop) — a cancelled start, or the
    /// daemon task being torn down with the process — the runtime still
    /// must not be dropped in place: inside an async context that panics,
    /// and under `panic = "abort"` a panic is the end of the process.
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            std::thread::spawn(move || runtime.shutdown_timeout(SHUTDOWN_GRACE));
        }
    }
}

/// Fold every command already queued behind `first` into the one that
/// matters: the latest, or a shutdown if one is waiting.
///
/// Rapid connect/disconnect clicks used to be replayed one by one, each
/// connect building and verifying a whole engine (up to the listen timeout)
/// only for the next command to tear it down again.
fn coalesce(first: DaemonCommand, queue: &mut mpsc::Receiver<DaemonCommand>) -> DaemonCommand {
    let mut latest = first;
    while let Ok(next) = queue.try_recv() {
        if matches!(latest, DaemonCommand::Shutdown(_)) {
            // A shutdown is final; drop anything queued after it.
            continue;
        }
        latest = next;
    }
    latest
}

/// Stops the engine from anywhere; see [`ZeroNetDaemon::stopper`].
#[derive(Clone)]
pub struct DaemonStopper(mpsc::Sender<DaemonCommand>);

impl DaemonStopper {
    /// Stop the engine and wait until its ports and TUN are released.
    pub async fn stop(&self) {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        if self.0.send(DaemonCommand::Stop(ack_tx)).await.is_err() {
            return;
        }
        let _ = tokio::time::timeout(SHUTDOWN_GRACE + Duration::from_secs(2), ack_rx).await;
    }
}

impl ZeroNetDaemon {
    pub fn spawn() -> Self {
        let (status_tx, status_rx) = watch::channel(DaemonStats::default());
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<DaemonCommand>(32);
        let running = Arc::new(AtomicBool::new(true));

        let runner_flag = Arc::clone(&running);
        let status_sender = status_tx.clone();

        tokio::spawn(async move {
            let mut engine: Option<RunningEngine> = None;
            let mut last_up = 0u64;
            let mut last_down = 0u64;
            let mut tick_interval = tokio::time::interval(Duration::from_millis(500));
            tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // A command that arrived while an engine was starting, and
            // superseded that start.
            let mut pending: Option<DaemonCommand> = None;

            while runner_flag.load(Ordering::Relaxed) {
                let cmd = match pending.take() {
                    Some(cmd) => cmd,
                    None => tokio::select! {
                        maybe_cmd = cmd_rx.recv() => {
                            let Some(cmd) = maybe_cmd else { break };
                            cmd
                        }
                        _ = tick_interval.tick() => {
                            let Some(running_engine) = engine.as_mut() else { continue };
                            if let Some(reason) = running_engine.exit_reason() {
                                // The engine is gone but the UI still says
                                // connected, with the desktop and TUN pointed
                                // at listeners that no longer exist.
                                tracing::error!(error = %reason, "engine exited");
                                if let Some(dead) = engine.take() {
                                    dead.stop_and_wait().await;
                                }
                                update(&status_sender, |st| {
                                    st.status = ConnectionStatus::Error;
                                    st.error_msg = Some(reason.clone());
                                    st.tun_active = false;
                                    st.upload_speed_bps = 0;
                                    st.download_speed_bps = 0;
                                    st.active_connections = 0;
                                });
                                continue;
                            }
                            let snapshot = running_engine.server.stats.snapshot();
                            let up_diff = snapshot.uploaded.saturating_sub(last_up);
                            let down_diff = snapshot.downloaded.saturating_sub(last_down);
                            last_up = snapshot.uploaded;
                            last_down = snapshot.downloaded;

                            // Replaced in place rather than through `update`,
                            // because throughput ticks are not status
                            // transitions and must not bump the revision the
                            // UI uses to detect new errors. Only published
                            // when something changed, so an idle tunnel does
                            // not wake the UI twice a second.
                            status_sender.send_if_modified(|st| {
                                let next = (
                                    snapshot.uploaded,
                                    snapshot.downloaded,
                                    up_diff * 2, // 500 ms window
                                    down_diff * 2,
                                    snapshot.succeeded.saturating_sub(snapshot.failed),
                                );
                                let current = (
                                    st.upload_bytes,
                                    st.download_bytes,
                                    st.upload_speed_bps,
                                    st.download_speed_bps,
                                    st.active_connections,
                                );
                                if next == current {
                                    return false;
                                }
                                st.upload_bytes = next.0;
                                st.download_bytes = next.1;
                                st.upload_speed_bps = next.2;
                                st.download_speed_bps = next.3;
                                st.active_connections = next.4;
                                true
                            });
                            continue;
                        }
                    },
                };

                match coalesce(cmd, &mut cmd_rx) {
                    DaemonCommand::Connect {
                        config_json,
                        node_name,
                        options,
                    }
                    | DaemonCommand::SwitchNode {
                        config_json,
                        node_name,
                        options,
                    } => {
                        // Retire the previous engine first and in full.
                        // Starting the new one while the old listeners are
                        // still bound is exactly the split-traffic failure
                        // described at the top of this module.
                        if let Some(old) = engine.take() {
                            old.stop_and_wait().await;
                        }
                        last_up = 0;
                        last_down = 0;

                        update(&status_sender, |st| {
                            st.status = ConnectionStatus::Connecting;
                            st.active_node_name = node_name.clone();
                            st.error_msg = None;
                            st.tun_active = false;
                            st.upload_speed_bps = 0;
                            st.download_speed_bps = 0;
                        });

                        // A newer command cancels this start rather than
                        // queueing behind it: a disconnect clicked while a
                        // node is still being dialled must not wait out the
                        // listen timeout first.
                        let outcome = tokio::select! {
                            outcome = start_engine(&config_json, &options) => outcome,
                            next = cmd_rx.recv() => {
                                match next {
                                    Some(next) => pending = Some(next),
                                    None => break,
                                }
                                continue;
                            }
                        };
                        match outcome {
                            Ok(started) => {
                                let tun_active = started.tun_active;
                                engine = Some(started.engine);
                                update(&status_sender, |st| {
                                    st.status = ConnectionStatus::Connected;
                                    st.active_node_name = node_name.clone();
                                    st.error_msg = None;
                                    st.tun_active = tun_active;
                                });
                            }
                            Err(err) => {
                                let msg = format!("{err:#}");
                                tracing::error!(error = %msg, "engine failed to start");
                                update(&status_sender, |st| {
                                    st.status = ConnectionStatus::Error;
                                    st.error_msg = Some(msg.clone());
                                    st.tun_active = false;
                                });
                            }
                        }
                    }
                    stop @ (DaemonCommand::Disconnect | DaemonCommand::Stop(_)) => {
                        let ack = match stop {
                            DaemonCommand::Stop(ack) => Some(ack),
                            _ => None,
                        };
                        if let Some(old) = engine.take() {
                            old.stop_and_wait().await;
                        }
                        last_up = 0;
                        last_down = 0;
                        update(&status_sender, |st| {
                            st.status = ConnectionStatus::Disconnected;
                            st.error_msg = None;
                            st.tun_active = false;
                            st.upload_speed_bps = 0;
                            st.download_speed_bps = 0;
                            st.active_connections = 0;
                        });
                        if let Some(ack) = ack {
                            let _ = ack.send(());
                        }
                    }
                    DaemonCommand::Shutdown(ack) => {
                        if let Some(old) = engine.take() {
                            old.stop_and_wait().await;
                        }
                        update(&status_sender, |st| {
                            st.status = ConnectionStatus::Disconnected;
                            st.error_msg = None;
                            st.tun_active = false;
                            st.upload_speed_bps = 0;
                            st.download_speed_bps = 0;
                            st.active_connections = 0;
                        });
                        let _ = ack.send(());
                        return;
                    }
                }
            }

            if let Some(old) = engine.take() {
                old.stop_and_wait().await;
            }
        });

        Self {
            status_receiver: status_rx,
            command_sender: cmd_tx,
            running,
        }
    }

    pub fn status_receiver(&self) -> watch::Receiver<DaemonStats> {
        self.status_receiver.clone()
    }

    pub fn status(&self) -> ConnectionStatus {
        self.status_receiver.borrow().status
    }

    pub async fn connect(
        &self,
        config_json: String,
        node_name: String,
        options: EngineOptions,
    ) -> Result<()> {
        self.command_sender
            .send(DaemonCommand::Connect {
                config_json,
                node_name,
                options,
            })
            .await
            .context("sending connect command")
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.command_sender
            .send(DaemonCommand::Disconnect)
            .await
            .context("sending disconnect command")
    }

    /// Stop the engine and wait until it has actually released its ports
    /// and TUN device, then end the daemon.
    ///
    /// For the exit path: [`disconnect`](Self::disconnect) only queues the
    /// request, and a process that exits straight after it can leave the
    /// engine's route changes behind. Bounded, so a wedged engine cannot
    /// hold the exit hostage.
    pub async fn shutdown(&self) {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        if self
            .command_sender
            .send(DaemonCommand::Shutdown(ack_tx))
            .await
            .is_err()
        {
            return;
        }
        let _ = tokio::time::timeout(SHUTDOWN_GRACE + Duration::from_secs(2), ack_rx).await;
    }

    /// Stop the engine and wait until it has released its ports and TUN
    /// descriptor. Needed before a new TUN device with the same name can be
    /// created: the kernel keeps the old one alive while any descriptor to
    /// it is open.
    pub async fn stop(&self) {
        self.stopper().stop().await;
    }

    /// A handle that can [`stop`](Self::stop) the engine from a task that
    /// outlives this borrow.
    pub fn stopper(&self) -> DaemonStopper {
        DaemonStopper(self.command_sender.clone())
    }

    pub async fn switch_node(
        &self,
        config_json: String,
        node_name: String,
        options: EngineOptions,
    ) -> Result<()> {
        self.command_sender
            .send(DaemonCommand::SwitchNode {
                config_json,
                node_name,
                options,
            })
            .await
            .context("sending switch node command")
    }
}

impl Drop for ZeroNetDaemon {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Apply a status transition and bump the revision counter.
fn update(sender: &watch::Sender<DaemonStats>, f: impl FnOnce(&mut DaemonStats)) {
    let mut st = sender.borrow().clone();
    f(&mut st);
    st.revision = st.revision.wrapping_add(1);
    let _ = sender.send(st);
}

struct StartedEngine {
    engine: RunningEngine,
    tun_active: bool,
}

/// Build, launch and *verify* an engine.
///
/// The previous implementation reported success the moment the server task
/// was spawned, so a config that could not bind its ports still showed as
/// connected. This waits for `Server::wait_until_listening`, races it against
/// the run task exiting early, and gives up after [`LISTEN_TIMEOUT`].
async fn start_engine(raw_config: &str, options: &EngineOptions) -> Result<StartedEngine> {
    let effective_json = prepare_runnable_config_with(raw_config, options)?;

    let mut configs = zero_config::parse_config_array(&effective_json)
        .map_err(|e| anyhow::anyhow!("config parse error: {e}"))?;
    if configs.is_empty() {
        anyhow::bail!("no usable outbound in this profile");
    }
    let (_, cfg, _) = configs.remove(0);

    let generation = zero_config::RuntimeGeneration::compile(cfg, GenerationId(1))
        .map_err(|e| anyhow::anyhow!("compilation error: {e}"))?;

    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("zeronet-engine")
        .build()
        .context("building engine runtime")?;

    // `run` reports a bind failure by returning early; ferry that back so the
    // user sees "address already in use" instead of a silent non-connection.
    // The same channel reports a later exit to the daemon loop.
    let (err_tx, mut err_rx) = tokio::sync::oneshot::channel::<Option<String>>();
    let run_server = Arc::clone(&server);
    runtime.spawn(async move {
        let outcome = match run_server.run().await {
            Ok(()) => None,
            Err(e) => Some(e.to_string()),
        };
        let _ = err_tx.send(outcome);
    });

    // If this start is cancelled by a newer command, dropping the future
    // drops `engine`, whose `Drop` retires the runtime safely instead of
    // leaking its listeners.
    let mut engine = RunningEngine {
        server: Arc::clone(&server),
        runtime: Some(runtime),
        exited: tokio::sync::oneshot::channel().1,
    };

    // `wait_until_listening` never resolves if `run` failed before binding, so
    // it is raced against both the run result and a hard timeout.
    let listening = {
        let server = Arc::clone(&server);
        async move { server.wait_until_listening().await }
    };

    let failure = tokio::select! {
        () = listening => None,
        early = &mut err_rx => Some(match early {
            Ok(Some(msg)) => msg,
            Ok(None) => "engine exited before accepting connections".to_string(),
            Err(_) => "engine task ended unexpectedly".to_string(),
        }),
        _ = tokio::time::sleep(LISTEN_TIMEOUT) => Some(format!(
            "timed out after {}s waiting for inbound listeners",
            LISTEN_TIMEOUT.as_secs()
        )),
    };
    if let Some(reason) = failure {
        // Waited for, so a retry right after the failure does not race the
        // half-started engine for its ports.
        engine.stop_and_wait().await;
        anyhow::bail!("{reason}");
    }
    engine.exited = err_rx;

    // TUN comes up alongside the proxy listeners and is allowed to fail on its
    // own — an unprivileged run still gets a working SOCKS/HTTP proxy. Report
    // which of the two actually happened so the UI can be honest about it: a
    // green "TUN ON" over untunnelled traffic is the one lie this client must
    // not tell.
    let tun_active = options.tun_mode && options.tun_ready;

    Ok(StartedEngine { engine, tun_active })
}

/// Check that a stored profile can actually be run.
///
/// Profiles reach the database from several routes — pasted JSON, a scanner
/// retarget, an older build — and nothing used to verify them. An unusable
/// one sat in the list looking normal until connect time, when it surfaced a
/// raw engine message like `outbounds[0].settings.vnext is required for
/// vless` with no hint of what to do about it.
///
/// Validation now happens on import, and the list marks anything that fails.
pub fn validate_profile(raw_config: &str, options: &EngineOptions) -> Result<(), String> {
    let runnable = prepare_runnable_config_with(raw_config, options)
        .map_err(|e| describe_config_error(&e.to_string()))?;

    let mut parsed = zero_config::parse_config_array(&runnable)
        .map_err(|e| describe_config_error(&e.to_string()))?;
    if parsed.is_empty() {
        return Err("this profile contains no usable outbound".into());
    }

    let (_, cfg, _) = parsed.remove(0);
    zero_config::RuntimeGeneration::compile(cfg, GenerationId(1))
        .map(|_| ())
        .map_err(|e| describe_config_error(&e.to_string()))
}

/// Turn an engine parse error into something a user can act on.
///
/// The engine's messages name JSON paths, which is right for a config file
/// and useless in a profile list.
pub fn describe_config_error(raw: &str) -> String {
    let lowered = raw.to_ascii_lowercase();

    if lowered.contains("vnext is required") || lowered.contains("servers is required") {
        return "the profile has no server details. Re-import it from its share link".into();
    }
    if lowered.contains("no usable") || lowered.contains("no outbound") {
        return "the profile has no proxy outbound".into();
    }
    if lowered.contains("uuid") {
        return "the profile's UUID is not valid".into();
    }
    if lowered.contains("reality") && lowered.contains("fingerprint") {
        return "REALITY needs a browser fingerprint (fp=), which this profile is missing".into();
    }
    if lowered.contains("invalid config json") || lowered.contains("not valid json") {
        return "the profile is not valid JSON".into();
    }
    // Nothing recognised: pass the engine's own words through rather than
    // inventing a vaguer message.
    raw.to_string()
}

/// Back-compat wrapper: build a runnable config with default ports.
pub fn prepare_runnable_config(raw_config: &str, tun_mode: bool) -> Result<String> {
    prepare_runnable_config_with(raw_config, &EngineOptions::default().with_tun(tun_mode))
}

/// Normalise whatever the user stored — a share link, a single config object,
/// or an array — into one runnable config honouring `options`.
pub fn prepare_runnable_config_with(raw_config: &str, options: &EngineOptions) -> Result<String> {
    let trimmed = raw_config.trim();
    if trimmed.is_empty() {
        anyhow::bail!("profile is empty");
    }

    let is_link = [
        "vless://",
        "trojan://",
        "vmess://",
        "ss://",
        "hysteria2://",
        "tuic://",
        "anytls://",
    ]
    .iter()
    .any(|scheme| trimmed.starts_with(scheme));

    if is_link {
        let preset = zero_config::IranPreset {
            outbounds: zero_config::presets::outbounds_from_links([trimmed]),
            listen: options.listen_address().to_string(),
            socks_port: options.socks_port,
            http_port: Some(options.http_port),
            remote_dns: zero_config::RemoteDns::Google,
            local_dns: zero_config::LocalDns::Google,
            anti_sanction_dns: zero_config::AntiSanctionDns::Shecan,
            fragment: options.fragment_enabled,
            manage_assets: false,
            ..zero_config::IranPreset::default()
        };
        let mut built = preset.build();
        apply_engine_options(&mut built, options);
        return Ok(serde_json::to_string_pretty(&built)?);
    }

    let mut val: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| anyhow::anyhow!("invalid config JSON: {e}"))?;

    let map = if let Some(arr) = val.as_array_mut() {
        if arr.is_empty() {
            anyhow::bail!("config array is empty");
        }
        arr[0]
            .as_object_mut()
            .context("first config must be an object")?
    } else {
        val.as_object_mut().context("config must be an object")?
    };

    let outbounds = map
        .entry("outbounds")
        .or_insert_with(|| serde_json::json!([]));
    if let Some(o_arr) = outbounds.as_array_mut() {
        if o_arr.is_empty() {
            anyhow::bail!("config has no outbounds");
        }
        if !has_tag(o_arr, "direct") {
            o_arr.push(serde_json::json!({"tag": "direct", "protocol": "freedom"}));
        }
        if !has_tag(o_arr, "block") {
            o_arr.push(serde_json::json!({"tag": "block", "protocol": "blackhole"}));
        }
    }

    let inbounds = map
        .entry("inbounds")
        .or_insert_with(|| serde_json::json!([]));
    if let Some(inb_arr) = inbounds.as_array_mut() {
        let mut has_socks = false;
        let mut has_http = false;
        for inbound in inb_arr.iter_mut() {
            match inbound.get("protocol").and_then(|p| p.as_str()) {
                Some("socks") => has_socks = true,
                Some("http") => has_http = true,
                _ => {}
            }
        }
        if !has_socks {
            inb_arr.push(serde_json::json!({
                "tag": "socks-in",
                "port": options.socks_port,
                "protocol": "socks"
            }));
        }
        if !has_http {
            inb_arr.push(serde_json::json!({
                "tag": "http-in",
                "port": options.http_port,
                "protocol": "http"
            }));
        }
    }

    // One pass applies every setting to both shapes of profile, so a stored
    // JSON config and a share link cannot drift apart in what Settings means.
    apply_engine_options(&mut val, options);

    Ok(serde_json::to_string_pretty(&val)?)
}

/// Stamp the user's settings onto a built configuration.
///
/// This runs over both a preset-built config and a hand-stored one. Doing it
/// in one place is the point: the two paths used to honour different subsets
/// of Settings, so a port change took effect on a pasted link and a sniffing
/// change took effect on neither.
///
/// Anything the profile itself did not ask for is *set*, not merged: a stored
/// profile carrying stale ports from an older build must follow the current
/// settings rather than quietly overriding them.
fn apply_engine_options(config: &mut serde_json::Value, options: &EngineOptions) {
    let Some(map) = config.as_object_mut() else {
        return;
    };

    // ---- log
    map.entry("log")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .map(|log| log.insert("loglevel".into(), serde_json::json!(options.log_level)));

    // ---- routing
    if let Some(routing) = map
        .entry("routing")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
    {
        routing.insert(
            "domainStrategy".into(),
            serde_json::json!(options.domain_strategy),
        );
    }

    // ---- inbounds
    if let Some(inbounds) = map.get_mut("inbounds").and_then(|i| i.as_array_mut()) {
        for inbound in inbounds.iter_mut() {
            let protocol = inbound
                .get("protocol")
                .and_then(|p| p.as_str())
                .unwrap_or_default()
                .to_string();
            match protocol.as_str() {
                "socks" => {
                    inbound["port"] = serde_json::json!(options.socks_port);
                    inbound["listen"] = serde_json::json!(options.listen_address());
                    inbound
                        .as_object_mut()
                        .and_then(|o| {
                            o.entry("settings")
                                .or_insert_with(|| serde_json::json!({}))
                                .as_object_mut()
                        })
                        .map(|settings| {
                            settings.insert("udp".into(), serde_json::json!(options.udp_enabled))
                        });
                    apply_sniffing(inbound, options);
                }
                "http" => {
                    inbound["port"] = serde_json::json!(options.http_port);
                    inbound["listen"] = serde_json::json!(options.listen_address());
                    apply_sniffing(inbound, options);
                }
                "tun" => apply_sniffing(inbound, options),
                _ => {}
            }
        }

        if options.tun_mode {
            ensure_tun_inbound(inbounds, options);
            for inbound in inbounds.iter_mut() {
                if inbound.get("protocol").and_then(|p| p.as_str()) == Some("tun") {
                    retune_tun_inbound(inbound, options);
                }
            }
        } else {
            // Switching TUN off must actually remove the interface, or the
            // engine keeps trying to claim it on every reconnect.
            inbounds.retain(|i| i.get("protocol").and_then(|p| p.as_str()) != Some("tun"));
        }
    }

    // ---- outbounds
    if let Some(outbounds) = map.get_mut("outbounds").and_then(|o| o.as_array_mut()) {
        for outbound in outbounds.iter_mut() {
            // `freedom` and `blackhole` carry no TLS and no sessions to
            // multiplex; stamping either onto them is noise the parser then
            // has to tolerate.
            let protocol = outbound
                .get("protocol")
                .and_then(|p| p.as_str())
                .unwrap_or_default()
                .to_string();
            if matches!(protocol.as_str(), "freedom" | "blackhole" | "dns") {
                continue;
            }
            apply_mux(outbound, options);
            apply_fingerprint(outbound, options);
            apply_evasion(outbound, options);
            apply_sockopt(outbound, options);
        }
    }

    // ---- dns and observatory
    apply_custom_dns(map, options);
    apply_clean_ip(map, options);
}

/// Inbound sniffing, spelled the way the parser reads it.
fn apply_sniffing(inbound: &mut serde_json::Value, options: &EngineOptions) {
    let Some(object) = inbound.as_object_mut() else {
        return;
    };
    if !options.sniffing_enabled {
        object.insert("sniffing".into(), serde_json::json!({"enabled": false}));
        return;
    }
    let mut targets = vec!["tls", "http"];
    if options.sniffing_route_only {
        // QUIC sniffing only ever informs routing, so it is worth having
        // exactly when the user has asked not to rewrite destinations.
        targets.push("quic");
    }
    object.insert(
        "sniffing".into(),
        serde_json::json!({
            "enabled": true,
            "destOverride": targets,
            "routeOnly": options.sniffing_route_only,
        }),
    );
}

fn apply_mux(outbound: &mut serde_json::Value, options: &EngineOptions) {
    // Mux and XTLS Vision are mutually exclusive, and the engine rejects the
    // pair rather than picking one. A global "multiplexing on" must therefore
    // not be stamped onto a Vision profile: the user would get a connection
    // that refuses to start, blamed on nothing they can see.
    let enabled = options.mux_enabled && !uses_vision(outbound);
    let Some(object) = outbound.as_object_mut() else {
        return;
    };
    object.insert(
        "mux".into(),
        serde_json::json!({
            "enabled": enabled,
            "concurrency": options.mux_concurrency,
        }),
    );
}

/// Whether an outbound negotiates XTLS Vision, in either shape it can arrive
/// in: a share link's `flow=` parameter, or an expanded user object's `flow`.
fn uses_vision(outbound: &serde_json::Value) -> bool {
    if let Some(link) = outbound.get("link").and_then(|l| l.as_str()) {
        return link.contains("xtls-rprx-vision");
    }
    let mut users = outbound
        .get("settings")
        .and_then(|s| s.get("vnext"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|server| server.get("users").and_then(|u| u.as_array()))
        .flatten();
    users.any(|user| {
        user.get("flow")
            .and_then(|f| f.as_str())
            .is_some_and(|flow| flow.contains("vision"))
    })
}

/// Apply the uTLS shape to whichever security block the outbound actually
/// uses.
///
/// REALITY keeps its fingerprint in `realitySettings`, plain TLS in
/// `tlsSettings`. Writing it into the wrong one is silently ignored, which is
/// the failure mode this exists to avoid — and on an outbound with no TLS at
/// all there is no ClientHello to shape, so nothing is written.
fn apply_fingerprint(outbound: &mut serde_json::Value, options: &EngineOptions) {
    if options.utls_fingerprint.is_empty() {
        return;
    }
    // A share link has not been expanded into `streamSettings` yet — the
    // parser does that later — so the shape is carried in its own `fp=`
    // parameter and that is the only place a change would survive.
    if let Some(link) = outbound.get("link").and_then(|l| l.as_str()) {
        let rewritten = set_link_fingerprint(link, &options.utls_fingerprint);
        outbound["link"] = serde_json::json!(rewritten);
        return;
    }
    let Some(stream) = outbound
        .as_object_mut()
        .and_then(|o| o.get_mut("streamSettings"))
        .and_then(|s| s.as_object_mut())
    else {
        return;
    };
    let block = match stream.get("security").and_then(|s| s.as_str()) {
        Some("reality") => "realitySettings",
        Some("tls") => "tlsSettings",
        _ => return,
    };
    if let Some(settings) = stream
        .entry(block)
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
    {
        settings.insert(
            "fingerprint".into(),
            serde_json::json!(options.utls_fingerprint),
        );
    }
}

/// Stamp the evasion knobs onto one outbound.
///
/// Two shapes again, and the split matters twice over: a share link cannot
/// describe this network at all, so the overlay lives in the outbound's own
/// `evasion` object; expanded JSON carries it in `streamSettings.finalmask`,
/// which is the only evasion spelling the parser reads on that path. Writing
/// `streamSettings.fragment` — as older builds did — is silently ignored, and
/// "silently ignored" is exactly the failure this whole pass exists to end.
///
/// Everything here is *set*, not merged: the row says what is in force, so a
/// stale fragment entry left by a previous build or a hand edit is replaced
/// (when shredding is on) or removed (when it is off), never quietly kept.
fn apply_evasion(outbound: &mut serde_json::Value, options: &EngineOptions) {
    let keepalive = options.keepalive_shape();
    // Fragmentation splits a plaintext ClientHello, so it only means
    // something on a TLS-bearing outbound without ECH — ECH encrypts the SNI
    // and there is no plaintext name left to split.
    let want_fragment = options.fragment_enabled && outbound_shreds_well(outbound);

    if outbound.get("link").and_then(|l| l.as_str()).is_some() {
        let Some(object) = outbound.as_object_mut() else {
            return;
        };
        let Some(evasion) = object
            .entry("evasion")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
        else {
            return;
        };
        if want_fragment {
            evasion.insert("fragment".into(), fragment_overlay(options));
        } else {
            evasion.remove("fragment");
        }
        match keepalive {
            Some((idle, lifetime)) => {
                evasion.insert("keepalive".into(), keepalive_overlay(idle, lifetime));
            }
            None => {
                evasion.remove("keepalive");
            }
        }
        if evasion.is_empty() {
            object.remove("evasion");
        }
        return;
    }

    let mut desired: Vec<serde_json::Value> = Vec::new();
    if want_fragment {
        desired.push(fragment_mask(options));
    }
    if let Some((idle, lifetime)) = keepalive {
        desired.push(keepalive_mask(idle, lifetime));
    }

    // Written only where `finalmask` already exists or something is wanted:
    // an outbound with no evasion to strip and none to add must come out of
    // this byte-identical, not carrying empty scaffolding.
    let Some(stream) = outbound
        .as_object_mut()
        .and_then(|o| o.get_mut("streamSettings"))
        .and_then(|s| s.as_object_mut())
    else {
        return;
    };
    if let Some(finalmask) = stream.get_mut("finalmask").and_then(|f| f.as_object_mut()) {
        if let Some(tcp) = finalmask.get_mut("tcp").and_then(|t| t.as_array_mut()) {
            // One fragment and one keepalive entry each: `parse_finalmask`
            // takes the last of a duplicated type, so leaving an old one
            // would make the winner depend on ordering nobody can see.
            tcp.retain(|entry| {
                !matches!(
                    entry.get("type").and_then(|t| t.as_str()),
                    Some("fragment") | Some("keepalive")
                )
            });
            tcp.extend(desired.iter().cloned());
            if tcp.is_empty() {
                finalmask.remove("tcp");
            }
        } else if !desired.is_empty() {
            finalmask.insert("tcp".into(), serde_json::json!(desired));
        }
        if finalmask.is_empty() {
            stream.remove("finalmask");
        }
    } else if !desired.is_empty() {
        stream.insert("finalmask".into(), serde_json::json!({"tcp": desired}));
    }
}

/// `{"packets": "tlshello", "length": "100-200", "interval": "1-1"}` — the
/// fragment shape for a link-form outbound's `evasion` overlay.
fn fragment_overlay(options: &EngineOptions) -> serde_json::Value {
    let (min, max) = options.fragment_length_range();
    serde_json::json!({
        "packets": "tlshello",
        "length": format!("{min}-{max}"),
        "interval": "1-1",
    })
}

/// The same fragment as a `finalmask.tcp[]` entry.
fn fragment_mask(options: &EngineOptions) -> serde_json::Value {
    serde_json::json!({
        "type": "fragment",
        "settings": fragment_overlay(options),
    })
}

fn keepalive_overlay(idle: u64, lifetime: u64) -> serde_json::Value {
    serde_json::json!({
        "idle": format!("{idle}s"),
        "lifetime": format!("{lifetime}s"),
    })
}

fn keepalive_mask(idle: u64, lifetime: u64) -> serde_json::Value {
    serde_json::json!({
        "type": "keepalive",
        "settings": keepalive_overlay(idle, lifetime),
    })
}

/// Whether ClientHello fragmentation would do anything for this outbound.
///
/// Plaintext has no ClientHello to split; ECH has already encrypted the name
/// the split would expose. A share link is judged through the link parser —
/// `vmess://` hides its transport inside base64 and has no query string to
/// eyeball — and a link that will not parse is judged unusable rather than
/// guessed at.
fn outbound_shreds_well(outbound: &serde_json::Value) -> bool {
    // Never REALITY. Its ClientHello already names a real, unblocked site,
    // so there is no forbidden SNI to hide, and REALITY servers commonly
    // reject a ClientHello split across records: real Xray with `tlshello`
    // fragmentation fails against the same servers ours did. Turning it on
    // by default for every REALITY profile left them all unable to connect.
    if let Some(link) = outbound.get("link").and_then(|l| l.as_str()) {
        return match zero_config::parse_link(link) {
            Ok(parsed) => match &parsed.outbound.stream.security {
                zero_config::Security::Tls(tls) => tls.ech.is_none(),
                _ => false,
            },
            Err(_) => false,
        };
    }
    let Some(stream) = outbound.get("streamSettings") else {
        return false;
    };
    if !matches!(
        stream.get("security").and_then(|s| s.as_str()),
        Some("tls") | Some("xtls")
    ) {
        return false;
    }
    !stream
        .get("tlsSettings")
        .and_then(|tls| tls.get("echConfigList"))
        .is_some_and(|v| !v.is_null())
}

/// The named TCP congestion control for this machine's sockets.
///
/// Written to `streamSettings.sockopt` in both shapes — including on a
/// link-form outbound, where it is the overlay the link parser honours.
/// Empty means "system default" and removes the key rather than setting an
/// algorithm named "".
fn apply_sockopt(outbound: &mut serde_json::Value, options: &EngineOptions) {
    let name = options.tcp_congestion.trim();
    let Some(object) = outbound.as_object_mut() else {
        return;
    };
    if name.is_empty() {
        if let Some(stream) = object
            .get_mut("streamSettings")
            .and_then(|s| s.as_object_mut())
        {
            if let Some(sockopt) = stream.get_mut("sockopt").and_then(|s| s.as_object_mut()) {
                sockopt.remove("tcpCongestion");
                if sockopt.is_empty() {
                    stream.remove("sockopt");
                }
            }
            if stream.is_empty() {
                object.remove("streamSettings");
            }
        }
        return;
    }
    if let Some(sockopt) = object
        .entry("streamSettings")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .and_then(|stream| {
            stream
                .entry("sockopt")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
        })
    {
        sockopt.insert("tcpCongestion".into(), serde_json::json!(name));
    }
}

/// Put the user's own resolver ahead of every other.
///
/// Placed first in `dns.servers`, which is also where the resolver picker
/// looks first for unscoped queries — the preset's remote tier is scoped by
/// domain and sorts after it. Blank removes the entry again: "no custom DNS"
/// has to mean the preset's set, untouched.
fn apply_custom_dns(map: &mut serde_json::Map<String, serde_json::Value>, options: &EngineOptions) {
    let dns = map
        .entry("dns")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut();
    let Some(dns) = dns else {
        return;
    };
    let servers = dns
        .entry("servers")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    let Some(servers) = servers else {
        return;
    };
    servers.retain(|s| s.get("tag").and_then(|t| t.as_str()) != Some("custom"));
    if !options.custom_dns.trim().is_empty() {
        servers.insert(
            0,
            serde_json::json!({"address": options.custom_dns.trim(), "tag": "custom"}),
        );
    }
}

/// Clean-IP rotation: rank the scanner's clean edges through the observatory.
///
/// The observatory is created when absent with the preset's own probe shape.
/// Switched off, the `cleanIp` block is removed again so the setting cannot
/// outlive the toggle that controls it.
fn apply_clean_ip(map: &mut serde_json::Map<String, serde_json::Value>, options: &EngineOptions) {
    if !options.clean_ip_rotation {
        if let Some(observatory) = map.get_mut("observatory").and_then(|o| o.as_object_mut()) {
            observatory.remove("cleanIp");
        }
        return;
    }
    let Some(observatory) = map
        .entry("observatory")
        .or_insert_with(|| {
            serde_json::json!({
                "probeUrl": "https://www.gstatic.com/generate_204",
                "probeInterval": "300s",
            })
        })
        .as_object_mut()
    else {
        return;
    };
    observatory.insert(
        "cleanIp".into(),
        serde_json::json!({
            "candidates": options.clean_ip_candidates,
            "host": "www.speedtest.net",
            "path": "/",
        }),
    );
}

/// The scanner's results as bounded clean-IP candidates.
///
/// Only healthy hits on the two ports a CDN edge serves TLS on are worth
/// probing, and the list is capped so a long scan cannot produce an
/// observatory the engine refuses outright (256) or that probes for minutes
/// (the runtime's own bound is 64).
pub fn clean_ip_candidates(
    results: &[zero_scanner::types::ProbeResult],
    require_ws: bool,
) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for hit in results {
        if !hit.is_healthy(require_ws) || !matches!(hit.port, 443 | 8443) {
            continue;
        }
        if out.len() >= 64 {
            break;
        }
        if seen.insert((hit.ip, hit.port)) {
            out.push(format!("{}:{}", hit.ip, hit.port));
        }
    }
    out
}

/// Replace a share link's `fp=` parameter.
///
/// Left alone when the link carries no TLS: `fp` on a plaintext outbound
/// describes a ClientHello that is never sent, and some parsers reject the
/// combination outright.
fn set_link_fingerprint(link: &str, fingerprint: &str) -> String {
    let Some((head, rest)) = link.split_once('?') else {
        return link.to_string();
    };
    // The fragment is the profile name and may contain anything, `&` and `=`
    // included, so it is split off before the query is touched.
    let (query, fragment) = match rest.split_once('#') {
        Some((q, f)) => (q, Some(f)),
        None => (rest, None),
    };

    let mut fields: Vec<(&str, &str)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
        .collect();

    let security = fields
        .iter()
        .find(|(k, _)| *k == "security")
        .map(|(_, v)| *v)
        .unwrap_or("none");
    if !matches!(security, "tls" | "reality" | "xtls") {
        return link.to_string();
    }

    match fields.iter_mut().find(|(k, _)| *k == "fp") {
        Some(field) => field.1 = fingerprint,
        None => fields.push(("fp", fingerprint)),
    }

    let query: Vec<String> = fields
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                (*k).to_string()
            } else {
                format!("{k}={v}")
            }
        })
        .collect();
    let mut out = format!("{head}?{}", query.join("&"));
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

/// Bring an existing TUN inbound in line with the current settings.
fn retune_tun_inbound(inbound: &mut serde_json::Value, options: &EngineOptions) {
    let Some(settings) = inbound.as_object_mut().and_then(|o| {
        o.entry("settings")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
    }) else {
        return;
    };
    settings.insert("name".into(), serde_json::json!(options.tun_device_name));
    settings.insert("mtu".into(), serde_json::json!(options.tun_mtu));
    settings.insert(
        "autoRoute".into(),
        serde_json::json!(options.tun_auto_route),
    );
    settings.insert(
        "strictRoute".into(),
        serde_json::json!(options.strict_route_effective()),
    );
    // A v6 default route on a machine with no working v6 path black-holes
    // every AAAA connection, so the halves are installed independently.
    let mut routes = vec!["0.0.0.0/1", "128.0.0.0/1"];
    if options.ipv6_enabled {
        routes.push("::/1");
        routes.push("8000::/1");
    }
    settings.insert("routes".into(), serde_json::json!(routes));
}

fn has_tag(arr: &[serde_json::Value], tag: &str) -> bool {
    arr.iter()
        .any(|o| o.get("tag").and_then(|t| t.as_str()) == Some(tag))
}

fn ensure_tun_inbound(inbounds: &mut Vec<serde_json::Value>, options: &EngineOptions) {
    if inbounds
        .iter()
        .any(|i| i.get("protocol").and_then(|p| p.as_str()) == Some("tun"))
    {
        return;
    }
    let mut addresses = vec!["10.254.0.1/30".to_string()];
    if options.ipv6_enabled {
        addresses.push("fdfe:dcba:9876::1/126".to_string());
    }
    inbounds.push(serde_json::json!({
        "tag": "tun-in",
        "protocol": "tun",
        "settings": {
            "name": options.tun_device_name,
            "mtu": options.tun_mtu,
            "autoRoute": options.tun_auto_route,
            "strictRoute": options.strict_route_effective(),
            "enableTcp": true,
            "enableUdp": options.udp_enabled,
            "enableIcmp": true,
            "addresses": addresses,
            "routes": ["0.0.0.0/1", "128.0.0.0/1"]
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@155.117.13.26:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.googletagmanager.com&fp=chrome&pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY&sid=7963d08380d47375&type=tcp&headerType=none#AmneziaVPN";

    fn inbound_ports(json: &str) -> Vec<(String, u64)> {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        v["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                (
                    i["protocol"].as_str().unwrap_or_default().to_string(),
                    i["port"].as_u64().unwrap_or_default(),
                )
            })
            .collect()
    }

    #[test]
    fn share_links_honour_configured_ports() {
        let opts = EngineOptions {
            socks_port: 21080,
            http_port: 21081,
            tun_mtu: 1400,
            ..EngineOptions::default()
        };
        let json = prepare_runnable_config_with(LINK, &opts).unwrap();
        let ports = inbound_ports(&json);
        assert!(ports.contains(&("socks".to_string(), 21080)), "{ports:?}");
        assert!(ports.contains(&("http".to_string(), 21081)), "{ports:?}");
    }

    #[test]
    fn stored_json_is_retuned_to_the_configured_ports() {
        // A profile saved with the old hard-coded ports must follow the
        // current settings, not the ports it happened to be written with.
        let stored = serde_json::json!({
            "inbounds": [
                {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks"}
            ],
            "outbounds": [{"tag": "proxy", "protocol": "freedom"}]
        })
        .to_string();

        let opts = EngineOptions {
            socks_port: 31080,
            http_port: 31081,
            ..EngineOptions::default()
        };
        let json = prepare_runnable_config_with(&stored, &opts).unwrap();
        let ports = inbound_ports(&json);
        assert!(ports.contains(&("socks".to_string(), 31080)), "{ports:?}");
        assert!(ports.contains(&("http".to_string(), 31081)), "{ports:?}");
    }

    #[test]
    fn tun_inbound_uses_the_configured_mtu() {
        let opts = EngineOptions {
            tun_mode: true,
            tun_mtu: 1280,
            ..EngineOptions::default()
        };
        let json = prepare_runnable_config_with(LINK, &opts).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let tun = v["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["protocol"] == "tun")
            .expect("tun inbound present");
        assert_eq!(tun["settings"]["mtu"].as_u64(), Some(1280));
    }

    #[test]
    fn turning_tun_off_removes_a_previously_added_interface() {
        let with_tun = serde_json::json!({
            "inbounds": [
                {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks"},
                {"tag": "tun-in", "protocol": "tun", "settings": {"name": "zeronet0"}}
            ],
            "outbounds": [{"tag": "proxy", "protocol": "freedom"}]
        })
        .to_string();

        let json =
            prepare_runnable_config_with(&with_tun, &EngineOptions::default().with_tun(false))
                .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            !v["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["protocol"] == "tun"),
            "tun inbound survived being switched off"
        );
    }

    #[test]
    fn empty_and_malformed_profiles_are_rejected_with_a_reason() {
        assert!(prepare_runnable_config("   ", false).is_err());
        assert!(prepare_runnable_config("not json at all", false).is_err());

        let no_outbounds = serde_json::json!({"outbounds": []}).to_string();
        let err = prepare_runnable_config(&no_outbounds, false).unwrap_err();
        assert!(err.to_string().contains("outbounds"), "{err}");
    }

    #[test]
    fn a_profile_with_no_server_details_is_rejected() {
        // The exact shape an older build wrote, which surfaced at connect
        // time as "outbounds[0].settings.vnext is required for vless".
        let broken = serde_json::json!({
            "outbounds": [{"tag": "proxy", "protocol": "vless"}]
        })
        .to_string();

        let err = validate_profile(&broken, &EngineOptions::default()).unwrap_err();
        assert!(
            err.contains("no server details"),
            "the engine's own wording leaked through: {err}"
        );
        assert!(!err.contains("vnext"), "engine JSON paths leaked: {err}");
    }

    #[test]
    fn a_good_profile_validates() {
        assert!(validate_profile(LINK, &EngineOptions::default()).is_ok());

        let json = serde_json::json!({
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "1.2.3.4", "port": 443,
                    "users": [{"id": "245abd35-7efa-4bc8-85d4-a04f3798329f", "encryption": "none"}]
                }]}
            }]
        })
        .to_string();
        assert!(validate_profile(&json, &EngineOptions::default()).is_ok());
    }

    #[test]
    fn engine_errors_are_translated_into_advice() {
        let cases = [
            (
                "outbounds[0].settings.vnext is required for vless",
                "no server details",
            ),
            ("config has no outbounds", "no proxy outbound"),
            ("invalid config JSON: expected value", "not valid JSON"),
        ];
        for (raw, expected) in cases {
            let described = describe_config_error(raw);
            assert!(
                described.contains(expected),
                "{raw:?} became {described:?}, expected it to mention {expected:?}"
            );
        }
    }

    #[test]
    fn an_unrecognised_error_is_passed_through_verbatim() {
        // Inventing a vaguer message would lose the only diagnostic there is.
        let odd = "some entirely new engine failure";
        assert_eq!(describe_config_error(odd), odd);
    }

    /// Every option moved off its default, so a setting the builder ignores
    /// shows up as a failure rather than as a silent no-op.
    fn loud_options() -> EngineOptions {
        EngineOptions {
            tun_mode: true,
            socks_port: 41080,
            http_port: 41081,
            tun_mtu: 1320,
            tun_device_name: "zraytest0".into(),
            tun_auto_route: true,
            tun_strict_route: true,
            allow_lan: true,
            udp_enabled: false,
            sniffing_enabled: true,
            sniffing_route_only: true,
            log_level: "debug".into(),
            utls_fingerprint: "firefox".into(),
            mux_enabled: true,
            mux_concurrency: 24,
            fragment_enabled: true,
            tls_fragment_size: 300,
            keepalive_interval_secs: 75,
            tcp_congestion: "cubic".into(),
            custom_dns: "9.9.9.9".into(),
            clean_ip_rotation: true,
            clean_ip_candidates: vec!["198.51.100.7:443".to_string()],
            domain_strategy: "AsIs".into(),
            ipv6_enabled: false,
            tun_ready: true,
        }
    }

    fn inbound_named<'a>(v: &'a serde_json::Value, protocol: &str) -> &'a serde_json::Value {
        v["inbounds"]
            .as_array()
            .expect("inbounds")
            .iter()
            .find(|i| i["protocol"] == protocol)
            .unwrap_or_else(|| panic!("no {protocol} inbound"))
    }

    fn proxy_outbound(v: &serde_json::Value) -> &serde_json::Value {
        v["outbounds"]
            .as_array()
            .expect("outbounds")
            .iter()
            .find(|o| o["tag"] == "proxy")
            .expect("proxy outbound")
    }

    /// The same assertions for a share link and for stored JSON.
    ///
    /// The two shapes are built by different code paths, and every setting
    /// that used to be honoured by only one of them was a setting the user
    /// changed with no effect.
    fn assert_options_applied(json: &str) {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();

        assert_eq!(v["log"]["loglevel"], "debug", "log level not applied");
        assert_eq!(
            v["routing"]["domainStrategy"], "AsIs",
            "domain strategy not applied"
        );

        let socks = inbound_named(&v, "socks");
        assert_eq!(socks["port"].as_u64(), Some(41080));
        assert_eq!(
            socks["listen"], "0.0.0.0",
            "Allow LAN did not widen the bind address"
        );
        assert_eq!(
            socks["settings"]["udp"].as_bool(),
            Some(false),
            "UDP setting not applied to the SOCKS inbound"
        );
        assert_eq!(socks["sniffing"]["enabled"].as_bool(), Some(true));
        assert_eq!(socks["sniffing"]["routeOnly"].as_bool(), Some(true));

        assert_eq!(inbound_named(&v, "http")["port"].as_u64(), Some(41081));

        let tun = inbound_named(&v, "tun");
        assert_eq!(tun["settings"]["name"], "zraytest0");
        assert_eq!(tun["settings"]["mtu"].as_u64(), Some(1320));
        assert_eq!(tun["settings"]["autoRoute"].as_bool(), Some(true));
        assert_eq!(tun["settings"]["strictRoute"].as_bool(), Some(true));
        let routes: Vec<&str> = tun["settings"]["routes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r.as_str())
            .collect();
        assert!(
            !routes.iter().any(|r| r.contains(':')),
            "IPv6 is off but v6 routes were installed: {routes:?}"
        );

        let proxy = proxy_outbound(&v);
        assert_eq!(proxy["mux"]["concurrency"].as_u64(), Some(24));

        // A share link still carries its shape in `fp=`; expanded JSON keeps
        // it in whichever security block the transport uses.
        if let Some(link) = proxy["link"].as_str() {
            assert!(
                link.contains("fp=firefox"),
                "uTLS fingerprint did not reach the link: {link}"
            );
            assert!(
                !link.contains("fp=chrome"),
                "the old fingerprint survived: {link}"
            );
        } else {
            let stream = &proxy["streamSettings"];
            let block = match stream["security"].as_str() {
                Some("reality") => "realitySettings",
                Some("tls") => "tlsSettings",
                other => panic!("proxy has no TLS to shape: {other:?}"),
            };
            assert_eq!(
                stream[block]["fingerprint"], "firefox",
                "uTLS fingerprint went into the wrong block"
            );
        }

        // Evasion again in both shapes: a link carries it in `evasion`,
        // expanded JSON in `streamSettings.finalmask.tcp[]`. Size 300 must
        // arrive as the "200-400" range, and keepalive at 75s idle must grow
        // a lifetime the engine will not reject.
        let (fragment_length, idle, lifetime) = if proxy["link"].is_string() {
            let evasion = &proxy["evasion"];
            (
                evasion["fragment"]["length"].as_str().map(str::to_string),
                evasion["keepalive"]["idle"].as_str().map(str::to_string),
                evasion["keepalive"]["lifetime"]
                    .as_str()
                    .map(str::to_string),
            )
        } else {
            let tcp = proxy["streamSettings"]["finalmask"]["tcp"]
                .as_array()
                .expect("finalmask.tcp[]");
            let fragment = tcp
                .iter()
                .find(|e| e["type"] == "fragment")
                .expect("fragment mask missing");
            let keepalive = tcp
                .iter()
                .find(|e| e["type"] == "keepalive")
                .expect("keepalive mask missing");
            (
                fragment["settings"]["length"].as_str().map(str::to_string),
                keepalive["settings"]["idle"].as_str().map(str::to_string),
                keepalive["settings"]["lifetime"]
                    .as_str()
                    .map(str::to_string),
            )
        };
        assert_eq!(
            fragment_length.as_deref(),
            Some("200-400"),
            "TLS fragment size 300 must reach the engine as the 200-400 range"
        );
        assert_eq!(idle.as_deref(), Some("75s"), "keepalive idle not applied");
        assert_eq!(
            lifetime.as_deref(),
            Some("150s"),
            "keepalive lifetime must exceed the idle it is paired with"
        );

        // Congestion control is a property of this machine's sockets, so it
        // lives in `streamSettings.sockopt` on both shapes.
        assert_eq!(
            proxy["streamSettings"]["sockopt"]["tcpCongestion"], "cubic",
            "TCP congestion control not applied"
        );

        // The custom resolver must sort ahead of the preset's tier.
        assert_eq!(v["dns"]["servers"][0]["address"], "9.9.9.9");
        assert_eq!(v["dns"]["servers"][0]["tag"], "custom");

        // And the scanner's clean edges must reach the observatory.
        assert_eq!(v["observatory"]["probeInterval"], "300s");
        assert_eq!(v["observatory"]["cleanIp"]["host"], "www.speedtest.net");
        assert_eq!(v["observatory"]["cleanIp"]["path"], "/");
        let candidates: Vec<&str> = v["observatory"]["cleanIp"]["candidates"]
            .as_array()
            .expect("cleanIp candidates")
            .iter()
            .filter_map(|c| c.as_str())
            .collect();
        assert_eq!(candidates, vec!["198.51.100.7:443"]);
    }

    #[test]
    fn multiplexing_is_refused_on_a_vision_profile_in_either_shape() {
        // The engine rejects VLESS Mux with XTLS Vision, so a global
        // "multiplexing on" must not be stamped onto such a profile.
        let opts = EngineOptions {
            mux_enabled: true,
            mux_concurrency: 24,
            ..EngineOptions::default()
        };

        // Share link, carrying `flow=xtls-rprx-vision`.
        assert_eq!(validate_profile(LINK, &opts), Ok(()));
        let json = prepare_runnable_config_with(LINK, &opts).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            proxy_outbound(&v)["mux"]["enabled"].as_bool(),
            Some(false),
            "mux was forced onto a Vision link"
        );

        // Expanded JSON, carrying the same flow on the user object.
        let stored = serde_json::json!({
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "1.2.3.4", "port": 443,
                    "users": [{
                        "id": "245abd35-7efa-4bc8-85d4-a04f3798329f",
                        "encryption": "none",
                        "flow": "xtls-rprx-vision"
                    }]
                }]},
                "streamSettings": {"network": "tcp", "security": "reality"}
            }]
        })
        .to_string();
        let json = prepare_runnable_config_with(&stored, &opts).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            proxy_outbound(&v)["mux"]["enabled"].as_bool(),
            Some(false),
            "mux was forced onto a Vision outbound"
        );
    }

    #[test]
    fn multiplexing_still_reaches_a_profile_that_can_take_it() {
        // The Vision guard must not turn the setting off everywhere.
        let opts = EngineOptions {
            mux_enabled: true,
            mux_concurrency: 24,
            ..EngineOptions::default()
        };
        let plain = serde_json::json!({
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "1.2.3.4", "port": 443,
                    "users": [{"id": "245abd35-7efa-4bc8-85d4-a04f3798329f", "encryption": "none"}]
                }]},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "a.example"}}
            }]
        })
        .to_string();
        let json = prepare_runnable_config_with(&plain, &opts).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(proxy_outbound(&v)["mux"]["enabled"].as_bool(), Some(true));
        assert_eq!(validate_profile(&plain, &opts), Ok(()));
    }

    #[test]
    fn strict_routing_is_clamped_to_something_the_engine_accepts() {
        // `strictRoute` without `autoRoute` is refused by the compiler, and
        // the user would see only "connect failed".
        let opts = EngineOptions {
            tun_mode: true,
            tun_auto_route: false,
            tun_strict_route: true,
            ..EngineOptions::default()
        };
        assert!(!opts.strict_route_effective());
        assert_eq!(validate_profile(LINK, &opts), Ok(()));

        let both = EngineOptions {
            tun_auto_route: true,
            ..opts
        };
        assert!(both.strict_route_effective());
        let json = prepare_runnable_config_with(LINK, &both).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            inbound_named(&v, "tun")["settings"]["strictRoute"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn rewriting_a_link_fingerprint_leaves_the_rest_of_it_alone() {
        let out = set_link_fingerprint(LINK, "safari");
        assert!(out.contains("fp=safari"), "{out}");
        assert!(
            out.ends_with("#AmneziaVPN"),
            "the profile name was lost: {out}"
        );
        assert!(out.contains("pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY"));
        assert!(out.contains("sid=7963d08380d47375"));
        assert!(out.starts_with("vless://245abd35-7efa-4bc8-85d4-a04f3798329f@155.117.13.26:443?"));
        assert_eq!(out.matches("fp=").count(), 1, "fp was duplicated: {out}");
    }

    #[test]
    fn a_link_with_no_fingerprint_yet_gains_one() {
        let bare = "vless://id@1.2.3.4:443?security=tls&type=tcp#Node";
        let out = set_link_fingerprint(bare, "edge");
        assert!(out.contains("fp=edge"), "{out}");
        assert!(out.ends_with("#Node"), "{out}");
    }

    #[test]
    fn a_plaintext_link_is_not_given_a_clienthello_shape() {
        // There is no TLS handshake to shape, and some parsers reject `fp`
        // on a plaintext outbound outright.
        let plain = "vless://id@1.2.3.4:80?encryption=none&type=tcp#Plain";
        assert_eq!(set_link_fingerprint(plain, "chrome"), plain);
        // Neither is a link with no query at all.
        let no_query = "ss://abcdef@1.2.3.4:8388#Plain";
        assert_eq!(set_link_fingerprint(no_query, "chrome"), no_query);
    }

    #[test]
    fn a_profile_name_containing_query_characters_survives() {
        // Fragments are user text: `&` and `=` in a node name must not be
        // read as query fields.
        let awkward = "vless://id@1.2.3.4:443?security=reality&type=tcp#US&EU=fast";
        let out = set_link_fingerprint(awkward, "ios");
        assert!(out.ends_with("#US&EU=fast"), "{out}");
        assert!(out.contains("fp=ios"), "{out}");
    }

    #[test]
    fn every_setting_reaches_a_config_built_from_a_share_link() {
        // A TLS link: fragmentation is a TLS-only remedy (see below).
        let tls_link = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@1.2.3.4:443?encryption=none&security=tls&sni=example.com&fp=chrome&type=tcp#TLS";
        let json = prepare_runnable_config_with(tls_link, &loud_options()).unwrap();
        assert_options_applied(&json);
    }

    #[test]
    fn reality_profiles_are_never_fragmented() {
        // Fragmenting a REALITY ClientHello made servers hang up on it; real
        // Xray fails the same way. Fragmentation on, REALITY link: none.
        let json = prepare_runnable_config_with(LINK, &loud_options()).unwrap();
        let config: serde_json::Value = serde_json::from_str(&json).unwrap();
        let proxy = &config["outbounds"][0];
        assert!(
            proxy["evasion"].get("fragment").is_none(),
            "a REALITY outbound was given ClientHello fragmentation: {proxy}"
        );
    }

    #[test]
    fn every_setting_reaches_a_config_stored_as_json() {
        // Deliberately carrying stale ports, a loopback bind and no sniffing,
        // the way an older build wrote them.
        let stored = serde_json::json!({
            "log": {"loglevel": "none"},
            "inbounds": [
                {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks"},
                {"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http"}
            ],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "1.2.3.4", "port": 443,
                    "users": [{"id": "245abd35-7efa-4bc8-85d4-a04f3798329f", "encryption": "none"}]
                }]},
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {"serverName": "example.com", "fingerprint": "chrome"}
                }
            }]
        })
        .to_string();
        let json = prepare_runnable_config_with(&stored, &loud_options()).unwrap();
        assert_options_applied(&json);
    }

    #[test]
    fn a_config_built_with_the_new_options_still_compiles() {
        // Applying the settings must not produce JSON the engine rejects.
        assert_eq!(validate_profile(LINK, &loud_options()), Ok(()));
    }

    /// The stale shape an older build — or a hand edit — leaves behind, with
    /// every managed knob carrying a value the current settings disagree with.
    fn stale_stored_config() -> String {
        serde_json::json!({
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "1.2.3.4", "port": 443,
                    "users": [{"id": "245abd35-7efa-4bc8-85d4-a04f3798329f", "encryption": "none"}]
                }]},
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {"serverName": "example.com"},
                    "sockopt": {"tcpCongestion": "reno"},
                    "finalmask": {"tcp": [
                        {"type": "fragment", "settings": {"packets": "tlshello", "length": "9-9", "interval": "1-1"}},
                        {"type": "keepalive", "settings": {"idle": "9s", "lifetime": "900s"}}
                    ]}
                }
            }],
            "dns": {"servers": [
                {"address": "9.9.9.9", "tag": "custom"},
                "https://dns.google/dns-query"
            ]},
            "observatory": {
                "probeUrl": "https://www.gstatic.com/generate_204",
                "probeInterval": "300s",
                "cleanIp": {"candidates": ["203.0.113.9:443"], "host": "old.example", "path": "/"}
            }
        })
        .to_string()
    }

    #[test]
    fn switching_everything_off_strips_what_it_used_to_stamp() {
        // A setting that is off must leave nothing behind claiming otherwise:
        // stale fragment entries, an old resolver at the front of the queue,
        // clean-IP candidates from some previous scan.
        let opts = EngineOptions {
            fragment_enabled: false,
            keepalive_interval_secs: 0,
            tcp_congestion: String::new(),
            custom_dns: String::new(),
            clean_ip_rotation: false,
            ..EngineOptions::default()
        };
        let json = prepare_runnable_config_with(&stale_stored_config(), &opts).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let proxy = proxy_outbound(&v);
        let stream = &proxy["streamSettings"];

        assert!(
            stream.get("finalmask").is_none(),
            "a stale fragment survived: {}",
            stream["finalmask"]
        );
        assert!(stream["sockopt"].get("tcpCongestion").is_none());
        let servers = v["dns"]["servers"].as_array().expect("dns servers");
        assert!(
            !servers
                .iter()
                .any(|s| s.get("tag").and_then(|t| t.as_str()) == Some("custom")),
            "the custom resolver outlived its setting"
        );
        assert!(v["observatory"].get("cleanIp").is_none());
        assert_eq!(
            validate_profile(&stale_stored_config(), &opts),
            Ok(()),
            "stripping must leave a config the engine still accepts"
        );
    }

    #[test]
    fn a_link_outbound_is_stripped_too() {
        let opts = EngineOptions {
            fragment_enabled: false,
            keepalive_interval_secs: 0,
            tcp_congestion: String::new(),
            ..EngineOptions::default()
        };
        let json = prepare_runnable_config_with(LINK, &opts).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let proxy = proxy_outbound(&v);
        assert!(proxy["evasion"].get("fragment").is_none());
        assert!(proxy["evasion"].get("keepalive").is_none());
    }

    #[test]
    fn fragment_sizes_are_clamped_below_the_path_mtu() {
        // The dialog bounds the input, but a stored settings file is not
        // bounded by anything: 1500 must come out as a range the engine
        // accepts, not a config that fails to parse.
        let opts = EngineOptions {
            tls_fragment_size: 1500,
            ..EngineOptions::default()
        };
        assert_eq!(opts.fragment_length_range(), (1000, 1400));
        let tiny = EngineOptions {
            tls_fragment_size: 20,
            ..EngineOptions::default()
        };
        assert_eq!(tiny.fragment_length_range(), (14, 26));
        // The historic default must keep its historic shape.
        let default = EngineOptions::default();
        assert_eq!(default.fragment_length_range(), (100, 200));
    }

    #[test]
    fn keepalive_lifetime_always_exceeds_idle() {
        // The engine rejects `lifetime <= idle` outright, so the pair is
        // derived rather than left to arithmetic at the call site.
        let opts = EngineOptions {
            keepalive_interval_secs: 300,
            ..EngineOptions::default()
        };
        assert_eq!(opts.keepalive_shape(), Some((300, 600)));
        let near = EngineOptions {
            keepalive_interval_secs: 100,
            ..EngineOptions::default()
        };
        assert_eq!(near.keepalive_shape(), Some((100, 200)));
        let off = EngineOptions {
            keepalive_interval_secs: 0,
            ..EngineOptions::default()
        };
        assert_eq!(off.keepalive_shape(), None);
    }

    #[test]
    fn plaintext_and_ech_outbounds_are_never_shredded() {
        // There is no ClientHello to split on a plaintext outbound, and ECH
        // has already encrypted the name the split would expose.
        let opts = EngineOptions {
            fragment_enabled: true,
            keepalive_interval_secs: 0,
            tcp_congestion: String::new(),
            ..EngineOptions::default()
        };

        let plain_link = "vless://id@1.2.3.4:80?encryption=none&type=tcp#Plain";
        let json = prepare_runnable_config_with(plain_link, &opts).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            proxy_outbound(&v)["evasion"].get("fragment").is_none(),
            "a plaintext link was given a ClientHello to split"
        );

        let ech = serde_json::json!({
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "1.2.3.4", "port": 443,
                    "users": [{"id": "245abd35-7efa-4bc8-85d4-a04f3798329f", "encryption": "none"}]
                }]},
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {"serverName": "example.com", "echConfigList": "AA=="}
                }
            }]
        })
        .to_string();
        let json = prepare_runnable_config_with(&ech, &opts).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let stream = &proxy_outbound(&v)["streamSettings"];
        let shredded = stream["finalmask"]["tcp"]
            .as_array()
            .map(|tcp| tcp.iter().any(|e| e["type"] == "fragment"))
            .unwrap_or(false);
        assert!(!shredded, "an ECH outbound was given a plaintext split");
    }

    #[test]
    fn clean_ip_candidates_are_bounded_and_belong_on_a_tls_edge() {
        use zero_scanner::types::{ProbeMode, ProbeResult, ResultFlags};
        let hit = |ip: &str, port: u16, ok: bool| ProbeResult {
            ip: ip.parse().unwrap(),
            port,
            mode: ProbeMode::Http,
            latencies_ms: vec![10.0],
            flags: if ok {
                ResultFlags::HTTP_OK | ResultFlags::WS_OK
            } else {
                ResultFlags::empty()
            },
            http_status: if ok { 204 } else { 0 },
            colo: if ok { Some("THR".into()) } else { None },
            throughput_mbps: 0.0,
            isp: None,
            asn: None,
        };
        let results = vec![
            hit("198.51.100.7", 443, true),
            hit("198.51.100.8", 8443, true),
            hit("198.51.100.9", 80, true),    // not a TLS edge
            hit("198.51.100.10", 443, false), // never answered
            hit("198.51.100.7", 443, true),   // duplicate
        ];
        assert_eq!(
            clean_ip_candidates(&results, true),
            vec!["198.51.100.7:443", "198.51.100.8:8443"]
        );

        let many: Vec<ProbeResult> = (1..=100)
            .map(|i| hit(&format!("198.51.100.{i}"), 443, true))
            .collect();
        assert_eq!(clean_ip_candidates(&many, false).len(), 64);
    }

    #[test]
    fn loopback_is_the_default_bind_address() {
        // Binding an open proxy to every interface by default would hand
        // anyone on the same network a free exit node.
        let opts = EngineOptions::default();
        assert_eq!(opts.listen_address(), "127.0.0.1");
        assert_eq!(opts.clone().listen_address(), "127.0.0.1");
        let json = prepare_runnable_config_with(LINK, &opts).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(inbound_named(&v, "socks")["listen"], "127.0.0.1");
    }

    #[test]
    fn switching_sniffing_off_disables_it_rather_than_dropping_the_block() {
        // A missing `sniffing` block means "whatever the parser defaults to",
        // which is not the same as the user having switched it off.
        let opts = EngineOptions {
            sniffing_enabled: false,
            ..EngineOptions::default()
        };
        let json = prepare_runnable_config_with(LINK, &opts).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            inbound_named(&v, "socks")["sniffing"]["enabled"].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn ipv6_routing_installs_both_halves_of_the_v6_default_route() {
        let opts = EngineOptions {
            tun_mode: true,
            ipv6_enabled: true,
            ..EngineOptions::default()
        };
        let json = prepare_runnable_config_with(LINK, &opts).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let routes: Vec<String> = inbound_named(&v, "tun")["settings"]["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap_or_default().to_string())
            .collect();
        // Two halves rather than ::/0, so the tunnel does not outrank a
        // more specific route the system already has.
        assert!(routes.contains(&"::/1".to_string()), "{routes:?}");
        assert!(routes.contains(&"8000::/1".to_string()), "{routes:?}");
    }

    #[test]
    fn a_direct_outbound_is_left_unmultiplexed() {
        // `freedom` has no sessions to multiplex and no ClientHello to shape.
        let json = prepare_runnable_config_with(LINK, &loud_options()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let direct = v["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["protocol"] == "freedom")
            .expect("direct outbound");
        assert!(direct.get("mux").is_none(), "mux was stamped onto freedom");
    }

    fn test_server() -> Arc<zero_runtime::Server> {
        let json = prepare_runnable_config_with(LINK, &EngineOptions::default()).unwrap();
        let (_, cfg, _) = zero_config::parse_config_array(&json).unwrap().remove(0);
        let generation = zero_config::RuntimeGeneration::compile(cfg, GenerationId(1)).unwrap();
        Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
            config: Arc::clone(&generation.config),
            generation: generation.id,
        }))
    }

    #[tokio::test]
    async fn queued_commands_collapse_to_the_latest() {
        let (tx, mut rx) = mpsc::channel(8);
        tx.send(DaemonCommand::Disconnect).await.unwrap();
        tx.send(DaemonCommand::Connect {
            config_json: "b".into(),
            node_name: "B".into(),
            options: EngineOptions::default(),
        })
        .await
        .unwrap();
        let first = DaemonCommand::Connect {
            config_json: "a".into(),
            node_name: "A".into(),
            options: EngineOptions::default(),
        };
        match coalesce(first, &mut rx) {
            DaemonCommand::Connect { node_name, .. } => assert_eq!(node_name, "B"),
            _ => panic!("the latest command did not win"),
        }

        // A shutdown is never overtaken by what was queued after it.
        let (ack, _keep) = tokio::sync::oneshot::channel();
        tx.send(DaemonCommand::Disconnect).await.unwrap();
        assert!(matches!(
            coalesce(DaemonCommand::Shutdown(ack), &mut rx),
            DaemonCommand::Shutdown(_)
        ));
        assert!(rx.try_recv().is_err(), "the queue was not drained");
    }

    #[tokio::test]
    async fn dropping_an_engine_inside_async_code_does_not_panic() {
        // A cancelled start drops its engine inside the daemon task. Dropping
        // a Tokio runtime there panics — fatal under `panic = "abort"` — so
        // the engine hands it to a thread instead.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let engine = RunningEngine {
            server: test_server(),
            runtime: Some(runtime),
            exited: tokio::sync::oneshot::channel().1,
        };
        drop(engine);
    }

    #[tokio::test]
    async fn a_stopped_engine_reports_when_it_is_gone() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (_exit_tx, exited) = tokio::sync::oneshot::channel();
        let engine = RunningEngine {
            server: test_server(),
            runtime: Some(runtime),
            exited,
        };
        tokio::time::timeout(Duration::from_secs(5), engine.stop())
            .await
            .expect("shutdown finished within the grace period")
            .expect("completion was signalled");
    }

    #[test]
    fn default_options_match_the_historical_ports() {
        let opts = EngineOptions::default();
        assert_eq!(opts.socks_port, 10808);
        assert_eq!(opts.http_port, 10809);
        assert!(!opts.tun_mode);
    }
}
