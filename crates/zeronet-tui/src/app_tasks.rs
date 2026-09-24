//! Background work for the client, and the state machine around it.
//!
//! Everything here used to run inline in the event handlers, which the frame
//! loop awaits: driving `gsettings`/`kwriteconfig` for the system proxy,
//! `sudo` for TUN, tearing a helper down (up to two seconds of polling), a
//! database write per latency reading, compiling every node of a refreshed
//! feed. While any of it ran nothing was drawn and no key was read.
//!
//! Each job now runs on a Tokio task or the blocking pool and reports back
//! as a [`BgEvent`] on one channel, which the frame loop drains like any
//! other input. Jobs whose answer can go stale — a TUN interface for a
//! connect the user has since cancelled — carry the generation they were
//! started under and are discarded when it no longer matches.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::*;
use zeronet_tui::elevate::TunHandover;
use zeronet_tui::sysproxy::Applied;

/// How often housekeeping runs: flushing latency readings, checking feeds.
const HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(5);
/// Latency readings buffered before a flush is forced early.
const PING_FLUSH_BATCH: usize = 64;
/// Shortest gap between two automatic attempts on the same feed, so one
/// that keeps failing is not re-fetched every housekeeping tick.
const FEED_RETRY_GAP: Duration = Duration::from_secs(30 * 60);
/// Upper bound on the system proxy revert at exit.
const PROXY_REVERT_TIMEOUT: Duration = Duration::from_secs(15);

/// A system-proxy change for the worker.
pub(crate) enum ProxyJob {
    Apply {
        mode: SystemProxyMode,
        endpoints: ProxyEndpoints,
    },
    /// Undo whatever this process changed. `announce` controls the toast;
    /// `ack` fires once done, for the exit path.
    Revert {
        announce: bool,
        ack: Option<oneshot::Sender<()>>,
    },
}

/// How a TUN request for a connect ended.
pub(crate) enum TunOutcome {
    /// sudo wants a password and the user may give one.
    NeedPassword,
    /// No way to get privileges without asking, and asking is not possible
    /// (declined, or no prompting backend): proxy only.
    Skipped,
    /// The helper is up and the descriptor has been handed over.
    Armed(Box<PrivilegedTun>, TunHandover),
    Failed(ElevationError),
}

/// Something a background job finished.
pub(crate) enum BgEvent {
    Proxy {
        requested: Option<SystemProxyMode>,
        endpoints: ProxyEndpoints,
        announce: bool,
        result: Result<Applied, String>,
    },
    Tun {
        generation: u64,
        action: EngineAction,
        outcome: TunOutcome,
    },
    PasswordChecked {
        password: String,
        result: Result<(), ElevationError>,
    },
    Housekeeping,
    /// The post-connect traffic check finished.
    Health {
        /// The daemon revision it was started for; a later connection's
        /// check replaces it.
        revision: u64,
        node: String,
        result: Result<std::time::Duration, String>,
    },
    /// The process was asked to terminate (SIGTERM, SIGHUP, SIGINT…).
    Terminate(&'static str),
}

/// Bookkeeping for the jobs above, kept in one field of the app.
pub(crate) struct Background {
    pub(crate) tx: mpsc::UnboundedSender<BgEvent>,
    pub(crate) rx: mpsc::UnboundedReceiver<BgEvent>,
    proxy_jobs: mpsc::UnboundedSender<ProxyJob>,
    /// Proxy jobs queued or running.
    proxy_pending: usize,
    /// Bumped by every connect or disconnect; a TUN job started under an
    /// older value belongs to a request the user has moved on from.
    generation: u64,
    /// A retired helper still removing its routes. A new helper for the
    /// same device waits for it.
    tun_teardown: Option<JoinHandle<()>>,
    /// A password is being checked; a second Enter must not start another.
    validating: bool,
    /// Generation of the TUN job still running, if one is.
    tun_job: Option<u64>,
    pending_pings: Vec<(i64, f64)>,
    ping_flush: Option<JoinHandle<()>>,
    /// The latency sweep in progress, so a new one replaces it rather than
    /// running alongside it.
    sweep: Option<JoinHandle<()>>,
    pub(crate) feeds_in_flight: HashSet<i64>,
    feed_attempts: HashMap<i64, Instant>,
}

impl Background {
    pub(crate) fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let proxy_jobs = spawn_proxy_worker(tx.clone());
        spawn_housekeeping(tx.clone());
        spawn_signal_listener(tx.clone());
        Self {
            tx,
            rx,
            proxy_jobs,
            proxy_pending: 0,
            generation: 0,
            tun_teardown: None,
            validating: false,
            tun_job: None,
            pending_pings: Vec::new(),
            ping_flush: None,
            sweep: None,
            feeds_in_flight: HashSet::new(),
            feed_attempts: HashMap::new(),
        }
    }

    fn queue_proxy(&mut self, job: ProxyJob) {
        if self.proxy_jobs.send(job).is_ok() {
            self.proxy_pending += 1;
        }
    }
}

/// One worker runs every system-proxy job, strictly in order: two changes
/// racing on the blocking pool could land in either order and leave the
/// desktop in the state the user asked to leave.
fn spawn_proxy_worker(events: mpsc::UnboundedSender<BgEvent>) -> mpsc::UnboundedSender<ProxyJob> {
    let (jobs_tx, mut jobs_rx) = mpsc::unbounded_channel::<ProxyJob>();
    tokio::spawn(async move {
        while let Some(job) = jobs_rx.recv().await {
            match job {
                ProxyJob::Apply { mode, endpoints } => {
                    let result = tokio::task::spawn_blocking(move || {
                        sysproxy::apply_tracked(mode, endpoints)
                    })
                    .await
                    .unwrap_or_else(|e| Err(format!("system proxy worker failed: {e}")));
                    let _ = events.send(BgEvent::Proxy {
                        requested: Some(mode),
                        endpoints,
                        announce: true,
                        result,
                    });
                }
                ProxyJob::Revert { announce, ack } => {
                    let result = tokio::task::spawn_blocking(sysproxy::revert_tracked)
                        .await
                        .unwrap_or_else(|e| Err(format!("system proxy worker failed: {e}")))
                        .map(|restored| match restored {
                            Some(backend) => Applied::Restored(backend),
                            None => Applied::Untouched,
                        });
                    let _ = events.send(BgEvent::Proxy {
                        requested: None,
                        endpoints: ProxyEndpoints {
                            http_port: 0,
                            socks_port: 0,
                            pac_port: 0,
                        },
                        announce,
                        result,
                    });
                    if let Some(ack) = ack {
                        let _ = ack.send(());
                    }
                }
            }
        }
    });
    jobs_tx
}

fn spawn_housekeeping(events: mpsc::UnboundedSender<BgEvent>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(HOUSEKEEPING_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if events.send(BgEvent::Housekeeping).is_err() {
                break;
            }
        }
    });
}

/// Turn termination signals into an orderly quit.
///
/// Without this, closing the terminal window (SIGHUP) or a plain `kill`
/// (SIGTERM) ended the process on the spot: the desktop stayed pointed at a
/// proxy that no longer existed and the engine's route changes stayed put.
fn spawn_signal_listener(events: mpsc::UnboundedSender<BgEvent>) {
    #[cfg(unix)]
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let kinds = [
            (SignalKind::terminate(), "SIGTERM"),
            (SignalKind::hangup(), "SIGHUP"),
            (SignalKind::interrupt(), "SIGINT"),
            (SignalKind::quit(), "SIGQUIT"),
        ];
        let mut streams = Vec::new();
        for (kind, name) in kinds {
            match signal(kind) {
                Ok(stream) => streams.push((stream, name)),
                Err(error) => tracing::warn!(%error, signal = name, "cannot watch signal"),
            }
        }
        if streams.is_empty() {
            return;
        }
        let waits = streams.iter_mut().map(|(stream, name)| {
            let name: &'static str = name;
            Box::pin(async move {
                stream.recv().await;
                name
            })
        });
        let (name, _, _) = futures::future::select_all(waits).await;
        let _ = events.send(BgEvent::Terminate(name));
    });
    #[cfg(not(unix))]
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = events.send(BgEvent::Terminate("Ctrl+C"));
        }
    });
}

/// A subscription's nodes, compiled and ready to store.
pub(crate) struct FeedRows {
    pub(crate) rows: Vec<(String, String, String, u16, String)>,
    pub(crate) skipped: usize,
}

/// Fetch a feed and compile its nodes, entirely off the frame loop.
async fn fetch_and_build(url: String, socks_port: u16, http_port: u16) -> Result<FeedRows, String> {
    let feed = subscription::fetch_feed(&url).await?;
    tokio::task::spawn_blocking(move || {
        let mut rows = Vec::with_capacity(feed.profiles.len());
        let mut skipped = feed.skipped;
        for profile in &feed.profiles {
            let preset = zero_config::IranPreset {
                outbounds: zero_config::presets::outbounds_from_links([profile.link.as_str()]),
                socks_port,
                http_port: Some(http_port),
                manage_assets: false,
                ..zero_config::IranPreset::default()
            };
            let Ok(json) = serde_json::to_string_pretty(&preset.build()) else {
                skipped += 1;
                continue;
            };
            rows.push((
                profile.remark.clone(),
                profile.protocol.clone(),
                profile.address.clone(),
                profile.port,
                json,
            ));
        }
        FeedRows { rows, skipped }
    })
    .await
    .map_err(|e| format!("building the feed's profiles failed: {e}"))
}

impl App<'_> {
    // ------------------------------------------------------ dispatch

    /// Apply one finished background job. Returns whether the picture may
    /// have changed.
    pub(crate) async fn on_background(&mut self, event: BgEvent) -> bool {
        match event {
            BgEvent::Health {
                revision,
                node,
                result,
            } => {
                // Only the connection this check was started for counts.
                if revision != self.stats.revision
                    || self.stats.status != zeronet_tui::daemon::ConnectionStatus::Connected
                {
                    return false;
                }
                match result {
                    Ok(delay) => self.toasts.success(format!(
                        "{node} is carrying traffic · {} ms",
                        delay.as_millis()
                    )),
                    Err(reason) => self.toasts.warning(format!(
                        "Connected to {node}, but no traffic gets through it ({reason}). \
                         Apps using the proxy will not load. Try another profile."
                    )),
                }
                true
            }
            BgEvent::Proxy {
                requested,
                endpoints,
                announce,
                result,
            } => {
                self.bg.proxy_pending = self.bg.proxy_pending.saturating_sub(1);
                self.on_proxy_outcome(requested, endpoints, announce, result);
                true
            }
            BgEvent::Tun {
                generation,
                action,
                outcome,
            } => {
                if self.bg.tun_job == Some(generation) {
                    self.bg.tun_job = None;
                }
                if generation != self.bg.generation {
                    // The user disconnected or picked another node while
                    // this was being set up: release it, quietly.
                    if let TunOutcome::Armed(helper, handover) = outcome {
                        close_descriptor(handover.fd);
                        self.retire_helper(helper);
                    }
                    return false;
                }
                if let Err(e) = self.on_tun_outcome(action, outcome).await {
                    self.toasts.error(format!("Connect failed: {e:#}"));
                }
                true
            }
            BgEvent::PasswordChecked { password, result } => {
                self.bg.validating = false;
                if let Err(e) = self.on_password_checked(password, result).await {
                    self.toasts.error(format!("Connect failed: {e:#}"));
                }
                true
            }
            BgEvent::Housekeeping => {
                self.flush_ping_writes();
                self.refresh_due_subscriptions();
                false
            }
            BgEvent::Terminate(name) => {
                tracing::info!(signal = name, "terminating");
                self.should_quit = true;
                true
            }
        }
    }

    // -------------------------------------------------- system proxy

    /// Queue `mode` for the proxy worker. PAC mode needs its server up
    /// first: pointing the desktop at a URL that serves nothing would break
    /// every application's networking.
    pub(crate) async fn queue_system_proxy(&mut self, mode: SystemProxyMode) {
        let endpoints = self.proxy_endpoints();
        if mode == SystemProxyMode::Pac && self.pac_server.is_none() {
            let script = sysproxy::pac_script(endpoints);
            match PacServer::start(endpoints.pac_port, script).await {
                Ok(server) => self.pac_server = Some(server),
                Err(e) => {
                    self.toasts.error(format!("PAC mode unavailable: {e}"));
                    return;
                }
            }
        }
        self.bg.queue_proxy(ProxyJob::Apply { mode, endpoints });
    }

    /// Queue an undo of whatever this client changed. A no-op when nothing
    /// was changed and nothing is on its way to being changed.
    pub(crate) fn queue_proxy_revert(&mut self, announce: bool) {
        if !self.system_proxy.writes_settings() && self.bg.proxy_pending == 0 {
            return;
        }
        self.bg.queue_proxy(ProxyJob::Revert {
            announce,
            ack: None,
        });
    }

    fn on_proxy_outcome(
        &mut self,
        requested: Option<SystemProxyMode>,
        endpoints: ProxyEndpoints,
        announce: bool,
        result: Result<Applied, String>,
    ) {
        match (requested, result) {
            (Some(mode), Ok(Applied::Set(backend))) => {
                self.system_proxy = mode;
                if mode != SystemProxyMode::Pac {
                    self.pac_server = None;
                }
                let detail = match mode {
                    SystemProxyMode::Manual => format!(
                        "HTTP :{} · SOCKS :{}",
                        endpoints.http_port, endpoints.socks_port
                    ),
                    SystemProxyMode::Pac => sysproxy::pac_url(
                        self.pac_server
                            .as_ref()
                            .map(|s| s.port())
                            .unwrap_or(endpoints.pac_port),
                    ),
                    SystemProxyMode::Clear => "apps will not use any proxy".to_string(),
                    SystemProxyMode::Unmanaged => String::new(),
                };
                self.toasts.success(format!(
                    "System proxy → {} ({backend}) · {detail}",
                    mode.label()
                ));
            }
            (requested, Ok(Applied::Restored(backend))) => {
                self.system_proxy = SystemProxyMode::Unmanaged;
                self.pac_server = None;
                if announce {
                    self.toasts.info(if requested.is_some() {
                        format!("System proxy restored to its previous settings ({backend}).")
                    } else {
                        format!("System proxy restored ({backend}).")
                    });
                }
            }
            (requested, Ok(Applied::Untouched)) => {
                self.system_proxy = SystemProxyMode::Unmanaged;
                self.pac_server = None;
                if announce && requested.is_some() {
                    self.toasts
                        .info("Leaving your system proxy settings untouched.");
                }
            }
            (Some(mode), Err(e)) => {
                // Do not claim a mode that was not applied.
                if mode == SystemProxyMode::Pac && self.system_proxy != SystemProxyMode::Pac {
                    self.pac_server = None;
                }
                self.toasts.error(format!("System proxy failed: {e}"));
            }
            // A revert never reports `Set`.
            (None, Ok(Applied::Set(_))) => {}
            (None, Err(e)) => {
                self.toasts
                    .error(format!("Could not restore the system proxy: {e}"));
            }
        }
    }

    // ----------------------------------------------------------- TUN

    /// Start bringing a TUN interface up for `action`, off the frame loop.
    ///
    /// `password` is the one the user just typed, or `None` to try without.
    pub(crate) fn begin_tun_connect(&mut self, action: EngineAction, password: Option<String>) {
        let (EngineAction::Connect(id) | EngineAction::Switch(id)) = action else {
            return;
        };
        let Some(cfg) = self.config_by_id(id) else {
            return;
        };
        let raw = cfg.raw_content.clone();
        let options = self.engine_options();
        let prompt_allowed = !self.elevation_declined && self.elevator.can_prompt();

        // A live helper is kept: if the new profile fits the interface it
        // already holds up, a switch only swaps the bypass route. Rebuilding
        // the device for every switch failed outright, because the kernel
        // keeps a TUN device alive while the running engine still has it
        // open, so the new one could not take its name.
        let alive = self
            .privileged_tun
            .as_mut()
            .is_some_and(|helper| helper.is_running());
        let reusable = if alive {
            self.privileged_tun.take()
        } else {
            None
        };
        if reusable.is_none() {
            self.release_privileged_tun();
        } else if let Some(stale) = zero_tun::inherited::clear() {
            close_descriptor(stale.fd);
        }
        let teardown = self.bg.tun_teardown.take();
        let stopper = self.daemon.stopper();

        self.bg.generation += 1;
        let generation = self.bg.generation;
        self.bg.tun_job = Some(generation);
        let events = self.bg.tx.clone();
        if reusable.is_none() {
            self.toasts.info("Bringing up TUN…");
        }

        tokio::spawn(async move {
            if let Some(teardown) = teardown {
                let _ = teardown.await;
            }
            let mut leftover = None;
            if let Some(helper) = reusable {
                match retarget_tun(&raw, &options, helper).await {
                    Ok((helper, handover)) => {
                        let _ = events.send(BgEvent::Tun {
                            generation,
                            action,
                            outcome: TunOutcome::Armed(helper, handover),
                        });
                        return;
                    }
                    Err(helper) => leftover = helper,
                }
            }
            // A fresh interface. The running engine has to let go of the old
            // one first, and its helper has to remove its routes, before a
            // device with the same name can be created.
            stopper.stop().await;
            if let Some(helper) = leftover {
                let _ = tokio::task::spawn_blocking(move || drop(helper)).await;
            }
            let mut password = password;
            let outcome = arm_tun(&raw, &options, password.as_deref(), prompt_allowed).await;
            if let Some(password) = password.as_mut() {
                zeroize(password);
            }
            let _ = events.send(BgEvent::Tun {
                generation,
                action,
                outcome,
            });
        });
    }

    async fn on_tun_outcome(&mut self, action: EngineAction, outcome: TunOutcome) -> Result<()> {
        let mut options = self.engine_options();
        options.tun_ready = false;
        match outcome {
            TunOutcome::NeedPassword => {
                self.pending_elevation = Some(action);
                self.open_sudo_dialog(None);
                return Ok(());
            }
            TunOutcome::Skipped => {
                self.toasts.warning(
                    "TUN skipped: no administrator rights. Apps using the SOCKS/HTTP proxy still work.",
                );
            }
            TunOutcome::Armed(helper, handover) => {
                let descriptor = zero_tun::inherited::InheritedTun {
                    fd: handover.fd,
                    header_len: handover.header_len,
                    mtu: handover.mtu,
                };
                // The engine's own connections must leave by the real
                // interface, not follow the default routes into the tunnel.
                zero_core::platform::set_bound_interface(handover.uplink.as_deref());
                match zero_tun::inherited::set(descriptor) {
                    Ok(()) => {
                        self.toasts
                            .success(format!("TUN {} is up.", handover.device));
                        self.privileged_tun = Some(helper);
                        options.tun_ready = true;
                    }
                    Err(why) => {
                        close_descriptor(handover.fd);
                        self.retire_helper(helper);
                        self.toasts.error(format!("TUN handover refused: {why}"));
                    }
                }
            }
            TunOutcome::Failed(error) => {
                self.toasts.error(format!("TUN unavailable: {error}"));
                if matches!(error, ElevationError::Rejected) {
                    self.decline_elevation();
                }
            }
        }
        self.dial(action, options).await
    }

    /// Check, off the frame loop, that the live connection carries traffic.
    pub(crate) fn begin_health_check(&mut self) {
        let events = self.bg.tx.clone();
        let revision = self.stats.revision;
        let node = self.stats.active_node_name.clone();
        let port = self.settings.socks_port;
        tokio::spawn(async move {
            let result = zeronet_tui::ping::real_delay(port).await;
            let _ = events.send(BgEvent::Health {
                revision,
                node,
                result,
            });
        });
    }

    /// Hand a connect or switch to the daemon.
    pub(crate) async fn dial(
        &mut self,
        action: EngineAction,
        options: EngineOptions,
    ) -> Result<()> {
        let (EngineAction::Connect(id) | EngineAction::Switch(id)) = action else {
            return Ok(());
        };
        let Some(cfg) = self.config_by_id(id) else {
            return Ok(());
        };
        let (raw, remark) = (cfg.raw_content.clone(), cfg.remark.clone());
        let verb = if matches!(action, EngineAction::Connect(_)) {
            self.daemon.connect(raw, remark.clone(), options).await?;
            "Connecting to"
        } else {
            self.daemon
                .switch_node(raw, remark.clone(), options)
                .await?;
            "Switching to"
        };
        self.toasts.info(format!("{verb} {remark}…"));
        Ok(())
    }

    /// Enter in the password dialog: check the password off the frame loop.
    pub(crate) fn begin_password_check(&mut self, password: String) {
        if self.bg.validating {
            return;
        }
        self.bg.validating = true;
        let events = self.bg.tx.clone();
        tokio::spawn(async move {
            let attempt = password.clone();
            let result = tokio::task::spawn_blocking(move || {
                let mut attempt = attempt;
                let result = elevate::validate_password(&attempt);
                zeroize(&mut attempt);
                result
            })
            .await
            .unwrap_or_else(|e| Err(ElevationError::Failed(e.to_string())));
            let _ = events.send(BgEvent::PasswordChecked { password, result });
        });
    }

    async fn on_password_checked(
        &mut self,
        mut password: String,
        result: Result<(), ElevationError>,
    ) -> Result<()> {
        let dialog_up = matches!(self.modal_state, ModalState::SudoPassword { .. });
        if let Err(error) = result {
            zeroize(&mut password);
            if matches!(error, ElevationError::Rejected) && dialog_up {
                // Keep the dialog up with the reason on it: a wrong password
                // is the one failure worth a second try in place.
                self.open_sudo_dialog(Some(error.to_string()));
                return Ok(());
            }
            self.toasts.error(format!("TUN unavailable: {error}"));
            if dialog_up {
                self.close_modal();
            }
            // The connect that was waiting still goes ahead, in proxy mode:
            // dropping it left the connection manager believing the user was
            // online while nothing had been dialled.
            let pending = self.pending_elevation.take();
            self.decline_elevation();
            if let Some(action) = pending {
                let options = self.engine_options();
                let mut options = options;
                options.tun_ready = false;
                self.dial(action, options).await?;
            }
            return Ok(());
        }

        if dialog_up {
            self.close_modal();
        }
        match self.pending_elevation.take() {
            Some(action) => self.begin_tun_connect(action, Some(password)),
            None => {
                zeroize(&mut password);
                self.toasts.success("Administrator rights granted.");
            }
        }
        Ok(())
    }

    /// Stop using the current TUN helper without waiting for it.
    ///
    /// Dropping a helper blocks until it has removed its routes (bounded at
    /// two seconds), so that happens on the blocking pool; the next helper
    /// waits for it through `tun_teardown`.
    pub(crate) fn retire_helper(&mut self, helper: Box<PrivilegedTun>) {
        // Without the tunnel's routes, binding to the uplink is pointless and,
        // if the network changes, harmful.
        zero_core::platform::set_bound_interface(None);
        let previous = self.bg.tun_teardown.take();
        self.bg.tun_teardown = Some(tokio::spawn(async move {
            if let Some(previous) = previous {
                let _ = previous.await;
            }
            let _ = tokio::task::spawn_blocking(move || drop(helper)).await;
        }));
    }

    /// Invalidate any TUN job in flight: its result now belongs to a request
    /// the user has moved on from.
    pub(crate) fn cancel_pending_connect(&mut self) {
        self.bg.generation += 1;
        self.bg.tun_job = None;
    }

    /// Whether a connect is still being prepared — a TUN job running, or a
    /// password being asked for or checked — and has not reached the daemon.
    pub(crate) fn connect_in_progress(&self) -> bool {
        self.bg.tun_job.is_some() || self.bg.validating || self.pending_elevation.is_some()
    }

    // ---------------------------------------------------------- pings

    /// Start a latency sweep, replacing one still in progress.
    pub(crate) fn start_ping_sweep(
        &mut self,
        targets: Vec<PingTarget>,
        tx: tokio::sync::mpsc::UnboundedSender<PingResult>,
    ) {
        if let Some(previous) = self.bg.sweep.take() {
            previous.abort();
        }
        self.bg.sweep = Some(tokio::spawn(async move {
            ping_all(targets, tx).await;
        }));
    }

    /// Buffer a reading for the database.
    pub(crate) fn record_ping(&mut self, config_id: i64, latency_ms: f64) {
        self.bg.pending_pings.push((config_id, latency_ms));
        if self.bg.pending_pings.len() >= PING_FLUSH_BATCH {
            self.flush_ping_writes();
        }
    }

    /// Write buffered readings in one transaction on the blocking pool.
    fn flush_ping_writes(&mut self) {
        if self.bg.pending_pings.is_empty() {
            return;
        }
        if self
            .bg
            .ping_flush
            .as_ref()
            .is_some_and(|h| !h.is_finished())
        {
            return; // The next housekeeping tick picks the rest up.
        }
        let batch = std::mem::take(&mut self.bg.pending_pings);
        let db = self.db.clone();
        self.bg.ping_flush = Some(tokio::task::spawn_blocking(move || {
            if let Err(error) = db.record_pings(&batch) {
                tracing::warn!(%error, "saving latency readings failed");
            }
        }));
    }

    // ---------------------------------------------------------- feeds

    /// Fetch one feed in the background, unless it is already being fetched.
    pub(crate) fn spawn_feed_fetch(&mut self, id: i64, name: String, url: String) -> bool {
        if !self.bg.feeds_in_flight.insert(id) {
            return false;
        }
        self.bg.feed_attempts.insert(id, Instant::now());
        let tx = self.feed_tx.clone();
        let (socks_port, http_port) = (self.settings.socks_port, self.settings.http_port);
        tokio::spawn(async move {
            let result = fetch_and_build(url, socks_port, http_port).await;
            let _ = tx.send(FeedUpdate { id, name, result });
        });
        true
    }

    /// Auto-update: refresh every feed whose interval has elapsed.
    fn refresh_due_subscriptions(&mut self) {
        let interval = i64::from(self.settings.sub_update_interval_hours.max(1)) * 3600;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        let due: Vec<(i64, String, String)> = self
            .subscriptions
            .iter()
            .filter(|sub| sub.last_updated.is_none_or(|at| now - at >= interval))
            .filter(|sub| {
                self.bg
                    .feed_attempts
                    .get(&sub.id)
                    .is_none_or(|at| at.elapsed() >= FEED_RETRY_GAP)
            })
            .map(|sub| (sub.id, sub.remark.clone(), sub.url.clone()))
            .collect();
        for (id, name, url) in due {
            self.spawn_feed_fetch(id, name, url);
        }
    }

    // ------------------------------------------------------ shutdown

    /// Undo everything this session changed on the machine, in order, and
    /// wait for it. Runs on every way out of the frame loop — a quit, a
    /// signal, a dead terminal, an error — not just the quit dialog.
    pub(crate) async fn shutdown(&mut self) {
        if let Some(scan) = self.scan_handle.take() {
            scan.abort();
        }
        if let Some(sweep) = self.bg.sweep.take() {
            sweep.abort();
        }
        // Nothing still in flight may re-arm TUN after this point.
        self.cancel_pending_connect();

        // The desktop first, so applications stop using the proxy before it
        // disappears. Queued behind any change still in flight.
        let (ack_tx, ack_rx) = oneshot::channel();
        self.bg.queue_proxy(ProxyJob::Revert {
            announce: false,
            ack: Some(ack_tx),
        });
        match tokio::time::timeout(PROXY_REVERT_TIMEOUT, ack_rx).await {
            Ok(_) => tracing::info!("system proxy restored on exit"),
            Err(_) => tracing::error!("timed out restoring the system proxy on exit"),
        }
        self.pac_server = None;

        self.daemon.shutdown().await;

        self.release_privileged_tun();
        if let Some(teardown) = self.bg.tun_teardown.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), teardown).await;
        }

        if let Some(flush) = self.bg.ping_flush.take() {
            let _ = flush.await;
        }
        let batch = std::mem::take(&mut self.bg.pending_pings);
        if !batch.is_empty() {
            let db = self.db.clone();
            let _ = tokio::task::spawn_blocking(move || db.record_pings(&batch)).await;
        }
    }
}

/// Bring a TUN interface up through the privileged helper, on the blocking
/// pool. Decides first whether it can be done without a password.
/// Reuse a running helper for another profile: same interface, new bypass
/// route, fresh descriptor. Hands the helper back when the profile needs a
/// different interface or the helper could not be updated.
async fn retarget_tun(
    raw: &str,
    options: &EngineOptions,
    mut helper: Box<PrivilegedTun>,
) -> Result<(Box<PrivilegedTun>, TunHandover), Option<Box<PrivilegedTun>>> {
    let Ok(built) = zeronet_tui::daemon::prepare_runnable_config_with(raw, options) else {
        return Err(Some(helper));
    };
    let Some(request) = elevate::request_from_config(&built, "") else {
        return Err(Some(helper));
    };
    if !helper.serves(&request) {
        return Err(Some(helper));
    }
    let joined = tokio::task::spawn_blocking(move || {
        let result = helper.retarget(&request);
        (helper, result)
    })
    .await;
    match joined {
        Ok((helper, Ok(handover))) => Ok((helper, handover)),
        Ok((helper, Err(error))) => {
            tracing::warn!(%error, "reusing the TUN interface failed; rebuilding it");
            Err(Some(helper))
        }
        // The blocking task panicked and took the helper with it; its drop
        // has already asked the helper to tear down.
        Err(_) => Err(None),
    }
}

async fn arm_tun(
    raw: &str,
    options: &EngineOptions,
    password: Option<&str>,
    prompt_allowed: bool,
) -> TunOutcome {
    if password.is_none() {
        let ready = tokio::task::spawn_blocking(elevate::privileges_ready)
            .await
            .unwrap_or(false);
        if !ready {
            return if prompt_allowed {
                TunOutcome::NeedPassword
            } else {
                TunOutcome::Skipped
            };
        }
    }

    let socket = elevate::handover_socket_path();
    let built = match zeronet_tui::daemon::prepare_runnable_config_with(raw, options) {
        Ok(built) => built,
        // The dial itself will report the bad profile.
        Err(error) => return TunOutcome::Failed(ElevationError::Failed(format!("{error:#}"))),
    };
    let Some(request) = elevate::request_from_config(&built, &socket) else {
        return TunOutcome::Failed(ElevationError::Failed(
            "the profile has no TUN inbound".into(),
        ));
    };
    let owned = password.map(str::to_owned);
    let opened = tokio::task::spawn_blocking(move || {
        let mut owned = owned;
        let result = elevate::open_privileged_tun(&request, owned.as_deref());
        if let Some(secret) = owned.as_mut() {
            zeroize(secret);
        }
        result
    })
    .await;
    match opened {
        Ok(Ok((helper, handover))) => TunOutcome::Armed(Box::new(helper), handover),
        Ok(Err(error)) => TunOutcome::Failed(error),
        Err(error) => TunOutcome::Failed(ElevationError::Failed(error.to_string())),
    }
}
