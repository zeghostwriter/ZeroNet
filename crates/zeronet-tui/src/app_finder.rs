//! The config finder in the client: find a working server and connect to it,
//! like the Android app, and share how the found servers fared.
//!
//! `F` (or F3, or the footer button) starts a search (`zeronet_tui::finder`).
//! Known servers are tested first — earlier finds that worked, then what
//! other users report working — and only then the public feeds. The first
//! server that carries a real request is stored as a profile (origin
//! `found` or `crowd`) and, unless the user is already connected, dialled at
//! once; the search goes on for a couple of backups. When a found server's
//! post-connect check fails, the next best found one is tried.
//!
//! Crowd reports name servers by their link key and carry only found
//! profiles' results: a profile the user imported, typed or subscribed to is
//! never part of one. They are anonymous (see `deploy/crowd-relay`) and can
//! be turned off in Settings (Server finder → Help others connect).

use std::time::Instant;

use super::*;
use zeronet_tui::finder::{self, FinderEvent, FinderRequest, Origin, Progress, Tally};

/// Stop searching once this many servers work.
const WANT_ALIVE: usize = 3;
/// Found servers tried in a row after failed checks before searching anew.
const MAX_SWITCHES: u32 = 4;
/// `settings` keys outside `AppSettings`.
const CROWD_NET_KEY: &str = "crowd_net";
const NONCE_KEY: &str = "crowd_nonce";
const NONCE_DAY_KEY: &str = "crowd_nonce_day";

/// One running search.
pub(crate) struct FinderSession {
    cancel: zero_discovery::CancellationToken,
    /// Connect to the first server found (when not already connected).
    connect: bool,
    /// Dial the first find even though a connection is up: the one in use
    /// stopped carrying traffic.
    replace: bool,
    stage: String,
    progress: Progress,
    found: usize,
    started: Instant,
}

/// The finder's part of the app.
pub(crate) struct FinderState {
    pub(crate) session: Option<FinderSession>,
    pub(crate) tx: tokio::sync::mpsc::UnboundedSender<FinderEvent>,
    pub(crate) rx: tokio::sync::mpsc::UnboundedReceiver<FinderEvent>,
    /// Results of found servers awaiting a crowd report.
    tally: Tally,
    /// Found servers dialled in a row after failed checks.
    switches: u32,
    /// A report is being sent.
    reporting: bool,
}

impl FinderState {
    pub(crate) fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            session: None,
            tx,
            rx,
            tally: Tally::default(),
            switches: 0,
            reporting: false,
        }
    }

    pub(crate) fn running(&self) -> bool {
        self.session.is_some()
    }
}

impl App<'_> {
    /// Where the finder keeps feed and rankings caches.
    fn finder_cache_dir(&self) -> Option<std::path::PathBuf> {
        self.db.path().parent().map(|dir| dir.join("finder"))
    }

    /// Start a search; `connect` dials the first server found unless a
    /// connection is already up or on its way.
    pub(crate) fn start_finder(&mut self, connect: bool) {
        if let Some(session) = &mut self.finder.session {
            // Asking again while a search runs only upgrades it to connect.
            if connect && !session.connect {
                session.connect = true;
                self.toasts.info("Still searching. Will connect to the first server that works.");
            } else {
                self.toasts.info("Already searching for servers…");
            }
            return;
        }
        let request = FinderRequest {
            history: self.db.found_history(finder::HISTORY_LINKS).unwrap_or_default(),
            sources: zero_discovery::sources::enabled(&[], self.settings.finder_max_tier),
            cache_dir: self.finder_cache_dir(),
            want_alive: WANT_ALIVE,
            max_seconds: 90,
            crowd_net: self
                .db
                .get_value(CROWD_NET_KEY)
                .filter(|net| zero_discovery::crowd::valid_net(net))
                .unwrap_or_else(|| zero_discovery::crowd::ALL_NETS.into()),
            use_crowd: true,
        };
        let cancel = zero_discovery::CancellationToken::new();
        let tx = self.finder.tx.clone();
        tokio::spawn(finder::run(request, tx, cancel.clone()));
        let connect = connect && !self.connection.wants_connection();
        self.finder.session = Some(FinderSession {
            cancel,
            connect,
            replace: false,
            stage: "known".into(),
            progress: Progress::default(),
            found: 0,
            started: Instant::now(),
        });
        self.toasts.info(if connect {
            "Looking for a server that works on this network…"
        } else {
            "Looking for more working servers…"
        });
    }

    /// Stop the search, keeping what it found.
    pub(crate) fn cancel_finder(&mut self) {
        if let Some(session) = &self.finder.session {
            session.cancel.cancel();
        }
    }

    /// One event from the search. Returns whether the screen changed.
    pub(crate) async fn on_finder_event(&mut self, event: FinderEvent) -> bool {
        match event {
            FinderEvent::Stage(stage) => {
                if let Some(session) = &mut self.finder.session {
                    session.stage = stage;
                }
            }
            FinderEvent::Progress(progress) => {
                if let Some(session) = &mut self.finder.session {
                    session.progress = progress;
                }
            }
            FinderEvent::Failed { key } => {
                self.finder.tally.failed(&key);
                let _ = self.db.record_found_failure(&key);
            }
            FinderEvent::Note(note) => tracing::info!(%note, "finder"),
            FinderEvent::Alive { info, delay_ms, origin } => {
                self.finder.tally.ok(&info.key, delay_ms);
                let Some(id) = self.store_found(&info, delay_ms, origin) else {
                    return true;
                };
                if let Some(session) = &mut self.finder.session {
                    session.found += 1;
                }
                self.reload_configs();
                let (connect, replace) = self
                    .finder
                    .session
                    .as_ref()
                    .map_or((false, false), |s| (s.connect, s.replace));
                let online = self.connection.wants_connection();
                if connect && (!online || replace) {
                    if let Some(session) = &mut self.finder.session {
                        // Only the first find is dialled; the rest are backups.
                        session.connect = false;
                        session.replace = false;
                    }
                    self.toasts.success(format!("Found {} · {delay_ms} ms. Connecting…", info.name));
                    // Already online: switch the running engine over.
                    let action = if online {
                        self.connection.select(id)
                    } else {
                        self.connection.connect_to(id)
                    };
                    self.focus_profile(id);
                    if let Err(error) = self.apply_engine_action(action).await {
                        self.toasts.error(format!("Connecting failed: {error}"));
                    }
                } else {
                    self.toasts.info(format!("Found {} · {delay_ms} ms", info.name));
                }
            }
            FinderEvent::Done { alive, reason } => {
                let session = self.finder.session.take();
                let seconds = session.as_ref().map_or(0, |s| s.started.elapsed().as_secs());
                let _ = self.db.prune_found(self.settings.finder_keep);
                self.reload_configs();
                if alive == 0 && reason != "cancelled" {
                    self.toasts.warning(
                        "No working server found this time. Try again in a while, raise Search Depth in Settings, or add a config of your own.",
                    );
                    if let Some(session) = &session {
                        if session.connect {
                            self.connection.on_engine_failed();
                        }
                    }
                } else if alive > 0 {
                    self.toasts.info(format!(
                        "Search finished: {alive} working server{} in {seconds} s.",
                        if alive == 1 { "" } else { "s" }
                    ));
                }
                self.flush_crowd_report();
            }
        }
        true
    }

    /// Build a runnable profile from a found link and store it. Returns the
    /// profile id, or `None` when the link cannot run here.
    fn store_found(&mut self, info: &zero_discovery::LinkInfo, delay_ms: u32, origin: Origin) -> Option<i64> {
        let link = zero_config::parse_link(&info.link).ok()?;
        let (json, remark, protocol, address, port) = match self.profile_from_link(&link) {
            Ok(profile) => profile,
            Err(error) => {
                tracing::debug!(%error, "a found server cannot run here");
                return None;
            }
        };
        let found = zeronet_tui::db::FoundServer {
            remark: &remark,
            protocol: &protocol,
            address: &address,
            port,
            raw_content: &json,
            link: &info.link,
            link_key: &info.key,
            origin: origin.as_str(),
            delay_ms: f64::from(delay_ms),
        };
        self.db.upsert_found(&found).ok()
    }

    /// The post-connect check of a found server finished: count it, and when
    /// it carries nothing, move to the next best found server (or search).
    pub(crate) async fn on_found_health(&mut self, id: i64, result: &Result<Duration, String>) {
        let Some(key) = self.db.found_link_key(id) else {
            return;
        };
        match result {
            Ok(delay) => {
                self.finder.switches = 0;
                self.finder.tally.ok(&key, delay.as_millis().min(u128::from(u32::MAX)) as u32);
            }
            Err(_) => {
                self.finder.tally.failed(&key);
                let _ = self.db.record_found_failure(&key);
                self.reload_configs();
                if !self.connection.wants_connection() {
                    return;
                }
                self.finder.switches += 1;
                let next = self
                    .db
                    .found_ranked()
                    .unwrap_or_default()
                    .into_iter()
                    .find(|candidate| {
                        *candidate != id && self.config_by_id(*candidate).is_some_and(|c| c.ping_ms.is_some())
                    });
                match next {
                    Some(next) if self.finder.switches <= MAX_SWITCHES => {
                        let name = self.config_by_id(next).map(|c| c.remark.clone()).unwrap_or_default();
                        self.toasts.info(format!("Trying another found server: {name}"));
                        let action = self.connection.connect_to(next);
                        self.focus_profile(next);
                        if let Err(error) = self.apply_engine_action(action).await {
                            self.toasts.error(format!("Switching failed: {error}"));
                        }
                    }
                    _ => {
                        self.finder.switches = 0;
                        if !self.finder.running() {
                            // Nothing left that worked: search again; the
                            // new find replaces the dead connection.
                            self.start_finder(false);
                            if let Some(session) = &mut self.finder.session {
                                session.connect = true;
                                session.replace = true;
                            }
                        }
                    }
                }
            }
        }
        if !self.finder.running() {
            self.flush_crowd_report();
        }
    }

    /// Send what the found servers did, when the user shares results.
    fn flush_crowd_report(&mut self) {
        if !self.settings.share_results {
            let _ = self.finder.tally.take();
            return;
        }
        if self.finder.reporting || self.finder.tally.is_empty() {
            return;
        }
        let results = self.finder.tally.take();
        self.finder.reporting = true;
        // In TUN mode this process's own sockets leave through the tunnel,
        // where the relay would see the VPN server instead of this network.
        let through_tunnel = self.stats.tun_active
            && matches!(self.stats.status, ConnectionStatus::Connected | ConnectionStatus::Reconnecting);
        let nonce = self.daily_nonce();
        let cache = self.finder_cache_dir();
        let events = self.bg.tx.clone();
        tokio::spawn(async move {
            let count = results.len();
            let result = finder::report(cache, nonce, through_tunnel, results).await;
            let _ = events.send(app_tasks::BgEvent::CrowdReported { count, result });
        });
    }

    /// The relay answered (or did not).
    pub(crate) fn on_crowd_reported(&mut self, count: usize, result: Result<Option<String>, String>) {
        self.finder.reporting = false;
        match result {
            Ok(net) => {
                tracing::info!(count, ?net, "crowd report sent");
                if let Some(net) = net.filter(|net| zero_discovery::crowd::valid_net(net)) {
                    let _ = self.db.set_value(CROWD_NET_KEY, &net);
                }
            }
            // Sharing must never get in the way: logged, not shown.
            Err(error) => tracing::info!(%error, "crowd report not sent"),
        }
    }

    /// A random value for today, sent with reports so people behind one VPN
    /// server count as different people. New every day.
    fn daily_nonce(&self) -> String {
        let day = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 86_400;
        if self.db.get_value(NONCE_DAY_KEY).as_deref() == Some(day.to_string().as_str()) {
            if let Some(nonce) = self.db.get_value(NONCE_KEY).filter(|n| n.len() == 24) {
                return nonce;
            }
        }
        let bytes: [u8; 12] = rand::random();
        let nonce: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let _ = self.db.set_value(NONCE_KEY, &nonce);
        let _ = self.db.set_value(NONCE_DAY_KEY, &day.to_string());
        nonce
    }

    /// The header's second line while a search runs.
    pub(crate) fn finder_status(&self) -> Option<String> {
        let session = self.finder.session.as_ref()?;
        let p = session.progress;
        let stage = match session.stage.as_str() {
            "known" | "history" => "testing known servers",
            "fetch" => "downloading public lists",
            "parse" => "reading lists",
            "tcp" => "reaching servers",
            "real" => "testing servers",
            other => other,
        };
        // Most telling first: a narrow header cuts the end off.
        let mut text = format!(
            "Finding servers · {} working · {stage} · {} s",
            session.found,
            session.started.elapsed().as_secs()
        );
        if p.candidates > 0 {
            text.push_str(&format!(
                " · {} candidates · {} reachable · {} tested",
                p.candidates, p.tcp_open, p.real_done
            ));
        }
        Some(text)
    }
}
