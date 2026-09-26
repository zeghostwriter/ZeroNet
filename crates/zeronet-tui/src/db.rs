//! SQLite Database for ZeroNet TUI.
//!
//! Handles:
//! - configs: storing JSON / share links for VMess, VLESS, Trojan, Shadowsocks, etc.
//! - subscriptions: saving subscription URLs, remarks, auto-update interval.
//! - metrics: latency history and packet statistics per node.
//! - settings: app settings, TUN mode, DNS presets, fragmentation toggles, scanner concurrency.

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigRecord {
    pub id: i64,
    pub remark: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub raw_content: String,
    pub is_active: bool,
    pub subscription_id: Option<i64>,
    pub ping_ms: Option<f64>,
    pub last_used: Option<i64>,
    /// Where the profile came from: `user` (imported, typed or from the
    /// user's own subscription), `found` (the config finder found it in a
    /// public feed) or `crowd` (other users' rankings). Only `found` and
    /// `crowd` profiles are ever part of a crowd report.
    #[serde(default = "user_origin")]
    pub origin: String,
}

fn user_origin() -> String {
    ORIGIN_USER.to_string()
}

/// [`ConfigRecord::origin`] of everything the user added themselves.
pub const ORIGIN_USER: &str = "user";

impl ConfigRecord {
    /// Whether the finder found this profile (public feed or crowd), so its
    /// test results may be shared.
    pub fn is_found(&self) -> bool {
        self.origin != ORIGIN_USER
    }
}

/// A server the finder found, as it is stored.
#[derive(Debug, Clone)]
pub struct FoundServer<'a> {
    pub remark: &'a str,
    pub protocol: &'a str,
    pub address: &'a str,
    pub port: u16,
    /// The runnable JSON config.
    pub raw_content: &'a str,
    /// The share link it was built from.
    pub link: &'a str,
    /// `zero_discovery::link_key` of [`FoundServer::link`].
    pub link_key: &'a str,
    pub origin: &'a str,
    pub delay_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionRecord {
    pub id: i64,
    pub remark: String,
    pub url: String,
    pub auto_update_mins: u32,
    pub last_updated: Option<i64>,
    pub node_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricRecord {
    pub id: i64,
    pub config_id: i64,
    pub latency_ms: f64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSettings {
    pub tun_enabled: bool,
    pub tun_device_name: String,
    pub tun_mtu: u16,
    pub remote_dns: String,
    pub custom_dns: String,
    pub anti_sanction: String,
    pub socks_port: u16,
    pub http_port: u16,
    pub tls_fragment_size: u16,
    pub jitter_delay_ms: u64,
    pub scanner_concurrency: usize,
    pub clean_ip_rotation: bool,
    pub mux_enabled: bool,
    pub mux_concurrency: u16,
    pub sniffing_enabled: bool,
    pub domain_strategy: String,
    pub tcp_congestion: String,
    pub anti_censorship_level: String,
    pub ipv6_enabled: bool,
    pub keepalive_interval_secs: u64,
    pub sub_update_interval_hours: u32,
    pub auto_reconnect: bool,
    /// How the desktop's proxy settings should be driven: `off`, `manual` or
    /// `pac`. See `crate::sysproxy`.
    pub system_proxy_mode: String,
    /// Port the PAC script is served on in PAC mode.
    pub pac_port: u16,

    // ---------------------------------------------------- core (v2rayN parity)
    /// Engine log verbosity: `none`, `error`, `warning`, `info`, `debug`.
    pub log_level: String,
    /// Bind the SOCKS/HTTP inbounds to `0.0.0.0` instead of loopback.
    pub allow_lan: bool,
    /// Offer UDP associate on the SOCKS inbound.
    pub udp_enabled: bool,
    /// A sniffed domain informs routing but does not rewrite the destination.
    pub sniffing_route_only: bool,
    /// uTLS ClientHello shape applied to TLS/REALITY outbounds.
    pub utls_fingerprint: String,
    /// Split the ClientHello across packets on every TLS-bearing outbound.
    pub fragment_enabled: bool,
    /// Install the default routes over TUN.
    pub tun_auto_route: bool,
    /// Also block traffic that tries to leave around the tunnel.
    pub tun_strict_route: bool,

    // ------------------------------------------------- Cloudflare edge scanner
    /// Probe depth: `tcp`, `tls` or `http`.
    pub scanner_mode: String,
    pub scanner_port: u16,
    /// Probes per candidate, which is what makes loss and jitter measurable.
    pub scanner_tries: usize,
    pub scanner_timeout_secs: u64,
    /// Candidates to test before stopping. Zero runs until stopped.
    pub scanner_target_count: usize,
    /// SNI presented while probing. Empty rotates well-known edge names.
    pub scanner_sni: String,
    /// Require a successful WebSocket upgrade before calling an edge healthy.
    pub scanner_require_ws: bool,
    pub scanner_ws_path: String,
    /// Sweep the addresses either side of every working edge.
    pub scanner_neighbors: bool,
    pub scanner_ipv4: bool,
    pub scanner_ipv6: bool,
    /// Bytes downloaded per probe to measure throughput. Zero skips it.
    pub scanner_speed_bytes: usize,

    // ---------------------------------------------------------- appearance
    /// Palette key, see `crate::theme::ThemeId::key`.
    pub theme: String,
    /// Motion on or off. The terminal can still force it off (see `caps`).
    pub animations: bool,
    /// Show the client's own CPU and memory in the status bar.
    pub show_usage: bool,
    /// Whether the hidden palette has been found.
    pub secret_theme_unlocked: bool,
    /// Notices the user chose "Don't show again" on, comma-separated keys.
    pub muted_notices: String,
    /// Look for a new release at start (release builds only).
    pub auto_update_check: bool,

    // ------------------------------------------------------- config finder
    /// Share which public servers the finder saw working (and not), anonymously.
    pub share_results: bool,
    /// Highest feed tier a search reaches (0 = the project's tested list only).
    pub finder_max_tier: u32,
    /// Keep this many found servers; the least useful beyond it are pruned.
    pub finder_keep: usize,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            tun_enabled: true,
            tun_device_name: "zeronet0".into(),
            tun_mtu: 1500,
            remote_dns: "google".into(),
            custom_dns: "".into(),
            anti_sanction: "shecan".into(),
            socks_port: 10808,
            http_port: 10809,
            tls_fragment_size: 150,
            jitter_delay_ms: 15,
            scanner_concurrency: 50,
            clean_ip_rotation: true,
            mux_enabled: false,
            mux_concurrency: 8,
            sniffing_enabled: true,
            domain_strategy: "IPIfNonMatch".into(),
            tcp_congestion: "bbr".into(),
            anti_censorship_level: "IranEvasion".into(),
            ipv6_enabled: true,
            keepalive_interval_secs: 30,
            sub_update_interval_hours: 24,
            auto_reconnect: true,
            system_proxy_mode: "unmanaged".into(),
            pac_port: 11080,

            log_level: "warning".into(),
            allow_lan: false,
            udp_enabled: true,
            sniffing_route_only: false,
            utls_fingerprint: "chrome".into(),
            fragment_enabled: false,
            tun_auto_route: true,
            tun_strict_route: false,

            scanner_mode: "http".into(),
            scanner_port: 443,
            scanner_tries: 2,
            scanner_timeout_secs: 3,
            scanner_target_count: 50,
            scanner_sni: "cloudflare.com".into(),
            scanner_require_ws: false,
            scanner_ws_path: "/".into(),
            scanner_neighbors: false,
            scanner_ipv4: true,
            scanner_ipv6: false,
            scanner_speed_bytes: 0,
            theme: "golden-dark".into(),
            animations: true,
            show_usage: true,
            secret_theme_unlocked: false,
            muted_notices: String::new(),
            auto_update_check: true,
            share_results: true,
            finder_max_tier: 2,
            finder_keep: 40,
        }
    }
}

/// How long a statement waits on a lock held by another connection (a
/// second client instance, or a backup tool) before failing with `BUSY`.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Latency samples older than this are pruned; nothing reads further back.
const METRICS_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;
/// Minimum spacing between two metrics prunes.
const METRICS_PRUNE_INTERVAL_SECS: i64 = 60 * 60;
/// Schema revision this build migrates databases up to.
const SCHEMA_VERSION: i64 = 2;

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
    db_path: PathBuf,
    /// Unix time of the last metrics prune, shared across clones.
    last_prune: Arc<std::sync::atomic::AtomicI64>,
}

impl Database {
    pub fn open<P: AsRef<Path>>(path: P) -> SqlResult<Self> {
        let db_path = path.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let conn = Connection::open(&db_path)?;
        // Without a busy timeout a second instance (or anything else holding
        // the file) turns every write into an immediate `database is locked`.
        conn.busy_timeout(BUSY_TIMEOUT)?;
        // The schema relies on `ON DELETE CASCADE`. The bundled SQLite build
        // happens to default foreign keys on, but that is a compile-time
        // choice of the library, not of this code; stating it here keeps the
        // cascade working against a system SQLite built with the stock
        // default (off).
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path,
            last_prune: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        };
        db.init_schema()?;
        db.migrate()?;
        db.prune_metrics();
        Ok(db)
    }

    /// The connection, tolerating a poisoned lock.
    ///
    /// A panic on another thread while it held the connection leaves SQLite
    /// itself consistent (every multi-row change is a transaction), so
    /// refusing all further access would only turn one failure into many.
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Open the user's database.
    ///
    /// `ZERONET_DATA_DIR` overrides the location. That exists so a test or a
    /// scripted run can be pointed at a throwaway directory: driving the real
    /// application against a developer's own database once cost a set of
    /// saved profiles, and nothing in a test should be able to reach them.
    pub fn open_default() -> SqlResult<Self> {
        let data_dir = match std::env::var_os("ZERONET_DATA_DIR") {
            Some(dir) => PathBuf::from(dir),
            None => dirs_or_local(),
        };
        Self::open(data_dir.join("zeronet.db"))
    }

    /// Open a database in a fresh temporary directory.
    ///
    /// For tests and for any automated run of the real binary.
    pub fn open_temporary(label: &str) -> SqlResult<Self> {
        let dir = std::env::temp_dir().join(format!(
            "zeronet-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        Self::open(dir.join("zeronet.db"))
    }

    pub fn path(&self) -> &Path {
        &self.db_path
    }

    fn init_schema(&self) -> SqlResult<()> {
        let conn = self.lock();
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                remark TEXT NOT NULL,
                url TEXT NOT NULL UNIQUE,
                auto_update_mins INTEGER NOT NULL DEFAULT 1440,
                last_updated INTEGER
            );

            CREATE TABLE IF NOT EXISTS configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                remark TEXT NOT NULL,
                protocol TEXT NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                raw_content TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 0,
                subscription_id INTEGER,
                ping_ms REAL,
                last_used INTEGER,
                FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_id INTEGER NOT NULL,
                latency_ms REAL NOT NULL,
                timestamp INTEGER NOT NULL,
                FOREIGN KEY (config_id) REFERENCES configs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                message TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    /// Bring an older database up to [`SCHEMA_VERSION`].
    ///
    /// Tracked with `PRAGMA user_version` so each step runs exactly once, and
    /// each step runs in its own transaction so an interrupted upgrade is
    /// retried from a consistent state on the next launch.
    fn migrate(&self) -> SqlResult<()> {
        let mut conn = self.lock();
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version >= SCHEMA_VERSION {
            return Ok(());
        }

        let tx = conn.transaction()?;
        if version < 1 {
            // A database written through a SQLite with foreign keys off can
            // hold rows whose parent is gone, and with the keys enforced any
            // later write to such a row would fail. The orphans are
            // reconciled first: latency samples of deleted profiles are
            // dropped, and profiles of a deleted feed become ordinary
            // hand-made profiles rather than being deleted behind the user's
            // back. Then the indexes the hot queries (and the cascades) need.
            tx.execute_batch(
                r#"
                DELETE FROM metrics
                 WHERE config_id NOT IN (SELECT id FROM configs);
                UPDATE configs SET subscription_id = NULL
                 WHERE subscription_id IS NOT NULL
                   AND subscription_id NOT IN (SELECT id FROM subscriptions);
                CREATE INDEX IF NOT EXISTS idx_configs_subscription
                    ON configs(subscription_id);
                CREATE INDEX IF NOT EXISTS idx_metrics_config_time
                    ON metrics(config_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_metrics_time
                    ON metrics(timestamp);
                "#,
            )?;
        }
        if version < 2 {
            // Profiles the config finder adds: where they came from (only
            // found ones are ever reported to the crowd), the share link's
            // key to recognise a server found again, and how it fared.
            tx.execute_batch(
                r#"
                ALTER TABLE configs ADD COLUMN origin TEXT NOT NULL DEFAULT 'user';
                ALTER TABLE configs ADD COLUMN link_key TEXT;
                ALTER TABLE configs ADD COLUMN share_link TEXT;
                ALTER TABLE configs ADD COLUMN found_ok INTEGER NOT NULL DEFAULT 0;
                ALTER TABLE configs ADD COLUMN found_fail INTEGER NOT NULL DEFAULT 0;
                ALTER TABLE configs ADD COLUMN last_ok INTEGER;
                CREATE INDEX IF NOT EXISTS idx_configs_link_key ON configs(link_key);
                "#,
            )?;
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()
    }

    /// Drop latency samples past the retention window.
    ///
    /// Every ping result used to add a row for ever: a client left connected
    /// grew the table by tens of thousands of rows a day with nothing ever
    /// reading them back. Rate-limited, since it runs from the write path.
    fn prune_metrics(&self) {
        use std::sync::atomic::Ordering;
        let now = now_secs();
        let last = self.last_prune.load(Ordering::Relaxed);
        if now - last < METRICS_PRUNE_INTERVAL_SECS {
            return;
        }
        self.last_prune.store(now, Ordering::Relaxed);
        let conn = self.lock();
        if let Err(error) = conn.execute(
            "DELETE FROM metrics WHERE timestamp < ?1",
            params![now - METRICS_RETENTION_SECS],
        ) {
            tracing::warn!(%error, "pruning latency samples failed");
        }
    }

    pub fn insert_feedback(&self, email: Option<&str>, message: &str) -> SqlResult<i64> {
        let conn = self.lock();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        conn.execute(
            "INSERT INTO feedback (email, message, timestamp) VALUES (?1, ?2, ?3)",
            params![email, message, ts],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn load_settings(&self) -> AppSettings {
        let conn = self.lock();
        let mut stmt = match conn.prepare("SELECT key, value FROM settings") {
            Ok(s) => s,
            Err(_) => return AppSettings::default(),
        };

        let mut settings = AppSettings::default();
        let rows = stmt.query_map([], |row| {
            let k: String = row.get(0)?;
            let v: String = row.get(1)?;
            Ok((k, v))
        });

        if let Ok(iter) = rows {
            for item in iter.flatten() {
                match item.0.as_str() {
                    "tun_enabled" => settings.tun_enabled = item.1 == "1" || item.1 == "true",
                    "tun_device_name" => settings.tun_device_name = item.1,
                    "tun_mtu" => {
                        if let Ok(p) = item.1.parse() {
                            settings.tun_mtu = p;
                        }
                    }
                    "remote_dns" => settings.remote_dns = item.1,
                    "custom_dns" => settings.custom_dns = item.1,
                    "anti_sanction" => settings.anti_sanction = item.1,
                    "socks_port" => {
                        if let Ok(p) = item.1.parse() {
                            settings.socks_port = p;
                        }
                    }
                    "http_port" => {
                        if let Ok(p) = item.1.parse() {
                            settings.http_port = p;
                        }
                    }
                    "tls_fragment_size" => {
                        if let Ok(v) = item.1.parse() {
                            settings.tls_fragment_size = v;
                        }
                    }
                    "jitter_delay_ms" => {
                        if let Ok(v) = item.1.parse() {
                            settings.jitter_delay_ms = v;
                        }
                    }
                    "scanner_concurrency" => {
                        if let Ok(v) = item.1.parse() {
                            settings.scanner_concurrency = v;
                        }
                    }
                    "clean_ip_rotation" => {
                        settings.clean_ip_rotation = item.1 == "1" || item.1 == "true"
                    }
                    "mux_enabled" => settings.mux_enabled = item.1 == "1" || item.1 == "true",
                    "mux_concurrency" => {
                        if let Ok(v) = item.1.parse() {
                            settings.mux_concurrency = v;
                        }
                    }
                    "sniffing_enabled" => {
                        settings.sniffing_enabled = item.1 == "1" || item.1 == "true"
                    }
                    "domain_strategy" => settings.domain_strategy = item.1,
                    "tcp_congestion" => settings.tcp_congestion = item.1,
                    "anti_censorship_level" => settings.anti_censorship_level = item.1,
                    "ipv6_enabled" => settings.ipv6_enabled = item.1 == "1" || item.1 == "true",
                    "keepalive_interval_secs" => {
                        if let Ok(v) = item.1.parse() {
                            settings.keepalive_interval_secs = v;
                        }
                    }
                    "sub_update_interval_hours" => {
                        if let Ok(v) = item.1.parse() {
                            settings.sub_update_interval_hours = v;
                        }
                    }
                    "auto_reconnect" => settings.auto_reconnect = item.1 == "1" || item.1 == "true",
                    "system_proxy_mode" => settings.system_proxy_mode = item.1,
                    "pac_port" => {
                        if let Ok(p) = item.1.parse() {
                            settings.pac_port = p;
                        }
                    }
                    "log_level" => settings.log_level = item.1,
                    "allow_lan" => settings.allow_lan = truthy(&item.1),
                    "udp_enabled" => settings.udp_enabled = truthy(&item.1),
                    "sniffing_route_only" => settings.sniffing_route_only = truthy(&item.1),
                    "utls_fingerprint" => settings.utls_fingerprint = item.1,
                    "fragment_enabled" => settings.fragment_enabled = truthy(&item.1),
                    "tun_auto_route" => settings.tun_auto_route = truthy(&item.1),
                    "tun_strict_route" => settings.tun_strict_route = truthy(&item.1),
                    "scanner_mode" => settings.scanner_mode = item.1,
                    "scanner_port" => {
                        if let Ok(v) = item.1.parse() {
                            settings.scanner_port = v;
                        }
                    }
                    "scanner_tries" => {
                        if let Ok(v) = item.1.parse() {
                            settings.scanner_tries = v;
                        }
                    }
                    "scanner_timeout_secs" => {
                        if let Ok(v) = item.1.parse() {
                            settings.scanner_timeout_secs = v;
                        }
                    }
                    "scanner_target_count" => {
                        if let Ok(v) = item.1.parse() {
                            settings.scanner_target_count = v;
                        }
                    }
                    "scanner_sni" => settings.scanner_sni = item.1,
                    "scanner_require_ws" => settings.scanner_require_ws = truthy(&item.1),
                    "scanner_ws_path" => settings.scanner_ws_path = item.1,
                    "scanner_neighbors" => settings.scanner_neighbors = truthy(&item.1),
                    "scanner_ipv4" => settings.scanner_ipv4 = truthy(&item.1),
                    "scanner_ipv6" => settings.scanner_ipv6 = truthy(&item.1),
                    "scanner_speed_bytes" => {
                        if let Ok(v) = item.1.parse() {
                            settings.scanner_speed_bytes = v;
                        }
                    }
                    "theme" => settings.theme = item.1,
                    "animations" => settings.animations = truthy(&item.1),
                    "show_usage" => settings.show_usage = truthy(&item.1),
                    "secret_theme_unlocked" => settings.secret_theme_unlocked = truthy(&item.1),
                    "muted_notices" => settings.muted_notices = item.1,
                    "auto_update_check" => settings.auto_update_check = truthy(&item.1),
                    "share_results" => settings.share_results = truthy(&item.1),
                    "finder_max_tier" => {
                        if let Ok(v) = item.1.parse::<u32>() {
                            settings.finder_max_tier = v.min(3);
                        }
                    }
                    "finder_keep" => {
                        if let Ok(v) = item.1.parse::<usize>() {
                            settings.finder_keep = v.clamp(5, 500);
                        }
                    }
                    _ => {}
                }
            }
        }
        settings
    }

    pub fn save_settings(&self, settings: &AppSettings) -> SqlResult<()> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )?;

        let pairs = [
            ("tun_enabled", if settings.tun_enabled { "1" } else { "0" }),
            ("tun_device_name", &settings.tun_device_name),
            ("tun_mtu", &settings.tun_mtu.to_string()),
            ("remote_dns", &settings.remote_dns),
            ("custom_dns", &settings.custom_dns),
            ("anti_sanction", &settings.anti_sanction),
            ("socks_port", &settings.socks_port.to_string()),
            ("http_port", &settings.http_port.to_string()),
            ("tls_fragment_size", &settings.tls_fragment_size.to_string()),
            ("jitter_delay_ms", &settings.jitter_delay_ms.to_string()),
            (
                "scanner_concurrency",
                &settings.scanner_concurrency.to_string(),
            ),
            (
                "clean_ip_rotation",
                if settings.clean_ip_rotation { "1" } else { "0" },
            ),
            ("mux_enabled", if settings.mux_enabled { "1" } else { "0" }),
            ("mux_concurrency", &settings.mux_concurrency.to_string()),
            (
                "sniffing_enabled",
                if settings.sniffing_enabled { "1" } else { "0" },
            ),
            ("domain_strategy", &settings.domain_strategy),
            ("tcp_congestion", &settings.tcp_congestion),
            ("anti_censorship_level", &settings.anti_censorship_level),
            (
                "ipv6_enabled",
                if settings.ipv6_enabled { "1" } else { "0" },
            ),
            (
                "keepalive_interval_secs",
                &settings.keepalive_interval_secs.to_string(),
            ),
            (
                "sub_update_interval_hours",
                &settings.sub_update_interval_hours.to_string(),
            ),
            (
                "auto_reconnect",
                if settings.auto_reconnect { "1" } else { "0" },
            ),
            ("system_proxy_mode", &settings.system_proxy_mode),
            ("pac_port", &settings.pac_port.to_string()),
            ("log_level", &settings.log_level),
            ("allow_lan", if settings.allow_lan { "1" } else { "0" }),
            ("udp_enabled", if settings.udp_enabled { "1" } else { "0" }),
            (
                "sniffing_route_only",
                if settings.sniffing_route_only {
                    "1"
                } else {
                    "0"
                },
            ),
            ("utls_fingerprint", &settings.utls_fingerprint),
            (
                "fragment_enabled",
                if settings.fragment_enabled { "1" } else { "0" },
            ),
            (
                "tun_auto_route",
                if settings.tun_auto_route { "1" } else { "0" },
            ),
            (
                "tun_strict_route",
                if settings.tun_strict_route { "1" } else { "0" },
            ),
            ("scanner_mode", &settings.scanner_mode),
            ("scanner_port", &settings.scanner_port.to_string()),
            ("scanner_tries", &settings.scanner_tries.to_string()),
            (
                "scanner_timeout_secs",
                &settings.scanner_timeout_secs.to_string(),
            ),
            (
                "scanner_target_count",
                &settings.scanner_target_count.to_string(),
            ),
            ("scanner_sni", &settings.scanner_sni),
            (
                "scanner_require_ws",
                if settings.scanner_require_ws {
                    "1"
                } else {
                    "0"
                },
            ),
            ("scanner_ws_path", &settings.scanner_ws_path),
            (
                "scanner_neighbors",
                if settings.scanner_neighbors { "1" } else { "0" },
            ),
            (
                "scanner_ipv4",
                if settings.scanner_ipv4 { "1" } else { "0" },
            ),
            (
                "scanner_ipv6",
                if settings.scanner_ipv6 { "1" } else { "0" },
            ),
            (
                "scanner_speed_bytes",
                &settings.scanner_speed_bytes.to_string(),
            ),
            ("theme", &settings.theme),
            ("animations", if settings.animations { "1" } else { "0" }),
            ("show_usage", if settings.show_usage { "1" } else { "0" }),
            (
                "secret_theme_unlocked",
                if settings.secret_theme_unlocked {
                    "1"
                } else {
                    "0"
                },
            ),
            ("muted_notices", &settings.muted_notices),
            (
                "auto_update_check",
                if settings.auto_update_check { "1" } else { "0" },
            ),
            ("share_results", if settings.share_results { "1" } else { "0" }),
            ("finder_max_tier", &settings.finder_max_tier.to_string()),
            ("finder_keep", &settings.finder_keep.to_string()),
        ];

        for (k, v) in pairs {
            stmt.execute(params![k, v])?;
        }
        Ok(())
    }

    pub fn get_configs(&self) -> SqlResult<Vec<ConfigRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT id, remark, protocol, address, port, raw_content, is_active, subscription_id, ping_ms, last_used, origin
             FROM configs ORDER BY is_active DESC, id ASC"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(ConfigRecord {
                id: row.get(0)?,
                remark: row.get(1)?,
                protocol: row.get(2)?,
                address: row.get(3)?,
                port: row.get(4)?,
                raw_content: row.get(5)?,
                is_active: row.get::<_, i64>(6)? != 0,
                subscription_id: row.get(7)?,
                ping_ms: row.get(8)?,
                last_used: row.get(9)?,
                origin: row.get(10)?,
            })
        })?;

        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    pub fn insert_config(
        &self,
        remark: &str,
        protocol: &str,
        address: &str,
        port: u16,
        raw_content: &str,
        subscription_id: Option<i64>,
    ) -> SqlResult<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO configs (remark, protocol, address, port, raw_content, is_active, subscription_id)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![remark, protocol, address, port, raw_content, subscription_id],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn delete_config(&self, id: i64) -> SqlResult<()> {
        let conn = self.lock();
        conn.execute("DELETE FROM configs WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Rename a profile.
    pub fn rename_config(&self, id: i64, remark: &str) -> SqlResult<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE configs SET remark = ?2 WHERE id = ?1",
            params![id, remark],
        )?;
        Ok(())
    }

    /// Delete several profiles in one transaction.
    ///
    /// Bulk delete is a single unit of work so a failure part-way through
    /// cannot leave the list half-pruned.
    pub fn delete_configs(&self, ids: &[i64]) -> SqlResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let mut removed = 0;
        {
            let mut stmt = tx.prepare("DELETE FROM configs WHERE id = ?1")?;
            for id in ids {
                removed += stmt.execute(params![id])?;
            }
        }
        tx.commit()?;
        Ok(removed)
    }

    /// Copy a profile, giving the copy a distinct name.
    pub fn duplicate_config(&self, id: i64) -> SqlResult<i64> {
        let conn = self.lock();
        let (remark, protocol, address, port, raw, sub_id): (
            String,
            String,
            String,
            u16,
            String,
            Option<i64>,
        ) = conn.query_row(
            "SELECT remark, protocol, address, port, raw_content, subscription_id
             FROM configs WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;

        conn.execute(
            "INSERT INTO configs (remark, protocol, address, port, raw_content, is_active, subscription_id)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![format!("{remark} (copy)"), protocol, address, port, raw, sub_id],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Replace every profile belonging to a subscription.
    ///
    /// Done in one transaction so a feed that fails half-way through cannot
    /// leave the user with a partially-updated node list — they either get
    /// the new set or keep the old one.
    pub fn replace_subscription_configs(
        &self,
        subscription_id: i64,
        profiles: &[(String, String, String, u16, String)],
    ) -> SqlResult<usize> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;

        // The feed may have been deleted while its fetch was in flight.
        // Writing its nodes anyway would resurrect profiles the user just
        // removed, attached to a feed that no longer exists.
        let exists: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM subscriptions WHERE id = ?1)",
            params![subscription_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }

        // Remember which profile was in use so the refresh does not silently
        // change the active node.
        let active_remark: Option<String> = tx
            .query_row(
                "SELECT remark FROM configs WHERE subscription_id = ?1 AND is_active = 1",
                params![subscription_id],
                |row| row.get(0),
            )
            .ok();

        tx.execute(
            "DELETE FROM configs WHERE subscription_id = ?1",
            params![subscription_id],
        )?;

        let mut inserted = 0;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO configs (remark, protocol, address, port, raw_content, is_active, subscription_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            )?;
            for (remark, protocol, address, port, raw) in profiles {
                stmt.execute(params![
                    remark,
                    protocol,
                    address,
                    port,
                    raw,
                    subscription_id
                ])?;
                inserted += 1;
            }
        }

        if let Some(remark) = active_remark {
            tx.execute(
                "UPDATE configs SET is_active = 1
                 WHERE subscription_id = ?1 AND remark = ?2",
                params![subscription_id, remark],
            )?;
        }

        tx.execute(
            "UPDATE subscriptions SET last_updated = ?2 WHERE id = ?1",
            params![subscription_id, now_secs()],
        )?;

        tx.commit()?;
        Ok(inserted)
    }

    /// Update a profile's stored JSON and endpoint.
    pub fn update_config_content(
        &self,
        id: i64,
        address: &str,
        port: u16,
        raw_content: &str,
    ) -> SqlResult<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE configs SET address = ?2, port = ?3, raw_content = ?4 WHERE id = ?1",
            params![id, address, port, raw_content],
        )?;
        Ok(())
    }

    /// Mark one profile as the one in use.
    ///
    /// One transaction, so a crash between clearing the old flag and setting
    /// the new one cannot leave the database with no active profile.
    pub fn set_active_config(&self, id: i64) -> SqlResult<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE configs SET is_active = 0 WHERE is_active != 0 AND id != ?1",
            params![id],
        )?;
        tx.execute(
            "UPDATE configs SET is_active = 1, last_used = ?2 WHERE id = ?1",
            params![id, now_secs()],
        )?;
        tx.commit()
    }

    pub fn update_config_ping(&self, id: i64, latency_ms: f64) -> SqlResult<()> {
        self.record_pings(&[(id, latency_ms)])
    }

    /// Store a batch of latency readings in one transaction.
    ///
    /// A latency sweep over a large subscription produces hundreds of
    /// readings within a couple of seconds; committing each one separately
    /// cost two statements and a WAL commit apiece.
    pub fn record_pings(&self, readings: &[(i64, f64)]) -> SqlResult<()> {
        if readings.is_empty() {
            return Ok(());
        }
        let ts = now_secs();
        {
            let mut conn = self.lock();
            let tx = conn.transaction()?;
            {
                let mut update =
                    tx.prepare_cached("UPDATE configs SET ping_ms = ?2 WHERE id = ?1")?;
                let mut sample = tx.prepare_cached(
                    "INSERT INTO metrics (config_id, latency_ms, timestamp)
                     SELECT ?1, ?2, ?3 WHERE EXISTS (SELECT 1 FROM configs WHERE id = ?1)",
                )?;
                for (id, latency_ms) in readings {
                    // A profile deleted while its probe was in flight simply
                    // has nothing to update; that is not an error.
                    update.execute(params![id, latency_ms])?;
                    sample.execute(params![id, latency_ms, ts])?;
                }
            }
            tx.commit()?;
        }
        self.prune_metrics();
        Ok(())
    }

    // ------------------------------------------------------- config finder

    /// Store a server the finder saw working, or refresh the one already
    /// stored for the same link. A server the user added themselves is never
    /// touched or re-labelled: only found profiles are matched by key.
    /// Returns the profile id.
    pub fn upsert_found(&self, found: &FoundServer<'_>) -> SqlResult<i64> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let now = now_secs();
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM configs WHERE link_key = ?1 AND origin != 'user' LIMIT 1",
                params![found.link_key],
                |row| row.get(0),
            )
            .ok();
        let id = match existing {
            Some(id) => {
                tx.execute(
                    "UPDATE configs SET ping_ms = ?2, found_ok = found_ok + 1, last_ok = ?3 WHERE id = ?1",
                    params![id, found.delay_ms, now],
                )?;
                id
            }
            None => {
                tx.execute(
                    "INSERT INTO configs (remark, protocol, address, port, raw_content, is_active,
                                          subscription_id, ping_ms, origin, link_key, share_link,
                                          found_ok, last_ok)
                     VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, ?6, ?7, ?8, ?9, 1, ?10)",
                    params![
                        found.remark,
                        found.protocol,
                        found.address,
                        found.port,
                        found.raw_content,
                        found.delay_ms,
                        found.origin,
                        found.link_key,
                        found.link,
                        now
                    ],
                )?;
                tx.last_insert_rowid()
            }
        };
        tx.execute(
            "INSERT INTO metrics (config_id, latency_ms, timestamp) VALUES (?1, ?2, ?3)",
            params![id, found.delay_ms, now],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// A found server failed a test (or its health check): count it.
    pub fn record_found_failure(&self, link_key: &str) -> SqlResult<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE configs SET found_fail = found_fail + 1, ping_ms = NULL
             WHERE link_key = ?1 AND origin != 'user'",
            params![link_key],
        )?;
        Ok(())
    }

    /// The link key of a found profile, if it is one.
    pub fn found_link_key(&self, id: i64) -> Option<String> {
        let conn = self.lock();
        conn.query_row(
            "SELECT link_key FROM configs WHERE id = ?1 AND origin != 'user'",
            params![id],
            |row| row.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten()
    }

    /// Share links of found servers that worked, most recent success first:
    /// what the next search tests before anything else.
    pub fn found_history(&self, limit: usize) -> SqlResult<Vec<String>> {
        let conn = self.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT share_link FROM configs
             WHERE origin != 'user' AND share_link IS NOT NULL AND last_ok IS NOT NULL
             ORDER BY last_ok DESC, found_ok - found_fail DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| row.get::<_, String>(0))?;
        rows.collect()
    }

    /// Found profiles, best first: the working ones by delay, then the rest.
    pub fn found_ranked(&self) -> SqlResult<Vec<i64>> {
        let conn = self.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT id FROM configs WHERE origin != 'user'
             ORDER BY CASE WHEN ping_ms IS NULL THEN 1 ELSE 0 END, ping_ms ASC, last_ok DESC",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
        rows.collect()
    }

    /// Keep at most `keep` found profiles: the active one always stays, then
    /// the most useful (successes minus failures, most recent success).
    /// Returns how many were removed.
    pub fn prune_found(&self, keep: usize) -> SqlResult<usize> {
        let conn = self.lock();
        conn.execute(
            "DELETE FROM configs WHERE origin != 'user' AND is_active = 0 AND id NOT IN (
                 SELECT id FROM configs WHERE origin != 'user'
                 ORDER BY is_active DESC, found_ok - found_fail DESC, last_ok DESC
                 LIMIT ?1)",
            params![keep as i64],
        )
    }

    /// A small named value outside [`AppSettings`] (the crowd network name,
    /// the daily report nonce).
    pub fn get_value(&self, key: &str) -> Option<String> {
        let conn = self.lock();
        conn.query_row("SELECT value FROM settings WHERE key = ?1", params![key], |row| row.get(0))
            .ok()
    }

    pub fn set_value(&self, key: &str, value: &str) -> SqlResult<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_active_config(&self) -> SqlResult<Option<ConfigRecord>> {
        let list = self.get_configs()?;
        Ok(list.into_iter().find(|c| c.is_active))
    }

    pub fn get_subscriptions(&self) -> SqlResult<Vec<SubscriptionRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT s.id, s.remark, s.url, s.auto_update_mins, s.last_updated,
                    (SELECT COUNT(*) FROM configs c WHERE c.subscription_id = s.id) as node_count
             FROM subscriptions s ORDER BY s.id ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(SubscriptionRecord {
                id: row.get(0)?,
                remark: row.get(1)?,
                url: row.get(2)?,
                auto_update_mins: row.get(3)?,
                last_updated: row.get(4)?,
                node_count: row.get::<_, i64>(5)? as usize,
            })
        })?;

        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }
        Ok(list)
    }

    /// Add a feed, or rename it when the URL is already known.
    ///
    /// Returns the feed's id in both cases. `last_insert_rowid` is not that:
    /// on the conflict path no row is inserted and it reports whatever the
    /// connection inserted last, which could be an unrelated profile.
    pub fn insert_subscription(&self, remark: &str, url: &str) -> SqlResult<i64> {
        let conn = self.lock();
        conn.query_row(
            "INSERT INTO subscriptions (remark, url) VALUES (?1, ?2)
             ON CONFLICT(url) DO UPDATE SET remark = excluded.remark
             RETURNING id",
            params![remark, url],
            |row| row.get(0),
        )
    }

    /// Delete a feed and every profile it added.
    ///
    /// The profiles are removed explicitly as well as through the foreign
    /// key, in one transaction, so the outcome does not depend on how the
    /// connection happened to be configured.
    pub fn delete_subscription(&self, id: i64) -> SqlResult<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM configs WHERE subscription_id = ?1",
            params![id],
        )?;
        tx.execute("DELETE FROM subscriptions WHERE id = ?1", params![id])?;
        tx.commit()
    }

    pub fn get_metrics_history(&self, config_id: i64, limit: usize) -> SqlResult<Vec<f64>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT latency_ms FROM metrics WHERE config_id = ?1 ORDER BY timestamp DESC LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![config_id, limit as i64], |row| row.get(0))?;
        let mut pings = Vec::new();
        for r in rows {
            pings.push(r?);
        }
        pings.reverse();
        Ok(pings)
    }
}

fn dirs_or_local() -> PathBuf {
    if let Some(mut dir) = dirs_home() {
        dir.push(".zeronet");
        dir
    } else {
        PathBuf::from("./data")
    }
}

fn dirs_home() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("APPDATA"))
            .ok()
            .map(PathBuf::from)
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// A stored boolean. Historic rows were written both ways, so both are read.
fn truthy(value: &str) -> bool {
    matches!(value, "1" | "true" | "TRUE" | "True" | "yes" | "on")
}

/// Seconds since the Unix epoch.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field of `AppSettings`, moved off its default.
    ///
    /// The point is that adding a field to the struct and forgetting either
    /// half of the persistence pair is caught here rather than by a user whose
    /// setting silently reverts on the next launch.
    fn all_non_default() -> AppSettings {
        AppSettings {
            tun_enabled: false,
            tun_device_name: "zray9".into(),
            tun_mtu: 1280,
            remote_dns: "quad9".into(),
            custom_dns: "9.9.9.9".into(),
            anti_sanction: "electro".into(),
            socks_port: 21080,
            http_port: 21081,
            tls_fragment_size: 275,
            jitter_delay_ms: 45,
            scanner_concurrency: 320,
            clean_ip_rotation: false,
            mux_enabled: true,
            mux_concurrency: 16,
            sniffing_enabled: false,
            domain_strategy: "AsIs".into(),
            tcp_congestion: "cubic".into(),
            anti_censorship_level: "Aggressive".into(),
            ipv6_enabled: false,
            keepalive_interval_secs: 90,
            sub_update_interval_hours: 6,
            auto_reconnect: false,
            system_proxy_mode: "pac".into(),
            pac_port: 12080,

            log_level: "debug".into(),
            allow_lan: true,
            udp_enabled: false,
            sniffing_route_only: true,
            utls_fingerprint: "firefox".into(),
            fragment_enabled: true,
            tun_auto_route: false,
            tun_strict_route: true,

            scanner_mode: "tls".into(),
            scanner_port: 8443,
            scanner_tries: 7,
            scanner_timeout_secs: 9,
            scanner_target_count: 4000,
            scanner_sni: "www.speedtest.net".into(),
            scanner_require_ws: true,
            scanner_ws_path: "/ws".into(),
            scanner_neighbors: true,
            scanner_ipv4: false,
            scanner_ipv6: true,
            scanner_speed_bytes: 262_144,
            theme: "nightshade".into(),
            animations: false,
            show_usage: false,
            secret_theme_unlocked: true,
            muted_notices: "startup.elevated,startup.no-elevator".into(),
            auto_update_check: false,
            share_results: false,
            finder_max_tier: 3,
            finder_keep: 12,
        }
    }

    #[test]
    fn every_setting_survives_a_save_and_reload() {
        let db = Database::open_temporary("settings-roundtrip").expect("open");
        let wanted = all_non_default();
        db.save_settings(&wanted).expect("save");
        assert_eq!(db.load_settings(), wanted);
    }

    #[test]
    fn no_setting_is_left_at_its_default_by_the_fixture() {
        // Otherwise the round-trip test above would pass for a field that is
        // never actually written.
        assert_ne!(all_non_default(), AppSettings::default());
        let defaults = serde_json::to_value(AppSettings::default()).unwrap();
        let moved = serde_json::to_value(all_non_default()).unwrap();
        for (key, value) in defaults.as_object().unwrap() {
            assert_ne!(
                moved.get(key),
                Some(value),
                "{key} is still at its default, so the round trip does not test it"
            );
        }
    }

    #[test]
    fn a_fresh_database_reports_the_defaults() {
        let db = Database::open_temporary("settings-fresh").expect("open");
        assert_eq!(db.load_settings(), AppSettings::default());
    }

    #[test]
    fn deleting_a_feed_removes_the_profiles_it_added() {
        // The confirmation dialog promises this.
        let db = Database::open_temporary("feed-cascade").expect("open");
        let sub = db
            .insert_subscription("Feed", "https://example.com/sub")
            .unwrap();
        let rows = vec![
            (
                "A".to_string(),
                "vless".to_string(),
                "1.1.1.1".to_string(),
                443u16,
                "{}".to_string(),
            ),
            (
                "B".to_string(),
                "vless".to_string(),
                "1.1.1.2".to_string(),
                443u16,
                "{}".to_string(),
            ),
        ];
        assert_eq!(db.replace_subscription_configs(sub, &rows).unwrap(), 2);
        let own = db
            .insert_config("Mine", "vless", "9.9.9.9", 443, "{}", None)
            .unwrap();
        db.record_pings(&[(own, 12.0)]).unwrap();

        db.delete_subscription(sub).unwrap();
        let left: Vec<String> = db
            .get_configs()
            .unwrap()
            .into_iter()
            .map(|c| c.remark)
            .collect();
        assert_eq!(left, vec!["Mine".to_string()]);

        // Deleting a profile takes its latency samples with it.
        db.delete_configs(&[own]).unwrap();
        assert!(db.get_metrics_history(own, 10).unwrap().is_empty());
    }

    #[test]
    fn re_adding_a_known_feed_returns_its_own_id() {
        let db = Database::open_temporary("feed-id").expect("open");
        let first = db
            .insert_subscription("Feed", "https://example.com/a")
            .unwrap();
        // An unrelated insert in between is what `last_insert_rowid` would
        // have reported on the conflict path.
        db.insert_config("X", "vless", "1.1.1.1", 443, "{}", None)
            .unwrap();
        let again = db
            .insert_subscription("Renamed", "https://example.com/a")
            .unwrap();
        assert_eq!(first, again);
        assert_eq!(db.get_subscriptions().unwrap()[0].remark, "Renamed");
    }

    #[test]
    fn a_feed_deleted_mid_refresh_is_not_resurrected() {
        let db = Database::open_temporary("feed-gone").expect("open");
        let sub = db
            .insert_subscription("Feed", "https://example.com/b")
            .unwrap();
        db.delete_subscription(sub).unwrap();
        let rows = vec![(
            "A".to_string(),
            "vless".to_string(),
            "1.1.1.1".to_string(),
            443u16,
            "{}".to_string(),
        )];
        assert!(db.replace_subscription_configs(sub, &rows).is_err());
        assert!(db.get_configs().unwrap().is_empty());
    }

    #[test]
    fn exactly_one_profile_is_active_after_switching() {
        let db = Database::open_temporary("active").expect("open");
        let a = db
            .insert_config("A", "vless", "1.1.1.1", 443, "{}", None)
            .unwrap();
        let b = db
            .insert_config("B", "vless", "1.1.1.2", 443, "{}", None)
            .unwrap();
        db.set_active_config(a).unwrap();
        db.set_active_config(b).unwrap();
        let active: Vec<i64> = db
            .get_configs()
            .unwrap()
            .into_iter()
            .filter(|c| c.is_active)
            .map(|c| c.id)
            .collect();
        assert_eq!(active, vec![b]);
    }

    #[test]
    fn a_ping_for_a_deleted_profile_is_ignored() {
        let db = Database::open_temporary("ping-gone").expect("open");
        let a = db
            .insert_config("A", "vless", "1.1.1.1", 443, "{}", None)
            .unwrap();
        db.record_pings(&[(a, 10.0), (a + 1000, 20.0)]).unwrap();
        assert_eq!(db.get_metrics_history(a, 10).unwrap(), vec![10.0]);
        assert_eq!(db.get_configs().unwrap()[0].ping_ms, Some(10.0));
    }

    #[test]
    fn an_old_database_with_orphans_migrates_cleanly() {
        let dir = std::env::temp_dir().join(format!(
            "zeronet-migrate-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("zeronet.db");
        {
            // The shape an older build left: no foreign keys, a profile
            // pointing at a deleted feed, a sample for a deleted profile.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "PRAGMA foreign_keys = OFF;
                 CREATE TABLE subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, remark TEXT NOT NULL, url TEXT NOT NULL UNIQUE, auto_update_mins INTEGER NOT NULL DEFAULT 1440, last_updated INTEGER);
                 CREATE TABLE configs (id INTEGER PRIMARY KEY AUTOINCREMENT, remark TEXT NOT NULL, protocol TEXT NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL, raw_content TEXT NOT NULL, is_active INTEGER NOT NULL DEFAULT 0, subscription_id INTEGER, ping_ms REAL, last_used INTEGER, FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE);
                 CREATE TABLE metrics (id INTEGER PRIMARY KEY AUTOINCREMENT, config_id INTEGER NOT NULL, latency_ms REAL NOT NULL, timestamp INTEGER NOT NULL, FOREIGN KEY (config_id) REFERENCES configs(id) ON DELETE CASCADE);
                 INSERT INTO configs (remark, protocol, address, port, raw_content, subscription_id) VALUES ('Orphan', 'vless', '1.1.1.1', 443, '{}', 77);
                 INSERT INTO metrics (config_id, latency_ms, timestamp) VALUES (999, 1.0, 1);",
            )
            .unwrap();
        }
        let db = Database::open(&path).expect("migrates");
        let configs = db.get_configs().unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].subscription_id, None);
        // Profiles from before the finder are the user's own.
        assert_eq!(configs[0].origin, ORIGIN_USER);
        assert!(!configs[0].is_found());
        // And the orphan can still be written to with keys enforced.
        db.set_active_config(configs[0].id).unwrap();
        db.record_pings(&[(configs[0].id, 5.0)]).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn found<'a>(key: &'a str, link: &'a str, origin: &'a str, delay: f64) -> FoundServer<'a> {
        FoundServer {
            remark: "Found",
            protocol: "vless",
            address: "1.2.3.4",
            port: 443,
            raw_content: "{}",
            link,
            link_key: key,
            origin,
            delay_ms: delay,
        }
    }

    #[test]
    fn a_server_found_twice_is_one_profile_and_user_profiles_are_never_relabelled() {
        let db = Database::open_temporary("found").unwrap();
        let mine = db.insert_config("Mine", "vless", "1.2.3.4", 443, "{}", None).unwrap();
        let a = db.upsert_found(&found("aaaa", "vless://a", "found", 120.0)).unwrap();
        let again = db.upsert_found(&found("aaaa", "vless://a", "crowd", 90.0)).unwrap();
        assert_eq!(a, again);
        assert_ne!(a, mine);
        let configs = db.get_configs().unwrap();
        let row = configs.iter().find(|c| c.id == a).unwrap();
        assert_eq!(row.origin, "found", "the first origin sticks");
        assert_eq!(row.ping_ms, Some(90.0));
        assert!(row.is_found());
        assert!(!configs.iter().find(|c| c.id == mine).unwrap().is_found());
        assert_eq!(db.found_link_key(a).as_deref(), Some("aaaa"));
        assert_eq!(db.found_link_key(mine), None);

        // A failure clears the delay; history lists only servers that worked.
        db.upsert_found(&found("bbbb", "vless://b", "crowd", 300.0)).unwrap();
        db.record_found_failure("aaaa").unwrap();
        let history = db.found_history(10).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(db.found_ranked().unwrap().first().copied(), db.get_configs().unwrap().iter().find(|c| c.remark == "Found" && c.ping_ms == Some(300.0)).map(|c| c.id));
    }

    #[test]
    fn pruning_keeps_the_active_and_the_most_useful_found_servers_and_every_user_profile() {
        let db = Database::open_temporary("prune").unwrap();
        db.insert_config("Mine", "vless", "1.2.3.4", 443, "{}", None).unwrap();
        let mut ids = Vec::new();
        for i in 0..6 {
            let key = format!("k{i}");
            let link = format!("vless://{i}");
            ids.push(db.upsert_found(&found(&key, &link, "found", 100.0)).unwrap());
        }
        // k5 is the most useful; k0 is the one in use.
        for _ in 0..3 {
            db.upsert_found(&found("k5", "vless://5", "found", 100.0)).unwrap();
        }
        db.set_active_config(ids[0]).unwrap();
        for i in 0..5 {
            db.record_found_failure(&format!("k{i}")).unwrap();
        }
        let removed = db.prune_found(2).unwrap();
        assert_eq!(removed, 4);
        let left: Vec<_> = db.get_configs().unwrap();
        assert!(left.iter().any(|c| c.remark == "Mine"));
        assert!(left.iter().any(|c| c.id == ids[0]), "the active profile stays");
        assert!(left.iter().any(|c| c.id == ids[5]), "the most useful stays");
        assert_eq!(left.len(), 3);
    }

    #[test]
    fn named_values_round_trip_beside_the_settings() {
        let db = Database::open_temporary("values").unwrap();
        assert_eq!(db.get_value("crowd_net"), None);
        db.set_value("crowd_net", "asn:58224").unwrap();
        db.set_value("crowd_net", "asn:12880").unwrap();
        assert_eq!(db.get_value("crowd_net").as_deref(), Some("asn:12880"));
        // Unknown keys do not disturb the settings.
        assert_eq!(db.load_settings(), AppSettings::default());
    }

    #[test]
    fn legacy_boolean_spellings_are_still_read() {
        assert!(truthy("1"));
        assert!(truthy("true"));
        assert!(!truthy("0"));
        assert!(!truthy("false"));
        assert!(!truthy(""));
    }
}
