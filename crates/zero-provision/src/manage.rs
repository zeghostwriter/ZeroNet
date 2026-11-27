//! Coming back to a server the app set up: read its usage, remove it.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::layout;
use crate::record::{ServerRecord, Service};
use crate::scripts;
use crate::ssh::{self, Auth, Connection, Login};

/// Log in with the app's own key. Fails when the record kept no key (the
/// person declined it), in which case the caller asks for the password again.
pub async fn connect(record: &ServerRecord) -> Result<Connection, ssh::Error> {
    let key = record.ssh_key.clone().ok_or(ssh::Error::AuthFailed)?;
    let login = Login {
        host: record.host.clone(),
        port: record.ssh_port,
        user: record.ssh_user.clone(),
        auth: Auth::Key(key),
    };
    ssh::connect(&login, &record.host_key.fingerprint).await
}

/// One inbound's live figures, exactly as the server reports them: counts and
/// byte totals, nothing that names a person (see `zero_runtime::usage`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundUsage {
    pub tag: String,
    pub sessions: u64,
    pub devices_now: u64,
    pub devices_recent: u64,
    pub uplink: u64,
    pub downlink: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub window_secs: u64,
    pub inbounds: Vec<InboundUsage>,
}

impl Usage {
    pub fn devices_now(&self) -> u64 {
        self.inbounds.iter().map(|i| i.devices_now).sum()
    }
}

/// Why the usage could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    Ssh(ssh::Error),
    /// The server program is up but too old to report usage.
    Unsupported,
    /// The server is not running.
    Down,
}

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsageError::Ssh(e) => e.fmt(f),
            UsageError::Unsupported => f.write_str(
                "This server's program is too old to report who is connected. Update it from the \
                 server's menu.",
            ),
            UsageError::Down => f.write_str(
                "The server program is not running. Open the server's menu and restart it.",
            ),
        }
    }
}

/// Ask the server how many people are connected.
///
/// The Zray server reports it itself (see `zero_runtime::usage`). The MasterDNS
/// server keeps no such figure, so it is worked out from the session lines in
/// its log: sessions created, less those closed or expired. That can lag by up
/// to five minutes (a client that vanishes is only noticed when its session
/// times out) and reports no byte counts.
pub async fn usage(conn: &Connection, record: &ServerRecord) -> Result<Usage, UsageError> {
    let mut usage = Usage {
        window_secs: crate::manage::WINDOW,
        inbounds: Vec::new(),
    };
    if record.services.iter().any(|s| {
        matches!(
            s,
            Service::Reality(_) | Service::Xhttp(_) | Service::Zerov1(_)
        )
    }) {
        let port = record.management_port.to_string();
        let env = [
            ("TOKEN_FILE", layout::ZRAY_TOKEN),
            ("MANAGEMENT_PORT", port.as_str()),
        ];
        let out = conn
            .script(&env, scripts::USAGE, Duration::from_secs(20))
            .await
            .map_err(UsageError::Ssh)?;
        if !out.ok() {
            // curl: 22 is an HTTP error (a 404 is an older program), the rest
            // mean nothing answered.
            return Err(match out.status {
                22 => UsageError::Unsupported,
                _ => UsageError::Down,
            });
        }
        let zray: Usage = serde_json::from_str(&out.stdout).map_err(|_| UsageError::Unsupported)?;
        usage.window_secs = zray.window_secs;
        usage.inbounds = zray.inbounds;
    }
    if record
        .services
        .iter()
        .any(|s| matches!(s, Service::MasterDns(_)))
    {
        let env = [("SERVICE", layout::MASTERDNS_SERVICE)];
        let out = conn
            .script(&env, scripts::MASTERDNS_LOG, Duration::from_secs(20))
            .await
            .map_err(UsageError::Ssh)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        usage.inbounds.push(masterdns_usage(&out.stdout, now));
    }
    Ok(usage)
}

/// Seconds of recent activity the usage figures speak about.
pub const WINDOW: u64 = 300;

/// The MasterDNS figure from its journal lines (`journalctl -o short-unix`).
fn masterdns_usage(log: &str, now: u64) -> InboundUsage {
    let (mut created, mut closed, mut expired, mut recent) = (0u64, 0u64, 0u64, 0u64);
    for line in log.lines() {
        let at: u64 = line
            .split_whitespace()
            .next()
            .and_then(|t| t.split('.').next())
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);
        if line.contains("Session Created") {
            created += 1;
            if at + WINDOW >= now {
                recent += 1;
            }
        } else if line.contains("Session Closed") {
            closed += 1;
        } else if let Some(rest) = line.split("Expired Sessions Cleaned, Count:").nth(1) {
            expired += rest
                .trim()
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0);
        }
    }
    let now_open = created.saturating_sub(closed + expired);
    InboundUsage {
        tag: "masterdns".into(),
        sessions: now_open,
        devices_now: now_open,
        devices_recent: now_open.max(recent),
        uplink: 0,
        downlink: 0,
    }
}

/// What [`remove`] reports as it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removed {
    Services,
    Files,
    Firewall,
    Access,
}

fn ports_of(record: &ServerRecord) -> (Vec<u16>, Vec<u16>) {
    let (mut tcp, mut udp) = (Vec::new(), Vec::new());
    for service in &record.services {
        match service {
            Service::Reality(r) => tcp.push(r.port),
            Service::Xhttp(x) => tcp.push(x.port),
            Service::Zerov1(z) => tcp.push(z.port),
            Service::MasterDns(_) => udp.push(53),
        }
    }
    (tcp, udp)
}

const REMOVE: &str = r#"
systemctl disable --now "$ZRAY_SERVICE" >/dev/null 2>&1 || true
systemctl disable --now "$MASTERDNS_SERVICE" >/dev/null 2>&1 || true
echo "step=services"
rm -f "$ZRAY_UNIT" "$MASTERDNS_UNIT"
systemctl daemon-reload >/dev/null 2>&1 || true
rm -rf "$ZRAY_DIR" "$ZRAY_ETC" /var/lib/zray "$MASTERDNS_DIR" "$MASTERDNS_ETC"
id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" >/dev/null 2>&1 || true
getent group "$SVC_USER" >/dev/null 2>&1 && groupdel "$SVC_USER" >/dev/null 2>&1 || true
echo "step=files"
tcp=$(echo "$TCP" | tr ',' ' '); udp=$(echo "$UDP" | tr ',' ' ')
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then
  for p in $tcp; do [ "$p" = none ] || ufw delete allow "$p/tcp" >/dev/null 2>&1 || true; done
  for p in $udp; do [ "$p" = none ] || ufw delete allow "$p/udp" >/dev/null 2>&1 || true; done
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
  for p in $tcp; do [ "$p" = none ] || firewall-cmd --permanent --remove-port="$p/tcp" >/dev/null 2>&1 || true; done
  for p in $udp; do [ "$p" = none ] || firewall-cmd --permanent --remove-port="$p/udp" >/dev/null 2>&1 || true; done
  firewall-cmd --reload >/dev/null 2>&1 || true
fi
echo "step=firewall"
home=$(getent passwd "$LOGIN_USER" | cut -d: -f6)
if [ -n "$home" ] && [ -f "$home/.ssh/authorized_keys" ]; then
  grep -vF " $KEY_COMMENT" "$home/.ssh/authorized_keys" > "$home/.ssh/authorized_keys.zray" || true
  cat "$home/.ssh/authorized_keys.zray" > "$home/.ssh/authorized_keys"
  rm -f "$home/.ssh/authorized_keys.zray"
fi
echo "step=access"
"#;

/// Take everything the installer put on the server away again: the services,
/// their files and account, the firewall ports it opened, and the app's own SSH
/// key. Nothing else on the server is touched. The connection must have been
/// made with the app's key or the password; the key is removed last.
pub async fn remove(
    conn: &Connection,
    record: &ServerRecord,
    on: &(dyn Fn(Removed) + Sync),
) -> Result<(), ssh::Error> {
    let (tcp, udp) = ports_of(record);
    let list = |ports: &[u16]| {
        if ports.is_empty() {
            "none".to_string()
        } else {
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        }
    };
    let (tcp, udp) = (list(&tcp), list(&udp));
    let comment = layout::key_comment(&record.id);
    let env = [
        ("ZRAY_SERVICE", layout::ZRAY_SERVICE),
        ("MASTERDNS_SERVICE", layout::MASTERDNS_SERVICE),
        ("ZRAY_UNIT", layout::ZRAY_UNIT),
        ("MASTERDNS_UNIT", layout::MASTERDNS_UNIT),
        ("ZRAY_DIR", layout::ZRAY_DIR),
        ("ZRAY_ETC", layout::ZRAY_ETC),
        ("MASTERDNS_DIR", layout::MASTERDNS_DIR),
        ("MASTERDNS_ETC", layout::MASTERDNS_ETC),
        ("SVC_USER", layout::ZRAY_USER),
        ("TCP", tcp.as_str()),
        ("UDP", udp.as_str()),
        ("LOGIN_USER", record.ssh_user.as_str()),
        ("KEY_COMMENT", comment.as_str()),
    ];
    let out = conn.script(&env, REMOVE, Duration::from_secs(120)).await?;
    for line in out.stdout.lines() {
        match line.strip_prefix("step=") {
            Some("services") => on(Removed::Services),
            Some("files") => on(Removed::Files),
            Some("firewall") => on(Removed::Firewall),
            Some("access") => on(Removed::Access),
            _ => {}
        }
    }
    if out.ok() {
        Ok(())
    } else {
        Err(ssh::Error::Protocol(format!(
            "removal stopped part-way: {}",
            out.stderr.trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "\
1760180000.100 host masterdns-server[1]: 2026/10/11 10:00:00 [MasterDnsVPN Server] [INFO] \u{1f9dd} Session Created, ID: 1, Mode: RAW (Bytes)
1760180010.200 host masterdns-server[1]: 2026/10/11 10:00:10 [MasterDnsVPN Server] [INFO] \u{1f9dd} Session Created, ID: 2, Mode: RAW (Bytes)
1760183000.300 host masterdns-server[1]: 2026/10/11 10:50:00 [MasterDnsVPN Server] [INFO] \u{1f9dd} Session Created, ID: 3, Mode: RAW (Bytes)
1760183100.400 host masterdns-server[1]: 2026/10/11 10:51:40 [MasterDnsVPN Server] [INFO] \u{1f6aa} Session Closed By Client, Session: 2
1760183200.500 host masterdns-server[1]: 2026/10/11 10:53:20 [MasterDnsVPN Server] [INFO] \u{1f4e1} Expired Sessions Cleaned, Count: 1
";

    #[test]
    fn open_sessions_are_created_less_closed_less_expired() {
        let usage = masterdns_usage(LOG, 1760183250);
        assert_eq!(usage.sessions, 1, "three created, one closed, one expired");
        assert_eq!(usage.devices_now, 1);
        // Only session 3 was created inside the last five minutes.
        assert_eq!(usage.devices_recent, 1);
        assert_eq!(usage.tag, "masterdns");
    }

    #[test]
    fn an_empty_log_is_no_one() {
        let usage = masterdns_usage("", 1760183250);
        assert_eq!(
            (usage.sessions, usage.devices_now, usage.devices_recent),
            (0, 0, 0)
        );
    }

    #[test]
    fn more_closes_than_creates_never_goes_negative() {
        let log = "1760183100.4 h m[1]: Session Closed By Client, Session: 9\n";
        assert_eq!(masterdns_usage(log, 1760183250).sessions, 0);
    }

    #[test]
    fn the_figure_carries_no_address() {
        let text = serde_json::to_string(&masterdns_usage(LOG, 1760183250)).unwrap();
        assert!(!text.contains("host"));
    }
}
