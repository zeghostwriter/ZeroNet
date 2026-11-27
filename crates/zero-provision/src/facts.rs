//! What the installer learns about a server before it changes anything.
//!
//! One read-only shell script prints `key=value` lines; [`Facts::parse`]
//! turns them into a struct and [`Facts::problems`] says whether the server
//! can take what was asked for. Nothing is installed, written or started by
//! the probe, so it is safe to run on a server that already hosts other
//! things.

use std::collections::HashMap;

/// The read-only probe, run on the server.
pub const SCRIPT: &str = r#"
echo "arch=$(uname -m)"
if [ -r /etc/os-release ]; then . /etc/os-release; fi
echo "os_id=${ID:-unknown}"
echo "os_like=${ID_LIKE:-}"
echo "os_version=${VERSION_ID:-}"
echo "os_name=${PRETTY_NAME:-unknown}"
echo "uid=$(id -u)"
if [ -d /run/systemd/system ]; then echo "systemd=1"; else echo "systemd=0"; fi
echo "mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)"
echo "disk_mb=$(df -Pm /opt 2>/dev/null | awk 'NR==2 {print $4}')"
for tool in curl wget sha256sum useradd ufw firewall-cmd ss apt-get dnf yum; do
  if command -v "$tool" >/dev/null 2>&1; then echo "has_$tool=1"; else echo "has_$tool=0"; fi
done
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then echo "ufw_active=1"; else echo "ufw_active=0"; fi
if command -v systemctl >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then echo "firewalld_active=1"; else echo "firewalld_active=0"; fi
if command -v ss >/dev/null 2>&1; then
  echo "tcp_listen=$(ss -H -ltnp 2>/dev/null | awk '{n=split($4,a,":"); p=a[n]; h=substr($4,1,length($4)-length(p)-1); proc="-"; if (match($0,/users:\(\("[^"]+"/)) proc=substr($0,RSTART+9,RLENGTH-10); print p"/"proc"/"h}' | sort -u | tr '\n' ' ')"
  echo "udp_listen=$(ss -H -lunp 2>/dev/null | awk '{n=split($4,a,":"); p=a[n]; h=substr($4,1,length($4)-length(p)-1); proc="-"; if (match($0,/users:\(\("[^"]+"/)) proc=substr($0,RSTART+9,RLENGTH-10); print p"/"proc"/"h}' | sort -u | tr '\n' ' ')"
  echo "primary_ip4=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1)"
fi
if ip -6 addr show scope global 2>/dev/null | grep -q inet6 && ip -6 route show default 2>/dev/null | grep -q .; then echo "ipv6=1"; else echo "ipv6=0"; fi
if [ -x /opt/zray/zray ]; then echo "zray_installed=1"; echo "zray_version=$(/opt/zray/zray version 2>/dev/null | head -1)"; else echo "zray_installed=0"; fi
if [ -x /opt/masterdns/masterdns-server ]; then echo "masterdns_installed=1"; else echo "masterdns_installed=0"; fi
if [ -f /etc/zray/server.json ]; then echo "zray_config=1"; else echo "zray_config=0"; fi
"#;

/// A listening socket: its port and the program holding it (`-` when the probe
/// could not tell).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub port: u16,
    pub process: String,
    /// The address it is bound to: `0.0.0.0`, `*`, `[::]`, `127.0.0.53`, ...
    pub address: String,
}

impl Listener {
    /// Whether this socket is bound to a loopback address only.
    pub fn loopback_only(&self) -> bool {
        self.address.starts_with("127.") || self.address.contains("::1")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub arch: String,
    pub os_id: String,
    pub os_like: String,
    pub os_version: String,
    pub os_name: String,
    pub root: bool,
    pub systemd: bool,
    pub mem_mb: u64,
    pub disk_mb: u64,
    pub tools: HashMap<String, bool>,
    pub ufw_active: bool,
    pub firewalld_active: bool,
    pub tcp: Vec<Listener>,
    pub udp: Vec<Listener>,
    /// The server's main IPv4 address on its default route (what a service
    /// should bind to when a wildcard bind would collide with a loopback one).
    pub primary_ip4: String,
    /// A global IPv6 address and a default route. Without both, names that have
    /// an IPv6 address would be dialled on it first and time out.
    pub ipv6: bool,
    pub zray_installed: bool,
    pub zray_version: String,
    pub zray_config: bool,
    pub masterdns_installed: bool,
}

/// Something that stops an install, or that the person should know about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// A CPU the released server programs are not built for.
    UnsupportedCpu(String),
    /// No systemd: the installer registers services with it.
    NoSystemd,
    /// Neither root nor a passwordless `sudo`.
    NeedRoot,
    /// No way to download, and no package manager to get one.
    NoDownloader,
    /// Not enough room for the program and its state.
    LowDisk(u64),
    /// Another program already uses a port the install needs and cannot share.
    PortInUse { port: u16, process: String },
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Problem::UnsupportedCpu(arch) => write!(
                f,
                "This server's processor ({arch}) is not supported. Zray's server runs on x86_64 \
                 and ARM64 (aarch64) Linux."
            ),
            Problem::NoSystemd => f.write_str(
                "This server does not use systemd, which the installer needs to keep the server \
                 running. Use a standard Debian, Ubuntu, Fedora or similar image.",
            ),
            Problem::NeedRoot => f.write_str(
                "The login is not root and has no password-free sudo. Log in as root, or give the \
                 user passwordless sudo.",
            ),
            Problem::NoDownloader => f.write_str(
                "The server has neither curl nor wget, and no package manager the installer \
                 knows. Install curl on it, then try again.",
            ),
            Problem::LowDisk(mb) => write!(
                f,
                "Only {mb} MB of disk is free; the installer needs at least 200 MB."
            ),
            Problem::PortInUse { port, process } => write!(
                f,
                "Port {port} is already used by \"{process}\" on this server. Stop that program \
                 (or pick another server), then try again."
            ),
        }
    }
}

impl Facts {
    /// Read the probe's output. Unknown lines are ignored, so a newer probe
    /// does not break an older reader.
    pub fn parse(text: &str) -> Facts {
        let mut map: HashMap<&str, &str> = HashMap::new();
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=') {
                map.insert(key.trim(), value.trim());
            }
        }
        let get = |key: &str| map.get(key).copied().unwrap_or("");
        let flag = |key: &str| get(key) == "1";
        let number = |key: &str| get(key).parse::<u64>().unwrap_or(0);
        let tools = [
            "curl",
            "wget",
            "sha256sum",
            "useradd",
            "ufw",
            "firewall-cmd",
            "ss",
            "apt-get",
            "dnf",
            "yum",
        ]
        .iter()
        .map(|t| (t.to_string(), flag(&format!("has_{t}"))))
        .collect();
        Facts {
            arch: get("arch").to_string(),
            os_id: get("os_id").to_string(),
            os_like: get("os_like").to_string(),
            os_version: get("os_version").to_string(),
            os_name: get("os_name").to_string(),
            root: get("uid") == "0",
            systemd: flag("systemd"),
            mem_mb: number("mem_mb"),
            disk_mb: number("disk_mb"),
            tools,
            ufw_active: flag("ufw_active"),
            firewalld_active: flag("firewalld_active"),
            tcp: listeners(get("tcp_listen")),
            udp: listeners(get("udp_listen")),
            primary_ip4: get("primary_ip4").to_string(),
            ipv6: flag("ipv6"),
            zray_installed: flag("zray_installed"),
            zray_version: get("zray_version").to_string(),
            zray_config: flag("zray_config"),
            masterdns_installed: flag("masterdns_installed"),
        }
    }

    pub fn has(&self, tool: &str) -> bool {
        self.tools.get(tool).copied().unwrap_or(false)
    }

    /// The release asset name suffix for this CPU, or `None` when unsupported.
    pub fn asset_arch(&self) -> Option<&'static str> {
        match self.arch.as_str() {
            "x86_64" | "amd64" => Some("x64"),
            "aarch64" | "arm64" => Some("ARM64"),
            _ => None,
        }
    }

    /// Whether a package manager the installer can drive is present.
    pub fn can_install_packages(&self) -> bool {
        self.has("apt-get") || self.has("dnf") || self.has("yum")
    }

    /// Whether another program (not ours) holds `port` on an address a service
    /// binding the whole machine would collide with, on TCP or UDP. A socket
    /// bound to loopback only (`systemd-resolved` on 127.0.0.53:53) does not
    /// count when `loopback_ok` is set, which is the case for a service that
    /// binds a specific public address instead.
    pub fn port_taken_by_other(&self, port: u16, udp: bool, loopback_ok: bool) -> Option<&str> {
        let list = if udp { &self.udp } else { &self.tcp };
        list.iter()
            .find(|l| {
                l.port == port
                    && !matches!(l.process.as_str(), "zray" | "masterdns-server")
                    && !(loopback_ok && l.loopback_only())
            })
            .map(|l| l.process.as_str())
    }

    /// What stops an install on this server.
    pub fn problems(&self) -> Vec<Problem> {
        let mut problems = Vec::new();
        if self.asset_arch().is_none() {
            problems.push(Problem::UnsupportedCpu(self.arch.clone()));
        }
        if !self.systemd {
            problems.push(Problem::NoSystemd);
        }
        if !self.has("curl") && !self.has("wget") && !self.can_install_packages() {
            problems.push(Problem::NoDownloader);
        }
        if self.disk_mb != 0 && self.disk_mb < 200 {
            problems.push(Problem::LowDisk(self.disk_mb));
        }
        problems
    }
}

fn listeners(text: &str) -> Vec<Listener> {
    text.split_whitespace()
        .filter_map(|entry| {
            let mut parts = entry.splitn(3, '/');
            Some(Listener {
                port: parts.next()?.parse().ok()?,
                process: parts.next()?.to_string(),
                address: parts.next().unwrap_or("*").to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "arch=x86_64\nos_id=debian\nos_like=\nos_version=12\nos_name=Debian GNU/Linux 12 (bookworm)\nuid=0\nsystemd=1\nmem_mb=1987\ndisk_mb=20480\nhas_curl=1\nhas_wget=0\nhas_sha256sum=1\nhas_useradd=1\nhas_ufw=1\nhas_firewall-cmd=0\nhas_ss=1\nhas_apt-get=1\nhas_dnf=0\nhas_yum=0\nufw_active=1\nfirewalld_active=0\ntcp_listen=22/sshd/0.0.0.0 443/nginx/0.0.0.0 8443/zray/0.0.0.0 \nudp_listen=53/systemd-resolve/127.0.0.53 443/zray/0.0.0.0 \nprimary_ip4=203.0.113.7\nzray_installed=1\nzray_version=zray 0.3.0\nzray_config=1\nmasterdns_installed=0\n";

    #[test]
    fn a_typical_debian_server_parses_and_passes() {
        let facts = Facts::parse(SAMPLE);
        assert_eq!(facts.os_name, "Debian GNU/Linux 12 (bookworm)");
        assert!(facts.root && facts.systemd && facts.ufw_active);
        assert_eq!(facts.asset_arch(), Some("x64"));
        assert!(facts.problems().is_empty());
        assert_eq!(facts.mem_mb, 1987);
    }

    #[test]
    fn our_own_server_does_not_count_as_a_port_conflict() {
        let facts = Facts::parse(SAMPLE);
        assert_eq!(facts.port_taken_by_other(443, false, false), Some("nginx"));
        assert_eq!(
            facts.port_taken_by_other(8443, false, false),
            None,
            "zray's own port"
        );
        // The resolver's stub is on loopback: a wildcard bind collides with
        // it, a bind to the public address does not.
        assert_eq!(
            facts.port_taken_by_other(53, true, false),
            Some("systemd-resolve")
        );
        assert_eq!(facts.port_taken_by_other(53, true, true), None);
        assert_eq!(facts.port_taken_by_other(443, true, false), None);
        assert_eq!(facts.primary_ip4, "203.0.113.7");
    }

    #[test]
    fn unsupported_servers_say_why() {
        let mut facts = Facts::parse(SAMPLE);
        facts.arch = "armv7l".into();
        facts.systemd = false;
        facts.disk_mb = 50;
        let problems = facts.problems();
        assert_eq!(problems.len(), 3);
        assert!(problems
            .iter()
            .any(|p| matches!(p, Problem::UnsupportedCpu(a) if a == "armv7l")));
        assert!(problems.contains(&Problem::NoSystemd));
        assert!(problems.contains(&Problem::LowDisk(50)));
    }

    #[test]
    fn garbage_input_is_an_empty_unsupported_server_not_a_panic() {
        let facts = Facts::parse("not key value\n\n===\n");
        assert!(!facts.problems().is_empty());
    }
}
