//! Where everything lives on the server, and the files the installer writes.
//!
//! One place for the paths, so the installer, the status check and the
//! uninstaller cannot disagree about what is theirs. Everything the installer
//! creates is under these names; nothing else on the server is touched.

use serde_json::{json, Value};

/// GitHub project the server program is downloaded from.
pub const REPO: &str = "zeghostwriter/ZeroNet";

pub const ZRAY_DIR: &str = "/opt/zray";
pub const ZRAY_BIN: &str = "/opt/zray/zray";
pub const ZRAY_ETC: &str = "/etc/zray";
pub const ZRAY_CONFIG: &str = "/etc/zray/server.json";
pub const ZRAY_TOKEN: &str = "/etc/zray/management.token";
pub const ZRAY_UNIT: &str = "/etc/systemd/system/zray.service";
pub const ZRAY_SERVICE: &str = "zray";
/// The unprivileged account the server runs as.
pub const ZRAY_USER: &str = "zray";
/// Scratch space for downloads, removed when the install ends.
pub const WORK_DIR: &str = "/tmp/zray-setup";

pub const MASTERDNS_DIR: &str = "/opt/masterdns";
pub const MASTERDNS_BIN: &str = "/opt/masterdns/masterdns-server";
pub const MASTERDNS_ETC: &str = "/etc/masterdns";
pub const MASTERDNS_CONFIG: &str = "/etc/masterdns/server_config.toml";
pub const MASTERDNS_KEY: &str = "/etc/masterdns/encrypt_key.txt";
pub const MASTERDNS_UNIT: &str = "/etc/systemd/system/masterdns.service";
pub const MASTERDNS_SERVICE: &str = "masterdns";
pub const MASTERDNS_USER: &str = "masterdns";

/// The MasterDnsVPN server release the installer deploys: a pinned tag and the
/// SHA-256 of each archive, so what is installed is exactly what was reviewed.
/// (Upstream's release hashes, re-checked by downloading the archives.) Moving
/// to a newer release is a deliberate change to these three lines.
pub const MASTERDNS_REPO: &str = "masterking32/MasterDnsVPN";
pub const MASTERDNS_TAG: &str = "v2026.06.13.234407-7de2476";
pub const MASTERDNS_SHA256_AMD64: &str =
    "597bdc510b896a3b4ac89865ee7cefa73191025c64093f5e0f85c76a70430de9";
pub const MASTERDNS_SHA256_ARM64: &str =
    "4f3d0e8afac0381e5a47e3064e07d0bac27c56b5f1a4fd8df8013f157168cbbf";

/// The archive name and hash for a CPU (`x64` or `ARM64`, as in `Facts`).
pub fn masterdns_asset(arch: &str) -> Option<(&'static str, &'static str)> {
    match arch {
        "x64" => Some((
            "MasterDnsVPN_Server_Linux_AMD64.tar.gz",
            MASTERDNS_SHA256_AMD64,
        )),
        "ARM64" => Some((
            "MasterDnsVPN_Server_Linux_ARM64.tar.gz",
            MASTERDNS_SHA256_ARM64,
        )),
        _ => None,
    }
}

/// The systemd unit for the MasterDNS server. It binds port 53 as its own user
/// with only that one privilege, like the Zray unit.
pub fn masterdns_unit() -> String {
    format!(
        "[Unit]\n\
         Description=MasterDnsVPN server\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         User={MASTERDNS_USER}\n\
         Group={MASTERDNS_USER}\n\
         ExecStart={MASTERDNS_BIN} -config {MASTERDNS_CONFIG} -nowait\n\
         Restart=always\n\
         RestartSec=2\n\
         LimitNOFILE=1048576\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
         CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\
         NoNewPrivileges=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         PrivateDevices=true\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectControlGroups=true\n\
         RestrictSUIDSGID=true\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// What the MasterDNS server needs to know.
pub struct MasterDnsServer<'a> {
    /// The tunnel domain, delegated to this server.
    pub domain: &'a str,
    /// The address to bind: the machine's own address, or `0.0.0.0`.
    pub bind: &'a str,
    /// AES-256-GCM, the one authenticated method (see `zero-masterdns`).
    pub method: u8,
}

/// The server's `server_config.toml`. Only what differs from the program's own
/// defaults is written, so a later release's new defaults apply untouched. It
/// answers as a SOCKS5 proxy; the program itself refuses private targets.
pub fn masterdns_config(server: &MasterDnsServer) -> String {
    format!(
        "DOMAIN = [\"{}\"]\n\
         PROTOCOL_TYPE = \"SOCKS5\"\n\
         UDP_HOST = \"{}\"\n\
         UDP_PORT = 53\n\
         DATA_ENCRYPTION_METHOD = {}\n\
         ENCRYPTION_KEY_FILE = \"{MASTERDNS_KEY}\"\n\
         LOG_LEVEL = \"INFO\"\n",
        server.domain, server.bind, server.method
    )
}

/// The key length the server insists on for a method (it silently replaces any
/// other key with one of its own). AES-256-GCM, method 5, takes 32 characters.
pub const MASTERDNS_KEY_LEN: usize = 32;

/// The comment on the app's SSH key for server `id`. Unique per server and per
/// install, so removing one server's access never touches another's.
pub fn key_comment(id: &str) -> String {
    format!("zray-{id}")
}

/// The systemd unit for the Zray server.
///
/// It runs as its own user with only the right to bind low ports, a read-only
/// view of the system and no way to gain privileges, so a flaw in the server
/// does not hand over the machine. `management_port` is the loopback port of
/// the management API the usage figures come from.
pub fn zray_unit(management_port: u16) -> String {
    format!(
        "[Unit]\n\
         Description=Zray server\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         User={ZRAY_USER}\n\
         Group={ZRAY_USER}\n\
         ExecStart={ZRAY_BIN} run {ZRAY_CONFIG} --management 127.0.0.1:{management_port} \
         --management-token-file {ZRAY_TOKEN}\n\
         Restart=always\n\
         RestartSec=2\n\
         LimitNOFILE=1048576\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
         CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\
         NoNewPrivileges=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         PrivateDevices=true\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectControlGroups=true\n\
         RestrictSUIDSGID=true\n\
         StateDirectory=zray\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Inbound tags the usage figures are reported under.
pub const VISION_TAG: &str = "reality-in";
pub const XHTTP_TAG: &str = "xhttp-in";
pub const ZEROV1_TAG: &str = "zerov1-in";

/// The ZeroV1 inbound: its port, the path it answers on and its secret key.
/// Its users are the REALITY users, by the sixteen bytes of their UUIDs.
pub struct Zerov1Inbound<'a> {
    pub port: u16,
    pub path: &'a str,
    pub secret_key: &'a str,
}

/// What the REALITY inbounds need. One key pair, short id and user list are
/// shared by both inbounds, so a person can hold either config.
pub struct RealityInbound<'a> {
    /// The real site the server relays to anyone who is not a client.
    pub sni: &'a str,
    pub private_key: &'a str,
    pub short_id: &'a str,
    /// `(name, uuid)` pairs.
    pub users: &'a [(String, String)],
    /// Port of the VLESS + Vision inbound on TCP, when it is installed.
    pub vision_port: Option<u16>,
    /// Port and request path of the XHTTP inbound, when it is installed.
    pub xhttp: Option<(u16, &'a str)>,
    /// The ZeroV1 inbound, when it is installed.
    pub zerov1: Option<Zerov1Inbound<'a>>,
}

/// The server's whole configuration. Clients may reach any public address and
/// nothing private: the rule at the top sends traffic aimed at the server's own
/// network (loopback, LAN, link-local, cloud metadata) to a black hole, so a
/// client cannot use the server to reach services that trust it.
///
/// `ipv6` says whether the machine can actually reach the IPv6 internet; when
/// it cannot, names are resolved to IPv4 only, because a destination whose
/// IPv6 address is tried first on a machine without IPv6 stalls until the
/// dial times out.
pub fn zray_config(reality: &RealityInbound, ipv6: bool) -> Value {
    let clients = |flow: &str| -> Vec<Value> {
        reality
            .users
            .iter()
            .map(|(name, id)| json!({"id": id, "flow": flow, "email": name}))
            .collect()
    };
    let security = json!({
        "security": "reality",
        "realitySettings": {
            "show": false,
            "dest": format!("{}:443", reality.sni),
            "xver": 0,
            "serverNames": [reality.sni],
            "privateKey": reality.private_key,
            "shortIds": [reality.short_id],
        },
    });
    // Both inbounds share the REALITY settings; only the carrier differs. XHTTP
    // carries its own framing, so it takes no Vision flow.
    let inbound = |tag: &str, port: u16, flow: &str, network: Value| {
        let mut stream = security.clone();
        for (key, value) in network.as_object().expect("an object") {
            stream[key] = value.clone();
        }
        json!({
            "tag": tag,
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": clients(flow), "decryption": "none"},
            "streamSettings": stream,
        })
    };
    let mut inbounds = Vec::new();
    if let Some(port) = reality.vision_port {
        inbounds.push(inbound(
            VISION_TAG,
            port,
            "xtls-rprx-vision",
            json!({"network": "tcp"}),
        ));
    }
    if let Some((port, path)) = reality.xhttp {
        inbounds.push(inbound(
            XHTTP_TAG,
            port,
            "",
            json!({"network": "xhttp", "xhttpSettings": {"path": path, "mode": "auto"}}),
        ));
    }
    if let Some(zerov1) = &reality.zerov1 {
        let users: Vec<Value> = reality
            .users
            .iter()
            .filter_map(|(name, id)| {
                crate::links::zerov1_user_id(id).map(|id| json!({"id": id, "name": name}))
            })
            .collect();
        let mut stream = security.clone();
        stream["network"] = json!("tcp");
        inbounds.push(json!({
            "tag": ZEROV1_TAG,
            "listen": "0.0.0.0",
            "port": zerov1.port,
            "protocol": "zerov1",
            "settings": {"path": zerov1.path, "secretKey": zerov1.secret_key, "users": users},
            "streamSettings": stream,
        }));
    }
    json!({
        "log": {"loglevel": "warning"},
        // The machine's own resolver: the hosting provider's DNS is the one
        // that is always reachable from its own network, which a built-in
        // default (a public DNS-over-HTTPS service) is not everywhere.
        "dns": {
            "servers": ["localhost"],
            "leakPolicy": "fallback",
            "queryStrategy": if ipv6 { "UseIP" } else { "UseIPv4" },
        },
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"rules": [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
        ]},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inbound(users: &[(String, String)]) -> RealityInbound<'_> {
        RealityInbound {
            sni: "www.microsoft.com",
            private_key: "uJLQY8ZQJjlg2Bld0RFcuTJsGZSnBeZyGP2yR4xCxFM",
            short_id: "0123456789abcdef",
            users,
            vision_port: Some(443),
            xhttp: None,
            zerov1: None,
        }
    }

    /// The server config must be one the engine itself accepts, or the service
    /// would fail to start on a stranger's machine.
    #[test]
    fn the_server_config_compiles_in_the_engine() {
        let users = vec![("Main".to_string(), crate::keys::new_uuid())];
        let config = zray_config(&inbound(&users), false);
        let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("the engine accepts the generated server config");
        assert_eq!(generation.config.inbounds.len(), 1);
        assert_eq!(&*generation.config.inbounds[0].tag, VISION_TAG);
    }

    /// XHTTP rides the same REALITY keys on its own port, takes no Vision
    /// flow, and the engine accepts the result.
    #[test]
    fn the_xhttp_inbound_shares_the_reality_keys_and_compiles() {
        let users = vec![("Main".to_string(), crate::keys::new_uuid())];
        let mut both = inbound(&users);
        both.xhttp = Some((8443, "/a1b2c3d4"));
        let config = zray_config(&both, false);
        let inbounds = config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        let (vision, xhttp) = (&inbounds[0], &inbounds[1]);
        assert_eq!(vision["tag"], VISION_TAG);
        assert_eq!(vision["settings"]["clients"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(xhttp["tag"], XHTTP_TAG);
        assert_eq!(xhttp["port"], 8443);
        assert_eq!(xhttp["settings"]["clients"][0]["flow"], "");
        assert_eq!(xhttp["streamSettings"]["network"], "xhttp");
        assert_eq!(
            xhttp["streamSettings"]["xhttpSettings"]["path"],
            "/a1b2c3d4"
        );
        assert_eq!(
            xhttp["streamSettings"]["realitySettings"],
            vision["streamSettings"]["realitySettings"]
        );
        let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("the engine accepts both inbounds");
        assert_eq!(generation.config.inbounds.len(), 2);

        let mut only = inbound(&users);
        only.vision_port = None;
        only.xhttp = Some((443, "/p"));
        let config = zray_config(&only, false);
        assert_eq!(config["inbounds"].as_array().unwrap().len(), 1);
        zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("XHTTP alone is accepted");
    }

    /// VLESS, XHTTP and ZeroV1 on one server: three inbounds, one REALITY
    /// setup and one user list, each user's ZeroV1 id being their UUID's bytes.
    #[test]
    fn zerov1_sits_beside_vless_and_xhttp_on_the_same_keys_and_users() {
        let users = vec![("Main".to_string(), crate::keys::new_uuid())];
        let (secret, _) = zero_protocol::tide::generate_keypair();
        let secret = zero_protocol::tide::encode_key(&secret);
        let mut all = inbound(&users);
        all.xhttp = Some((8443, "/a1b2c3d4"));
        all.zerov1 = Some(Zerov1Inbound {
            port: 2083,
            path: "/static/9f8e7d",
            secret_key: &secret,
        });
        let config = zray_config(&all, false);
        let inbounds = config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 3);
        let zerov1 = &inbounds[2];
        assert_eq!(zerov1["tag"], ZEROV1_TAG);
        assert_eq!(zerov1["protocol"], "zerov1");
        assert_eq!(zerov1["port"], 2083);
        assert_eq!(
            zerov1["streamSettings"]["realitySettings"],
            inbounds[0]["streamSettings"]["realitySettings"],
            "one REALITY setup for all of them"
        );
        let id = crate::links::zerov1_user_id(&users[0].1).unwrap();
        assert_eq!(zerov1["settings"]["users"][0]["id"], id);
        assert_eq!(zerov1["settings"]["users"][0]["name"], "Main");
        let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("the engine accepts all three inbounds");
        assert_eq!(generation.config.inbounds.len(), 3);

        let mut only = inbound(&users);
        only.vision_port = None;
        only.zerov1 = Some(Zerov1Inbound {
            port: 443,
            path: "/static/9f8e7d",
            secret_key: &secret,
        });
        let config = zray_config(&only, false);
        assert_eq!(config["inbounds"].as_array().unwrap().len(), 1);
        zero_config::compile_config(&config, zero_core::GenerationId(1))
            .expect("ZeroV1 alone is accepted");
    }

    #[test]
    fn a_machine_without_ipv6_resolves_to_ipv4_only() {
        let users = vec![("Main".to_string(), crate::keys::new_uuid())];
        assert_eq!(
            zray_config(&inbound(&users), false)["dns"]["queryStrategy"],
            "UseIPv4"
        );
        assert_eq!(
            zray_config(&inbound(&users), true)["dns"]["queryStrategy"],
            "UseIP"
        );
    }

    #[test]
    fn private_networks_are_blocked_before_anything_else() {
        let users = vec![("Main".to_string(), crate::keys::new_uuid())];
        let config = zray_config(&inbound(&users), false);
        let rules = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["ip"][0], "geoip:private");
        assert_eq!(rules[0]["outboundTag"], "block");
    }

    #[test]
    fn the_masterdns_config_is_what_the_server_expects() {
        let text = masterdns_config(&MasterDnsServer {
            domain: "t.example.com",
            bind: "203.0.113.7",
            method: 5,
        });
        assert!(text.contains("DOMAIN = [\"t.example.com\"]"));
        assert!(text.contains("UDP_HOST = \"203.0.113.7\""));
        assert!(text.contains("UDP_PORT = 53"));
        assert!(text.contains("DATA_ENCRYPTION_METHOD = 5"));
        assert!(text.contains("ENCRYPTION_KEY_FILE = \"/etc/masterdns/encrypt_key.txt\""));
    }

    #[test]
    fn the_pinned_masterdns_archives_are_known_for_both_cpus() {
        assert_eq!(masterdns_asset("x64").unwrap().1.len(), 64);
        assert_eq!(masterdns_asset("ARM64").unwrap().1.len(), 64);
        assert!(masterdns_asset("riscv").is_none());
        assert!(masterdns_unit().contains("-config /etc/masterdns/server_config.toml"));
    }

    #[test]
    fn the_unit_binds_low_ports_and_nothing_more() {
        let unit = zray_unit(20123);
        assert!(unit.contains("--management 127.0.0.1:20123"));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
        assert!(!unit.contains("User=root"));
    }
}
