//! `zero-config` — parse, validate and compile configuration.
//!
//! Two front ends (Xray JSON and share links) produce one compiled
//! `RuntimeConfig`. The runtime never sees a `serde_json::Value`
//! (RESEARCH-01 §4).

pub mod dns;
pub mod model;
pub mod presets;
pub mod routing;
pub mod share_link;
pub mod xhttp;
pub mod xray_json;

pub use model::*;
pub use presets::{AntiSanctionDns, IranPreset, LocalDns, RemoteDns};
pub use share_link::{parse_link, parse_subscription, ShareLink};
pub use xray_json::{compile_config, parse_config, parse_config_array, Diagnostic, ParseOutput};

/// Trojan's wire credential: lowercase hex of SHA-224 over the password.
pub fn trojan_hash(password: &str) -> [u8; 56] {
    use sha2::{Digest, Sha224};
    let digest = Sha224::digest(password.as_bytes());
    let hex = format!("{digest:x}");
    let mut out = [0u8; 56];
    out.copy_from_slice(hex.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_core::Address;

    #[test]
    fn trojan_hash_is_56_hex_chars() {
        let h = trojan_hash("password");
        assert_eq!(h.len(), 56);
        assert!(h.iter().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn trojan_hash_matches_known_sha224() {
        // SHA-224("password")
        let expected = "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01";
        assert_eq!(
            std::str::from_utf8(&trojan_hash("password")).unwrap(),
            expected
        );
    }

    #[test]
    fn xhttp_modes_are_compiled_into_the_transport_model() {
        let config = serde_json::json!({
            "inbounds": [],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1",
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000001"}]
                }]},
                "streamSettings": {
                    "network": "xhttp",
                    "xhttpSettings": {"mode": "packet-up"}
                }
            }]
        });
        let (config, _) = parse_config(&config).unwrap();
        let transport = &config.outbounds[0].stream.transport;
        let Transport::Xhttp(settings) = transport else {
            panic!("expected xhttp")
        };
        assert_eq!(settings.xhttp_mode, XhttpMode::PacketUp);
    }

    #[test]
    fn xhttp_auto_uses_packet_up_for_h2_without_reality() {
        let config = serde_json::json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1",
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000001"}]
                }]},
                "streamSettings": {
                    "network": "xhttp",
                    "xhttpSettings": {"httpVersion": "2"}
                }
            }]
        });
        let (config, _) = parse_config(&config).unwrap();
        let Transport::Xhttp(settings) = &config.outbounds[0].stream.transport else {
            panic!("expected xhttp")
        };
        assert_eq!(settings.xhttp_mode, XhttpMode::PacketUp);
    }

    #[test]
    fn xhttp_download_settings_are_compiled_independently() {
        let config = serde_json::json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "upload.example",
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000001"}]
                }]},
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {"serverName": "upload.example"},
                    "xhttpSettings": {
                        "path": "/up",
                        "mode": "stream-up",
                        "downloadSettings": {
                            "address": "download.example",
                            "port": 8443,
                            "network": "xhttp",
                            "security": "tls",
                            "tlsSettings": {"serverName": "download.example"},
                            "xhttpSettings": {"path": "/down"}
                        }
                    }
                }
            }]
        });
        let (config, _) = parse_config(&config).unwrap();
        let Transport::Xhttp(upload) = &config.outbounds[0].stream.transport else {
            panic!("expected upload XHTTP")
        };
        let download = upload.xhttp_download.as_ref().expect("download settings");
        assert_eq!(download.address, Address::domain("download.example"));
        assert_eq!(download.port, 8443);
        let Transport::Xhttp(settings) = &download.stream.transport else {
            panic!("expected download XHTTP")
        };
        assert_eq!(settings.path.as_ref(), "/down");
    }

    #[test]
    fn vless_mux_settings_are_compiled_and_validated() {
        let config = serde_json::json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1",
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000001", "flow": "xtls-rprx-vision"}]
                }]},
                "mux": {"enabled": true, "concurrency": 8},
                "streamSettings": {"network": "tcp", "security": "tls"}
            }]
        });
        let error = parse_config(&config).unwrap_err();
        assert!(error.contains("Mux cannot be combined with Vision"));

        let config = serde_json::json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1",
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000001"}]
                }]},
                "mux": {"enabled": true, "concurrency": 8},
                "streamSettings": {"network": "tcp", "security": "tls"}
            }]
        });
        let (config, _) = parse_config(&config).unwrap();
        assert!(config.outbounds[0].mux.enabled);
        assert_eq!(config.outbounds[0].mux.max_concurrency, 8);
    }

    #[test]
    fn unsupported_inbound_transports_fail_closed() {
        let config = serde_json::json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": 1080,
                "protocol": "vless",
                "settings": {"clients": [{"id": "00000000-0000-0000-0000-000000000001"}]},
                "streamSettings": {
                    "network": "quic"
                }
            }],
            "outbounds": [{"protocol": "freedom"}]
        });
        let error = parse_config(&config).unwrap_err();
        assert!(error.contains("inbound transport \"quic\" is not implemented"));
    }

    #[test]
    fn accepts_reserved_xray_api_routing_target_for_api_inbound() {
        let config = serde_json::json!({
            "inbounds": [{"tag": "api", "protocol": "socks", "listen": "127.0.0.1", "port": 0}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]}
        });
        assert!(parse_config(&config).is_ok());
    }

    #[test]
    fn compiles_tun_addresses_and_explicit_routes() {
        let config = serde_json::json!({
            "inbounds": [{
                "tag": "tun",
                "protocol": "tun",
                "settings": {
                    "name": "zray-test",
                    "mtu": 1400,
                    "addresses": ["198.18.0.1/15", "2001:db8::1/64"],
                    "routes": ["0.0.0.0/1", "128.0.0.0/1"],
                    "autoRoute": true,
                    "strictRoute": true
                }
            }],
            "outbounds": [{"protocol": "freedom"}]
        });
        let (config, _) = parse_config(&config).unwrap();
        let InboundProtocol::Tun(tun) = &config.inbounds[0].protocol else {
            panic!("expected TUN inbound")
        };
        assert_eq!(tun.mtu, 1400);
        assert_eq!(tun.addresses.len(), 2);
        assert_eq!(tun.routes.len(), 2);
        assert!(tun.auto_route && tun.strict_route);
    }

    #[test]
    fn compiles_bounded_observatory_configuration() {
        let config = serde_json::json!({
            "outbounds": [{"tag": "proxy-a", "protocol": "freedom"}],
            "observatory": {
                "probeUrl": "https://example.com/health",
                "probeInterval": "30s",
                "subjectSelector": ["proxy-"]
            }
        });
        let (config, _) = parse_config(&config).unwrap();
        let observatory = config.observatory.unwrap();
        assert_eq!(
            observatory.probe_interval,
            std::time::Duration::from_secs(30)
        );
        assert_eq!(observatory.subject_selector[0].as_ref(), "proxy-");
        assert!(observatory.clean_ip.is_none());
    }

    #[test]
    fn compiles_bounded_clean_ip_candidates() {
        let config = serde_json::json!({
            "outbounds": [{"protocol": "freedom"}],
            "observatory": {
                "cleanIp": {
                    "candidates": ["192.0.2.10:443", "[2001:db8::10]:8443"],
                    "host": "edge.example.com",
                    "path": "/health"
                }
            }
        });
        let (config, _) = parse_config(&config).unwrap();
        let clean_ip = config.observatory.unwrap().clean_ip.unwrap();
        assert_eq!(clean_ip.candidates.len(), 2);
        assert_eq!(clean_ip.host.as_ref(), "edge.example.com");
        assert_eq!(clean_ip.path.as_ref(), "/health");
    }

    #[test]
    fn compiles_rule_set_assets() {
        let config = serde_json::json!({
            "outbounds": [{"protocol": "freedom"}],
            "assets": {
                "directory": "/var/lib/zray",
                "refreshInterval": "6h",
                "retryInterval": "10m",
                "refreshOnStart": true,
                "files": [
                    {
                        "name": "geosite.dat",
                        "kind": "geosite",
                        "urls": ["https://example.com/geosite.dat"],
                        "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
                    },
                    {"name": "geoip.dat", "kind": "geoip", "urls": "https://example.com/geoip.dat"}
                ]
            }
        });
        let (config, _) = parse_config(&config).unwrap();
        let assets = config.assets.unwrap();
        assert_eq!(
            assets.refresh_interval,
            std::time::Duration::from_secs(21_600)
        );
        assert_eq!(assets.retry_interval, std::time::Duration::from_secs(600));
        assert!(assets.refresh_on_start);
        assert_eq!(assets.directory.as_deref(), Some("/var/lib/zray"));
        assert_eq!(assets.files.len(), 2);
        assert_eq!(assets.files[0].kind, crate::AssetFileKind::Geosite);
        assert!(assets.files[0].sha256.is_some());
        assert_eq!(assets.files[1].urls.len(), 1);
    }

    #[test]
    fn asset_names_cannot_escape_the_cache_directory() {
        for name in ["../geosite.dat", "sub/geosite.dat", ".hidden"] {
            let config = serde_json::json!({
                "outbounds": [{"protocol": "freedom"}],
                "assets": {"files": [{"name": name, "kind": "geosite", "urls": []}]}
            });
            let error = parse_config(&config).unwrap_err();
            assert!(error.contains("simple file name"), "{name}: {error}");
        }
    }

    #[test]
    fn asset_mirrors_must_be_http_urls_and_pins_must_be_well_formed() {
        let config = serde_json::json!({
            "outbounds": [{"protocol": "freedom"}],
            "assets": {"files": [
                {"name": "geosite.dat", "kind": "geosite", "urls": ["file:///etc/passwd"]}
            ]}
        });
        assert!(parse_config(&config).unwrap_err().contains("http(s)"));

        let config = serde_json::json!({
            "outbounds": [{"protocol": "freedom"}],
            "assets": {"files": [
                {"name": "geosite.dat", "kind": "geosite", "urls": [], "sha256": "nope"}
            ]}
        });
        assert!(parse_config(&config).unwrap_err().contains("hexadecimal"));

        let config = serde_json::json!({
            "outbounds": [{"protocol": "freedom"}],
            "assets": {"files": [{"name": "x.dat", "kind": "sing-box", "urls": []}]}
        });
        assert!(parse_config(&config)
            .unwrap_err()
            .contains("geosite or geoip"));
    }

    #[test]
    fn duplicate_asset_names_are_rejected() {
        let config = serde_json::json!({
            "outbounds": [{"protocol": "freedom"}],
            "assets": {"files": [
                {"name": "geosite.dat", "kind": "geosite", "urls": []},
                {"name": "geosite.dat", "kind": "geoip", "urls": []}
            ]}
        });
        assert!(parse_config(&config).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn socks_password_accounts_are_compiled_for_the_runtime() {
        let config = serde_json::json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": 1080,
                "protocol": "socks",
                "settings": {
                    "auth": "password",
                    "accounts": [{"user": "alice", "pass": "correct-horse"}]
                }
            }],
            "outbounds": [{"protocol": "freedom"}]
        });
        let (config, _) = parse_config(&config).unwrap();
        let SocksAuth::Password(accounts) = &config.inbounds[0].socks_auth else {
            panic!("expected password auth")
        };
        assert_eq!(accounts[0].username.as_ref(), "alice");
        assert_eq!(accounts[0].password.as_ref(), "correct-horse");
    }

    #[test]
    fn compiles_anytls_client_and_server_with_certificate_tls() {
        let config = serde_json::json!({
            "inbounds": [],
            "outbounds": [{
                "protocol": "anytls",
                "settings": {
                    "address": "proxy.example",
                    "port": 443,
                    "password": "correct-horse"
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "tls"
                }
            }]
        });
        let (config, _) = parse_config(&config).unwrap();
        assert!(matches!(
            config.outbounds[0].protocol,
            OutboundProtocol::AnyTls(_)
        ));
    }

    #[test]
    fn compiles_hysteria2_client_with_certificate_tls() {
        let config = serde_json::json!({
            "inbounds": [],
            "outbounds": [{
                "protocol": "hysteria2",
                "settings": {
                    "address": "proxy.example",
                    "port": 443,
                    "password": "correct-horse"
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "tls",
                    "tlsSettings": {"serverName": "proxy.example", "alpn": ["h3"]}
                }
            }]
        });
        let (config, _) = parse_config(&config).unwrap();
        assert!(matches!(
            config.outbounds[0].protocol,
            OutboundProtocol::Hysteria2(_)
        ));
    }

    #[test]
    fn grpc_service_name_becomes_an_http2_path() {
        let config = serde_json::json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1",
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000001"}]
                }]},
                "streamSettings": {
                    "network": "grpc",
                    "grpcSettings": {"serviceName": "proxy"}
                }
            }]
        });
        let (config, _) = parse_config(&config).unwrap();
        let Transport::Grpc(settings) = &config.outbounds[0].stream.transport else {
            panic!("expected grpc")
        };
        assert_eq!(settings.path.as_ref(), "/proxy/Tun");
    }

    #[test]
    fn compile_assigns_ids_and_materialises_balancer_members() {
        let config = serde_json::json!({
            "outbounds": [
                {
                    "protocol": "vless",
                    "tag": "direct",
                    "settings": {"vnext": [{
                        "address": "127.0.0.1",
                        "port": 443,
                        "users": [{"id": "00000000-0000-0000-0000-000000000001"}]
                    }]}
                },
                {"protocol": "blackhole", "tag": "sink"}
            ],
            "routing": {
                "balancers": [{"tag": "fallback", "selector": ["direct"]}],
                "rules": [{"balancerTag": "fallback"}]
            }
        });
        let (generation, _) = compile_config(&config, zero_core::GenerationId(7)).unwrap();
        assert_eq!(generation.id, zero_core::GenerationId(7));
        assert_eq!(
            generation.outbound_id("direct"),
            Some(zero_core::OutboundId(0))
        );
        assert_eq!(
            generation.balancer_ids("fallback").unwrap(),
            &[zero_core::OutboundId(0)]
        );
    }

    #[test]
    fn parses_shadowsocks_inbound_and_outbound() {
        let config = serde_json::json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": 8388,
                "protocol": "shadowsocks",
                "settings": {"method": "aes-256-gcm", "password": "secret"}
            }],
            "outbounds": [{
                "protocol": "shadowsocks",
                "settings": {"servers": [{
                    "address": "proxy.example",
                    "port": 8388,
                    "method": "chacha20-ietf-poly1305",
                    "password": "secret"
                }]}
            }]
        });
        let (compiled, _) = parse_config(&config).unwrap();
        assert!(matches!(
            compiled.inbounds[0].protocol,
            InboundProtocol::Shadowsocks(_)
        ));
        assert!(matches!(
            compiled.outbounds[0].protocol,
            OutboundProtocol::Shadowsocks(ShadowsocksConfig {
                method: ShadowsocksMethod::Chacha20Poly1305,
                ..
            })
        ));
    }

    #[test]
    fn parses_tuic_v5_client_and_server() {
        let config = serde_json::json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": 8443,
                "protocol": "tuic",
                "settings": {
                    "uuid": "00000000-0000-0000-0000-000000000001",
                    "password": "secret"
                },
                "streamSettings": {
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [{"certificate": ["CERT"], "key": ["KEY"]}]
                    }
                }
            }],
            "outbounds": [{
                "protocol": "tuic",
                "settings": {"servers": [{
                    "address": "proxy.example",
                    "port": 8443,
                    "uuid": "00000000-0000-0000-0000-000000000001",
                    "password": "secret"
                }]},
                "streamSettings": {
                    "security": "tls",
                    "tlsSettings": {"serverName": "proxy.example"}
                }
            }]
        });
        let (compiled, _) = parse_config(&config).unwrap();
        assert!(matches!(
            compiled.inbounds[0].protocol,
            InboundProtocol::Tuic(_)
        ));
        assert!(matches!(
            compiled.outbounds[0].protocol,
            OutboundProtocol::Tuic(_)
        ));
    }

    #[test]
    fn parses_vmess_users_and_cipher_policy() {
        let config = serde_json::json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": 10086,
                "protocol": "vmess",
                "settings": {"clients": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "security": "aes-128-gcm"
                }]}
            }],
            "outbounds": [{
                "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": "proxy.example",
                    "port": 443,
                    "users": [{
                        "id": "00000000-0000-0000-0000-000000000001",
                        "security": "chacha20-poly1305"
                    }]
                }]}
            }]
        });
        let (compiled, _) = parse_config(&config).unwrap();
        assert!(matches!(
            compiled.inbounds[0].protocol,
            InboundProtocol::Vmess(VmessInboundConfig { .. })
        ));
        assert!(matches!(
            compiled.outbounds[0].protocol,
            OutboundProtocol::Vmess(VmessConfig {
                cipher: VmessCipher::Chacha20Poly1305,
                ..
            })
        ));
    }
}
