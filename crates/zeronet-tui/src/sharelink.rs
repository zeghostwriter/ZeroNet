//! Producing share links from a stored profile.
//!
//! Sharing is the other half of importing, and it is what v2rayN users reach
//! for constantly: copy a node, hand it to someone, show it as a QR code.
//!
//! A profile reaches the database by one of two routes, so this handles both:
//!
//! * **Imported from a link.** The builder preserves the original URI under
//!   `outbounds[0].link`, so the exact bytes the user pasted are handed back —
//!   no re-encoding, nothing silently dropped.
//! * **Built in the app** (the manual form, or a node retargeted onto a clean
//!   IP). There is no original, so a link is synthesised from the Xray-style
//!   outbound: `vnext`/`servers`, plus `streamSettings` for transport and TLS.

use std::fmt::Write as _;

use base64::Engine as _;

/// A profile rendered as a shareable URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareUri {
    pub uri: String,
    /// True when the original imported link was returned verbatim.
    pub verbatim: bool,
}

/// Build a share link for a stored profile.
///
/// `raw_content` is the profile JSON as stored; `remark` becomes the URI
/// fragment (the node's display name).
pub fn share_uri(raw_content: &str, remark: &str) -> Result<ShareUri, String> {
    let value: serde_json::Value =
        serde_json::from_str(raw_content).map_err(|e| format!("profile is not valid JSON: {e}"))?;

    let outbound = proxy_outbound(&value).ok_or("profile has no proxy outbound")?;

    // The imported original, when there is one, is always the better answer.
    if let Some(link) = outbound.get("link").and_then(|l| l.as_str()) {
        if !link.trim().is_empty() {
            return Ok(ShareUri {
                uri: retag(link.trim(), remark),
                verbatim: true,
            });
        }
    }

    synthesize(outbound, remark).map(|uri| ShareUri {
        uri,
        verbatim: false,
    })
}

/// A short transport description for the server table: `tcp · reality`,
/// `ws · tls`, `grpc`. `None` when the profile does not say.
pub fn transport_label(raw_content: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(raw_content).ok()?;
    let outbound = proxy_outbound(&value)?;
    let stream = outbound.get("streamSettings");
    let network = stream
        .and_then(|s| s.get("network"))
        .and_then(|n| n.as_str())
        .filter(|n| !n.is_empty());
    let security = stream
        .and_then(|s| s.get("security"))
        .and_then(|n| n.as_str())
        .filter(|s| !s.is_empty() && *s != "none");
    let network = match outbound.get("protocol").and_then(|p| p.as_str()) {
        Some("hysteria2" | "hysteria" | "tuic") => Some("quic"),
        _ => network.or(Some("tcp")),
    }?;
    let network = match network {
        "splithttp" => "xhttp",
        "raw" => "tcp",
        other => other,
    };
    Some(match security {
        Some(security) => format!("{network} · {security}"),
        None => network.to_string(),
    })
}

/// The outbound that carries the actual proxy, skipping `direct` and `block`.
fn proxy_outbound(value: &serde_json::Value) -> Option<&serde_json::Value> {
    let outbounds = value.get("outbounds")?.as_array()?;
    outbounds
        .iter()
        .find(|o| o.get("tag").and_then(|t| t.as_str()) == Some("proxy"))
        .or_else(|| {
            outbounds.iter().find(|o| {
                !matches!(
                    o.get("protocol").and_then(|p| p.as_str()),
                    Some("freedom") | Some("blackhole") | Some("dns")
                )
            })
        })
        .or_else(|| outbounds.first())
}

/// Replace a link's `#fragment` with the profile's current name.
///
/// A renamed profile should share under its new name; everything before the
/// fragment is left byte-for-byte intact.
fn retag(link: &str, remark: &str) -> String {
    let body = link.split_once('#').map_or(link, |(b, _)| b);
    if remark.trim().is_empty() {
        body.to_string()
    } else {
        format!("{body}#{}", percent_encode(remark))
    }
}

fn synthesize(outbound: &serde_json::Value, remark: &str) -> Result<String, String> {
    let protocol = outbound
        .get("protocol")
        .and_then(|p| p.as_str())
        .ok_or("outbound has no protocol")?;

    match protocol {
        "vless" => synth_vless(outbound, remark),
        "trojan" => synth_trojan(outbound, remark),
        "shadowsocks" => synth_shadowsocks(outbound, remark),
        "vmess" => synth_vmess(outbound, remark),
        other => Err(format!("{other} profiles cannot be shared as a link")),
    }
}

/// The first entry of `settings.vnext` or `settings.servers`.
/// The message shown when a stored profile has no endpoint to share.
///
/// Profiles written by older builds can carry a protocol and nothing else;
/// "outbound has no server" is engine-speak, so say what the user can do.
const NO_SERVER: &str =
    "this profile has no server details saved. Re-import it from its share link";

fn first_server(outbound: &serde_json::Value) -> Option<&serde_json::Value> {
    let settings = outbound.get("settings")?;
    for key in ["vnext", "servers"] {
        if let Some(server) = settings
            .get(key)
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
        {
            return Some(server);
        }
    }
    None
}

fn host_port(server: &serde_json::Value) -> Result<(String, u16), String> {
    let address = server
        .get("address")
        .and_then(|a| a.as_str())
        .ok_or("server has no address")?;
    let port = server
        .get("port")
        .and_then(|p| p.as_u64())
        .ok_or("server has no port")? as u16;
    Ok((address.to_string(), port))
}

/// Transport and TLS parameters shared by the VLESS and Trojan URI formats.
fn stream_query(outbound: &serde_json::Value) -> Vec<(String, String)> {
    let mut params: Vec<(String, String)> = Vec::new();
    let Some(stream) = outbound.get("streamSettings") else {
        return params;
    };

    let network = stream
        .get("network")
        .and_then(|n| n.as_str())
        .unwrap_or("tcp");
    params.push(("type".into(), network.into()));

    let security = stream
        .get("security")
        .and_then(|s| s.as_str())
        .unwrap_or("none");
    params.push(("security".into(), security.into()));

    match security {
        "reality" => {
            if let Some(r) = stream.get("realitySettings") {
                push_str(&mut params, "sni", r.get("serverName"));
                push_str(&mut params, "pbk", r.get("publicKey"));
                push_str(&mut params, "sid", r.get("shortId"));
                push_str(&mut params, "fp", r.get("fingerprint"));
                push_str(&mut params, "spx", r.get("spiderX"));
            }
        }
        "tls" => {
            if let Some(t) = stream.get("tlsSettings") {
                push_str(&mut params, "sni", t.get("serverName"));
                push_str(&mut params, "fp", t.get("fingerprint"));
                if let Some(alpn) = t.get("alpn").and_then(|a| a.as_array()) {
                    let joined: Vec<&str> = alpn.iter().filter_map(|v| v.as_str()).collect();
                    if !joined.is_empty() {
                        params.push(("alpn".into(), joined.join(",")));
                    }
                }
            }
        }
        _ => {}
    }

    match network {
        "ws" => {
            if let Some(ws) = stream.get("wsSettings") {
                push_str(&mut params, "path", ws.get("path"));
                push_str(
                    &mut params,
                    "host",
                    ws.get("headers").and_then(|h| h.get("Host")),
                );
            }
        }
        "grpc" => {
            if let Some(g) = stream.get("grpcSettings") {
                push_str(&mut params, "serviceName", g.get("serviceName"));
            }
        }
        "xhttp" | "splithttp" => {
            if let Some(x) = stream
                .get("xhttpSettings")
                .or_else(|| stream.get("splithttpSettings"))
            {
                push_str(&mut params, "path", x.get("path"));
                push_str(&mut params, "host", x.get("host"));
                push_str(&mut params, "mode", x.get("mode"));
            }
        }
        _ => {}
    }

    params
}

fn push_str(params: &mut Vec<(String, String)>, key: &str, value: Option<&serde_json::Value>) {
    if let Some(s) = value.and_then(|v| v.as_str()) {
        if !s.is_empty() {
            params.push((key.to_string(), s.to_string()));
        }
    }
}

fn synth_vless(outbound: &serde_json::Value, remark: &str) -> Result<String, String> {
    let server = first_server(outbound).ok_or(NO_SERVER)?;
    let (host, port) = host_port(server)?;
    let user = server
        .get("users")
        .and_then(|u| u.as_array())
        .and_then(|a| a.first())
        .ok_or(NO_SERVER)?;
    let id = user
        .get("id")
        .and_then(|i| i.as_str())
        .ok_or("vless user has no id")?;

    let mut params = vec![("encryption".to_string(), "none".to_string())];
    if let Some(flow) = user.get("flow").and_then(|f| f.as_str()) {
        if !flow.is_empty() && flow != "none" {
            params.push(("flow".into(), flow.into()));
        }
    }
    params.extend(stream_query(outbound));

    Ok(format!(
        "vless://{id}@{}:{port}?{}#{}",
        bracket_ipv6(&host),
        encode_query(&params),
        percent_encode(remark)
    ))
}

fn synth_trojan(outbound: &serde_json::Value, remark: &str) -> Result<String, String> {
    let server = first_server(outbound).ok_or(NO_SERVER)?;
    let (host, port) = host_port(server)?;
    let password = server
        .get("password")
        .and_then(|p| p.as_str())
        .ok_or("trojan server has no password")?;

    Ok(format!(
        "trojan://{}@{}:{port}?{}#{}",
        percent_encode(password),
        bracket_ipv6(&host),
        encode_query(&stream_query(outbound)),
        percent_encode(remark)
    ))
}

fn synth_shadowsocks(outbound: &serde_json::Value, remark: &str) -> Result<String, String> {
    let server = first_server(outbound).ok_or(NO_SERVER)?;
    let (host, port) = host_port(server)?;
    let method = server
        .get("method")
        .and_then(|m| m.as_str())
        .ok_or("shadowsocks server has no method")?;
    let password = server
        .get("password")
        .and_then(|p| p.as_str())
        .ok_or("shadowsocks server has no password")?;

    // SIP002: base64url(method:password) with no padding.
    let userinfo =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{method}:{password}"));
    Ok(format!(
        "ss://{userinfo}@{}:{port}#{}",
        bracket_ipv6(&host),
        percent_encode(remark)
    ))
}

fn synth_vmess(outbound: &serde_json::Value, remark: &str) -> Result<String, String> {
    let server = first_server(outbound).ok_or(NO_SERVER)?;
    let (host, port) = host_port(server)?;
    let user = server
        .get("users")
        .and_then(|u| u.as_array())
        .and_then(|a| a.first())
        .ok_or(NO_SERVER)?;
    let id = user
        .get("id")
        .and_then(|i| i.as_str())
        .ok_or("vmess user has no id")?;

    let stream = outbound.get("streamSettings");
    let network = stream
        .and_then(|s| s.get("network"))
        .and_then(|n| n.as_str())
        .unwrap_or("tcp");
    let security = stream
        .and_then(|s| s.get("security"))
        .and_then(|s| s.as_str())
        .unwrap_or("none");

    // The v2rayN "vmess://" format: base64 of a flat JSON object, version 2.
    let payload = serde_json::json!({
        "v": "2",
        "ps": remark,
        "add": host,
        "port": port.to_string(),
        "id": id,
        "aid": user.get("alterId").and_then(|a| a.as_u64()).unwrap_or(0).to_string(),
        "scy": user.get("security").and_then(|s| s.as_str()).unwrap_or("auto"),
        "net": network,
        "type": "none",
        "host": stream
            .and_then(|s| s.get("wsSettings"))
            .and_then(|w| w.get("headers"))
            .and_then(|h| h.get("Host"))
            .and_then(|h| h.as_str())
            .unwrap_or(""),
        "path": stream
            .and_then(|s| s.get("wsSettings"))
            .and_then(|w| w.get("path"))
            .and_then(|p| p.as_str())
            .unwrap_or(""),
        "tls": if security == "tls" { "tls" } else { "" },
        "sni": stream
            .and_then(|s| s.get("tlsSettings"))
            .and_then(|t| t.get("serverName"))
            .and_then(|s| s.as_str())
            .unwrap_or(""),
    });

    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.to_string());
    Ok(format!("vmess://{encoded}"))
}

fn encode_query(params: &[(String, String)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        let _ = write!(out, "{}={}", percent_encode(k), percent_encode(v));
    }
    out
}

/// Wrap a bare IPv6 literal in brackets so it is a valid URI authority.
fn bracket_ipv6(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Percent-encode everything outside the URI unreserved set.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// Bundle several profiles into a subscription body.
///
/// One link per line, base64-encoded — the format every client accepts when
/// pointed at a subscription URL.
pub fn subscription_body(links: &[String]) -> String {
    base64::engine::general_purpose::STANDARD.encode(links.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AMNEZIA_LINK: &str = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@155.117.13.26:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.googletagmanager.com&fp=chrome&pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY&sid=7963d08380d47375&type=tcp&headerType=none#AmneziaVPN";

    fn imported_profile(link: &str) -> String {
        serde_json::json!({
            "outbounds": [
                {"tag": "proxy", "link": link},
                {"tag": "direct", "protocol": "freedom"}
            ]
        })
        .to_string()
    }

    #[test]
    fn transport_labels_read_the_stream_settings() {
        let reality = r#"{"outbounds":[{"tag":"proxy","protocol":"vless","streamSettings":{"network":"tcp","security":"reality"}}]}"#;
        assert_eq!(transport_label(reality).as_deref(), Some("tcp · reality"));
        let ws = r#"{"outbounds":[{"protocol":"freedom"},{"protocol":"vmess","streamSettings":{"network":"ws","security":"tls"}}]}"#;
        assert_eq!(transport_label(ws).as_deref(), Some("ws · tls"));
        let bare = r#"{"outbounds":[{"protocol":"shadowsocks"}]}"#;
        assert_eq!(transport_label(bare).as_deref(), Some("tcp"));
        let quic =
            r#"{"outbounds":[{"protocol":"hysteria2","streamSettings":{"security":"tls"}}]}"#;
        assert_eq!(transport_label(quic).as_deref(), Some("quic · tls"));
        assert_eq!(transport_label("not json"), None);
    }

    #[test]
    fn an_imported_link_comes_back_verbatim() {
        let profile = imported_profile(AMNEZIA_LINK);
        let share = share_uri(&profile, "AmneziaVPN").unwrap();
        assert!(share.verbatim);
        assert!(share.uri.starts_with("vless://245abd35"));
        assert!(share
            .uri
            .contains("pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY"));
    }

    #[test]
    fn renaming_a_profile_renames_the_shared_link() {
        let profile = imported_profile(AMNEZIA_LINK);
        let share = share_uri(&profile, "My Node").unwrap();
        assert!(share.uri.ends_with("#My%20Node"), "got {}", share.uri);
        // Everything before the fragment is untouched.
        assert!(share.uri.contains("sid=7963d08380d47375"));
    }

    #[test]
    fn a_manually_built_vless_profile_round_trips_through_the_parser() {
        let form = crate::manual_profile::ManualProfileForm::new();
        let profile = form.to_json().unwrap();
        let share = share_uri(&profile, "Manual Node").unwrap();
        assert!(!share.verbatim, "synthesised link was reported as verbatim");

        // The real test: zero-config must be able to read back what we wrote.
        let parsed = zero_config::parse_link(&share.uri)
            .unwrap_or_else(|e| panic!("synthesised link {} did not parse: {e}", share.uri));
        assert_eq!(parsed.remark, "Manual Node");
        let zero_config::OutboundProtocol::Vless(v) = &parsed.outbound.protocol else {
            panic!(
                "expected a vless outbound, got {:?}",
                parsed.outbound.protocol
            );
        };
        assert_eq!(v.port, 443);
        assert_eq!(v.address.to_string(), "155.117.13.26");
    }

    #[test]
    fn synthesised_reality_parameters_survive_the_round_trip() {
        let form = crate::manual_profile::ManualProfileForm::new();
        let share = share_uri(&form.to_json().unwrap(), "R").unwrap();
        assert!(share.uri.contains("security=reality"));
        assert!(share
            .uri
            .contains("pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY"));
        assert!(share.uri.contains("sid=7963d08380d47375"));
        assert!(share.uri.contains("sni=www.googletagmanager.com"));
        assert!(share.uri.contains("flow=xtls-rprx-vision"));
    }

    #[test]
    fn a_trojan_profile_synthesises_a_parseable_link() {
        let profile = serde_json::json!({
            "outbounds": [{
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {"servers": [{
                    "address": "example.com", "port": 443, "password": "p@ss word"
                }]},
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {"serverName": "example.com"},
                    "wsSettings": {"path": "/ws", "headers": {"Host": "example.com"}}
                }
            }]
        })
        .to_string();

        let share = share_uri(&profile, "Trojan WS").unwrap();
        let parsed = zero_config::parse_link(&share.uri)
            .unwrap_or_else(|e| panic!("{} did not parse: {e}", share.uri));
        assert_eq!(parsed.remark, "Trojan WS");
        // A password with a space and an @ must survive percent-encoding.
        let zero_config::OutboundProtocol::Trojan(t) = &parsed.outbound.protocol else {
            panic!("expected trojan");
        };
        assert_eq!(t.port, 443);
    }

    #[test]
    fn a_shadowsocks_profile_uses_sip002() {
        let profile = serde_json::json!({
            "outbounds": [{
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": {"servers": [{
                    "address": "1.2.3.4", "port": 8388,
                    "method": "aes-256-gcm", "password": "secret"
                }]}
            }]
        })
        .to_string();

        let share = share_uri(&profile, "SS Node").unwrap();
        assert!(share.uri.starts_with("ss://"));
        let parsed = zero_config::parse_link(&share.uri)
            .unwrap_or_else(|e| panic!("{} did not parse: {e}", share.uri));
        assert_eq!(parsed.remark, "SS Node");
    }

    #[test]
    fn a_vmess_profile_emits_the_v2rayn_json_form() {
        let profile = serde_json::json!({
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": "1.2.3.4", "port": 443,
                    "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": 0}]
                }]},
                "streamSettings": {"network": "ws", "security": "tls",
                    "wsSettings": {"path": "/p", "headers": {"Host": "h.example"}},
                    "tlsSettings": {"serverName": "h.example"}}
            }]
        })
        .to_string();

        let share = share_uri(&profile, "VMess").unwrap();
        assert!(share.uri.starts_with("vmess://"));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(share.uri.trim_start_matches("vmess://"))
            .expect("vmess payload is base64");
        let obj: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(obj["ps"], "VMess");
        assert_eq!(obj["add"], "1.2.3.4");
        assert_eq!(obj["net"], "ws");
        assert_eq!(obj["path"], "/p");
        assert_eq!(obj["tls"], "tls");
    }

    #[test]
    fn ipv6_hosts_are_bracketed() {
        let profile = serde_json::json!({
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "2606:4700::1111", "port": 443,
                    "users": [{"id": "245abd35-7efa-4bc8-85d4-a04f3798329f"}]
                }]}
            }]
        })
        .to_string();
        let share = share_uri(&profile, "v6").unwrap();
        assert!(
            share.uri.contains("@[2606:4700::1111]:443"),
            "got {}",
            share.uri
        );
    }

    #[test]
    fn unsupported_and_malformed_profiles_explain_themselves() {
        assert!(share_uri("not json", "x")
            .unwrap_err()
            .contains("valid JSON"));
        assert!(share_uri(r#"{"outbounds":[]}"#, "x").is_err());

        let wireguard = serde_json::json!({
            "outbounds": [{"tag": "proxy", "protocol": "wireguard"}]
        })
        .to_string();
        let err = share_uri(&wireguard, "wg").unwrap_err();
        assert!(err.contains("cannot be shared"), "{err}");
    }

    #[test]
    fn the_proxy_outbound_is_picked_over_direct_and_block() {
        let profile = serde_json::json!({
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
                {"tag": "proxy", "link": AMNEZIA_LINK}
            ]
        })
        .to_string();
        let share = share_uri(&profile, "n").unwrap();
        assert!(share.uri.starts_with("vless://"));
    }

    #[test]
    fn a_subscription_body_is_base64_of_newline_separated_links() {
        let ss = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:secret");
        let links = vec![
            AMNEZIA_LINK.to_string(),
            format!("ss://{ss}@1.2.3.4:8388#SS"),
        ];
        let body = subscription_body(&links);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&body)
            .unwrap();
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text.lines().count(), 2);
        // And it must round-trip through the subscription parser.
        let parsed = zero_config::parse_subscription(&body);
        assert_eq!(parsed.len(), 2);
        for entry in &parsed {
            assert!(entry.is_ok(), "{:?}", entry.as_ref().err());
        }
    }

    #[test]
    fn percent_encoding_covers_the_reserved_set() {
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("p@ss/word?"), "p%40ss%2Fword%3F");
        assert_eq!(percent_encode("safe-_.~"), "safe-_.~");
        // Non-ASCII names are common in subscription feeds.
        assert_eq!(percent_encode("日本"), "%E6%97%A5%E6%9C%AC");
    }
}
