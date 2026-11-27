//! Subscriptions that answer with JSON instead of share links.
//!
//! Panels such as BPB (`…/sub/normal/…?app=xray`), Marzban's and Hiddify's
//! Xray endpoints serve complete client configurations: one Xray config
//! object, or an array of them where each carries a `remarks` name. Others
//! (`?app=sing-box`) serve a sing-box config. The app works in share links,
//! so every proxy outbound in such a body is turned into the equivalent link;
//! the rest of the config (routing, DNS, the `fragment` helper outbound a
//! panel chains in) is the client's own business, which ZeroNet decides by
//! itself.
//!
//! Only what a link can express is emitted. An outbound whose transport a
//! link cannot carry is left out rather than turned into a link that would
//! silently behave differently.

use serde_json::{Map, Value};

/// The tag BPB gives the stand-in outbound of its serverless ("WorkerLess")
/// configs: a VLESS entry for `google.com` with a made-up id that the client
/// needs only because Xray refuses a config with no proxy in it. Nothing is
/// routed to it, and as a share link it would answer a TCP test (Google is
/// up) and carry nothing.
const PLACEHOLDER_TAG: &str = "fake-outbound";

/// Share links for every proxy outbound in a JSON subscription body, or
/// `None` when the body is not JSON of a shape this module knows.
pub fn links_from_json(text: &str) -> Option<Vec<String>> {
    let trimmed = text.trim_start_matches('\u{feff}').trim();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return None;
    }
    let value: Value = serde_json::from_str(trimmed).ok()?;
    let configs: Vec<&Value> = match &value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![&value],
        _ => return None,
    };
    let mut links = Vec::new();
    let mut recognised = false;
    for config in configs {
        let Some(outbounds) = config.get("outbounds").and_then(Value::as_array) else {
            continue;
        };
        recognised = true;
        let remarks = config
            .get("remarks")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|remarks| !remarks.is_empty());
        // The fragmentation of every direct outbound, by tag: a proxy that is
        // dialled through one (`dialerProxy`) is fragmented the same way.
        let dialers: std::collections::HashMap<&str, Value> = outbounds
            .iter()
            .filter_map(Value::as_object)
            .filter(|outbound| str_of(outbound, "protocol") == Some("freedom"))
            .filter_map(|outbound| Some((str_of(outbound, "tag")?, fragment_mask(outbound)?)))
            .collect();
        let mut proxies: Vec<(String, String)> = outbounds
            .iter()
            .filter_map(Value::as_object)
            .filter(|outbound| str_of(outbound, "tag") != Some(PLACEHOLDER_TAG))
            .filter_map(|outbound| {
                if outbound.contains_key("protocol") {
                    let (link, tag) = xray_outbound(outbound)?;
                    let own = fragment_mask(outbound).or_else(|| {
                        let via = outbound
                            .get("streamSettings")?
                            .get("sockopt")?
                            .get("dialerProxy")?
                            .as_str()?;
                        dialers.get(via).cloned()
                    });
                    Some((with_fragment(link, own), tag))
                } else {
                    sing_box_outbound(outbound)
                }
            })
            .collect();
        // A config with no server in it whose traffic all leaves through a
        // fragmenting direct outbound (BPB's "Serverless"): one direct
        // profile, preferring the outbound the panel calls `proxy`.
        if proxies.is_empty() {
            let direct = outbounds
                .iter()
                .filter_map(Value::as_object)
                .filter(|outbound| str_of(outbound, "protocol") == Some("freedom"))
                .filter_map(|outbound| Some((str_of(outbound, "tag")?, fragment_mask(outbound)?)))
                .min_by_key(|(tag, _)| *tag != "proxy");
            if let Some((tag, mask)) = direct {
                proxies.push((
                    format!("direct://?fm={}", encode(&mask.to_string())),
                    tag.to_string(),
                ));
            }
        }
        let single = proxies.len() == 1;
        for (index, (link, tag)) in proxies.into_iter().enumerate() {
            let name = match (remarks, single) {
                (Some(remarks), true) => remarks.to_string(),
                (Some(remarks), false) => format!("{remarks} {}", index + 1),
                (None, _) if !tag.is_empty() => tag,
                (None, _) => format!("config {}", index + 1),
            };
            links.push(format!("{link}#{}", encode(&name)));
        }
    }
    // A panel lists the same direct profile once per DNS choice and the like;
    // two links that differ only in their names are one link.
    let mut seen = std::collections::HashSet::new();
    links.retain(|link| seen.insert(link.split('#').next().unwrap_or(link).to_string()));
    recognised.then_some(links)
}

// ------------------------------------------------------------------- Xray

/// The TCP fragmentation an Xray outbound asks for, as a `finalmask` object
/// (what a link's `fm=` carries): from `streamSettings.finalmask`, or from
/// the older `settings.fragment` of a direct outbound.
fn fragment_mask(outbound: &Map<String, Value>) -> Option<Value> {
    let masks: Vec<Value> = outbound
        .get("streamSettings")
        .and_then(|stream| stream.get("finalmask"))
        .and_then(|mask| mask.get("tcp"))
        .and_then(Value::as_array)
        .map(|masks| {
            masks
                .iter()
                .filter(|mask| mask.get("type").and_then(Value::as_str) == Some("fragment"))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if !masks.is_empty() {
        return Some(serde_json::json!({"tcp": masks}));
    }
    let fragment = outbound.get("settings")?.get("fragment")?.as_object()?;
    Some(serde_json::json!({"tcp": [{"type": "fragment", "settings": fragment}]}))
}

/// `link` with the fragmentation it was meant to be dialled with, for the
/// link kinds that have a query (VMess and Shadowsocks links do not).
fn with_fragment(link: String, mask: Option<Value>) -> String {
    match mask {
        Some(mask) if link.starts_with("vless://") || link.starts_with("trojan://") => {
            let joiner = if link.contains('?') { '&' } else { '?' };
            format!("{link}{joiner}fm={}", encode(&mask.to_string()))
        }
        _ => link,
    }
}

/// One Xray outbound as `(link without remark, tag)`.
fn xray_outbound(outbound: &Map<String, Value>) -> Option<(String, String)> {
    // Xray writes a server either nested (`vnext`, `servers`) or, in its
    // simplified form, flat; read both as the nested one.
    let nested = zero_config::nested_outbound(&Value::Object(outbound.clone()));
    let outbound = nested
        .as_ref()
        .and_then(Value::as_object)
        .unwrap_or(outbound);
    let protocol = str_of(outbound, "protocol")?.to_ascii_lowercase();
    let tag = str_of(outbound, "tag").unwrap_or("").to_string();
    let settings = outbound.get("settings")?;
    let stream = outbound
        .get("streamSettings")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let link = match protocol.as_str() {
        "vless" => {
            let (host, port, user) = vnext(settings)?;
            let id = str_of(user, "id")?;
            let mut query = xray_stream(&stream)?;
            // A VLESS Encryption server's setting travels in the link; "none"
            // for an unencrypted one.
            let encryption = str_of(user, "encryption")
                .filter(|setting| !setting.is_empty())
                .unwrap_or("none")
                .to_string();
            query.insert(0, ("encryption", encryption));
            if let Some(flow) = str_of(user, "flow").filter(|flow| !flow.is_empty()) {
                query.push(("flow", flow.to_string()));
            }
            format!(
                "vless://{}@{}?{}",
                encode(id),
                endpoint(host, port),
                join(&query)
            )
        }
        "trojan" => {
            let (host, port, server) = first_server(settings)?;
            let password = str_of(server, "password")?;
            let query = xray_stream(&stream)?;
            format!(
                "trojan://{}@{}?{}",
                encode(password),
                endpoint(host, port),
                join(&query)
            )
        }
        "shadowsocks" => {
            let (host, port, server) = first_server(settings)?;
            let method = str_of(server, "method")?;
            let password = str_of(server, "password")?;
            // A plain TCP link is all ss:// carries.
            if !matches!(network(&stream).as_str(), "tcp" | "raw") {
                return None;
            }
            shadowsocks_link(method, password, host, port)
        }
        "vmess" => {
            let (host, port, user) = vnext(settings)?;
            let id = str_of(user, "id")?;
            let query = xray_stream(&stream)?;
            vmess_link(
                host,
                port,
                id,
                str_of(user, "security").unwrap_or("auto"),
                &query,
                &tag,
            )
        }
        _ => return None,
    };
    Some((link, tag))
}

fn vnext(settings: &Value) -> Option<(&str, u64, &Map<String, Value>)> {
    let server = settings.get("vnext")?.as_array()?.first()?.as_object()?;
    let user = server.get("users")?.as_array()?.first()?.as_object()?;
    Some((str_of(server, "address")?, port_of(server)?, user))
}

fn first_server(settings: &Value) -> Option<(&str, u64, &Map<String, Value>)> {
    let server = settings.get("servers")?.as_array()?.first()?.as_object()?;
    Some((str_of(server, "address")?, port_of(server)?, server))
}

fn network(stream: &Map<String, Value>) -> String {
    str_of(stream, "network")
        .unwrap_or("tcp")
        .to_ascii_lowercase()
}

/// The query parameters for a stream, or `None` when a link cannot carry it.
fn xray_stream(stream: &Map<String, Value>) -> Option<Vec<(&'static str, String)>> {
    let mut query: Vec<(&'static str, String)> = Vec::new();
    let network = network(stream);
    let security = str_of(stream, "security")
        .unwrap_or("none")
        .to_ascii_lowercase();
    match network.as_str() {
        "tcp" | "raw" => {
            // An HTTP camouflage header is not something a VLESS or Trojan
            // link can carry.
            let header = stream
                .get("tcpSettings")
                .or_else(|| stream.get("rawSettings"))
                .and_then(|s| s.get("header"))
                .and_then(|h| h.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("none");
            if !header.eq_ignore_ascii_case("none") {
                return None;
            }
            query.push(("type", "tcp".into()));
        }
        "ws" | "websocket" => {
            let ws = stream.get("wsSettings").and_then(Value::as_object);
            query.push(("type", "ws".into()));
            push_path_host(&mut query, ws, header_host(ws));
        }
        "httpupgrade" => {
            let settings = stream.get("httpupgradeSettings").and_then(Value::as_object);
            query.push(("type", "httpupgrade".into()));
            push_path_host(&mut query, settings, header_host(settings));
        }
        "grpc" | "gun" => {
            let grpc = stream.get("grpcSettings").and_then(Value::as_object);
            query.push(("type", "grpc".into()));
            if let Some(service) = grpc.and_then(|g| str_of(g, "serviceName")) {
                query.push(("serviceName", service.to_string()));
            }
            if let Some(authority) = grpc.and_then(|g| str_of(g, "authority")) {
                query.push(("authority", authority.to_string()));
            }
            if grpc
                .and_then(|g| g.get("multiMode"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                query.push(("mode", "multi".into()));
            }
        }
        "xhttp" | "splithttp" => {
            let xhttp = stream
                .get("xhttpSettings")
                .or_else(|| stream.get("splithttpSettings"))
                .and_then(Value::as_object);
            query.push(("type", "xhttp".into()));
            push_path_host(&mut query, xhttp, None);
            if let Some(mode) = xhttp.and_then(|x| str_of(x, "mode")) {
                query.push(("mode", mode.to_string()));
            }
            if let Some(extra) = xhttp.and_then(|x| x.get("extra")).filter(|e| e.is_object()) {
                query.push(("extra", extra.to_string()));
            }
        }
        _ => return None,
    }
    match security.as_str() {
        "tls" => {
            let tls = stream.get("tlsSettings").and_then(Value::as_object);
            query.push(("security", "tls".into()));
            if let Some(tls) = tls {
                push_opt(&mut query, "sni", str_of(tls, "serverName"));
                push_opt(&mut query, "fp", str_of(tls, "fingerprint"));
                push_alpn(&mut query, tls.get("alpn"));
                if tls.get("allowInsecure").and_then(Value::as_bool) == Some(true) {
                    query.push(("allowInsecure", "1".into()));
                }
            }
        }
        "reality" => {
            let reality = stream.get("realitySettings").and_then(Value::as_object)?;
            query.push(("security", "reality".into()));
            push_opt(&mut query, "sni", str_of(reality, "serverName"));
            push_opt(&mut query, "fp", str_of(reality, "fingerprint"));
            push_opt(
                &mut query,
                "pbk",
                str_of(reality, "publicKey").or_else(|| str_of(reality, "password")),
            );
            push_opt(&mut query, "sid", str_of(reality, "shortId"));
            push_opt(&mut query, "spx", str_of(reality, "spiderX"));
        }
        "none" | "" => query.push(("security", "none".into())),
        _ => return None,
    }
    Some(query)
}

fn header_host(settings: Option<&Map<String, Value>>) -> Option<String> {
    let settings = settings?;
    str_of(settings, "host")
        .filter(|host| !host.is_empty())
        .map(str::to_string)
        .or_else(|| {
            let headers = settings.get("headers")?.as_object()?;
            headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("host"))
                .and_then(|(_, value)| value.as_str())
                .map(str::to_string)
        })
}

fn push_path_host(
    query: &mut Vec<(&'static str, String)>,
    settings: Option<&Map<String, Value>>,
    host: Option<String>,
) {
    if let Some(path) = settings.and_then(|s| str_of(s, "path")) {
        query.push(("path", path.to_string()));
    }
    let host = host.or_else(|| settings.and_then(|s| str_of(s, "host")).map(str::to_string));
    push_opt(query, "host", host.as_deref());
}

// ---------------------------------------------------------------- sing-box

/// One sing-box outbound as `(link without remark, tag)`.
fn sing_box_outbound(outbound: &Map<String, Value>) -> Option<(String, String)> {
    let kind = str_of(outbound, "type")?.to_ascii_lowercase();
    let tag = str_of(outbound, "tag").unwrap_or("").to_string();
    let host = str_of(outbound, "server")?;
    let port = outbound.get("server_port").and_then(Value::as_u64)?;
    let link = match kind.as_str() {
        "vless" => {
            let mut query = sing_box_stream(outbound)?;
            query.insert(0, ("encryption", "none".into()));
            push_opt(&mut query, "flow", str_of(outbound, "flow"));
            format!(
                "vless://{}@{}?{}",
                encode(str_of(outbound, "uuid")?),
                endpoint(host, port),
                join(&query)
            )
        }
        "trojan" => {
            let query = sing_box_stream(outbound)?;
            format!(
                "trojan://{}@{}?{}",
                encode(str_of(outbound, "password")?),
                endpoint(host, port),
                join(&query)
            )
        }
        "vmess" => {
            let query = sing_box_stream(outbound)?;
            vmess_link(
                host,
                port,
                str_of(outbound, "uuid")?,
                str_of(outbound, "security").unwrap_or("auto"),
                &query,
                &tag,
            )
        }
        "shadowsocks" => {
            if outbound.contains_key("plugin") {
                return None;
            }
            shadowsocks_link(
                str_of(outbound, "method")?,
                str_of(outbound, "password")?,
                host,
                port,
            )
        }
        "hysteria2" => {
            // The certificate settings and Salamander are all a link carries
            // of a Hysteria 2 outbound; bandwidth hints and ports ranges are
            // the client's own business.
            let tls = outbound.get("tls").and_then(Value::as_object);
            let mut query: Vec<(&'static str, String)> = Vec::new();
            push_opt(
                &mut query,
                "sni",
                tls.and_then(|t| str_of(t, "server_name")),
            );
            if tls.and_then(|t| t.get("insecure")).and_then(Value::as_bool) == Some(true) {
                query.push(("insecure", "1".into()));
            }
            if let Some(obfs) = outbound.get("obfs").and_then(Value::as_object) {
                query.push(("obfs", str_of(obfs, "type")?.to_string()));
                query.push(("obfs-password", str_of(obfs, "password")?.to_string()));
            }
            format!(
                "hysteria2://{}@{}/?{}",
                encode(str_of(outbound, "password")?),
                endpoint(host, port),
                join(&query)
            )
        }
        _ => return None,
    };
    Some((link, tag))
}

fn sing_box_stream(outbound: &Map<String, Value>) -> Option<Vec<(&'static str, String)>> {
    let mut query: Vec<(&'static str, String)> = Vec::new();
    match outbound.get("transport").and_then(Value::as_object) {
        None => query.push(("type", "tcp".into())),
        Some(transport) => match str_of(transport, "type")?.to_ascii_lowercase().as_str() {
            "ws" => {
                query.push(("type", "ws".into()));
                push_path_host(&mut query, Some(transport), header_host(Some(transport)));
            }
            "httpupgrade" => {
                query.push(("type", "httpupgrade".into()));
                push_path_host(&mut query, Some(transport), header_host(Some(transport)));
            }
            "grpc" => {
                query.push(("type", "grpc".into()));
                push_opt(&mut query, "serviceName", str_of(transport, "service_name"));
            }
            _ => return None,
        },
    }
    match outbound.get("tls").and_then(Value::as_object) {
        Some(tls) if tls.get("enabled").and_then(Value::as_bool) == Some(true) => {
            let reality = tls
                .get("reality")
                .and_then(Value::as_object)
                .filter(|r| r.get("enabled").and_then(Value::as_bool) == Some(true));
            query.push((
                "security",
                if reality.is_some() { "reality" } else { "tls" }.into(),
            ));
            push_opt(&mut query, "sni", str_of(tls, "server_name"));
            let fingerprint = tls
                .get("utls")
                .and_then(Value::as_object)
                .filter(|u| u.get("enabled").and_then(Value::as_bool) != Some(false))
                .and_then(|u| str_of(u, "fingerprint"));
            push_opt(&mut query, "fp", fingerprint);
            push_alpn(&mut query, tls.get("alpn"));
            if tls.get("insecure").and_then(Value::as_bool) == Some(true) {
                query.push(("allowInsecure", "1".into()));
            }
            if let Some(reality) = reality {
                push_opt(&mut query, "pbk", str_of(reality, "public_key"));
                push_opt(&mut query, "sid", str_of(reality, "short_id"));
            }
        }
        _ => query.push(("security", "none".into())),
    }
    Some(query)
}

// ------------------------------------------------------------------ links

fn vmess_link(
    host: &str,
    port: u64,
    id: &str,
    cipher: &str,
    query: &[(&'static str, String)],
    remark: &str,
) -> String {
    use base64::Engine as _;
    let get = |key: &str| {
        query
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    let security = get("security");
    let body = serde_json::json!({
        "v": "2",
        "ps": remark,
        "add": host,
        "port": port.to_string(),
        "id": id,
        "aid": "0",
        "scy": cipher,
        "net": get("type"),
        "type": "none",
        "host": get("host"),
        "path": if get("type") == "grpc" { get("serviceName") } else { get("path") },
        "tls": if security == "tls" { "tls" } else { "" },
        "sni": get("sni"),
        "alpn": get("alpn"),
        "fp": get("fp"),
    });
    format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(body.to_string())
    )
}

fn shadowsocks_link(method: &str, password: &str, host: &str, port: u64) -> String {
    use base64::Engine as _;
    let credential =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{method}:{password}"));
    format!("ss://{credential}@{}", endpoint(host, port))
}

fn endpoint(host: &str, port: u64) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn join(query: &[(&'static str, String)]) -> String {
    query
        .iter()
        .map(|(key, value)| format!("{key}={}", encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn push_opt(query: &mut Vec<(&'static str, String)>, key: &'static str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        query.push((key, value.to_string()));
    }
}

fn push_alpn(query: &mut Vec<(&'static str, String)>, alpn: Option<&Value>) {
    let joined = match alpn {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::String(text)) => text.clone(),
        _ => String::new(),
    };
    push_opt(query, "alpn", Some(&joined));
}

fn str_of<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn port_of(object: &Map<String, Value>) -> Option<u64> {
    let port = object.get("port")?;
    port.as_u64()
        .or_else(|| port.as_str()?.trim().parse().ok())
        .filter(|port| (1..=65_535).contains(port))
}

/// Percent-encode everything but RFC 3986's unreserved characters.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::parse_links;

    /// The shape a BPB panel serves for `sub/normal?app=xray`: an array of
    /// full Xray configs, each with its `remarks`, a VLESS/Trojan outbound
    /// over WebSocket and TLS through Cloudflare, and helper outbounds.
    const BPB_XRAY: &str = r#"[
      {
        "remarks": "💦 1 - VLESS - speed.cloudflare.com : 443",
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["8.8.8.8"]},
        "inbounds": [{"port": 10808, "protocol": "socks", "tag": "socks-in"}],
        "outbounds": [
          {
            "protocol": "vless",
            "settings": {"vnext": [{"address": "speed.cloudflare.com", "port": 443,
              "users": [{"id": "89b3cbba-e6ac-485a-9481-976a0415eab9", "encryption": "none"}]}]},
            "streamSettings": {
              "network": "ws",
              "security": "tls",
              "sockopt": {"dialerProxy": "fragment"},
              "tlsSettings": {"serverName": "example.workers.dev", "fingerprint": "randomized",
                "alpn": ["http/1.1"], "allowInsecure": false},
              "wsSettings": {"headers": {"Host": "example.workers.dev"}, "path": "/Qx7kd0?ed=2560"}
            },
            "tag": "proxy"
          },
          {"protocol": "freedom", "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "1-1"}}, "tag": "fragment"},
          {"protocol": "freedom", "tag": "direct"},
          {"protocol": "blackhole", "tag": "block"}
        ]
      },
      {
        "remarks": "💦 2 - Trojan - [2606:4700::] : 2053",
        "outbounds": [
          {
            "protocol": "trojan",
            "settings": {"servers": [{"address": "2606:4700::", "port": 2053, "password": "bpb-trojan"}]},
            "streamSettings": {"network": "ws", "security": "tls",
              "tlsSettings": {"serverName": "example.workers.dev", "fingerprint": "chrome"},
              "wsSettings": {"host": "example.workers.dev", "path": "/tr?ed=2560"}},
            "tag": "proxy"
          },
          {"protocol": "freedom", "tag": "direct"}
        ]
      }
    ]"#;

    #[test]
    fn a_sing_box_hysteria2_outbound_keeps_its_salamander_password() {
        let body = r#"{"outbounds": [
            {"type": "hysteria2", "tag": "hy", "server": "203.0.113.9", "server_port": 8443,
             "password": "secret pw", "up_mbps": 20,
             "obfs": {"type": "salamander", "password": "gawrgura"},
             "tls": {"enabled": true, "server_name": "a.example", "insecure": true}}
        ]}"#;
        let links = links_from_json(body).expect("recognised as JSON");
        assert_eq!(links.len(), 1);
        let parsed = zero_config::parse_link(&links[0]).expect("the link parses");
        let zero_config::OutboundProtocol::Hysteria2(config) = parsed.outbound.protocol else {
            panic!("expected Hysteria2");
        };
        assert_eq!(&*config.password, "secret pw");
        assert_eq!(config.obfs_password.as_deref(), Some("gawrgura"));
        let zero_config::Security::Tls(tls) = parsed.outbound.stream.security else {
            panic!("expected certificate TLS");
        };
        assert!(tls.allow_insecure);
        assert_eq!(tls.server_name.as_deref(), Some("a.example"));
    }

    #[test]
    fn a_serverless_config_becomes_one_direct_profile() {
        // BPB's "Serverless": all traffic goes out through a fragmenting
        // `freedom` outbound; the VLESS entry (older panels) is only there to
        // satisfy Xray. Two configs differing only in their DNS are one profile.
        let config = |remarks: &str| {
            format!(
                r#"{{"remarks": "{remarks}", "outbounds": [
                {{"tag": "proxy", "protocol": "freedom", "streamSettings": {{"finalmask": {{"tcp": [
                    {{"type": "fragment", "settings": {{"packets": "tlshello", "length": "100-200",
                      "delay": "1-1", "maxSplit": "0"}}}}]}}}}}},
                {{"tag": "http-fragment", "protocol": "freedom", "streamSettings": {{"finalmask": {{"tcp": [
                    {{"type": "fragment", "settings": {{"packets": "1-1", "length": "100-200", "delay": "1-1"}}}}]}}}}}},
                {{"tag": "fake-outbound", "protocol": "vless",
                  "settings": {{"vnext": [{{"address": "google.com", "port": 443,
                    "users": [{{"id": "8b876217-143b-4108-a7c6-abd1d0581fba", "encryption": "none"}}]}}]}},
                  "streamSettings": {{"network": "ws", "security": "tls",
                    "tlsSettings": {{"serverName": "google.com"}}}}}}
            ]}}"#
            )
        };
        let body = format!("[{}, {}]", config("Serverless 1"), config("Serverless 2"));
        let links = links_from_json(&body).expect("recognised as JSON");
        assert_eq!(links.len(), 1, "{links:?}");
        let parsed = zero_config::parse_link(&links[0]).expect("the link parses");
        let zero_config::OutboundProtocol::Freedom { .. } = parsed.outbound.protocol else {
            panic!("expected a direct outbound");
        };
        // The TLS fragmentation, not the HTTP one.
        let fragment = parsed
            .outbound
            .stream
            .evasion
            .tcp_fragment
            .expect("fragmented");
        assert_eq!(fragment.packets, zero_config::FragmentPackets::TlsHello);
        assert_eq!(parsed.remark, "Serverless 1");
    }

    #[test]
    fn a_pasted_reality_config_in_either_form_becomes_the_same_link() {
        let nested = r#"{"remarks": "r", "outbounds": [{"tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": "s.example", "port": 443, "users": [
                {"id": "11111111-1111-4111-8111-111111111111", "encryption": "none",
                 "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "serverName": "www.samsung.com", "fingerprint": "chrome",
                "publicKey": "JZoEjtfm1Zv3zGd2nGJmGCVZU8EbIn0Wg2EvrQ3VXTA",
                "shortId": "0123456789abcdef", "spiderX": "/"}}}]}"#;
        let flat = nested.replace(
            r#""vnext": [{"address": "s.example", "port": 443, "users": [
                {"id": "11111111-1111-4111-8111-111111111111", "encryption": "none",
                 "flow": "xtls-rprx-vision"}]}]"#,
            r#""address": "s.example", "port": 443, "id": "11111111-1111-4111-8111-111111111111",
                "encryption": "none", "flow": "xtls-rprx-vision""#,
        );
        assert_ne!(flat, nested, "the flat form was written");
        for text in [
            nested.to_string(),
            format!("\u{feff}{flat}"),
            format!("[{flat}]"),
        ] {
            let links = links_from_json(&text).expect("recognised as a config");
            assert_eq!(links.len(), 1, "{text}");
            let link = &links[0];
            assert!(
                link.starts_with("vless://11111111-1111-4111-8111-111111111111@s.example:443?"),
                "{link}"
            );
            for part in [
                "security=reality",
                "sni=www.samsung.com",
                "flow=xtls-rprx-vision",
                "pbk=JZoEjtfm1Zv3zGd2nGJmGCVZU8EbIn0Wg2EvrQ3VXTA",
                "sid=0123456789abcdef",
            ] {
                assert!(link.contains(part), "{part} missing from {link}");
            }
        }
    }

    #[test]
    fn the_simplified_outbound_form_and_vless_encryption_survive_the_import() {
        let outbound: Value = serde_json::json!({
            "protocol": "vless", "tag": "enc",
            "settings": {"address": "198.51.100.7", "port": 443,
                "id": "5783a3e7-e373-51cd-8642-c83782b807c5",
                "encryption": "mlkem768x25519plus.native.0rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "s", "multiMode": true}}
        });
        let (link, tag) = xray_outbound(outbound.as_object().unwrap()).expect("a link");
        assert_eq!(tag, "enc");
        assert!(link.starts_with("vless://5783a3e7-e373-51cd-8642-c83782b807c5@198.51.100.7:443?"));
        assert!(
            link.contains("encryption=mlkem768x25519plus.native.0rtt."),
            "{link}"
        );
        assert!(link.contains("mode=multi"), "{link}");
    }

    #[test]
    fn a_smart_fragment_config_keeps_each_servers_fragment_settings() {
        // BPB's "Smart Fragment": the same server once per fragment length.
        let outbound = |tag: &str, length: &str| {
            format!(
                r#"{{"tag": "{tag}", "protocol": "vless",
                "settings": {{"vnext": [{{"address": "188.114.96.3", "port": 443,
                  "users": [{{"id": "00000000-0000-0000-0000-000000000002", "encryption": "none"}}]}}]}},
                "streamSettings": {{"network": "ws", "security": "tls",
                  "tlsSettings": {{"serverName": "W.example.dev", "alpn": ["http/1.1"]}},
                  "wsSettings": {{"path": "/p?ed=2560"}},
                  "finalmask": {{"tcp": [{{"type": "fragment", "settings": {{"packets": "tlshello",
                    "length": "{length}", "delay": "1-1", "maxSplit": "0"}}}}]}}}}}}"#
            )
        };
        let body = format!(
            r#"{{"remarks": "Smart Fragment", "outbounds": [{}, {}, {}]}}"#,
            outbound("proxy-1", "1-5"),
            outbound("proxy-2", "10-20"),
            outbound("proxy-3", "100-200"),
        );
        let links = links_from_json(&body).expect("recognised as JSON");
        assert_eq!(links.len(), 3);
        let lengths: Vec<_> = links
            .iter()
            .map(|link| {
                let parsed = zero_config::parse_link(link).expect("the link parses");
                parsed
                    .outbound
                    .stream
                    .evasion
                    .tcp_fragment
                    .expect("fragmented")
                    .length
            })
            .collect();
        assert_eq!(
            lengths.iter().map(|l| (l.min, l.max)).collect::<Vec<_>>(),
            [(1, 5), (10, 20), (100, 200)]
        );
    }

    #[test]
    fn a_proxy_dialled_through_a_fragmenting_outbound_is_fragmented_too() {
        // The older BPB shape: `dialerProxy` names a direct outbound.
        let body = r#"{"outbounds": [
            {"tag": "proxy", "protocol": "vless",
             "settings": {"vnext": [{"address": "188.114.96.3", "port": 443,
               "users": [{"id": "00000000-0000-0000-0000-000000000002", "encryption": "none"}]}]},
             "streamSettings": {"network": "ws", "security": "tls", "sockopt": {"dialerProxy": "fragment"},
               "tlsSettings": {"serverName": "W.example.dev"}}},
            {"tag": "fragment", "protocol": "freedom",
             "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "1-1"}}}
        ]}"#;
        let links = links_from_json(body).expect("recognised as JSON");
        assert_eq!(links.len(), 1);
        let parsed = zero_config::parse_link(&links[0]).expect("the link parses");
        assert!(parsed.outbound.stream.evasion.tcp_fragment.is_some());
    }

    #[test]
    fn a_bpb_xray_subscription_becomes_links_the_parser_accepts() {
        let links = links_from_json(BPB_XRAY).expect("recognised as JSON");
        assert_eq!(links.len(), 2, "{links:?}");
        let report = parse_links(&links.join("\n"));
        assert_eq!(report.rejected, 0, "{:?}", report.reasons);
        assert_eq!(report.items.len(), 2);

        let vless = &report.items[0];
        assert_eq!(vless.protocol, "vless");
        assert_eq!(vless.transport, "ws");
        assert_eq!(vless.security, "tls");
        assert_eq!(vless.host, "speed.cloudflare.com");
        assert_eq!(vless.port, 443);
        assert_eq!(vless.name, "💦 1 - VLESS - speed.cloudflare.com : 443");
        assert!(
            vless.link.contains("path=%2FQx7kd0%3Fed%3D2560"),
            "{}",
            vless.link
        );
        assert!(vless.link.contains("host=example.workers.dev"));
        assert!(vless.link.contains("sni=example.workers.dev"));

        let trojan = &report.items[1];
        assert_eq!(trojan.protocol, "trojan");
        assert_eq!(trojan.port, 2053);
        assert!(
            trojan.link.contains("@[2606:4700::]:2053"),
            "{}",
            trojan.link
        );
    }

    #[test]
    fn a_single_config_with_several_proxies_numbers_them() {
        let body = r#"{"remarks": "Best ping", "outbounds": [
          {"protocol": "vless", "tag": "prox-1", "settings": {"vnext": [{"address": "1.1.1.1", "port": 443,
            "users": [{"id": "89b3cbba-e6ac-485a-9481-976a0415eab9"}]}]},
           "streamSettings": {"network": "grpc", "security": "reality",
             "grpcSettings": {"serviceName": "svc", "multiMode": true},
             "realitySettings": {"serverName": "www.speedtest.net", "fingerprint": "chrome",
               "publicKey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "shortId": "01ab"}}},
          {"protocol": "shadowsocks", "tag": "prox-2", "settings": {"servers": [{"address": "2.2.2.2",
            "port": 8388, "method": "aes-256-gcm", "password": "pw"}]}},
          {"protocol": "dns", "tag": "dns-out"}
        ]}"#;
        let links = links_from_json(body).unwrap();
        let report = parse_links(&links.join("\n"));
        assert_eq!(report.rejected, 0, "{:?}", report.reasons);
        let names: Vec<_> = report.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["Best ping 1", "Best ping 2"]);
        assert_eq!(report.items[0].security, "reality");
        assert_eq!(report.items[0].transport, "grpc");
        assert_eq!(report.items[1].protocol, "ss");
    }

    #[test]
    fn a_sing_box_config_is_read_too() {
        let body = r#"{"outbounds": [
          {"type": "vless", "tag": "BPB 1", "server": "zula.ir", "server_port": 443,
           "uuid": "89b3cbba-e6ac-485a-9481-976a0415eab9",
           "tls": {"enabled": true, "server_name": "example.workers.dev",
             "utls": {"enabled": true, "fingerprint": "chrome"}},
           "transport": {"type": "ws", "path": "/abc", "headers": {"Host": "example.workers.dev"}}},
          {"type": "trojan", "tag": "BPB 2", "server": "3.3.3.3", "server_port": 443, "password": "pw",
           "tls": {"enabled": true, "server_name": "t.example.com"}},
          {"type": "selector", "tag": "✅ Selector", "outbounds": ["BPB 1", "BPB 2"]},
          {"type": "direct", "tag": "direct"}
        ]}"#;
        let links = links_from_json(body).unwrap();
        let report = parse_links(&links.join("\n"));
        assert_eq!(report.rejected, 0, "{:?}", report.reasons);
        let names: Vec<_> = report.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["BPB 1", "BPB 2"]);
        assert_eq!(report.items[0].transport, "ws");
    }

    #[test]
    fn what_a_link_cannot_carry_is_left_out() {
        let body = r#"{"outbounds": [
          {"protocol": "vless", "settings": {"vnext": [{"address": "1.1.1.1", "port": 80,
            "users": [{"id": "89b3cbba-e6ac-485a-9481-976a0415eab9"}]}]},
           "streamSettings": {"network": "tcp", "tcpSettings": {"header": {"type": "http"}}}},
          {"protocol": "vless", "settings": {"vnext": [{"address": "1.1.1.1", "port": 80,
            "users": [{"id": "89b3cbba-e6ac-485a-9481-976a0415eab9"}]}]},
           "streamSettings": {"network": "h2"}}
        ]}"#;
        assert_eq!(links_from_json(body), Some(Vec::new()));
    }

    #[test]
    fn text_that_is_not_json_is_not_claimed() {
        assert_eq!(links_from_json("vless://x@y:1"), None);
        assert_eq!(links_from_json("{not json"), None);
        assert_eq!(links_from_json(r#"{"hello": 1}"#), None);
    }
}
