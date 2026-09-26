//! `vless://`, `trojan://`, and compatible proxy share links.
//!
//! This is how essentially every user imports a config, so the parser has to
//! be tolerant of the variations real panels emit while still refusing
//! anything ambiguous.

use std::collections::BTreeMap;
use std::sync::Arc;

use percent_encoding::percent_decode_str;
use zero_core::Address;

use crate::model::*;

/// One parsed share link.
#[derive(Debug, Clone)]
pub struct ShareLink {
    pub remark: String,
    pub outbound: Outbound,
    /// The link exactly as supplied, trimmed. Keeping it lets a caller emit
    /// configuration that references the original rather than a re-encoding,
    /// which is the only way to guarantee nothing was dropped in translation.
    pub link: String,
}

/// Decode a subscription body: either newline-separated links, or a single
/// base64 blob containing them.
pub fn parse_subscription(body: &str) -> Vec<Result<ShareLink, String>> {
    let text = match decode_base64_body(body) {
        Some(decoded) => decoded,
        None => body.to_string(),
    };

    // Feeds scraped from web pages join links with HTML line breaks.
    let text = text
        .replace("<br/>", "\n")
        .replace("<br />", "\n")
        .replace("<br>", "\n");
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(parse_link)
        .collect()
}

/// A subscription body is base64 when it decodes cleanly *and* the result
/// looks like links. Guessing on decode success alone misfires on plain text.
fn decode_base64_body(body: &str) -> Option<String> {
    let compact: String = body.split_whitespace().collect();
    if compact.is_empty() {
        return None;
    }
    let engines: [&dyn base64_dyn::Decode; 2] = [&base64_dyn::Standard, &base64_dyn::UrlSafe];
    for e in engines {
        if let Some(bytes) = e.decode(&compact) {
            if let Ok(s) = String::from_utf8(bytes) {
                if s.contains("://") {
                    return Some(s);
                }
            }
        }
    }
    None
}

mod base64_dyn {
    use base64::Engine as _;

    pub trait Decode {
        fn decode(&self, s: &str) -> Option<Vec<u8>>;
    }

    pub struct Standard;
    pub struct UrlSafe;

    impl Decode for Standard {
        fn decode(&self, s: &str) -> Option<Vec<u8>> {
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .ok()
                .or_else(|| {
                    base64::engine::general_purpose::STANDARD_NO_PAD
                        .decode(s)
                        .ok()
                })
        }
    }

    impl Decode for UrlSafe {
        fn decode(&self, s: &str) -> Option<Vec<u8>> {
            base64::engine::general_purpose::URL_SAFE
                .decode(s)
                .ok()
                .or_else(|| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(s)
                        .ok()
                })
        }
    }
}

pub fn parse_link(link: &str) -> Result<ShareLink, String> {
    let link = link.trim();
    // Links copied out of web pages and Telegram HTML exports carry their
    // query separators HTML-escaped. Nothing in a share link legitimately
    // contains a literal `&amp;`, so it is undone before parsing.
    let unescaped;
    let link = if link.contains("&amp;") {
        unescaped = link.replace("&amp;", "&");
        unescaped.as_str()
    } else {
        link
    };
    let mut parsed = parse_link_inner(link)?;
    parsed.link = link.to_owned();
    Ok(parsed)
}

fn parse_link_inner(link: &str) -> Result<ShareLink, String> {
    let (scheme, rest) = link
        .split_once("://")
        .ok_or_else(|| format!("share link has no scheme: {link:?}"))?;
    // Schemes are case-insensitive (RFC 3986 §3.1); some QR generators
    // upper-case the whole payload.
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => parse_vless(rest),
        "trojan" => parse_trojan(rest),
        "ss" => parse_shadowsocks(rest),
        "vmess" => parse_vmess(rest),
        "anytls" => parse_anytls(rest),
        // `hy2://` is the short form the Hysteria project itself documents.
        "hysteria2" | "hy2" => parse_hysteria2(rest),
        "tuic" => parse_tuic(rest),
        "wireguard" | "wg" => parse_wireguard(rest),
        _ => Err(format!("unsupported share link scheme {scheme:?}")),
    }
}

/// Split `credential@host:port?query#fragment`.
struct LinkParts<'a> {
    credential: String,
    host: &'a str,
    port: u16,
    query: BTreeMap<String, String>,
    remark: String,
}

fn split_link(rest: &str) -> Result<LinkParts<'_>, String> {
    let (body, fragment) = match rest.split_once('#') {
        Some((b, f)) => (b, f),
        None => (rest, ""),
    };
    let (authority, query_str) = match body.split_once('?') {
        Some((a, q)) => (a, q),
        None => (body, ""),
    };
    let (credential, host_port) = authority
        .rsplit_once('@')
        .ok_or_else(|| "share link is missing the '@' before the host".to_string())?;
    // Most panels emit `host:port/?query`; the path segment carries nothing
    // (transport paths travel in the query) and must not reach the port.
    let host_port = host_port
        .split_once('/')
        .map_or(host_port, |(authority, _)| authority);

    let (host, port) = zero_core::address::split_host_port(host_port)
        .ok_or_else(|| format!("cannot parse host:port from {host_port:?}"))?;

    Ok(LinkParts {
        credential: decode(credential),
        host,
        port,
        query: parse_query(query_str),
        remark: decode(fragment),
    })
}

fn parse_query(q: &str) -> BTreeMap<String, String> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(k).to_ascii_lowercase(), decode(v))
        })
        .collect()
}

fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn parse_vless(rest: &str) -> Result<ShareLink, String> {
    let p = split_link(rest)?;
    let uuid = parse_uuid(&p.credential)?;
    let q = &p.query;

    let flow = Flow::parse(q.get("flow").map(String::as_str).unwrap_or(""))
        .ok_or_else(|| format!("unknown flow {:?}", q.get("flow")))?;

    let stream = build_stream(q, p.host)?;

    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::Vless(VlessConfig {
            address: Address::parse_host(p.host),
            port: p.port,
            uuid,
            flow,
            encryption: q
                .get("encryption")
                .map(String::as_str)
                .unwrap_or("none")
                .into(),
        }),
        stream,
        mux: MuxConfig::default(),
    };
    outbound.validate()?;

    Ok(ShareLink {
        link: String::new(),
        remark: p.remark,
        outbound,
    })
}

fn parse_trojan(rest: &str) -> Result<ShareLink, String> {
    let p = split_link(rest)?;
    if p.credential.is_empty() {
        return Err("trojan link has an empty password".into());
    }
    let stream = build_stream(&p.query, p.host)?;

    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::Trojan(TrojanConfig {
            address: Address::parse_host(p.host),
            port: p.port,
            password_hash: crate::trojan_hash(&p.credential),
        }),
        stream,
        mux: MuxConfig::default(),
    };
    outbound.validate()?;

    Ok(ShareLink {
        link: String::new(),
        remark: p.remark,
        outbound,
    })
}

/// Decode a SIP002 userinfo segment into `method:password`.
///
/// Returns `None` when the segment is not base64, or decodes to something
/// that is not a credential pair — in both cases the caller should treat the
/// userinfo as literal text.
fn decode_ss_userinfo(userinfo: &str) -> Option<String> {
    // SIP002 allows the base64 padding to be percent-encoded (`%3D`).
    let userinfo = decode(userinfo);
    let bytes = decode_base64_any(&userinfo)?;
    let text = String::from_utf8(bytes).ok()?;

    // A credential pair, and the method half must be a method we know — that
    // is what stops an arbitrary base64-looking password from being mistaken
    // for an encoded pair.
    let (method, password) = text.split_once(':')?;
    if password.is_empty() || ShadowsocksMethod::parse(method).is_none() {
        return None;
    }
    Some(text)
}

fn parse_shadowsocks(rest: &str) -> Result<ShareLink, String> {
    let (encoded_body, fragment) = match rest.split_once('#') {
        Some((body, fragment)) => (body, fragment),
        None => (rest, ""),
    };
    // The `@` that ends the userinfo comes before the query: a query such
    // as `?note=@channel` must not be mistaken for it.
    let authority_end = encoded_body.find('?').unwrap_or(encoded_body.len());
    let userinfo_split = encoded_body[..authority_end]
        .rfind('@')
        .map(|at| (&encoded_body[..at], &encoded_body[at + 1..]));
    let decoded_body = if let Some((userinfo, host_part)) = userinfo_split {
        // SIP002: `ss://base64url(method:password)@host:port`, which is what
        // Shadowsocks-libev, sing-box, Clash and v2rayN all emit today. The
        // userinfo is base64 even though the rest of the link is plain, so a
        // link containing `@` still needs decoding — treating the whole body
        // as plaintext rejected every modern ss:// link with "credential must
        // be method:password".
        //
        // Some older panels write the userinfo in the clear instead, so a
        // decode that does not yield a `method:password` pair falls back to
        // the literal text rather than failing.
        let credential = decode_ss_userinfo(userinfo).unwrap_or_else(|| userinfo.to_string());
        format!("{credential}@{host_part}")
    } else {
        // Legacy `ss://base64(method:password@host:port)`, sometimes with a
        // `?plugin=` query or `/` after the payload.
        let (payload, tail) = match encoded_body.find(['/', '?']) {
            Some(at) => encoded_body.split_at(at),
            None => (encoded_body, ""),
        };
        let bytes = decode_base64_any(&decode(payload))
            .ok_or_else(|| "Shadowsocks link payload is not valid base64".to_string())?;
        let mut text = String::from_utf8(bytes)
            .map_err(|_| "Shadowsocks link payload is not UTF-8".to_string())?;
        text.push_str(tail);
        text
    };
    let normalized = format!("{decoded_body}#{fragment}");
    let mut p = split_link(&normalized)?;
    let (method, password) = p.credential.split_once(':').ok_or_else(|| {
        // The userinfo was base64 of a pair whose method is not one we
        // speak: say which, instead of claiming the link has no pair.
        decode_base64_any(&p.credential)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| {
                text.split_once(':')
                    .map(|(method, _)| format!("unsupported Shadowsocks method {method:?}"))
            })
            .unwrap_or_else(|| "Shadowsocks credential must be method:password".to_string())
    })?;
    let method = ShadowsocksMethod::parse(method)
        .ok_or_else(|| format!("unsupported Shadowsocks method {method:?}"))?;
    if password.is_empty() {
        return Err("Shadowsocks password must not be empty".into());
    }
    p.credential = password.to_string();
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::Shadowsocks(ShadowsocksConfig {
            address: Address::parse_host(p.host),
            port: p.port,
            method,
            password: p.credential.into(),
        }),
        stream: StreamSettings::default(),
        mux: MuxConfig::default(),
    };
    outbound.validate()?;
    Ok(ShareLink {
        link: String::new(),
        remark: p.remark,
        outbound,
    })
}

/// Decode base64 in any of the four alphabets/padding variants panels emit,
/// ignoring embedded whitespace (line-wrapped payloads).
fn decode_base64_any(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let compact: String = text.split_whitespace().collect();
    let text = compact.as_str();
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(text))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(text))
        .ok()
}

fn parse_vmess(rest: &str) -> Result<ShareLink, String> {
    let encoded = rest.split_once('#').map_or(rest, |(body, _)| body);
    let bytes = decode_base64_any(&decode(encoded))
        .ok_or_else(|| "VMess link payload is not valid base64".to_string())?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("VMess link payload is not JSON: {error}"))?;
    let text = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
    };
    let host = text("add");
    if host.is_empty() {
        return Err("VMess link is missing add".into());
    }
    // Checked, not `as u16`: a port of 70000 used to wrap silently to 4464.
    let port = value
        .get("port")
        .and_then(|port| port.as_u64().or_else(|| port.as_str()?.trim().parse().ok()))
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| "VMess link is missing a valid port".to_string())?;
    let uuid = parse_uuid(text("id"))?;
    // `aid` is ignored, as in Xray: it has no alterId at all any more and
    // always speaks AEAD, which every server of the last several years
    // accepts whatever alterId the link was published with.

    let net = text("net").to_ascii_lowercase();
    let transport_name = match net.as_str() {
        "" | "tcp" | "raw" => "raw",
        value => value,
    };
    // `type` is TCP's header obfuscation. On any other transport Xray does
    // not look at it, and panels fill it with "auto", "---" or the transport
    // name; only on TCP does "http" mean something.
    let header_type = text("type").to_ascii_lowercase();
    let http_camouflage = transport_name == "raw" && header_type == "http";
    // The same panel filler ("auto", "---") appears on TCP links too; it
    // means no header, as v2rayN reads it.
    if transport_name == "raw"
        && !matches!(header_type.as_str(), "" | "none" | "http" | "auto" | "---")
    {
        return Err(format!(
            "VMess link header type {header_type:?} is unsupported on TCP"
        ));
    }

    let mut query = BTreeMap::new();
    query.insert("type".to_string(), transport_name.to_string());
    query.insert(
        "security".to_string(),
        if text("tls") == "tls" { "tls" } else { "none" }.to_string(),
    );
    query.insert("scy".to_string(), text("scy").to_string());
    query.insert("fp".to_string(), text("fp").to_string());
    // On TCP the host is the camouflage header's, not a WebSocket's.
    if !text("host").is_empty() && !http_camouflage {
        query.insert("host".to_string(), text("host").to_string());
    }
    if !text("path").is_empty() {
        query.insert("path".to_string(), text("path").to_string());
    }
    if !text("sni").is_empty() {
        query.insert("sni".to_string(), text("sni").to_string());
    }
    if !text("alpn").is_empty() {
        query.insert("alpn".to_string(), text("alpn").to_string());
    }
    let mut stream = build_stream(&query, host)?;
    if http_camouflage {
        // The shape v2rayN writes into `tcpSettings.header`: the link's path
        // and host become the request line and Host header.
        let first = |value: &str| {
            value
                .split(',')
                .map(str::trim)
                .find(|item| !item.is_empty())
                .map(str::to_owned)
        };
        let mut headers = BTreeMap::new();
        if let Some(host_header) = first(text("host")) {
            headers.insert(Box::from("Host"), Box::from(host_header.as_str()));
        }
        stream.raw_http_header = Some(RawHttpHeader {
            request: RawHttpRequest {
                version: Box::from("1.1"),
                method: Box::from("GET"),
                path: Box::from(first(text("path")).unwrap_or_else(|| "/".into()).as_str()),
                headers,
            },
            response: None,
        });
    }
    let cipher = VmessCipher::parse(text("scy"))
        .ok_or_else(|| format!("VMess cipher {:?} is unsupported", text("scy")))?;
    let remark = text("ps").to_string();
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::Vmess(VmessConfig {
            address: Address::parse_host(host),
            port,
            uuid,
            cipher,
        }),
        stream,
        mux: MuxConfig::default(),
    };
    outbound.validate()?;
    Ok(ShareLink {
        remark,
        outbound,
        link: String::new(),
    })
}

fn parse_anytls(rest: &str) -> Result<ShareLink, String> {
    let p = split_link(rest)?;
    if p.credential.is_empty() {
        return Err("AnyTLS link has an empty password".into());
    }
    let stream = build_stream(&p.query, p.host)?;
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::AnyTls(AnyTlsConfig {
            address: Address::parse_host(p.host),
            port: p.port,
            password: p.credential.into(),
        }),
        stream,
        mux: MuxConfig::default(),
    };
    outbound.validate()?;
    Ok(ShareLink {
        link: String::new(),
        remark: p.remark,
        outbound,
    })
}

fn parse_hysteria2(rest: &str) -> Result<ShareLink, String> {
    let p = split_link(rest)?;
    if p.credential.is_empty() {
        return Err("Hysteria2 link has an empty password".into());
    }
    let mut stream = build_stream(&p.query, p.host)?;
    if matches!(stream.security, Security::None) {
        let fingerprint = Fingerprint::parse(p.query.get("fp").map(String::as_str).unwrap_or(""))
            .ok_or_else(|| "unknown Hysteria2 fingerprint".to_string())?;
        stream.security = Security::Tls(TlsConfig {
            server_name: Some(Arc::from(
                p.query.get("sni").map(String::as_str).unwrap_or(p.host),
            )),
            alpn: vec![Box::from("h3")],
            fingerprint,
            allow_insecure: false,
            ech: None,
            trusted_roots: Vec::new(),
        });
    }
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::Hysteria2(Hysteria2Config {
            address: Address::parse_host(p.host),
            port: p.port,
            password: p.credential.into(),
        }),
        stream,
        mux: MuxConfig::default(),
    };
    outbound.validate()?;
    Ok(ShareLink {
        link: String::new(),
        remark: p.remark,
        outbound,
    })
}

fn parse_tuic(rest: &str) -> Result<ShareLink, String> {
    let p = split_link(rest)?;
    let (uuid_text, password) = p
        .credential
        .split_once(':')
        .ok_or_else(|| "TUIC link credential must be uuid:password".to_string())?;
    let uuid = parse_uuid(uuid_text)?;
    if password.is_empty() {
        return Err("TUIC link has an empty password".into());
    }
    let mut stream = build_stream(&p.query, p.host)?;
    if matches!(stream.security, Security::None) {
        let fingerprint = Fingerprint::parse(p.query.get("fp").map(String::as_str).unwrap_or(""))
            .ok_or_else(|| "unknown TUIC fingerprint".to_string())?;
        stream.security = Security::Tls(TlsConfig {
            server_name: Some(Arc::from(
                p.query.get("sni").map(String::as_str).unwrap_or(p.host),
            )),
            alpn: vec![Box::from("h3")],
            fingerprint,
            allow_insecure: false,
            ech: None,
            trusted_roots: Vec::new(),
        });
    }
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::Tuic(TuicConfig {
            address: Address::parse_host(p.host),
            port: p.port,
            uuid,
            password: password.into(),
        }),
        stream,
        mux: MuxConfig::default(),
    };
    outbound.validate()?;
    Ok(ShareLink {
        link: String::new(),
        remark: p.remark,
        outbound,
    })
}

/// `wireguard://<private key>@host:port?publickey=…&address=…&reserved=a,b,c`
/// with optional `presharedkey`, `keepalive` and AmneziaWG `jc`/`jmin`/
/// `jmax`/`s1`…`s4`/`h1`…`h4` — the form v2rayN, NekoBox and Hiddify share.
fn parse_wireguard(rest: &str) -> Result<ShareLink, String> {
    let p = split_link(rest)?;
    let get = |k: &str| p.query.get(k).map(String::as_str).filter(|v| !v.is_empty());
    let mut settings = serde_json::json!({
        "secretKey": p.credential,
        "endpoint": if p.host.contains(':') { format!("[{}]:{}", p.host.trim_matches(|c| c == '[' || c == ']'), p.port) } else { format!("{}:{}", p.host, p.port) },
        "peers": [{"publicKey": get("publickey").or(get("peerpublickey")).unwrap_or("")}],
        "address": get("address").or(get("ip")).unwrap_or(""),
    });
    if let Some(psk) = get("presharedkey") {
        settings["peers"][0]["presharedKey"] = psk.into();
    }
    if let Some(keepalive) = get("keepalive").and_then(|v| v.parse::<u64>().ok()) {
        settings["keepAlive"] = keepalive.into();
    }
    if let Some(reserved) = get("reserved") {
        let bytes: Vec<u64> = reserved.split(',').filter_map(|b| b.trim().parse().ok()).collect();
        settings["reserved"] = if bytes.len() == 3 { bytes.into() } else { reserved.into() };
    }
    let mut amnezia = serde_json::Map::new();
    for key in ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"] {
        if let Some(value) = get(key) {
            amnezia.insert(key.into(), value.parse::<u64>().map(Into::into).unwrap_or_else(|_| value.into()));
        }
    }
    if !amnezia.is_empty() {
        settings["amnezia"] = amnezia.into();
    }
    let protocol = crate::xray_json::parse_amnezia_wireguard(Some(&settings), "wireguard link")?;
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol,
        stream: StreamSettings::default(),
        mux: MuxConfig::default(),
    };
    outbound.validate()?;
    Ok(ShareLink {
        link: String::new(),
        remark: p.remark,
        outbound,
    })
}

fn build_stream(q: &BTreeMap<String, String>, host: &str) -> Result<StreamSettings, String> {
    let get = |k: &str| q.get(k).map(String::as_str).unwrap_or("");
    // Xray lower-cases these names; panels emit `type=Tcp` or `fp=Chrome`.
    let network = get("type").to_ascii_lowercase();
    let security_name = get("security").to_ascii_lowercase();
    let fingerprint_name = get("fp").to_ascii_lowercase();

    let transport = match network.as_str() {
        "" | "tcp" | "raw" => Transport::Raw,
        "ws" => Transport::WebSocket(build_ws(q, host)),
        "httpupgrade" => Transport::HttpUpgrade(build_ws(q, host)),
        "grpc" => {
            // Query keys are lower-cased by `parse_query`, so the link's
            // `serviceName` arrives as `servicename`. The path is built the
            // way the Xray JSON parser builds it (`/<service>/Tun`); a bare
            // `/<service>` is rejected by every real gRPC server.
            let service = q.get("servicename").map(String::as_str).unwrap_or("");
            let mut config = build_ws(q, host);
            config.path = Arc::from(crate::xray_json::grpc_path(service));
            if let Some(authority) = q.get("authority").filter(|value| !value.is_empty()) {
                config.host = Some(Arc::from(authority.as_str()));
            }
            Transport::Grpc(config)
        }
        "xhttp" | "splithttp" => {
            let mut config = build_ws(q, host);
            config.xhttp_mode = XhttpMode::parse(get("mode"))
                .ok_or_else(|| format!("unsupported xhttp mode {:?}", get("mode")))?;
            // `extra` is the rest of Xray's `xhttpSettings` as JSON: padding
            // and placement settings, headers, and `downloadSettings`.
            if let Some(extra) = q.get("extra").filter(|extra| !extra.trim().is_empty()) {
                let extra = match serde_json::from_str::<serde_json::Value>(extra) {
                    Ok(serde_json::Value::Object(extra)) => extra,
                    _ => return Err("xhttp extra is not a JSON object".into()),
                };
                if let Some(headers) = extra.get("headers").and_then(|h| h.as_object()) {
                    for (name, value) in headers {
                        if let Some(value) = value.as_str() {
                            config.headers.insert(name.as_str().into(), value.into());
                        }
                    }
                }
                config.xhttp = crate::xhttp::parse_settings(&extra, config.xhttp_mode)?;
                if let Some(download) = extra.get("downloadSettings") {
                    config.xhttp_download = Some(Box::new(crate::xray_json::parse_xhttp_download(
                        download, "extra",
                    )?));
                }
            }
            Transport::Xhttp(config)
        }
        other => return Err(format!("unsupported transport type {other:?}")),
    };

    // Xray's rules (`tls.GetFingerprint`, `transport_security.go`): no
    // fingerprint means Chrome, for TLS and REALITY alike; `unsafe` means
    // the plain Go TLS stack, which REALITY refuses.
    let fingerprint = match fingerprint_name.as_str() {
        "" => Fingerprint::Chrome,
        "unsafe" => {
            if security_name == "reality" {
                return Err("REALITY cannot use fp=unsafe; it needs a browser fingerprint".into());
            }
            Fingerprint::Unshaped
        }
        name => Fingerprint::parse(name).ok_or_else(|| format!("unknown fingerprint {name:?}"))?,
    };

    let security = match security_name.as_str() {
        "" | "none" => Security::None,
        "tls" => {
            let sni = match get("sni") {
                "" => Some(Arc::from(host)),
                s => Some(Arc::from(s)),
            };
            Security::Tls(TlsConfig {
                server_name: sni,
                alpn: parse_alpn(get("alpn")),
                fingerprint,
                allow_insecure: matches!(get("allowinsecure"), "1" | "true"),
                ech: None,
                trusted_roots: Vec::new(),
            })
        }
        "reality" => {
            let pbk = get("pbk");
            if pbk.is_empty() {
                return Err("reality link is missing pbk".into());
            }
            Security::Reality(RealityConfig {
                server_name: Arc::from(match get("sni") {
                    "" => host,
                    s => s,
                }),
                public_key: parse_reality_key(pbk)?,
                short_id: parse_short_id(get("sid"))?,
                fingerprint,
                spider_x: match get("spx") {
                    "" => None,
                    s => Some(Arc::from(s)),
                },
                mldsa65_verify: None,
            })
        }
        other => return Err(format!("unsupported security {other:?}")),
    };

    let mut transport = transport;
    if let Transport::Xhttp(config) = &mut transport {
        // Same rule as the Xray JSON parser (Xray's `decideHTTPVersion`).
        let alpn: Vec<&str> = match &security {
            Security::Tls(tls) => tls.alpn.iter().map(|a| &**a).collect(),
            _ => Vec::new(),
        };
        config.xhttp_http_version = crate::xray_json::xray_http_version(security.name(), &alpn);
        if config.xhttp_mode == XhttpMode::Auto {
            config.xhttp_mode = if matches!(security, Security::Reality(_)) {
                if config.xhttp_download.is_some() {
                    XhttpMode::StreamUp
                } else {
                    XhttpMode::StreamOne
                }
            } else {
                XhttpMode::PacketUp
            };
        }
    }

    Ok(StreamSettings {
        transport,
        security,
        sockopt: Sockopt::default(),
        evasion: Evasion::default(),
        raw_http_header: None,
    })
}

fn build_ws(q: &BTreeMap<String, String>, host: &str) -> WebSocketConfig {
    let raw_path = q.get("path").map(String::as_str).unwrap_or("/");
    // Xray encodes the early-data budget in the path query as `ed=N`.
    let (path, early_data_len) = extract_early_data(raw_path);
    WebSocketConfig {
        path: Arc::from(path.as_str()),
        host: Some(Arc::from(q.get("host").map(String::as_str).unwrap_or(host))),
        headers: BTreeMap::new(),
        early_data_len,
        xhttp_mode: XhttpMode::StreamOne,
        xhttp_http_version: XhttpHttpVersion::Http1,
        xhttp_download: None,
        xhttp: Default::default(),
    }
}

/// Split `?ed=N` out of a WebSocket path, returning the path with the rest of
/// the query preserved.
pub fn extract_early_data(path: &str) -> (String, usize) {
    let Some((base, query)) = path.split_once('?') else {
        return (path.to_string(), 0);
    };
    let mut kept: Vec<&str> = Vec::new();
    let mut ed = 0usize;
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("ed=") {
            ed = v.parse().unwrap_or(0);
        } else if !pair.is_empty() {
            kept.push(pair);
        }
    }
    let rebuilt = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    (rebuilt, ed)
}

fn parse_alpn(s: &str) -> Vec<Box<str>> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(Box::from)
        .collect()
}

pub fn parse_uuid(s: &str) -> Result<[u8; 16], String> {
    let s = s.trim();
    let len = s.len();
    if (32..=36).contains(&len) {
        return uuid::Uuid::parse_str(s)
            .map(|u| *u.as_bytes())
            .map_err(|_| format!("invalid UUID {s:?}"));
    }
    // Xray's `uuid.ParseString`: any other text of 1-30 bytes names a user
    // too, as SHA-1 over sixteen zero bytes and the text, stamped as a
    // version-5 UUID. Panels hand out ids like "nasnet" on purpose, and the
    // server derives the same UUID from them.
    if len == 0 || len > 30 {
        return Err(format!("invalid UUID {s:?}"));
    }
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update([0u8; 16]);
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | (5 << 4);
    uuid[8] = (uuid[8] & (0xff >> 2)) | (0x02 << 6);
    Ok(uuid)
}

fn parse_reality_key(s: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    let s = s.trim();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .or_else(|_| hex::decode_fallback(s))
        .map_err(|_| format!("reality public key is not base64 or hex: {s:?}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "reality public key must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_short_id(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if !s.len().is_multiple_of(2) || s.len() > 16 {
        return Err(format!("reality shortId must be up to 16 hex chars: {s:?}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("bad hex in shortId {s:?}"))
        })
        .collect()
}

mod hex {
    #[derive(Debug)]
    pub struct Error;

    pub fn decode_fallback(s: &str) -> Result<Vec<u8>, Error> {
        if !s.len().is_multiple_of(2) {
            return Err(Error);
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| Error))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outbound(link: &str) -> Outbound {
        parse_link(link)
            .unwrap_or_else(|e| panic!("{link}: {e}"))
            .outbound
    }

    #[test]
    fn non_uuid_ids_map_to_the_uuid_xray_derives() {
        // Expected values from `xray uuid -i <text>` (Xray 26.7.28).
        let expect = |text: &str, uuid: &str| {
            assert_eq!(
                parse_uuid(text).unwrap(),
                *uuid::Uuid::parse_str(uuid).unwrap().as_bytes(),
                "{text}"
            );
        };
        expect("nasnet", "e8b1500b-e9e8-5492-8312-f4eadf7d0767");
        expect(
            "telegram-id-ArV2ray",
            "346dc791-6f67-5b8b-8453-ee705077378e",
        );
        // A real UUID still parses as itself, dashed or not.
        expect(
            "245abd35-7efa-4bc8-85d4-a04f3798329f",
            "245abd35-7efa-4bc8-85d4-a04f3798329f",
        );
        expect(
            "245abd357efa4bc885d4a04f3798329f",
            "245abd35-7efa-4bc8-85d4-a04f3798329f",
        );
        // Xray's limits: empty, 31 bytes and over 36 are errors.
        assert!(parse_uuid("").is_err());
        assert!(parse_uuid(&"a".repeat(31)).is_err());
        assert!(parse_uuid(&"a".repeat(37)).is_err());
    }

    #[test]
    fn fingerprints_follow_xray_defaults() {
        const REALITY: &str = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@1.2.3.4:443?security=reality&sni=a.com&pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY&sid=ab&type=tcp";
        let Security::Reality(r) = outbound(&format!("{REALITY}&fp=")).stream.security else {
            panic!()
        };
        assert_eq!(r.fingerprint, Fingerprint::Chrome, "empty fp is Chrome");
        assert!(parse_link(&format!("{REALITY}&fp=unsafe")).is_err());

        const TLS: &str = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@1.2.3.4:443?security=tls&sni=a.com&type=ws";
        let Security::Tls(t) = outbound(&format!("{TLS}&fp=unsafe")).stream.security else {
            panic!()
        };
        assert_eq!(t.fingerprint, Fingerprint::Unshaped, "unsafe is plain TLS");
        let Security::Tls(t) = outbound(TLS).stream.security else {
            panic!()
        };
        assert_eq!(t.fingerprint, Fingerprint::Chrome, "no fp is Chrome");
        let Security::Tls(t) = outbound(&format!("{TLS}&fp=Firefox")).stream.security else {
            panic!()
        };
        assert_eq!(
            t.fingerprint,
            Fingerprint::Firefox,
            "names are case-insensitive"
        );
    }

    #[test]
    fn transport_names_and_escaped_separators_are_tolerated() {
        let o = outbound("vless://245abd35-7efa-4bc8-85d4-a04f3798329f@1.2.3.4:443?security=TLS&amp;type=Ws&amp;path=%2Fx&amp;sni=a.com");
        assert!(matches!(o.stream.transport, Transport::WebSocket(_)));
        assert!(matches!(o.stream.security, Security::Tls(_)));
    }

    #[test]
    fn a_feed_joined_with_html_line_breaks_yields_every_link() {
        let feed = "trojan://p@1.2.3.4:443?security=tls&sni=a.com#A<br/>trojan://p@1.2.3.5:443?security=tls&sni=a.com#B<br>trojan://p@1.2.3.6:443?security=tls&sni=a.com#C";
        let links = parse_subscription(feed);
        assert_eq!(links.len(), 3);
        assert!(links.iter().all(Result::is_ok));
    }

    fn vmess(fields: serde_json::Value) -> Result<ShareLink, String> {
        use base64::Engine;
        let mut base = serde_json::json!({
            "v": "2", "ps": "t", "add": "1.2.3.4", "port": "443",
            "id": "245abd35-7efa-4bc8-85d4-a04f3798329f", "aid": "0",
            "scy": "auto", "net": "tcp", "type": "none", "host": "", "path": "", "tls": ""
        });
        for (k, v) in fields.as_object().unwrap() {
            base[k] = v.clone();
        }
        parse_link(&format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(base.to_string())
        ))
    }

    #[test]
    fn vmess_links_are_read_the_way_xray_reads_them() {
        // alterId is ignored: Xray always speaks AEAD.
        assert!(vmess(serde_json::json!({"aid": "64"})).is_ok());
        // `type` means nothing outside TCP.
        for junk in ["auto", "---", "gun", "none"] {
            let link = vmess(serde_json::json!({"net": "ws", "type": junk, "path": "/w"}));
            assert!(link.is_ok(), "ws with type={junk}: {:?}", link.err());
        }
        // On TCP, "http" is header camouflage with the link's path and host.
        let o =
            vmess(serde_json::json!({"type": "http", "path": "/cam,/other", "host": "h.example"}))
                .unwrap()
                .outbound;
        let header = o.stream.raw_http_header.expect("HTTP camouflage");
        assert_eq!(&*header.request.path, "/cam");
        assert_eq!(
            header.request.headers.get("Host").map(|v| &**v),
            Some("h.example")
        );
        // Panel filler means no header on TCP too; a real other header type
        // is still an error.
        assert!(vmess(serde_json::json!({"type": "auto"}))
            .unwrap()
            .outbound
            .stream
            .raw_http_header
            .is_none());
        assert!(vmess(serde_json::json!({"type": "srtp"})).is_err());
    }

    #[test]
    fn shadowsocks_2022_chacha_and_a_query_with_an_at_sign_parse() {
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let userinfo = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("2022-blake3-chacha20-poly1305:{key}"));
        let o = outbound(&format!("ss://{userinfo}@1.2.3.4:8388?note=@channel#name"));
        let OutboundProtocol::Shadowsocks(ss) = &o.protocol else {
            panic!()
        };
        assert_eq!(ss.method, ShadowsocksMethod::Blake3Chacha20Poly1305);
        assert_eq!(o.endpoint().map(|(_, port)| port), Some(8388));

        // An unknown method is named, not reported as a missing pair.
        let unknown = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("rc4-md5:secret");
        let error = parse_link(&format!("ss://{unknown}@1.2.3.4:8388")).unwrap_err();
        assert!(error.contains("rc4-md5"), "{error}");
    }

    const VLESS_REALITY: &str = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@1.2.3.4:443\
?encryption=none&flow=xtls-rprx-vision&security=reality\
&sni=www.googletagmanager.com&fp=chrome\
&pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY&sid=7963d08380d47375\
&type=tcp&headerType=none#Test";

    const VLESS_WS: &str = "vless://2ff1826e-405c-40dc-8b36-9c4e14ad0d55@example.workers.dev:443\
?encryption=none&host=example.workers.dev&type=ws&security=tls\
&path=%2Fvl%2Fabc%3Fed%3D2560&sni=ExAmPle.WorKERS.dev&fp=chrome&alpn=http%2F1.1#WS";

    #[test]
    fn parses_reality_vision_link() {
        let l = parse_link(VLESS_REALITY).expect("should parse");
        assert_eq!(l.remark, "Test");
        let OutboundProtocol::Vless(v) = &l.outbound.protocol else {
            panic!("expected vless");
        };
        assert_eq!(v.flow, Flow::Vision);
        assert_eq!(v.port, 443);
        let Security::Reality(r) = &l.outbound.stream.security else {
            panic!("expected reality");
        };
        assert_eq!(&*r.server_name, "www.googletagmanager.com");
        assert_eq!(
            r.short_id,
            vec![0x79, 0x63, 0xd0, 0x83, 0x80, 0xd4, 0x73, 0x75]
        );
        assert_eq!(r.fingerprint, Fingerprint::Chrome);
        assert_eq!(l.outbound.stream.transport, Transport::Raw);
    }

    #[test]
    fn parses_websocket_link_with_early_data() {
        let l = parse_link(VLESS_WS).expect("should parse");
        let Transport::WebSocket(ws) = &l.outbound.stream.transport else {
            panic!("expected ws");
        };
        assert_eq!(&*ws.path, "/vl/abc");
        assert_eq!(ws.early_data_len, 2560);
        assert_eq!(ws.host.as_deref(), Some("example.workers.dev"));
        let Security::Tls(t) = &l.outbound.stream.security else {
            panic!("expected tls");
        };
        // SNI casing is preserved verbatim: panels randomise it deliberately.
        assert_eq!(t.server_name.as_deref(), Some("ExAmPle.WorKERS.dev"));
        assert_eq!(t.alpn, vec![Box::<str>::from("http/1.1")]);
    }

    #[test]
    fn parses_raw_and_base64_shadowsocks_links() {
        let raw = parse_link("ss://aes-256-gcm:secret@example.com:8388#raw").unwrap();
        assert_eq!(raw.remark, "raw");
        assert!(matches!(
            raw.outbound.protocol,
            OutboundProtocol::Shadowsocks(ShadowsocksConfig {
                method: ShadowsocksMethod::Aes256Gcm,
                ..
            })
        ));

        use base64::Engine;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("chacha20-ietf-poly1305:secret@example.com:8388");
        let encoded = parse_link(&format!("ss://{payload}#encoded")).unwrap();
        assert_eq!(encoded.remark, "encoded");
        assert!(matches!(
            encoded.outbound.protocol,
            OutboundProtocol::Shadowsocks(ShadowsocksConfig {
                method: ShadowsocksMethod::Chacha20Poly1305,
                ..
            })
        ));
    }

    #[test]
    fn parses_legacy_vmess_json_link_into_aead_model() {
        use base64::Engine;
        let json = serde_json::json!({
            "v": "2",
            "ps": "vmess-test",
            "add": "proxy.example",
            "port": "443",
            "id": "00000000-0000-0000-0000-000000000001",
            "aid": "0",
            "scy": "aes-128-gcm",
            "net": "ws",
            "type": "none",
            "host": "cdn.example",
            "path": "/vmess",
            "tls": "tls",
            "sni": "cdn.example",
            "fp": "chrome"
        });
        let payload = base64::engine::general_purpose::STANDARD_NO_PAD.encode(json.to_string());
        let link = parse_link(&format!("vmess://{payload}")).unwrap();
        assert_eq!(link.remark, "vmess-test");
        assert!(matches!(
            link.outbound.protocol,
            OutboundProtocol::Vmess(VmessConfig {
                cipher: VmessCipher::Aes128Gcm,
                ..
            })
        ));
        assert!(matches!(
            link.outbound.stream.transport,
            Transport::WebSocket(_)
        ));
    }

    #[test]
    fn rejects_vision_over_websocket() {
        let bad = VLESS_WS.replace("?encryption=none", "?encryption=none&flow=xtls-rprx-vision");
        let err = parse_link(&bad).unwrap_err();
        assert!(
            err.contains("raw TCP only") && err.contains("VLESS Encryption"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn rejects_reality_over_websocket() {
        let bad = VLESS_WS.replace(
            "security=tls",
            "security=reality&pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY",
        );
        let err = parse_link(&bad).unwrap_err();
        assert!(err.contains("REALITY"), "unexpected: {err}");
    }

    #[test]
    fn accepts_firefox_reality_fingerprint() {
        let link = VLESS_REALITY.replace("&fp=chrome", "&fp=firefox");
        let parsed = parse_link(&link).unwrap();
        assert!(matches!(
            parsed.outbound.stream.security,
            Security::Reality(RealityConfig {
                fingerprint: Fingerprint::Firefox,
                ..
            })
        ));
    }

    #[test]
    fn rejects_allow_insecure() {
        let bad = VLESS_WS.replace("&alpn=http%2F1.1", "&alpn=http%2F1.1&allowInsecure=1");
        assert!(parse_link(&bad).unwrap_err().contains("allowInsecure"));
    }

    #[test]
    fn early_data_extraction_keeps_other_query_params() {
        assert_eq!(
            extract_early_data("/p?a=1&ed=2560&b=2"),
            ("/p?a=1&b=2".to_string(), 2560)
        );
        assert_eq!(extract_early_data("/p"), ("/p".to_string(), 0));
    }

    #[test]
    fn parses_base64_subscription() {
        use base64::Engine;
        let body = base64::engine::general_purpose::STANDARD
            .encode(format!("{VLESS_REALITY}\n{VLESS_WS}"));
        let out = parse_subscription(&body);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(Result::is_ok));
    }

    #[test]
    fn parses_plain_subscription() {
        let out = parse_subscription(&format!("{VLESS_REALITY}\n{VLESS_WS}"));
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn rejects_bad_uuid() {
        // Short text is a valid id to Xray (hashed into a UUID); what it
        // rejects is UUID-length text that is not hex, and anything longer.
        for bad_id in ["zz5abd35-7efa-4bc8-85d4-a04f3798329f", &"x".repeat(40)] {
            let bad = VLESS_REALITY.replace("245abd35-7efa-4bc8-85d4-a04f3798329f", bad_id);
            assert!(parse_link(&bad).unwrap_err().contains("UUID"), "{bad_id}");
        }
    }

    #[test]
    fn parses_anytls_link_over_certificate_tls() {
        let link = parse_link(
            "anytls://correct-horse@example.com:443?security=tls&sni=cdn.example&fp=chrome#AnyTLS",
        )
        .unwrap();
        assert_eq!(link.remark, "AnyTLS");
        assert!(matches!(
            link.outbound.protocol,
            OutboundProtocol::AnyTls(_)
        ));
        assert!(matches!(link.outbound.stream.security, Security::Tls(_)));
    }

    #[test]
    fn parses_hysteria2_link_with_tls_default() {
        let link = parse_link("hysteria2://secret@example.com:443?sni=cdn.example#H2").unwrap();
        assert_eq!(link.remark, "H2");
        assert!(matches!(
            link.outbound.protocol,
            OutboundProtocol::Hysteria2(_)
        ));
        let Security::Tls(tls) = &link.outbound.stream.security else {
            panic!("expected certificate TLS");
        };
        assert_eq!(tls.server_name.as_deref(), Some("cdn.example"));
    }

    #[test]
    fn parses_tuic_link_with_uuid_password_and_h3() {
        let link = parse_link(
            "tuic://00000000-0000-0000-0000-000000000001:secret@example.com:443?sni=cdn.example#TUIC",
        )
        .unwrap();
        assert_eq!(link.remark, "TUIC");
        assert!(matches!(link.outbound.protocol, OutboundProtocol::Tuic(_)));
        let Security::Tls(tls) = &link.outbound.stream.security else {
            panic!("expected certificate TLS");
        };
        assert_eq!(tls.server_name.as_deref(), Some("cdn.example"));
        assert_eq!(tls.alpn, vec![Box::<str>::from("h3")]);
    }

    #[test]
    fn shadowsocks_sip002_userinfo_is_base64_decoded() {
        // `ss://base64url(method:password)@host:port` — the format
        // Shadowsocks-libev, sing-box, Clash and v2rayN all emit. It contains
        // an `@`, which used to make the parser skip decoding entirely and
        // reject the link.
        use base64::Engine;
        let userinfo =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:secret");
        let link = parse_link(&format!("ss://{userinfo}@1.2.3.4:8388#SIP002")).unwrap();
        assert_eq!(link.remark, "SIP002");
        let OutboundProtocol::Shadowsocks(ss) = &link.outbound.protocol else {
            panic!("expected shadowsocks, got {:?}", link.outbound.protocol);
        };
        assert_eq!(ss.port, 8388);
        assert_eq!(&*ss.password, "secret");
    }

    #[test]
    fn shadowsocks_sip002_accepts_standard_and_padded_base64() {
        use base64::Engine;
        for encoded in [
            base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:secret"),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode("aes-256-gcm:secret"),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:secret"),
        ] {
            let link = parse_link(&format!("ss://{encoded}@1.2.3.4:8388#n"))
                .unwrap_or_else(|e| panic!("{encoded} rejected: {e}"));
            let OutboundProtocol::Shadowsocks(ss) = &link.outbound.protocol else {
                panic!("expected shadowsocks");
            };
            assert_eq!(&*ss.password, "secret");
        }
    }

    const UUID: &str = "245abd35-7efa-4bc8-85d4-a04f3798329f";

    #[test]
    fn grpc_links_keep_their_service_name_as_an_xray_grpc_path() {
        let link = parse_link(&format!(
            "vless://{UUID}@example.com:443?type=grpc&serviceName=my-svc&security=tls&sni=example.com#g"
        ))
        .unwrap();
        let Transport::Grpc(grpc) = &link.outbound.stream.transport else {
            panic!("expected grpc");
        };
        assert_eq!(&*grpc.path, "/my-svc/Tun");
    }

    #[test]
    fn a_path_slash_after_the_port_is_accepted() {
        let link = parse_link(&format!(
            "vless://{UUID}@example.com:8443/?type=ws&path=%2Fws&security=tls#slash"
        ))
        .unwrap();
        let OutboundProtocol::Vless(vless) = &link.outbound.protocol else {
            panic!("expected vless");
        };
        assert_eq!(vless.port, 8443);
        assert_eq!(link.remark, "slash");
        let ipv6 = parse_link(&format!("vless://{UUID}@[2001:db8::1]:443/?type=tcp")).unwrap();
        let OutboundProtocol::Vless(vless) = &ipv6.outbound.protocol else {
            panic!("expected vless");
        };
        assert_eq!(vless.address, Address::parse_host("2001:db8::1"));
    }

    #[test]
    fn shadowsocks_percent_encoded_base64_padding_is_decoded() {
        // base64("aes-128-gcm:test") = "YWVzLTEyOC1nY206dGVzdA==".
        let link = parse_link("ss://YWVzLTEyOC1nY206dGVzdA%3D%3D@1.2.3.4:8388#p").unwrap();
        let OutboundProtocol::Shadowsocks(ss) = &link.outbound.protocol else {
            panic!("expected shadowsocks");
        };
        assert_eq!(&*ss.password, "test");
    }

    #[test]
    fn legacy_shadowsocks_payload_tolerates_a_trailing_query() {
        use base64::Engine;
        let payload =
            base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:secret@1.2.3.4:8388");
        let link = parse_link(&format!("ss://{payload}/?plugin=none#legacy")).unwrap();
        assert_eq!(link.remark, "legacy");
        let OutboundProtocol::Shadowsocks(ss) = &link.outbound.protocol else {
            panic!("expected shadowsocks");
        };
        assert_eq!(ss.port, 8388);
    }

    #[test]
    fn vmess_ports_out_of_range_are_rejected_not_wrapped() {
        use base64::Engine;
        for port in [
            serde_json::json!(70000),
            serde_json::json!("0"),
            serde_json::json!(-1),
        ] {
            let json = serde_json::json!({
                "add": "proxy.example", "port": port,
                "id": "00000000-0000-0000-0000-000000000001", "aid": 0,
                "scy": "aes-128-gcm", "net": "tcp"
            });
            let payload = base64::engine::general_purpose::URL_SAFE.encode(json.to_string());
            let error = parse_link(&format!("vmess://{payload}")).unwrap_err();
            assert!(error.contains("port"), "{port}: {error}");
        }
    }

    #[test]
    fn hy2_scheme_alias_and_uppercase_schemes_parse() {
        let link = parse_link("hy2://secret@example.com:443/?sni=example.com#h").unwrap();
        assert!(matches!(
            link.outbound.protocol,
            OutboundProtocol::Hysteria2(_)
        ));
        let upper = parse_link(&format!("VLESS://{UUID}@example.com:443?type=tcp")).unwrap();
        assert!(matches!(
            upper.outbound.protocol,
            OutboundProtocol::Vless(_)
        ));
    }

    #[test]
    fn xhttp_links_honour_mode_and_resolve_auto_like_the_json_parser() {
        let packet = parse_link(&format!(
            "vless://{UUID}@example.com:443?type=xhttp&path=%2Fx&security=tls&sni=example.com"
        ))
        .unwrap();
        let Transport::Xhttp(x) = &packet.outbound.stream.transport else {
            panic!("expected xhttp");
        };
        assert_eq!(x.xhttp_mode, XhttpMode::PacketUp);
        // Xray's decideHTTPVersion: TLS without a single-entry ALPN is h2.
        assert_eq!(x.xhttp_http_version, XhttpHttpVersion::Http2);
        let h1 = parse_link(&format!(
            "vless://{UUID}@example.com:443?type=xhttp&security=tls&alpn=http%2F1.1"
        ))
        .unwrap();
        let Transport::Xhttp(x) = &h1.outbound.stream.transport else {
            panic!("expected xhttp");
        };
        assert_eq!(x.xhttp_http_version, XhttpHttpVersion::Http1);

        let explicit = parse_link(&format!(
            "vless://{UUID}@example.com:443?type=xhttp&mode=stream-up&security=tls&alpn=h2"
        ))
        .unwrap();
        let Transport::Xhttp(x) = &explicit.outbound.stream.transport else {
            panic!("expected xhttp");
        };
        assert_eq!(x.xhttp_mode, XhttpMode::StreamUp);
        assert_eq!(x.xhttp_http_version, XhttpHttpVersion::Http2);

        assert!(parse_link(&format!(
            "vless://{UUID}@example.com:443?type=xhttp&mode=bogus"
        ))
        .is_err());
    }

    #[test]
    fn xhttp_extra_carries_padding_placement_and_headers() {
        let extra = r#"{"mode":"auto","xPaddingBytes":"1-1","xPaddingObfsMode":true,"xPaddingKey":"ctx","xPaddingHeader":"x-grpc-context","xPaddingMethod":"tokenish","sessionIDPlacement":"header","sessionIDKey":"Idempotency-Key","seqPlacement":"header","seqKey":"Upload-Offset","headers":{"X-Test":"1"}}"#;
        let encoded: String =
            percent_encoding::utf8_percent_encode(extra, percent_encoding::NON_ALPHANUMERIC)
                .collect();
        let link = parse_link(&format!(
            "vless://{UUID}@example.com:443?type=xhttp&path=%2Fx&security=tls&extra={encoded}"
        ))
        .unwrap();
        let Transport::Xhttp(x) = &link.outbound.stream.transport else {
            panic!("expected xhttp");
        };
        assert!(x.xhttp.x_padding_obfs_mode);
        assert_eq!(x.xhttp.x_padding_bytes, (1, 1));
        assert_eq!(&*x.xhttp.session_key, "Idempotency-Key");
        assert_eq!(&*x.xhttp.seq_placement, "header");
        assert_eq!(x.headers.get("X-Test").map(|v| &**v), Some("1"));

        let bad = format!(
            "vless://{UUID}@example.com:443?type=xhttp&security=tls&extra=%7B%22xPaddingPlacement%22%3A%22nowhere%22%7D"
        );
        assert!(parse_link(&bad).is_err());
    }

    #[test]
    fn malformed_links_are_errors_not_panics() {
        for link in [
            "",
            "vless://",
            "vless://@",
            "vless://x@:",
            "vless://x@[::1",
            "vless://x@host:99999",
            "ss://%%%",
            "ss://@",
            "vmess://",
            "vmess://!!!!",
            "trojan://@h:1",
            "tuic://a@h:1",
            "hysteria2://@h:1",
            "\u{0}://",
            "vless://€@€:€?€=€#€",
        ] {
            assert!(parse_link(link).is_err(), "{link:?} should be rejected");
        }
    }

    #[test]
    fn shadowsocks_plaintext_userinfo_still_works() {
        // Older panels write the credential in the clear; that must keep
        // parsing now that the base64 path exists.
        let link = parse_link("ss://aes-256-gcm:secret@1.2.3.4:8388#plain").unwrap();
        let OutboundProtocol::Shadowsocks(ss) = &link.outbound.protocol else {
            panic!("expected shadowsocks");
        };
        assert_eq!(&*ss.password, "secret");
        assert_eq!(link.remark, "plain");
    }

    #[test]
    fn shadowsocks_password_that_looks_like_base64_is_not_misread() {
        // A plaintext password can be valid base64 by accident. It must only
        // be treated as an encoded pair when it decodes to a *known method*
        // plus a password.
        let link = parse_link("ss://aes-256-gcm:YWJjZGVm@1.2.3.4:8388#n").unwrap();
        let OutboundProtocol::Shadowsocks(ss) = &link.outbound.protocol else {
            panic!("expected shadowsocks");
        };
        assert_eq!(&*ss.password, "YWJjZGVm");
    }

    #[test]
    fn shadowsocks_legacy_whole_body_base64_still_works() {
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode("aes-256-gcm:secret@1.2.3.4:8388");
        let link = parse_link(&format!("ss://{payload}#legacy")).unwrap();
        let OutboundProtocol::Shadowsocks(ss) = &link.outbound.protocol else {
            panic!("expected shadowsocks");
        };
        assert_eq!(ss.port, 8388);
        assert_eq!(link.remark, "legacy");
    }
}
