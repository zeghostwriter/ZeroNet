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
        // `socks5h` is curl's spelling for "let the proxy resolve names",
        // which is the only way this outbound works.
        "socks" | "socks5" | "socks5h" => parse_socks(rest),
        "masterdns" => parse_masterdns(rest),
        // `tor://#name`: Tor with its defaults. Bridges do not fit a link
        // sensibly (they carry spaces and certificates), so they live in JSON.
        "tor" => {
            let remark = rest.split_once('#').map_or("", |(_, name)| name);
            let outbound = Outbound {
                tag: Arc::from("proxy"),
                protocol: OutboundProtocol::Tor(TorConfig::default()),
                stream: StreamSettings::default(),
                mux: MuxConfig::default(),
            };
            outbound.validate()?;
            Ok(ShareLink {
                link: String::new(),
                remark: decode(remark),
                outbound,
            })
        }
        "zerov1" | "tide" => parse_tide(rest),
        // `hy2://` is the short form the Hysteria project itself documents.
        "hysteria2" | "hy2" => parse_hysteria2(rest),
        "tuic" => parse_tuic(rest),
        "juicity" => parse_juicity(rest),
        "wireguard" | "wg" => parse_wireguard(rest),
        "warp" => parse_warp_link(rest),
        "direct" => parse_direct(rest),
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
            vision_seed: None,
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

/// `socks5://[user:password@]host:port#name`, for a local Tor, Orbot or
/// Psiphon client or any SOCKS5 server. v2rayN's `socks://<base64 user:pass>@…`
/// form is read too. No credential is the normal case for a local client.
fn parse_socks(rest: &str) -> Result<ShareLink, String> {
    use base64::Engine as _;
    let (body, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let authority = body.split(['?', '/']).next().unwrap_or("");
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let (host, port) = zero_core::address::split_host_port(host_port)
        .ok_or_else(|| format!("cannot parse host:port from {host_port:?}"))?;
    let auth = match userinfo.filter(|u| !u.is_empty()) {
        None => None,
        Some(u) => {
            // Split before decoding so a `%3A` in the password stays inside it.
            let (user, pass) = match u.split_once(':') {
                Some((user, pass)) => (decode(user), decode(pass)),
                None => {
                    let raw = decode(u);
                    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
                        .decode(raw.trim_end_matches('='))
                        .or_else(|_| {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(raw.trim_end_matches('='))
                        })
                        .map_err(|_| "SOCKS5 link credential must be user:password".to_string())?;
                    let text = String::from_utf8(bytes)
                        .map_err(|_| "SOCKS5 link credential is not text".to_string())?;
                    let (user, pass) = text.split_once(':').ok_or_else(|| {
                        "SOCKS5 link credential must be user:password".to_string()
                    })?;
                    (user.to_string(), pass.to_string())
                }
            };
            Some(SocksCredential {
                username: user.into(),
                password: pass.into(),
            })
        }
    };
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::Socks(SocksConfig {
            address: Address::parse_host(host),
            port,
            auth,
            http: false,
        }),
        stream: StreamSettings::default(),
        mux: MuxConfig::default(),
    };
    outbound.validate()?;
    Ok(ShareLink {
        link: String::new(),
        remark: decode(fragment),
        outbound,
    })
}

/// Resolvers given as `ip` or `ip:port` (`[v6]:port`), 53 when no port is named.
fn parse_resolver(text: &str) -> Option<std::net::SocketAddr> {
    let text = text.trim();
    text.parse::<std::net::SocketAddr>().ok().or_else(|| {
        text.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| std::net::SocketAddr::new(ip, 53))
    })
}

/// `masterdns://<key>@t.example.com?resolvers=8.8.8.8,1.1.1.1:53&server=203.0.113.7#name`
///
/// MasterDnsVPN has no link format of its own; this one is Zray's. The key and
/// domain are required. `resolvers` are the DNS servers the queries go through
/// (IP addresses, port 53 unless named), `server` adds the server's own address
/// as a direct resolver (it answers on UDP 53), `method` is the encryption id
/// (5, AES-256-GCM, when absent) and `mode` is `socks5` (default) or `tcp`.
fn parse_masterdns(rest: &str) -> Result<ShareLink, String> {
    let (body, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (authority, query_str) = body.split_once('?').unwrap_or((body, ""));
    let (key, domain) = authority
        .rsplit_once('@')
        .ok_or_else(|| "MasterDNS link is missing the key before the '@'".to_string())?;
    let domain = domain.trim_end_matches('/').to_ascii_lowercase();
    let query = parse_query(query_str);
    let mut resolvers = Vec::new();
    if let Some(server) = query.get("server").filter(|s| !s.is_empty()) {
        resolvers.push(
            parse_resolver(server)
                .ok_or_else(|| format!("MasterDNS server {server:?} is not an IP address"))?,
        );
    }
    for item in query
        .get("resolvers")
        .map(String::as_str)
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.trim().is_empty())
    {
        let resolver = parse_resolver(item)
            .ok_or_else(|| format!("MasterDNS resolver {item:?} is not an IP address"))?;
        if !resolvers.contains(&resolver) {
            resolvers.push(resolver);
        }
    }
    let method = match query.get("method") {
        None => 5,
        Some(m) => m
            .parse()
            .map_err(|_| format!("MasterDNS method {m:?} is not a number"))?,
    };
    let mode = match query.get("mode").map(|m| m.to_ascii_lowercase()).as_deref() {
        None | Some("socks5") | Some("socks") => MasterDnsMode::Socks5,
        Some("tcp") => MasterDnsMode::Tcp,
        Some(other) => return Err(format!("MasterDNS mode {other:?} is not socks5 or tcp")),
    };
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::MasterDns(MasterDnsConfig {
            domain: domain.into(),
            key: decode(key).into(),
            method,
            resolvers,
            mode,
        }),
        stream: StreamSettings::default(),
        mux: MuxConfig::default(),
    };
    outbound.validate()?;
    Ok(ShareLink {
        link: String::new(),
        remark: decode(fragment),
        outbound,
    })
}

/// `zerov1://<user>@host:port?key=<server key>&path=/prefix&...#name`
/// (`tide://` is read too; it is the name the protocol was built under).
///
/// The user id and server key are unpadded URL-safe base64. Tide always
/// runs over HTTP/2 in TLS, so a link that says nothing about security gets
/// TLS for its host with `h2`, which is what every Tide server speaks.
fn parse_tide(rest: &str) -> Result<ShareLink, String> {
    use base64::Engine as _;
    let p = split_link(rest)?;
    let decode = |text: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text.trim())
            .ok()
    };
    let user: [u8; 16] = decode(&p.credential)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "Tide link has no valid user id".to_string())?;
    let server_key: [u8; 32] = p
        .query
        .get("key")
        .and_then(|key| decode(key))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "Tide link has no valid server key".to_string())?;
    let path = p.query.get("path").map(String::as_str).unwrap_or("");
    let plain = path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'));
    if path.len() < 2 || !path.starts_with('/') || path.ends_with('/') || !plain {
        return Err("Tide link has no valid path".into());
    }
    let mut query = p.query.clone();
    query
        .entry("security".into())
        .or_insert_with(|| "tls".into());
    query.insert("alpn".into(), "h2".into());
    // The path is Tide's own; the stream below is plain TLS over TCP.
    query.remove("path");
    query.remove("type");
    let tuning = TideTuning::parse(&|key| query.get(key).cloned())?;
    let stream = build_stream(&query, p.host)?;
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::Tide(TideConfig {
            address: Address::parse_host(p.host),
            port: p.port,
            path: path.into(),
            server_key,
            user,
            split: query.get("split").map(String::as_str) != Some("0"),
            packet_upload: query.get("upload").map(String::as_str) == Some("packet"),
            datagrams: query.get("dg").map(String::as_str) == Some("1"),
            rotate: query.get("rotate").map(String::as_str) != Some("0"),
            tuning,
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

/// `direct://?hide=auto#name` or `direct://?fm=<finalmask JSON>#name`: no
/// server. Connections leave this device directly, with the server name in
/// the TLS hello kept from the filter (`hide=`: `auto`, `urgent`, `tfo` or `decoy`,
/// see [`SniMethod`]) and/or the hello cut up as `fm` says (BPB's
/// "Serverless" / "WorkerLess"). It helps where the filter reads the name out
/// of the hello and the address itself is not blocked; with neither it would
/// be a plain direct connection, which is refused as pointless.
fn parse_direct(rest: &str) -> Result<ShareLink, String> {
    let rest = rest.trim_start_matches('/');
    let (body, remark) = rest.split_once('#').unwrap_or((rest, ""));
    let query = parse_query(body.strip_prefix('?').unwrap_or(body));
    let mut evasion = query
        .get("fm")
        .and_then(|text| crate::xray_json::fragment_from_finalmask(text))
        .unwrap_or_default();
    evasion.sni_desync = match query
        .get("hide")
        .map(|hide| hide.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("") | Some("none") => None,
        Some("auto") => Some(SniDesyncConfig::default()),
        Some("urgent") => Some(SniDesyncConfig::urgent()),
        Some("tfo" | "fastopen") => Some(SniDesyncConfig::fast_open()),
        Some("record" | "recordversion") => Some(SniDesyncConfig::record()),
        Some("empty" | "emptyrecord") => Some(SniDesyncConfig::empty_record()),
        Some("decoy") => Some(SniDesyncConfig::decoy()),
        Some(other) => return Err(format!("unknown direct hide mode {other:?}")),
    };
    if evasion.is_empty() {
        return Err("a direct link needs hide= (auto, urgent, record, empty, tfo, decoy) or fm= (the fragment settings as finalmask JSON)".into());
    }
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::Freedom {
            domain_strategy: DomainStrategy::UseIp,
        },
        stream: StreamSettings {
            evasion,
            ..StreamSettings::default()
        },
        mux: MuxConfig::default(),
    };
    outbound.validate()?;
    Ok(ShareLink {
        link: String::new(),
        remark: decode(remark),
        outbound,
    })
}

fn parse_hysteria2(rest: &str) -> Result<ShareLink, String> {
    let p = split_link(rest)?;
    if p.credential.is_empty() {
        return Err("Hysteria2 link has an empty password".into());
    }
    let obfs_password = hysteria2_obfs(&p.query)?;
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
            allow_insecure: link_insecure(&p.query),
            ech: None,
            trusted_roots: Vec::new(),
            pinned_cert_sha256: Vec::new(),
            verify_names: Vec::new(),
            key_log_file: None,
        });
    }
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::Hysteria2(Hysteria2Config {
            address: Address::parse_host(p.host),
            port: p.port,
            password: p.credential.into(),
            obfs_password,
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
            allow_insecure: link_insecure(&p.query),
            ech: None,
            trusted_roots: Vec::new(),
            pinned_cert_sha256: Vec::new(),
            verify_names: Vec::new(),
            key_log_file: None,
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

/// `juicity://<uuid>:<password>@host:port?sni=&congestion_control=#name`
///
/// Juicity's own share link. The credential is `uuid:password`, exactly like
/// TUIC; the carrier is certificate TLS over QUIC with ALPN `h3`. The
/// `congestion_control` hint is accepted and ignored (the QUIC stack picks the
/// controller), and `pinned_certchain_sha256` is accepted and ignored because
/// this client verifies the ordinary certificate chain rather than a pinned
/// hash. `allow_insecure=1` is honoured like on every other TLS carrier.
fn parse_juicity(rest: &str) -> Result<ShareLink, String> {
    let p = split_link(rest)?;
    let (uuid_text, password) = p
        .credential
        .split_once(':')
        .ok_or_else(|| "Juicity link credential must be uuid:password".to_string())?;
    let uuid = parse_uuid(uuid_text)?;
    if password.is_empty() {
        return Err("Juicity link has an empty password".into());
    }
    let mut stream = build_stream(&p.query, p.host)?;
    if matches!(stream.security, Security::None) {
        let fingerprint = Fingerprint::parse(p.query.get("fp").map(String::as_str).unwrap_or(""))
            .ok_or_else(|| "unknown Juicity fingerprint".to_string())?;
        stream.security = Security::Tls(TlsConfig {
            server_name: Some(Arc::from(
                p.query.get("sni").map(String::as_str).unwrap_or(p.host),
            )),
            alpn: vec![Box::from("h3")],
            fingerprint,
            allow_insecure: link_insecure(&p.query),
            ech: None,
            trusted_roots: Vec::new(),
            pinned_cert_sha256: Vec::new(),
            verify_names: Vec::new(),
            key_log_file: None,
        });
    }
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol: OutboundProtocol::Juicity(JuicityConfig {
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

/// The prefix of a WARP account link.
pub const WARP_LINK_SCHEME: &str = "warp://";

/// A `warp://` link for the settings of a `warp` outbound (see
/// `xray_json::parse_warp`): the settings as JSON, base64url without padding,
/// with the remark after `#`. Everything an account needs travels in it, so
/// importing one is a paste.
pub fn warp_link(settings: &serde_json::Value, remark: &str) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(settings.to_string());
    if remark.is_empty() {
        format!("{WARP_LINK_SCHEME}{body}")
    } else {
        let remark =
            percent_encoding::utf8_percent_encode(remark, percent_encoding::NON_ALPHANUMERIC);
        format!("{WARP_LINK_SCHEME}{body}#{remark}")
    }
}

/// `warp://<base64url settings JSON>#remark`, built by [`warp_link`].
fn parse_warp_link(rest: &str) -> Result<ShareLink, String> {
    use base64::Engine as _;
    let (body, remark) = rest.split_once('#').unwrap_or((rest, ""));
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(body))
        .map_err(|error| format!("warp link is not base64: {error}"))?;
    let settings: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("warp link is not JSON: {error}"))?;
    let protocol = crate::xray_json::parse_warp(Some(&settings), "warp link")?;
    let outbound = Outbound {
        tag: Arc::from("proxy"),
        protocol,
        stream: StreamSettings::default(),
        mux: MuxConfig::default(),
    };
    outbound.validate()?;
    Ok(ShareLink {
        link: String::new(),
        remark: decode(remark),
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
        let bytes: Vec<u64> = reserved
            .split(',')
            .filter_map(|b| b.trim().parse().ok())
            .collect();
        settings["reserved"] = if bytes.len() == 3 {
            bytes.into()
        } else {
            reserved.into()
        };
    }
    let mut amnezia = serde_json::Map::new();
    for key in [
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
    ] {
        if let Some(value) = get(key) {
            amnezia.insert(
                key.into(),
                value
                    .parse::<u64>()
                    .map(Into::into)
                    .unwrap_or_else(|_| value.into()),
            );
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

    let transport_is_raw = matches!(network.as_str(), "" | "tcp" | "raw");
    let transport = match network.as_str() {
        "" | "tcp" | "raw" => Transport::Raw,
        "ws" => Transport::WebSocket(build_ws(q)),
        "httpupgrade" => Transport::HttpUpgrade(build_ws(q)),
        "grpc" => {
            // Query keys are lower-cased by `parse_query`, so the link's
            // `serviceName` arrives as `servicename`. The path is built the
            // way the Xray JSON parser builds it (`/<service>/Tun`); a bare
            // `/<service>` is rejected by every real gRPC server.
            let service = q.get("servicename").map(String::as_str).unwrap_or("");
            let mut config = build_ws(q);
            let (single, multi) = crate::xray_json::grpc_paths(service);
            config.path = Arc::from(single);
            config.grpc_multi_path = multi.map(Arc::from);
            // `mode=multi` is Xray's `multiMode`: the client speaks MultiHunk.
            config.grpc_multi = get("mode") == "multi";
            if let Some(authority) = q.get("authority").filter(|value| !value.is_empty()) {
                config.host = Some(Arc::from(authority.as_str()));
            }
            Transport::Grpc(config)
        }
        "xhttp" | "splithttp" => {
            let mut config = build_ws(q);
            config.xhttp_mode = XhttpMode::parse(get("mode"))
                .ok_or_else(|| format!("unsupported xhttp mode {:?}", get("mode")))?;
            // `extra` is the rest of Xray's `xhttpSettings` as JSON: padding
            // and placement settings, headers, and `downloadSettings`.
            //
            // The sing-box family writes the padding range as its own
            // `x_padding_bytes=100-1000` instead; it counts for a link whose
            // `extra` does not set it.
            let mut extra = match q.get("extra").filter(|extra| !extra.trim().is_empty()) {
                None => None,
                Some(extra) => match serde_json::from_str::<serde_json::Value>(extra) {
                    Ok(serde_json::Value::Object(extra)) => Some(extra),
                    _ => return Err("xhttp extra is not a JSON object".into()),
                },
            };
            if let Some(range) = q.get("x_padding_bytes").filter(|range| !range.is_empty()) {
                extra
                    .get_or_insert_with(Default::default)
                    .entry("xPaddingBytes")
                    .or_insert_with(|| range.as_str().into());
            }
            if let Some(extra) = extra {
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
                allow_insecure: link_insecure(q),
                ech: link_ech(q),
                trusted_roots: Vec::new(),
                verify_names: Vec::new(),
                key_log_file: None,
                pinned_cert_sha256: crate::xray_json::parse_cert_pins(get("pcs"))
                    .map_err(|error| format!("pcs: {error}"))?,
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
    crate::xray_json::host_from_server_name(&mut transport, &security);
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

    // The fragmentation the link's author found to work, for certificate TLS
    // that does not hide its name already (a hello cannot be both).
    let evasion = match &security {
        Security::Tls(tls) if tls.ech.is_none() => get_fm(q),
        _ => Evasion::default(),
    };

    Ok(StreamSettings {
        transport,
        security,
        sockopt: Sockopt::default(),
        evasion,
        raw_http_header: match transport_is_raw {
            true => link_http_camouflage(q),
            false => None,
        },
        direct: None,
    })
}

/// TCP header camouflage from a URI-style link: `headerType=http` with the
/// link's `host` (comma list, first wins) as the `Host` header and `path` as
/// the request line, the way v2rayN and Xray's own share links write it.
/// Any other `headerType` (`none`, empty, panel filler) means no header.
fn link_http_camouflage(q: &BTreeMap<String, String>) -> Option<RawHttpHeader> {
    if !q
        .get("headertype")
        .is_some_and(|t| t.eq_ignore_ascii_case("http"))
    {
        return None;
    }
    let first = |key: &str| {
        q.get(key)?
            .split(',')
            .map(str::trim)
            .find(|item| !item.is_empty())
            .map(str::to_owned)
    };
    let mut headers = BTreeMap::new();
    if let Some(host) = first("host") {
        headers.insert(Box::from("Host"), Box::from(host.as_str()));
    }
    Some(RawHttpHeader {
        request: RawHttpRequest {
            version: Box::from("1.1"),
            method: Box::from("GET"),
            path: Box::from(first("path").as_deref().unwrap_or("/")),
            headers,
        },
        response: None,
    })
}

/// The `fm=` of a link as evasion, empty when there is none or it is not
/// readable (the link then connects as it did before it was read).
fn get_fm(q: &BTreeMap<String, String>) -> Evasion {
    q.get("fm")
        .and_then(|text| crate::xray_json::fragment_from_finalmask(text))
        .unwrap_or_default()
}

/// The `ech=` of a TLS link (v2rayN and NekoBox write the list there, many
/// feeds write Xray's `cloudflare-ech.com+udp://1.1.1.1` query instead; see
/// [`crate::xray_json::ech_from_text`]). A value that cannot be read is left
/// out rather than failing the link: it connected without ECH before this
/// was read, and the engine can still turn ECH on by itself where it helps.
/// Whether a link asks to skip certificate checks. The spellings in use:
/// `allowInsecure=1` (Xray), `insecure=1` (Hysteria 2, panels) and
/// `allow_insecure=1` (TUIC, Juicity). Keys are lower-cased by `parse_query`.
fn link_insecure(q: &BTreeMap<String, String>) -> bool {
    ["allowinsecure", "insecure", "allow_insecure"]
        .iter()
        .any(|key| matches!(q.get(*key).map(String::as_str), Some("1" | "true")))
}

/// The Salamander password of a Hysteria 2 link
/// (`obfs=salamander&obfs-password=…`), `None` for a link without one. A
/// type other than Salamander is an error: connecting without obfuscation
/// to a server that expects some would only look like a dead server.
fn hysteria2_obfs(q: &BTreeMap<String, String>) -> Result<Option<Box<str>>, String> {
    let kind = q.get("obfs").map(String::as_str).unwrap_or("");
    if kind.is_empty() || kind.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    if !kind.eq_ignore_ascii_case("salamander") {
        return Err(format!("unsupported Hysteria2 obfs type {kind:?}"));
    }
    let password = ["obfs-password", "obfs_password", "obfspassword"]
        .iter()
        .find_map(|key| q.get(*key))
        .map(String::as_str)
        .unwrap_or("");
    if password.len() < 4 {
        return Err("the Hysteria2 Salamander password must be at least 4 bytes".into());
    }
    Ok(Some(password.into()))
}

fn link_ech(q: &BTreeMap<String, String>) -> Option<EchConfig> {
    let text = q.get("ech").or_else(|| q.get("echconfiglist"))?;
    crate::xray_json::ech_from_text(text, None).ok()
}

fn build_ws(q: &BTreeMap<String, String>) -> WebSocketConfig {
    let raw_path = q.get("path").map(String::as_str).unwrap_or("/");
    // Xray encodes the early-data budget in the path query as `ed=N`.
    let (path, early_data_len) = extract_early_data(raw_path);
    WebSocketConfig {
        path: Arc::from(path.as_str()),
        // No `host=` leaves it to `host_from_server_name`, then the address.
        host: q
            .get("host")
            .filter(|host| !host.is_empty())
            .map(|host| Arc::from(host.as_str())),
        headers: BTreeMap::new(),
        early_data_len,
        xhttp_mode: XhttpMode::StreamOne,
        xhttp_http_version: XhttpHttpVersion::Http1,
        xhttp_download: None,
        xhttp: Default::default(),
        grpc_multi_path: None,
        grpc_multi: false,
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
            s.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("bad hex in shortId {s:?}"))
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
            .map(|i| {
                s.get(i..i + 2)
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                    .ok_or(Error)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A feed can carry anything where a key should be, including text cut
    /// off with "…": the hex decoders must refuse it, never slice through it.
    #[test]
    fn non_ascii_keys_are_refused_not_panicked_on() {
        for bad in ["a…", "…", "ab\u{e9}d", "\u{e9}\u{e9}", "0123456789abcde…"] {
            assert!(parse_short_id(bad).is_err(), "short id {bad:?}");
            assert!(parse_reality_key(bad).is_err(), "key {bad:?}");
        }
        assert_eq!(parse_short_id("ab12").unwrap(), vec![0xab, 0x12]);
    }

    fn masterdns(link: &str) -> Result<MasterDnsConfig, String> {
        match parse_link(link)?.outbound.protocol {
            OutboundProtocol::MasterDns(m) => Ok(m),
            other => Err(format!("not a MasterDNS outbound: {other:?}")),
        }
    }

    #[test]
    fn a_masterdns_link_names_the_domain_key_and_resolvers() {
        let m = masterdns(
            "masterdns://k3y%2Bsecret@T.Example.com?server=203.0.113.7&resolvers=8.8.8.8,1.1.1.1:5353,[2001:4860:4860::8888]&method=4&mode=tcp#My%20DNS",
        )
        .unwrap();
        assert_eq!(&*m.domain, "t.example.com");
        assert_eq!(&*m.key, "k3y+secret");
        assert_eq!(m.method, 4);
        assert_eq!(m.mode, MasterDnsMode::Tcp);
        let resolvers: Vec<String> = m.resolvers.iter().map(|r| r.to_string()).collect();
        // The server itself comes first, then the resolvers; port 53 by default.
        assert_eq!(
            resolvers,
            [
                "203.0.113.7:53",
                "8.8.8.8:53",
                "1.1.1.1:5353",
                "[2001:4860:4860::8888]:53"
            ]
        );
        assert_eq!(
            parse_link("masterdns://k@t.example.com?server=203.0.113.7#My%20DNS")
                .unwrap()
                .remark,
            "My DNS"
        );
    }

    #[test]
    fn a_masterdns_link_defaults_to_aes_gcm_and_socks5() {
        let m = masterdns("masterdns://k@t.example.com?resolvers=9.9.9.9").unwrap();
        assert_eq!((m.method, m.mode), (5, MasterDnsMode::Socks5));
    }

    #[test]
    fn a_bad_masterdns_link_says_what_is_wrong() {
        for (link, needle) in [
            ("masterdns://t.example.com?resolvers=9.9.9.9", "key"),
            ("masterdns://k@t.example.com", "resolver"),
            (
                "masterdns://k@t.example.com?resolvers=dns.google",
                "not an IP",
            ),
            ("masterdns://k@localhost?resolvers=9.9.9.9", "domain"),
            (
                "masterdns://k@t.example.com?resolvers=9.9.9.9&method=2",
                "method",
            ),
            (
                "masterdns://k@t.example.com?resolvers=9.9.9.9&mode=udp",
                "mode",
            ),
        ] {
            let error = masterdns(link).unwrap_err();
            assert!(error.contains(needle), "{link}: {error}");
        }
    }

    #[test]
    fn the_masterdns_key_never_prints() {
        let m = masterdns("masterdns://very-secret-key@t.example.com?resolvers=9.9.9.9").unwrap();
        assert!(!format!("{m:?}").contains("very-secret-key"));
    }

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
    fn pcs_becomes_certificate_pins_and_a_bad_one_fails_the_link() {
        let hash = "cd6e838b9bfe31cab8b3d5c858b0d6223fe84ece236c1fdb281be93c302e1e6e";
        let link = |pcs: &str| {
            parse_link(&format!(
                "vless://11111111-2222-3333-4444-555555555555@203.0.113.9:443?security=tls&sni=a.example&type=ws&pcs={pcs}#x"
            ))
        };
        let o = link(&format!("{hash},{}", hash.to_uppercase()))
            .unwrap()
            .outbound;
        let Security::Tls(tls) = o.stream.security else {
            panic!("tls")
        };
        assert_eq!(tls.pinned_cert_sha256.len(), 2);
        assert_eq!(tls.pinned_cert_sha256[0], tls.pinned_cert_sha256[1]);
        assert_eq!(tls.pinned_cert_sha256[0][..2], [0xcd, 0x6e]);
        assert!(link("abcd").is_err(), "a short pin must not be skipped");
        assert!(link("zz").is_err());
    }

    #[test]
    fn a_uri_link_with_header_type_http_gets_the_camouflage_header() {
        let o = parse_link(
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.9:80?encryption=none&type=tcp&headerType=http&host=a.example,b.example&path=%2Fx#t",
        )
        .unwrap()
        .outbound;
        let header = o.stream.raw_http_header.expect("HTTP camouflage");
        assert_eq!(&*header.request.path, "/x");
        assert_eq!(
            header.request.headers.get("Host").map(|v| &**v),
            Some("a.example")
        );
        // `none` and a missing headerType leave the stream bare, and a
        // WebSocket link ignores the key.
        for tail in ["headerType=none", "type=tcp", "type=ws&headerType=http"] {
            let o = parse_link(&format!(
                "vless://11111111-2222-3333-4444-555555555555@203.0.113.9:80?encryption=none&{tail}#t"
            ))
            .unwrap()
            .outbound;
            assert!(o.stream.raw_http_header.is_none(), "{tail}");
        }
    }

    #[test]
    fn allow_insecure_is_kept_when_a_tls_link_asks_for_it() {
        let insecure_of = |link: &str| {
            let Security::Tls(tls) = parse_link(link).unwrap().outbound.stream.security else {
                panic!("expected certificate TLS");
            };
            tls.allow_insecure
        };
        assert!(!insecure_of(VLESS_WS));
        for spelling in ["allowInsecure=1", "insecure=1", "allowInsecure=true"] {
            let link =
                VLESS_WS.replace("&alpn=http%2F1.1", &format!("&alpn=http%2F1.1&{spelling}"));
            assert!(insecure_of(&link), "{spelling}");
        }
        // `=0` is what panels write for "verify".
        let link = VLESS_WS.replace(
            "&alpn=http%2F1.1",
            "&alpn=http%2F1.1&allowInsecure=0&insecure=0",
        );
        assert!(!insecure_of(&link));
    }

    #[test]
    fn quic_links_take_insecure_the_same_way() {
        let insecure_of = |link: &str| {
            let Security::Tls(tls) = parse_link(link).unwrap().outbound.stream.security else {
                panic!("expected certificate TLS");
            };
            tls.allow_insecure
        };
        let uuid = "00000000-0000-0000-0000-000000000001";
        for (base, key) in [
            (
                "hysteria2://secret@example.com:443?sni=a.example",
                "insecure",
            ),
            (
                &format!("tuic://{uuid}:pw@example.com:443?sni=a.example"),
                "allow_insecure",
            ),
            (
                &format!("juicity://{uuid}:pw@example.com:443?sni=a.example"),
                "allow_insecure",
            ),
        ] {
            assert!(!insecure_of(&format!("{base}#a")), "{base}");
            assert!(insecure_of(&format!("{base}&{key}=1#a")), "{base}");
            assert!(!insecure_of(&format!("{base}&{key}=0#a")), "{base}");
            assert!(insecure_of(&format!("{base}&allowInsecure=1#a")), "{base}");
        }
    }

    #[test]
    fn a_hysteria2_link_reads_its_salamander_password() {
        let obfs_of = |query: &str| {
            let link = parse_link(&format!("hysteria2://secret@example.com:443/?{query}#h"));
            link.map(|link| match link.outbound.protocol {
                OutboundProtocol::Hysteria2(config) => config.obfs_password.map(String::from),
                _ => panic!("expected Hysteria2"),
            })
        };
        assert_eq!(obfs_of("sni=a.example"), Ok(None));
        assert_eq!(
            obfs_of("obfs=salamander&obfs-password=gawrgura"),
            Ok(Some("gawrgura".into()))
        );
        // The type is case-insensitive, `none` is no obfuscation, and the
        // password may be spelled the other ways in use.
        assert_eq!(
            obfs_of("obfs=Salamander&obfs_password=gawrgura"),
            Ok(Some("gawrgura".into()))
        );
        assert_eq!(obfs_of("obfs=none"), Ok(None));
        // A percent-encoded password is decoded.
        assert_eq!(
            obfs_of("obfs=salamander&obfs-password=pass%20word%2B1"),
            Ok(Some("pass word+1".into()))
        );
        // What the server could not use is refused, not connected without.
        assert!(obfs_of("obfs=salamander").unwrap_err().contains("4 bytes"));
        assert!(obfs_of("obfs=salamander&obfs-password=abc")
            .unwrap_err()
            .contains("4 bytes"));
        assert!(obfs_of("obfs=gecko&obfs-password=gawrgura")
            .unwrap_err()
            .contains("unsupported"));
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
    fn parses_socks_links_with_and_without_a_credential() {
        let local = parse_link("socks5://127.0.0.1:9050#Tor").unwrap();
        assert_eq!(local.remark, "Tor");
        match &local.outbound.protocol {
            OutboundProtocol::Socks(s) => {
                assert_eq!(s.port, 9050);
                assert_eq!(s.address, Address::parse_host("127.0.0.1"));
                assert!(s.auth.is_none());
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(local.outbound.stream.security, Security::None));

        // A %3A in the password must not be mistaken for the separator.
        let plain = parse_link("socks5h://alice:p%3Ass@proxy.example:1080").unwrap();
        match &plain.outbound.protocol {
            OutboundProtocol::Socks(s) => {
                let auth = s.auth.as_ref().unwrap();
                assert_eq!(&*auth.username, "alice");
                assert_eq!(&*auth.password, "p:ss");
            }
            other => panic!("{other:?}"),
        }

        // v2rayN: base64("alice:secret") in the user position.
        let b64 = parse_link("socks://YWxpY2U6c2VjcmV0@[::1]:1080").unwrap();
        match &b64.outbound.protocol {
            OutboundProtocol::Socks(s) => {
                let auth = s.auth.as_ref().unwrap();
                assert_eq!((&*auth.username, &*auth.password), ("alice", "secret"));
                assert_eq!(s.address, Address::parse_host("::1"));
            }
            other => panic!("{other:?}"),
        }

        assert!(parse_link("socks5://127.0.0.1").is_err());
        assert!(parse_link("socks5://nocolon@127.0.0.1:9050").is_err());
    }

    #[test]
    fn parses_the_bare_tor_link() {
        let link = parse_link("tor://#Tor%20network").unwrap();
        assert_eq!(link.remark, "Tor network");
        assert_eq!(
            link.outbound.protocol,
            OutboundProtocol::Tor(TorConfig::default())
        );
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
    fn a_websocket_link_with_no_host_sends_the_server_name_as_host() {
        let host_of = |link: &str| {
            let Transport::WebSocket(ws) = parse_link(link).unwrap().outbound.stream.transport
            else {
                panic!("expected WebSocket");
            };
            ws.host.map(|host| host.to_string())
        };
        // Reached by IP, named by the SNI: the Worker is the SNI, not the IP.
        let by_ip = "vless://00000000-0000-0000-0000-000000000002@188.114.96.3:443\
            ?security=tls&sni=Worker.Example.dev&type=ws&path=%2Fws&encryption=none#a";
        assert_eq!(host_of(by_ip).as_deref(), Some("Worker.Example.dev"));
        // An explicit host wins; an empty one is no host.
        let explicit = by_ip.replace("&type=ws", "&host=real.example.com&type=ws");
        assert_eq!(host_of(&explicit).as_deref(), Some("real.example.com"));
        let empty = by_ip.replace("&type=ws", "&host=&type=ws");
        assert_eq!(host_of(&empty).as_deref(), Some("Worker.Example.dev"));
        // No TLS name to fall back to: left for the address.
        let plain = "vless://00000000-0000-0000-0000-000000000002@203.0.113.7:80\
            ?security=none&type=ws&path=%2Fws&encryption=none#a";
        assert_eq!(host_of(plain), None);
    }

    #[test]
    fn xhttp_padding_can_come_as_its_own_link_parameter() {
        let padding_of = |query: &str| {
            let link = parse_link(&format!(
                "vless://00000000-0000-0000-0000-000000000002@cdn.example.com:443\
                 ?security=tls&sni=cdn.example.com&type=xhttp&path=%2Fx&mode=packet-up\
                 &encryption=none{query}#x"
            ))
            .unwrap();
            let Transport::Xhttp(config) = link.outbound.stream.transport else {
                panic!("expected XHTTP");
            };
            config.xhttp.x_padding_bytes
        };
        // The sing-box spelling.
        assert_eq!(padding_of("&x_padding_bytes=100-1000"), (100, 1000));
        // `extra` says it already, and wins.
        assert_eq!(
            padding_of("&x_padding_bytes=100-1000&extra=%7B%22xPaddingBytes%22%3A%2210-20%22%7D"),
            (10, 20)
        );
        // Not a range: refused, as it is inside `extra`.
        assert!(parse_link(
            "vless://00000000-0000-0000-0000-000000000002@cdn.example.com:443\
             ?security=tls&type=xhttp&mode=packet-up&x_padding_bytes=lots#x"
        )
        .is_err());
    }

    const FM: &str = "%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22%2C%22settings%22%3A%7B%22packets%22%3A%22tlshello%22%2C%22length%22%3A%2210-20%22%2C%22delay%22%3A%221-1%22%7D%7D%5D%7D";

    #[test]
    fn a_tls_link_keeps_the_fragmentation_it_carries() {
        let fragment_of = |extra: &str, security: &str| {
            let link = parse_link(&format!(
                "vless://00000000-0000-0000-0000-000000000002@188.114.97.6:443\
                 ?security={security}&sni=x.example.com&type=ws&path=%2Fws&encryption=none{extra}#cdn"
            ))
            .unwrap();
            link.outbound.stream.evasion.tcp_fragment
        };
        assert!(fragment_of("", "tls").is_none());
        let fragment = fragment_of(&format!("&fm={FM}"), "tls").expect("fragmented");
        assert_eq!((fragment.length.min, fragment.length.max), (10, 20));
        // Text that is not a finalmask object, or has no fragment in it, is
        // left out and the link connects as before.
        assert!(fragment_of("&fm=tlshello-0-len", "tls").is_none());
        assert!(fragment_of("&fm=%7B%22udp%22%3A%5B%5D%7D", "tls").is_none());
        // Plain TCP has no hello to cut.
        assert!(fragment_of(&format!("&fm={FM}"), "none").is_none());
        // And a hello that is encrypted is not cut up as well.
        assert!(fragment_of(&format!("&fm={FM}&ech=udp%3A%2F%2F1.1.1.1"), "tls").is_none());
    }

    #[test]
    fn a_direct_link_is_a_server_less_profile_with_its_fragmentation() {
        let link = parse_link(&format!("direct://?fm={FM}#Serverless")).unwrap();
        assert_eq!(link.remark, "Serverless");
        assert!(matches!(
            link.outbound.protocol,
            OutboundProtocol::Freedom { .. }
        ));
        assert!(link.outbound.endpoint().is_none());
        assert!(link.outbound.stream.evasion.tcp_fragment.is_some());
        // The slash after the scheme is allowed, as in the other links.
        assert!(parse_link(&format!("direct:///?fm={FM}#x")).is_ok());
        // Without fragmentation or hiding it would be a plain direct connection.
        assert!(parse_link("direct://#plain").is_err());
        assert!(parse_link("direct://?fm=nothing#plain").is_err());
    }

    #[test]
    fn a_direct_link_can_hide_the_name_instead_of_cutting_the_hello() {
        let method_of = |hide: &str| {
            parse_link(&format!("direct://?hide={hide}#h"))
                .map(|link| link.outbound.stream.evasion.sni_desync.map(|d| d.method))
        };
        assert_eq!(method_of("auto"), Ok(Some(SniMethod::Auto)));
        assert_eq!(method_of("urgent"), Ok(Some(SniMethod::Urgent)));
        assert_eq!(method_of("Decoy"), Ok(Some(SniMethod::Decoy)));
        assert_eq!(method_of("tfo"), Ok(Some(SniMethod::FastOpen)));
        assert_eq!(method_of("record"), Ok(Some(SniMethod::Record)));
        assert_eq!(method_of("empty"), Ok(Some(SniMethod::EmptyRecord)));
        assert!(method_of("none").is_err());
        assert!(method_of("sudoku").unwrap_err().contains("unknown"));
        // Both together is allowed: the name hidden and the hello cut up.
        let both = parse_link(&format!("direct://?hide=urgent&fm={FM}#b")).unwrap();
        assert!(both.outbound.stream.evasion.sni_desync.is_some());
        assert!(both.outbound.stream.evasion.tcp_fragment.is_some());
    }

    #[test]
    fn a_tls_link_keeps_the_ech_it_asks_for() {
        let ech_of = |extra: &str| {
            let link = parse_link(&format!(
                "vless://00000000-0000-0000-0000-000000000002@188.114.97.6:443\
                 ?security=tls&sni=x.example.com&type=ws&path=%2Fws&encryption=none{extra}#cdn"
            ))
            .unwrap();
            let Security::Tls(tls) = link.outbound.stream.security else {
                panic!("expected certificate TLS");
            };
            tls.ech
        };
        assert!(ech_of("").is_none());

        // The feed spelling: look it up under Cloudflare's shared name.
        let query = ech_of("&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1").unwrap();
        assert!(query.config_list.is_empty());
        assert_eq!(query.query_name.as_deref(), Some("cloudflare-ech.com"));

        // The list itself, with its `+` read as a space by a form decoder.
        let list = ech_of("&ech=AEX+DQBBVgAgACDzZYk23tgiGbAeubeC2MHb6tSC9Ds5cheCtbyYkeAseQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=").unwrap();
        assert_eq!(list.config_list.len(), 71);
        assert_eq!(list.query_name, None);
        let spaced = ech_of("&ech=AEX%20DQBBVgAgACDzZYk23tgiGbAeubeC2MHb6tSC9Ds5cheCtbyYkeAseQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=").unwrap();
        assert_eq!(spaced.config_list, list.config_list);

        // Unreadable, or empty: the link still works, without ECH.
        assert!(ech_of("&ech=%%%not-base64").is_none());
        assert!(ech_of("&ech=").is_none());
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
    fn parses_juicity_link_with_uuid_password_and_h3() {
        let link = parse_link(
            "juicity://00000000-0000-0000-0000-000000000001:secret@example.com:443?sni=cdn.example&congestion_control=bbr#Juicity",
        )
        .unwrap();
        assert_eq!(link.remark, "Juicity");
        let OutboundProtocol::Juicity(juicity) = &link.outbound.protocol else {
            panic!("expected juicity, got {:?}", link.outbound.protocol);
        };
        assert_eq!(juicity.port, 443);
        assert_eq!(&*juicity.password, "secret");
        assert_eq!(juicity.uuid[15], 1);
        let Security::Tls(tls) = &link.outbound.stream.security else {
            panic!("expected certificate TLS");
        };
        assert_eq!(tls.server_name.as_deref(), Some("cdn.example"));
        assert_eq!(tls.alpn, vec![Box::<str>::from("h3")]);
        assert!(!tls.allow_insecure);
    }

    #[test]
    fn juicity_link_imports_securely_and_rejects_empty_password() {
        // A plain Juicity link verifies the certificate chain; only a link
        // that says `allow_insecure=1` skips it.
        let link = parse_link(
            "juicity://00000000-0000-0000-0000-000000000001:pw@example.com:443?sni=a.example#J",
        )
        .unwrap();
        let Security::Tls(tls) = &link.outbound.stream.security else {
            panic!("expected certificate TLS");
        };
        assert!(!tls.allow_insecure);
        assert!(parse_link(
            "juicity://00000000-0000-0000-0000-000000000001:@example.com:443#empty"
        )
        .is_err());
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
    fn a_grpc_link_with_mode_multi_speaks_multihunk() {
        let link = parse_link(&format!(
            "vless://{UUID}@example.com:443?type=grpc&serviceName=my-svc&mode=multi&security=tls&sni=example.com#g"
        ))
        .unwrap();
        let Transport::Grpc(grpc) = &link.outbound.stream.transport else {
            panic!("expected grpc");
        };
        assert!(grpc.grpc_multi);
        assert_eq!(grpc.grpc_multi_path.as_deref(), Some("/my-svc/TunMulti"));
        assert_eq!(&*grpc.path, "/my-svc/Tun");
    }

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

    #[test]
    fn a_warp_link_carries_a_whole_account_and_round_trips() {
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD.encode([3u8; 40]);
        let settings = serde_json::json!({
            "route": "masque-h2",
            "masque": {"privateKey": der, "serverPublicKey": der, "address": ["172.16.0.2"]}
        });
        let link = warp_link(&settings, "WARP خانه");
        assert!(link.starts_with("warp://"));
        let parsed = parse_link(&link).unwrap();
        assert_eq!(parsed.remark, "WARP خانه");
        let OutboundProtocol::AmneziaWireguard(warp) = &parsed.outbound.protocol else {
            panic!("expected a WARP outbound")
        };
        assert_eq!(warp.route, WarpRoute::MasqueHttp2);
        assert!(warp.masque.is_some() && !warp.wireguard_usable());
        // Damage is reported, not guessed at.
        assert!(parse_link("warp://!!!").is_err());
        assert!(parse_link(&format!("warp://{}", "e30")).is_err());
    }

    #[test]
    fn a_zerov1_link_asks_for_udp_only_when_it_says_so() {
        let key = "A".repeat(43);
        let user = "A".repeat(22);
        let link = |extra: &str| {
            format!("zerov1://{user}@example.org:443?key={key}&path=/static/ab{extra}#n")
        };
        let datagrams = |text: String| {
            let parsed = parse_link(&text).unwrap();
            let OutboundProtocol::Tide(tide) = &parsed.outbound.protocol else {
                panic!("expected a ZeroV1 outbound")
            };
            tide.datagrams
        };
        // A link from a server that predates the lane must not ask for it:
        // that server refuses the request instead of ignoring it.
        assert!(!datagrams(link("")));
        assert!(datagrams(link("&dg=1")));
        assert!(!datagrams(link("&dg=0")));
        // The old scheme name reads the same way.
        assert!(datagrams(link("&dg=1").replace("zerov1://", "tide://")));
    }

    fn tide_tuning(extra: &str) -> Result<TideTuning, String> {
        let key = "A".repeat(43);
        let user = "A".repeat(22);
        let link = format!("zerov1://{user}@example.org:443?key={key}&path=/static/ab{extra}#n");
        parse_link(&link).map(|parsed| match parsed.outbound.protocol {
            OutboundProtocol::Tide(tide) => tide.tuning,
            _ => panic!("expected a ZeroV1 outbound"),
        })
    }

    #[test]
    fn a_plain_zerov1_link_changes_nothing_about_the_defaults() {
        assert_eq!(tide_tuning("").unwrap(), TideTuning::default());
    }

    #[test]
    fn a_zerov1_link_can_set_how_it_looks_and_paces() {
        let t = tide_tuning(
            "&authority=Cdn.Example.com&ua=firefox&lang=fa-IR,fa;q%3D0.9&headers=referer:https://a.test/,x-visit:7\
             &pipes=3&uploads=5&ping=20&idle=120&linger=0&age=60-300&volume=512",
        )
        .unwrap();
        assert_eq!(t.authority.as_deref(), Some("cdn.example.com"));
        assert!(t.user_agent.as_deref().unwrap().contains("Firefox/"));
        assert_eq!(t.language.as_deref(), Some("fa-IR,fa;q=0.9"));
        assert_eq!(t.headers.len(), 2);
        assert_eq!(&*t.headers[0].0, "referer");
        assert_eq!(&*t.headers[0].1, "https://a.test/");
        assert_eq!(
            (t.down_pipes, t.up_pipes, t.ping_secs, t.idle_secs),
            (Some(3), Some(5), Some(20), Some(120))
        );
        assert_eq!(
            (t.linger_ms, t.age_secs, t.volume_mb),
            (Some(0), Some((60, 300)), Some(512))
        );
        // `host` is the name most people reach for; it means the same.
        assert_eq!(
            tide_tuning("&host=a.test").unwrap().authority.as_deref(),
            Some("a.test")
        );
        // Any text is a user agent when it is not a preset name.
        assert_eq!(
            tide_tuning("&ua=MyBrowser%2F1.0")
                .unwrap()
                .user_agent
                .as_deref(),
            Some("MyBrowser/1.0")
        );
    }

    #[test]
    fn a_zerov1_option_out_of_range_is_refused_not_clamped() {
        for bad in [
            "&pipes=0",
            "&pipes=9",
            "&uploads=7",
            "&ping=1",
            "&idle=5",
            "&linger=60000",
            "&age=300-60",
            "&age=5-9",
            "&volume=8",
            "&authority=bad/name",
            "&ua=%00",
            "&headers=content-type:text/html",
            "&headers=host:evil.test",
            "&headers=novalue",
        ] {
            assert!(tide_tuning(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn two_zerov1_links_that_differ_only_in_a_cookie_do_not_share_a_client() {
        let a = tide_tuning("&headers=cookie:sesame-A").unwrap();
        let b = tide_tuning("&headers=cookie:sesame-B").unwrap();
        assert_ne!(format!("{a:?}"), format!("{b:?}"));
        // The value itself never shows in the debug form.
        assert!(!format!("{a:?}").contains("sesame"));
    }
}
