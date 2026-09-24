//! Fetching and applying subscription feeds.
//!
//! A subscription URL returns a list of share links — plain, one per line, or
//! the whole body base64-encoded. Updating a feed replaces exactly the
//! profiles that came from it and leaves hand-made ones alone.
//!
//! ## Why there is an HTTP client in here
//!
//! The workspace has no HTTP client, and pulling one in for a single GET
//! would add a large dependency tree to a censorship-circumvention tool where
//! dependency surface is a real cost. This is a deliberately small client
//! built on the `tokio-rustls` already in the workspace: GET only, redirects,
//! `Content-Length` and chunked bodies, `identity` encoding. That is the whole
//! surface a subscription endpoint needs.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Longest a feed may take before the fetch is abandoned.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
/// Largest body accepted, so a hostile or broken endpoint cannot exhaust
/// memory.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Redirect hops followed before giving up.
const MAX_REDIRECTS: usize = 5;

/// What an update produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedContents {
    /// Profiles parsed out of the body: `(remark, protocol, address, port, link)`.
    pub profiles: Vec<FeedProfile>,
    /// Entries that were present but unreadable.
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedProfile {
    pub remark: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    /// The original share link, kept verbatim for re-sharing.
    pub link: String,
}

/// Fetch a subscription URL and parse the share links it returns.
pub async fn fetch_feed(url: &str) -> Result<FeedContents, String> {
    let body = tokio::time::timeout(FETCH_TIMEOUT, http_get(url))
        .await
        .map_err(|_| format!("timed out after {}s", FETCH_TIMEOUT.as_secs()))??;
    Ok(parse_feed(&body))
}

/// Parse a subscription body into profiles.
///
/// Split out from the fetch so the parsing is testable without a network.
pub fn parse_feed(body: &str) -> FeedContents {
    let mut profiles = Vec::new();
    let mut skipped = 0usize;
    // Feeds assembled from several sources routinely repeat a node; storing
    // it twice doubles the list, the latency sweep and the confusion.
    let mut seen = std::collections::HashSet::new();

    // A byte-order mark in front of the first line would otherwise make the
    // first link's scheme unrecognisable and silently drop it.
    let body = body.trim_start_matches('\u{feff}');

    for entry in zero_config::parse_subscription(body) {
        match entry {
            Ok(link) => {
                if !seen.insert(link.link.clone()) {
                    continue;
                }
                let protocol = link.outbound.protocol.name().to_string();
                let (address, port) = endpoint_of(&link.outbound.protocol);
                let remark = if link.remark.trim().is_empty() {
                    format!("{}-{address}", protocol.to_uppercase())
                } else {
                    link.remark.clone()
                };
                profiles.push(FeedProfile {
                    remark,
                    protocol,
                    address,
                    port,
                    link: link.link.clone(),
                });
            }
            Err(_) => skipped += 1,
        }
    }

    FeedContents { profiles, skipped }
}

fn endpoint_of(protocol: &zero_config::OutboundProtocol) -> (String, u16) {
    match protocol {
        zero_config::OutboundProtocol::Vless(v) => (v.address.to_string(), v.port),
        zero_config::OutboundProtocol::Trojan(t) => (t.address.to_string(), t.port),
        zero_config::OutboundProtocol::Shadowsocks(s) => (s.address.to_string(), s.port),
        zero_config::OutboundProtocol::Vmess(m) => (m.address.to_string(), m.port),
        zero_config::OutboundProtocol::Hysteria2(h) => (h.address.to_string(), h.port),
        zero_config::OutboundProtocol::Tuic(t) => (t.address.to_string(), t.port),
        zero_config::OutboundProtocol::AnyTls(a) => (a.address.to_string(), a.port),
        _ => ("proxy".into(), 443),
    }
}

// ------------------------------------------------------------------ HTTP

/// A parsed absolute URL. Only what a GET needs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Url {
    secure: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(input: &str) -> Result<Url, String> {
    let input = input.trim();
    let (scheme, rest) = input
        .split_once("://")
        .ok_or_else(|| format!("{input:?} is not an http(s) URL"))?;

    let secure = match scheme.to_ascii_lowercase().as_str() {
        "https" => true,
        "http" => false,
        other => return Err(format!("unsupported scheme {other:?}")),
    };

    // The fragment is client-side only and must never be sent.
    let rest = rest.split_once('#').map_or(rest, |(before, _)| before);
    // The authority ends at the first `/` or `?`: a token-bearing URL like
    // `https://host?token=…` has no path at all, and treating the query as
    // part of the host name made it unresolvable.
    let (authority, path) = match rest.find(['/', '?']) {
        Some(idx) if rest.as_bytes()[idx] == b'?' => (&rest[..idx], format!("/{}", &rest[idx..])),
        Some(idx) => (&rest[..idx], rest[idx..].to_string()),
        None => (rest, "/".to_string()),
    };
    // Credentials in the URL are not forwarded; a subscription that needs
    // auth should carry a token in its path or query instead.
    let authority = authority.rsplit('@').next().unwrap_or(authority);

    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        // IPv6 literal.
        let (host, tail) = stripped
            .split_once(']')
            .ok_or_else(|| "malformed IPv6 host".to_string())?;
        let port = tail
            .strip_prefix(':')
            .map(|p| p.parse::<u16>().map_err(|_| "bad port".to_string()))
            .transpose()?;
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                Some(p.parse::<u16>().map_err(|_| "bad port".to_string())?),
            ),
            None => (authority.to_string(), None),
        }
    };

    if host.is_empty() {
        return Err("URL has no host".into());
    }

    Ok(Url {
        secure,
        host,
        port: port.unwrap_or(if secure { 443 } else { 80 }),
        path: if path.is_empty() {
            "/".to_string()
        } else {
            path
        },
    })
}

impl Url {
    /// The `Host` header value: the port is included when it is not the
    /// scheme's default, and an IPv6 literal keeps its brackets. Virtual
    /// hosting on a non-standard port routes on exactly this.
    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default_port = if self.secure { 443 } else { 80 };
        if self.port == default_port {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

async fn http_get(url: &str) -> Result<String, String> {
    let mut target = parse_url(url)?;

    for _ in 0..=MAX_REDIRECTS {
        let response = request_once(&target).await?;

        match response.status {
            200..=299 => return Ok(response.body),
            301 | 302 | 303 | 307 | 308 => {
                let location = response
                    .location
                    .ok_or_else(|| format!("HTTP {} with no Location header", response.status))?;
                target = resolve_redirect(&target, &location)?;
            }
            status => {
                return Err(format!("server returned HTTP {status}"));
            }
        }
    }
    Err("too many redirects".into())
}

/// Resolve a `Location` header against the request it answered.
fn resolve_redirect(from: &Url, location: &str) -> Result<Url, String> {
    let location = location.trim();
    if location.contains("://") {
        return parse_url(location);
    }
    // Scheme-relative: same scheme, new authority.
    if let Some(rest) = location.strip_prefix("//") {
        let scheme = if from.secure { "https" } else { "http" };
        return parse_url(&format!("{scheme}://{rest}"));
    }
    // Relative redirects are common; anchor them to the current host.
    let path = if location.starts_with('/') {
        location.to_string()
    } else {
        let base = from.path.rsplit_once('/').map(|(b, _)| b).unwrap_or("");
        format!("{base}/{location}")
    };
    Ok(Url {
        path,
        ..from.clone()
    })
}

struct Response {
    status: u16,
    location: Option<String>,
    body: String,
}

async fn request_once(url: &Url) -> Result<Response, String> {
    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: ZeroNet-TUI\r\n\
         Accept: */*\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n\r\n",
        url.path,
        url.host_header()
    );

    let stream = match tokio::net::TcpStream::connect((url.host.as_str(), url.port)).await {
        Ok(s) => s,
        Err(e) => return Err(format!("cannot reach {}:{}: {e}", url.host, url.port)),
    };

    let raw = if url.secure {
        let connector = tokio_rustls::TlsConnector::from(tls_config());
        let server_name = rustls_pki_types::ServerName::try_from(url.host.clone())
            .map_err(|_| format!("{:?} is not a valid TLS server name", url.host))?;
        let mut tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("TLS handshake failed: {e}"))?;

        tls.write_all(request.as_bytes())
            .await
            .map_err(|e| format!("cannot reach {}:{}: send failed: {e}", url.host, url.port))?;
        read_capped(&mut tls)
            .await
            .map_err(|e| format!("cannot reach {}:{}: {e}", url.host, url.port))?
    } else {
        let mut stream = stream;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("cannot reach {}:{}: send failed: {e}", url.host, url.port))?;
        read_capped(&mut stream)
            .await
            .map_err(|e| format!("cannot reach {}:{}: {e}", url.host, url.port))?
    };

    parse_response(&raw)
}

/// The TLS client configuration, built once.
///
/// Rebuilding the root store copies every bundled trust anchor, and doing
/// that per feed per refresh was pure waste.
fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

async fn read_capped<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            // Plenty of servers close a `Connection: close` response without
            // a TLS close_notify. rustls reports that as an unexpected EOF,
            // which would throw away a complete feed. The body framing
            // (Content-Length or the chunked terminator) is what detects a
            // genuinely truncated response, so the EOF is taken as the end.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !buf.is_empty() => 0,
            Err(e) => return Err(format!("read failed: {e}")),
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_BODY_BYTES {
            return Err("response is too large to be a subscription".into());
        }
    }
    Ok(buf)
}

fn parse_response(raw: &[u8]) -> Result<Response, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response".to_string())?;

    let head = String::from_utf8_lossy(&raw[..split]);
    let body_bytes = &raw[split + 4..];

    let mut lines = head.lines();
    let status_line = lines.next().ok_or("empty HTTP response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("cannot parse status line {status_line:?}"))?;

    let mut location = None;
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "location" => location = Some(value.to_string()),
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => chunked = true,
            "content-length" => content_length = value.parse().ok(),
            _ => {}
        }
    }

    let body = if chunked {
        decode_chunked(body_bytes)?
    } else if let Some(length) = content_length {
        // A body shorter than advertised is a cut connection, and parsing
        // the fragment would replace a feed's nodes with a partial list.
        if body_bytes.len() < length {
            return Err(format!(
                "response truncated: {} of {length} bytes received",
                body_bytes.len()
            ));
        }
        body_bytes[..length].to_vec()
    } else {
        body_bytes.to_vec()
    };

    Ok(Response {
        status,
        location,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// Decode a `Transfer-Encoding: chunked` body.
fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "truncated chunk header".to_string())?;
        let header = String::from_utf8_lossy(&input[..line_end]);
        // A chunk header may carry extensions after a `;`.
        let size_text = header.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| format!("bad chunk size {size_text:?}"))?;

        input = &input[line_end + 2..];
        if size == 0 {
            break;
        }
        if size > input.len() {
            return Err("truncated chunk body".into());
        }
        out.extend_from_slice(&input[..size]);
        // Skip the chunk's trailing CRLF.
        input = input.get(size + 2..).unwrap_or(&[]);

        if out.len() > MAX_BODY_BYTES {
            return Err("response is too large to be a subscription".into());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VLESS: &str = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@155.117.13.26:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=example.com&pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY&sid=7963d08380d47375&fp=chrome&type=tcp#Node A";

    #[test]
    fn a_plain_feed_parses_into_profiles() {
        let body = format!("{VLESS}\ntrojan://pw@example.com:443?security=tls&type=tcp#Node B");
        let feed = parse_feed(&body);
        assert_eq!(feed.profiles.len(), 2);
        assert_eq!(feed.skipped, 0);
        assert_eq!(feed.profiles[0].remark, "Node A");
        assert_eq!(feed.profiles[0].protocol, "vless");
        assert_eq!(feed.profiles[0].address, "155.117.13.26");
        assert_eq!(feed.profiles[0].port, 443);
        // The original link is kept so the profile can be re-shared.
        assert!(feed.profiles[0].link.starts_with("vless://"));
    }

    #[test]
    fn a_base64_feed_parses_too() {
        use base64::Engine as _;
        let body = base64::engine::general_purpose::STANDARD.encode(VLESS);
        let feed = parse_feed(&body);
        assert_eq!(feed.profiles.len(), 1);
    }

    #[test]
    fn unreadable_entries_are_counted_not_fatal() {
        let body = format!("{VLESS}\nvless://zz5abd35-7efa-4bc8-85d4-a04f3798329f@host:443\n");
        let feed = parse_feed(&body);
        assert_eq!(feed.profiles.len(), 1);
        assert_eq!(feed.skipped, 1, "a bad entry should not lose the good ones");
    }

    #[test]
    fn an_unnamed_node_gets_a_generated_name() {
        let body = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@1.2.3.4:443?encryption=none&security=none&type=tcp";
        let feed = parse_feed(body);
        assert_eq!(feed.profiles.len(), 1);
        assert_eq!(feed.profiles[0].remark, "VLESS-1.2.3.4");
    }

    #[test]
    fn duplicate_nodes_and_a_byte_order_mark_are_handled() {
        let body = format!("\u{feff}{VLESS}\n{VLESS}\n");
        let feed = parse_feed(&body);
        assert_eq!(feed.profiles.len(), 1, "the repeated node was stored twice");
        assert_eq!(feed.skipped, 0, "the BOM cost the first link");
    }

    #[test]
    fn a_query_without_a_path_stays_out_of_the_host() {
        // `https://host?token=…` used to become the host `host?token=…`.
        let u = parse_url("https://sub.example.com?token=abc#frag").unwrap();
        assert_eq!(u.host, "sub.example.com");
        assert_eq!(u.path, "/?token=abc");
        let u = parse_url("http://example.com:8080/api/sub?x=1#ignored").unwrap();
        assert_eq!(u.port, 8080);
        assert_eq!(u.path, "/api/sub?x=1", "the fragment must never be sent");
    }

    #[test]
    fn the_host_header_carries_a_non_default_port() {
        assert_eq!(
            parse_url("https://a.example/x").unwrap().host_header(),
            "a.example"
        );
        assert_eq!(
            parse_url("https://a.example:8443/x").unwrap().host_header(),
            "a.example:8443"
        );
        assert_eq!(
            parse_url("http://[::1]:8080/x").unwrap().host_header(),
            "[::1]:8080"
        );
    }

    #[test]
    fn a_body_shorter_than_its_content_length_is_rejected() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort";
        assert!(parse_response(raw).is_err());
        // And trailing junk past the advertised length is not part of it.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        assert_eq!(parse_response(raw).unwrap().body, "hello");
    }

    #[test]
    fn a_scheme_relative_redirect_keeps_the_scheme() {
        let from = parse_url("https://a.example/sub").unwrap();
        let to = resolve_redirect(&from, "//b.example/other").unwrap();
        assert!(to.secure);
        assert_eq!(to.host, "b.example");
        assert_eq!(to.path, "/other");
    }

    #[test]
    fn urls_parse_with_sensible_defaults() {
        let u = parse_url("https://example.com/sub").unwrap();
        assert!(u.secure);
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/sub");

        let u = parse_url("http://example.com").unwrap();
        assert!(!u.secure);
        assert_eq!(u.port, 80);
        assert_eq!(u.path, "/", "a URL with no path should request root");

        let u = parse_url("https://example.com:8443/a/b?c=d").unwrap();
        assert_eq!(u.port, 8443);
        assert_eq!(u.path, "/a/b?c=d", "the query must survive");
    }

    #[test]
    fn ipv6_and_credentialed_urls_parse() {
        let u = parse_url("https://[2606:4700::1111]:8443/sub").unwrap();
        assert_eq!(u.host, "2606:4700::1111");
        assert_eq!(u.port, 8443);

        // Credentials are stripped rather than leaked into the Host header.
        let u = parse_url("https://user:pass@example.com/sub").unwrap();
        assert_eq!(u.host, "example.com");
    }

    #[test]
    fn bad_urls_are_rejected_with_a_reason() {
        assert!(parse_url("example.com/sub").is_err());
        assert!(parse_url("ftp://example.com")
            .unwrap_err()
            .contains("scheme"));
        assert!(parse_url("https://").unwrap_err().contains("host"));
    }

    #[test]
    fn redirects_resolve_absolute_and_relative_targets() {
        let from = parse_url("https://a.example/sub/list").unwrap();

        let abs = resolve_redirect(&from, "https://b.example/other").unwrap();
        assert_eq!(abs.host, "b.example");
        assert_eq!(abs.path, "/other");

        let root = resolve_redirect(&from, "/v2/list").unwrap();
        assert_eq!(root.host, "a.example");
        assert_eq!(root.path, "/v2/list");

        let rel = resolve_redirect(&from, "list2").unwrap();
        assert_eq!(rel.path, "/sub/list2");
    }

    #[test]
    fn a_content_length_response_is_parsed() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "hello");
    }

    #[test]
    fn a_chunked_response_is_reassembled() {
        // Two chunks plus the terminator, which is what most CDNs emit.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.body, "hello world");
    }

    #[test]
    fn chunk_extensions_are_ignored() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;name=value\r\nhello\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw).unwrap().body, "hello");
    }

    #[test]
    fn a_redirect_exposes_its_location() {
        let raw = b"HTTP/1.1 302 Found\r\nLocation: https://b.example/x\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 302);
        assert_eq!(r.location.as_deref(), Some("https://b.example/x"));
    }

    #[test]
    fn a_truncated_chunk_is_an_error_not_a_partial_feed() {
        // Silently accepting a truncated body would drop nodes without
        // saying so, and the update replaces the whole list.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\nshort\r\n";
        assert!(parse_response(raw).is_err());
    }

    #[test]
    fn a_malformed_response_is_rejected() {
        assert!(parse_response(b"not http at all").is_err());
        assert!(parse_response(b"\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn fetching_from_a_local_server_round_trips() {
        // A one-shot HTTP server, so the client is exercised end to end
        // without touching the network.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = format!("{VLESS}\n");

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut scratch = vec![0u8; 4096];
            let _ = socket.read(&mut scratch).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(response.as_bytes()).await;
        });

        let feed = fetch_feed(&format!("http://127.0.0.1:{port}/sub"))
            .await
            .expect("fetch succeeds");
        assert_eq!(feed.profiles.len(), 1);
        assert_eq!(feed.profiles[0].remark, "Node A");
    }

    #[tokio::test]
    async fn an_http_error_is_reported_with_its_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut scratch = vec![0u8; 4096];
            let _ = socket.read(&mut scratch).await;
            let _ = socket
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await;
        });

        let err = fetch_feed(&format!("http://127.0.0.1:{port}/missing"))
            .await
            .unwrap_err();
        assert!(err.contains("404"), "{err}");
    }

    #[tokio::test]
    async fn an_unreachable_host_fails_fast_with_a_reason() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let err = fetch_feed(&format!("http://127.0.0.1:{port}/sub"))
            .await
            .unwrap_err();
        assert!(err.contains("cannot reach"), "{err}");
    }
}
