//! The HTTP/1.1 upgrade handshake.

use std::collections::BTreeMap;

use base64::Engine;
use sha1::{Digest, Sha1};
use zero_core::{Confidence, Failure, FailureKind, Stage};

/// GUID from RFC 6455 §1.3, used to derive `Sec-WebSocket-Accept`.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Debug, Clone)]
pub struct WsConfig {
    pub path: String,
    /// `Host:` header. May differ from the TLS SNI — that difference is the
    /// whole point of domain fronting.
    pub host: String,
    pub headers: BTreeMap<String, String>,
    /// Max bytes to carry in the handshake itself.
    pub early_data_len: usize,
    /// XHTTP request shaping; ignored by the other carriers.
    pub xhttp: std::sync::Arc<crate::xhttp_request::XhttpOptions>,
    /// Whether the carrier runs over TLS or REALITY (XHTTP writes `https`
    /// URLs into its padding headers then).
    pub secure: bool,
}

impl WsConfig {
    pub fn new(path: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
            headers: BTreeMap::new(),
            early_data_len: 0,
            xhttp: Default::default(),
            secure: false,
        }
    }
}

/// Generate a fresh 16-byte `Sec-WebSocket-Key`.
pub fn generate_key() -> String {
    let raw: [u8; 16] = rand::random();
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// The `Sec-WebSocket-Accept` a conforming server must return.
pub fn expected_accept(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// Build the upgrade request.
///
/// `early_data` is carried in `Sec-WebSocket-Protocol` as base64url without
/// padding, matching Xray (`transport/internet/websocket/dialer.go:153`).
/// This saves a full round trip, which matters most on the high-latency paths
/// Iranian users actually get.
pub fn build_request(cfg: &WsConfig, key: &str, early_data: &[u8]) -> Vec<u8> {
    let mut req = format!("GET {} HTTP/1.1\r\n", cfg.path);
    req.push_str(&format!("Host: {}\r\n", cfg.host));
    req.push_str("Upgrade: websocket\r\n");
    req.push_str("Connection: Upgrade\r\n");
    req.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    req.push_str("Sec-WebSocket-Version: 13\r\n");

    if !early_data.is_empty() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(early_data);
        req.push_str(&format!("Sec-WebSocket-Protocol: {encoded}\r\n"));
    }

    for (k, v) in &cfg.headers {
        // Host and the handshake headers are owned by us.
        let lower = k.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host"
                | "upgrade"
                | "connection"
                | "sec-websocket-key"
                | "sec-websocket-version"
                | "sec-websocket-protocol"
        ) {
            continue;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }

    req.push_str("\r\n");
    req.into_bytes()
}

/// Parse and validate the server's response.
///
/// Returns the number of bytes the response occupied, so the caller can keep
/// any payload the server pipelined immediately after it.
pub fn verify_response(buf: &[u8], key: &str) -> Result<Option<usize>, Failure> {
    // CDN edges add their own headers to the 101; 32 was tight enough that a
    // chatty edge made a valid upgrade fail as "malformed".
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);

    let status = match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(e) => {
            return Err(Failure::new(FailureKind::HttpMalformed, Stage::RequestSent)
                .with_confidence(Confidence::Confirmed)
                .with_detail(format!("malformed websocket response: {e}")))
        }
    };

    let code = resp.code.unwrap_or(0);
    if code != 101 {
        // A CDN edge that rejects the upgrade is a very different failure from
        // one that never answers, so it gets its own classification.
        let kind = match code {
            403 => FailureKind::Http403,
            421 => FailureKind::Http421,
            500..=599 => FailureKind::Http5xx,
            _ => FailureKind::WebsocketRejected,
        };
        return Err(Failure::new(kind, Stage::RequestSent)
            .with_confidence(Confidence::Confirmed)
            .with_detail(format!("websocket upgrade returned HTTP {code}")));
    }

    let accept = resp
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("sec-websocket-accept"))
        .map(|h| String::from_utf8_lossy(h.value).trim().to_string());

    match accept {
        Some(got) if got == expected_accept(key) => Ok(Some(status)),
        Some(got) => Err(
            Failure::new(FailureKind::WebsocketMalformed, Stage::RequestSent)
                .with_confidence(Confidence::Confirmed)
                .with_detail(format!("bad Sec-WebSocket-Accept: {got}")),
        ),
        None => Err(
            Failure::new(FailureKind::WebsocketMalformed, Stage::RequestSent)
                .with_confidence(Confidence::Confirmed)
                .with_detail("response has no Sec-WebSocket-Accept"),
        ),
    }
}

/// Accept a server-side WebSocket upgrade. The early-data subprotocol is
/// decoded into the stream's initial payload, so protocol parsers see exactly
/// the same byte sequence whether the client used early data or a normal
/// post-upgrade write.
pub async fn accept_server<S>(
    mut inner: S,
    cfg: &WsConfig,
) -> Result<crate::ws::WebSocketStream<S>, Failure>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use bytes::BytesMut;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = BytesMut::with_capacity(1024);
    // Only bytes that arrived since the last scan (plus the three before them,
    // for a terminator split across reads) are searched, so a slow drip of
    // header bytes costs linear rather than quadratic time.
    let mut scanned = 0usize;
    let head_end = loop {
        if let Some(end) = buffer[scanned..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break scanned + end + 4;
        }
        scanned = buffer.len().saturating_sub(3);
        if buffer.len() >= 16 * 1024 {
            return Err(
                Failure::new(FailureKind::WebsocketMalformed, Stage::RequestSent)
                    .with_detail("websocket request headers exceed the size limit"),
            );
        }
        let n = inner
            .read_buf(&mut buffer)
            .await
            .map_err(|error| Failure::from_io(&error, Stage::RequestSent))?;
        if n == 0 {
            return Err(
                Failure::new(FailureKind::WebsocketMalformed, Stage::RequestSent)
                    .with_detail("connection closed during websocket request"),
            );
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    request.parse(&buffer[..head_end]).map_err(|error| {
        Failure::new(FailureKind::HttpMalformed, Stage::RequestSent)
            .with_detail(format!("malformed websocket request: {error}"))
    })?;
    if request.method != Some("GET") {
        return Err(
            Failure::new(FailureKind::WebsocketRejected, Stage::RequestSent)
                .with_detail("websocket request method is not GET"),
        );
    }
    let path = request.path.unwrap_or("");
    if path.split_once('?').map_or(path, |(base, _)| base) != cfg.path {
        return Err(
            Failure::new(FailureKind::WebsocketRejected, Stage::RequestSent)
                .with_detail("websocket path does not match the configured path"),
        );
    }
    let key = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("sec-websocket-key"))
        .and_then(|header| std::str::from_utf8(header.value).ok())
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| {
            Failure::new(FailureKind::WebsocketMalformed, Stage::RequestSent)
                .with_detail("websocket request has no Sec-WebSocket-Key")
        })?;
    // Early data rides in `Sec-WebSocket-Protocol`. Mirror Xray's server
    // (`transport/internet/websocket/hub.go`): accept either base64 alphabet,
    // treat a value that does not decode as an ordinary subprotocol rather
    // than an error, and echo the header back when it did carry early data —
    // a browser-based client fails the upgrade if its offered subprotocol is
    // not selected in the 101.
    let protocol = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("sec-websocket-protocol"))
        .and_then(|header| std::str::from_utf8(header.value).ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let early = protocol.and_then(|value| {
        let normalized: String = value
            .chars()
            .filter(|c| *c != '=')
            .map(|c| match c {
                '+' => '-',
                '/' => '_',
                other => other,
            })
            .collect();
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(normalized)
            .ok()
            .filter(|decoded| !decoded.is_empty())
    });

    let mut response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
        expected_accept(key)
    );
    if let (Some(value), Some(_)) = (protocol, early.as_ref()) {
        response.push_str("Sec-WebSocket-Protocol: ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    inner
        .write_all(response.as_bytes())
        .await
        .map_err(|error| Failure::from_io(&error, Stage::RequestSent))?;
    inner
        .flush()
        .await
        .map_err(|error| Failure::from_io(&error, Stage::RequestSent))?;

    let leftover = buffer.split_off(head_end);
    Ok(crate::ws::WebSocketStream::new_server(
        inner,
        leftover,
        early.unwrap_or_default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_matches_rfc6455_example() {
        // RFC 6455 §1.3 worked example.
        assert_eq!(
            expected_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn request_has_required_headers() {
        let cfg = WsConfig::new("/vl/abc", "edge.example");
        let req = String::from_utf8(build_request(&cfg, "KEY", b"")).unwrap();
        assert!(req.starts_with("GET /vl/abc HTTP/1.1\r\n"));
        assert!(req.contains("Host: edge.example\r\n"));
        assert!(req.contains("Upgrade: websocket\r\n"));
        assert!(req.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
        assert!(!req.contains("Sec-WebSocket-Protocol"));
    }

    #[test]
    fn early_data_uses_base64url_without_padding() {
        let cfg = WsConfig::new("/p", "h");
        // 0xFB 0xEF is "++8=" in standard base64 and "--8" url-safe unpadded,
        // so it catches both the +/- substitution and the dropped padding.
        let req = String::from_utf8(build_request(&cfg, "K", &[0xFB, 0xEF])).unwrap();
        assert!(req.contains("Sec-WebSocket-Protocol: --8\r\n"), "{req}");

        // And the / -> _ substitution.
        let req = String::from_utf8(build_request(&cfg, "K", &[0xFF, 0xFE])).unwrap();
        assert!(req.contains("Sec-WebSocket-Protocol: __4\r\n"), "{req}");
    }

    #[test]
    fn custom_headers_cannot_override_handshake_headers() {
        let mut cfg = WsConfig::new("/p", "real.host");
        cfg.headers.insert("Host".into(), "evil.host".into());
        cfg.headers.insert("User-Agent".into(), "zray".into());
        let req = String::from_utf8(build_request(&cfg, "K", b"")).unwrap();
        assert!(req.contains("Host: real.host\r\n"));
        assert!(!req.contains("evil.host"));
        assert!(req.contains("User-Agent: zray\r\n"));
    }

    #[test]
    fn accepts_valid_101_response() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            expected_accept(key)
        );
        let n = verify_response(resp.as_bytes(), key).unwrap().unwrap();
        assert_eq!(n, resp.len());
    }

    #[test]
    fn keeps_pipelined_payload_offset() {
        let key = "k";
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            expected_accept(key)
        );
        let mut buf = head.clone().into_bytes();
        buf.extend_from_slice(b"EXTRA");
        assert_eq!(verify_response(&buf, key).unwrap(), Some(head.len()));
    }

    #[test]
    fn partial_response_is_incomplete_not_an_error() {
        assert!(verify_response(b"HTTP/1.1 101 Switch", "k")
            .unwrap()
            .is_none());
    }

    #[test]
    fn rejects_wrong_accept_key() {
        let resp = "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: wrong\r\n\r\n";
        let f = verify_response(resp.as_bytes(), "k").unwrap_err();
        assert_eq!(f.kind, FailureKind::WebsocketMalformed);
    }

    #[test]
    fn classifies_403_distinctly() {
        let resp = "HTTP/1.1 403 Forbidden\r\n\r\n";
        let f = verify_response(resp.as_bytes(), "k").unwrap_err();
        assert_eq!(f.kind, FailureKind::Http403);
        // 403 is deterministic: retrying the same path is pointless.
        assert!(!f.kind.is_transient());
    }

    #[test]
    fn classifies_5xx_distinctly() {
        let f = verify_response(b"HTTP/1.1 502 Bad Gateway\r\n\r\n", "k").unwrap_err();
        assert_eq!(f.kind, FailureKind::Http5xx);
        assert!(f.kind.is_transient());
    }

    #[test]
    fn generated_keys_are_unique_and_decodable() {
        let a = generate_key();
        let b = generate_key();
        assert_ne!(a, b);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&a)
                .unwrap()
                .len(),
            16
        );
    }
}
