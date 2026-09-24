use super::parser::ProxyConfig;
use crate::probe::speed::{find_subslice, parse_status};
use crate::probe::trace::extract_colo;
use crate::probe::{connect_tcp, connect_tls, shared_tls_config};
use rand::Rng;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct ProxyValidationResult {
    pub success: bool,
    pub ttfb_ms: f64,
    pub throughput_mbps: f64,
    pub colo: Option<String>,
    pub error: Option<String>,
}

impl ProxyValidationResult {
    fn failed(error: impl Into<String>) -> Self {
        Self {
            success: false,
            ttfb_ms: 0.0,
            throughput_mbps: 0.0,
            colo: None,
            error: Some(error.into()),
        }
    }
}

/// Destination requested through the tunnel. Plain HTTP on port 80: the old
/// code sent a plain-HTTP request to port 443, which Cloudflare answers with
/// "400 plain HTTP request sent to HTTPS port" - and that error page was then
/// accepted as proof the proxy works.
const TEST_TARGET: &str = "cp.cloudflare.com";
const TEST_PORT: u16 = 80;
const HTTP_PAYLOAD: &[u8] =
    b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: cp.cloudflare.com\r\nUser-Agent: curl/7.88.1\r\nConnection: close\r\n\r\n";

const RESPONSE_BUF_BYTES: usize = 4096;
const MAX_UPGRADE_HEADER_BYTES: usize = 8192;

/// Validates that `cfg` actually works end to end through the edge `ip`: the
/// proxy protocol handshake is sent over the configured transport, and the
/// request it carries must come back as a real HTTP response from the far
/// side of the tunnel.
///
/// `timeout` bounds the whole validation (connect, TLS, upgrade, request).
/// Previously only the connect and TLS steps were bounded, so an edge that
/// accepted the WebSocket request and then went silent hung the scan worker
/// forever.
///
/// Transports that need a full client stack (gRPC, XHTTP, HTTP/2, QUIC,
/// mKCP) and protocols without a native implementation here (VMess) are
/// validated up to the transport layer only: TLS (and the WebSocket upgrade,
/// when used) must succeed against the edge.
pub async fn validate_proxy(
    ip: IpAddr,
    cfg: &ProxyConfig,
    timeout: Duration,
) -> ProxyValidationResult {
    match tokio::time::timeout(timeout, validate_inner(ip, cfg, timeout)).await {
        Ok(res) => res,
        Err(_) => ProxyValidationResult::failed("Proxy validation timed out"),
    }
}

async fn validate_inner(ip: IpAddr, cfg: &ProxyConfig, timeout: Duration) -> ProxyValidationResult {
    let tcp_timeout = (timeout / 3).clamp(Duration::from_millis(800), Duration::from_secs(3));
    let (tcp_stream, _) = match connect_tcp(ip, cfg.port, tcp_timeout).await {
        Ok(s) => s,
        Err(e) => return ProxyValidationResult::failed(format!("TCP connect: {}", e)),
    };

    let security = cfg.security.to_ascii_lowercase();
    if security.is_empty() || security == "none" {
        return validate_over(tcp_stream, cfg).await;
    }

    let tls_timeout = (timeout / 2).clamp(Duration::from_millis(1500), Duration::from_secs(4));
    let sni = if cfg.sni.is_empty() {
        cfg.host.as_str()
    } else {
        cfg.sni.as_str()
    };
    match connect_tls(tcp_stream, sni, shared_tls_config(), tls_timeout).await {
        Ok(s) => validate_over(s, cfg).await,
        Err(e) => ProxyValidationResult::failed(format!("TLS handshake: {}", e)),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Transport {
    Raw,
    WebSocket,
    HttpUpgrade,
    Unsupported,
}

fn transport_of(cfg: &ProxyConfig) -> Transport {
    match cfg.transport.to_ascii_lowercase().as_str() {
        "" | "tcp" | "raw" => Transport::Raw,
        "ws" | "websocket" => Transport::WebSocket,
        "httpupgrade" => Transport::HttpUpgrade,
        _ => Transport::Unsupported,
    }
}

async fn validate_over<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    cfg: &ProxyConfig,
) -> ProxyValidationResult {
    let start = Instant::now();
    let transport = transport_of(cfg);

    // Bytes that arrived with the upgrade response and belong to the stream.
    let mut leftover = Vec::new();
    if matches!(transport, Transport::WebSocket | Transport::HttpUpgrade) {
        match http_upgrade(&mut stream, cfg).await {
            Ok(rest) => leftover = rest,
            Err(e) => return ProxyValidationResult::failed(e),
        }
    }

    let protocol = cfg.protocol.to_ascii_lowercase();
    let packet = match protocol.as_str() {
        "vless" => match vless_request(&cfg.id_or_password) {
            Some(p) => p,
            None => return ProxyValidationResult::failed("Invalid VLESS UUID"),
        },
        "trojan" => trojan_request(&cfg.id_or_password),
        _ => Vec::new(),
    };

    if packet.is_empty() || transport == Transport::Unsupported {
        // Transport-level validation only (see `validate_proxy`).
        return ProxyValidationResult {
            success: true,
            ttfb_ms: start.elapsed().as_secs_f64() * 1000.0,
            throughput_mbps: 0.0,
            colo: None,
            error: None,
        };
    }

    let websocket = transport == Transport::WebSocket;
    let out = if websocket { ws_frame(&packet) } else { packet };
    let write_start = Instant::now();
    if let Err(e) = stream.write_all(&out).await {
        return ProxyValidationResult::failed(format!("Proxy payload write: {}", e));
    }
    let _ = stream.flush().await;

    let mut reader = PayloadReader {
        websocket,
        raw: leftover,
        payload: Vec::with_capacity(RESPONSE_BUF_BYTES),
        closed: false,
    };
    let mut ttfb = None;
    loop {
        match reader.fill(&mut stream).await {
            Ok(true) => {
                ttfb.get_or_insert_with(|| write_start.elapsed());
                if response_complete(&reader.payload, &protocol)
                    || reader.payload.len() >= RESPONSE_BUF_BYTES
                {
                    break;
                }
            }
            Ok(false) => break,
            Err(e) => {
                if reader.payload.is_empty() {
                    return ProxyValidationResult::failed(format!("Proxy read: {}", e));
                }
                break;
            }
        }
    }

    let Some(http) = tunnelled_http(&reader.payload, &protocol) else {
        return ProxyValidationResult::failed("Proxy returned no tunnelled HTTP response");
    };
    match parse_status(http) {
        Some(status) if (200..400).contains(&status) => ProxyValidationResult {
            success: true,
            ttfb_ms: ttfb.unwrap_or_else(|| write_start.elapsed()).as_secs_f64() * 1000.0,
            throughput_mbps: 0.0,
            colo: extract_colo(http),
            error: None,
        },
        Some(status) => {
            ProxyValidationResult::failed(format!("Tunnelled request returned HTTP {}", status))
        }
        None => ProxyValidationResult::failed("Proxy returned invalid non-HTTP data"),
    }
}

/// Performs the WebSocket / HTTP-upgrade handshake and returns any bytes
/// received after the response headers.
async fn http_upgrade<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &ProxyConfig,
) -> Result<Vec<u8>, String> {
    let path = if cfg.path.starts_with('/') {
        cfg.path.as_str()
    } else {
        "/"
    };
    let host = if cfg.host.is_empty() {
        cfg.sni.as_str()
    } else {
        cfg.host.as_str()
    };
    let key: [u8; 16] = rand::thread_rng().gen();
    let req = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Mozilla/5.0\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        path,
        host,
        base64_encode(&key)
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("WS write: {}", e))?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("WS read: {}", e))?;
        if n == 0 {
            return Err("WS upgrade: connection closed".to_string());
        }
        let prev = buf.len();
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&buf[prev.saturating_sub(3)..], b"\r\n\r\n") {
            let end = prev.saturating_sub(3) + pos + 4;
            return match parse_status(&buf) {
                Some(101) => Ok(buf.split_off(end)),
                _ => {
                    let line_end = find_subslice(&buf, b"\r\n").unwrap_or(buf.len()).min(64);
                    Err(format!(
                        "WS rejected: {}",
                        String::from_utf8_lossy(&buf[..line_end]).trim()
                    ))
                }
            };
        }
        if buf.len() > MAX_UPGRADE_HEADER_BYTES {
            return Err("WS upgrade: oversized response headers".to_string());
        }
    }
}

fn base64_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(data)
}

fn vless_request(uuid: &str) -> Option<Vec<u8>> {
    let uuid_bytes = parse_uuid(uuid)?;
    let mut packet = Vec::with_capacity(64 + HTTP_PAYLOAD.len());
    packet.push(0u8); // Version 0
    packet.extend_from_slice(&uuid_bytes);
    packet.push(0u8); // Addons length
    packet.push(1u8); // Command: TCP
    packet.extend_from_slice(&TEST_PORT.to_be_bytes());
    packet.push(2u8); // Address type: domain
    packet.push(TEST_TARGET.len() as u8);
    packet.extend_from_slice(TEST_TARGET.as_bytes());
    packet.extend_from_slice(HTTP_PAYLOAD);
    Some(packet)
}

fn trojan_request(password: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(128 + HTTP_PAYLOAD.len());
    packet.extend_from_slice(sha224_hex(password).as_bytes());
    packet.extend_from_slice(b"\r\n");
    packet.push(1u8); // CONNECT
    packet.push(3u8); // Address type: domain (SOCKS5 numbering)
    packet.push(TEST_TARGET.len() as u8);
    packet.extend_from_slice(TEST_TARGET.as_bytes());
    packet.extend_from_slice(&TEST_PORT.to_be_bytes());
    packet.extend_from_slice(b"\r\n");
    packet.extend_from_slice(HTTP_PAYLOAD);
    packet
}

/// The HTTP response carried back through the tunnel, after the protocol's
/// own response header. VLESS prefixes `[version=0, addons_len, addons..]`;
/// Trojan sends the payload as is. Anything else (for example the edge's own
/// "400 Bad Request" to an unparseable request) is not a tunnelled response.
fn tunnelled_http<'a>(payload: &'a [u8], protocol: &str) -> Option<&'a [u8]> {
    match protocol {
        "vless" => {
            if *payload.first()? != 0 {
                return None;
            }
            let addons = *payload.get(1)? as usize;
            let http = payload.get(2 + addons..)?;
            http.starts_with(b"HTTP/1.").then_some(http)
        }
        _ => payload.starts_with(b"HTTP/1.").then_some(payload),
    }
}

fn response_complete(payload: &[u8], protocol: &str) -> bool {
    let Some(http) = tunnelled_http(payload, protocol) else {
        // Enough bytes to know it is not a tunnelled response.
        return payload.len() >= 16;
    };
    let Some(head_end) = find_subslice(http, b"\r\n\r\n") else {
        return false;
    };
    // Non-2xx: the status line is all we need.
    if !matches!(parse_status(http), Some(200..=299)) {
        return true;
    }
    let body = &http[head_end + 4..];
    find_subslice(body, b"colo=").is_some_and(|p| body[p..].contains(&b'\n'))
}

/// Encodes `payload` as one masked binary WebSocket frame (RFC 6455 §5.2;
/// client frames must be masked).
fn ws_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x82); // FIN + binary
    let len = payload.len();
    if len < 126 {
        frame.push(0x80 | len as u8);
    } else if len <= u16::MAX as usize {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mask: [u8; 4] = rand::thread_rng().gen();
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    frame
}

/// Reads the tunnelled byte stream, unwrapping WebSocket frames if needed.
struct PayloadReader {
    websocket: bool,
    /// Undecoded bytes (WebSocket framing) not yet turned into payload.
    raw: Vec<u8>,
    payload: Vec<u8>,
    closed: bool,
}

impl PayloadReader {
    /// Appends more payload; `Ok(false)` once the stream is closed and
    /// nothing new arrived.
    async fn fill<S: AsyncRead + Unpin>(&mut self, stream: &mut S) -> std::io::Result<bool> {
        loop {
            let before = self.payload.len();
            if self.websocket {
                self.decode_frames()?;
            } else {
                self.payload.append(&mut self.raw);
            }
            if self.payload.len() > before {
                return Ok(true);
            }
            if self.closed {
                return Ok(false);
            }
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                self.closed = true;
            } else {
                self.raw.extend_from_slice(&chunk[..n]);
            }
        }
    }

    fn decode_frames(&mut self) -> std::io::Result<()> {
        loop {
            let (b0, b1) = match self.raw.get(..2) {
                Some(h) => (h[0], h[1]),
                None => return Ok(()),
            };
            let opcode = b0 & 0x0F;
            let masked = b1 & 0x80 != 0;
            let mut pos = 2;
            let len = match b1 & 0x7F {
                126 => {
                    let Some(ext) = self.raw.get(2..4) else {
                        return Ok(());
                    };
                    pos = 4;
                    u16::from_be_bytes([ext[0], ext[1]]) as usize
                }
                127 => {
                    let Some(ext) = self.raw.get(2..10) else {
                        return Ok(());
                    };
                    pos = 10;
                    let len = u64::from_be_bytes(ext.try_into().unwrap_or([0xFF; 8]));
                    usize::try_from(len).unwrap_or(usize::MAX)
                }
                n => n as usize,
            };
            if len > 1 << 20 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "oversized WebSocket frame",
                ));
            }
            let mask = if masked {
                let Some(m) = self.raw.get(pos..pos + 4) else {
                    return Ok(());
                };
                pos += 4;
                Some([m[0], m[1], m[2], m[3]])
            } else {
                None
            };
            let Some(data) = self.raw.get(pos..pos + len) else {
                return Ok(());
            };
            match opcode {
                0x0..=0x2 => match mask {
                    Some(m) => self
                        .payload
                        .extend(data.iter().enumerate().map(|(i, b)| b ^ m[i % 4])),
                    None => self.payload.extend_from_slice(data),
                },
                0x8 => self.closed = true,
                _ => {} // ping/pong/reserved: ignored
            }
            self.raw.drain(..pos + len);
        }
    }
}

fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    // Work on bytes: slicing a `str` at fixed offsets panics on multi-byte
    // characters, which a pasted share link can contain.
    let hex: Vec<u8> = s.bytes().filter(|&b| b != b'-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        bytes[i] = (hi * 16 + lo) as u8;
    }
    Some(bytes)
}

fn sha224_hex(input: &str) -> String {
    use sha2::{Digest, Sha224};
    let mut hasher = Sha224::new();
    hasher.update(input.as_bytes());
    let out = hasher.finalize();
    let mut s = String::with_capacity(56);
    for b in out {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_parsing_never_panics_on_non_ascii() {
        assert!(parse_uuid("00000000-0000-0000-0000-00000000000é").is_none());
        assert!(parse_uuid("ééééééééééééééééé").is_none());
        assert_eq!(
            parse_uuid("01234567-89ab-cdef-0123-456789ABCDEF").unwrap()[..4],
            [0x01, 0x23, 0x45, 0x67]
        );
    }

    #[test]
    fn edge_error_page_is_not_a_tunnelled_response() {
        let edge_400 = b"HTTP/1.1 400 Bad Request\r\nServer: cloudflare\r\n\r\n";
        assert!(tunnelled_http(edge_400, "vless").is_none());
        let tunnelled = b"\x00\x00HTTP/1.1 200 OK\r\n\r\nfl=1\ncolo=AMS\n";
        let http = tunnelled_http(tunnelled, "vless").unwrap();
        assert_eq!(parse_status(http), Some(200));
        assert_eq!(extract_colo(http).as_deref(), Some("AMS"));
        assert!(response_complete(tunnelled, "vless"));
    }

    #[test]
    fn websocket_frames_round_trip() {
        let payload: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let frame = ws_frame(&payload);
        let mut reader = PayloadReader {
            websocket: true,
            raw: frame,
            payload: Vec::new(),
            closed: false,
        };
        reader.decode_frames().unwrap();
        assert_eq!(reader.payload, payload);
        assert!(reader.raw.is_empty());

        // Unmasked server frames, split mid-header, plus a ping in between.
        let mut raw = vec![0x82, 3, b'a', b'b', b'c', 0x89, 0];
        raw.extend_from_slice(&[0x82, 2, b'd']);
        let mut reader = PayloadReader {
            websocket: true,
            raw,
            payload: Vec::new(),
            closed: false,
        };
        reader.decode_frames().unwrap();
        assert_eq!(reader.payload, b"abc");
        reader.raw.push(b'e');
        reader.decode_frames().unwrap();
        assert_eq!(reader.payload, b"abcde");
    }

    #[tokio::test]
    async fn vless_over_websocket_end_to_end() {
        // Minimal fake edge + VLESS server: completes the WS upgrade, checks
        // the framed VLESS header, and answers with a framed trace.
        let (client, mut server) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let n = server.read(&mut buf).await.unwrap();
            assert!(buf[..n].starts_with(b"GET /ws HTTP/1.1"));
            server
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
                .await
                .unwrap();
            let n = server.read(&mut buf).await.unwrap();
            let mut reader = PayloadReader {
                websocket: true,
                raw: buf[..n].to_vec(),
                payload: Vec::new(),
                closed: false,
            };
            reader.decode_frames().unwrap();
            assert_eq!(reader.payload[0], 0);
            assert_eq!(reader.payload[18], 1); // TCP command
            let body = b"\x00\x00HTTP/1.1 200 OK\r\n\r\nfl=1\ncolo=AMS\n";
            let mut frame = vec![0x82, body.len() as u8];
            frame.extend_from_slice(body);
            server.write_all(&frame).await.unwrap();
        });
        let cfg = ProxyConfig::parse(
            "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?type=ws&security=tls&path=%2Fws",
        )
        .unwrap();
        let res = validate_over(client, &cfg).await;
        assert!(res.success, "{:?}", res.error);
        assert_eq!(res.colo.as_deref(), Some("AMS"));
    }
}
