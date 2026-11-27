//! SOCKS5 and HTTP CONNECT inbounds.
//!
//! Both normalise to the same `Destination`, so nothing downstream can tell
//! which one a session arrived on (RESEARCH-01 §11). The two are detected on
//! one port by their first byte: SOCKS5 always begins `0x05`, and no HTTP
//! method does.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zero_core::{Address, Destination, Network};

pub const SOCKS5: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USERPASS: u8 = 0x02;
const AUTH_UNACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

/// What an inbound handshake produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub destination: Destination,
    /// Bytes already read from the client that belong to the payload.
    ///
    /// HTTP proxying without CONNECT starts mid-request, so the first request
    /// line and headers must be replayed to the origin.
    pub prefix: Vec<u8>,
    pub kind: InboundKind,
}

/// One SOCKS5 UDP request or response datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub destination: Destination,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub username: Box<str>,
    pub password: Box<str>,
}

/// Decode the RFC 1928 UDP request header.
pub fn parse_udp_datagram(packet: &[u8]) -> Result<UdpDatagram, String> {
    if packet.len() < 4 || packet[..2] != [0, 0] {
        return Err("invalid SOCKS5 UDP reserved bytes".into());
    }
    if packet[2] != 0 {
        return Err("fragmented SOCKS5 UDP datagrams are not supported".into());
    }
    let (address, offset) = decode_address(packet, 3)?;
    if offset + 2 > packet.len() {
        return Err("truncated SOCKS5 UDP port".into());
    }
    let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    Ok(UdpDatagram {
        destination: Destination::udp(address, port),
        payload: packet[offset + 2..].to_vec(),
    })
}

/// Encode a SOCKS5 UDP response/request datagram.
pub fn encode_udp_datagram(destination: &Destination, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > u16::MAX as usize {
        return Err("SOCKS5 UDP payload exceeds 65535 bytes".into());
    }
    let mut out = vec![0, 0, 0];
    encode_address(&destination.address, destination.port, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

fn decode_address(packet: &[u8], mut offset: usize) -> Result<(Address, usize), String> {
    if offset >= packet.len() {
        return Err("missing SOCKS5 UDP address type".into());
    }
    let atyp = packet[offset];
    offset += 1;
    let address = match atyp {
        ATYP_IPV4 => {
            if offset + 4 > packet.len() {
                return Err("truncated SOCKS5 UDP IPv4 address".into());
            }
            let ip = IpAddr::V4(Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            ));
            offset += 4;
            Address::Ip(ip)
        }
        ATYP_IPV6 => {
            if offset + 16 > packet.len() {
                return Err("truncated SOCKS5 UDP IPv6 address".into());
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&packet[offset..offset + 16]);
            offset += 16;
            Address::Ip(IpAddr::V6(bytes.into()))
        }
        ATYP_DOMAIN => {
            let len = *packet
                .get(offset)
                .ok_or_else(|| "truncated SOCKS5 UDP domain length".to_string())?
                as usize;
            offset += 1;
            if offset + len > packet.len() {
                return Err("truncated SOCKS5 UDP domain".into());
            }
            let name = std::str::from_utf8(&packet[offset..offset + len])
                .map_err(|_| "SOCKS5 UDP domain is not UTF-8")?;
            offset += len;
            Address::parse_host(name)
        }
        other => return Err(format!("unsupported SOCKS5 UDP address type {other}")),
    };
    Ok((address, offset))
}

fn encode_address(address: &Address, port: u16, out: &mut Vec<u8>) -> Result<(), String> {
    match address {
        Address::Ip(IpAddr::V4(ip)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(name) => {
            if name.len() > u8::MAX as usize {
                return Err("SOCKS5 UDP domain is too long".into());
            }
            out.push(ATYP_DOMAIN);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    Socks5,
    HttpConnect,
    /// Plain HTTP proxying; the request must be forwarded, not swallowed.
    HttpForward,
}

/// Peek the first byte to choose a protocol.
pub fn detect(first: u8) -> InboundKind {
    if first == SOCKS5 {
        InboundKind::Socks5
    } else {
        // Distinguishing CONNECT from other methods needs the request line,
        // which the HTTP path reads for itself.
        InboundKind::HttpConnect
    }
}

// ------------------------------------------------------------------ socks5

/// Run the SOCKS5 greeting and request.
pub async fn accept_socks5<S>(stream: &mut S) -> Result<Accepted, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    accept_socks5_with_credentials(stream, &[]).await
}

/// Run an HTTP forward/CONNECT request, optionally requiring a
/// `Proxy-Authorization: Basic` credential.
///
/// An empty credential slice preserves the no-auth behavior used by the
/// default inbound and makes the authentication policy explicit at the call
/// site, the same way [`accept_socks5_with_credentials`] does. Without this,
/// an `http` inbound had no way to be protected at all: `socks_auth` was only
/// consulted on the SOCKS5 path, so enabling "allow LAN" exposed an
/// unauthenticated HTTP proxy even when accounts were configured.
pub async fn accept_http_with_credentials<S>(
    stream: &mut S,
    first: u8,
    credentials: &[Credential],
) -> Result<Accepted, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    accept_http_inner(stream, first, credentials).await
}

/// Run an HTTP forward/CONNECT request with no authentication.
pub async fn accept_http<S>(stream: &mut S, first: u8) -> Result<Accepted, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    accept_http_inner(stream, first, &[]).await
}

async fn accept_http_inner<S>(
    stream: &mut S,
    first: u8,
    credentials: &[Credential],
) -> Result<Accepted, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = BytesMut::with_capacity(1024);
    buf.put_u8(first);

    let head_end = loop {
        if let Some(p) = find_head_end(&buf) {
            break p;
        }
        if buf.len() >= MAX_HTTP_HEAD {
            return Err("HTTP request head exceeded the size limit".into());
        }
        let n = stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| format!("reading HTTP request: {e}"))?;
        if n == 0 {
            return Err("connection closed before the HTTP request completed".into());
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    if !credentials.is_empty() && !basic_auth_ok(&head, credentials) {
        stream
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"proxy\"\r\n\
Content-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .map_err(|e| format!("writing 407: {e}"))?;
        return Err("HTTP proxy credentials missing or wrong".into());
    }

    let request_line = head.lines().next().unwrap_or("").to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        let destination = parse_authority(&target, 443)
            .ok_or_else(|| format!("cannot parse CONNECT target {target:?}"))?;
        return Ok(Accepted {
            destination,
            prefix: buf[head_end..].to_vec(),
            kind: InboundKind::HttpConnect,
        });
    }

    // Absolute-form request, or fall back to the Host header.
    let destination = parse_absolute_target(&target)
        .or_else(|| {
            head.lines()
                .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                .and_then(|l| l.split_once(':'))
                .and_then(|(_, v)| parse_authority(v.trim(), 80))
        })
        .ok_or_else(|| format!("cannot determine destination from {request_line:?}"))?;

    // The request, head included, must reach the origin — but as the origin
    // expects it, not as a proxy does. See [`origin_form_head`].
    let mut prefix = origin_form_head(&head).into_bytes();
    prefix.extend_from_slice(&buf[head_end..]);
    Ok(Accepted {
        destination,
        prefix,
        kind: InboundKind::HttpForward,
    })
}

/// Whether the head carries a `Proxy-Authorization: Basic` value matching one
/// of `credentials`.
///
/// Every configured account is tried, and no early return reveals which one
/// matched — a proxy that answered differently per account would let a
/// neighbour on the LAN enumerate valid usernames.
fn basic_auth_ok(head: &str, credentials: &[Credential]) -> bool {
    use base64::Engine as _;
    let mut found = false;
    for line in head.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        let Some(encoded) = value
            .trim()
            .strip_prefix("Basic ")
            .or_else(|| value.trim().strip_prefix("basic "))
        else {
            continue;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            continue;
        };
        let Ok(pair) = String::from_utf8(decoded) else {
            continue;
        };
        let Some((user, password)) = pair.split_once(':') else {
            continue;
        };
        found = true;
        // Every account is tried and the results are combined, so a caller
        // cannot tell which one matched, or how many were left to try.
        let matched = credentials.iter().fold(false, |seen, account| {
            seen | (constant_time_eq(account.username.as_bytes(), user.as_bytes())
                & constant_time_eq(account.password.as_bytes(), password.as_bytes()))
        });
        found &= matched;
    }
    found
}

/// Equal length and contents, without an early exit on the first difference.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub async fn accept_socks5_with_credentials<S>(
    stream: &mut S,
    credentials: &[Credential],
) -> Result<Accepted, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Greeting: VER NMETHODS METHODS...
    let mut head = [0u8; 2];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|e| format!("socks5 greeting: {e}"))?;
    if head[0] != SOCKS5 {
        return Err(format!("unsupported SOCKS version {}", head[0]));
    }
    let n = head[1] as usize;
    let mut methods = vec![0u8; n];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|e| format!("socks5 methods: {e}"))?;

    let required_method = if credentials.is_empty() {
        AUTH_NONE
    } else {
        AUTH_USERPASS
    };
    if !methods.contains(&required_method) {
        let _ = stream.write_all(&[SOCKS5, AUTH_UNACCEPTABLE]).await;
        return Err("client offered no supported SOCKS5 auth method".into());
    }
    stream
        .write_all(&[SOCKS5, required_method])
        .await
        .map_err(|e| format!("socks5 method reply: {e}"))?;

    if required_method == AUTH_USERPASS {
        let mut version = [0u8; 2];
        stream
            .read_exact(&mut version)
            .await
            .map_err(|e| format!("socks5 username/password version: {e}"))?;
        if version[0] != 0x01 {
            let _ = stream.write_all(&[0x01, 0x01]).await;
            return Err("unsupported SOCKS5 username/password version".into());
        }
        let mut username = vec![0u8; version[1] as usize];
        stream
            .read_exact(&mut username)
            .await
            .map_err(|e| format!("socks5 username: {e}"))?;
        let mut password_len = [0u8; 1];
        stream
            .read_exact(&mut password_len)
            .await
            .map_err(|e| format!("socks5 password length: {e}"))?;
        let mut password = vec![0u8; password_len[0] as usize];
        stream
            .read_exact(&mut password)
            .await
            .map_err(|e| format!("socks5 password: {e}"))?;
        let valid = credentials.iter().any(|credential| {
            credential.username.as_bytes() == username.as_slice()
                && credential.password.as_bytes() == password.as_slice()
        });
        stream
            .write_all(&[0x01, if valid { 0x00 } else { 0x01 }])
            .await
            .map_err(|e| format!("socks5 auth reply: {e}"))?;
        if !valid {
            return Err("SOCKS5 username/password authentication failed".into());
        }
    }

    // Request: VER CMD RSV ATYP ADDR PORT
    let mut req = [0u8; 4];
    stream
        .read_exact(&mut req)
        .await
        .map_err(|e| format!("socks5 request: {e}"))?;
    if req[0] != SOCKS5 {
        return Err(format!("unsupported SOCKS version {}", req[0]));
    }

    let network = match req[1] {
        CMD_CONNECT => Network::Tcp,
        CMD_UDP_ASSOCIATE => Network::Udp,
        other => {
            let _ = reply(stream, REP_CMD_NOT_SUPPORTED, None).await;
            return Err(format!("unsupported SOCKS5 command {other}"));
        }
    };

    let address = read_address(stream, req[3]).await?;
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .map_err(|e| format!("socks5 port: {e}"))?;

    Ok(Accepted {
        destination: Destination::new(address, u16::from_be_bytes(port), network),
        prefix: Vec::new(),
        kind: InboundKind::Socks5,
    })
}

async fn read_address<S: AsyncRead + Unpin>(stream: &mut S, atyp: u8) -> Result<Address, String> {
    match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            Ok(Address::Ip(IpAddr::V4(Ipv4Addr::from(b))))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            Ok(Address::Ip(IpAddr::V6(Ipv6Addr::from(b))))
        }
        ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await.map_err(|e| e.to_string())?;
            let mut b = vec![0u8; l[0] as usize];
            stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            let name = String::from_utf8(b).map_err(|_| "domain is not UTF-8".to_string())?;
            // A client may send a literal in a domain field; normalise it so
            // routing does not treat "1.2.3.4" as a name.
            Ok(Address::parse_host(&name))
        }
        other => Err(format!("unsupported SOCKS5 address type {other}")),
    }
}

/// Send a SOCKS5 reply.
pub async fn reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u8,
    bound: Option<Destination>,
) -> std::io::Result<()> {
    let mut out = BytesMut::with_capacity(22);
    out.put_u8(SOCKS5);
    out.put_u8(code);
    out.put_u8(0x00); // reserved

    match bound.as_ref().map(|b| (&b.address, b.port)) {
        Some((Address::Ip(IpAddr::V6(ip)), port)) => {
            out.put_u8(ATYP_IPV6);
            out.put_slice(&ip.octets());
            out.put_u16(port);
        }
        Some((Address::Ip(IpAddr::V4(ip)), port)) => {
            out.put_u8(ATYP_IPV4);
            out.put_slice(&ip.octets());
            out.put_u16(port);
        }
        // A domain bound address is not useful to the client; report 0.0.0.0.
        _ => {
            out.put_u8(ATYP_IPV4);
            out.put_slice(&[0, 0, 0, 0]);
            out.put_u16(0);
        }
    }

    stream.write_all(&out).await
}

// -------------------------------------------------------------------- http

/// Largest request head we will buffer before giving up.
const MAX_HTTP_HEAD: usize = 16 * 1024;

/// Rewrite a forward-proxy request head into what an origin server expects.
///
/// A browser talking to an HTTP proxy sends `GET http://host/path HTTP/1.1`.
/// Handed on verbatim, that absolute form makes many origins answer 404 or
/// 400 — which is what "the system proxy works for HTTPS sites but not plain
/// HTTP ones" in Firefox was. So, as Xray does:
///
/// * the request target becomes origin form (`/path?query`);
/// * proxy-only headers (`Proxy-Connection`, `Proxy-Authorization`) are
///   dropped, and a `Host` header is added if the client left it out;
/// * `Connection: close` is forced. Only this first request is rewritten,
///   so a kept-alive connection would carry the browser's next request —
///   possibly for a different site — to this origin, untouched.
fn origin_form_head(head: &str) -> String {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("HTTP/1.1");

    let (authority, path) = match target.split_once("://") {
        Some((_, rest)) => match rest.find('/') {
            Some(slash) => (Some(&rest[..slash]), &rest[slash..]),
            None => match rest.find('?') {
                Some(q) => (Some(&rest[..q]), &rest[q..]),
                None => (Some(rest), "/"),
            },
        },
        None => (None, target),
    };
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };

    let mut out = format!("{method} {path} {version}\r\n");
    let mut has_host = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let name = line.split(':').next().unwrap_or("").trim();
        if name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("keep-alive")
        {
            continue;
        }
        has_host |= name.eq_ignore_ascii_case("host");
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !has_host {
        if let Some(authority) = authority {
            out.push_str(&format!("Host: {authority}\r\n"));
        }
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_absolute_target(target: &str) -> Option<Destination> {
    let (scheme, rest) = target.split_once("://")?;
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    parse_authority(authority, default_port)
}

/// Parse `host`, `host:port`, `[v6]` or `[v6]:port`.
pub fn parse_authority(s: &str, default_port: u16) -> Option<Destination> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some((host, port)) = zero_core::address::split_host_port(s) {
        return Some(Destination::tcp(Address::parse_host(host), port));
    }
    Some(Destination::tcp(Address::parse_host(s), default_port))
}

/// The response sent after a successful CONNECT.
pub const CONNECT_OK: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

/// Run the client side of an HTTP `CONNECT` over a stream that is already
/// connected to the proxy: the other way an upstream proxy is spoken to.
///
/// The request names the destination as `host:port` (a name is sent as a
/// name, so the proxy resolves it), with Basic credentials when there are
/// any. The reply head is read one byte at a time up to its blank line, so no
/// byte of the tunnelled stream is consumed with it and the stream is
/// returned as it is. Any 2xx is success; the rest is reported with the
/// proxy's own status line.
pub async fn connect_http<S>(
    mut stream: S,
    credential: Option<&Credential>,
    destination: &Destination,
) -> Result<S, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use base64::Engine as _;
    if destination.network != Network::Tcp {
        return Err("an HTTP proxy carries TCP only".into());
    }
    let authority = match &destination.address {
        Address::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", destination.port),
        Address::Domain(name) if name.bytes().any(|b| b <= b' ' || b == 0x7f) => {
            return Err("destination name has characters that cannot be sent".into());
        }
        other => format!("{other}:{}", destination.port),
    };
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(c) = credential {
        let token = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", c.username, c.password));
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
    stream.write_all(request.as_bytes()).await.map_err(io_err)?;

    let mut head = Vec::with_capacity(128);
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 8192 {
            return Err("HTTP proxy reply is too long".into());
        }
        head.push(stream.read_u8().await.map_err(io_err)?);
    }
    let text = String::from_utf8_lossy(&head);
    let status_line = text.lines().next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or("");
    let code: u16 = parts.next().and_then(|code| code.parse().ok()).unwrap_or(0);
    if !version.starts_with("HTTP/1.") {
        return Err("upstream is not an HTTP proxy".into());
    }
    match code {
        200..=299 => Ok(stream),
        407 => Err("HTTP proxy rejected the user name or password".into()),
        _ => Err(format!("HTTP proxy refused the tunnel: {status_line}")),
    }
}

/// Run the client side of a SOCKS5 CONNECT over a stream that is already
/// connected to the proxy (RFC 1928, with RFC 1929 user/password).
///
/// This is how a local Tor, Orbot or Psiphon client becomes an upstream: they
/// all expose SOCKS5. A domain name is sent as a name (ATYP 3), never resolved
/// here, so the far side does the lookup. That matters for Tor, where a local
/// lookup would leak the name outside the circuit.
///
/// Only CONNECT is spoken, so UDP destinations are refused. On success the
/// reply (including its bound address, which nobody needs) has been consumed
/// and the stream carries the tunnelled bytes from here on.
pub async fn connect_socks5<S>(
    mut stream: S,
    credential: Option<&Credential>,
    destination: &Destination,
) -> Result<S, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if destination.network != Network::Tcp {
        return Err("SOCKS5 upstream carries TCP only".into());
    }
    // RFC 1929 caps user name and password at 255 bytes each.
    if let Some(c) = credential {
        if c.username.len() > 255 || c.password.len() > 255 {
            return Err("SOCKS5 user name or password is longer than 255 bytes".into());
        }
    }

    // Offer "no auth" first and user/password only when we have one, so a
    // server that wants neither is not asked a question it cannot answer.
    let greeting: &[u8] = if credential.is_some() {
        &[SOCKS5, 2, AUTH_NONE, AUTH_USERPASS]
    } else {
        &[SOCKS5, 1, AUTH_NONE]
    };
    stream.write_all(greeting).await.map_err(io_err)?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await.map_err(io_err)?;
    if choice[0] != SOCKS5 {
        return Err("upstream is not a SOCKS5 server".into());
    }
    match (choice[1], credential) {
        (AUTH_NONE, _) => {}
        (AUTH_USERPASS, Some(c)) => {
            let mut auth = Vec::with_capacity(3 + c.username.len() + c.password.len());
            auth.push(0x01);
            auth.push(c.username.len() as u8);
            auth.extend_from_slice(c.username.as_bytes());
            auth.push(c.password.len() as u8);
            auth.extend_from_slice(c.password.as_bytes());
            stream.write_all(&auth).await.map_err(io_err)?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await.map_err(io_err)?;
            if status[1] != 0 {
                return Err("SOCKS5 upstream rejected the user name or password".into());
            }
        }
        // 0xFF, or a method we never offered.
        _ => return Err("SOCKS5 upstream accepts none of our login methods".into()),
    }

    let mut request = BytesMut::with_capacity(22);
    request.put_slice(&[SOCKS5, CMD_CONNECT, 0]);
    match &destination.address {
        Address::Ip(IpAddr::V4(ip)) => {
            request.put_u8(ATYP_IPV4);
            request.put_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            request.put_u8(ATYP_IPV6);
            request.put_slice(&ip.octets());
        }
        Address::Domain(name) => {
            if name.is_empty() || name.len() > 255 {
                return Err("SOCKS5 domain must be 1 to 255 bytes".into());
            }
            request.put_u8(ATYP_DOMAIN);
            request.put_u8(name.len() as u8);
            request.put_slice(name.as_bytes());
        }
    }
    request.put_u16(destination.port);
    stream.write_all(&request).await.map_err(io_err)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(io_err)?;
    if head[0] != SOCKS5 {
        return Err("SOCKS5 reply has the wrong version".into());
    }
    if head[1] != REP_SUCCESS {
        return Err(format!("SOCKS5 upstream refused: {}", reply_text(head[1])));
    }
    // Drain the bound address so the first tunnelled byte is the payload.
    let bound = match head[3] {
        ATYP_IPV4 => 4 + 2,
        ATYP_IPV6 => 16 + 2,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(io_err)?;
            len[0] as usize + 2
        }
        _ => return Err("SOCKS5 reply has an unknown address type".into()),
    };
    let mut skip = [0u8; 258];
    stream
        .read_exact(&mut skip[..bound])
        .await
        .map_err(io_err)?;
    Ok(stream)
}

fn io_err(error: std::io::Error) -> String {
    format!("SOCKS5 upstream: {error}")
}

/// RFC 1928 §6 reply codes, in words. Tor adds 0xF0-0xF7 (proxy extensions).
fn reply_text(code: u8) -> &'static str {
    match code {
        0x01 => "general failure",
        0x02 => "not allowed",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        0xF0 => "onion service descriptor not found",
        0xF1 => "onion service descriptor invalid",
        0xF2 => "onion service introduction failed",
        0xF3 => "onion service rendezvous failed",
        0xF4 => "onion service client authorization needed",
        0xF5 => "onion service client authorization wrong",
        0xF6 => "onion service address invalid",
        0xF7 => "onion service introduction timed out",
        _ => "unknown reply code",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// A one-shot SOCKS5 server on the far end of a duplex pipe: replies to
    /// the greeting with `method`, optionally checks user/password, then
    /// answers the CONNECT with `reply` and returns the request it saw.
    async fn fake_upstream(
        mut server: tokio::io::DuplexStream,
        method: u8,
        reply: u8,
        bound_domain: bool,
    ) -> (Vec<u8>, tokio::io::DuplexStream) {
        let mut hello = [0u8; 2];
        server.read_exact(&mut hello).await.unwrap();
        let mut methods = vec![0u8; hello[1] as usize];
        server.read_exact(&mut methods).await.unwrap();
        server.write_all(&[SOCKS5, method]).await.unwrap();
        if method == AUTH_USERPASS {
            let mut ver_len = [0u8; 2];
            server.read_exact(&mut ver_len).await.unwrap();
            let mut user = vec![0u8; ver_len[1] as usize];
            server.read_exact(&mut user).await.unwrap();
            let mut plen = [0u8; 1];
            server.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; plen[0] as usize];
            server.read_exact(&mut pass).await.unwrap();
            let ok = user == b"alice" && pass == b"secret";
            server
                .write_all(&[1, if ok { 0 } else { 1 }])
                .await
                .unwrap();
            if !ok {
                return (Vec::new(), server);
            }
        }
        let mut head = [0u8; 4];
        server.read_exact(&mut head).await.unwrap();
        let mut request = head.to_vec();
        let rest = match head[3] {
            ATYP_IPV4 => 4,
            ATYP_IPV6 => 16,
            _ => {
                let mut len = [0u8; 1];
                server.read_exact(&mut len).await.unwrap();
                request.push(len[0]);
                len[0] as usize
            }
        } + 2;
        let mut tail = vec![0u8; rest];
        server.read_exact(&mut tail).await.unwrap();
        request.extend_from_slice(&tail);
        let mut answer = vec![SOCKS5, reply, 0];
        if bound_domain {
            answer.extend_from_slice(&[ATYP_DOMAIN, 3, b'a', b'b', b'c', 0x1F, 0x90]);
        } else {
            answer.extend_from_slice(&[ATYP_IPV4, 0, 0, 0, 0, 0, 0]);
        }
        server.write_all(&answer).await.unwrap();
        (request, server)
    }

    #[tokio::test]
    async fn client_connect_sends_the_name_and_leaves_payload_untouched() {
        let (client, server) = duplex(4096);
        let upstream = tokio::spawn(fake_upstream(server, AUTH_NONE, REP_SUCCESS, true));
        let target = Destination::tcp(Address::domain("example.onion"), 443);
        let mut stream = connect_socks5(client, None, &target).await.unwrap();
        let (request, mut server) = upstream.await.unwrap();
        // The domain went out as a name, not a locally resolved address.
        assert_eq!(&request[..4], &[SOCKS5, CMD_CONNECT, 0, ATYP_DOMAIN]);
        assert_eq!(&request[5..18], b"example.onion");
        assert_eq!(&request[18..], &443u16.to_be_bytes());
        // The bound address was drained: the next byte is application data.
        server.write_all(b"hi").await.unwrap();
        let mut got = [0u8; 2];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hi");
    }

    #[tokio::test]
    async fn client_connect_encodes_ip_destinations() {
        let (client, server) = duplex(4096);
        let upstream = tokio::spawn(fake_upstream(server, AUTH_NONE, REP_SUCCESS, false));
        let target = Destination::tcp(Address::Ip("192.0.2.7".parse().unwrap()), 8080);
        connect_socks5(client, None, &target).await.unwrap();
        let (request, _) = upstream.await.unwrap();
        assert_eq!(
            request,
            [SOCKS5, CMD_CONNECT, 0, ATYP_IPV4, 192, 0, 2, 7, 0x1F, 0x90]
        );
    }

    #[tokio::test]
    async fn client_connect_logs_in_with_user_and_password() {
        let good = Credential {
            username: "alice".into(),
            password: "secret".into(),
        };
        let (client, server) = duplex(4096);
        let upstream = tokio::spawn(fake_upstream(server, AUTH_USERPASS, REP_SUCCESS, false));
        let target = Destination::tcp(Address::domain("example.com"), 80);
        connect_socks5(client, Some(&good), &target).await.unwrap();
        upstream.await.unwrap();

        let bad = Credential {
            username: "alice".into(),
            password: "wrong".into(),
        };
        let (client, server) = duplex(4096);
        tokio::spawn(fake_upstream(server, AUTH_USERPASS, REP_SUCCESS, false));
        let error = connect_socks5(client, Some(&bad), &target)
            .await
            .err()
            .unwrap();
        assert!(error.contains("rejected"), "{error}");
    }

    #[tokio::test]
    async fn client_connect_reports_refusals_and_bad_peers() {
        let target = Destination::tcp(Address::domain("example.com"), 80);

        let (client, server) = duplex(4096);
        tokio::spawn(fake_upstream(server, AUTH_NONE, 0x05, false));
        let error = connect_socks5(client, None, &target).await.err().unwrap();
        assert!(error.contains("connection refused"), "{error}");

        // Tor's own extension codes are named, not "unknown".
        let (client, server) = duplex(4096);
        tokio::spawn(fake_upstream(server, AUTH_NONE, 0xF0, false));
        let error = connect_socks5(client, None, &target).await.err().unwrap();
        assert!(
            error.contains("onion service descriptor not found"),
            "{error}"
        );

        // No acceptable method.
        let (client, server) = duplex(4096);
        tokio::spawn(fake_upstream(server, AUTH_UNACCEPTABLE, REP_SUCCESS, false));
        let error = connect_socks5(client, None, &target).await.err().unwrap();
        assert!(error.contains("none of our login methods"), "{error}");

        // Something that is not SOCKS5 at all (an HTTP server).
        let (client, mut server) = duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 3];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(b"HT").await.unwrap();
        });
        let error = connect_socks5(client, None, &target).await.err().unwrap();
        assert!(error.contains("not a SOCKS5"), "{error}");

        // UDP is refused before anything is written.
        let (client, _server) = duplex(64);
        let udp = Destination::new(Address::domain("example.com"), 53, Network::Udp);
        let error = connect_socks5(client, None, &udp).await.err().unwrap();
        assert!(error.contains("TCP only"), "{error}");
    }

    #[test]
    fn detects_socks5_by_first_byte() {
        assert_eq!(detect(0x05), InboundKind::Socks5);
        assert_eq!(detect(b'C'), InboundKind::HttpConnect);
        assert_eq!(detect(b'G'), InboundKind::HttpConnect);
    }

    #[tokio::test]
    async fn socks5_connect_to_domain() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            // greeting
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut r = [0u8; 2];
            client.read_exact(&mut r).await.unwrap();
            assert_eq!(r, [0x05, 0x00]);
            // CONNECT example.com:443
            let mut req = vec![0x05, 0x01, 0x00, 0x03, 11];
            req.extend_from_slice(b"example.com");
            req.extend_from_slice(&443u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
        });

        let a = accept_socks5(&mut server).await.unwrap();
        assert_eq!(a.destination.address.as_domain(), Some("example.com"));
        assert_eq!(a.destination.port, 443);
        assert_eq!(a.destination.network, Network::Tcp);
        assert!(a.prefix.is_empty());
    }

    #[tokio::test]
    async fn socks5_connect_to_ipv4() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut r = [0u8; 2];
            client.read_exact(&mut r).await.unwrap();
            let mut req = vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4];
            req.extend_from_slice(&80u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
        });

        let a = accept_socks5(&mut server).await.unwrap();
        assert_eq!(a.destination.address, Address::parse_host("1.2.3.4"));
        assert_eq!(a.destination.port, 80);
    }

    #[tokio::test]
    async fn socks5_udp_associate_is_recognised() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut r = [0u8; 2];
            client.read_exact(&mut r).await.unwrap();
            let mut req = vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0];
            req.extend_from_slice(&0u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
        });

        let a = accept_socks5(&mut server).await.unwrap();
        assert_eq!(a.destination.network, Network::Udp);
    }

    #[test]
    fn socks5_udp_datagram_roundtrips_domain_and_payload() {
        let input = UdpDatagram {
            destination: Destination::udp(Address::domain("example.com"), 53),
            payload: b"query".to_vec(),
        };
        let encoded = encode_udp_datagram(&input.destination, &input.payload).unwrap();
        assert_eq!(parse_udp_datagram(&encoded).unwrap(), input);
    }

    #[test]
    fn socks5_udp_rejects_fragments() {
        assert!(parse_udp_datagram(&[0, 0, 1, ATYP_IPV4, 1, 2, 3, 4, 0, 53]).is_err());
    }

    #[tokio::test]
    async fn socks5_rejects_unsupported_auth() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            // Only GSSAPI offered.
            client.write_all(&[0x05, 0x01, 0x01]).await.unwrap();
            let mut r = [0u8; 2];
            let _ = client.read_exact(&mut r).await;
            assert_eq!(r, [0x05, 0xFF]);
        });
        assert!(accept_socks5(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn socks5_password_authenticates_before_connect_request() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            client
                .write_all(&[0x05, 0x01, AUTH_USERPASS])
                .await
                .unwrap();
            let mut method = [0u8; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [0x05, AUTH_USERPASS]);
            client
                .write_all(&[
                    0x01, 0x04, b'u', b's', b'e', b'r', 0x06, b's', b'e', b'c', b'r', b'e', b't',
                ])
                .await
                .unwrap();
            let mut auth = [0u8; 2];
            client.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth, [0x01, 0x00]);
            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80])
                .await
                .unwrap();
        });
        let credentials = [Credential {
            username: "user".into(),
            password: "secret".into(),
        }];
        let accepted = accept_socks5_with_credentials(&mut server, &credentials)
            .await
            .unwrap();
        assert_eq!(
            accepted.destination,
            Destination::tcp(Address::parse_host("1.2.3.4"), 80)
        );
    }

    #[tokio::test]
    async fn socks5_domain_field_holding_a_literal_is_normalised() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut r = [0u8; 2];
            client.read_exact(&mut r).await.unwrap();
            let mut req = vec![0x05, 0x01, 0x00, 0x03, 7];
            req.extend_from_slice(b"1.2.3.4");
            req.extend_from_slice(&443u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
        });

        let a = accept_socks5(&mut server).await.unwrap();
        assert!(
            a.destination.address.is_ip(),
            "literal should not stay a domain"
        );
    }

    #[tokio::test]
    async fn http_connect_extracts_authority() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            client
                .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                .await
                .unwrap();
        });

        let mut first = [0u8; 1];
        server.read_exact(&mut first).await.unwrap();
        let a = accept_http(&mut server, first[0]).await.unwrap();
        assert_eq!(a.kind, InboundKind::HttpConnect);
        assert_eq!(a.destination.address.as_domain(), Some("example.com"));
        assert_eq!(a.destination.port, 443);
        assert!(a.prefix.is_empty());
    }

    #[tokio::test]
    async fn http_forward_preserves_the_whole_request() {
        let (mut client, mut server) = duplex(4096);
        let raw = b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        tokio::spawn(async move {
            client.write_all(raw).await.unwrap();
        });

        let mut first = [0u8; 1];
        server.read_exact(&mut first).await.unwrap();
        let a = accept_http(&mut server, first[0]).await.unwrap();
        assert_eq!(a.kind, InboundKind::HttpForward);
        assert_eq!(a.destination.port, 80);
        assert_eq!(a.destination.address.as_domain(), Some("example.com"));
        // The origin must receive the request it would have received directly.
        assert_eq!(
            String::from_utf8(a.prefix).unwrap(),
            "GET /path HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn http_forward_strips_proxy_headers_and_keeps_the_body() {
        let (mut client, mut server) = duplex(4096);
        let raw = b"POST http://example.com:8080?q=1 HTTP/1.1\r\n\
Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic eA==\r\n\
Content-Length: 4\r\n\r\nbody";
        tokio::spawn(async move {
            client.write_all(raw).await.unwrap();
        });

        let mut first = [0u8; 1];
        server.read_exact(&mut first).await.unwrap();
        let a = accept_http(&mut server, first[0]).await.unwrap();
        assert_eq!(a.destination.port, 8080);
        assert_eq!(
            String::from_utf8(a.prefix).unwrap(),
            "POST /?q=1 HTTP/1.1\r\nContent-Length: 4\r\nHost: example.com:8080\r\n\
Connection: close\r\n\r\nbody"
        );
    }

    fn credential(user: &str, pass: &str) -> Credential {
        Credential {
            username: user.into(),
            password: pass.into(),
        }
    }

    fn basic(user: &str, pass: &str) -> String {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
        )
    }

    /// `allow_lan` bound an `http` inbound to every interface, and
    /// `socks_auth` was consulted only on the SOCKS5 path — so accounts
    /// configured for an HTTP proxy protected nothing.
    #[tokio::test]
    async fn an_http_proxy_with_credentials_refuses_an_anonymous_client() {
        let (mut client, mut server) = duplex(4096);
        // The client has to outlive the refusal, so it reads the reply and
        // hands it back rather than dropping its end first.
        let seen = tokio::spawn(async move {
            client
                .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                .await
                .unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            reply
        });

        let credentials = [credential("alice", "s3cret")];
        let mut first = [0u8; 1];
        server.read_exact(&mut first).await.unwrap();
        let error = accept_http_with_credentials(&mut server, first[0], &credentials)
            .await
            .unwrap_err();
        assert!(error.contains("credentials"), "got: {error}");

        drop(server);
        let reply = String::from_utf8(seen.await.unwrap()).unwrap();
        assert!(reply.starts_with("HTTP/1.1 407"), "got: {reply}");
        assert!(reply.contains("Proxy-Authenticate: Basic"), "got: {reply}");
    }

    #[tokio::test]
    async fn an_http_proxy_with_credentials_refuses_a_wrong_password() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            let _ = client
                .write_all(
                    b"CONNECT example.com:443 HTTP/1.1\r\n\
Proxy-Authorization: Basic YWxpY2U6d3Jvbmc=\r\n\r\n",
                )
                .await;
        });

        let credentials = [credential("alice", "s3cret")];
        let mut first = [0u8; 1];
        server.read_exact(&mut first).await.unwrap();
        assert!(
            accept_http_with_credentials(&mut server, first[0], &credentials)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_http_proxy_with_credentials_admits_the_right_one() {
        let (mut client, mut server) = duplex(4096);
        let raw = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: {}\r\n\r\n",
            basic("alice", "s3cret")
        );
        tokio::spawn(async move {
            client.write_all(raw.as_bytes()).await.unwrap();
        });

        let credentials = [credential("bob", "other"), credential("alice", "s3cret")];
        let mut first = [0u8; 1];
        server.read_exact(&mut first).await.unwrap();
        let accepted = accept_http_with_credentials(&mut server, first[0], &credentials)
            .await
            .expect("the configured account must be admitted");
        assert_eq!(accepted.kind, InboundKind::HttpConnect);
        assert_eq!(
            accepted.destination.address.as_domain(),
            Some("example.com")
        );
    }

    /// The credential is for the proxy, so it must not reach the origin.
    #[tokio::test]
    async fn an_authenticated_http_forward_does_not_leak_the_header() {
        let (mut client, mut server) = duplex(4096);
        let raw = format!(
            "GET http://example.com/path HTTP/1.1\r\nProxy-Authorization: {}\r\n\r\n",
            basic("alice", "s3cret")
        );
        tokio::spawn(async move {
            client.write_all(raw.as_bytes()).await.unwrap();
        });

        let credentials = [credential("alice", "s3cret")];
        let mut first = [0u8; 1];
        server.read_exact(&mut first).await.unwrap();
        let accepted = accept_http_with_credentials(&mut server, first[0], &credentials)
            .await
            .unwrap();
        let forwarded = String::from_utf8(accepted.prefix).unwrap();
        assert!(!forwarded.to_lowercase().contains("proxy-authorization"));
    }

    /// No accounts configured must behave exactly as before.
    #[tokio::test]
    async fn an_http_proxy_without_credentials_stays_open() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            client
                .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
        });
        let mut first = [0u8; 1];
        server.read_exact(&mut first).await.unwrap();
        assert!(accept_http(&mut server, first[0]).await.is_ok());
    }

    #[tokio::test]
    async fn http_falls_back_to_host_header() {
        let (mut client, mut server) = duplex(4096);
        tokio::spawn(async move {
            client
                .write_all(b"GET /only/path HTTP/1.1\r\nHost: fallback.example:8080\r\n\r\n")
                .await
                .unwrap();
        });

        let mut first = [0u8; 1];
        server.read_exact(&mut first).await.unwrap();
        let a = accept_http(&mut server, first[0]).await.unwrap();
        assert_eq!(a.destination.address.as_domain(), Some("fallback.example"));
        assert_eq!(a.destination.port, 8080);
    }

    #[test]
    fn authority_parsing_handles_v6_and_defaults() {
        let d = parse_authority("[::1]:443", 80).unwrap();
        assert_eq!(d.port, 443);
        assert!(d.address.is_ip());

        let d = parse_authority("example.com", 80).unwrap();
        assert_eq!(d.port, 80);

        assert!(parse_authority("", 80).is_none());
    }

    #[tokio::test]
    async fn reply_encodes_success() {
        let (mut client, mut server) = duplex(64);
        reply(&mut server, REP_SUCCESS, None).await.unwrap();
        let mut b = [0u8; 10];
        client.read_exact(&mut b).await.unwrap();
        assert_eq!(&b[..4], &[0x05, 0x00, 0x00, 0x01]);
    }

    /// Reads from `stream` until the request head ends, then answers `reply`.
    async fn fake_proxy(mut stream: tokio::io::DuplexStream, reply: &'static [u8]) -> Vec<u8> {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        stream.write_all(reply).await.unwrap();
        head
    }

    #[tokio::test]
    async fn http_connect_names_the_destination_and_leaves_the_payload_untouched() {
        let (client, server) = duplex(1024);
        let proxy = tokio::spawn(fake_proxy(
            server,
            b"HTTP/1.1 200 Connection established\r\n\r\nhello",
        ));
        let credential = Credential {
            username: "a".into(),
            password: "b".into(),
        };
        let mut stream = connect_http(
            client,
            Some(&credential),
            &Destination::tcp(Address::domain("example.com"), 443),
        )
        .await
        .unwrap();
        // The tunnelled bytes sent right behind the reply are still there.
        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
        let head = String::from_utf8(proxy.await.unwrap()).unwrap();
        assert!(
            head.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(head.contains("Host: example.com:443\r\n"));
        // base64("a:b")
        assert!(head.contains("Proxy-Authorization: Basic YTpi\r\n"));
    }

    #[tokio::test]
    async fn http_connect_brackets_an_ipv6_literal_and_sends_no_login_unasked() {
        let (client, server) = duplex(1024);
        let proxy = tokio::spawn(fake_proxy(server, b"HTTP/1.0 200 OK\r\n\r\n"));
        connect_http(
            client,
            None,
            &Destination::tcp(Address::parse_host("2001:db8::1"), 80),
        )
        .await
        .unwrap();
        let head = String::from_utf8(proxy.await.unwrap()).unwrap();
        assert!(
            head.starts_with("CONNECT [2001:db8::1]:80 HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(!head.contains("Proxy-Authorization"));
    }

    #[tokio::test]
    async fn http_connect_reports_what_the_proxy_said() {
        for (reply, wanted) in [
            (
                &b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..],
                "user name or password",
            ),
            (&b"HTTP/1.1 502 Bad Gateway\r\n\r\n"[..], "502 Bad Gateway"),
            (&b"SSH-2.0-OpenSSH\r\n\r\n"[..], "not an HTTP proxy"),
        ] {
            let (client, server) = duplex(1024);
            let reply: &'static [u8] = Box::leak(reply.to_vec().into_boxed_slice());
            tokio::spawn(fake_proxy(server, reply));
            let error = connect_http(
                client,
                None,
                &Destination::tcp(Address::domain("x.test"), 1),
            )
            .await
            .unwrap_err();
            assert!(error.contains(wanted), "{error}");
        }
    }

    #[tokio::test]
    async fn http_connect_refuses_udp_and_names_that_would_break_the_request() {
        let (client, _server) = duplex(64);
        assert!(connect_http(
            client,
            None,
            &Destination::udp(Address::domain("x.test"), 1)
        )
        .await
        .is_err());
        let (client, _server) = duplex(64);
        let bad = Destination::tcp(Address::domain("x.test\r\nX-Evil: 1"), 80);
        assert!(connect_http(client, None, &bad).await.is_err());
    }
}
