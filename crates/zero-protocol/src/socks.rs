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

/// Run SOCKS5 with RFC 1929 username/password authentication. An empty
/// credential slice preserves the no-auth behavior used by the default
/// inbound and makes the authentication policy explicit at the call site.
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

/// Parse an HTTP proxy request.
///
/// `first` is the byte already consumed by protocol detection.
pub async fn accept_http<S>(stream: &mut S, first: u8) -> Result<Accepted, String>
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

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
}
