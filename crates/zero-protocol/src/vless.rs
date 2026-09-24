//! VLESS.
//!
//! VLESS is a thin multiplexing header with no cryptography of its own — all
//! confidentiality comes from the security layer beneath it (TLS or REALITY).
//! That is why `encryption` must be `none`: it is not a weakness, it is the
//! protocol's design.
//!
//! Request header:
//!
//! ```text
//! 1  version (0)
//! 16 uuid
//! 1  addons length M
//! M  addons (protobuf-encoded Addons{ flow })
//! 1  command (1=TCP, 2=UDP, 3=MUX)
//! 2  port, big endian (TCP/UDP only)
//! 1  address type (1=IPv4, 2=domain, 3=IPv6) (TCP/UDP only)
//! N  address (TCP/UDP only)
//! .. payload
//! ```
//!
//! Response header is `version`, `addons length`, `addons`, then payload.

use bytes::{BufMut, BytesMut};
use zero_core::{Address, Destination, Network};

pub const VERSION: u8 = 0;

pub const CMD_TCP: u8 = 1;
pub const CMD_UDP: u8 = 2;
pub const CMD_MUX: u8 = 3;

pub const ADDR_IPV4: u8 = 1;
pub const ADDR_DOMAIN: u8 = 2;
pub const ADDR_IPV6: u8 = 3;

/// The authenticated request decoded by a VLESS server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub uuid: [u8; 16],
    pub destination: Destination,
    pub flow: Option<Box<str>>,
    pub mux: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestParse {
    Incomplete,
    Complete { request: Request, consumed: usize },
}

/// Parse one VLESS request header without touching the payload that follows.
/// The caller can therefore hand the same stream directly to the relay after
/// consuming exactly `consumed` bytes from its input buffer.
pub fn parse_request(buf: &[u8]) -> Result<RequestParse, String> {
    if buf.len() < 18 {
        return Ok(RequestParse::Incomplete);
    }
    if buf[0] != VERSION {
        return Err(format!(
            "unexpected VLESS request version {} (expected {VERSION})",
            buf[0]
        ));
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&buf[1..17]);
    let addon_len = buf[17] as usize;
    let command_at = 18 + addon_len;
    if buf.len() < command_at + 1 {
        return Ok(RequestParse::Incomplete);
    }
    let flow = if buf[18..command_at]
        .windows(FLOW_VISION.len())
        .any(|window| window == FLOW_VISION.as_bytes())
    {
        Some(FLOW_VISION.into())
    } else {
        None
    };
    let (network, port, at, address, mux) = if buf[command_at] == CMD_MUX {
        // Xray's Mux command has no port/address bytes. The carrier target is
        // the fixed dispatcher endpoint and each logical destination is in
        // the first Mux metadata frame that follows this header.
        (
            Network::Tcp,
            crate::mux::CONTROL_PORT,
            command_at + 1,
            Address::domain(crate::mux::CONTROL_HOST),
            true,
        )
    } else {
        let network = match buf[command_at] {
            CMD_TCP => Network::Tcp,
            CMD_UDP => Network::Udp,
            other => return Err(format!("unsupported VLESS command {other}")),
        };
        if buf.len() < command_at + 4 {
            return Ok(RequestParse::Incomplete);
        }
        let port = u16::from_be_bytes([buf[command_at + 1], buf[command_at + 2]]);
        let at = command_at + 3;
        let address = match buf[at] {
            ADDR_IPV4 => {
                let at = at + 1;
                if buf.len() < at + 4 {
                    return Ok(RequestParse::Incomplete);
                }
                let ip = std::net::Ipv4Addr::new(buf[at], buf[at + 1], buf[at + 2], buf[at + 3]);
                (at + 4, Address::from(ip))
            }
            ADDR_DOMAIN => {
                let at = at + 1;
                let len = *buf
                    .get(at)
                    .ok_or_else(|| "missing VLESS domain length".to_string())?
                    as usize;
                let at = at + 1;
                if buf.len() < at + len {
                    return Ok(RequestParse::Incomplete);
                }
                let name = std::str::from_utf8(&buf[at..at + len])
                    .map_err(|_| "VLESS domain is not UTF-8")?;
                (at + len, Address::domain(name))
            }
            ADDR_IPV6 => {
                let at = at + 1;
                if buf.len() < at + 16 {
                    return Ok(RequestParse::Incomplete);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[at..at + 16]);
                (at + 16, Address::from(std::net::Ipv6Addr::from(octets)))
            }
            other => return Err(format!("unsupported VLESS address type {other}")),
        };
        (network, port, address.0, address.1, false)
    };

    Ok(RequestParse::Complete {
        request: Request {
            uuid,
            destination: Destination::new(address, port, network),
            flow,
            mux,
        },
        consumed: at,
    })
}

/// VLESS UDP body framing: every datagram is a two-byte big-endian length
/// followed by the payload. The destination was carried in the request
/// header, so it is not repeated for each packet.
pub fn encode_udp_frame(payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return Err("VLESS UDP payload must contain 1..=65535 bytes".into());
    }
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Parse one complete VLESS UDP body frame, returning the consumed byte count.
pub fn decode_udp_frame(buf: &[u8]) -> Result<(Vec<u8>, usize), String> {
    if buf.len() < 2 {
        return Err("incomplete VLESS UDP frame length".into());
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if len == 0 {
        return Err("empty VLESS UDP frame".into());
    }
    if buf.len() < 2 + len {
        return Err("incomplete VLESS UDP frame".into());
    }
    Ok((buf[2..2 + len].to_vec(), 2 + len))
}

/// The Vision flow identifier.
pub const FLOW_VISION: &str = "xtls-rprx-vision";

/// Encode the `Addons` protobuf.
///
/// Only field 1 (`flow`, a length-delimited string) is ever populated, so
/// rather than pull in a protobuf runtime for one optional string we emit the
/// two-byte tag/length prefix directly. Xray emits addons *only* for Vision;
/// any other flow writes a bare zero length, and matching that exactly matters
/// because the byte is observable.
pub fn encode_addons(flow: &str) -> Vec<u8> {
    if flow != FLOW_VISION {
        return vec![0];
    }
    let f = flow.as_bytes();
    let mut inner = Vec::with_capacity(2 + f.len());
    inner.push(0x0A); // field 1, wire type 2 (length-delimited)
    inner.push(f.len() as u8);
    inner.extend_from_slice(f);

    let mut out = Vec::with_capacity(1 + inner.len());
    out.push(inner.len() as u8);
    out.extend_from_slice(&inner);
    out
}

/// Write the address+port portion, which is port-first in VLESS.
pub fn encode_address(dst: &Destination, out: &mut BytesMut) {
    out.put_u16(dst.port);
    match &dst.address {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.put_u8(ADDR_IPV4);
            out.put_slice(&ip.octets());
        }
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.put_u8(ADDR_IPV6);
            out.put_slice(&ip.octets());
        }
        Address::Domain(d) => {
            out.put_u8(ADDR_DOMAIN);
            let bytes = d.as_bytes();
            // A domain longer than 255 cannot be represented; callers must
            // have rejected it far earlier, but truncating silently would
            // send traffic to the wrong host.
            debug_assert!(bytes.len() <= 255, "domain too long for VLESS");
            out.put_u8(bytes.len() as u8);
            out.put_slice(bytes);
        }
    }
}

/// Build the full request header.
pub fn encode_request(uuid: &[u8; 16], flow: &str, dst: &Destination) -> BytesMut {
    let mut out = BytesMut::with_capacity(64);
    out.put_u8(VERSION);
    out.put_slice(uuid);
    out.put_slice(&encode_addons(flow));
    out.put_u8(match dst.network {
        Network::Tcp => CMD_TCP,
        Network::Udp => CMD_UDP,
    });
    encode_address(dst, &mut out);
    out
}

/// Build the outer VLESS request for Xray Mux. The logical destination is
/// carried by the first Mux metadata frame, so the VLESS target is the fixed
/// control endpoint used by Xray's mux dispatcher.
pub fn encode_mux_request(uuid: &[u8; 16], flow: &str) -> BytesMut {
    // Xray's RequestCommandMux is a special VLESS command: unlike TCP and
    // UDP it is followed by no port/address bytes. The fixed endpoint is
    // represented by the command itself; the logical target is in Mux frames.
    let mut out = BytesMut::with_capacity(32);
    out.put_u8(VERSION);
    out.put_slice(uuid);
    out.put_slice(&encode_addons(flow));
    out.put_u8(CMD_MUX);
    out
}

/// Outcome of trying to parse a response header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseParse {
    /// Need more bytes; nothing consumed.
    Incomplete,
    /// Header complete, occupying this many bytes.
    Complete { consumed: usize },
}

/// Parse the response header prefix.
///
/// Returns how many bytes the header occupied so the caller can hand the rest
/// to the application untouched.
pub fn parse_response(buf: &[u8]) -> Result<ResponseParse, String> {
    if buf.len() < 2 {
        return Ok(ResponseParse::Incomplete);
    }
    if buf[0] != VERSION {
        return Err(format!(
            "unexpected VLESS response version {} (expected {VERSION})",
            buf[0]
        ));
    }
    let addon_len = buf[1] as usize;
    let total = 2 + addon_len;
    if buf.len() < total {
        return Ok(ResponseParse::Incomplete);
    }
    Ok(ResponseParse::Complete { consumed: total })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn dst_domain() -> Destination {
        Destination::tcp(Address::domain("example.com"), 443)
    }

    #[test]
    fn no_flow_writes_a_single_zero_byte() {
        assert_eq!(encode_addons(""), vec![0]);
        assert_eq!(encode_addons("none"), vec![0]);
    }

    #[test]
    fn vision_addons_match_protobuf_layout() {
        let a = encode_addons(FLOW_VISION);
        // 1 length byte + 2 tag/len bytes + 16 string bytes
        assert_eq!(a.len(), 19);
        assert_eq!(a[0], 18, "addons payload length");
        assert_eq!(a[1], 0x0A, "field 1, wire type 2");
        assert_eq!(a[2], 16, "string length");
        assert_eq!(&a[3..], FLOW_VISION.as_bytes());
    }

    #[test]
    fn request_header_layout_for_domain() {
        let uuid = [0xABu8; 16];
        let req = encode_request(&uuid, "", &dst_domain());

        assert_eq!(req[0], VERSION);
        assert_eq!(&req[1..17], &uuid);
        assert_eq!(req[17], 0, "no addons");
        assert_eq!(req[18], CMD_TCP);
        assert_eq!(u16::from_be_bytes([req[19], req[20]]), 443);
        assert_eq!(req[21], ADDR_DOMAIN);
        assert_eq!(req[22], 11, "len(example.com)");
        assert_eq!(&req[23..34], b"example.com");
        assert_eq!(req.len(), 34);
    }

    #[test]
    fn request_header_layout_for_ipv4() {
        let d = Destination::tcp(Address::parse_host("1.2.3.4"), 80);
        let req = encode_request(&[0u8; 16], "", &d);
        assert_eq!(req[18], CMD_TCP);
        assert_eq!(u16::from_be_bytes([req[19], req[20]]), 80);
        assert_eq!(req[21], ADDR_IPV4);
        assert_eq!(&req[22..26], &[1, 2, 3, 4]);
        assert_eq!(req.len(), 26);
    }

    #[test]
    fn request_header_layout_for_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let d = Destination::tcp(Address::Ip(ip), 443);
        let req = encode_request(&[0u8; 16], "", &d);
        assert_eq!(req[21], ADDR_IPV6);
        assert_eq!(req.len(), 22 + 16);
    }

    #[test]
    fn udp_uses_the_udp_command() {
        let d = Destination::udp(Address::domain("a.io"), 53);
        let req = encode_request(&[0u8; 16], "", &d);
        assert_eq!(req[18], CMD_UDP);
    }

    #[test]
    fn udp_frame_roundtrips_and_reports_consumed_bytes() {
        let mut wire = encode_udp_frame(b"hello").unwrap();
        wire.extend_from_slice(b"next");
        let (payload, consumed) = decode_udp_frame(&wire).unwrap();
        assert_eq!(payload, b"hello");
        assert_eq!(consumed, 7);
        assert_eq!(&wire[consumed..], b"next");
    }

    #[test]
    fn udp_frame_rejects_empty_oversized_and_incomplete_payloads() {
        assert!(encode_udp_frame(&[]).is_err());
        assert!(decode_udp_frame(&[0, 0]).is_err());
        assert!(decode_udp_frame(&[0, 4, 1, 2]).is_err());
        assert!(encode_udp_frame(&vec![0u8; u16::MAX as usize + 1]).is_err());
    }

    #[test]
    fn parses_request_and_preserves_payload_boundary() {
        let destination = Destination::tcp(Address::domain("origin.example"), 8443);
        let mut wire = encode_request(&[7u8; 16], FLOW_VISION, &destination).to_vec();
        wire.extend_from_slice(b"payload");
        let RequestParse::Complete { request, consumed } = parse_request(&wire).unwrap() else {
            panic!("request should be complete");
        };
        assert_eq!(request.uuid, [7u8; 16]);
        assert_eq!(request.destination, destination);
        assert_eq!(request.flow.as_deref(), Some(FLOW_VISION));
        assert_eq!(&wire[consumed..], b"payload");
    }

    #[test]
    fn request_parser_distinguishes_incomplete_and_invalid_headers() {
        assert_eq!(parse_request(&[VERSION]).unwrap(), RequestParse::Incomplete);
        assert!(parse_request(&[9u8; 18]).is_err());
        let request = encode_mux_request(&[0u8; 16], "").to_vec();
        let RequestParse::Complete { request, .. } = parse_request(&request).unwrap() else {
            panic!("expected a complete mux request")
        };
        assert!(request.mux);
        assert_eq!(
            request.destination,
            Destination::tcp(
                Address::domain(crate::mux::CONTROL_HOST),
                crate::mux::CONTROL_PORT
            )
        );
    }

    #[test]
    fn vision_request_carries_the_flow() {
        let req = encode_request(&[0u8; 16], FLOW_VISION, &dst_domain());
        assert_eq!(req[17], 18, "addons length");
        assert_eq!(&req[20..36], FLOW_VISION.as_bytes());
        // Command follows the addons block.
        assert_eq!(req[36], CMD_TCP);
    }

    #[test]
    fn parses_empty_response_header() {
        assert_eq!(
            parse_response(&[0, 0]).unwrap(),
            ResponseParse::Complete { consumed: 2 }
        );
    }

    #[test]
    fn parses_response_with_addons() {
        let mut buf = vec![0, 3, 1, 2, 3];
        buf.extend_from_slice(b"payload");
        assert_eq!(
            parse_response(&buf).unwrap(),
            ResponseParse::Complete { consumed: 5 }
        );
    }

    #[test]
    fn incomplete_response_is_not_an_error() {
        assert_eq!(parse_response(&[0]).unwrap(), ResponseParse::Incomplete);
        assert_eq!(
            parse_response(&[0, 5, 1]).unwrap(),
            ResponseParse::Incomplete
        );
    }

    #[test]
    fn rejects_wrong_response_version() {
        assert!(parse_response(&[9, 0]).is_err());
    }
}

/// A stream adapter that strips the VLESS response header lazily.
///
/// The header must **not** be read eagerly before relaying starts. A server
/// only emits it once it has something to send, and it may have nothing to
/// send until it has forwarded the client's first payload — which cannot
/// happen while the client is blocked reading the header. Waiting for it up
/// front deadlocks against any server that behaves this way, including
/// Cloudflare Worker based ones.
pub struct VlessStream<S> {
    inner: S,
    /// Header bytes seen so far; `None` once the header is fully consumed.
    header: Option<Vec<u8>>,
    /// Payload that arrived in the same read as the header and did not fit in
    /// the caller's buffer. Without this, the overflow would be dropped.
    spill: Vec<u8>,
    spill_offset: usize,
}

impl<S> VlessStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header: Some(Vec::with_capacity(2)),
            spill: Vec::new(),
            spill_offset: 0,
        }
    }

    /// True until the response header has been fully consumed.
    pub fn header_pending(&self) -> bool {
        self.header.is_some()
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for VlessStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let this = self.get_mut();

        loop {
            // Hand back anything left over from the read that completed the
            // header before touching the socket again.
            if this.spill_offset < this.spill.len() {
                let n = (this.spill.len() - this.spill_offset).min(buf.remaining());
                buf.put_slice(&this.spill[this.spill_offset..this.spill_offset + n]);
                this.spill_offset += n;
                if this.spill_offset >= this.spill.len() {
                    this.spill.clear();
                    this.spill_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // Fast path: header already dealt with.
            if this.header.is_none() {
                return std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            // Read into a scratch buffer so we never hand header bytes up.
            let mut scratch = [0u8; 8192];
            let mut rb = tokio::io::ReadBuf::new(&mut scratch);
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        // EOF before the header completed.
                        return Poll::Ready(Ok(()));
                    }

                    let pending = this.header.as_mut().expect("checked above");
                    pending.extend_from_slice(filled);

                    match parse_response(pending) {
                        Ok(ResponseParse::Incomplete) => continue,
                        Ok(ResponseParse::Complete { consumed }) => {
                            let body = pending[consumed..].to_vec();
                            this.header = None;
                            if body.is_empty() {
                                // Header only: go back and read real payload.
                                continue;
                            }
                            let n = body.len().min(buf.remaining());
                            buf.put_slice(&body[..n]);
                            if n < body.len() {
                                // Caller's buffer was smaller than what
                                // arrived; keep the rest for the next read
                                // rather than losing it.
                                this.spill = body;
                                this.spill_offset = n;
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Err(e) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                e,
                            )))
                        }
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for VlessStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn strips_empty_header_then_yields_payload() {
        let (mut peer, s) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            peer.write_all(&[0, 0]).await.unwrap();
            peer.write_all(b"payload").await.unwrap();
            peer.shutdown().await.unwrap();
        });

        let mut v = VlessStream::new(s);
        let mut got = Vec::new();
        v.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"payload");
    }

    #[tokio::test]
    async fn strips_header_arriving_in_the_same_packet_as_payload() {
        let (mut peer, s) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8, 0u8];
            buf.extend_from_slice(b"hello");
            peer.write_all(&buf).await.unwrap();
            peer.shutdown().await.unwrap();
        });

        let mut v = VlessStream::new(s);
        let mut got = Vec::new();
        v.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello");
    }

    #[tokio::test]
    async fn strips_header_with_addons() {
        let (mut peer, s) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8, 3u8, 1, 2, 3];
            buf.extend_from_slice(b"data");
            peer.write_all(&buf).await.unwrap();
            peer.shutdown().await.unwrap();
        });

        let mut v = VlessStream::new(s);
        let mut got = Vec::new();
        v.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"data");
    }

    #[tokio::test]
    async fn handles_header_split_across_reads() {
        let (mut peer, s) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            peer.write_all(&[0]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            peer.write_all(&[0]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            peer.write_all(b"late").await.unwrap();
            peer.shutdown().await.unwrap();
        });

        let mut v = VlessStream::new(s);
        let mut got = Vec::new();
        v.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"late");
    }

    #[tokio::test]
    async fn writes_pass_through_before_the_header_arrives() {
        // The critical property: the client must be able to send its payload
        // while the response header has not been received yet, or a server
        // that waits for that payload before replying will deadlock.
        let (mut peer, s) = tokio::io::duplex(4096);
        let mut v = VlessStream::new(s);

        v.write_all(b"client-first").await.unwrap();
        v.flush().await.unwrap();
        assert!(v.header_pending(), "header has not arrived yet");

        let mut got = vec![0u8; 12];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"client-first");

        // Only now does the server answer.
        peer.write_all(&[0, 0]).await.unwrap();
        peer.write_all(b"server-reply").await.unwrap();
        let mut back = vec![0u8; 12];
        v.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"server-reply");
    }

    #[tokio::test]
    async fn small_reader_buffer_does_not_lose_payload() {
        // The header and a large payload arrive together, but the caller
        // reads in small chunks. Every byte must still be delivered.
        let (mut peer, s) = tokio::io::duplex(65536);
        let payload: Vec<u8> = (0..4000).map(|i| (i % 251) as u8).collect();
        let expect = payload.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8, 0u8];
            buf.extend_from_slice(&payload);
            peer.write_all(&buf).await.unwrap();
            peer.shutdown().await.unwrap();
        });

        let mut v = VlessStream::new(s);
        let mut got = Vec::new();
        let mut chunk = [0u8; 64];
        loop {
            let n = v.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(got, expect);
    }

    #[tokio::test]
    async fn rejects_a_bad_version_byte() {
        let (mut peer, s) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            peer.write_all(&[9, 0]).await.unwrap();
        });
        let mut v = VlessStream::new(s);
        let mut got = Vec::new();
        assert!(v.read_to_end(&mut got).await.is_err());
    }
}
