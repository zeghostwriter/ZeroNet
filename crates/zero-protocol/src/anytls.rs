//! AnyTLS v2's authenticated, length-delimited stream.
//!
//! The transport is intentionally kept as one logical stream here.  Session
//! pooling can be added above this boundary later; a single stream still has
//! the complete AnyTLS wire contract and is interoperable with a v2 peer.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zero_core::{Address, Destination, Network};

use crate::io_util::{ReadBuffer, WriteBuffer, DEFAULT_READ_CAPACITY};

const HEADER_LEN: usize = 7;
const MAX_FRAME: usize = u16::MAX as usize;
const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_SYN_ACK: u8 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameHeader {
    command: u8,
    stream_id: u32,
    length: usize,
}

fn encode_frame(command: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.push(command);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn decode_header(header: &[u8; HEADER_LEN]) -> io::Result<FrameHeader> {
    let command = header[0];
    if !matches!(
        command,
        CMD_WASTE | CMD_SYN | CMD_PSH | CMD_FIN | CMD_SETTINGS | CMD_SYN_ACK
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown AnyTLS command {command}"),
        ));
    }
    Ok(FrameHeader {
        command,
        stream_id: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        length: u16::from_be_bytes([header[5], header[6]]) as usize,
    })
}

fn encode_destination(destination: &Destination) -> io::Result<Vec<u8>> {
    if destination.network != Network::Tcp {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "AnyTLS stream setup only carries TCP destinations",
        ));
    }
    let mut out = Vec::with_capacity(1 + 16 + destination.port as usize);
    match &destination.address {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            if domain.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "AnyTLS destination domain is too long",
                ));
            }
            out.push(3);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(out)
}

fn decode_destination(bytes: &[u8]) -> io::Result<Destination> {
    let (&kind, rest) = bytes
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty AnyTLS destination"))?;
    let (address, rest) = match kind {
        1 => {
            if rest.len() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short AnyTLS IPv4 destination",
                ));
            }
            (
                Address::from(std::net::Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3])),
                &rest[4..],
            )
        }
        4 => {
            if rest.len() < 16 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short AnyTLS IPv6 destination",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            (Address::from(std::net::Ipv6Addr::from(octets)), &rest[16..])
        }
        3 => {
            let (&length, rest) = rest.split_first().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "missing AnyTLS domain length")
            })?;
            let length = length as usize;
            if rest.len() < length {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short AnyTLS domain destination",
                ));
            }
            let domain = std::str::from_utf8(&rest[..length]).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "AnyTLS domain is not UTF-8")
            })?;
            (Address::domain(domain), &rest[length..])
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported AnyTLS address type {other}"),
            ))
        }
    };
    if rest.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "AnyTLS destination has trailing or missing port bytes",
        ));
    }
    Ok(Destination::tcp(
        address,
        u16::from_be_bytes([rest[0], rest[1]]),
    ))
}

fn password_hash(password: &str) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(Sha256::digest(password.as_bytes()).as_slice());
    hash
}

/// Establish an AnyTLS v2 client stream and announce one destination.
pub async fn client_handshake<S>(
    mut stream: S,
    password: &str,
    destination: &Destination,
) -> io::Result<AnyTlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut auth = Vec::with_capacity(34);
    auth.extend_from_slice(&password_hash(password));
    auth.extend_from_slice(&0u16.to_be_bytes());
    stream.write_all(&auth).await?;

    let mut settings = b"v=2\nclient=zray-anytls/1.0".to_vec();
    let mut initial = encode_frame(CMD_SETTINGS, 0, &settings);
    initial.extend_from_slice(&encode_frame(CMD_SYN, 1, &[]));
    initial.extend_from_slice(&encode_frame(CMD_PSH, 1, &encode_destination(destination)?));
    stream.write_all(&initial).await?;
    stream.flush().await?;
    settings.fill(0);

    Ok(AnyTlsStream::new(stream, 1))
}

/// Authenticate an AnyTLS server connection and return the announced target.
pub async fn server_handshake<S>(
    mut stream: S,
    passwords: &[impl AsRef<[u8]>],
) -> io::Result<(AnyTlsStream<S>, Destination)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hash = [0u8; 32];
    stream.read_exact(&mut hash).await?;
    let mut padding_len = [0u8; 2];
    stream.read_exact(&mut padding_len).await?;
    let padding_len = u16::from_be_bytes(padding_len) as usize;
    if padding_len > 16 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "AnyTLS authentication padding is too large",
        ));
    }
    let mut padding = vec![0u8; padding_len];
    stream.read_exact(&mut padding).await?;
    if !passwords.iter().any(|candidate| candidate.as_ref() == hash) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "AnyTLS authentication failed",
        ));
    }

    let mut target = None;
    let mut stream_id = None;
    let mut settings_seen = false;
    while target.is_none() {
        let (header, payload) = read_frame(&mut stream).await?;
        match header.command {
            CMD_SETTINGS => settings_seen = true,
            CMD_SYN if header.stream_id != 0 => stream_id = Some(header.stream_id),
            CMD_PSH if stream_id == Some(header.stream_id) => {
                target = Some(decode_destination(&payload)?);
            }
            CMD_WASTE => {}
            _ => {}
        }
        if !settings_seen && target.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "AnyTLS stream opened before settings",
            ));
        }
    }
    let stream_id = stream_id.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "AnyTLS target has no stream id")
    })?;
    let target = target.expect("target is set by the loop condition");
    let response = encode_frame(CMD_SYN_ACK, stream_id, &[]);
    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok((AnyTlsStream::new(stream, stream_id), target))
}

async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(FrameHeader, Vec<u8>)> {
    let mut raw = [0u8; HEADER_LEN];
    stream.read_exact(&mut raw).await?;
    let header = decode_header(&raw)?;
    let mut payload = vec![0u8; header.length];
    stream.read_exact(&mut payload).await?;
    Ok((header, payload))
}

/// A single logical AnyTLS stream. Frames for other stream IDs are rejected so
/// a future pooled session cannot silently deliver another user's bytes.
///
/// Writes are buffered: `poll_write` frames the caller's bytes, starts sending
/// them and reports them accepted; `poll_flush`/`poll_shutdown` drain the rest.
pub struct AnyTlsStream<S> {
    inner: S,
    stream_id: u32,
    read_buf: ReadBuffer,
    /// Payload of the PSH frame at the head of `read_buf` not yet delivered:
    /// `read_buf.data()[plain_pos..plain_end]`, followed by consuming
    /// `frame_len` bytes once drained.
    plain_pos: usize,
    plain_end: usize,
    frame_len: usize,
    write_buf: WriteBuffer,
    sent_fin: bool,
    eof: bool,
}

impl<S> AnyTlsStream<S> {
    fn new(inner: S, stream_id: u32) -> Self {
        Self {
            inner,
            stream_id,
            read_buf: ReadBuffer::with_capacity(DEFAULT_READ_CAPACITY),
            plain_pos: 0,
            plain_end: 0,
            frame_len: 0,
            write_buf: WriteBuffer::default(),
            sent_fin: false,
            eof: false,
        }
    }

    fn push_frame(&mut self, command: u8, payload: &[u8]) {
        let out = self.write_buf.buf_mut();
        out.reserve(HEADER_LEN + payload.len());
        out.push(command);
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AnyTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let initial = buf.filled().len();
        loop {
            if this.plain_pos < this.plain_end {
                let window = &this.read_buf.data()[this.plain_pos..this.plain_end];
                let n = window.len().min(buf.remaining());
                buf.put_slice(&window[..n]);
                this.plain_pos += n;
                if this.plain_pos < this.plain_end {
                    return Poll::Ready(Ok(()));
                }
                this.read_buf.consume(this.frame_len);
                (this.plain_pos, this.plain_end, this.frame_len) = (0, 0, 0);
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            let delivered = buf.filled().len() > initial;

            // Header first, then the whole frame; both usually arrive in the
            // same transport read.
            let mut need = HEADER_LEN;
            if this.read_buf.len() >= HEADER_LEN {
                let raw: [u8; HEADER_LEN] = this.read_buf.data()[..HEADER_LEN]
                    .try_into()
                    .expect("header length checked");
                need += decode_header(&raw)?.length;
            }
            if this.read_buf.len() < need {
                match this
                    .read_buf
                    .poll_fill(Pin::new(&mut this.inner), cx, HEADER_LEN)
                {
                    Poll::Ready(Ok(true)) if this.read_buf.len() >= HEADER_LEN => {}
                    Poll::Ready(Ok(_)) if delivered => return Poll::Ready(Ok(())),
                    Poll::Ready(Ok(_)) if this.read_buf.is_empty() => {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(_)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated AnyTLS frame header",
                        )))
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending if delivered => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
                let raw: [u8; HEADER_LEN] = this.read_buf.data()[..HEADER_LEN]
                    .try_into()
                    .expect("header length checked");
                let need = HEADER_LEN + decode_header(&raw)?.length;
                match this.read_buf.poll_fill(Pin::new(&mut this.inner), cx, need) {
                    Poll::Ready(Ok(true)) => {}
                    Poll::Ready(Ok(false)) if delivered => return Poll::Ready(Ok(())),
                    Poll::Ready(Ok(false)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated AnyTLS frame payload",
                        )))
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending if delivered => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }

            let raw: [u8; HEADER_LEN] = this.read_buf.data()[..HEADER_LEN]
                .try_into()
                .expect("header length checked");
            let header = decode_header(&raw)?;
            let frame_len = HEADER_LEN + header.length;
            match header.command {
                CMD_PSH if header.stream_id == this.stream_id => {
                    if header.length == 0 {
                        this.read_buf.consume(frame_len);
                    } else {
                        this.plain_pos = HEADER_LEN;
                        this.plain_end = frame_len;
                        this.frame_len = frame_len;
                    }
                }
                CMD_WASTE | CMD_SETTINGS | CMD_SYN_ACK => this.read_buf.consume(frame_len),
                CMD_FIN if header.stream_id == this.stream_id => {
                    this.read_buf.consume(frame_len);
                    this.eof = true;
                }
                CMD_PSH | CMD_FIN => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "AnyTLS frame addressed to another stream",
                    )))
                }
                CMD_SYN => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected AnyTLS SYN after stream setup",
                    )))
                }
                _ => unreachable!("AnyTLS header validation rejects unknown commands"),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AnyTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.sent_fin {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "AnyTLS stream is closed",
            )));
        }
        if !this.write_buf.is_empty() {
            match this.write_buf.poll_drain(Pin::new(&mut this.inner), cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let amount = data.len().min(MAX_FRAME);
        this.push_frame(CMD_PSH, &data[..amount]);
        if let Poll::Ready(Err(error)) = this.write_buf.poll_drain(Pin::new(&mut this.inner), cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(amount))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.write_buf.poll_drain(Pin::new(&mut this.inner), cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            result => result,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.sent_fin {
            // Queued behind any buffered data, so FIN is always sent — the
            // previous version skipped it whenever data was still pending.
            this.push_frame(CMD_FIN, &[]);
            this.sent_fin = true;
        }
        match this.write_buf.poll_drain(Pin::new(&mut this.inner), cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            result => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn anytls_roundtrip_authenticates_and_preserves_target() {
        let (client, server) = duplex(64 * 1024);
        let target = Destination::tcp(Address::domain("example.com"), 443);
        let expected = target.clone();
        let server_task = tokio::spawn(async move {
            let hash = password_hash("secret");
            let (mut stream, received) = server_handshake(server, &[hash]).await.unwrap();
            assert_eq!(received, expected);
            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(b"world").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut client = client_handshake(client, "secret", &target).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"world");
        server_task.await.unwrap();
    }

    /// A shutdown issued while data is still queued must still end with a
    /// FIN frame after that data (it used to skip the FIN).
    #[tokio::test]
    async fn shutdown_with_queued_data_sends_data_then_fin() {
        let (client_io, mut server_io) = duplex(64);
        let mut stream = AnyTlsStream::new(client_io, 9);
        let payload = vec![0xabu8; 1000];
        let reader = tokio::spawn(async move {
            let mut wire = Vec::new();
            server_io.read_to_end(&mut wire).await.unwrap();
            wire
        });
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        let wire = reader.await.unwrap();
        assert_eq!(wire.len(), HEADER_LEN + 1000 + HEADER_LEN);
        assert_eq!(wire[0], CMD_PSH);
        assert_eq!(wire[HEADER_LEN + 1000], CMD_FIN);
    }

    #[tokio::test]
    async fn bulk_frames_survive_small_reads_and_interleaved_control_frames() {
        let (mut peer, stream_io) = duplex(8 * 1024);
        let mut stream = AnyTlsStream::new(stream_io, 3);
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 241) as u8).collect();
        let expected = payload.clone();
        tokio::spawn(async move {
            for chunk in payload.chunks(60_000) {
                peer.write_all(&encode_frame(CMD_WASTE, 0, &[0; 32]))
                    .await
                    .unwrap();
                peer.write_all(&encode_frame(CMD_PSH, 3, chunk))
                    .await
                    .unwrap();
            }
            peer.write_all(&encode_frame(CMD_FIN, 3, &[]))
                .await
                .unwrap();
        });
        let mut got = Vec::new();
        let mut chunk = [0u8; 999];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(got, expected);
    }

    #[test]
    fn destination_roundtrips_all_address_families() {
        for destination in [
            Destination::tcp(Address::from(std::net::Ipv4Addr::LOCALHOST), 80),
            Destination::tcp(Address::from(std::net::Ipv6Addr::LOCALHOST), 443),
            Destination::tcp(Address::domain("example.com"), 8443),
        ] {
            assert_eq!(
                decode_destination(&encode_destination(&destination).unwrap()).unwrap(),
                destination
            );
        }
    }
}
