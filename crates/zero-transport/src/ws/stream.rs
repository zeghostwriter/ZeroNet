//! The WebSocket stream adapter.
//!
//! Presents a plain byte stream to the protocol layer above, hiding framing
//! entirely — VLESS must not know it is riding on WebSocket.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zero_core::{Failure, FailureKind, Stage};

use super::frame::{self, Frame, OP_CLOSE, OP_PING};
use super::handshake::{build_request, generate_key, verify_response, WsConfig};

/// Cap on the handshake response, so a hostile or broken peer cannot make us
/// buffer without bound before the upgrade completes.
const MAX_HANDSHAKE_RESPONSE: usize = 16 * 1024;

/// How much socket data one `poll_read` pulls in at a time.
const READ_CHUNK: usize = 16 * 1024;

/// Encoded frames queued beyond this make `poll_write` wait for the socket.
const MAX_QUEUED_WRITE: usize = 1024 * 1024;

pub struct WebSocketStream<S> {
    inner: S,
    /// Bytes read from the socket, not yet framed.
    read_buf: BytesMut,
    /// Decoded payload waiting to be handed to the caller.
    payload: BytesMut,
    /// Encoded frames waiting to go out.
    write_buf: BytesMut,
    /// The peer is done sending: a CLOSE frame arrived or the socket hit EOF.
    read_closed: bool,
    /// A CLOSE frame is queued or sent. RFC 6455 §5.5.1 forbids any data
    /// frame after it, so writes fail from here on.
    close_sent: bool,
    /// Which end this is, which decides whether outgoing frames are masked.
    role: frame::Role,
}

impl<S> WebSocketStream<S> {
    fn new(inner: S, leftover: BytesMut) -> Self {
        Self {
            inner,
            read_buf: leftover,
            payload: BytesMut::new(),
            write_buf: BytesMut::new(),
            read_closed: false,
            close_sent: false,
            role: frame::Role::Client,
        }
    }

    pub(crate) fn new_server(inner: S, leftover: BytesMut, early: Vec<u8>) -> Self {
        Self {
            inner,
            read_buf: leftover,
            payload: BytesMut::from(early.as_slice()),
            write_buf: BytesMut::new(),
            read_closed: false,
            close_sent: false,
            // A server must not mask. Encoding client frames from here is a
            // protocol violation that a conformant peer refuses outright.
            role: frame::Role::Server,
        }
    }
}

/// Perform the upgrade and return a byte stream.
///
/// `early_data` is sent inside the handshake request, so the first payload
/// costs no extra round trip. The caller is responsible for keeping it within
/// `cfg.early_data_len`; whatever it does not send here must be written
/// normally afterwards.
pub async fn connect<S>(
    mut inner: S,
    cfg: &WsConfig,
    early_data: &[u8],
) -> Result<WebSocketStream<S>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = generate_key();
    let request = build_request(cfg, &key, early_data);

    inner
        .write_all(&request)
        .await
        .map_err(|e| Failure::from_io(&e, Stage::RequestSent))?;
    inner
        .flush()
        .await
        .map_err(|e| Failure::from_io(&e, Stage::RequestSent))?;

    let mut buf = BytesMut::with_capacity(1024);
    loop {
        let consumed = verify_response(&buf, &key)?;
        if let Some(n) = consumed {
            let leftover = buf.split_off(n);
            return Ok(WebSocketStream::new(inner, leftover));
        }

        if buf.len() >= MAX_HANDSHAKE_RESPONSE {
            return Err(
                Failure::new(FailureKind::WebsocketMalformed, Stage::RequestSent)
                    .with_detail("handshake response exceeded the size limit"),
            );
        }

        let n = inner
            .read_buf(&mut buf)
            .await
            .map_err(|e| Failure::from_io(&e, Stage::RequestSent))?;
        if n == 0 {
            return Err(
                Failure::new(FailureKind::WebsocketMalformed, Stage::RequestSent)
                    .with_confidence(zero_core::Confidence::Likely)
                    .with_detail("connection closed during websocket handshake"),
            );
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocketStream<S> {
    /// Push queued frames toward the socket.
    fn poll_flush_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "websocket write returned 0",
                    )))
                }
                Poll::Ready(Ok(n)) => self.write_buf.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Decode buffered bytes, answering control frames inline.
    fn drain_frames(&mut self) -> io::Result<bool> {
        let mut produced = false;
        while let Some(f) = frame::decode(&mut self.read_buf)? {
            match f.opcode {
                OP_CLOSE => {
                    self.read_closed = true;
                    // RFC 6455 §5.5.1: answer a CLOSE we did not start, echoing
                    // its status code. Without the reply the peer only learns
                    // the connection is gone from its own close timeout.
                    if !self.close_sent {
                        self.close_sent = true;
                        let code = f.payload.get(..2).unwrap_or(&[]);
                        frame::encode(self.role, &Frame::close_with(code), &mut self.write_buf);
                    }
                    // Nothing after a CLOSE frame is meaningful.
                    self.read_buf.clear();
                    return Ok(produced);
                }
                OP_PING => {
                    // Reply in line; a dropped pong looks like a dead peer.
                    // After our CLOSE no further frame may be sent.
                    if !self.close_sent {
                        frame::encode(self.role, &Frame::pong(&f.payload), &mut self.write_buf);
                    }
                }
                _ if f.is_control() => { /* pong and friends: ignore */ }
                _ => {
                    if f.payload.is_empty() {
                        continue;
                    }
                    // The decoded payload is already its own buffer, split out
                    // of `read_buf`; take it over instead of copying it.
                    if self.payload.is_empty() {
                        self.payload = f.payload;
                    } else {
                        self.payload.extend_from_slice(&f.payload);
                    }
                    produced = true;
                }
            }
        }
        Ok(produced)
    }
}

/// A WebSocket Ping is the protocol's own no-op: RFC 6455 §5.5.2 makes it a
/// control frame that carries no application meaning, and any conforming peer
/// answers with a Pong. Better than padding for keepalive shaping, because an
/// intermediary sees a normal WebSocket exchange rather than an unexplained
/// byte on an otherwise idle connection.
impl<S: AsyncRead + AsyncWrite + Unpin> zero_evasion::KeepaliveCarrier for WebSocketStream<S> {
    fn poll_keepalive(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let this = self.get_mut();
        if this.close_sent || this.read_closed {
            return Poll::Ready(Ok(false));
        }
        // Encoded through the same path as payload, so a client frame gets a
        // fresh mask — a repeated mask on an idle connection would be its own
        // signature.
        frame::encode_slice(this.role, OP_PING, &[], &mut this.write_buf);
        match this.poll_flush_write_buf(cx) {
            // The frame is queued in full either way.
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(true)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // Push queued control replies first, and on every pass.
            //
            // This must happen before returning data: `drain_frames` can
            // decode a PING and a data frame in the same pass, and if we
            // returned the data without flushing, the PONG would sit unsent
            // until the caller happened to read or write again. A server
            // using pings for liveness would treat us as dead.
            let _ = this.poll_flush_write_buf(cx);

            if !this.payload.is_empty() {
                let n = this.payload.len().min(buf.remaining());
                buf.put_slice(&this.payload[..n]);
                this.payload.advance(n);
                return Poll::Ready(Ok(()));
            }

            if this.read_closed {
                return Poll::Ready(Ok(())); // clean EOF
            }

            // Try framing what we already have before touching the socket.
            if this.drain_frames()? {
                continue;
            }
            if this.read_closed {
                // A CLOSE just arrived: push the reply before reporting EOF.
                let _ = this.poll_flush_write_buf(cx);
                return Poll::Ready(Ok(()));
            }

            // Read straight into the frame buffer rather than through a stack
            // scratch buffer and a second copy.
            let start = this.read_buf.len();
            this.read_buf.resize(start + READ_CHUNK, 0);
            let mut rb = ReadBuf::new(&mut this.read_buf[start..]);
            let polled = Pin::new(&mut this.inner).poll_read(cx, &mut rb);
            let filled = rb.filled().len();
            this.read_buf.truncate(start + filled);
            match polled {
                Poll::Ready(Ok(())) => {
                    if filled == 0 {
                        // Peer closed without a CLOSE frame.
                        this.read_closed = true;
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebSocketStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.close_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "websocket is closing; no data may follow a CLOSE frame",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Bound in-flight buffering so a stalled peer applies backpressure
        // instead of growing our memory.
        if this.write_buf.len() > MAX_QUEUED_WRITE {
            match this.poll_flush_write_buf(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        frame::encode_slice(this.role, frame::OP_BINARY, buf, &mut this.write_buf);

        match this.poll_flush_write_buf(cx) {
            // Partial socket writes are fine: the frame is queued in full, so
            // the caller's bytes are all accounted for.
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.close_sent {
            this.close_sent = true;
            frame::encode(this.role, &Frame::close(), &mut this.write_buf);
        }
        match this.poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::handshake::expected_accept;

    /// Read the upgrade request head.
    ///
    /// Returns the key, any early data, and **the bytes after the head** —
    /// keeping those separate matters: feeding the HTTP head into the frame
    /// decoder silently corrupts the stream.
    async fn read_head(
        s: &mut tokio::io::DuplexStream,
    ) -> Option<(String, Option<Vec<u8>>, BytesMut)> {
        let mut buf = BytesMut::new();
        let end = loop {
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
            if s.read_buf(&mut buf).await.ok()? == 0 {
                return None;
            }
        };
        let body = buf.split_off(end);
        let text = String::from_utf8_lossy(&buf).to_string();

        let header = |name: &str| -> Option<String> {
            text.lines()
                .find(|l| l.to_ascii_lowercase().starts_with(name))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        };

        let key = header("sec-websocket-key:")?;
        let early = header("sec-websocket-protocol:").map(|p| {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(p)
                .unwrap_or_default()
        });
        Some((key, early, body))
    }

    /// Encode an unmasked server frame.
    fn server_frame(payload: &[u8]) -> BytesMut {
        let mut out = BytesMut::new();
        out.extend_from_slice(&[0x82]);
        let l = payload.len();
        if l < 126 {
            out.extend_from_slice(&[l as u8]);
        } else if l <= u16::MAX as usize {
            out.extend_from_slice(&[126]);
            out.extend_from_slice(&(l as u16).to_be_bytes());
        } else {
            out.extend_from_slice(&[127]);
            out.extend_from_slice(&(l as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    async fn send_101(s: &mut tokio::io::DuplexStream, key: &str) -> std::io::Result<()> {
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            expected_accept(key)
        );
        s.write_all(resp.as_bytes()).await
    }

    /// Complete the upgrade, echo any early data, then echo binary frames.
    async fn serve_echo(mut s: tokio::io::DuplexStream) {
        let Some((key, early, mut rb)) = read_head(&mut s).await else {
            return;
        };
        if send_101(&mut s, &key).await.is_err() {
            return;
        }
        if let Some(ed) = early {
            if !ed.is_empty() && s.write_all(&server_frame(&ed)).await.is_err() {
                return;
            }
        }
        loop {
            match frame::decode(&mut rb) {
                Ok(Some(f)) if f.opcode == frame::OP_BINARY => {
                    if s.write_all(&server_frame(&f.payload)).await.is_err() {
                        return;
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => match s.read_buf(&mut rb).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                },
                Err(_) => return,
            }
        }
    }

    #[tokio::test]
    async fn completes_handshake_and_echoes() {
        let (client, server) = tokio::io::duplex(65536);
        tokio::spawn(serve_echo(server));

        let cfg = WsConfig::new("/vl/x", "edge.example");
        let mut ws = connect(client, &cfg, b"").await.expect("upgrade");

        ws.write_all(b"hello zray").await.unwrap();
        ws.flush().await.unwrap();

        let mut got = vec![0u8; 10];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello zray");
    }

    #[tokio::test]
    async fn early_data_reaches_the_server_in_the_handshake() {
        let (client, server) = tokio::io::duplex(65536);
        tokio::spawn(serve_echo(server));

        let cfg = WsConfig::new("/vl/x", "edge.example");
        let mut ws = connect(client, &cfg, b"EARLY").await.expect("upgrade");

        // The server echoes what it decoded from the handshake header, which
        // proves the payload travelled in the upgrade request itself.
        let mut got = vec![0u8; 5];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"EARLY");
    }

    #[tokio::test]
    async fn server_accept_handles_early_data_before_framed_payload() {
        let (client, server) = tokio::io::duplex(65_536);
        let cfg = WsConfig::new("/in", "edge.example");
        let server_cfg = cfg.clone();
        let server_task = tokio::spawn(async move {
            let mut ws = super::super::handshake::accept_server(server, &server_cfg)
                .await
                .unwrap();
            let mut request = [0u8; 5];
            ws.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"early");
            ws.write_all(b"reply").await.unwrap();
            ws.flush().await.unwrap();
        });
        let mut ws = connect(client, &cfg, b"early").await.unwrap();
        let mut response = [0u8; 5];
        ws.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"reply");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn large_payload_survives_framing() {
        let (client, server) = tokio::io::duplex(1024 * 1024);
        tokio::spawn(serve_echo(server));

        let cfg = WsConfig::new("/p", "h");
        let ws = connect(client, &cfg, b"").await.unwrap();

        // Larger than the 16-bit length field, to exercise 64-bit framing.
        let payload = vec![0x5Au8; 200_000];
        let w = payload.clone();
        let (mut rd, mut wr) = tokio::io::split(ws);
        tokio::spawn(async move {
            wr.write_all(&w).await.unwrap();
            wr.flush().await.unwrap();
        });

        let mut got = vec![0u8; payload.len()];
        rd.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn responds_to_ping_with_pong() {
        let (client, mut server) = tokio::io::duplex(65536);
        let h = tokio::spawn(async move {
            let (key, _, _) = read_head(&mut server).await.unwrap();
            send_101(&mut server, &key).await.unwrap();
            server.write_all(&[0x89, 0x00]).await.unwrap(); // unmasked PING
            server
                .write_all(&server_frame(b"after-ping"))
                .await
                .unwrap();

            let mut rb = BytesMut::new();
            loop {
                if let Ok(Some(f)) = frame::decode(&mut rb) {
                    return f.opcode;
                }
                if server.read_buf(&mut rb).await.unwrap_or(0) == 0 {
                    return 0;
                }
            }
        });

        let cfg = WsConfig::new("/p", "h");
        let mut ws = connect(client, &cfg, b"").await.unwrap();
        let mut got = vec![0u8; 10];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"after-ping");

        // The ping must have been answered inline while reading data.
        assert_eq!(h.await.unwrap(), frame::OP_PONG);
    }

    #[tokio::test]
    async fn clean_close_frame_produces_eof() {
        let (client, mut server) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            let (key, _, _) = read_head(&mut server).await.unwrap();
            send_101(&mut server, &key).await.unwrap();
            server.write_all(&server_frame(b"bye")).await.unwrap();
            server.write_all(&[0x88, 0x00]).await.unwrap(); // CLOSE
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let cfg = WsConfig::new("/p", "h");
        let mut ws = connect(client, &cfg, b"").await.unwrap();
        let mut got = Vec::new();
        ws.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"bye");
    }

    #[tokio::test]
    async fn peer_close_is_answered_and_blocks_further_writes() {
        let (client, mut server) = tokio::io::duplex(65536);
        let peer = tokio::spawn(async move {
            let (key, _, mut rb) = read_head(&mut server).await.unwrap();
            send_101(&mut server, &key).await.unwrap();
            // CLOSE with status 1001 (going away).
            server.write_all(&[0x88, 0x02, 0x03, 0xE9]).await.unwrap();
            loop {
                if let Some(f) = frame::decode(&mut rb).unwrap() {
                    return f;
                }
                assert_ne!(server.read_buf(&mut rb).await.unwrap(), 0);
            }
        });

        let cfg = WsConfig::new("/p", "h");
        let mut ws = connect(client, &cfg, b"").await.unwrap();
        let mut got = Vec::new();
        ws.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty());

        let reply = peer.await.unwrap();
        assert_eq!(reply.opcode, frame::OP_CLOSE, "CLOSE must be answered");
        assert_eq!(&reply.payload[..], &[0x03, 0xE9], "status code is echoed");

        let err = ws.write_all(b"late").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn rejected_upgrade_is_classified() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            let _ = server.read(&mut b).await;
            let _ = server
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await;
        });

        let cfg = WsConfig::new("/p", "h");
        let err = match connect(client, &cfg, b"").await {
            Ok(_) => panic!("expected the 403 upgrade to fail"),
            Err(e) => e,
        };
        assert_eq!(err.kind, FailureKind::Http403);
    }
}
