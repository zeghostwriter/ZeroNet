//! The client-side XTLS Vision padding stream.
//!
//! Vision is a byte framing layer inside the outer TLS/REALITY stream. The
//! VLESS response header stays unframed; after it, both directions begin with
//! the account UUID followed by command/length/padding frames. Command 0
//! continues padding, while command 1 ends it and leaves subsequent bytes as
//! ordinary plaintext inside the outer stream.
//!
//! This implementation deliberately emits `PaddingEnd`, never
//! `PaddingDirect`. The latter requires handing an already-record-aligned raw
//! TCP socket back through the outer TLS implementation; emitting End is the
//! interoperable Xray mode and keeps the stream safe on transports that cannot
//! expose that handoff. Xray still accepts the resulting Vision flow.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const COMMAND_CONTINUE: u8 = 0x00;
const COMMAND_END: u8 = 0x01;
const COMMAND_DIRECT: u8 = 0x02;
const LONG_PADDING_MIN: usize = 900;
const LONG_PADDING_RANDOM_MAX: usize = 500;
const SHORT_PADDING_RANDOM_MAX: usize = 256;
const MAX_FRAME_PLAINTEXT: usize = 8171; // Xray buf.Size (8192) - UUID/header room
const READ_CHUNK: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadMode {
    ResponseHeader,
    InitialUuid,
    Frames,
    Plain,
}

/// A Vision stream for a VLESS TCP connection.
pub struct VisionStream<S> {
    inner: S,
    uuid: [u8; 16],
    read_mode: ReadMode,
    read_input: BytesMut,
    read_output: BytesMut,
    eof: bool,

    write_padding: bool,
    write_attempts: u8,
    inner_looks_tls: bool,
    write_first: bool,
    pending_write: BytesMut,
    direct_read_switch: Option<DirectReadSwitch<S>>,
}

/// Hook that hands the underlying stream back to raw mode once Vision has
/// spliced the last padded frame.
type DirectReadSwitch<S> = Box<dyn FnMut(&mut S) + Send>;

impl<S> VisionStream<S> {
    /// Construct the client side. The first read exposes the plain VLESS
    /// response header so `VlessStream` can strip it; all later reads unpad
    /// Vision frames.
    pub fn new_client(inner: S, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            read_mode: ReadMode::ResponseHeader,
            read_input: BytesMut::with_capacity(READ_CHUNK),
            read_output: BytesMut::new(),
            eof: false,
            write_padding: true,
            write_attempts: 0,
            inner_looks_tls: false,
            write_first: true,
            pending_write: BytesMut::new(),
            direct_read_switch: None,
        }
    }

    /// Construct the server side. The VLESS response header is emitted by the
    /// server dispatcher before this wrapper is installed, so server reads
    /// begin at the UUID-prefixed Vision frame immediately.
    pub fn new_server(inner: S, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            read_mode: ReadMode::InitialUuid,
            read_input: BytesMut::with_capacity(READ_CHUNK),
            read_output: BytesMut::new(),
            eof: false,
            write_padding: true,
            write_attempts: 0,
            inner_looks_tls: false,
            write_first: true,
            pending_write: BytesMut::new(),
            direct_read_switch: None,
        }
    }

    /// Install a carrier-specific callback for the authenticated Vision
    /// `PaddingDirect` transition. The protocol stays independent of the
    /// concrete REALITY/TLS implementation while the carrier can preserve
    /// already-buffered bytes and enter raw mode deliberately.
    pub fn with_direct_read_switch<F>(mut self, switch: F) -> Self
    where
        F: FnMut(&mut S) + Send + 'static,
    {
        self.direct_read_switch = Some(Box::new(switch));
        self
    }

    /// Send the mandatory empty first Vision frame. Xray emits this even when
    /// the local application has not produced payload yet, which prevents the
    /// VLESS header from being a distinctive short record.
    pub async fn send_initial_frame(&mut self) -> io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let frame = make_frame(&[], Some(&self.uuid), COMMAND_CONTINUE, true);
        tokio::io::AsyncWriteExt::write_all(&mut self.inner, &frame).await?;
        tokio::io::AsyncWriteExt::flush(&mut self.inner).await?;
        self.write_first = false;
        Ok(())
    }

    fn make_write_payload(&mut self, input: &[u8]) -> Vec<u8> {
        if !self.write_padding {
            return input.to_vec();
        }

        self.write_attempts = self.write_attempts.saturating_add(1);
        if looks_like_tls_client_hello(input) {
            self.inner_looks_tls = true;
        }

        let complete_app_data = is_complete_tls_application_data(input);
        let end_padding = complete_app_data || (!self.inner_looks_tls && self.write_attempts >= 8);
        let command = if end_padding {
            self.write_padding = false;
            COMMAND_END
        } else {
            COMMAND_CONTINUE
        };

        let mut out = Vec::with_capacity(input.len() + 1024 + 21);
        let mut offset = 0usize;
        let long_padding = self.inner_looks_tls;
        while offset < input.len() {
            let end = (offset + MAX_FRAME_PLAINTEXT).min(input.len());
            let prefix = self.write_first.then_some(&self.uuid);
            // Only the final frame can terminate padding. Earlier chunks must
            // remain Continue even when a large application write is split.
            let frame_command = if end == input.len() {
                command
            } else {
                COMMAND_CONTINUE
            };
            out.extend_from_slice(&make_frame(
                &input[offset..end],
                prefix,
                frame_command,
                long_padding,
            ));
            self.write_first = false;
            offset = end;
        }
        out
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while !self.pending_write.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending_write) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Vision inner stream accepted zero bytes",
                    )))
                }
                Poll::Ready(Ok(n)) => self.pending_write.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>>
    where
        S: AsyncRead + Unpin,
    {
        let mut scratch = [0u8; READ_CHUNK];
        let mut read_buf = ReadBuf::new(&mut scratch);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    self.eof = true;
                    Poll::Ready(Ok(false))
                } else {
                    self.read_input.extend_from_slice(&scratch[..n]);
                    Poll::Ready(Ok(true))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn parse_response_header(&mut self) -> io::Result<bool> {
        if self.read_input.len() < 2 {
            return Ok(false);
        }
        let total = 2usize + self.read_input[1] as usize;
        if total > 2 + 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS response addons are too large",
            ));
        }
        if self.read_input.len() < total {
            return Ok(false);
        }
        if self.read_input[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected VLESS response version",
            ));
        }
        let header = self.read_input.split_to(total);
        self.read_output.extend_from_slice(&header);
        self.read_mode = ReadMode::InitialUuid;
        Ok(true)
    }

    fn parse_one_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.read_mode == ReadMode::InitialUuid {
            if self.read_input.len() < self.uuid.len() {
                return Ok(None);
            }
            if self.read_input[..16] != self.uuid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Vision UUID prefix does not match the VLESS account",
                ));
            }
            self.read_input.advance(16);
            self.read_mode = ReadMode::Frames;
        }

        if self.read_input.len() < 5 {
            return Ok(None);
        }
        let command = self.read_input[0];
        if !matches!(command, COMMAND_CONTINUE | COMMAND_END | COMMAND_DIRECT) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown Vision command {command:#04x}"),
            ));
        }
        let content_len = u16::from_be_bytes([self.read_input[1], self.read_input[2]]) as usize;
        let padding_len = u16::from_be_bytes([self.read_input[3], self.read_input[4]]) as usize;
        if content_len + padding_len > MAX_FRAME_PLAINTEXT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Vision frame exceeds the Xray plaintext bound",
            ));
        }
        let total = 5 + content_len + padding_len;
        if self.read_input.len() < total {
            return Ok(None);
        }

        let frame = self.read_input.split_to(total);
        let content = frame[5..5 + content_len].to_vec();
        if command != COMMAND_CONTINUE {
            if command == COMMAND_DIRECT {
                if let Some(switch) = self.direct_read_switch.as_mut() {
                    switch(&mut self.inner);
                }
            }
            self.read_mode = ReadMode::Plain;
        }
        Ok(Some(content))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_output.is_empty() {
                let n = self.read_output.len().min(buf.remaining());
                let bytes = self.read_output.split_to(n);
                buf.put_slice(&bytes);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }

            match self.read_mode {
                ReadMode::ResponseHeader => match self.parse_response_header() {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(e) => return Poll::Ready(Err(e)),
                },
                ReadMode::InitialUuid | ReadMode::Frames => match self.parse_one_frame() {
                    Ok(Some(content)) => {
                        if !content.is_empty() {
                            self.read_output.extend_from_slice(&content);
                        }
                        continue;
                    }
                    Ok(None) => {}
                    Err(e) => return Poll::Ready(Err(e)),
                },
                ReadMode::Plain => {
                    // The final Vision frame and the first raw/plain bytes
                    // can arrive in one carrier read. Once the transition is
                    // observed, those bytes are no longer frame data, but
                    // they still belong before the next read from `inner`.
                    // Dropping them here truncates the tunneled TLS stream.
                    if !self.read_input.is_empty() {
                        let n = self.read_input.len().min(buf.remaining());
                        let bytes = self.read_input.split_to(n);
                        buf.put_slice(&bytes);
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut self.inner).poll_read(cx, buf);
                }
            }

            match self.poll_fill(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => continue,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !self.pending_write.is_empty() {
            match self.poll_flush_pending(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if !self.write_padding && self.pending_write.is_empty() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        let framed = self.make_write_payload(buf);
        self.pending_write.extend_from_slice(&framed);
        let accepted = buf.len();
        match self.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(accepted)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

fn make_frame(content: &[u8], uuid: Option<&[u8; 16]>, command: u8, long_padding: bool) -> Vec<u8> {
    let max_padding = MAX_FRAME_PLAINTEXT.saturating_sub(content.len());
    let mut rng = rand::rngs::OsRng;
    let padding = if long_padding && content.len() < LONG_PADDING_MIN {
        LONG_PADDING_MIN
            .saturating_sub(content.len())
            .saturating_add((rng.next_u32() as usize) % LONG_PADDING_RANDOM_MAX)
    } else {
        (rng.next_u32() as usize) % SHORT_PADDING_RANDOM_MAX
    }
    .min(max_padding);

    let mut out = Vec::with_capacity(uuid.map_or(0, |_| 16) + 5 + content.len() + padding);
    if let Some(uuid) = uuid {
        out.extend_from_slice(uuid);
    }
    out.push(command);
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&(padding as u16).to_be_bytes());
    out.extend_from_slice(content);
    let old = out.len();
    out.resize(old + padding, 0);
    rng.fill_bytes(&mut out[old..]);
    out
}

fn looks_like_tls_client_hello(input: &[u8]) -> bool {
    input.len() >= 6 && input[0] == 0x16 && input[1] == 0x03 && input[5] == 0x01
}

fn is_complete_tls_application_data(input: &[u8]) -> bool {
    if input.is_empty() {
        return false;
    }
    let mut at = 0usize;
    while at < input.len() {
        if input.len() - at < 5 || input[at..at + 3] != [0x17, 0x03, 0x03] {
            return false;
        }
        let len = u16::from_be_bytes([input[at + 3], input[at + 4]]) as usize;
        at += 5;
        if input.len() - at < len {
            return false;
        }
        at += len;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const UUID: [u8; 16] = [0x42; 16];

    #[test]
    fn frame_has_uuid_and_protocol_lengths() {
        let frame = make_frame(b"hello", Some(&UUID), COMMAND_CONTINUE, true);
        assert_eq!(&frame[..16], &UUID);
        assert_eq!(frame[16], COMMAND_CONTINUE);
        assert_eq!(u16::from_be_bytes([frame[17], frame[18]]), 5);
        let padding = u16::from_be_bytes([frame[19], frame[20]]) as usize;
        assert_eq!(frame.len(), 21 + 5 + padding);
        assert!(padding >= 895);
    }

    #[test]
    fn application_record_detector_requires_complete_records() {
        let mut record = vec![0x17, 0x03, 0x03, 0, 3, 1, 2, 3];
        assert!(is_complete_tls_application_data(&record));
        record.pop();
        assert!(!is_complete_tls_application_data(&record));
        assert!(!is_complete_tls_application_data(b"GET /"));
    }

    #[tokio::test]
    async fn client_frame_roundtrip_preserves_header_and_payload() {
        let (mut peer, server_side) = tokio::io::duplex(65536);
        let mut client = VisionStream::new_client(server_side, UUID);
        client.send_initial_frame().await.unwrap();
        client.write_all(b"payload").await.unwrap();
        client.flush().await.unwrap();

        let mut wire = vec![0u8; 4096];
        let n = peer.read(&mut wire).await.unwrap();
        assert!(n > 16 + 5);

        // Feed a realistic response: plain VLESS header, then the first
        // server-to-client UUID-prefixed frame and a terminating frame.
        let first = make_frame(&[], Some(&UUID), COMMAND_CONTINUE, true);
        let second = make_frame(b"reply", None, COMMAND_END, false);
        // The server side of the test uses its raw inner stream so we can
        // validate the reader independently of the writer path.
        let (mut producer, response_io) = tokio::io::duplex(65536);
        let mut reader = VisionStream::new_client(response_io, UUID);
        tokio::spawn(async move {
            producer.write_all(&[0, 0]).await.unwrap();
            producer.write_all(&first).await.unwrap();
            producer.write_all(&second).await.unwrap();
            producer.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        reader.read_to_end(&mut got).await.unwrap();
        let mut expected = vec![0, 0];
        expected.extend_from_slice(b"reply");
        assert_eq!(got, expected);

        // Keep the client and server variables live long enough to ensure the
        // generic stream remains usable in both directions.
        let _ = (&mut client, n);
    }

    #[tokio::test]
    async fn bad_uuid_is_rejected_after_response_header() {
        let (mut producer, response_io) = tokio::io::duplex(4096);
        let mut reader = VisionStream::new_client(response_io, UUID);
        tokio::spawn(async move {
            producer.write_all(&[0, 0]).await.unwrap();
            producer.write_all(&[0x99; 16]).await.unwrap();
        });
        let mut out = [0u8; 64];
        assert_eq!(reader.read(&mut out).await.unwrap(), 2);
        assert!(reader.read(&mut out).await.is_err());
    }

    #[tokio::test]
    async fn server_reader_unframes_initial_uuid_and_payload() {
        let (mut producer, input) = tokio::io::duplex(4096);
        let mut server = VisionStream::new_server(input, UUID);
        tokio::spawn(async move {
            producer
                .write_all(&make_frame(&[], Some(&UUID), COMMAND_CONTINUE, false))
                .await
                .unwrap();
            producer
                .write_all(&make_frame(b"request", None, COMMAND_END, false))
                .await
                .unwrap();
            producer.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"request");
    }

    #[tokio::test]
    async fn transition_preserves_plain_bytes_already_buffered_after_final_frame() {
        let (mut producer, response_io) = tokio::io::duplex(4096);
        let mut reader = VisionStream::new_client(response_io, UUID);
        let final_frame = make_frame(b"payload", Some(&UUID), COMMAND_DIRECT, false);
        tokio::spawn(async move {
            producer.write_all(&[0, 0]).await.unwrap();
            producer.write_all(&final_frame).await.unwrap();
            producer.write_all(b"tail").await.unwrap();
        });

        let mut got = Vec::new();
        reader.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, [b"\0\0".as_slice(), b"payload", b"tail"].concat());
    }
}
