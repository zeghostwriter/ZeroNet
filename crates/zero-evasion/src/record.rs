//! Hiding the server name behind the version in the TLS record header.
//!
//! Every TLS record starts with five bytes: type, a two-byte version, a
//! two-byte length. A ClientHello is sent in a record of type 0x16 and, by
//! custom, version 0x0301. The version in that first record header carries no
//! meaning any more (the real one is inside the hello), and servers do not
//! look at it beyond "major version 3": OpenSSL, BoringSSL, Go and rustls all
//! accept 0x0304 or anything up to 0x03ff there.
//!
//! A filter that reads server names out of the stream does look: it only
//! parses records whose header says 0x0300 to 0x0303, and lets the rest by.
//!
//! ```text
//! what the client sends   16 03 01 05 00 ...    16 03 04 05 00 ...  (this module)
//! the server reads        a ClientHello         the same ClientHello
//! the filter reads        a ClientHello, name   "not TLS", no name
//! ```
//!
//! It costs nothing (three bytes of the first write change) and needs
//! nothing from the system, so it works on every platform, unlike the urgent
//! byte ([`crate::urgent`]). Where it does not work: an address the filter
//! buffers whole and judges by what the connection does afterwards (the
//! Cloudflare ranges): the handshake completes there and the first request is
//! never answered, which is why [`crate::choice`] puts it behind the urgent
//! byte and moves a server off it when it goes silent.
//!
//! The rule this module keeps: only the version bytes of the *first* record
//! change, and only when the first write starts like a TLS handshake record.
//! Everything else, every later byte and every read, passes straight through.
//!
//! [`EmptyRecordStream`] is the sibling that leans on the same blind spot from
//! the other side: it puts one empty handshake record (`16 03 03 00 00`, no
//! bytes of any message) in front of the hello, in the same segment. The
//! filter reads the empty record as the start of the stream and gives up on
//! the next one; servers skip a record with nothing in it, and the
//! transcript the handshake signs is unchanged, since the record holds no
//! handshake bytes.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The version written into the first record's header.
const VERSION: [u8; 2] = [0x03, 0x04];
/// Bytes of the stream that matter: the type and the two version bytes.
const HEADER: usize = 3;

/// A stream whose first write, when it starts a TLS handshake record, goes
/// out with [`VERSION`] in the record header (see the module text).
pub struct RecordVersionStream<S> {
    inner: S,
    /// How many bytes of the stream have been written, counted until the
    /// header is past (then it stays at [`HEADER`] and nothing is changed).
    sent: usize,
}

impl<S> RecordVersionStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, sent: 0 }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordVersionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.sent >= HEADER {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        // The first write of a TLS stack is the whole hello record; anything
        // that does not look like one is left alone for good.
        if this.sent == 0 && !(buf.len() >= HEADER && buf[0] == 0x16 && buf[1] == 0x03) {
            this.sent = HEADER;
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        // A copy, so a write that comes back pending is made again from the
        // caller's untouched bytes.
        let mut patched = buf.to_vec();
        patched[1..HEADER].copy_from_slice(&VERSION);
        let polled = Pin::new(&mut this.inner).poll_write(cx, &patched);
        if let Poll::Ready(Ok(n)) = &polled {
            this.sent += n;
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordVersionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

/// An empty handshake record, written ahead of the hello.
const EMPTY_RECORD: [u8; 5] = [0x16, 0x03, 0x03, 0x00, 0x00];

/// A stream whose first write, when it starts a TLS handshake record, goes
/// out behind an empty handshake record (see the module text).
pub struct EmptyRecordStream<S> {
    inner: S,
    /// Nothing written yet, so the next write may be the hello.
    first: bool,
    /// The empty record and the hello together, and how much of them the
    /// inner stream has taken. Kept until all of it went, so a partial write
    /// never splits the empty record from the hello.
    pending: Option<(Vec<u8>, usize)>,
}

impl<S> EmptyRecordStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            first: true,
            pending: None,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EmptyRecordStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if std::mem::take(&mut this.first)
            && buf.len() >= HEADER
            && buf[0] == 0x16
            && buf[1] == 0x03
        {
            this.pending = Some(([&EMPTY_RECORD[..], buf].concat(), 0));
        }
        let Some((data, done)) = this.pending.as_mut() else {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        };
        while *done < data.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &data[*done..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => *done += n,
                other => return other,
            }
        }
        this.pending = None;
        // The caller's bytes are all out; the empty record was ours.
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for EmptyRecordStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn written(first: &[u8], second: &[u8]) -> Vec<u8> {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut stream = RecordVersionStream::new(client);
        stream.write_all(first).await.unwrap();
        stream.write_all(second).await.unwrap();
        drop(stream);
        let mut out = Vec::new();
        server.read_to_end(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn a_hello_record_goes_out_with_the_other_version() {
        let hello = [0x16, 0x03, 0x01, 0x00, 0x04, 1, 2, 3, 4];
        let out = written(&hello, &[0x16, 0x03, 0x01, 9]).await;
        assert_eq!(&out[..9], &[0x16, 0x03, 0x04, 0x00, 0x04, 1, 2, 3, 4]);
        // The second write is not a first write: it is untouched.
        assert_eq!(&out[9..], &[0x16, 0x03, 0x01, 9]);
    }

    #[tokio::test]
    async fn bytes_that_are_not_a_handshake_record_are_left_alone() {
        let http = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(written(http, b"x").await, [&http[..], b"x"].concat());
        let alert = [0x15, 0x03, 0x01, 0, 2, 1, 0];
        assert_eq!(written(&alert, b"").await, alert);
    }

    #[tokio::test]
    async fn the_empty_record_goes_ahead_of_the_hello_only() {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut stream = EmptyRecordStream::new(client);
        let hello = [0x16, 0x03, 0x01, 0x00, 0x02, 7, 8];
        assert_eq!(stream.write(&hello).await.unwrap(), hello.len());
        stream.write_all(b"after").await.unwrap();
        drop(stream);
        let mut out = Vec::new();
        server.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, [&EMPTY_RECORD[..], &hello, b"after"].concat());
    }

    #[tokio::test]
    async fn the_empty_record_survives_a_small_pipe() {
        // A pipe that takes three bytes at a time: the empty record and the
        // hello still arrive in order, and the caller is told its own length.
        let (client, mut server) = tokio::io::duplex(3);
        let mut stream = EmptyRecordStream::new(client);
        let hello: Vec<u8> = [&[0x16, 0x03, 0x01, 0x00, 0x08][..], &[1; 8]].concat();
        let sent = hello.clone();
        let writer = tokio::spawn(async move {
            stream.write_all(&sent).await.unwrap();
        });
        let mut out = vec![0u8; EMPTY_RECORD.len() + hello.len()];
        server.read_exact(&mut out).await.unwrap();
        writer.await.unwrap();
        assert_eq!(out, [&EMPTY_RECORD[..], &hello].concat());
    }

    #[tokio::test]
    async fn a_first_write_that_is_not_a_hello_gets_no_empty_record() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut stream = EmptyRecordStream::new(client);
        stream.write_all(b"GET /").await.unwrap();
        drop(stream);
        let mut out = Vec::new();
        server.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"GET /");
    }

    #[tokio::test]
    async fn a_short_first_write_is_not_patched_later() {
        let out = written(&[0x16], &[0x03, 0x01, 0, 0]).await;
        assert_eq!(out, [0x16, 0x03, 0x01, 0, 0]);
    }
}
