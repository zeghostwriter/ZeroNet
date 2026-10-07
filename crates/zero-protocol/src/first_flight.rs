//! Sends a protocol's request header in the same write as the first payload.
//!
//! How this works: VLESS and Trojan open a proxied stream with a short
//! request header (who is asking, where to). Written on its own it becomes a
//! tiny TLS record and, with `TCP_NODELAY`, a tiny packet of a recognisable
//! size at the very start of every connection, followed by a second packet
//! carrying what the application wanted to say. [`HeaderFirst`] holds the
//! header back until the application writes, then hands both to the carrier
//! as one write: one record, one packet, one less thing to recognise.
//!
//! The rule it keeps: the header is always the first bytes on the carrier,
//! exactly once, and nothing the caller wrote is reordered or lost.
//!
//! The surprise: some protocols let the *server* speak first (SSH, SMTP), so
//! the application may never write until it has read. A header that waited
//! forever would deadlock those. So the first read starts a short timer
//! ([`FIRST_PAYLOAD_WAIT`]); if no payload has turned up by then the header
//! goes out alone, which is what happened on every connection before. Closing
//! the write side without having written does the same.
//!
//! A server's response header has no such problem: a client cannot use it
//! before the payload behind it anyway, so [`HeaderFirst::hold`] keeps it
//! until the first payload however long that takes, as Xray's server does.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

/// How long a header waits for a payload to travel with once the caller has
/// started reading. A local application answers within a few milliseconds;
/// this only ever runs out for server-first protocols, which then pay it once
/// per connection.
pub const FIRST_PAYLOAD_WAIT: Duration = Duration::from_millis(100);

/// The most payload copied in beside the header. The rest of a larger first
/// write is left with the caller, which writes it straight through next.
const FIRST_PAYLOAD_MAX: usize = 16 * 1024;

/// A stream whose first write carries `header` in front of the caller's bytes.
pub struct HeaderFirst<S> {
    inner: S,
    /// The header, joined by the first payload once there is one. Emptied
    /// (and its memory returned) as soon as it is all on the carrier.
    pending: Vec<u8>,
    written: usize,
    /// False while the header is still waiting for a payload.
    released: bool,
    /// The carrier still owes a flush for what `pending` held.
    flush_due: bool,
    /// Whether a read may start the timer that sends the header alone.
    wait_on_read: bool,
    wait: Option<Pin<Box<Sleep>>>,
}

impl<S> HeaderFirst<S> {
    /// For a request header: sent with the first payload, or alone once the
    /// caller has been reading for [`FIRST_PAYLOAD_WAIT`] without writing.
    pub fn new(inner: S, header: Vec<u8>) -> Self {
        Self::build(inner, header, true)
    }

    /// For a response header: sent with the first payload, or alone when the
    /// write side closes without one. Reading never sends it.
    pub fn hold(inner: S, header: Vec<u8>) -> Self {
        Self::build(inner, header, false)
    }

    fn build(inner: S, header: Vec<u8>, wait_on_read: bool) -> Self {
        Self {
            inner,
            // Nothing to hold back means nothing to wait for.
            released: header.is_empty(),
            pending: header,
            written: 0,
            flush_due: false,
            wait_on_read,
            wait: None,
        }
    }

    /// The carrier and whatever is still waiting to be written to it.
    #[cfg(test)]
    pub(crate) fn parts(&self) -> (&S, &[u8]) {
        (&self.inner, &self.pending[self.written..])
    }

    fn release(&mut self) {
        self.released = true;
        self.flush_due = true;
        self.wait = None;
    }
}

impl<S: AsyncWrite + Unpin> HeaderFirst<S> {
    /// Push the released header (and payload) to the carrier and flush it.
    /// A no-op while the header is still held, and once it has gone.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.released {
            return Poll::Ready(Ok(()));
        }
        while self.written < self.pending.len() {
            let n =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        if !self.pending.is_empty() {
            self.pending = Vec::new();
            self.written = 0;
        }
        if self.flush_due {
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
            self.flush_due = false;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HeaderFirst<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.released && this.wait_on_read {
            let wait = this
                .wait
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(FIRST_PAYLOAD_WAIT)));
            if wait.as_mut().poll(cx).is_ready() {
                this.release();
            }
        }
        // A caller that only reads from here on would never push the header
        // out, so reads drive it too. Not ready yet is fine: the carrier wakes
        // this task when it can take more.
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HeaderFirst<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.released {
            ready!(this.poll_drain(cx))?;
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let taken = buf.len().min(FIRST_PAYLOAD_MAX);
        this.pending.extend_from_slice(&buf[..taken]);
        this.release();
        // The bytes are ours now, so they count as written even if the
        // carrier cannot take them this instant; later calls finish the job.
        match this.poll_drain(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            _ => Poll::Ready(Ok(taken)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.released {
            this.release();
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A carrier that remembers each write it was handed as a separate chunk,
    /// which is what becomes a separate record and packet on a real one. It
    /// never has anything to read.
    #[derive(Default)]
    pub(crate) struct Chunks {
        pub(crate) writes: Vec<Vec<u8>>,
        pub(crate) flushes: usize,
        pub(crate) shut: bool,
    }

    impl AsyncRead for Chunks {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for Chunks {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shut = true;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn the_header_travels_in_the_first_payloads_write() {
        let mut stream = HeaderFirst::new(Chunks::default(), b"HEAD".to_vec());
        stream.write_all(b"hello").await.unwrap();
        stream.write_all(b"again").await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(
            stream.inner.writes,
            [b"HEADhello".to_vec(), b"again".to_vec()]
        );
        assert!(stream.inner.flushes >= 1);
        assert_eq!(stream.pending.capacity(), 0, "the held copy is given back");
    }

    #[tokio::test(start_paused = true)]
    async fn a_caller_that_reads_first_gets_the_header_sent_after_the_wait() {
        let mut stream = HeaderFirst::new(Chunks::default(), b"HEAD".to_vec());
        let mut byte = [0u8; 1];
        let early = tokio::time::timeout(FIRST_PAYLOAD_WAIT / 2, stream.read(&mut byte)).await;
        assert!(early.is_err());
        assert!(
            stream.inner.writes.is_empty(),
            "still waiting for a payload"
        );

        let late = tokio::time::timeout(FIRST_PAYLOAD_WAIT, stream.read(&mut byte)).await;
        assert!(late.is_err());
        assert_eq!(stream.inner.writes, [b"HEAD".to_vec()]);
        assert_eq!(stream.inner.flushes, 1);

        stream.write_all(b"reply").await.unwrap();
        assert_eq!(stream.inner.writes, [b"HEAD".to_vec(), b"reply".to_vec()]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_held_response_header_outlasts_any_amount_of_reading() {
        let mut stream = HeaderFirst::hold(Chunks::default(), b"HEAD".to_vec());
        let mut byte = [0u8; 1];
        let waited = tokio::time::timeout(FIRST_PAYLOAD_WAIT * 50, stream.read(&mut byte)).await;
        assert!(waited.is_err());
        assert!(stream.inner.writes.is_empty());
        assert!(stream.wait.is_none(), "no timer is ever armed");

        stream.write_all(b"first").await.unwrap();
        assert_eq!(stream.inner.writes, [b"HEADfirst".to_vec()]);
    }

    #[tokio::test]
    async fn closing_without_writing_still_sends_the_header() {
        let mut stream = HeaderFirst::new(Chunks::default(), b"HEAD".to_vec());
        stream.shutdown().await.unwrap();
        assert_eq!(stream.inner.writes, [b"HEAD".to_vec()]);
        assert!(stream.inner.shut);
    }

    #[tokio::test]
    async fn a_large_first_write_arrives_whole_and_in_order() {
        let payload: Vec<u8> = (0..FIRST_PAYLOAD_MAX * 3).map(|i| i as u8).collect();
        let mut stream = HeaderFirst::new(Chunks::default(), b"HEAD".to_vec());
        stream.write_all(&payload).await.unwrap();
        let sent = stream.inner.writes.concat();
        assert_eq!(&sent[..4], b"HEAD");
        assert_eq!(&sent[4..], &payload[..]);
        assert_eq!(stream.inner.writes[0].len(), 4 + FIRST_PAYLOAD_MAX);
    }

    #[tokio::test]
    async fn no_header_means_a_plain_passthrough() {
        let mut stream = HeaderFirst::new(Chunks::default(), Vec::new());
        stream.write_all(b"data").await.unwrap();
        assert_eq!(stream.inner.writes, [b"data".to_vec()]);
        assert!(stream.wait.is_none());
    }
}
