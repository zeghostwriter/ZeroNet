//! A rate limit on what is read from a stream, for the traffic of clients
//! that have not proved who they are.
//!
//! How this works. [`Throttle`] wraps a stream and counts what is read from
//! it. The first `after_bytes` pass untouched, so a real browser-sized
//! exchange with the camouflage site looks normal; beyond that the stream is
//! held to `bytes_per_sec`, with `burst` bytes of credit that refills over
//! time (a token bucket). Writes pass straight through: the limit belongs to
//! the direction the wrapped stream is *read* in, so wrapping the client
//! limits its uploads and wrapping the target limits its downloads.
//!
//! The rule it keeps: a limit of zero is no limit, and a throttled read
//! always makes progress (at least one byte per refill tick), so a stream is
//! slowed, never stuck.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// How the reads of one stream are limited. All zero means unlimited.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Limit {
    pub after_bytes: u64,
    pub bytes_per_sec: u64,
    /// The most credit that can build up; defaults to one second's worth.
    pub burst: u64,
}

pub struct Throttle<S> {
    inner: S,
    limit: Limit,
    /// Bytes read so far, to know when `after_bytes` has passed.
    read: u64,
    /// Credit in bytes, and when it was last topped up.
    credit: f64,
    refilled: Instant,
    wait: Option<Pin<Box<Sleep>>>,
}

impl<S> Throttle<S> {
    pub fn new(inner: S, limit: Limit) -> Self {
        let capacity = Self::capacity_of(&limit);
        Self {
            inner,
            limit,
            read: 0,
            credit: capacity,
            refilled: Instant::now(),
            wait: None,
        }
    }

    /// The credit that can build up: the burst, or a second's worth when no
    /// burst is named.
    fn capacity_of(limit: &Limit) -> f64 {
        if limit.burst == 0 {
            limit.bytes_per_sec as f64
        } else {
            limit.burst as f64
        }
    }

    fn capacity(&self) -> f64 {
        Self::capacity_of(&self.limit)
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let earned =
            now.duration_since(self.refilled).as_secs_f64() * self.limit.bytes_per_sec as f64;
        self.credit = (self.credit + earned).min(self.capacity());
        self.refilled = now;
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Throttle<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.limit.bytes_per_sec == 0 {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        if this.read < this.limit.after_bytes {
            // Only as much as is still free, so the free part ends where it
            // was said to.
            let free = (this.limit.after_bytes - this.read).min(buf.remaining() as u64) as usize;
            let mut window = buf.take(free);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut window))?;
            let got = window.filled().len();
            // SAFETY: `got` bytes of the unfilled part were just written by
            // the inner read, through the window onto the same memory.
            unsafe { buf.assume_init(got) };
            buf.advance(got);
            this.read += got as u64;
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(wait) = this.wait.as_mut() {
                ready!(wait.as_mut().poll(cx));
                this.wait = None;
            }
            this.refill();
            if this.credit < 1.0 {
                // Come back when one byte has been earned.
                let secs = (1.0 - this.credit) / this.limit.bytes_per_sec as f64;
                this.wait = Some(Box::pin(tokio::time::sleep(Duration::from_secs_f64(secs))));
                continue;
            }
            let allowed = (this.credit as usize).min(buf.remaining());
            let mut limited = buf.take(allowed);
            let before = limited.filled().len();
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut limited))?;
            let got = limited.filled().len() - before;
            // `take` made a window onto `buf`'s unfilled space; what the read
            // wrote into it is there in `buf` too, initialised, and only
            // needs counting.
            // SAFETY: `got` bytes of the unfilled part were just written by
            // the inner read, through the window onto the same memory.
            unsafe { buf.assume_init(got) };
            buf.advance(got);
            this.credit -= got as f64;
            this.read += got as u64;
            return Poll::Ready(Ok(()));
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Throttle<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn time_to_read(total: usize, limit: Limit) -> Duration {
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            writer.write_all(&vec![7u8; total]).await.unwrap();
        });
        let mut throttled = Throttle::new(reader, limit);
        let started = std::time::Instant::now();
        let mut got = 0;
        let mut buffer = [0u8; 4096];
        while got < total {
            let n = throttled.read(&mut buffer).await.unwrap();
            assert!(n > 0, "the stream ended early");
            got += n;
        }
        started.elapsed()
    }

    #[tokio::test]
    async fn a_zero_limit_is_no_limit() {
        let elapsed = time_to_read(64 * 1024, Limit::default()).await;
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[tokio::test]
    async fn what_comes_before_after_bytes_is_not_slowed() {
        let limit = Limit {
            after_bytes: 32 * 1024,
            bytes_per_sec: 1000,
            burst: 1000,
        };
        let elapsed = time_to_read(32 * 1024, limit).await;
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[tokio::test]
    async fn after_the_free_part_the_rate_is_held() {
        // 1000 free bytes, then 4000 more at 2000 per second with a 500 byte
        // burst: 500 go at once and the other 3500 take about 1.75 seconds.
        let limit = Limit {
            after_bytes: 1000,
            bytes_per_sec: 2000,
            burst: 500,
        };
        let elapsed = time_to_read(5000, limit).await;
        assert!(
            elapsed >= Duration::from_millis(1500) && elapsed < Duration::from_secs(4),
            "{elapsed:?}"
        );
    }
}
