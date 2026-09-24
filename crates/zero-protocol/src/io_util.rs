//! Shared buffering primitives for the framed protocol streams.
//!
//! The AEAD framings (Shadowsocks, Shadowsocks 2022, VMess, AnyTLS) all parse
//! "need N more bytes" state machines. Reading exactly N bytes per step costs
//! one `poll_read` (usually one syscall or one TLS record copy) per length
//! field and another per payload, and allocating per frame on top of that.
//! [`ReadBuffer`] instead reads opportunistically into one reusable buffer and
//! lets the parser decrypt frames in place, so a single read can yield several
//! frames and the steady state allocates nothing.
//!
//! [`WriteBuffer`] is the matching reusable output buffer, and
//! [`ReplayFilter`] is the bounded, time-windowed replay set used by the
//! server handshakes that the specs require to reject replays.

use std::collections::HashSet;
use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Default read-buffer size. Large enough for two maximum Shadowsocks chunks
/// or several VMess chunks per read, small enough to keep per-connection
/// memory modest. Frames larger than this grow the buffer on demand.
pub(crate) const DEFAULT_READ_CAPACITY: usize = 32 * 1024;

/// A reusable, compacting read buffer.
///
/// Bytes between `start` and `end` are buffered but not yet consumed. The
/// parser may mutate them in place (to decrypt) and consumes them once the
/// frame is fully delivered; the buffer never moves or overwrites unconsumed
/// bytes except by compaction, which preserves their order and contents.
#[derive(Debug, Default)]
pub(crate) struct ReadBuffer {
    buf: Vec<u8>,
    start: usize,
    end: usize,
    capacity: usize,
}

impl ReadBuffer {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            end: 0,
            capacity,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.end - self.start
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    pub(crate) fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.end]
    }

    pub(crate) fn consume(&mut self, n: usize) {
        debug_assert!(n <= self.len());
        self.start += n.min(self.len());
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Make room for `extra` more bytes after `end`, compacting or growing.
    fn reserve_contiguous(&mut self, extra: usize) {
        let needed = self.len() + extra;
        if self.buf.len() < needed.max(self.capacity) {
            // Grow first so a compaction below has room to land in.
            let target = needed.max(self.capacity);
            self.buf.resize(target, 0);
        }
        if self.end + extra > self.buf.len() {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
    }

    /// Ensure at least `need` bytes are buffered, reading as much as the
    /// transport offers into the free space.
    ///
    /// Returns `Ready(Ok(true))` once `len() >= need`, and `Ready(Ok(false))`
    /// when the transport reached EOF first (whatever arrived stays buffered,
    /// so callers can distinguish a clean EOF at a frame boundary from a
    /// truncated frame by checking [`ReadBuffer::is_empty`]).
    pub(crate) fn poll_fill<R>(
        &mut self,
        mut reader: Pin<&mut R>,
        cx: &mut Context<'_>,
        need: usize,
    ) -> Poll<io::Result<bool>>
    where
        R: AsyncRead + ?Sized,
    {
        if self.len() >= need {
            return Poll::Ready(Ok(true));
        }
        self.reserve_contiguous(need - self.len());
        while self.len() < need {
            let mut read = ReadBuf::new(&mut self.buf[self.end..]);
            match reader.as_mut().poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let n = read.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(false));
                    }
                    self.end += n;
                }
            }
        }
        Poll::Ready(Ok(true))
    }
}

/// A reusable output buffer drained into the transport.
#[derive(Debug, Default)]
pub(crate) struct WriteBuffer {
    buf: Vec<u8>,
    pos: usize,
}

impl WriteBuffer {
    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn len(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The buffer to append new output to. Appending while older output is
    /// still pending is allowed and keeps byte order.
    pub(crate) fn buf_mut(&mut self) -> &mut Vec<u8> {
        if self.pos > 0 && self.pos >= self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        &mut self.buf
    }

    /// Write out everything buffered. Completes only when the transport has
    /// accepted every byte.
    pub(crate) fn poll_drain<W>(
        &mut self,
        mut writer: Pin<&mut W>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>>
    where
        W: AsyncWrite + ?Sized,
    {
        while self.pos < self.buf.len() {
            match writer.as_mut().poll_write(cx, &self.buf[self.pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "transport accepted zero bytes",
                    )))
                }
                Poll::Ready(Ok(n)) => self.pos += n,
            }
        }
        self.buf.clear();
        self.pos = 0;
        Poll::Ready(Ok(()))
    }
}

/// A bounded, two-generation replay set.
///
/// Every key is remembered for at least `window` and at most `2 * window`.
/// Each generation holds at most `max_per_generation` keys; a flood that
/// fills the current generation rotates it early, so memory stays bounded at
/// two generations no matter what the network sends (at the cost of a
/// shorter memory while under that flood).
pub(crate) struct ReplayFilter<const N: usize> {
    window: Duration,
    max_per_generation: usize,
    state: Mutex<Option<ReplayState<N>>>,
}

struct ReplayState<const N: usize> {
    current: HashSet<[u8; N]>,
    previous: HashSet<[u8; N]>,
    rotated_at: Instant,
}

impl<const N: usize> ReplayFilter<N> {
    pub(crate) const fn new(window: Duration, max_per_generation: usize) -> Self {
        Self {
            window,
            max_per_generation,
            state: Mutex::new(None),
        }
    }

    /// Record `key`, returning `false` when it was already seen within the
    /// replay window.
    pub(crate) fn check_and_insert(&self, key: &[u8; N]) -> bool {
        let now = Instant::now();
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = guard.get_or_insert_with(|| ReplayState {
            current: HashSet::new(),
            previous: HashSet::new(),
            rotated_at: now,
        });
        let elapsed = now.saturating_duration_since(state.rotated_at);
        if elapsed >= self.window * 2 {
            state.previous.clear();
            state.current.clear();
            state.rotated_at = now;
        } else if elapsed >= self.window {
            state.previous = std::mem::take(&mut state.current);
            state.rotated_at = now;
        }
        if state.current.contains(key) || state.previous.contains(key) {
            return false;
        }
        if state.current.len() >= self.max_per_generation {
            state.previous = std::mem::take(&mut state.current);
            state.rotated_at = now;
        }
        state.current.insert(*key);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_buffer_reads_ahead_and_compacts() {
        let (mut peer, mut reader) = tokio::io::duplex(1024);
        tokio::io::AsyncWriteExt::write_all(&mut peer, b"abcdefgh")
            .await
            .unwrap();
        let mut buffer = ReadBuffer::with_capacity(8);
        let ok = std::future::poll_fn(|cx| buffer.poll_fill(Pin::new(&mut reader), cx, 2))
            .await
            .unwrap();
        assert!(ok);
        // One read pulled everything that was available, not just two bytes.
        assert_eq!(buffer.data(), b"abcdefgh");
        buffer.consume(6);
        tokio::io::AsyncWriteExt::write_all(&mut peer, b"ijklmn")
            .await
            .unwrap();
        let ok = std::future::poll_fn(|cx| buffer.poll_fill(Pin::new(&mut reader), cx, 8))
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(buffer.data(), b"ghijklmn");
        drop(peer);
        buffer.consume(8);
        let ok = std::future::poll_fn(|cx| buffer.poll_fill(Pin::new(&mut reader), cx, 1))
            .await
            .unwrap();
        assert!(!ok);
        assert!(buffer.is_empty());
    }

    #[test]
    fn replay_filter_rejects_repeats_and_stays_bounded() {
        let filter = ReplayFilter::<4>::new(Duration::from_secs(60), 3);
        assert!(filter.check_and_insert(&[1, 0, 0, 0]));
        assert!(!filter.check_and_insert(&[1, 0, 0, 0]));
        assert!(filter.check_and_insert(&[2, 0, 0, 0]));
        assert!(filter.check_and_insert(&[3, 0, 0, 0]));
        // The generation is full: it rotates, but the rotated keys are still
        // remembered by the previous generation.
        assert!(filter.check_and_insert(&[4, 0, 0, 0]));
        assert!(!filter.check_and_insert(&[1, 0, 0, 0]));
        let guard = filter.state.lock().unwrap();
        let state = guard.as_ref().unwrap();
        assert!(state.current.len() <= 3 && state.previous.len() <= 3);
    }
}
