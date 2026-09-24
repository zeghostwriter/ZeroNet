//! TCP fragmentation.
//!
//! Splitting the TLS ClientHello across several TCP segments means the SNI
//! never appears contiguously in one segment, so stateless DPI that
//! string-matches within a single segment fails to reassemble it.
//!
//! The algorithm mirrors Xray's `FragmentWriter` (`proxy/freedom/freedom.go`)
//! byte for byte, because divergence here is directly observable to a censor
//! and would make Zray flows distinguishable from Xray flows.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::rand_between::rand_between;

/// Which writes get fragmented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packets {
    /// Only the first write, and only if it is a TLS handshake record. The
    /// record is re-framed into several smaller *valid* TLS records.
    TlsHello,
    /// Writes numbered `from..=to` (1-based) are split at raw byte
    /// boundaries, with no record re-framing.
    Range { from: u64, to: u64 },
}

#[derive(Debug, Clone, Copy)]
pub struct FragmentPolicy {
    pub packets: Packets,
    pub length_min: i64,
    pub length_max: i64,
    pub interval_min_ms: i64,
    pub interval_max_ms: i64,
    pub max_split_min: i64,
    pub max_split_max: i64,
}

impl Default for FragmentPolicy {
    fn default() -> Self {
        // BPB's field-tuned defaults (PLAN-02 §3.1).
        Self {
            packets: Packets::TlsHello,
            length_min: 100,
            length_max: 200,
            interval_min_ms: 1,
            interval_max_ms: 1,
            max_split_min: 0,
            max_split_max: 0,
        }
    }
}

impl FragmentPolicy {
    /// When the interval is zero Xray coalesces the re-framed records into a
    /// single write, which still defeats record-boundary matching but costs no
    /// extra latency or syscalls.
    fn combines_hello(&self) -> bool {
        self.interval_max_ms == 0
    }
}

/// Draw one fragment length.
///
/// Xray's config loader rejects non-positive lengths, but a policy can be
/// built directly. A zero draw would make the split loop emit empty fragments
/// forever (an unbounded allocation), and a negative one would wrap to a huge
/// `usize`; one byte is the smallest step that always makes progress.
fn fragment_len(policy: &FragmentPolicy) -> usize {
    let drawn = rand_between(policy.length_min, policy.length_max);
    usize::try_from(drawn).unwrap_or(0).max(1)
}

/// One planned output chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub bytes: Vec<u8>,
    /// Delay to observe *after* writing this chunk.
    pub delay_ms: i64,
}

/// Plan the fragmentation of a TLS handshake record.
///
/// Returns `None` when the input is not a fragmentable ClientHello, in which
/// case the caller must pass the buffer through untouched.
pub fn plan_tls_hello(buf: &[u8], policy: &FragmentPolicy) -> Option<Vec<Chunk>> {
    if buf.len() <= 5 || buf[0] != 22 {
        return None;
    }
    let record_len = 5 + ((buf[3] as usize) << 8 | buf[4] as usize);
    if buf.len() < record_len {
        // Already fragmented by someone else; do not re-frame.
        return None;
    }

    let data = &buf[5..record_len];
    let max_split = rand_between(policy.max_split_min, policy.max_split_max);
    let mut chunks = Vec::new();
    let mut combined: Vec<u8> = Vec::new();
    let mut from = 0usize;
    let mut split_num: i64 = 0;

    loop {
        let mut to = from.saturating_add(fragment_len(policy));
        split_num += 1;
        if to > data.len() || (max_split > 0 && split_num >= max_split) {
            to = data.len();
        }
        let l = to - from;

        // Each fragment is a complete TLS record: the original content type
        // and version, a rewritten length, then the slice.
        let mut rec = Vec::with_capacity(5 + l);
        rec.extend_from_slice(&buf[..3]);
        rec.push((l >> 8) as u8);
        rec.push(l as u8);
        rec.extend_from_slice(&data[from..to]);

        if policy.combines_hello() {
            combined.extend_from_slice(&rec);
        } else {
            chunks.push(Chunk {
                bytes: rec,
                delay_ms: rand_between(policy.interval_min_ms, policy.interval_max_ms),
            });
        }

        from = to;
        if from == data.len() {
            break;
        }
    }

    if !combined.is_empty() {
        chunks.push(Chunk {
            bytes: combined,
            delay_ms: 0,
        });
    }

    // Anything after the record travels unfragmented.
    if buf.len() > record_len {
        chunks.push(Chunk {
            bytes: buf[record_len..].to_vec(),
            delay_ms: 0,
        });
    }

    Some(chunks)
}

/// Plan a raw byte-boundary split, used by `Packets::Range`.
pub fn plan_raw(buf: &[u8], policy: &FragmentPolicy) -> Vec<Chunk> {
    let max_split = rand_between(policy.max_split_min, policy.max_split_max);
    let mut chunks = Vec::new();
    let mut from = 0usize;
    let mut split_num: i64 = 0;

    while from < buf.len() {
        let mut to = from.saturating_add(fragment_len(policy));
        split_num += 1;
        if to > buf.len() || (max_split > 0 && split_num >= max_split) {
            to = buf.len();
        }
        chunks.push(Chunk {
            bytes: buf[from..to].to_vec(),
            delay_ms: rand_between(policy.interval_min_ms, policy.interval_max_ms),
        });
        from = to;
    }
    chunks
}

/// A stream wrapper that fragments outbound writes.
///
/// Writes are planned once and then drained across poll cycles, so a partially
/// flushed plan is never restarted and never duplicates bytes on the wire.
pub struct FragmentStream<S> {
    inner: S,
    policy: FragmentPolicy,
    write_count: u64,
    /// Chunks still to be written, plus the offset within the head chunk.
    queue: std::collections::VecDeque<Chunk>,
    head_offset: usize,
    /// How many bytes of the caller's buffer the in-flight plan accounts for.
    pending_input: usize,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> FragmentStream<S> {
    pub fn new(inner: S, policy: FragmentPolicy) -> Self {
        Self {
            inner,
            policy,
            write_count: 0,
            queue: std::collections::VecDeque::new(),
            head_offset: 0,
            pending_input: 0,
            sleep: None,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    fn should_fragment(&self, count: u64) -> bool {
        match self.policy.packets {
            Packets::TlsHello => count == 1,
            Packets::Range { from, to } => count >= from && count <= to,
        }
    }
}

impl<S: AsyncWrite + Unpin> FragmentStream<S> {
    /// Drain the queued plan. Returns `Ready(Ok(()))` only when empty.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(sleep) = self.sleep.as_mut() {
                match sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => self.sleep = None,
                    Poll::Pending => return Poll::Pending,
                }
            }

            let Some(front) = self.queue.front() else {
                return Poll::Ready(Ok(()));
            };

            let remaining = &front.bytes[self.head_offset..];
            match Pin::new(&mut self.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "fragment write returned 0",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    self.head_offset += n;
                    if self.head_offset >= front.bytes.len() {
                        let delay = front.delay_ms;
                        self.queue.pop_front();
                        self.head_offset = 0;
                        if delay > 0 {
                            self.sleep = Some(Box::pin(tokio::time::sleep(
                                std::time::Duration::from_millis(delay as u64),
                            )));
                        }
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Finish any in-flight plan before accepting new input.
        if !this.queue.is_empty() || this.sleep.is_some() {
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {
                    let consumed = std::mem::take(&mut this.pending_input);
                    if consumed > 0 {
                        return Poll::Ready(Ok(consumed));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.write_count += 1;
        let count = this.write_count;

        if !this.should_fragment(count) {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        let plan = match this.policy.packets {
            Packets::TlsHello => plan_tls_hello(buf, &this.policy),
            Packets::Range { .. } => Some(plan_raw(buf, &this.policy)),
        };

        let Some(chunks) = plan else {
            // Not fragmentable; this write did not consume its turn.
            this.write_count -= 1;
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        };

        this.queue = chunks.into();
        this.head_offset = 0;
        this.pending_input = buf.len();

        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {
                let consumed = std::mem::take(&mut this.pending_input);
                Poll::Ready(Ok(consumed))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentStream<S> {
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
    use tokio::io::AsyncWriteExt;

    /// Build a synthetic TLS handshake record of `payload` bytes.
    fn tls_record(payload_len: usize) -> Vec<u8> {
        let mut v = vec![0x16, 0x03, 0x01];
        v.push((payload_len >> 8) as u8);
        v.push(payload_len as u8);
        v.extend((0..payload_len).map(|i| (i % 251) as u8));
        v
    }

    fn policy() -> FragmentPolicy {
        FragmentPolicy {
            interval_min_ms: 1,
            interval_max_ms: 1,
            ..Default::default()
        }
    }

    #[test]
    fn non_tls_input_is_not_planned() {
        assert!(plan_tls_hello(b"GET / HTTP/1.1\r\n\r\n", &policy()).is_none());
    }

    #[test]
    fn short_buffer_is_not_planned() {
        assert!(plan_tls_hello(&[0x16, 0x03, 0x01, 0x00], &policy()).is_none());
    }

    #[test]
    fn truncated_record_passes_through() {
        // Header claims 500 bytes but only 100 are present.
        let mut v = tls_record(100);
        v[3] = 0x01;
        v[4] = 0xf4;
        assert!(plan_tls_hello(&v, &policy()).is_none());
    }

    #[test]
    fn fragments_reassemble_to_the_original_record() {
        let original = tls_record(517);
        let chunks = plan_tls_hello(&original, &policy()).expect("should plan");
        assert!(chunks.len() > 1, "expected a split, got {}", chunks.len());

        // Every chunk must itself be a valid TLS record with the original
        // content type and version.
        let mut payload = Vec::new();
        for c in &chunks {
            assert_eq!(&c.bytes[..3], &original[..3]);
            let l = (c.bytes[3] as usize) << 8 | c.bytes[4] as usize;
            assert_eq!(l, c.bytes.len() - 5);
            payload.extend_from_slice(&c.bytes[5..]);
        }
        assert_eq!(payload, original[5..]);
    }

    #[test]
    fn fragment_lengths_respect_the_configured_range() {
        let original = tls_record(2000);
        let chunks = plan_tls_hello(&original, &policy()).unwrap();
        // All but the final chunk must be a full-size fragment.
        for c in &chunks[..chunks.len() - 1] {
            let l = c.bytes.len() - 5;
            assert!((100..200).contains(&l), "fragment length {l} out of range");
        }
    }

    #[test]
    fn zero_interval_coalesces_into_one_write() {
        let p = FragmentPolicy {
            interval_min_ms: 0,
            interval_max_ms: 0,
            ..Default::default()
        };
        let original = tls_record(1000);
        let chunks = plan_tls_hello(&original, &p).unwrap();
        assert_eq!(chunks.len(), 1, "interval 0 should coalesce");
        // Still multiple records inside that single write.
        let l0 = (chunks[0].bytes[3] as usize) << 8 | chunks[0].bytes[4] as usize;
        assert!(l0 < 1000);
    }

    #[test]
    fn max_split_caps_fragment_count() {
        let p = FragmentPolicy {
            length_min: 10,
            length_max: 11,
            max_split_min: 3,
            max_split_max: 3,
            ..policy()
        };
        let original = tls_record(1000);
        let chunks = plan_tls_hello(&original, &p).unwrap();
        assert_eq!(chunks.len(), 3);
    }

    #[test]
    fn trailing_bytes_after_the_record_are_preserved() {
        let mut original = tls_record(300);
        original.extend_from_slice(b"TRAILER");
        let chunks = plan_tls_hello(&original, &policy()).unwrap();
        let last = chunks.last().unwrap();
        assert_eq!(&last.bytes, b"TRAILER");
    }

    #[test]
    fn non_positive_lengths_still_terminate_and_deliver_everything() {
        for (length_min, length_max) in [(0, 0), (-5, -1), (0, 1)] {
            let p = FragmentPolicy {
                length_min,
                length_max,
                ..policy()
            };
            let original = tls_record(40);
            let chunks = plan_tls_hello(&original, &p).expect("should plan");
            let payload: Vec<u8> = chunks.iter().flat_map(|c| c.bytes[5..].to_vec()).collect();
            assert_eq!(payload, original[5..]);
            let raw = plan_raw(&original, &p);
            let joined: Vec<u8> = raw.iter().flat_map(|c| c.bytes.clone()).collect();
            assert_eq!(joined, original);
        }
    }

    #[test]
    fn raw_plan_reassembles_exactly() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
        let chunks = plan_raw(&data, &policy());
        assert!(chunks.len() > 1);
        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.bytes.clone()).collect();
        assert_eq!(joined, data);
    }

    #[tokio::test]
    async fn stream_writes_all_bytes_and_reports_full_length() {
        let (client, mut server) = tokio::io::duplex(65536);
        let original = tls_record(600);
        let expected_payload = original[5..].to_vec();

        let mut s = FragmentStream::new(client, policy());
        let n = s.write(&original).await.unwrap();
        assert_eq!(n, original.len(), "must report the caller's full length");
        s.flush().await.unwrap();
        drop(s);

        let mut got = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut server, &mut got)
            .await
            .unwrap();

        // Reassemble the records the peer saw.
        let mut payload = Vec::new();
        let mut i = 0;
        let mut records = 0;
        while i + 5 <= got.len() {
            let l = (got[i + 3] as usize) << 8 | got[i + 4] as usize;
            payload.extend_from_slice(&got[i + 5..i + 5 + l]);
            i += 5 + l;
            records += 1;
        }
        assert!(records > 1, "expected multiple records, got {records}");
        assert_eq!(payload, expected_payload);
    }

    #[tokio::test]
    async fn second_write_is_not_fragmented_in_tlshello_mode() {
        let (client, mut server) = tokio::io::duplex(65536);
        let mut s = FragmentStream::new(client, policy());
        s.write_all(&tls_record(300)).await.unwrap();

        let mut drain = vec![0u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut server, &mut drain).await;

        // A later TLS-looking write must pass through untouched.
        let later = tls_record(300);
        s.write_all(&later).await.unwrap();
        s.flush().await.unwrap();
        drop(s);

        let mut got = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut server, &mut got)
            .await
            .unwrap();
        assert!(got.ends_with(&later[5..]));
    }
}
