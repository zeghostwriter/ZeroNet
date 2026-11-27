//! Inbound preprocessing: what to do with a packet whose local stream is gone.
//!
//! When a packet arrives for a stream the client no longer has in its table,
//! the client has to decide between three things: route it (the stream is
//! actually live), drop it silently, or answer with a small control reset so
//! the server stops resending. Getting this right matters for the phone — a
//! wrong "route" would touch a freed stream, and a needless reset wastes the
//! user's cellular data and adds a packet the censor can see. So the client
//! keeps a short memory of streams it closed on purpose (a TCP `TIME_WAIT`-like
//! window) and treats late packets for them quietly.
//!
//! This module is the deterministic half of that path, split in two:
//!
//!   * [`ClosedStreamRegistry`] — the "recently closed" memory. A sans-IO data
//!     structure (an explicit `now` goes in, no clock of its own) that the live
//!     layer fills from the stream-close path and queries on every orphan
//!     packet.
//!   * [`classify_inbound`] — the pure decision for one orphan packet: given its
//!     type and whether its stream is live or recently closed, return the
//!     [`InboundAction`] the caller carries out.
//!
//! Ported from the Go client's `internal/client/client_utils.go`
//! (`preprocessInboundPacket`, `handleMissingStreamPacket`,
//! `ackRecentlyClosedStreamPacket`, and the `recentlyClosed*` registry) at the
//! pinned release `v2026.06.13.234407-7de2476`.

#[cfg(test)]
mod tests;

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::time::{Duration, Instant};

use zero_protocol::masterdns::enums::{
    control_ack_for, is_close_stream_packet, reverse_control_ack_for, PACKET_STREAM_DATA,
    PACKET_STREAM_DATA_ACK, PACKET_STREAM_DATA_NACK, PACKET_STREAM_RESEND, PACKET_STREAM_RST,
    PACKET_STREAM_RST_ACK,
};

/// The most streams the registry will remember at once. During a long session
/// a client can open and close many thousands of streams, so the memory is
/// capped and the earliest-expiring entries are evicted once it is full, the
/// same ceiling the Go client uses (`maxRecentlyClosed`).
const MAX_REMEMBERED: usize = 2000;

/// Fallback window if the configured retention is zero or negative. The Go
/// `rememberClosedStream` applies this same 15 s floor; in practice the config
/// is clamped above zero before it ever reaches here, so this only guards a
/// misconfiguration.
const FALLBACK_RETENTION: Duration = Duration::from_secs(15);

/// One remembered stream and when it should be forgotten. Kept in a min-heap
/// (earliest `expires` first) so pruning only ever looks at the front; the map
/// beside it is the real source of truth, and a heap entry is stale once the
/// map no longer agrees with its `expires` (which happens when a stream is
/// re-closed with a fresh window).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    expires: Instant,
    stream_id: u16,
}

// `BinaryHeap` is a *max*-heap, so the ordering is reversed: the entry that
// compares "greatest" here is the one that expires soonest, which is what we
// want at the top. Ties break on stream id purely to make the order total and
// deterministic (Go's heap leaves ties arbitrary, but ties only matter at the
// 2000-entry eviction edge and never touch the wire).
impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .expires
            .cmp(&self.expires)
            .then_with(|| other.stream_id.cmp(&self.stream_id))
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Does a stream-close reason mean the stream should be remembered as
/// recently-closed? Only a clean, mutually-agreed close counts: the two fixed
/// completion reasons, or any reason that ends in "acknowledged" (an ack came
/// back, so the peer knows the stream is gone). A stream that died some other
/// way is not remembered, because a late packet for it is worth a reset.
///
/// Mirrors the Go `shouldRememberClosedStream` exactly, trimming surrounding
/// whitespace first.
pub fn should_remember(reason: &str) -> bool {
    let reason = reason.trim();
    if reason.is_empty() {
        return false;
    }
    reason == "close handshake completed"
        || reason == "client local disconnect completed"
        || reason.ends_with("acknowledged")
}

/// A short memory of streams the client closed on purpose, so late packets for
/// them can be answered quietly instead of routed or met with a fresh reset.
///
/// Sans-IO: every method that cares about time takes `now` from the caller, so
/// the live layer owns the clock and this stays trivially testable. The caller
/// also owns the lock around it; the type itself is a plain data structure.
///
/// # The one rule to remember (the invariant)
///
/// The map is the source of truth. The heap only speeds up pruning and may hold
/// stale copies; an entry is live only if the map still maps its stream to the
/// exact `expires` the heap entry carries.
#[derive(Debug, Clone)]
pub struct ClosedStreamRegistry {
    retention: Duration,
    entries: HashMap<u16, Instant>,
    heap: BinaryHeap<Entry>,
}

impl ClosedStreamRegistry {
    /// A registry whose entries live for `retention`. A zero or negative
    /// `retention` falls back to [`FALLBACK_RETENTION`], matching the Go floor.
    pub fn new(retention: Duration) -> Self {
        let retention = if retention.is_zero() {
            FALLBACK_RETENTION
        } else {
            retention
        };
        Self {
            retention,
            entries: HashMap::new(),
            heap: BinaryHeap::new(),
        }
    }

    /// The window entries are kept for (after the zero/negative fallback).
    pub fn retention(&self) -> Duration {
        self.retention
    }

    /// How many streams are currently remembered (expired-but-not-yet-pruned
    /// entries may still be counted until the next prune).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is remembered right now.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remember `stream_id` as closed, expiring `retention` from `now`. Stream
    /// 0 (the virtual control stream) is never remembered. Re-remembering an
    /// already-known stream refreshes its window.
    ///
    /// The caller decides *whether* to remember (via [`should_remember`] on the
    /// close reason); this just does it. Prunes expired entries first, then caps
    /// the memory at [`MAX_REMEMBERED`], evicting the earliest-expiring streams.
    pub fn remember(&mut self, stream_id: u16, now: Instant) {
        if stream_id == 0 {
            return;
        }
        let expires = now + self.retention;
        self.prune(now);
        self.entries.insert(stream_id, expires);
        self.heap.push(Entry { expires, stream_id });
        self.evict(MAX_REMEMBERED);
    }

    /// Is `stream_id` currently remembered as recently closed? Stream 0 never
    /// is. Prunes first, then reports whether a live (unexpired) entry remains;
    /// an entry found expired is dropped on the way out.
    pub fn is_recently_closed(&mut self, stream_id: u16, now: Instant) -> bool {
        if stream_id == 0 {
            return false;
        }
        self.prune(now);
        match self.entries.get(&stream_id) {
            Some(&expires) if now < expires => true,
            Some(_) => {
                self.entries.remove(&stream_id);
                false
            }
            None => false,
        }
    }

    /// Forget everything (session reset). Keeps the configured retention.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.heap.clear();
    }

    /// Drop every entry whose window has passed as of `now`. Public so the live
    /// layer can run it on a timer, matching the Go `cleanupRecentlyClosed`.
    pub fn cleanup(&mut self, now: Instant) {
        self.prune(now);
    }

    /// Pop expired or stale entries off the front of the heap. Stops at the
    /// first live, unexpired entry, since the heap is ordered by expiry. A heap
    /// entry whose `expires` no longer matches the map is stale (the stream was
    /// re-closed) and is discarded without touching the map.
    fn prune(&mut self, now: Instant) {
        while let Some(top) = self.heap.peek().copied() {
            match self.entries.get(&top.stream_id) {
                Some(&expires) if expires == top.expires => {
                    if now < expires {
                        break;
                    }
                    self.entries.remove(&top.stream_id);
                    self.heap.pop();
                }
                _ => {
                    self.heap.pop();
                }
            }
        }
        self.compact();
    }

    /// Rebuild the heap from the map when it has collected too many stale
    /// entries, so a long session cannot grow it without bound. The threshold
    /// matches the Go `compactRecentlyClosedHeapLocked`: map length plus half
    /// again, but at least four slack entries.
    fn compact(&mut self) {
        let map_len = self.entries.len();
        let threshold = (map_len + map_len / 2).max(map_len + 4);
        if self.heap.len() <= threshold {
            return;
        }
        self.heap = self
            .entries
            .iter()
            .map(|(&stream_id, &expires)| Entry { expires, stream_id })
            .collect();
    }

    /// Evict earliest-expiring streams until at most `capacity` remain. Stale
    /// heap entries are skipped (not counted as an eviction), matching the Go
    /// `evictRecentlyClosedLocked`.
    fn evict(&mut self, capacity: usize) {
        while self.entries.len() > capacity {
            let Some(entry) = self.heap.pop() else {
                break;
            };
            match self.entries.get(&entry.stream_id) {
                Some(&expires) if expires == entry.expires => {
                    self.entries.remove(&entry.stream_id);
                }
                _ => {}
            }
        }
    }
}

/// What the caller should do with an inbound packet after orphan preprocessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundAction {
    /// Not consumed here: hand the packet to the normal live-stream path
    /// (immediate control-ack queueing and ARQ ack consumption, which need the
    /// live stream the preprocessor does not model). This is the result for
    /// stream 0 and for any packet whose stream is still in the table.
    Route,
    /// Consumed with no reply: drop the packet. An ack, a container, or a
    /// late packet for a stream closed cleanly enough that a reset is not owed.
    Consume,
    /// Consumed, and the caller should enqueue this orphan control packet so the
    /// server stops resending. `sequence_num` of 0 means the reset carries no
    /// sequence field (the Go `enqueueOrphanReset` sets `HasSequenceNum` only
    /// when the sequence is non-zero).
    Reset {
        packet_type: u8,
        stream_id: u16,
        sequence_num: u16,
    },
    /// Consumed, and the caller should mark this stream recently-closed (a
    /// `STREAM_RST_ACK` confirming our own reset was seen). No packet is sent.
    RememberClosed { stream_id: u16 },
}

/// Decide what to do with one inbound packet, the pure heart of the Go
/// `preprocessInboundPacket`.
///
/// `stream_exists` is whether the packet's stream is still in the live table,
/// and `recently_closed` is [`ClosedStreamRegistry::is_recently_closed`] for it
/// (the caller queries the registry only when the stream is an orphan — stream
/// id non-zero and not live — and passes `false` otherwise). Stream 0 and live
/// streams always [`Route`](InboundAction::Route); only an orphan packet is
/// classified further here.
pub fn classify_inbound(
    packet_type: u8,
    stream_id: u16,
    sequence_num: u16,
    stream_exists: bool,
    recently_closed: bool,
) -> InboundAction {
    if stream_id == 0 || stream_exists {
        return InboundAction::Route;
    }
    if recently_closed {
        classify_recently_closed(packet_type, stream_id, sequence_num)
    } else {
        classify_missing(packet_type, stream_id, sequence_num)
    }
}

/// Orphan packet for a stream we closed cleanly and still remember. Data (and
/// resends) earn a plain reset so the server gives up; a control packet we were
/// tracking earns its matching ack; everything else is dropped. Mirrors the Go
/// recently-closed branch plus `ackRecentlyClosedStreamPacket`.
fn classify_recently_closed(packet_type: u8, stream_id: u16, sequence_num: u16) -> InboundAction {
    if packet_type == PACKET_STREAM_DATA || packet_type == PACKET_STREAM_RESEND {
        return InboundAction::Reset {
            packet_type: PACKET_STREAM_RST,
            stream_id,
            sequence_num: 0,
        };
    }
    if packet_type == PACKET_STREAM_DATA_ACK || packet_type == PACKET_STREAM_DATA_NACK {
        return InboundAction::Consume;
    }
    if reverse_control_ack_for(packet_type).is_some() {
        return InboundAction::Consume;
    }
    if let Some(ack) = control_ack_for(packet_type) {
        return InboundAction::Reset {
            packet_type: ack,
            stream_id,
            sequence_num,
        };
    }
    InboundAction::Consume
}

/// Orphan packet for a stream we have no memory of. Containers and raw replies
/// are dropped untouched; data acks are dropped; a `STREAM_RST_ACK` confirms a
/// close so the stream is remembered; other acks are dropped; and anything that
/// looks like it opened or is tearing down a stream earns the matching reset so
/// the server stops. Mirrors the Go `handleMissingStreamPacket` (whose own
/// boolean is discarded by the caller, so every path here consumes).
fn classify_missing(packet_type: u8, stream_id: u16, sequence_num: u16) -> InboundAction {
    use zero_protocol::masterdns::enums::{
        PACKET_DNS_QUERY_RES, PACKET_PACKED_CONTROL_BLOCKS, PACKET_PONG,
    };

    if packet_type == PACKET_PACKED_CONTROL_BLOCKS
        || packet_type == PACKET_PONG
        || packet_type == PACKET_DNS_QUERY_RES
    {
        return InboundAction::Consume;
    }
    if packet_type == PACKET_STREAM_DATA_ACK || packet_type == PACKET_STREAM_DATA_NACK {
        return InboundAction::Consume;
    }
    // A STREAM_RST_ACK is the peer confirming our reset; remember the stream and
    // send nothing. Checked before the generic reverse-ack test (which would
    // otherwise swallow it without remembering).
    if packet_type == PACKET_STREAM_RST_ACK {
        return InboundAction::RememberClosed { stream_id };
    }
    if reverse_control_ack_for(packet_type).is_some() {
        return InboundAction::Consume;
    }
    // A STREAM_RST echoes back a RST_ACK that carries the original sequence, so
    // this is handled before the generic close-stream case (which uses no
    // sequence).
    if packet_type == PACKET_STREAM_RST {
        return InboundAction::Reset {
            packet_type: PACKET_STREAM_RST_ACK,
            stream_id,
            sequence_num,
        };
    }
    if is_close_stream_packet(packet_type) {
        if let Some(ack) = control_ack_for(packet_type) {
            return InboundAction::Reset {
                packet_type: ack,
                stream_id,
                sequence_num: 0,
            };
        }
    }
    InboundAction::Reset {
        packet_type: PACKET_STREAM_RST,
        stream_id,
        sequence_num: 0,
    }
}
