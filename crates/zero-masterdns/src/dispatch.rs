//! The TX-dispatch deterministic cores: how many copies of a packet to send,
//! and which stream the round-robin scheduler serves next.
//!
//! The live dispatcher is a loop over sockets and queues; these two pieces are
//! the decisions inside it that depend only on their inputs, pulled out so they
//! can be tested on their own and reused by the async layer.
//!
//! Ported from the Go client's `internal/client/{async_runtime,dispatcher}.go`
//! at the pinned release `v2026.06.13.234407-7de2476`.

#[cfg(test)]
mod tests;

use zero_protocol::masterdns::enums::{
    PACKET_PACKED_CONTROL_BLOCKS, PACKET_PING, PACKET_SOCKS5_SYN, PACKET_STREAM_CLOSE_READ,
    PACKET_STREAM_CLOSE_WRITE, PACKET_STREAM_SYN,
};

/// Is this one of the "setup" packet types that may use the larger
/// setup-duplication count? These are the handshake and teardown control
/// packets whose loss hurts the most, so the client is allowed to send more
/// copies of them. Mirrors the type list in the Go `runtimePacketDuplicationCount`.
fn is_setup_packet(packet_type: u8) -> bool {
    matches!(
        packet_type,
        PACKET_STREAM_SYN
            | PACKET_PACKED_CONTROL_BLOCKS
            | PACKET_SOCKS5_SYN
            | PACKET_STREAM_CLOSE_READ
            | PACKET_STREAM_CLOSE_WRITE
    )
}

/// How many copies of a packet to put on the wire (the tunnel has no built-in
/// loss recovery for the DNS carrier, so important packets are sent more than
/// once). `base` is the ordinary duplication count and `setup` the larger count
/// reserved for setup packets; both come from the (post-policy) session config.
///
/// The rule, matching the Go `runtimePacketDuplicationCount` exactly:
///
///  * the base count is floored at 1 (a zero or negative config still sends
///    one copy);
///  * a setup packet uses `setup` instead when `setup` is larger;
///  * a PING is capped at 2 copies no matter what, since a lost keepalive is
///    cheap to retry and flooding them wastes the phone's data.
///
/// The result is always at least 1, so it is returned as a `usize` ready to use
/// as a send-count.
pub fn duplication_count(packet_type: u8, base: i64, setup: i64) -> usize {
    let mut count = base.max(1);
    if is_setup_packet(packet_type) && setup > count {
        count = setup;
    }
    if packet_type == PACKET_PING {
        count = count.min(2);
    }
    count as usize
}

/// The orphan (session-level) queue's stand-in id in a dispatch pass. Streams
/// use their real `0..=65535` id; the orphan queue, which holds control packets
/// not tied to a live stream, is represented by `-1`, exactly as the Go
/// dispatcher appends `-1` to its sorted id list.
pub const ORPHAN_CANDIDATE: i32 = -1;

/// One entry the round-robin scheduler looks at in a single pass: a candidate
/// queue and a snapshot of its head. The live dispatcher fills this by peeking
/// each queue (without popping); [`select_stream`] then decides from the
/// snapshot alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchCandidate {
    /// The stream id, or [`ORPHAN_CANDIDATE`] for the orphan queue. The caller
    /// must present candidates in the dispatcher's iteration order: stream ids
    /// ascending, then the orphan candidate last.
    pub id: i32,
    /// The packet type at the head of this queue, or `None` if the queue is
    /// empty (nothing to peek, so this candidate cannot be chosen).
    pub head_type: Option<u8>,
    /// Whether this queue holds any work at all (Go's `FastSize() > 0`). Only
    /// consulted to decide whether stream 0 should yield its turn; a candidate
    /// with `head_type.is_some()` always also has work.
    pub has_work: bool,
}

/// What [`select_stream`] decided for one pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchSelection {
    /// The id of the chosen candidate, or `None` if nothing could be served
    /// this pass (every queue empty, or the only ready work was a stream-0 ping
    /// that yielded — which cannot happen, since it only yields when other work
    /// exists).
    pub selected: Option<i32>,
    /// The round-robin cursor to carry into the next pass. It advances to one
    /// past the *first* candidate that had anything to peek, even if that
    /// candidate then yielded, so the next pass starts fairly after it.
    pub new_cursor: i32,
}

/// Pick the next candidate to transmit from, round-robin, given a snapshot of
/// every candidate's head and the cursor from the previous pass.
///
/// The walk starts at the first candidate whose id is at or past `cursor`
/// (wrapping to the front if none is), then takes the first candidate that has
/// something to peek — with one fairness rule: if that candidate is stream 0
/// and its head is a PING, and *any other* candidate has work, stream 0 yields
/// its turn so real data is not held up behind a keepalive. When stream 0's
/// ping is the only work, it is served.
///
/// The cursor advances to one past the first candidate that had anything to
/// peek (whether or not it was ultimately chosen), which is what keeps the
/// scheduler fair across passes. If nothing could be peeked at all, the cursor
/// is returned unchanged.
///
/// Mirrors the selection loop in the Go `asyncStreamDispatcher`, including the
/// subtle detail that the cursor follows the first *peeked* id, not the first
/// *selected* one.
pub fn select_stream(candidates: &[DispatchCandidate], cursor: i32) -> DispatchSelection {
    let n = candidates.len();
    if n == 0 {
        return DispatchSelection {
            selected: None,
            new_cursor: cursor,
        };
    }

    // Start at the first candidate at or past the cursor; if the cursor is past
    // every id, wrap to the front.
    let start = candidates.iter().position(|c| c.id >= cursor).unwrap_or(0);

    let mut new_cursor = cursor;
    let mut rr_applied = false;
    for i in 0..n {
        let candidate = &candidates[(start + i) % n];
        let head = match candidate.head_type {
            Some(t) => t,
            None => continue,
        };

        // The cursor follows the first candidate we could peek, once per pass.
        if !rr_applied {
            new_cursor = candidate.id + 1;
            rr_applied = true;
        }

        // Stream 0's ping yields to any other ready work.
        if candidate.id == 0 && head == PACKET_PING {
            let other_work = candidates.iter().any(|o| o.id != 0 && o.has_work);
            if other_work {
                continue;
            }
        }

        return DispatchSelection {
            selected: Some(candidate.id),
            new_cursor,
        };
    }

    DispatchSelection {
        selected: None,
        new_cursor,
    }
}
