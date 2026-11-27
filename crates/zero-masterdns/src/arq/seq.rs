//! The 16-bit sequence-number space the stream layer runs in.
//!
//! Both directions of a stream number their packets with a `u16` that wraps.
//! "Later" and "earlier" are therefore relative: a packet is treated as ahead
//! of the receiver's next-expected sequence when the forward distance (modulo
//! 2^16) is in the first half of the ring, and behind it when that distance is
//! in the second half. Half the ring (32768) is the dividing line, exactly as
//! the Go server computes it, so the two ends always agree on which packets are
//! fresh.
//!
//! These are pure functions on the sequence numbers alone; the buffers and
//! timers that act on the verdicts live in the ARQ state machine.

/// Half of the sequence ring. A forward distance below this is "ahead"; at or
/// above it the packet is "behind" (a wrapped-around older sequence).
pub const HALF: u16 = 32768;

/// Forward distance from `base` to `sn`, modulo 2^16. This is `sn - base` with
/// wraparound: the number of steps you would advance `base` to reach `sn`.
#[inline]
pub fn forward_distance(sn: u16, base: u16) -> u16 {
    sn.wrapping_sub(base)
}

/// Whether `candidate` sits strictly behind `base` in the ring — a sequence the
/// receiver has already moved past. Mirrors Go `seqBehind`: not equal to
/// `base`, and the *backward* distance from `base` is within the near half.
#[inline]
pub fn seq_behind(base: u16, candidate: u16) -> bool {
    candidate != base && base.wrapping_sub(candidate) < HALF
}

/// Which receive bucket an inbound data sequence falls into, relative to the
/// receiver's next-expected sequence `rcv_nxt` and its advertised window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// A sequence the receiver has already passed (forward distance in the far
    /// half). The Go side re-ACKs it but does not buffer it, so a lost ACK on
    /// an old packet still gets answered.
    BehindReAck,
    /// Past the right edge of the receive window. Dropped silently, with no ACK,
    /// to push back on a sender that is too far ahead.
    BeyondWindow,
    /// Inside the window. Buffer it if the slot is free and the window allows,
    /// and always ACK it (even a duplicate) so the sender can release it.
    InWindow,
}

/// Classify an inbound data sequence, matching the branch order in Go
/// `processReceivedData`: first the behind-check (`diff >= 32768`), then the
/// window check (`diff > receiveWindowSize`), otherwise in-window.
#[inline]
pub fn classify(sn: u16, rcv_nxt: u16, receive_window_size: usize) -> Admit {
    let diff = forward_distance(sn, rcv_nxt);
    if diff >= HALF {
        Admit::BehindReAck
    } else if diff as usize > receive_window_size {
        Admit::BeyondWindow
    } else {
        Admit::InWindow
    }
}

/// The forward distance to use when deciding whether to emit NACKs for the gap
/// ahead of `rcv_nxt`, or `None` when there is nothing to NACK: the Go
/// `maybeSendDataNacks` skips a sequence that is exactly `rcv_nxt` (`diff == 0`)
/// or already behind it (`diff >= 32768`).
#[inline]
pub fn nack_distance(sn: u16, rcv_nxt: u16) -> Option<u16> {
    let diff = forward_distance(sn, rcv_nxt);
    if diff == 0 || diff >= HALF {
        None
    } else {
        Some(diff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_distance_wraps() {
        assert_eq!(forward_distance(5, 3), 2);
        assert_eq!(forward_distance(3, 5), u16::MAX - 1); // 65534
        assert_eq!(forward_distance(0, 0), 0);
        // Across the wrap boundary.
        assert_eq!(forward_distance(1, 0xFFFF), 2);
    }

    #[test]
    fn seq_behind_matches_go() {
        // Equal is never "behind".
        assert!(!seq_behind(10, 10));
        // One step back is behind.
        assert!(seq_behind(10, 9));
        // Just inside the near half behind.
        assert!(seq_behind(0, 0xFFFF));
        assert!(seq_behind(100, 100u16.wrapping_sub(HALF - 1)));
        // Exactly half away: forward, not behind.
        assert!(!seq_behind(0, HALF));
        // Far half the other way is "ahead", not behind.
        assert!(!seq_behind(10, 20));
    }

    #[test]
    fn classify_three_buckets() {
        let win = 600;
        // In order and within window.
        assert_eq!(classify(100, 100, win), Admit::InWindow);
        assert_eq!(classify(700, 100, win), Admit::InWindow); // diff 600 == win
                                                              // Just past the window edge.
        assert_eq!(classify(701, 100, win), Admit::BeyondWindow); // diff 601
                                                                  // Behind rcv_nxt (wrapped): forward distance in the far half.
        assert_eq!(classify(99, 100, win), Admit::BehindReAck);
        assert_eq!(classify(0xFFFF, 0, win), Admit::BehindReAck);
    }

    #[test]
    fn nack_distance_skips_current_and_behind() {
        assert_eq!(nack_distance(100, 100), None); // diff 0
        assert_eq!(nack_distance(99, 100), None); // behind
        assert_eq!(nack_distance(105, 100), Some(5));
        // Right at the half boundary is treated as behind (>= HALF).
        assert_eq!(nack_distance(100u16.wrapping_add(HALF), 100), None);
        assert_eq!(
            nack_distance(100u16.wrapping_add(HALF - 1), 100),
            Some(HALF - 1)
        );
    }
}
