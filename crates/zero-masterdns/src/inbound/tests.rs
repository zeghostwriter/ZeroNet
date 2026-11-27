//! Tests for inbound orphan-packet preprocessing: the recently-closed registry
//! (remember, expire, stream-0 guard, refresh, cap eviction), the close-reason
//! classifier, and the per-packet decision — all against the Go
//! `preprocessInboundPacket` / `handleMissingStreamPacket` /
//! `ackRecentlyClosedStreamPacket` / `recentlyClosed*` behaviour.

use super::*;

use zero_protocol::masterdns::enums::{
    PACKET_DNS_QUERY_RES, PACKET_PACKED_CONTROL_BLOCKS, PACKET_PONG,
    PACKET_SOCKS5_HOST_UNREACHABLE, PACKET_SOCKS5_HOST_UNREACHABLE_ACK, PACKET_STREAM_CLOSE_READ,
    PACKET_STREAM_CLOSE_READ_ACK, PACKET_STREAM_CLOSE_WRITE, PACKET_STREAM_CLOSE_WRITE_ACK,
    PACKET_STREAM_SYN, PACKET_STREAM_SYN_ACK,
};

const RETENTION: Duration = Duration::from_secs(15);

// --- ClosedStreamRegistry --------------------------------------------------

#[test]
fn remembered_stream_is_recently_closed_within_the_window() {
    let t0 = Instant::now();
    let mut reg = ClosedStreamRegistry::new(RETENTION);
    reg.remember(7, t0);
    assert!(reg.is_recently_closed(7, t0 + Duration::from_secs(10)));
}

#[test]
fn entry_expires_at_the_end_of_the_window() {
    let t0 = Instant::now();
    let mut reg = ClosedStreamRegistry::new(RETENTION);
    reg.remember(7, t0);
    // At exactly the expiry instant it is no longer "recent" (now < expires is
    // false), and well past it is certainly gone.
    assert!(!reg.is_recently_closed(7, t0 + RETENTION));
    assert!(!reg.is_recently_closed(7, t0 + Duration::from_secs(20)));
}

#[test]
fn stream_zero_is_never_remembered_or_recent() {
    let t0 = Instant::now();
    let mut reg = ClosedStreamRegistry::new(RETENTION);
    reg.remember(0, t0);
    assert!(reg.is_empty());
    assert!(!reg.is_recently_closed(0, t0 + Duration::from_secs(1)));
}

#[test]
fn re_remembering_refreshes_the_window() {
    let t0 = Instant::now();
    let mut reg = ClosedStreamRegistry::new(RETENTION);
    reg.remember(7, t0);
    // Refresh ten seconds in: the new window reaches to t0+25s.
    reg.remember(7, t0 + Duration::from_secs(10));
    assert_eq!(reg.len(), 1);
    // Past the original expiry but inside the refreshed one.
    assert!(reg.is_recently_closed(7, t0 + Duration::from_secs(20)));
}

#[test]
fn cleanup_drops_expired_entries() {
    let t0 = Instant::now();
    let mut reg = ClosedStreamRegistry::new(RETENTION);
    reg.remember(1, t0);
    reg.remember(2, t0 + Duration::from_secs(5));
    // Run cleanup after the first has expired but the second has not.
    reg.cleanup(t0 + Duration::from_secs(16));
    assert_eq!(reg.len(), 1);
    assert!(reg.is_recently_closed(2, t0 + Duration::from_secs(16)));
}

#[test]
fn clear_forgets_everything_but_keeps_retention() {
    let t0 = Instant::now();
    let mut reg = ClosedStreamRegistry::new(RETENTION);
    reg.remember(1, t0);
    reg.remember(2, t0);
    reg.clear();
    assert!(reg.is_empty());
    assert_eq!(reg.retention(), RETENTION);
}

#[test]
fn zero_retention_falls_back_to_fifteen_seconds() {
    let reg = ClosedStreamRegistry::new(Duration::ZERO);
    assert_eq!(reg.retention(), FALLBACK_RETENTION);
}

#[test]
fn memory_is_capped_evicting_the_earliest_expiring() {
    let t0 = Instant::now();
    let mut reg = ClosedStreamRegistry::new(RETENTION);
    // Insert one past the cap, each a millisecond later so the first inserted
    // has the earliest expiry and is the one evicted. None expire over the
    // ~2 s span (retention is 15 s).
    for i in 0..=(MAX_REMEMBERED as u64) {
        let stream_id = (i + 1) as u16;
        reg.remember(stream_id, t0 + Duration::from_millis(i));
    }
    assert_eq!(reg.len(), MAX_REMEMBERED);
    // The very first stream (earliest expiry) was evicted; the last survives.
    let probe = t0 + Duration::from_millis(MAX_REMEMBERED as u64);
    assert!(!reg.is_recently_closed(1, probe));
    assert!(reg.is_recently_closed((MAX_REMEMBERED + 1) as u16, probe));
}

// --- should_remember -------------------------------------------------------

#[test]
fn should_remember_accepts_the_clean_close_reasons() {
    assert!(should_remember("close handshake completed"));
    assert!(should_remember("client local disconnect completed"));
    assert!(should_remember("ACK acknowledged"));
    assert!(should_remember("remote close acknowledged"));
    // Surrounding whitespace is trimmed first.
    assert!(should_remember("  close handshake completed  "));
}

#[test]
fn should_remember_rejects_everything_else() {
    assert!(!should_remember(""));
    assert!(!should_remember("   "));
    assert!(!should_remember("timed out"));
    assert!(!should_remember("reset by peer"));
}

// --- classify_inbound: route cases -----------------------------------------

#[test]
fn stream_zero_always_routes() {
    // Even with no live stream, stream 0 is the virtual control stream and is
    // handled by the live path, never classified as an orphan.
    let action = classify_inbound(PACKET_STREAM_DATA, 0, 5, false, false);
    assert_eq!(action, InboundAction::Route);
}

#[test]
fn a_live_stream_always_routes() {
    let action = classify_inbound(PACKET_STREAM_DATA, 42, 5, true, false);
    assert_eq!(action, InboundAction::Route);
}

// --- classify_inbound: recently-closed orphan ------------------------------

#[test]
fn recently_closed_data_earns_a_plain_reset() {
    let action = classify_inbound(PACKET_STREAM_DATA, 42, 9, false, true);
    assert_eq!(
        action,
        InboundAction::Reset {
            packet_type: PACKET_STREAM_RST,
            stream_id: 42,
            sequence_num: 0,
        }
    );
}

#[test]
fn recently_closed_resend_earns_a_plain_reset() {
    let action = classify_inbound(PACKET_STREAM_RESEND, 42, 9, false, true);
    assert_eq!(
        action,
        InboundAction::Reset {
            packet_type: PACKET_STREAM_RST,
            stream_id: 42,
            sequence_num: 0,
        }
    );
}

#[test]
fn recently_closed_data_ack_is_dropped() {
    assert_eq!(
        classify_inbound(PACKET_STREAM_DATA_ACK, 42, 9, false, true),
        InboundAction::Consume
    );
    assert_eq!(
        classify_inbound(PACKET_STREAM_DATA_NACK, 42, 9, false, true),
        InboundAction::Consume
    );
}

#[test]
fn recently_closed_reverse_ack_is_dropped() {
    // A packet that is itself an ack of one of our control packets needs no
    // answer.
    assert_eq!(
        classify_inbound(PACKET_STREAM_SYN_ACK, 42, 9, false, true),
        InboundAction::Consume
    );
}

#[test]
fn recently_closed_tracked_control_earns_its_ack_with_sequence() {
    // A CLOSE_WRITE for a stream we remember gets its matching ack, carrying
    // the packet's own sequence number.
    let action = classify_inbound(PACKET_STREAM_CLOSE_WRITE, 42, 9, false, true);
    assert_eq!(
        action,
        InboundAction::Reset {
            packet_type: PACKET_STREAM_CLOSE_WRITE_ACK,
            stream_id: 42,
            sequence_num: 9,
        }
    );
}

#[test]
fn recently_closed_untracked_type_is_dropped() {
    // A PONG is not ack-tracked, so for a remembered stream it is simply
    // dropped.
    assert_eq!(
        classify_inbound(PACKET_PONG, 42, 9, false, true),
        InboundAction::Consume
    );
}

// --- classify_inbound: unknown (missing) orphan ----------------------------

#[test]
fn missing_container_and_raw_replies_are_dropped() {
    for t in [
        PACKET_PACKED_CONTROL_BLOCKS,
        PACKET_PONG,
        PACKET_DNS_QUERY_RES,
    ] {
        assert_eq!(
            classify_inbound(t, 42, 9, false, false),
            InboundAction::Consume
        );
    }
}

#[test]
fn missing_data_acks_are_dropped() {
    assert_eq!(
        classify_inbound(PACKET_STREAM_DATA_ACK, 42, 9, false, false),
        InboundAction::Consume
    );
    assert_eq!(
        classify_inbound(PACKET_STREAM_DATA_NACK, 42, 9, false, false),
        InboundAction::Consume
    );
}

#[test]
fn missing_rst_ack_remembers_the_stream() {
    // The peer confirming our reset: remember the stream, send nothing.
    assert_eq!(
        classify_inbound(PACKET_STREAM_RST_ACK, 42, 9, false, false),
        InboundAction::RememberClosed { stream_id: 42 }
    );
}

#[test]
fn missing_other_reverse_ack_is_dropped() {
    assert_eq!(
        classify_inbound(PACKET_STREAM_SYN_ACK, 42, 9, false, false),
        InboundAction::Consume
    );
}

#[test]
fn missing_rst_echoes_an_ack_carrying_the_sequence() {
    let action = classify_inbound(PACKET_STREAM_RST, 42, 9, false, false);
    assert_eq!(
        action,
        InboundAction::Reset {
            packet_type: PACKET_STREAM_RST_ACK,
            stream_id: 42,
            sequence_num: 9,
        }
    );
}

#[test]
fn missing_close_stream_earns_its_ack_without_a_sequence() {
    // A CLOSE_READ for an unknown stream gets its ack with no sequence field.
    let action = classify_inbound(PACKET_STREAM_CLOSE_READ, 42, 9, false, false);
    assert_eq!(
        action,
        InboundAction::Reset {
            packet_type: PACKET_STREAM_CLOSE_READ_ACK,
            stream_id: 42,
            sequence_num: 0,
        }
    );
}

#[test]
fn missing_socks5_failure_earns_its_ack() {
    let action = classify_inbound(PACKET_SOCKS5_HOST_UNREACHABLE, 42, 9, false, false);
    assert_eq!(
        action,
        InboundAction::Reset {
            packet_type: PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
            stream_id: 42,
            sequence_num: 0,
        }
    );
}

#[test]
fn missing_data_falls_back_to_a_plain_reset() {
    // Data for a stream we have no memory of (never cleanly closed): a plain
    // reset with no sequence.
    let action = classify_inbound(PACKET_STREAM_DATA, 42, 9, false, false);
    assert_eq!(
        action,
        InboundAction::Reset {
            packet_type: PACKET_STREAM_RST,
            stream_id: 42,
            sequence_num: 0,
        }
    );
}

#[test]
fn missing_syn_falls_back_to_a_plain_reset() {
    // A STREAM_SYN is neither an ack nor a close packet, so the unknown-stream
    // fallback applies.
    let action = classify_inbound(PACKET_STREAM_SYN, 42, 9, false, false);
    assert_eq!(
        action,
        InboundAction::Reset {
            packet_type: PACKET_STREAM_RST,
            stream_id: 42,
            sequence_num: 0,
        }
    );
}
