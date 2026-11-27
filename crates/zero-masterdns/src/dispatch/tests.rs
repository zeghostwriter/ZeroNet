//! Tests for the dispatch cores: the per-type duplication count and the
//! round-robin stream selection, checked against the Go
//! `runtimePacketDuplicationCount` and `asyncStreamDispatcher` behaviour.

use super::*;

use zero_protocol::masterdns::enums::{PACKET_STREAM_DATA, PACKET_STREAM_SYN};

// --- duplication_count -----------------------------------------------------

#[test]
fn duplication_floors_at_one() {
    // A zero or negative base still sends a single copy.
    assert_eq!(duplication_count(PACKET_STREAM_DATA, 0, 2), 1);
    assert_eq!(duplication_count(PACKET_STREAM_DATA, -5, 2), 1);
}

#[test]
fn duplication_uses_base_for_ordinary_packets() {
    // Data is not a setup packet, so the larger setup count is ignored.
    assert_eq!(duplication_count(PACKET_STREAM_DATA, 3, 9), 3);
}

#[test]
fn duplication_bumps_setup_packets_when_setup_is_larger() {
    assert_eq!(duplication_count(PACKET_STREAM_SYN, 2, 5), 5);
    // ...but never shrinks below the base when setup is smaller.
    assert_eq!(duplication_count(PACKET_STREAM_SYN, 6, 3), 6);
}

#[test]
fn duplication_caps_ping_at_two() {
    assert_eq!(duplication_count(PACKET_PING, 10, 10), 2);
    // A base of one still yields one, not two.
    assert_eq!(duplication_count(PACKET_PING, 1, 10), 1);
}

// --- select_stream ---------------------------------------------------------

/// A candidate with work whose head is the given type.
fn ready(id: i32, head: u8) -> DispatchCandidate {
    DispatchCandidate {
        id,
        head_type: Some(head),
        has_work: true,
    }
}

/// A candidate with nothing to peek.
fn empty(id: i32) -> DispatchCandidate {
    DispatchCandidate {
        id,
        head_type: None,
        has_work: false,
    }
}

#[test]
fn selecting_from_nothing_keeps_the_cursor() {
    let sel = select_stream(&[], 5);
    assert_eq!(sel.selected, None);
    assert_eq!(sel.new_cursor, 5);
}

#[test]
fn all_empty_queues_select_nothing_and_keep_cursor() {
    let candidates = [empty(0), empty(1), empty(2)];
    let sel = select_stream(&candidates, -1);
    assert_eq!(sel.selected, None);
    assert_eq!(sel.new_cursor, -1);
}

#[test]
fn single_ready_stream_is_chosen_and_advances_cursor() {
    let candidates = [ready(3, PACKET_STREAM_DATA)];
    let sel = select_stream(&candidates, -1);
    assert_eq!(sel.selected, Some(3));
    assert_eq!(sel.new_cursor, 4);
}

#[test]
fn round_robin_resumes_after_the_cursor() {
    // All three ready; a cursor of 2 should start the walk at id 2.
    let candidates = [
        ready(1, PACKET_STREAM_DATA),
        ready(2, PACKET_STREAM_DATA),
        ready(3, PACKET_STREAM_DATA),
    ];
    let sel = select_stream(&candidates, 2);
    assert_eq!(sel.selected, Some(2));
    assert_eq!(sel.new_cursor, 3);
}

#[test]
fn cursor_past_every_id_wraps_to_the_front() {
    let candidates = [ready(1, PACKET_STREAM_DATA), ready(2, PACKET_STREAM_DATA)];
    let sel = select_stream(&candidates, 100);
    assert_eq!(sel.selected, Some(1));
    assert_eq!(sel.new_cursor, 2);
}

#[test]
fn walk_skips_empty_candidates() {
    let candidates = [empty(1), ready(2, PACKET_STREAM_DATA), empty(3)];
    let sel = select_stream(&candidates, -1);
    assert_eq!(sel.selected, Some(2));
    assert_eq!(sel.new_cursor, 3);
}

#[test]
fn stream_zero_ping_yields_to_other_work() {
    // Stream 0 has a ping; stream 5 has data. Stream 0 yields, 5 is served,
    // but the cursor still followed the first peeked id (0 -> cursor 1).
    let candidates = [ready(0, PACKET_PING), ready(5, PACKET_STREAM_DATA)];
    let sel = select_stream(&candidates, -1);
    assert_eq!(sel.selected, Some(5));
    assert_eq!(sel.new_cursor, 1);
}

#[test]
fn stream_zero_ping_is_served_when_alone() {
    // No other work, so the ping is sent.
    let candidates = [ready(0, PACKET_PING), empty(5)];
    let sel = select_stream(&candidates, -1);
    assert_eq!(sel.selected, Some(0));
    assert_eq!(sel.new_cursor, 1);
}

#[test]
fn stream_zero_non_ping_is_served_even_with_other_work() {
    // Stream 0's head is data, not a ping, so the yield rule does not apply.
    let candidates = [ready(0, PACKET_STREAM_DATA), ready(5, PACKET_STREAM_DATA)];
    let sel = select_stream(&candidates, -1);
    assert_eq!(sel.selected, Some(0));
    assert_eq!(sel.new_cursor, 1);
}

#[test]
fn orphan_candidate_is_chosen_when_it_holds_the_only_work() {
    // Orphan last, as the dispatcher orders it; it is served and the cursor
    // follows it to 0 (-1 + 1).
    let candidates = [
        empty(0),
        empty(2),
        ready(ORPHAN_CANDIDATE, PACKET_STREAM_SYN),
    ];
    let sel = select_stream(&candidates, -1);
    assert_eq!(sel.selected, Some(ORPHAN_CANDIDATE));
    assert_eq!(sel.new_cursor, 0);
}

#[test]
fn stream_zero_ping_yields_to_orphan_work() {
    // The "other work" that makes stream 0 yield can be the orphan queue.
    let candidates = [
        ready(0, PACKET_PING),
        ready(ORPHAN_CANDIDATE, PACKET_STREAM_SYN),
    ];
    let sel = select_stream(&candidates, -1);
    assert_eq!(sel.selected, Some(ORPHAN_CANDIDATE));
    assert_eq!(sel.new_cursor, 1);
}
