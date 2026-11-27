//! Tests for the sans-IO ping scheduler. Time is explicit: each case starts a
//! scheduler at a base instant and advances by fixed offsets, checking the
//! interval tier, the ping-due timing, the wake throttle and the sequence
//! numbering against the Go `ping_manager.go` constants.

use super::*;

fn base() -> Instant {
    Instant::now()
}

/// Shorthand for `base + n` seconds / millis.
fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}
fn millis(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[test]
fn fresh_scheduler_starts_aggressive_not_due() {
    let t = base();
    let s = PingScheduler::new(PingConfig::default(), t);
    // Just connected: aggressive tier, but a ping is not due yet (the clock has
    // not advanced a full interval past the start).
    assert_eq!(s.next_interval(t), millis(100));
    let p = s.poll(t);
    assert!(!p.ping_due);
    assert_eq!(p.next_check, millis(100));
}

#[test]
fn interval_tiers_by_idle() {
    let t = base();
    let s = PingScheduler::new(PingConfig::default(), t);
    // With both activity clocks at the start, idle == elapsed, so the tier
    // follows the thresholds: warm < 8s, cool < 20s, cold < 30s.
    assert_eq!(s.next_interval(t + secs(7)), millis(100)); // aggressive
    assert_eq!(s.next_interval(t + secs(8)), millis(750)); // lazy
    assert_eq!(s.next_interval(t + secs(19)), millis(750)); // lazy
    assert_eq!(s.next_interval(t + secs(20)), secs(2)); // cooldown
    assert_eq!(s.next_interval(t + secs(29)), secs(2)); // cooldown
    assert_eq!(s.next_interval(t + secs(30)), secs(15)); // cold
    assert_eq!(s.next_interval(t + secs(120)), secs(15)); // cold
}

#[test]
fn recent_send_keeps_it_warm() {
    let t = base();
    let mut s = PingScheduler::new(PingConfig::default(), t);
    // Long idle would be cold, but a non-ping packet sent recently (either
    // direction) pulls it back to aggressive because the warm test is an OR.
    assert_eq!(s.next_interval(t + secs(60)), secs(15));
    s.note_packet(data_type(), false, t + secs(60));
    assert_eq!(s.next_interval(t + secs(61)), millis(100));
}

#[test]
fn recent_receive_keeps_it_warm() {
    let t = base();
    let mut s = PingScheduler::new(PingConfig::default(), t);
    s.note_packet(data_type(), true, t + secs(60));
    assert_eq!(s.next_interval(t + secs(61)), millis(100));
}

#[test]
fn note_packet_updates_the_right_clock() {
    let t = base();
    let mut s = PingScheduler::new(PingConfig::default(), t);
    // Inbound pong: records pong time, no wake.
    assert!(!s.note_packet(PACKET_PONG, true, t + millis(10)));
    assert_eq!(s.last_pong_received(), t + millis(10));
    // Outbound ping: records ping-sent time, no wake, and clears a due ping.
    assert!(!s.note_packet(PACKET_PING, false, t + millis(20)));
    assert!(!s.poll(t + millis(20)).ping_due);
}

#[test]
fn wake_throttle_collapses_bursts() {
    let t = base();
    let mut s = PingScheduler::new(PingConfig::default(), t);
    // last_woke starts at t, so anything inside the first 100ms is throttled.
    assert!(!s.note_packet(data_type(), false, t + millis(50)));
    // At exactly 100ms the throttle opens.
    assert!(s.note_packet(data_type(), false, t + millis(100)));
    // Another within 100ms of that is collapsed.
    assert!(!s.note_packet(data_type(), false, t + millis(150)));
    // And opens again a full throttle later.
    assert!(s.note_packet(data_type(), false, t + millis(200)));
}

#[test]
fn pong_and_ping_never_wake() {
    let t = base();
    let mut s = PingScheduler::new(PingConfig::default(), t);
    // Even well past the throttle, keepalives themselves never request a wake.
    assert!(!s.note_packet(PACKET_PONG, true, t + secs(5)));
    assert!(!s.note_packet(PACKET_PING, false, t + secs(10)));
}

#[test]
fn ping_due_then_sent_then_not_due() {
    let t = base();
    let mut s = PingScheduler::new(PingConfig::default(), t);
    // Not due a hair before one interval, due at exactly one interval.
    assert!(!s.poll(t + millis(99)).ping_due);
    assert!(s.poll(t + millis(100)).ping_due);
    // The caller "sends" it: feed the ping back so last_ping_sent advances.
    let seq = s.next_ping_sequence();
    assert_eq!(seq, 1);
    s.note_packet(PACKET_PING, false, t + millis(100));
    // No longer due right after; due again a full interval later.
    assert!(!s.poll(t + millis(100)).ping_due);
    assert!(!s.poll(t + millis(150)).ping_due);
    assert!(s.poll(t + millis(200)).ping_due);
}

#[test]
fn next_check_is_half_interval_clamped() {
    let t = base();
    let s = PingScheduler::new(PingConfig::default(), t);
    // aggressive 100ms -> 50ms, floored to 100ms.
    assert_eq!(s.poll(t).next_check, millis(100));
    // lazy 750ms -> 375ms (within range).
    assert_eq!(s.poll(t + secs(8)).next_check, millis(375));
    // cooldown 2s -> 1s, capped at 1s.
    assert_eq!(s.poll(t + secs(20)).next_check, secs(1));
    // cold 15s -> 7.5s, capped at 1s.
    assert_eq!(s.poll(t + secs(30)).next_check, secs(1));
}

#[test]
fn ping_sequence_counts_and_wraps() {
    let t = base();
    let mut s = PingScheduler::new(PingConfig::default(), t);
    assert_eq!(s.next_ping_sequence(), 1);
    assert_eq!(s.next_ping_sequence(), 2);
    assert_eq!(s.next_ping_sequence(), 3);
    // Jump to the u16 edge and confirm it wraps 0xFFFF -> 0.
    s.next_ping_seq = 0xFFFF;
    assert_eq!(s.next_ping_sequence(), 0);
    assert_eq!(s.next_ping_sequence(), 1);
}

#[test]
fn ping_payload_is_tagged_nonce() {
    assert_eq!(ping_payload([1, 2, 3, 4]), [b'P', b'O', b':', 1, 2, 3, 4]);
}

/// A stand-in ordinary data packet type for the activity-clock tests: any type
/// that is neither PING nor PONG behaves identically here.
pub(super) fn data_type() -> u8 {
    zero_protocol::masterdns::enums::PACKET_STREAM_DATA
}
