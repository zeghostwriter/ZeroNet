//! Tests for the sans-IO control reliability plane. Each one drives the state
//! machine with explicit timestamps and checks the packets it wants sent, the
//! acks it matches, and when it gives up — the same way the Go `arq_test.go`
//! cases exercise the control path. Being a child module, these reach into the
//! private buffer and RTO fields directly to assert on exact state.

use super::*;
use zero_protocol::masterdns::enums::{
    PACKET_PRIORITY_CRITICAL, PACKET_STREAM_CLOSE_READ, PACKET_STREAM_CLOSE_READ_ACK,
    PACKET_STREAM_CONNECTED, PACKET_STREAM_CONNECTED_ACK, PACKET_STREAM_DATA,
    PACKET_STREAM_DATA_ACK, PACKET_STREAM_SYN,
};

const SEQ: u16 = 7;
const FRAG: u8 = 0;
const TOTAL: u8 = 1;

fn plane() -> ControlReliability {
    ControlReliability::new(ControlConfig::client_defaults(), true)
}

/// Shorthand for a tracked send of `packet_type` with the stream-wide TTL.
fn send(
    cr: &mut ControlReliability,
    packet_type: u8,
    seq: u16,
    now: Instant,
) -> ControlSendOutcome {
    cr.send_control(
        packet_type,
        seq,
        FRAG,
        TOTAL,
        vec![1, 2, 3],
        PACKET_PRIORITY_CRITICAL,
        true,
        None,
        Duration::ZERO,
        now,
    )
}

#[test]
fn untracked_when_reliability_off() {
    let mut cr = ControlReliability::new(ControlConfig::client_defaults(), false);
    let t0 = Instant::now();
    let out = send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0);
    assert!(out.packet.is_some(), "an untracked send still goes out");
    assert!(!out.tracked, "reliability off means nothing is tracked");
    assert_eq!(cr.pending(), 0);
    // Dispatch notes and polls are inert while disabled.
    cr.on_dispatched(PACKET_STREAM_CONNECTED, SEQ, FRAG, t0);
    assert_eq!(
        cr.poll_retransmits(t0 + Duration::from_secs(10))
            .resends
            .len(),
        0
    );
}

#[test]
fn untracked_when_track_flag_false() {
    let mut cr = plane();
    let t0 = Instant::now();
    let out = cr.send_control(
        PACKET_STREAM_CONNECTED,
        SEQ,
        FRAG,
        TOTAL,
        vec![9],
        PACKET_PRIORITY_CRITICAL,
        false,
        None,
        Duration::ZERO,
        t0,
    );
    assert!(out.packet.is_some());
    assert!(!out.tracked);
    assert_eq!(cr.pending(), 0);
}

#[test]
fn tracked_send_records_item_and_echoes_packet() {
    let mut cr = plane();
    let t0 = Instant::now();
    let out = send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0);
    assert!(out.tracked);
    let packet = out.packet.expect("tracked send still emits the packet");
    assert_eq!(packet.packet_type, PACKET_STREAM_CONNECTED);
    assert_eq!(packet.seq, SEQ);
    assert_eq!(packet.priority, PACKET_PRIORITY_CRITICAL);
    assert_eq!(packet.payload, vec![1, 2, 3]);
    assert_eq!(cr.pending(), 1);
    assert!(cr.contains(PACKET_STREAM_CONNECTED, SEQ, FRAG));
}

#[test]
fn send_without_ack_mapping_is_dropped() {
    // STREAM_DATA has no control-ack mapping: a tracked request for it is
    // silently dropped and reported as success, with nothing enqueued.
    let mut cr = plane();
    let t0 = Instant::now();
    let out = send(&mut cr, PACKET_STREAM_DATA, SEQ, t0);
    assert!(out.packet.is_none());
    assert!(!out.tracked);
    assert_eq!(cr.pending(), 0);
}

#[test]
fn duplicate_send_is_deduplicated() {
    let mut cr = plane();
    let t0 = Instant::now();
    assert!(send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0).tracked);
    let dup = send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0);
    assert!(
        dup.packet.is_none(),
        "a second identical send emits nothing"
    );
    assert!(!dup.tracked);
    assert_eq!(cr.pending(), 1);
}

#[test]
fn matching_ack_releases_the_packet() {
    let mut cr = plane();
    let t0 = Instant::now();
    send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0);
    cr.on_dispatched(PACKET_STREAM_CONNECTED, SEQ, FRAG, t0);
    let m = cr.receive_ack(
        PACKET_STREAM_CONNECTED_ACK,
        SEQ,
        FRAG,
        t0 + Duration::from_millis(80),
    );
    assert_eq!(
        m,
        AckMatch::Recognised {
            origin: PACKET_STREAM_CONNECTED,
            tracked: true
        }
    );
    assert_eq!(cr.pending(), 0);
}

#[test]
fn unrecognised_ack_type() {
    let mut cr = plane();
    let t0 = Instant::now();
    // DATA_ACK is the data path's ack, not a tracked control ack.
    assert_eq!(
        cr.receive_ack(PACKET_STREAM_DATA_ACK, SEQ, FRAG, t0),
        AckMatch::NotControlAck
    );
}

#[test]
fn recognised_but_untracked_ack() {
    let mut cr = plane();
    let t0 = Instant::now();
    let m = cr.receive_ack(PACKET_STREAM_CONNECTED_ACK, SEQ, FRAG, t0);
    assert_eq!(
        m,
        AckMatch::Recognised {
            origin: PACKET_STREAM_CONNECTED,
            tracked: false
        }
    );
}

#[test]
fn close_stream_ack_matches_any_sequence() {
    // A CLOSE_READ tracked at seq 5 is released by a CLOSE_READ_ACK naming a
    // different sequence, because a resend may have changed the echoed seq.
    let mut cr = plane();
    let t0 = Instant::now();
    send(&mut cr, PACKET_STREAM_CLOSE_READ, 5, t0);
    cr.on_dispatched(PACKET_STREAM_CLOSE_READ, 5, FRAG, t0);
    let m = cr.receive_ack(PACKET_STREAM_CLOSE_READ_ACK, 9, FRAG, t0);
    assert_eq!(
        m,
        AckMatch::Recognised {
            origin: PACKET_STREAM_CLOSE_READ,
            tracked: true
        }
    );
    assert_eq!(cr.pending(), 0, "every tracked CLOSE_READ copy is dropped");
}

#[test]
fn close_stream_ack_drops_all_copies() {
    let mut cr = plane();
    let t0 = Instant::now();
    send(&mut cr, PACKET_STREAM_CLOSE_READ, 5, t0);
    send(&mut cr, PACKET_STREAM_CLOSE_READ, 6, t0);
    assert_eq!(cr.pending(), 2);
    cr.receive_ack(PACKET_STREAM_CLOSE_READ_ACK, 5, FRAG, t0);
    assert_eq!(cr.pending(), 0);
}

#[test]
fn ordinary_ack_matches_only_exact_key() {
    // CONNECTED is not a close-stream type, so an ack for a different seq does
    // not release the one tracked.
    let mut cr = plane();
    let t0 = Instant::now();
    send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0);
    let m = cr.receive_ack(PACKET_STREAM_CONNECTED_ACK, SEQ + 1, FRAG, t0);
    assert_eq!(
        m,
        AckMatch::Recognised {
            origin: PACKET_STREAM_CONNECTED,
            tracked: false
        }
    );
    assert_eq!(cr.pending(), 1);
}

#[test]
fn undispatched_item_is_not_resent() {
    let mut cr = plane();
    let t0 = Instant::now();
    send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0);
    // Never dispatched: even far in the future it is not a retransmit candidate.
    let out = cr.poll_retransmits(t0 + Duration::from_secs(30));
    assert!(out.resends.is_empty());
    assert!(out.expired.is_none());
}

#[test]
fn dispatched_item_resends_after_rto() {
    let mut cr = plane();
    let t0 = Instant::now();
    send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0);
    cr.on_dispatched(PACKET_STREAM_CONNECTED, SEQ, FRAG, t0);

    // Default control RTO is 500ms: not due at 400ms, due at 500ms.
    assert!(cr
        .poll_retransmits(t0 + Duration::from_millis(400))
        .resends
        .is_empty());
    let out = cr.poll_retransmits(t0 + Duration::from_millis(500));
    assert_eq!(out.resends.len(), 1);
    assert_eq!(out.resends[0].packet_type, PACKET_STREAM_CONNECTED);

    // After a resend the item is undispatched again and the RTO has grown by
    // the ordinary 1.25 factor (500ms -> 625ms).
    let item = &cr.snd_buf[&control_key(PACKET_STREAM_CONNECTED, SEQ, FRAG)];
    assert!(!item.dispatched);
    assert_eq!(item.retries, 1);
    assert_eq!(item.current_rto_ns, 625_000_000);
}

#[test]
fn setup_packet_uses_tight_initial_rto() {
    // STREAM_SYN is a setup packet: its initial RTO is capped at 350ms even
    // though the configured control RTO is 500ms.
    let mut cr = plane();
    let t0 = Instant::now();
    send(&mut cr, PACKET_STREAM_SYN, SEQ, t0);
    let item = &cr.snd_buf[&control_key(PACKET_STREAM_SYN, SEQ, FRAG)];
    assert_eq!(item.current_rto_ns, 350_000_000);

    cr.on_dispatched(PACKET_STREAM_SYN, SEQ, FRAG, t0);
    assert!(cr
        .poll_retransmits(t0 + Duration::from_millis(300))
        .resends
        .is_empty());
    assert_eq!(
        cr.poll_retransmits(t0 + Duration::from_millis(360))
            .resends
            .len(),
        1
    );
    // Setup growth is the gentler 1.15 factor. The multiply is done in f64 and
    // truncated toward zero exactly as Go's `time.Duration(float64 * factor)`:
    // 350ms * 1.15 lands a nanosecond short of 402.5ms, and that off-by-one is
    // the whole point — it has to match the server's rounding.
    let item = &cr.snd_buf[&control_key(PACKET_STREAM_SYN, SEQ, FRAG)];
    assert_eq!(item.current_rto_ns, 402_499_999);
}

#[test]
fn dispatch_failure_makes_it_immediately_due() {
    let mut cr = plane();
    let t0 = Instant::now() + Duration::from_secs(10);
    send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0);
    // The queue rejected it: it is backdated by one RTO, so it is due now.
    cr.on_dispatch_failed(PACKET_STREAM_CONNECTED, SEQ, FRAG, t0);
    let out = cr.poll_retransmits(t0);
    assert_eq!(out.resends.len(), 1);
}

#[test]
fn explicit_ttl_expiry() {
    let mut cr = plane();
    let t0 = Instant::now();
    cr.send_control(
        PACKET_STREAM_CONNECTED,
        SEQ,
        FRAG,
        TOTAL,
        vec![1],
        PACKET_PRIORITY_CRITICAL,
        true,
        None,
        Duration::from_secs(1),
        t0,
    );
    cr.on_dispatched(PACKET_STREAM_CONNECTED, SEQ, FRAG, t0);
    let out = cr.poll_retransmits(t0 + Duration::from_secs(1));
    assert_eq!(
        out.expired,
        Some(ControlExpiry {
            packet_type: PACKET_STREAM_CONNECTED,
            reason: "Packet TTL expired"
        })
    );
    assert_eq!(cr.pending(), 0);
}

#[test]
fn retry_exhaustion_expiry() {
    // Floor is 5 retries. Advancing by the max RTO each cycle guarantees the
    // item is due, so it is resent five times and expired on the sixth poll.
    let cfg = ControlConfig {
        control_max_retries: 5,
        control_packet_ttl: Duration::from_secs(600),
        ..ControlConfig::client_defaults()
    };
    let mut cr = ControlReliability::new(cfg, true);
    let t0 = Instant::now();
    send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0);
    cr.on_dispatched(PACKET_STREAM_CONNECTED, SEQ, FRAG, t0);

    let mut now = t0;
    let mut resends = 0;
    let mut expiry = None;
    for _ in 0..10 {
        now += Duration::from_secs(3);
        let out = cr.poll_retransmits(now);
        if let Some(e) = out.expired {
            expiry = Some(e);
            break;
        }
        resends += out.resends.len();
        cr.on_dispatched(PACKET_STREAM_CONNECTED, SEQ, FRAG, now);
    }
    assert_eq!(resends, 5, "resent until retries hit the floor of 5");
    assert_eq!(
        expiry,
        Some(ControlExpiry {
            packet_type: PACKET_STREAM_CONNECTED,
            reason: "Control packet max retransmissions exceeded"
        })
    );
}

#[test]
fn clean_round_trip_feeds_the_rto_estimate() {
    let mut cr = plane();
    let t0 = Instant::now();
    send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0);
    cr.on_dispatched(PACKET_STREAM_CONNECTED, SEQ, FRAG, t0);
    // The sample (80ms) is clamped up to the 500ms floor before it seeds the
    // estimate: srtt=500ms, rttvar=250ms, base=clamp(1500ms)=1500ms.
    cr.receive_ack(
        PACKET_STREAM_CONNECTED_ACK,
        SEQ,
        FRAG,
        t0 + Duration::from_millis(80),
    );
    assert!(cr.adaptive_rto.initialized);
    assert_eq!(cr.adaptive_rto.current_base, 1_500_000_000);

    // A fresh non-setup packet now starts at the raised base RTO.
    send(&mut cr, PACKET_STREAM_CONNECTED, SEQ + 1, t0);
    let item = &cr.snd_buf[&control_key(PACKET_STREAM_CONNECTED, SEQ + 1, FRAG)];
    assert_eq!(item.current_rto_ns, 1_500_000_000);
}

#[test]
fn resent_packet_is_not_sample_eligible() {
    let mut cr = plane();
    let t0 = Instant::now();
    send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0);
    cr.on_dispatched(PACKET_STREAM_CONNECTED, SEQ, FRAG, t0);
    cr.poll_retransmits(t0 + Duration::from_millis(500));
    cr.on_dispatched(
        PACKET_STREAM_CONNECTED,
        SEQ,
        FRAG,
        t0 + Duration::from_millis(500),
    );
    // The ack of a resent packet must not pollute the RTO estimate.
    cr.receive_ack(
        PACKET_STREAM_CONNECTED_ACK,
        SEQ,
        FRAG,
        t0 + Duration::from_millis(600),
    );
    assert!(!cr.adaptive_rto.initialized);
}

#[test]
fn clear_wipes_the_buffer() {
    let mut cr = plane();
    let t0 = Instant::now();
    send(&mut cr, PACKET_STREAM_CONNECTED, SEQ, t0);
    send(&mut cr, PACKET_STREAM_SYN, SEQ, t0);
    assert_eq!(cr.pending(), 2);
    cr.clear();
    assert!(cr.is_empty());
}
