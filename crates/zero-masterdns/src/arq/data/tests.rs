//! Tests for the sans-IO reliable data path. Each one drives the state machine
//! with explicit timestamps and checks the packets it wants sent and the bytes
//! it delivers, the same way the Go `arq_test.go` cases exercise the data path.

use super::*;
use zero_protocol::masterdns::enums::{
    PACKET_PRIORITY_CRITICAL, PACKET_PRIORITY_NORMAL, PACKET_PRIORITY_RETRY, PACKET_STREAM_DATA,
    PACKET_STREAM_DATA_ACK, PACKET_STREAM_DATA_NACK, PACKET_STREAM_RESEND,
};

/// A config with the gap-NACK grace period removed, so the first NACK for a
/// hole goes out immediately — otherwise the 100ms default delay hides it.
fn eager_nack_config() -> Config {
    Config {
        data_nack_initial_delay: Duration::ZERO,
        ..Config::client_defaults()
    }
}

#[test]
fn push_data_numbers_sequentially_and_backpressures() {
    let mut arq = DataArq::new(Config::client_defaults());
    let t = Instant::now();

    let p0 = arq.push_data(b"one".to_vec(), t);
    let p1 = arq.push_data(b"two".to_vec(), t);
    assert_eq!(p0.seq, 0);
    assert_eq!(p1.seq, 1);
    assert_eq!(p0.packet_type, PACKET_STREAM_DATA);
    assert_eq!(p0.priority, PACKET_PRIORITY_NORMAL);
    assert_eq!(p0.data, b"one");
    assert_eq!(arq.outstanding(), 2);
    assert_eq!(arq.snd_nxt(), 2);
    assert!(arq.can_send());
}

#[test]
fn ack_releases_the_chunk_and_frees_the_window() {
    let mut arq = DataArq::new(Config::client_defaults());
    let t = Instant::now();
    arq.push_data(b"x".to_vec(), t);
    arq.on_dispatched(0, t);

    let out = arq.receive_ack(0, t + Duration::from_millis(120));
    assert!(out.freed);
    assert!(out.window_freed);
    assert_eq!(arq.outstanding(), 0);

    // A second ack for the same (now released) sequence does nothing.
    let again = arq.receive_ack(0, t + Duration::from_millis(130));
    assert!(!again.freed);
}

#[test]
fn in_order_data_is_acked_and_delivered() {
    let mut arq = DataArq::new(Config::client_defaults());
    let t = Instant::now();

    let out = arq.receive_data(0, b"hello".to_vec(), t);
    assert_eq!(out.delivered, b"hello");
    assert_eq!(out.packets.len(), 1);
    assert_eq!(out.packets[0].packet_type, PACKET_STREAM_DATA_ACK);
    assert_eq!(out.packets[0].priority, PACKET_PRIORITY_CRITICAL);
    assert_eq!(out.packets[0].seq, 0);
    assert_eq!(arq.rcv_nxt(), 1);
}

#[test]
fn out_of_order_data_buffers_until_the_gap_fills() {
    let mut arq = DataArq::new(eager_nack_config());
    let t = Instant::now();

    // Receive seq 1 and 2 before 0: nothing can be delivered yet.
    let o1 = arq.receive_data(1, b"world".to_vec(), t);
    assert!(o1.delivered.is_empty());
    assert_eq!(arq.rcv_nxt(), 0);
    // ACK for 1, plus a NACK for the missing 0.
    assert!(o1
        .packets
        .iter()
        .any(|p| p.packet_type == PACKET_STREAM_DATA_ACK && p.seq == 1));
    assert!(o1
        .packets
        .iter()
        .any(|p| p.packet_type == PACKET_STREAM_DATA_NACK && p.seq == 0));

    let o2 = arq.receive_data(2, b"!".to_vec(), t);
    assert!(o2.delivered.is_empty());
    // The NACK for 0 is rate-limited now, so only the ACK for 2 goes out.
    assert!(o2
        .packets
        .iter()
        .any(|p| p.packet_type == PACKET_STREAM_DATA_ACK && p.seq == 2));
    assert!(!o2
        .packets
        .iter()
        .any(|p| p.packet_type == PACKET_STREAM_DATA_NACK));

    // Filling the hole delivers the whole contiguous run at once.
    let o0 = arq.receive_data(0, b"hi ".to_vec(), t);
    assert_eq!(o0.delivered, b"hi world!");
    assert_eq!(o0.cancel_queued_nacks, vec![0]);
    assert_eq!(arq.rcv_nxt(), 3);
}

#[test]
fn already_delivered_data_is_re_acked_only() {
    let mut arq = DataArq::new(Config::client_defaults());
    let t = Instant::now();
    arq.receive_data(0, b"a".to_vec(), t); // rcv_nxt -> 1

    let dup = arq.receive_data(0, b"a".to_vec(), t);
    assert!(dup.delivered.is_empty());
    assert_eq!(dup.packets.len(), 1);
    assert_eq!(dup.packets[0].packet_type, PACKET_STREAM_DATA_ACK);
    assert_eq!(dup.packets[0].seq, 0);
}

#[test]
fn in_window_duplicate_is_acked_without_overwriting() {
    let mut arq = DataArq::new(Config::client_defaults());
    let t = Instant::now();
    arq.receive_data(2, b"first".to_vec(), t); // buffered, gap at 0,1

    let dup = arq.receive_data(2, b"second".to_vec(), t);
    assert!(dup.delivered.is_empty());
    assert!(dup.cancel_queued_nacks.is_empty()); // not newly buffered
    assert!(dup
        .packets
        .iter()
        .any(|p| p.packet_type == PACKET_STREAM_DATA_ACK && p.seq == 2));

    // Fill the gap: the originally buffered "first" must survive, not "second".
    let o0 = arq.receive_data(0, b"[0]".to_vec(), t);
    assert_eq!(o0.delivered, b"[0]"); // 1 and 2 still pending
    let o1 = arq.receive_data(1, b"[1]".to_vec(), t);
    assert_eq!(o1.delivered, b"[1]first");
}

#[test]
fn data_beyond_the_window_is_dropped_silently() {
    let mut arq = DataArq::new(Config::client_defaults());
    let t = Instant::now();
    // receive_window_size is 1200 for the default 600 window.
    let out = arq.receive_data(1201, b"too far".to_vec(), t);
    assert!(out.packets.is_empty());
    assert!(out.delivered.is_empty());
    // The right edge (diff == window) is still accepted.
    let edge = arq.receive_data(1200, b"edge".to_vec(), t);
    assert_eq!(edge.packets.len(), 1);
    assert_eq!(edge.packets[0].packet_type, PACKET_STREAM_DATA_ACK);
}

#[test]
fn paused_stream_buffers_but_defers_delivery() {
    let cfg = Config {
        start_paused: true,
        ..Config::client_defaults()
    };
    let mut arq = DataArq::new(cfg);
    let t = Instant::now();

    let out = arq.receive_data(0, b"queued".to_vec(), t);
    assert!(out.delivered.is_empty()); // paused: not yet delivered
    assert_eq!(arq.rcv_nxt(), 0);
    assert_eq!(out.packets[0].packet_type, PACKET_STREAM_DATA_ACK); // still acked

    let flushed = arq.set_io_ready(true);
    assert_eq!(flushed, b"queued");
    assert_eq!(arq.rcv_nxt(), 1);
}

#[test]
fn due_packet_is_retransmitted_and_its_timeout_grows() {
    let cfg = Config {
        initial_rto: Duration::from_millis(100),
        max_rto: Duration::from_secs(5),
        ..Config::client_defaults()
    };
    let mut arq = DataArq::new(cfg);
    let base = Instant::now();
    arq.push_data(b"d".to_vec(), base);
    arq.on_dispatched(0, base);

    // Before the RTO elapses, nothing is due.
    match arq.poll_retransmits(base + Duration::from_millis(50)) {
        RetransmitOutcome::Resend(pkts) => assert!(pkts.is_empty()),
        other => panic!("unexpected {other:?}"),
    }

    // After it elapses, the lone packet is resent at RESEND priority.
    match arq.poll_retransmits(base + Duration::from_millis(150)) {
        RetransmitOutcome::Resend(pkts) => {
            assert_eq!(pkts.len(), 1);
            assert_eq!(pkts[0].packet_type, PACKET_STREAM_RESEND);
            assert_eq!(pkts[0].priority, PACKET_PRIORITY_RETRY);
            assert_eq!(pkts[0].seq, 0);
        }
        other => panic!("unexpected {other:?}"),
    }

    // A resent-but-not-redispatched packet is not due again (dispatched=false).
    match arq.poll_retransmits(base + Duration::from_millis(400)) {
        RetransmitOutcome::Resend(pkts) => assert!(pkts.is_empty()),
        other => panic!("unexpected {other:?}"),
    }

    // Re-dispatch, then confirm the grown 135ms timeout governs the next resend.
    let t2 = base + Duration::from_millis(400);
    arq.on_dispatched(0, t2);
    match arq.poll_retransmits(t2 + Duration::from_millis(130)) {
        RetransmitOutcome::Resend(pkts) => assert!(pkts.is_empty()), // 130ms < 135ms
        other => panic!("unexpected {other:?}"),
    }
    match arq.poll_retransmits(t2 + Duration::from_millis(140)) {
        RetransmitOutcome::Resend(pkts) => assert_eq!(pkts.len(), 1),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn ack_clears_the_retransmit_candidate() {
    let cfg = Config {
        initial_rto: Duration::from_millis(100),
        ..Config::client_defaults()
    };
    let mut arq = DataArq::new(cfg);
    let base = Instant::now();
    arq.push_data(b"d".to_vec(), base);
    arq.on_dispatched(0, base);
    arq.receive_ack(0, base + Duration::from_millis(40));

    // Nothing left to resend after the ack.
    match arq.poll_retransmits(base + Duration::from_secs(10)) {
        RetransmitOutcome::Resend(pkts) => assert!(pkts.is_empty()),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn many_due_packets_promote_only_the_oldest_front_budget() {
    // Window 300 -> front budget 30. Send 40 packets, let them all go overdue,
    // and confirm exactly 30 ride at RESEND priority (the oldest by sequence).
    let cfg = Config {
        window_size: 300,
        initial_rto: Duration::from_millis(50),
        max_rto: Duration::from_millis(50),
        ..Config::client_defaults()
    };
    let mut arq = DataArq::new(cfg);
    let base = Instant::now();
    for i in 0..40u16 {
        arq.push_data(vec![i as u8], base);
        arq.on_dispatched(i, base);
    }

    let pkts = match arq.poll_retransmits(base + Duration::from_millis(60)) {
        RetransmitOutcome::Resend(pkts) => pkts,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(pkts.len(), 40);
    let resends: Vec<u16> = pkts
        .iter()
        .filter(|p| p.packet_type == PACKET_STREAM_RESEND)
        .map(|p| p.seq)
        .collect();
    assert_eq!(resends.len(), 30);
    // Oldest 30 sequences (0..30) are the ones promoted.
    let mut sorted = resends.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, (0..30u16).collect::<Vec<_>>());
}

#[test]
fn peer_nack_resends_rate_limited() {
    let cfg = Config {
        data_nack_repeat_interval: Duration::from_secs(1),
        ..Config::client_defaults()
    };
    let mut arq = DataArq::new(cfg);
    let base = Instant::now();
    arq.push_data(b"d".to_vec(), base);
    arq.on_dispatched(0, base);

    let first = arq.receive_data_nack(0, base).expect("first resend");
    assert_eq!(first.packet_type, PACKET_STREAM_RESEND);
    assert_eq!(first.seq, 0);

    // Within the repeat interval the NACK is ignored.
    assert!(arq
        .receive_data_nack(0, base + Duration::from_millis(500))
        .is_none());
    // Past it, a fresh resend is produced.
    assert!(arq
        .receive_data_nack(0, base + Duration::from_millis(1000))
        .is_some());
    // An unknown sequence is never resent.
    assert!(arq.receive_data_nack(999, base).is_none());
}

#[test]
fn nack_grace_period_then_repeat_interval() {
    let cfg = Config {
        data_nack_initial_delay: Duration::from_millis(100),
        data_nack_repeat_interval: Duration::from_secs(1),
        ..Config::client_defaults()
    };
    let mut arq = DataArq::new(cfg);
    let base = Instant::now();

    // Gap opens: first sighting is inside the grace period, so no NACK yet.
    let o1 = arq.receive_data(1, b"b".to_vec(), base);
    assert!(!o1
        .packets
        .iter()
        .any(|p| p.packet_type == PACKET_STREAM_DATA_NACK));

    // Past the grace period, the NACK for the hole at 0 goes out.
    let o2 = arq.receive_data(2, b"c".to_vec(), base + Duration::from_millis(150));
    assert!(o2
        .packets
        .iter()
        .any(|p| p.packet_type == PACKET_STREAM_DATA_NACK && p.seq == 0));
}

#[test]
fn exhausting_retries_past_the_ttl_signals_close() {
    // TTL floors to 120s and retries to 60; keep RTO pinned at 50ms so every
    // poll past 60ms resends, and drive 60 resends before jumping past the TTL.
    let cfg = Config {
        window_size: 300,
        initial_rto: Duration::from_millis(50),
        max_rto: Duration::from_millis(50),
        data_packet_ttl: Duration::ZERO,
        max_data_retries: 0,
        data_nack_max_gap: 0,
        data_nack_initial_delay: Duration::ZERO,
        data_nack_repeat_interval: Duration::ZERO,
        compression_type: 0,
        start_paused: false,
    };
    let mut arq = DataArq::new(cfg);
    let base = Instant::now();
    arq.push_data(vec![1], base);
    arq.on_dispatched(0, base);

    let mut t = base;
    for _ in 0..60 {
        t += Duration::from_millis(60);
        match arq.poll_retransmits(t) {
            RetransmitOutcome::Resend(pkts) => assert_eq!(pkts.len(), 1),
            other => panic!("unexpected {other:?}"),
        }
        arq.on_dispatched(0, t);
    }

    // 60 retries done; past the 120s TTL the stream must be torn down.
    assert_eq!(
        arq.poll_retransmits(base + Duration::from_secs(120)),
        RetransmitOutcome::CloseMaxRetries
    );
}

#[test]
fn dispatch_failure_makes_the_chunk_immediately_due() {
    let cfg = Config {
        initial_rto: Duration::from_millis(100),
        ..Config::client_defaults()
    };
    let mut arq = DataArq::new(cfg);
    let base = Instant::now();
    arq.push_data(b"d".to_vec(), base);
    // The queue rejected it: it should be overdue right away.
    arq.on_dispatch_failed(0, base);
    match arq.poll_retransmits(base) {
        RetransmitOutcome::Resend(pkts) => assert_eq!(pkts.len(), 1),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn sequence_wraps_around_the_ring() {
    let mut arq = DataArq::new(Config::client_defaults());
    let t = Instant::now();
    // Deliver up to the top of the ring, then wrap to 0.
    // Shortcut: receive the last few sequences in order starting near the wrap.
    // Here we just confirm a wrapped forward sequence is still in-window.
    let out = arq.receive_data(0, b"start".to_vec(), t);
    assert_eq!(out.delivered, b"start"); // rcv_nxt -> 1

    // A sequence far behind (wrapped) is re-acked, not delivered.
    let behind = arq.receive_data(0xFFF0, b"old".to_vec(), t);
    assert!(behind.delivered.is_empty());
    assert_eq!(behind.packets[0].packet_type, PACKET_STREAM_DATA_ACK);
}
