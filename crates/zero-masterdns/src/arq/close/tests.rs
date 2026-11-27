//! Tests for the sans-IO close/teardown state machine. Each one drives the
//! machine with explicit timestamps and a [`StreamView`] snapshot, then checks
//! the [`CloseAction`]s it emits and the state it lands in — the same way the Go
//! `arq_test.go` cases exercise the close path, but against hand-computed
//! expectations since the Go harness ships no close vectors. Being a child
//! module, these reach into the private flag and timing fields directly to
//! assert on exact state.

use super::*;
use zero_protocol::masterdns::enums::{PACKET_PRIORITY_CRITICAL, PACKET_PRIORITY_LOW};

/// A client-side close machine with reliability on, all defaults, started at
/// `now`.
fn client(now: Instant) -> StreamLifecycle {
    StreamLifecycle::new(
        CloseConfig::client_defaults(),
        ControlConfig::client_defaults(),
        true,
        true,
        now,
    )
}

/// An empty data-path snapshot: nothing in flight, nothing buffered.
fn empty_view() -> StreamView {
    StreamView::default()
}

/// Shorthand for the terminal `ControlSend` the close machine emits: no payload,
/// no fragments, no explicit TTL.
fn terminal_send(priority: usize, packet_type: u8) -> ControlSend {
    ControlSend {
        priority,
        packet_type,
        seq: 0,
        fragment_id: 0,
        total_fragments: 0,
        ttl: Duration::ZERO,
        payload: Vec::new(),
    }
}

#[test]
fn fresh_stream_is_open_and_quiet() {
    let now = Instant::now();
    let s = client(now);
    assert_eq!(s.state(), StreamState::Open);
    assert!(!s.is_closed());
    assert_eq!(s.control_pending(), 0);
    assert_eq!(s.waiting_ack_for(), None);
    assert!(!s.should_stop_local_read());
}

#[test]
fn force_close_finalizes_immediately() {
    let now = Instant::now();
    let mut s = client(now);
    let opts = CloseOptions {
        force: true,
        ..CloseOptions::default()
    };
    let actions = s.close("forced", opts, &empty_view(), now);
    assert_eq!(
        actions,
        vec![
            CloseAction::CloseLocalConn,
            CloseAction::ClearAllData,
            CloseAction::SignalWindowNotFull,
            CloseAction::Finalized {
                reason: "forced".to_string()
            },
        ]
    );
    assert!(s.is_closed());
    // No close/reset flags were set, so finalize lands on the plain Closing
    // terminal state.
    assert_eq!(s.state(), StreamState::Closing);
}

#[test]
fn empty_options_finalize_like_force() {
    let now = Instant::now();
    let mut s = client(now);
    let actions = s.close("done", CloseOptions::default(), &empty_view(), now);
    assert_eq!(
        actions,
        vec![
            CloseAction::CloseLocalConn,
            CloseAction::ClearAllData,
            CloseAction::SignalWindowNotFull,
            CloseAction::Finalized {
                reason: "done".to_string()
            },
        ]
    );
    assert!(s.is_closed());
}

#[test]
fn close_read_emits_and_waits() {
    let now = Instant::now();
    let mut s = client(now);
    let opts = CloseOptions {
        send_close_read: true,
        ..CloseOptions::default()
    };
    let actions = s.close("local read eof", opts, &empty_view(), now);
    assert_eq!(
        actions,
        vec![CloseAction::Send(terminal_send(
            PACKET_PRIORITY_CRITICAL,
            PACKET_STREAM_CLOSE_READ
        ))]
    );
    assert_eq!(s.state(), StreamState::HalfClosedLocal);
    assert_eq!(s.waiting_ack_for(), Some(PACKET_STREAM_CLOSE_READ));
    assert_eq!(s.control_pending(), 1);
    assert!(s.should_stop_local_read());
    assert!(!s.is_closed());
}

#[test]
fn close_read_ack_without_remote_eof_clears_wait_only() {
    let now = Instant::now();
    let mut s = client(now);
    s.close(
        "local read eof",
        CloseOptions {
            send_close_read: true,
            ..CloseOptions::default()
        },
        &empty_view(),
        now,
    );
    s.note_control_dispatched(PACKET_STREAM_CLOSE_READ, 0, 0, now);
    let (handled, actions) =
        s.receive_control_ack(PACKET_STREAM_CLOSE_READ_ACK, 0, 0, &empty_view(), now);
    assert!(handled);
    assert!(actions.is_empty());
    assert_eq!(s.waiting_ack_for(), None);
    assert_eq!(s.control_pending(), 0);
    assert!(!s.is_closed());
    // The peer has not sent its own close-read yet, so the handshake stays open.
    assert_eq!(s.state(), StreamState::HalfClosedLocal);
}

#[test]
fn full_close_handshake_finalizes() {
    let now = Instant::now();
    let mut s = client(now);
    s.close(
        "local read eof",
        CloseOptions {
            send_close_read: true,
            ..CloseOptions::default()
        },
        &empty_view(),
        now,
    );
    s.note_control_dispatched(PACKET_STREAM_CLOSE_READ, 0, 0, now);

    // Peer closes its read side too: we flush but cannot finalize while still
    // waiting for our own close-read ack.
    let a_recv = s.mark_close_read_received(&empty_view());
    assert_eq!(a_recv, vec![CloseAction::SignalFlushReady]);
    assert!(!s.is_closed());
    assert_eq!(s.state(), StreamState::Closing);

    // Our close-read is acked: both halves settled, finalize.
    let (handled, a_ack) =
        s.receive_control_ack(PACKET_STREAM_CLOSE_READ_ACK, 0, 0, &empty_view(), now);
    assert!(handled);
    assert_eq!(
        a_ack,
        vec![
            CloseAction::CloseLocalConn,
            CloseAction::ClearAllData,
            CloseAction::SignalWindowNotFull,
            CloseAction::Finalized {
                reason: "close handshake completed".to_string()
            },
        ]
    );
    assert!(s.is_closed());
    assert_eq!(s.state(), StreamState::TimeWait);
}

#[test]
fn rst_emit_clears_and_waits() {
    let now = Instant::now();
    let mut s = client(now);
    let view = StreamView {
        snd_buf_len: 5,
        ..StreamView::default()
    };
    let actions = s.close(
        "boom",
        CloseOptions {
            send_rst: true,
            ..CloseOptions::default()
        },
        &view,
        now,
    );
    assert_eq!(
        actions,
        vec![
            CloseAction::ClearAllData,
            CloseAction::SignalWindowNotFull,
            CloseAction::Send(terminal_send(PACKET_PRIORITY_CRITICAL, PACKET_STREAM_RST)),
        ]
    );
    assert_eq!(s.state(), StreamState::Reset);
    assert_eq!(s.waiting_ack_for(), Some(PACKET_STREAM_RST));
    assert_eq!(s.control_pending(), 1);
    assert!(!s.is_closed());
}

#[test]
fn rst_ack_finalizes() {
    let now = Instant::now();
    let mut s = client(now);
    s.close(
        "boom",
        CloseOptions {
            send_rst: true,
            ..CloseOptions::default()
        },
        &empty_view(),
        now,
    );
    s.note_control_dispatched(PACKET_STREAM_RST, 0, 0, now);
    let (handled, actions) = s.receive_control_ack(PACKET_STREAM_RST_ACK, 0, 0, &empty_view(), now);
    assert!(handled);
    assert_eq!(
        actions,
        vec![
            CloseAction::CloseLocalConn,
            CloseAction::ClearAllData,
            CloseAction::SignalWindowNotFull,
            CloseAction::Finalized {
                reason: "RST acknowledged".to_string()
            },
        ]
    );
    assert!(s.is_closed());
    assert_eq!(s.state(), StreamState::Reset);
}

#[test]
fn peer_rst_clears_outbound_and_flushes() {
    let now = Instant::now();
    let mut s = client(now);
    let actions = s.mark_rst_received();
    assert_eq!(
        actions,
        vec![
            CloseAction::ClearOutboundData,
            CloseAction::SignalFlushReady,
        ]
    );
    assert_eq!(s.state(), StreamState::Reset);
    assert!(s.should_stop_local_read());
    assert!(!s.is_closed());
}

#[test]
fn peer_rst_drain_finalizes_when_empty() {
    let now = Instant::now();
    let mut s = client(now);
    s.mark_rst_received();
    let (actions, closed) = s.handle_terminal_retransmit_state(&empty_view(), now);
    assert!(closed);
    assert_eq!(
        actions,
        vec![
            CloseAction::CloseLocalConn,
            CloseAction::ClearAllData,
            CloseAction::SignalWindowNotFull,
            CloseAction::Finalized {
                reason: "peer reset received".to_string()
            },
        ]
    );
    assert!(s.is_closed());
}

#[test]
fn peer_rst_drain_waits_for_contiguous_data() {
    let now = Instant::now();
    let mut s = client(now);
    s.mark_rst_received();
    let view = StreamView {
        contiguous_ready: 3,
        rcv_buf_len: 3,
        ..StreamView::default()
    };
    let (actions, closed) = s.handle_terminal_retransmit_state(&view, now);
    assert!(!closed);
    assert_eq!(actions, vec![CloseAction::SignalFlushReady]);
    assert!(!s.is_closed());
}

#[test]
fn inactivity_timeout_resets_dead_stream() {
    let now = Instant::now();
    let mut s = client(now);
    // Default inactivity floor is 1800s; one second past it trips the watchdog.
    let later = now + Duration::from_secs(1801);
    let (actions, closed) = s.handle_terminal_retransmit_state(&empty_view(), later);
    // The Go path returns `true` to stop the retransmit pass even though the
    // stream only emitted an RST (not yet finalized).
    assert!(closed);
    assert_eq!(
        actions,
        vec![
            CloseAction::ClearAllData,
            CloseAction::SignalWindowNotFull,
            CloseAction::Send(terminal_send(PACKET_PRIORITY_CRITICAL, PACKET_STREAM_RST)),
        ]
    );
    assert_eq!(s.waiting_ack_for(), Some(PACKET_STREAM_RST));
    assert_eq!(s.state(), StreamState::Reset);
    assert!(!s.is_closed());
}

#[test]
fn inactivity_timeout_with_pending_only_touches_activity() {
    let now = Instant::now();
    let mut s = client(now);
    let view = StreamView {
        snd_buf_len: 2,
        ..StreamView::default()
    };
    let later = now + Duration::from_secs(1801);
    let (actions, closed) = s.handle_terminal_retransmit_state(&view, later);
    assert!(!closed);
    assert!(actions.is_empty());
    assert_eq!(s.state(), StreamState::Open);
    assert!(!s.is_closed());
}

#[test]
fn deferred_close_drains_then_settles() {
    let now = Instant::now();
    let mut s = client(now);
    let view = StreamView {
        snd_buf_len: 3,
        ..StreamView::default()
    };
    let actions = s.close(
        "drain then close read",
        CloseOptions {
            send_close_read: true,
            after_drain: true,
            ..CloseOptions::default()
        },
        &view,
        now,
    );
    // Nothing emitted yet: it is draining the outbound buffer first.
    assert!(actions.is_empty());
    assert_eq!(s.state(), StreamState::Draining);
    assert!(s.should_stop_local_read());
    assert!(!s.is_closed());
    assert_eq!(s.waiting_ack_for(), None);

    // The buffer drains: the deferred CLOSE_READ now goes out.
    let drained = empty_view();
    let (actions2, closed2) =
        s.handle_terminal_retransmit_state(&drained, now + Duration::from_secs(1));
    assert!(!closed2);
    assert_eq!(
        actions2,
        vec![CloseAction::Send(terminal_send(
            PACKET_PRIORITY_CRITICAL,
            PACKET_STREAM_CLOSE_READ
        ))]
    );
    assert_eq!(s.waiting_ack_for(), Some(PACKET_STREAM_CLOSE_READ));
    assert_eq!(s.state(), StreamState::HalfClosedLocal);
}

#[test]
fn deferred_drain_timeout_falls_back_to_rst() {
    let now = Instant::now();
    let mut s = client(now);
    let view = StreamView {
        snd_buf_len: 3,
        ..StreamView::default()
    };
    s.close(
        "close read after drain",
        CloseOptions {
            send_close_read: true,
            after_drain: true,
            ..CloseOptions::default()
        },
        &view,
        now,
    );
    // Drain never completes; advance past the 120s drain floor with data still
    // pending.
    let later = now + Duration::from_secs(121);
    let still_pending = StreamView {
        snd_buf_len: 3,
        ..StreamView::default()
    };
    let (actions, closed) = s.handle_terminal_retransmit_state(&still_pending, later);
    assert!(!closed);
    assert_eq!(
        actions,
        vec![
            CloseAction::ClearAllData,
            CloseAction::SignalWindowNotFull,
            CloseAction::Send(terminal_send(PACKET_PRIORITY_CRITICAL, PACKET_STREAM_RST)),
        ]
    );
    assert_eq!(s.waiting_ack_for(), Some(PACKET_STREAM_RST));
    assert_eq!(s.state(), StreamState::Reset);
}

#[test]
fn close_read_ack_wait_timeout_escalates_then_finalizes() {
    let now = Instant::now();
    let mut s = client(now);
    s.close(
        "local read eof",
        CloseOptions {
            send_close_read: true,
            ..CloseOptions::default()
        },
        &empty_view(),
        now,
    );
    s.note_control_dispatched(PACKET_STREAM_CLOSE_READ, 0, 0, now);

    // Ack never arrives; the 90s ack-wait floor expires -> escalate to RST.
    let later = now + Duration::from_secs(91);
    let (actions, closed) = s.handle_terminal_retransmit_state(&empty_view(), later);
    assert!(!closed);
    assert_eq!(
        actions,
        vec![
            CloseAction::ClearAllData,
            CloseAction::SignalWindowNotFull,
            CloseAction::Send(terminal_send(PACKET_PRIORITY_CRITICAL, PACKET_STREAM_RST)),
        ]
    );
    assert_eq!(s.waiting_ack_for(), Some(PACKET_STREAM_RST));
    assert_eq!(s.state(), StreamState::Reset);
    // The old CLOSE_READ was cleared; only the RST is tracked now.
    assert_eq!(s.control_pending(), 1);

    // The RST ack-wait also expires -> finalize.
    let even_later = later + Duration::from_secs(91);
    let (actions2, closed2) = s.handle_terminal_retransmit_state(&empty_view(), even_later);
    assert!(closed2);
    assert_eq!(
        actions2,
        vec![
            CloseAction::CloseLocalConn,
            CloseAction::ClearAllData,
            CloseAction::SignalWindowNotFull,
            CloseAction::Finalized {
                reason: "Terminal ACK wait timeout".to_string()
            },
        ]
    );
    assert!(s.is_closed());
}

#[test]
fn final_ack_watchdog_dedups() {
    let now = Instant::now();
    let mut s = client(now);
    s.close(
        "local read eof",
        CloseOptions {
            send_close_read: true,
            ..CloseOptions::default()
        },
        &empty_view(),
        now,
    );
    s.note_control_dispatched(PACKET_STREAM_CLOSE_READ, 0, 0, now);
    let (handled, _) =
        s.receive_control_ack(PACKET_STREAM_CLOSE_READ_ACK, 0, 0, &empty_view(), now);
    assert!(handled);

    let view = StreamView {
        rcv_nxt: 5,
        ..StreamView::default()
    };
    let later = now + Duration::from_secs(3);
    let actions = s.run_final_ack_watchdog(&view, later);
    assert_eq!(actions, vec![CloseAction::SendDataAck(4)]);

    // A second call at the same instant is suppressed by the 2s dedup window.
    let actions2 = s.run_final_ack_watchdog(&view, later);
    assert!(actions2.is_empty());
}

#[test]
fn double_close_read_is_idempotent() {
    let now = Instant::now();
    let mut s = client(now);
    let a1 = s.close(
        "eof",
        CloseOptions {
            send_close_read: true,
            ..CloseOptions::default()
        },
        &empty_view(),
        now,
    );
    assert_eq!(a1.len(), 1);
    assert_eq!(s.control_pending(), 1);

    let a2 = s.close(
        "eof again",
        CloseOptions {
            send_close_read: true,
            ..CloseOptions::default()
        },
        &empty_view(),
        now,
    );
    assert!(a2.is_empty());
    assert_eq!(s.control_pending(), 1);
}

#[test]
fn peer_close_write_clears_send_buffer() {
    let now = Instant::now();
    let mut s = client(now);
    let actions = s.mark_close_write_received(&empty_view(), now);
    assert_eq!(
        actions,
        vec![
            CloseAction::ClearSendBuffer,
            CloseAction::SignalWindowNotFull,
        ]
    );
    assert!(s.should_stop_local_read());
    assert!(!s.is_closed());
}

#[test]
fn close_write_ack_initiates_client_close_read() {
    let now = Instant::now();
    let mut s = client(now);
    let a1 = s.close(
        "local write eof",
        CloseOptions {
            send_close_write: true,
            ..CloseOptions::default()
        },
        &empty_view(),
        now,
    );
    assert_eq!(
        a1,
        vec![
            CloseAction::ClearRecvBuffer,
            CloseAction::Send(terminal_send(
                PACKET_PRIORITY_LOW,
                PACKET_STREAM_CLOSE_WRITE
            )),
        ]
    );
    assert_eq!(s.waiting_ack_for(), Some(PACKET_STREAM_CLOSE_WRITE));
    assert_eq!(s.control_pending(), 1);

    s.note_control_dispatched(PACKET_STREAM_CLOSE_WRITE, 0, 0, now);
    let (handled, a2) =
        s.receive_control_ack(PACKET_STREAM_CLOSE_WRITE_ACK, 0, 0, &empty_view(), now);
    assert!(handled);
    // The client's writer broke, so acking the close-write kicks off the
    // read-side close too.
    assert_eq!(
        a2,
        vec![CloseAction::Send(terminal_send(
            PACKET_PRIORITY_CRITICAL,
            PACKET_STREAM_CLOSE_READ
        ))]
    );
    assert_eq!(s.waiting_ack_for(), Some(PACKET_STREAM_CLOSE_READ));
    assert_eq!(s.control_pending(), 1);
    assert!(!s.is_closed());
}

#[test]
fn terminal_untracked_when_reliability_off() {
    let now = Instant::now();
    let mut s = StreamLifecycle::new(
        CloseConfig::client_defaults(),
        ControlConfig::client_defaults(),
        true,
        false,
        now,
    );
    let a1 = s.close(
        "eof",
        CloseOptions {
            send_close_read: true,
            ..CloseOptions::default()
        },
        &empty_view(),
        now,
    );
    // The packet still goes out, but it is a direct (untracked) send.
    assert_eq!(a1.len(), 1);
    assert_eq!(s.control_pending(), 0);
    assert_eq!(s.waiting_ack_for(), Some(PACKET_STREAM_CLOSE_READ));

    // The waiting-ack fallback still recognises the ack even with nothing
    // tracked.
    let (handled, a2) =
        s.receive_control_ack(PACKET_STREAM_CLOSE_READ_ACK, 0, 0, &empty_view(), now);
    assert!(handled);
    assert!(a2.is_empty());
    assert_eq!(s.waiting_ack_for(), None);
    assert!(!s.is_closed());
}

#[test]
fn control_retransmit_fires_after_rto() {
    let now = Instant::now();
    let mut s = client(now);
    s.close(
        "eof",
        CloseOptions {
            send_close_read: true,
            ..CloseOptions::default()
        },
        &empty_view(),
        now,
    );
    s.note_control_dispatched(PACKET_STREAM_CLOSE_READ, 0, 0, now);

    // Before the 500ms control RTO: nothing due.
    let (resends, actions) =
        s.poll_control_retransmits(&empty_view(), now + Duration::from_millis(400));
    assert!(resends.is_empty());
    assert!(actions.is_empty());

    // After the RTO: the CLOSE_READ is resent, no expiry.
    let (resends2, actions2) =
        s.poll_control_retransmits(&empty_view(), now + Duration::from_millis(600));
    assert_eq!(resends2.len(), 1);
    assert_eq!(resends2[0].packet_type, PACKET_STREAM_CLOSE_READ);
    assert!(actions2.is_empty());
}

#[test]
fn config_floors_apply() {
    let now = Instant::now();
    let cfg = CloseConfig {
        inactivity_timeout: Duration::from_secs(1),
        terminal_drain_timeout: Duration::from_secs(1),
        terminal_ack_wait: Duration::from_secs(1),
    };
    let s = StreamLifecycle::new(cfg, ControlConfig::client_defaults(), true, true, now);
    assert_eq!(s.inactivity_timeout, Duration::from_secs(120));
    assert_eq!(s.terminal_drain_timeout, Duration::from_secs(60));
    assert_eq!(s.terminal_ack_wait, Duration::from_secs(30));
}

#[test]
fn local_writer_broken_clears_receive_buffer() {
    let now = Instant::now();
    let mut s = client(now);
    let actions = s.mark_local_writer_broken();
    assert_eq!(actions, vec![CloseAction::ClearRecvBuffer]);
    assert!(s.local_writer_broken);
    assert!(!s.local_write_pending);
}
