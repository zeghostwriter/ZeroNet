//! The close handshake and teardown of one stream, as a pure (sans-IO) state
//! machine.
//!
//! A stream can end four ways, and this module is the referee for all of them:
//!
//!  * **Graceful read-close** — the local read side ended (the app sent EOF), so
//!    we tell the peer to finish draining what it still owes us and then close
//!    its writer (`STREAM_CLOSE_READ`).
//!  * **Graceful write-close** — the local write side ended, so we tell the peer
//!    to stop sending to us (`STREAM_CLOSE_WRITE`).
//!  * **Reset** — something went wrong (a dead peer, a broken local socket, an
//!    exhausted retransmit); we abort with `STREAM_RST`.
//!  * **Finalize** — both halves have settled (or we were forced), so the stream
//!    is torn down and its owner notified.
//!
//! # Why it owns the control plane
//!
//! Every terminal packet (`CLOSE_READ` / `CLOSE_WRITE` / `RST`) must survive the
//! lossy tunnel, so it is sent *through* the control reliability plane
//! ([`super::control`]) and tracked until its ack. The close machine therefore
//! owns a [`ControlReliability`] instance and drives it: it decides which
//! terminal packet to emit, hands it to the control plane to track, and reacts
//! when the control plane reports an ack arrived or a tracked packet ran out of
//! retries. Keeping the two together means the "a terminal packet was finally
//! acknowledged" and "a terminal packet gave up" edges live in one place.
//!
//! # Sans-IO contract
//!
//! Like the rest of the ARQ, this holds no socket, timer, or lock. It owns the
//! close/reset flags, the drain and ack-wait bookkeeping, and the control
//! plane; everything it cannot own — the data send/receive buffers, the count
//! of inbound packets still queued, the next expected sequence — is read from a
//! [`StreamView`] snapshot the caller passes in. Every decision that would do
//! IO is returned as a [`CloseAction`] for the caller to carry out: put a packet
//! on the wire, clear a buffer, close the socket, or tear the stream down. Clock
//! reads are always an explicit `now: Instant`, so a terminal packet's ack-wait
//! and drain deadlines are armed from the caller's clock, never guessed.
//!
//! # The invariant a newcomer must keep
//!
//! Once [`CloseAction::Finalized`] is emitted the stream is dead: `closed` is
//! true, every queue has been ordered cleared, and no later call will emit
//! another action. Callers must apply a returned action list in order and stop
//! feeding the machine once they have seen `Finalized`.

use std::time::{Duration, Instant};

use zero_protocol::masterdns::enums::{
    default_packet_priority, is_close_stream_packet, PACKET_STREAM_CLOSE_READ,
    PACKET_STREAM_CLOSE_READ_ACK, PACKET_STREAM_CLOSE_WRITE, PACKET_STREAM_CLOSE_WRITE_ACK,
    PACKET_STREAM_RST, PACKET_STREAM_RST_ACK,
};

use super::control::{
    AckMatch, ControlConfig, ControlExpiry, ControlReliability, ControlSend, ControlSendOutcome,
};

/// The lifecycle states a stream moves through, mirroring Go `StreamState`
/// (which itself mirrors the Python reference). The numeric order matches so a
/// state logged on one side reads the same on the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closing,
    Reset,
    Closed,
    Draining,
    TimeWait,
}

/// The read-only view of data-path and inbound-queue state the close machine
/// needs but does not own. The caller fills this from the [`DataArq`] and its
/// inbound queue each time it drives the close machine, so the two never hold
/// two copies of the same counter.
///
/// [`DataArq`]: super::data::DataArq
#[derive(Debug, Clone, Copy, Default)]
pub struct StreamView {
    /// Outstanding unacknowledged data packets (`len(sndBuf)`): the drain is
    /// complete when this hits zero.
    pub snd_buf_len: usize,
    /// Buffered-but-not-yet-delivered inbound data packets (`len(rcvBuf)`).
    pub rcv_buf_len: usize,
    /// Inbound data packets accepted but not yet processed (`pendingInbound`).
    pub pending_inbound: usize,
    /// Contiguous inbound packets ready to deliver from `rcvNxt` upward.
    pub contiguous_ready: usize,
    /// Next inbound sequence number expected (`rcvNxt`); the final-ack watchdog
    /// dup-acks `rcv_nxt - 1`.
    pub rcv_nxt: u16,
}

/// How a [`StreamLifecycle::close`] call should end the stream, mirroring Go
/// `CloseOptions`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloseOptions {
    /// Finalize immediately with no terminal packet (also clears the virtual
    /// flag). Overrides the send flags.
    pub force: bool,
    /// Abort the stream with `STREAM_RST`.
    pub send_rst: bool,
    /// End the local write side: ask the peer to stop sending (`CLOSE_WRITE`).
    pub send_close_write: bool,
    /// End the local read side: ask the peer to finish and close its writer
    /// (`CLOSE_READ`).
    pub send_close_read: bool,
    /// Drain outstanding outbound data before emitting the terminal packet,
    /// falling back to `RST` if the drain times out.
    pub after_drain: bool,
    /// Per-packet TTL for the emitted terminal packet. `Duration::ZERO` uses the
    /// stream-wide control retry/TTL limits instead.
    pub ttl: Duration,
}

/// One side effect the close machine wants the caller to perform. Apply these
/// in the order returned; stop once [`CloseAction::Finalized`] appears.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseAction {
    /// Put a terminal/control packet on the wire. If it was tracked for ack, the
    /// caller reports the enqueue result back via
    /// [`StreamLifecycle::note_control_dispatched`] /
    /// [`StreamLifecycle::note_control_dispatch_failed`]; for an untracked send
    /// those are harmless no-ops.
    Send(ControlSend),
    /// Send a bare `STREAM_DATA_ACK` of this sequence — the final-ack watchdog's
    /// duplicate ack that nudges a quiet peer to notice our half-close.
    SendDataAck(u16),
    /// Clear both data buffers (send and receive) — RST / abort / finalize.
    ClearAllData,
    /// Clear the outbound (send) buffer and evict any already-queued copies.
    ClearOutboundData,
    /// Clear the receive buffer (a local close-write or broken writer discards
    /// anything the peer still owes us).
    ClearRecvBuffer,
    /// Clear the send buffer and evict queued copies (a peer close-write means
    /// our outbound data will never be read).
    ClearSendBuffer,
    /// Wake any producer blocked on a full send window (outbound space freed).
    SignalWindowNotFull,
    /// Wake the flush path (newly deliverable data, or a terminal state the
    /// reader should observe).
    SignalFlushReady,
    /// Close the local connection socket.
    CloseLocalConn,
    /// The stream has reached its terminal state. Tear everything down and
    /// report `reason` to the owner. No further actions follow this one.
    Finalized { reason: String },
}

/// Tunables for the close/teardown timers, in explicit `Duration`s. The
/// constructor applies the same floors Go `NewARQ` does, so a zeroed config
/// lands on safe values.
#[derive(Debug, Clone, Copy)]
pub struct CloseConfig {
    /// Idle time after which a stream with nothing in flight is declared dead
    /// and reset. Floored to 120s.
    pub inactivity_timeout: Duration,
    /// How long a deferred terminal close waits for outbound data to drain
    /// before falling back to `RST`. Floored to 60s.
    pub terminal_drain_timeout: Duration,
    /// How long to wait for a terminal packet's ack before escalating. Floored
    /// to 30s.
    pub terminal_ack_wait: Duration,
}

impl CloseConfig {
    /// The client-side defaults: 1800s inactivity, 120s drain, 90s ack wait —
    /// the values Go `config/client.go` fills in when the TOML leaves them
    /// unset.
    pub fn client_defaults() -> Self {
        CloseConfig {
            inactivity_timeout: Duration::from_secs(1800),
            terminal_drain_timeout: Duration::from_secs(120),
            terminal_ack_wait: Duration::from_secs(90),
        }
    }
}

impl Default for CloseConfig {
    fn default() -> Self {
        Self::client_defaults()
    }
}

/// The close/teardown state machine for one stream, owning its control
/// reliability plane. Drive it with the `mark_*` hooks (peer signalled a
/// close/reset), [`receive_control_ack`], [`close`], and the pollers
/// ([`poll_control_retransmits`], [`handle_terminal_retransmit_state`],
/// [`run_final_ack_watchdog`]); apply the [`CloseAction`]s each returns.
///
/// [`receive_control_ack`]: StreamLifecycle::receive_control_ack
/// [`close`]: StreamLifecycle::close
/// [`poll_control_retransmits`]: StreamLifecycle::poll_control_retransmits
/// [`handle_terminal_retransmit_state`]: StreamLifecycle::handle_terminal_retransmit_state
/// [`run_final_ack_watchdog`]: StreamLifecycle::run_final_ack_watchdog
pub struct StreamLifecycle {
    control: ControlReliability,

    state: StreamState,
    closed: bool,
    close_reason: String,
    last_activity: Instant,
    is_client: bool,
    is_virtual: bool,
    enable_control_reliability: bool,

    // Close-read handshake (local read side ended).
    close_read_sent: bool,
    close_read_received: bool,
    close_read_acked: bool,
    close_read_seq_sent: Option<u16>,
    close_read_acked_at: Option<Instant>,

    // Close-write handshake (local write side ended).
    close_write_sent: bool,
    close_write_received: bool,
    close_write_acked: bool,
    close_write_seq_sent: Option<u16>,

    // Reset handshake.
    rst_received: bool,
    rst_sent: bool,
    rst_acked: bool,
    rst_seq_sent: Option<u16>,

    // Local endpoint state, set by the IO wrappers and read here.
    local_write_closed: bool,
    local_writer_broken: bool,
    local_write_pending: bool,
    stop_local_read: bool,

    // Deferred (drain-first) terminal close.
    deferred_close: bool,
    deferred_reason: String,
    deferred_deadline: Option<Instant>,
    deferred_packet: u8,
    drain_progress_at: Option<Instant>,
    drain_queue_fail_at: Option<Instant>,
    drain_queue_fails: u32,
    drain_stall_logged: bool,

    // Terminal ack wait.
    waiting_ack: bool,
    waiting_ack_for: u8,
    ack_wait_deadline: Option<Instant>,

    client_eof_at: Option<Instant>,
    last_duplicate_ack_at: Option<Instant>,

    inactivity_timeout: Duration,
    terminal_drain_timeout: Duration,
    terminal_ack_wait: Duration,
}

impl StreamLifecycle {
    /// Build a close machine at [`StreamState::Open`]. `now` seeds the activity
    /// clock. `enable_control_reliability` threads through to the owned control
    /// plane (and gates whether terminal packets are tracked for ack).
    pub fn new(
        close_cfg: CloseConfig,
        control_cfg: ControlConfig,
        is_client: bool,
        enable_control_reliability: bool,
        now: Instant,
    ) -> Self {
        StreamLifecycle {
            control: ControlReliability::new(control_cfg, enable_control_reliability),
            state: StreamState::Open,
            closed: false,
            close_reason: String::new(),
            last_activity: now,
            is_client,
            is_virtual: false,
            enable_control_reliability,
            close_read_sent: false,
            close_read_received: false,
            close_read_acked: false,
            close_read_seq_sent: None,
            close_read_acked_at: None,
            close_write_sent: false,
            close_write_received: false,
            close_write_acked: false,
            close_write_seq_sent: None,
            rst_received: false,
            rst_sent: false,
            rst_acked: false,
            rst_seq_sent: None,
            local_write_closed: false,
            local_writer_broken: false,
            local_write_pending: false,
            stop_local_read: false,
            deferred_close: false,
            deferred_reason: String::new(),
            deferred_deadline: None,
            deferred_packet: 0,
            drain_progress_at: None,
            drain_queue_fail_at: None,
            drain_queue_fails: 0,
            drain_stall_logged: false,
            waiting_ack: false,
            waiting_ack_for: 0,
            ack_wait_deadline: None,
            client_eof_at: None,
            last_duplicate_ack_at: None,
            inactivity_timeout: close_cfg.inactivity_timeout.max(Duration::from_secs(120)),
            terminal_drain_timeout: close_cfg
                .terminal_drain_timeout
                .max(Duration::from_secs(60)),
            terminal_ack_wait: close_cfg.terminal_ack_wait.max(Duration::from_secs(30)),
        }
    }

    // -- read-only accessors -------------------------------------------------

    /// The current lifecycle state.
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Whether the stream has reached its terminal state (a `Finalized` action
    /// was emitted). Once true the machine emits nothing further.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// How many control packets are tracked and awaiting their ack.
    pub fn control_pending(&self) -> usize {
        self.control.pending()
    }

    /// Whether a terminal ack is currently awaited, and for which packet type.
    pub fn waiting_ack_for(&self) -> Option<u8> {
        if self.waiting_ack {
            Some(self.waiting_ack_for)
        } else {
            None
        }
    }

    /// Whether local reads should stop (a terminal close is underway).
    pub fn should_stop_local_read(&self) -> bool {
        self.stop_local_read
    }

    // -- activity / local-endpoint setters -----------------------------------

    /// Note any stream activity (an inbound packet, a local read). Resets the
    /// inactivity clock, mirroring Go setting `a.lastActivity = now`.
    pub fn note_activity(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// Record the local app's EOF timestamp (client only), used to pace the
    /// client's post-EOF close-write. Mirrors Go `noteClientEOF`.
    pub fn note_client_eof(&mut self, now: Instant) {
        if self.is_client && self.client_eof_at.is_none() {
            self.client_eof_at = Some(now);
        }
    }

    /// Set whether a local write is in flight. The writer loop keeps this
    /// current; the close machine reads it to know the write side is quiet.
    pub fn set_local_write_pending(&mut self, pending: bool) {
        self.local_write_pending = pending;
    }

    /// Mark the local writer as broken (a local socket write error): the write
    /// side is dead, so inbound we would hand it is discarded. Mirrors Go
    /// `markLocalWriterBroken`.
    pub fn mark_local_writer_broken(&mut self) -> Vec<CloseAction> {
        self.local_writer_broken = true;
        self.local_write_pending = false;
        vec![CloseAction::ClearRecvBuffer]
    }

    // -- control-plane dispatch passthrough ----------------------------------

    /// Send a control packet (a stream's setup packets, for one) through the
    /// owned control plane, tracked until its ack when `track_for_ack` is set.
    /// Passthrough to [`ControlReliability::send_control`]; the ack of a packet
    /// is the one the fixed table pairs it with.
    #[allow(clippy::too_many_arguments)]
    pub fn send_control(
        &mut self,
        packet_type: u8,
        seq: u16,
        fragment_id: u8,
        total_fragments: u8,
        payload: Vec<u8>,
        priority: usize,
        track_for_ack: bool,
        ttl: Duration,
        now: Instant,
    ) -> ControlSendOutcome {
        self.control.send_control(
            packet_type,
            seq,
            fragment_id,
            total_fragments,
            payload,
            priority,
            track_for_ack,
            None,
            ttl,
            now,
        )
    }

    /// Report that a control/terminal packet left the send queue, starting its
    /// retransmit clock. Passthrough to the owned control plane.
    pub fn note_control_dispatched(
        &mut self,
        packet_type: u8,
        seq: u16,
        fragment_id: u8,
        now: Instant,
    ) {
        self.control
            .on_dispatched(packet_type, seq, fragment_id, now);
    }

    /// Report that the send queue rejected a control/terminal packet, so it is
    /// resent on the next poll. Passthrough to the owned control plane.
    pub fn note_control_dispatch_failed(
        &mut self,
        packet_type: u8,
        seq: u16,
        fragment_id: u8,
        now: Instant,
    ) {
        self.control
            .on_dispatch_failed(packet_type, seq, fragment_id, now);
    }

    // -- peer-signalled transitions ------------------------------------------

    /// The peer told us it has closed its read side (it will finish draining and
    /// stop reading). Mirrors Go `MarkCloseReadReceived`.
    pub fn mark_close_read_received(&mut self, view: &StreamView) -> Vec<CloseAction> {
        let mut out = Vec::new();
        if self.is_virtual {
            return out;
        }
        self.close_read_received = true;
        if self.close_read_sent {
            self.set_state(StreamState::Closing);
        } else {
            self.set_state(StreamState::HalfClosedRemote);
        }
        out.push(CloseAction::SignalFlushReady);
        self.try_finalize_remote_eof(view, &mut out);
        out
    }

    /// The peer told us it has closed its write side (it will send us no more).
    /// Clears our outbound buffer (it will never be read) and re-evaluates any
    /// deferred drain. Mirrors Go `MarkCloseWriteReceived`.
    pub fn mark_close_write_received(
        &mut self,
        view: &StreamView,
        now: Instant,
    ) -> Vec<CloseAction> {
        let mut out = Vec::new();
        if self.is_virtual {
            return out;
        }
        self.close_write_received = true;
        self.stop_local_read = true;
        out.push(CloseAction::ClearSendBuffer);
        out.push(CloseAction::SignalWindowNotFull);
        // A peer close-write can empty outbound state without an ack, so a
        // deferred terminal close may now be ready.
        self.settle_terminal_drain(view, now, &mut out);
        self.try_finalize_remote_eof(view, &mut out);
        out
    }

    /// The peer reset the stream. Clears our outbound state and flushes any
    /// readable data to the local side before the drain finalizes. Mirrors Go
    /// `MarkRstReceived`.
    pub fn mark_rst_received(&mut self) -> Vec<CloseAction> {
        let mut out = Vec::new();
        if self.is_virtual {
            return out;
        }
        self.rst_received = true;
        self.stop_local_read = true;
        self.control.clear();
        out.push(CloseAction::ClearOutboundData);
        self.set_state(StreamState::Reset);
        out.push(CloseAction::SignalFlushReady);
        out
    }

    // -- close entry point ---------------------------------------------------

    /// The single close entry point, mirroring Go `Close`. `opts` selects the
    /// teardown shape (force-finalize, RST, close-read, close-write, optionally
    /// drain-first). Returns the actions to apply.
    pub fn close(
        &mut self,
        reason: &str,
        opts: CloseOptions,
        view: &StreamView,
        now: Instant,
    ) -> Vec<CloseAction> {
        let mut out = Vec::new();
        self.close_into(reason, opts, view, now, &mut out);
        out
    }

    fn close_into(
        &mut self,
        reason: &str,
        opts: CloseOptions,
        view: &StreamView,
        now: Instant,
        out: &mut Vec<CloseAction>,
    ) {
        if self.is_virtual && !opts.force {
            return;
        }

        if opts.force || (!opts.send_rst && !opts.send_close_write && !opts.send_close_read) {
            self.is_virtual = false;
            self.finalize_close(reason, out);
            return;
        }

        if opts.send_close_read {
            if opts.after_drain {
                self.defer_terminal_packet(reason, PACKET_STREAM_CLOSE_READ, view, now, out);
            } else {
                self.emit_terminal_packet(
                    PACKET_STREAM_CLOSE_READ,
                    reason,
                    opts.ttl,
                    view,
                    now,
                    out,
                );
            }
            return;
        }

        if opts.send_close_write {
            self.emit_terminal_packet(PACKET_STREAM_CLOSE_WRITE, reason, opts.ttl, view, now, out);
            return;
        }

        // SendRST.
        if self.closed {
            return;
        }
        let already_resetting = self.rst_sent
            || self.rst_received
            || (self.waiting_ack && self.waiting_ack_for == PACKET_STREAM_RST)
            || (self.deferred_close && self.deferred_packet == PACKET_STREAM_RST);
        if already_resetting {
            return;
        }
        let has_pending_data = view.snd_buf_len > 0;
        self.close_reason = reason.to_string();
        self.set_state(StreamState::Reset);
        self.clear_deferred();
        if opts.after_drain && has_pending_data {
            self.defer_terminal_packet(reason, PACKET_STREAM_RST, view, now, out);
        } else {
            self.emit_terminal_packet(PACKET_STREAM_RST, reason, opts.ttl, view, now, out);
        }
    }

    // -- terminal emit / drain -----------------------------------------------

    /// Arm a drain-before-terminal phase: stop new local reads, remember which
    /// terminal packet to send once the outbound buffer empties, and settle
    /// immediately if nothing is pending. Mirrors Go `deferTerminalPacket`.
    fn defer_terminal_packet(
        &mut self,
        reason: &str,
        packet_type: u8,
        view: &StreamView,
        now: Instant,
        out: &mut Vec<CloseAction>,
    ) {
        if self.closed || self.is_virtual {
            return;
        }
        if self.state != StreamState::Reset && self.state != StreamState::Closed {
            self.set_state(StreamState::Draining);
        }
        self.stop_local_read = true;
        self.deferred_close = true;
        self.deferred_reason = reason.to_string();
        self.deferred_packet = packet_type;

        // Use the furthest-out deadline, matching Go's `deadline.After` guard,
        // so re-arming never shortens a drain already in progress.
        let deadline = now + self.terminal_drain_timeout;
        if self.deferred_deadline.map(|d| deadline > d).unwrap_or(true) {
            self.deferred_deadline = Some(deadline);
        }
        self.reset_drain_tracking(Some(now));

        if view.snd_buf_len == 0 {
            self.settle_terminal_drain(view, now, out);
        }
    }

    /// Complete a previously deferred terminal close: emit the deferred packet
    /// once the outbound buffer has drained, or fall back to `RST` if the drain
    /// deadline passed. Mirrors Go `settleTerminalDrain`.
    fn settle_terminal_drain(
        &mut self,
        view: &StreamView,
        now: Instant,
        out: &mut Vec<CloseAction>,
    ) {
        if self.closed || !self.deferred_close {
            return;
        }

        let (packet_type, reason) = if view.snd_buf_len == 0 {
            (self.deferred_packet, self.deferred_reason.clone())
        } else if self.deferred_deadline.map(|d| now > d).unwrap_or(false) {
            (
                PACKET_STREAM_RST,
                format!("{} but drain timeout expired", self.deferred_reason),
            )
        } else {
            return;
        };

        self.clear_deferred();

        let opts = CloseOptions {
            send_close_read: packet_type == PACKET_STREAM_CLOSE_READ,
            send_close_write: packet_type == PACKET_STREAM_CLOSE_WRITE,
            send_rst: packet_type == PACKET_STREAM_RST,
            ..CloseOptions::default()
        };
        self.close_into(&reason, opts, view, now, out);
    }

    /// Emit a terminal packet (`CLOSE_READ` / `CLOSE_WRITE` / `RST`) and start
    /// waiting for its ack. Mirrors Go `emitTerminalPacketWithTTL`.
    fn emit_terminal_packet(
        &mut self,
        packet_type: u8,
        reason: &str,
        ttl: Duration,
        view: &StreamView,
        now: Instant,
        out: &mut Vec<CloseAction>,
    ) {
        if self.closed || self.is_virtual {
            return;
        }
        self.close_reason = reason.to_string();
        self.stop_local_read = true;
        self.clear_deferred();

        if self.waiting_ack && self.waiting_ack_for == packet_type {
            return;
        }

        match packet_type {
            PACKET_STREAM_CLOSE_READ => {
                if self.rst_sent || self.rst_received || self.close_read_sent {
                    return;
                }
                let seq = *self.close_read_seq_sent.get_or_insert(0);
                self.begin_ack_wait(packet_type, now);
                self.mark_close_read_sent(view, out);
                self.push_terminal_send(
                    PACKET_STREAM_CLOSE_READ,
                    seq,
                    PACKET_STREAM_CLOSE_READ_ACK,
                    ttl,
                    now,
                    out,
                );
            }
            PACKET_STREAM_CLOSE_WRITE => {
                if self.rst_received || self.rst_sent || self.close_write_sent {
                    return;
                }
                let seq = *self.close_write_seq_sent.get_or_insert(0);
                self.begin_ack_wait(packet_type, now);
                self.mark_close_write_sent(out);
                self.push_terminal_send(
                    PACKET_STREAM_CLOSE_WRITE,
                    seq,
                    PACKET_STREAM_CLOSE_WRITE_ACK,
                    ttl,
                    now,
                    out,
                );
            }
            PACKET_STREAM_RST => {
                if self.rst_received || self.rst_sent {
                    return;
                }
                let seq = *self.rst_seq_sent.get_or_insert(0);
                self.control.clear();
                out.push(CloseAction::ClearAllData);
                out.push(CloseAction::SignalWindowNotFull);
                self.begin_ack_wait(packet_type, now);
                self.mark_rst_sent();
                self.push_terminal_send(
                    PACKET_STREAM_RST,
                    seq,
                    PACKET_STREAM_RST_ACK,
                    ttl,
                    now,
                    out,
                );
            }
            _ => {}
        }
    }

    /// Hand a terminal packet to the control plane (tracked for ack when
    /// reliability is on) and queue the resulting [`CloseAction::Send`]. The
    /// `now` stamps the control item's creation (its TTL clock); the retransmit
    /// clock only starts once the caller reports the dispatch back.
    fn push_terminal_send(
        &mut self,
        packet_type: u8,
        seq: u16,
        ack_type: u8,
        ttl: Duration,
        now: Instant,
        out: &mut Vec<CloseAction>,
    ) {
        let outcome = self.control.send_control(
            packet_type,
            seq,
            0,
            0,
            Vec::new(),
            default_packet_priority(packet_type),
            self.enable_control_reliability,
            Some(ack_type),
            ttl,
            now,
        );
        if let Some(packet) = outcome.packet {
            out.push(CloseAction::Send(packet));
        }
    }

    // -- local-side mark hooks -----------------------------------------------

    /// Our read side is now closing. Mirrors Go `MarkCloseReadSent` and its
    /// trailing `tryFinalizeRemoteEOF`.
    fn mark_close_read_sent(&mut self, view: &StreamView, out: &mut Vec<CloseAction>) {
        self.close_read_sent = true;
        if self.close_read_received {
            self.set_state(StreamState::Closing);
        } else {
            self.set_state(StreamState::HalfClosedLocal);
        }
        self.try_finalize_remote_eof(view, out);
    }

    fn mark_close_write_sent(&mut self, out: &mut Vec<CloseAction>) {
        self.close_write_sent = true;
        self.local_writer_broken = true;
        self.local_write_closed = true;
        out.push(CloseAction::ClearRecvBuffer);
        if self.close_read_received {
            self.set_state(StreamState::Closing);
        }
    }

    fn mark_rst_sent(&mut self) {
        self.rst_sent = true;
        self.control.clear();
        self.set_state(StreamState::Reset);
    }

    fn mark_close_read_acked(&mut self, now: Instant) {
        self.close_read_acked = true;
        self.close_read_acked_at = Some(now);
        if self.close_read_received {
            self.set_state(StreamState::Closing);
        }
    }

    fn mark_close_write_acked(&mut self) {
        self.close_write_acked = true;
        self.local_writer_broken = true;
        self.local_write_closed = true;
    }

    /// RST acknowledged. The data clear Go does inline here is subsumed by the
    /// `finalize_close` that always immediately follows (it emits
    /// [`CloseAction::ClearAllData`]), so this only clears control and flips the
    /// state. Mirrors Go `markRstAcked`.
    fn mark_rst_acked(&mut self) {
        self.rst_acked = true;
        self.control.clear();
        self.set_state(StreamState::Reset);
    }

    // -- control ack ---------------------------------------------------------

    /// Take one inbound control ack: fold its round trip into the control RTO,
    /// release the tracked terminal packet, and run the resulting close-state
    /// transition. Returns whether the ack was recognised/handled and the
    /// actions to apply. Mirrors Go `ReceiveControlAck`.
    pub fn receive_control_ack(
        &mut self,
        ack_packet_type: u8,
        seq: u16,
        fragment_id: u8,
        view: &StreamView,
        now: Instant,
    ) -> (bool, Vec<CloseAction>) {
        let mut out = Vec::new();
        self.last_activity = now;

        // The waiting-ack flags are read against our own state *before* the
        // control plane deletes the tracked entry, matching Go's ordering.
        let waiting_for = self.waiting_ack_for;
        let is_waiting_close_read = ack_packet_type == PACKET_STREAM_CLOSE_READ_ACK
            && waiting_for == PACKET_STREAM_CLOSE_READ;
        let is_waiting_close_write = ack_packet_type == PACKET_STREAM_CLOSE_WRITE_ACK
            && waiting_for == PACKET_STREAM_CLOSE_WRITE;
        let is_waiting_rst =
            ack_packet_type == PACKET_STREAM_RST_ACK && waiting_for == PACKET_STREAM_RST;

        let (origin, tracked) =
            match self
                .control
                .receive_ack(ack_packet_type, seq, fragment_id, now)
            {
                AckMatch::NotControlAck => return (false, out),
                AckMatch::Recognised { origin, tracked } => (origin, tracked),
            };

        if !tracked && !is_waiting_close_read && !is_waiting_close_write && !is_waiting_rst {
            return (false, out);
        }

        if tracked && self.handle_tracked_close_or_reset_ack(origin, view, now, &mut out) {
            return (true, out);
        }
        if tracked && self.handle_tracked_terminal_ack(origin, &mut out) {
            return (true, out);
        }
        if self.handle_waiting_terminal_ack(
            ack_packet_type,
            is_waiting_close_read,
            is_waiting_close_write,
            is_waiting_rst,
            view,
            now,
            &mut out,
        ) {
            return (true, out);
        }

        (tracked, out)
    }

    /// The ack released a tracked `CLOSE_READ` / `CLOSE_WRITE` / `RST`. Mirrors
    /// Go `handleTrackedCloseOrResetAck`.
    fn handle_tracked_close_or_reset_ack(
        &mut self,
        origin: u8,
        view: &StreamView,
        now: Instant,
        out: &mut Vec<CloseAction>,
    ) -> bool {
        match origin {
            PACKET_STREAM_CLOSE_READ => {
                self.mark_close_read_acked(now);
                self.clear_waiting_ack(PACKET_STREAM_CLOSE_READ);
                self.try_finalize_remote_eof(view, out);
                true
            }
            PACKET_STREAM_CLOSE_WRITE => {
                self.mark_close_write_acked();
                self.clear_waiting_ack(PACKET_STREAM_CLOSE_WRITE);
                self.maybe_initiate_client_close_read_after_writer_break(view, now, out);
                self.try_finalize_remote_eof(view, out);
                true
            }
            PACKET_STREAM_RST => {
                self.mark_rst_acked();
                self.finalize_close("RST acknowledged", out);
                true
            }
            _ => false,
        }
    }

    /// The ack released a tracked close-stream packet that is *not* one of the
    /// three terminal types (a SOCKS failure result, a connect-fail): its ack
    /// finalizes the stream directly. Mirrors Go `handleTrackedTerminalAck`.
    fn handle_tracked_terminal_ack(&mut self, origin: u8, out: &mut Vec<CloseAction>) -> bool {
        if is_close_stream_packet(origin)
            && origin != PACKET_STREAM_CLOSE_READ
            && origin != PACKET_STREAM_CLOSE_WRITE
            && origin != PACKET_STREAM_RST
        {
            self.finalize_close("terminal packet acknowledged", out);
            return true;
        }
        false
    }

    /// The ack matched a terminal packet we were waiting on but the control
    /// plane was not tracking (reliability off, or it already expired). Mirrors
    /// Go `handleWaitingTerminalAck`.
    #[allow(clippy::too_many_arguments)]
    fn handle_waiting_terminal_ack(
        &mut self,
        ack_packet_type: u8,
        is_waiting_close_read: bool,
        is_waiting_close_write: bool,
        is_waiting_rst: bool,
        view: &StreamView,
        now: Instant,
        out: &mut Vec<CloseAction>,
    ) -> bool {
        if ack_packet_type == PACKET_STREAM_CLOSE_READ_ACK && is_waiting_close_read {
            self.mark_close_read_acked(now);
            self.clear_waiting_ack(PACKET_STREAM_CLOSE_READ);
            self.try_finalize_remote_eof(view, out);
            return true;
        }
        if ack_packet_type == PACKET_STREAM_CLOSE_WRITE_ACK && is_waiting_close_write {
            self.mark_close_write_acked();
            self.clear_waiting_ack(PACKET_STREAM_CLOSE_WRITE);
            self.maybe_initiate_client_close_read_after_writer_break(view, now, out);
            self.try_finalize_remote_eof(view, out);
            return true;
        }
        if ack_packet_type == PACKET_STREAM_RST_ACK && is_waiting_rst {
            self.mark_rst_acked();
            self.finalize_close("RST acknowledged", out);
            return true;
        }
        false
    }

    // -- finalize predicates -------------------------------------------------

    /// Finalize the stream once both halves of the close handshake have settled.
    /// Mirrors Go `tryFinalizeRemoteEOF` (and its
    /// `tryFinalizeClientLocalDisconnect` fallback).
    fn try_finalize_remote_eof(&mut self, view: &StreamView, out: &mut Vec<CloseAction>) {
        let waiting_for_close_read_ack =
            self.waiting_ack && self.waiting_ack_for == PACKET_STREAM_CLOSE_READ;
        let receive_drained =
            (view.rcv_buf_len == 0 && view.pending_inbound == 0) || self.local_writer_broken;
        let write_side_settled = (!self.local_writer_broken
            && (!self.close_write_sent || self.close_write_acked))
            || (self.local_writer_broken && (self.close_write_acked || self.close_write_received));
        let should_close = !self.closed
            && self.close_read_received
            && receive_drained
            && (!self.local_write_pending || self.local_writer_broken)
            && (self.close_read_acked || (self.close_read_sent && !waiting_for_close_read_ack))
            && write_side_settled;

        if should_close {
            self.finalize_close("close handshake completed", out);
            return;
        }
        self.try_finalize_client_local_disconnect(view, out);
    }

    /// Peer sent us an RST: once our readable data has drained, finalize.
    /// Mirrors Go `tryFinalizePeerResetDrain`; returns whether it finalized.
    fn try_finalize_peer_reset_drain(
        &mut self,
        view: &StreamView,
        out: &mut Vec<CloseAction>,
    ) -> bool {
        if !self.rst_received || self.closed {
            return false;
        }
        if view.contiguous_ready > 0 {
            out.push(CloseAction::SignalFlushReady);
            return false;
        }
        if self.local_write_pending || view.pending_inbound > 0 {
            return false;
        }
        if view.rcv_buf_len > 0 {
            self.finalize_close("peer reset received with non-contiguous buffered data", out);
            return true;
        }
        self.finalize_close("peer reset received", out);
        true
    }

    /// Client-only: finalize once the local endpoint disconnected and both close
    /// halves acked with nothing left in flight. Mirrors Go
    /// `tryFinalizeClientLocalDisconnect`.
    fn try_finalize_client_local_disconnect(
        &mut self,
        view: &StreamView,
        out: &mut Vec<CloseAction>,
    ) {
        let should_close = self.is_client
            && !self.closed
            && self.local_writer_broken
            && self.close_write_acked
            && self.close_read_sent
            && self.close_read_acked
            && view.snd_buf_len == 0
            && view.rcv_buf_len == 0
            && view.pending_inbound == 0
            && !self.local_write_pending
            && !self.waiting_ack
            && !self.deferred_close;
        if should_close {
            self.finalize_close("client local disconnect completed", out);
        }
    }

    /// Client-only: after our write side broke and its close-write acked, start
    /// the read-side close too. Mirrors Go
    /// `maybeInitiateClientCloseReadAfterWriterBreak`.
    fn maybe_initiate_client_close_read_after_writer_break(
        &mut self,
        view: &StreamView,
        now: Instant,
        out: &mut Vec<CloseAction>,
    ) {
        let should_initiate = self.is_client
            && self.local_writer_broken
            && !self.closed
            && !self.rst_sent
            && !self.rst_received
            && !self.close_read_sent
            && !self.close_read_received;
        if !should_initiate {
            return;
        }
        let pending_outbound = view.snd_buf_len > 0 || self.local_write_pending;
        let opts = CloseOptions {
            send_close_read: true,
            after_drain: pending_outbound,
            ..CloseOptions::default()
        };
        self.close_into(
            "Client local endpoint disconnected after write side closed",
            opts,
            view,
            now,
            out,
        );
    }

    // -- pollers -------------------------------------------------------------

    /// Poll the owned control plane for due retransmits and expiries, mapping an
    /// expiry to the right teardown (finalize for a non-terminal close-stream
    /// type, otherwise RST). Returns the control resends plus any close actions.
    /// Mirrors Go `checkControlRetransmits` + `handleTrackedPacketTTLExpiry`.
    pub fn poll_control_retransmits(
        &mut self,
        view: &StreamView,
        now: Instant,
    ) -> (Vec<ControlSend>, Vec<CloseAction>) {
        let mut actions = Vec::new();
        if self.closed {
            return (Vec::new(), actions);
        }
        let poll = self.control.poll_retransmits(now);
        if let Some(expiry) = poll.expired {
            self.handle_tracked_packet_ttl_expiry(expiry, view, now, &mut actions);
        }
        (poll.resends, actions)
    }

    fn handle_tracked_packet_ttl_expiry(
        &mut self,
        expiry: ControlExpiry,
        view: &StreamView,
        now: Instant,
        out: &mut Vec<CloseAction>,
    ) {
        let ptype = expiry.packet_type;
        if is_close_stream_packet(ptype)
            && ptype != PACKET_STREAM_CLOSE_READ
            && ptype != PACKET_STREAM_CLOSE_WRITE
        {
            self.finalize_close(expiry.reason, out);
            return;
        }
        let opts = CloseOptions {
            send_rst: true,
            ..CloseOptions::default()
        };
        self.close_into(expiry.reason, opts, view, now, out);
    }

    /// Drive the deferred-drain and terminal-ack-wait watchdogs one tick.
    /// Returns the actions to apply and whether the stream is now closed, so the
    /// caller can skip the rest of its retransmit pass. Mirrors Go
    /// `handleTerminalRetransmitState`.
    pub fn handle_terminal_retransmit_state(
        &mut self,
        view: &StreamView,
        now: Instant,
    ) -> (Vec<CloseAction>, bool) {
        let mut out = Vec::new();

        if self.deferred_close {
            let pending = view.snd_buf_len;
            let should_close = pending == 0;
            let should_abort = self.deferred_deadline.map(|d| now > d).unwrap_or(false);
            let stalled_for = self
                .drain_progress_at
                .map(|p| now.saturating_duration_since(p))
                .unwrap_or(Duration::ZERO);
            let queue_blocked = self.drain_queue_fails >= 3
                && self
                    .drain_queue_fail_at
                    .map(|f| now.saturating_duration_since(f) <= Duration::from_secs(30))
                    .unwrap_or(false);
            let should_abort_early =
                pending > 0 && queue_blocked && stalled_for >= Duration::from_secs(20);
            if should_abort_early && !self.drain_stall_logged {
                self.drain_stall_logged = true;
            }

            if should_close || should_abort {
                self.settle_terminal_drain(view, now, &mut out);
            } else if should_abort_early {
                let opts = CloseOptions {
                    send_rst: true,
                    ..CloseOptions::default()
                };
                self.close_into(
                    "Deferred drain stalled after resend queue pressure",
                    opts,
                    view,
                    now,
                    &mut out,
                );
            }
            let closed = self.closed;
            return (out, closed);
        }

        if self.waiting_ack && self.ack_wait_deadline.map(|d| now > d).unwrap_or(false) {
            let waiting_for = self.waiting_ack_for;
            if waiting_for == PACKET_STREAM_RST {
                self.finalize_close("Terminal ACK wait timeout", &mut out);
                return (out, true);
            }
            if waiting_for == PACKET_STREAM_CLOSE_READ || waiting_for == PACKET_STREAM_CLOSE_WRITE {
                let opts = CloseOptions {
                    send_rst: true,
                    ..CloseOptions::default()
                };
                self.close_into(
                    "Close handshake ACK wait timeout",
                    opts,
                    view,
                    now,
                    &mut out,
                );
                return (out, false);
            }
            return (out, false);
        }

        if self.rst_received && !self.closed {
            let finalized = self.try_finalize_peer_reset_drain(view, &mut out);
            return (out, finalized);
        }

        let receive_drained_for_close_write =
            view.rcv_buf_len == 0 && view.pending_inbound == 0 && !self.local_write_pending;
        let peer_finished_sending = self.close_read_received || self.local_writer_broken;
        let grace_elapsed = self
            .client_eof_at
            .map(|t| now.saturating_duration_since(t) >= Duration::from_secs(2))
            .unwrap_or(false)
            || self
                .close_read_acked_at
                .map(|t| now.saturating_duration_since(t) >= Duration::from_secs(2))
                .unwrap_or(false);
        let should_initiate_close_write_after_eof = self.is_client
            && grace_elapsed
            && !self.closed
            && !self.rst_sent
            && !self.rst_received
            && self.close_read_sent
            && self.close_read_acked
            && !self.close_write_sent
            && !self.close_write_acked
            && !self.close_write_received
            && !(self.waiting_ack && self.waiting_ack_for == PACKET_STREAM_CLOSE_WRITE)
            && receive_drained_for_close_write
            && peer_finished_sending;
        if should_initiate_close_write_after_eof {
            let opts = CloseOptions {
                send_close_write: true,
                ..CloseOptions::default()
            };
            self.close_into("Client close-read grace elapsed", opts, view, now, &mut out);
            return (out, false);
        }

        if now.saturating_duration_since(self.last_activity) > self.inactivity_timeout {
            let has_pending = view.snd_buf_len > 0
                || (self.enable_control_reliability && self.control.pending() > 0);
            if has_pending {
                self.last_activity = now;
                return (out, false);
            }
            let opts = CloseOptions {
                send_rst: true,
                ..CloseOptions::default()
            };
            self.close_into(
                "Stream Inactivity Timeout (Dead)",
                opts,
                view,
                now,
                &mut out,
            );
            return (out, true);
        }

        (out, false)
    }

    /// Client-only: nudge a quiet peer that has stopped acknowledging our
    /// half-close by re-sending a duplicate `DATA_ACK` of the last byte we got.
    /// Mirrors Go `runFinalAckWatchdog`.
    pub fn run_final_ack_watchdog(&mut self, view: &StreamView, now: Instant) -> Vec<CloseAction> {
        let mut out = Vec::new();
        let should_ack = !self.closed
            && !self.rst_sent
            && !self.rst_received
            && self.is_client
            && self.close_read_sent
            && self.close_read_acked
            && !self.close_read_received
            && !self.close_write_sent
            && !self.close_write_acked
            && !self.close_write_received
            && !self.local_writer_broken
            && view.rcv_buf_len == 0
            && view.pending_inbound == 0
            && !self.local_write_pending
            && view.rcv_nxt > 0
            && now.saturating_duration_since(self.last_activity) >= Duration::from_secs(2)
            && self
                .last_duplicate_ack_at
                .map(|t| now.saturating_duration_since(t) >= Duration::from_secs(2))
                .unwrap_or(true);
        if !should_ack {
            return out;
        }
        let ack_sn = view.rcv_nxt.wrapping_sub(1);
        self.last_duplicate_ack_at = Some(now);
        out.push(CloseAction::SendDataAck(ack_sn));
        out
    }

    /// Note that a resend could not be enqueued during a drain, so the drain
    /// watchdog can detect a stalled queue. Mirrors Go `noteDrainQueueFailure`.
    pub fn note_drain_queue_failure(&mut self, now: Instant) {
        if self.deferred_close || self.state == StreamState::Draining {
            self.drain_queue_fail_at = Some(now);
            self.drain_queue_fails += 1;
        }
    }

    /// Note that outbound data drained further (an ack arrived), resetting the
    /// drain-stall tracking. Mirrors Go `noteDrainProgressLocked`.
    pub fn note_drain_progress(&mut self, now: Instant) {
        self.reset_drain_tracking(Some(now));
    }

    // -- final close ---------------------------------------------------------

    /// The terminal transition: mark the stream closed, pick the final state,
    /// order every queue cleared and the socket closed, and emit the single
    /// [`CloseAction::Finalized`]. Mirrors Go `finalizeClose`.
    fn finalize_close(&mut self, reason: &str, out: &mut Vec<CloseAction>) {
        if self.closed || self.is_virtual {
            return;
        }
        self.close_reason = reason.to_string();
        self.closed = true;
        self.clear_deferred();
        self.waiting_ack = false;
        self.waiting_ack_for = 0;
        self.ack_wait_deadline = None;

        if self.state == StreamState::Reset || self.rst_received || self.rst_sent {
            self.set_state(StreamState::Reset);
        } else if self.close_read_sent
            || self.close_read_received
            || self.close_write_sent
            || self.close_write_received
        {
            self.set_state(StreamState::TimeWait);
        } else {
            self.set_state(StreamState::Closing);
        }

        out.push(CloseAction::CloseLocalConn);
        self.control.clear();
        out.push(CloseAction::ClearAllData);
        out.push(CloseAction::SignalWindowNotFull);
        out.push(CloseAction::Finalized {
            reason: reason.to_string(),
        });
    }

    // -- small helpers -------------------------------------------------------

    fn set_state(&mut self, new_state: StreamState) {
        self.state = new_state;
    }

    fn begin_ack_wait(&mut self, packet_type: u8, now: Instant) {
        self.waiting_ack = true;
        self.waiting_ack_for = packet_type;
        self.ack_wait_deadline = Some(now + self.terminal_ack_wait);
    }

    fn clear_waiting_ack(&mut self, packet_type: u8) {
        if self.waiting_ack && self.waiting_ack_for == packet_type {
            self.waiting_ack = false;
            self.waiting_ack_for = 0;
            self.ack_wait_deadline = None;
        }
    }

    fn clear_deferred(&mut self) {
        self.deferred_close = false;
        self.deferred_reason = String::new();
        self.deferred_deadline = None;
        self.deferred_packet = 0;
    }

    fn reset_drain_tracking(&mut self, now: Option<Instant>) {
        self.drain_progress_at = now;
        self.drain_queue_fail_at = None;
        self.drain_queue_fails = 0;
        self.drain_stall_logged = false;
    }
}

#[cfg(test)]
mod tests;
