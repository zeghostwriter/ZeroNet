//! The state of a live tunnel: every stream, the queue of packets waiting for a
//! free query, and what to do with each packet that comes back.
//!
//! How it works: the tunnel is poll-driven. The server only speaks in answers
//! to queries, so a pool of workers (see `runtime`) each send one packet and
//! read the one packet that answers it. This module is what they share, kept
//! free of sockets and timers: [`Core::next_out`] hands a worker the next packet
//! to send, [`Core::handle_reply`] takes what came back, and [`Core::tick`] runs
//! the retransmit, close and keep-alive clocks. Every clock reads an explicit
//! `now`, so the whole thing is testable without a network.
//!
//! Rules it keeps:
//!  * a packet leaves the queue exactly once per [`Core::next_out`] call, and
//!    its retransmit clock starts at that moment (not when it was queued);
//!  * every control packet the server sends is acknowledged immediately, from
//!    here, before anything else is decided about it;
//!  * once a stream is finalized nothing more is delivered to its owner.
//!
//! The thing that surprises newcomers: nothing here sends data on its own
//! schedule. If the queue is empty a worker sends a keep-alive `PING`, which is
//! also the only way the server gets a chance to hand us downstream data.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot, Notify};
use zero_protocol::masterdns::enums::*;
use zero_protocol::masterdns::packet::BuildOptions;

use super::wire::Reply;
use super::Error;
use crate::arq::close::{
    CloseAction, CloseConfig, CloseOptions, StreamLifecycle, StreamState, StreamView,
};
use crate::arq::control::{ControlConfig, ControlSend};
use crate::arq::data::{Config as DataConfig, DataArq, RetransmitOutcome, SendPacket};
use crate::ping::{ping_payload, PingConfig, PingScheduler};
use crate::streamid::StreamIdAllocator;

/// How a stream asks the server to connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The server dials the target the stream names (`PROTOCOL_TYPE = "SOCKS5"`).
    Socks5,
    /// The server forwards every stream to one fixed place (`PROTOCOL_TYPE = "TCP"`).
    Tcp,
}

/// What the handshake and the config settle for one tunnel.
#[derive(Debug, Clone)]
pub(crate) struct Tuning {
    /// Payload bytes one data packet carries.
    pub chunk: usize,
    pub data: DataConfig,
    pub control: ControlConfig,
    pub close: CloseConfig,
    pub ping: PingConfig,
}

/// One packet waiting for a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Out {
    pub stream_id: u16,
    pub packet_type: u8,
    pub seq: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
    pub compression: u8,
    pub payload: Vec<u8>,
}

impl Out {
    pub fn options(&self, session_id: u8, cookie: u8) -> BuildOptions<'_> {
        BuildOptions {
            session_id,
            session_cookie: cookie,
            packet_type: self.packet_type,
            stream_id: self.stream_id,
            sequence_num: self.seq,
            fragment_id: self.fragment_id,
            total_fragments: self.total_fragments,
            compression_type: self.compression,
            payload: &self.payload,
        }
    }
}

/// Where a stream's downstream bytes go, and how a stream signals its owner.
pub(crate) struct StreamPorts {
    pub to_user: mpsc::UnboundedSender<Vec<u8>>,
    pub connect: oneshot::Sender<Result<(), Error>>,
    pub waker: Arc<Notify>,
}

struct Entry {
    data: DataArq,
    life: StreamLifecycle,
    to_user: Option<mpsc::UnboundedSender<Vec<u8>>>,
    connect: Option<oneshot::Sender<Result<(), Error>>>,
    waker: Arc<Notify>,
}

fn view(entry: &Entry) -> StreamView {
    StreamView {
        snd_buf_len: entry.data.outstanding(),
        rcv_buf_len: entry.data.recv_buffered(),
        pending_inbound: 0,
        contiguous_ready: entry.data.contiguous_ready(),
        rcv_nxt: entry.data.rcv_nxt(),
    }
}

/// The failure a SOCKS5 result packet stands for.
fn socks_failure(packet_type: u8) -> Option<Error> {
    let reason = match packet_type {
        PACKET_SOCKS5_CONNECT_FAIL => "the server could not connect",
        PACKET_SOCKS5_RULESET_DENIED => "the server's rules deny that destination",
        PACKET_SOCKS5_NETWORK_UNREACHABLE => "network unreachable from the server",
        PACKET_SOCKS5_HOST_UNREACHABLE => "host unreachable from the server",
        PACKET_SOCKS5_CONNECTION_REFUSED => "connection refused",
        PACKET_SOCKS5_TTL_EXPIRED => "the connection timed out at the server",
        PACKET_SOCKS5_COMMAND_UNSUPPORTED => "the server does not support that command",
        PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED => "the server does not support that address type",
        PACKET_SOCKS5_AUTH_FAILED => "the server refused the credentials",
        PACKET_SOCKS5_UPSTREAM_UNAVAILABLE => "the server's upstream proxy is unavailable",
        _ => return None,
    };
    Some(Error::Connect(reason.to_string()))
}

const LEVELS: usize = 6;
/// How often the clocks run at most; a tick is cheap but not free.
const TICK_EVERY: Duration = Duration::from_millis(20);
/// How long a repeat `RST` for one dead stream id is held back.
const RST_REPEAT: Duration = Duration::from_secs(1);

/// The shared tunnel state. See the module text.
pub(crate) struct Core {
    tuning: Tuning,
    mode: Mode,
    streams: HashMap<u16, Entry>,
    ids: StreamIdAllocator,
    queues: [VecDeque<Out>; LEVELS],
    ping: PingScheduler,
    last_tick: Instant,
    rst_sent: HashMap<u16, Instant>,
    /// Set when the server stopped knowing this session; the tunnel is over.
    pub dead: Option<Error>,
}

impl Core {
    pub fn new(tuning: Tuning, mode: Mode, now: Instant) -> Self {
        Core {
            ping: PingScheduler::new(tuning.ping, now),
            tuning,
            mode,
            streams: HashMap::new(),
            ids: StreamIdAllocator::new(),
            queues: Default::default(),
            last_tick: now,
            rst_sent: HashMap::new(),
            dead: None,
        }
    }

    pub fn chunk(&self) -> usize {
        self.tuning.chunk
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    pub fn has_queued(&self) -> bool {
        self.queues.iter().any(|q| !q.is_empty())
    }

    // ------------------------------------------------------------- queueing

    fn push(&mut self, priority: usize, out: Out) {
        let level = normalize_packet_priority(out.packet_type, priority).min(LEVELS - 1);
        self.queues[level].push_back(out);
    }

    fn push_send(&mut self, id: u16, packet: SendPacket) {
        self.push(
            packet.priority,
            Out {
                stream_id: id,
                packet_type: packet.packet_type,
                seq: packet.seq,
                fragment_id: 0,
                total_fragments: 0,
                compression: packet.compression_type,
                payload: packet.data,
            },
        );
    }

    fn push_control(&mut self, id: u16, c: ControlSend) {
        self.push(
            c.priority,
            Out {
                stream_id: id,
                packet_type: c.packet_type,
                seq: c.seq,
                fragment_id: c.fragment_id,
                total_fragments: c.total_fragments,
                compression: 0,
                payload: c.payload,
            },
        );
    }

    fn push_bare(&mut self, id: u16, packet_type: u8, seq: u16, fragment: u8, total: u8) {
        self.push(
            default_packet_priority(packet_type),
            Out {
                stream_id: id,
                packet_type,
                seq,
                fragment_id: fragment,
                total_fragments: total,
                compression: 0,
                payload: Vec::new(),
            },
        );
    }

    /// Drop queued data packets of a stream (its send buffer was wiped, so a
    /// queued copy would resurrect bytes the stream no longer owns).
    fn purge_data(&mut self, id: u16) {
        for queue in &mut self.queues {
            queue.retain(|o| {
                o.stream_id != id
                    || !matches!(o.packet_type, PACKET_STREAM_DATA | PACKET_STREAM_RESEND)
            });
        }
    }

    /// The next packet for a free worker, with its retransmit clock started.
    pub fn next_out(&mut self, now: Instant) -> Option<Out> {
        loop {
            let out = self.queues.iter_mut().find_map(|q| q.pop_front())?;
            if out.stream_id != 0 {
                match self.streams.get_mut(&out.stream_id) {
                    Some(entry) => match out.packet_type {
                        PACKET_STREAM_DATA | PACKET_STREAM_RESEND => {
                            entry.data.on_dispatched(out.seq, now)
                        }
                        t => entry
                            .life
                            .note_control_dispatched(t, out.seq, out.fragment_id, now),
                    },
                    // A data packet for a stream that no longer exists would
                    // only provoke a reset from the server; drop it.
                    None if matches!(
                        out.packet_type,
                        PACKET_STREAM_DATA | PACKET_STREAM_RESEND
                    ) =>
                    {
                        continue
                    }
                    None => {}
                }
            }
            self.ping.note_packet(out.packet_type, false, now);
            tracing::trace!(
                packet_type = out.packet_type,
                stream = out.stream_id,
                seq = out.seq,
                len = out.payload.len(),
                "masterdns send"
            );
            return Some(out);
        }
    }

    // -------------------------------------------------------------- streams

    /// Start a stream towards `target` (the SOCKS address bytes; ignored in
    /// [`Mode::Tcp`]). Returns its id. The setup packets are queued, tracked
    /// until the server acknowledges them.
    pub fn open(&mut self, target: &[u8], ports: StreamPorts, now: Instant) -> Result<u16, Error> {
        if let Some(error) = &self.dead {
            return Err(error.clone());
        }
        let id = self
            .ids
            .allocate(&|id| self.streams.contains_key(&id))
            .ok_or(Error::Busy)?;
        let mut data_cfg = self.tuning.data;
        // Nothing is delivered to the app until the server says it is connected.
        data_cfg.start_paused = true;
        let mut entry = Entry {
            data: DataArq::new(data_cfg),
            life: StreamLifecycle::new(self.tuning.close, self.tuning.control, true, true, now),
            to_user: Some(ports.to_user),
            connect: Some(ports.connect),
            waker: ports.waker,
        };
        let mut setup = Vec::new();
        match self.mode {
            Mode::Socks5 => {
                let chunks: Vec<&[u8]> = target.chunks(self.tuning.chunk.max(1)).collect();
                let total = chunks.len() as u8;
                for (i, part) in chunks.into_iter().enumerate() {
                    setup.push(entry.life.send_control(
                        PACKET_SOCKS5_SYN,
                        0,
                        i as u8,
                        total,
                        part.to_vec(),
                        default_packet_priority(PACKET_SOCKS5_SYN),
                        true,
                        Duration::from_secs(120),
                        now,
                    ));
                }
            }
            Mode::Tcp => setup.push(entry.life.send_control(
                PACKET_STREAM_SYN,
                0,
                0,
                0,
                Vec::new(),
                default_packet_priority(PACKET_STREAM_SYN),
                true,
                Duration::from_secs(120),
                now,
            )),
        }
        self.streams.insert(id, entry);
        for outcome in setup {
            if let Some(packet) = outcome.packet {
                self.push_control(id, packet);
            }
        }
        Ok(id)
    }

    /// Whether the stream can take another chunk from its owner right now.
    pub fn can_send(&self, id: u16) -> Option<bool> {
        self.streams.get(&id).map(|e| e.data.can_send())
    }

    /// Queue one chunk of the owner's bytes. `Ok(false)` means the window is
    /// full: wait for the stream's waker and try again with the same bytes.
    pub fn send(&mut self, id: u16, bytes: &[u8], now: Instant) -> Result<bool, Error> {
        let Some(entry) = self.streams.get_mut(&id) else {
            return Err(Error::Closed);
        };
        if entry.life.is_closed() || entry.life.should_stop_local_read() {
            return Err(Error::Closed);
        }
        if !entry.data.can_send() {
            return Ok(false);
        }
        entry.life.note_activity(now);
        let packet = entry.data.push_data(bytes.to_vec(), now);
        self.push_send(id, packet);
        Ok(true)
    }

    /// The owner finished writing: end the stream gracefully once what is in
    /// flight has been acknowledged.
    pub fn finish(&mut self, id: u16, now: Instant) {
        let Some(entry) = self.streams.get_mut(&id) else {
            return;
        };
        entry.life.note_client_eof(now);
        let view = view(entry);
        let actions = entry.life.close(
            "local app closed the connection",
            CloseOptions {
                send_close_read: true,
                after_drain: true,
                ..CloseOptions::default()
            },
            &view,
            now,
        );
        self.apply(id, actions);
    }

    /// The owner went away without a clean end: reset the stream.
    pub fn abort(&mut self, id: u16, reason: &str, now: Instant) {
        let Some(entry) = self.streams.get_mut(&id) else {
            return;
        };
        let view = view(entry);
        let actions = entry.life.close(
            reason,
            CloseOptions {
                send_rst: true,
                ..CloseOptions::default()
            },
            &view,
            now,
        );
        self.apply(id, actions);
    }

    /// Carry out what a stream's close machine decided, in order.
    fn apply(&mut self, id: u16, actions: Vec<CloseAction>) {
        for action in actions {
            match action {
                CloseAction::Send(control) => self.push_control(id, control),
                CloseAction::SendDataAck(seq) => {
                    self.push_bare(id, PACKET_STREAM_DATA_ACK, seq, 0, 0)
                }
                CloseAction::ClearAllData => {
                    if let Some(e) = self.streams.get_mut(&id) {
                        e.data.clear_all_queues();
                    }
                    self.purge_data(id);
                }
                CloseAction::ClearOutboundData | CloseAction::ClearSendBuffer => {
                    if let Some(e) = self.streams.get_mut(&id) {
                        e.data.clear_outbound_state();
                        e.waker.notify_waiters();
                    }
                    self.purge_data(id);
                }
                CloseAction::ClearRecvBuffer => {
                    if let Some(e) = self.streams.get_mut(&id) {
                        e.data.clear_recv_buffer();
                    }
                }
                CloseAction::SignalWindowNotFull => {
                    if let Some(e) = self.streams.get(&id) {
                        e.waker.notify_waiters();
                    }
                }
                CloseAction::SignalFlushReady => {}
                CloseAction::CloseLocalConn => {
                    if let Some(e) = self.streams.get_mut(&id) {
                        e.to_user = None;
                    }
                }
                CloseAction::Finalized { reason } => {
                    self.purge_data(id);
                    if let Some(mut e) = self.streams.remove(&id) {
                        if let Some(connect) = e.connect.take() {
                            let _ = connect.send(Err(Error::Connect(reason)));
                        }
                        e.waker.notify_waiters();
                    }
                    // Dropping the entry drops its sender: the owner sees EOF.
                    return;
                }
            }
        }
    }

    // ------------------------------------------------------------- replies

    /// Take one packet from the server.
    pub fn handle_reply(&mut self, reply: Reply, now: Instant) {
        let id = reply.stream_id;
        self.handle_reply_inner(reply, now);
        self.settle_eof(id);
    }

    /// Once the server has said it is done sending and everything it sent has
    /// been delivered, end the owner's read side (an EOF, like a TCP FIN). The
    /// stream itself lives on until the owner finishes writing too, so the
    /// close handshake can complete.
    fn settle_eof(&mut self, id: u16) {
        let Some(entry) = self.streams.get_mut(&id) else {
            return;
        };
        if entry.to_user.is_some()
            && matches!(
                entry.life.state(),
                StreamState::HalfClosedRemote | StreamState::Closing
            )
            && entry.data.recv_buffered() == 0
            && entry.data.contiguous_ready() == 0
        {
            entry.to_user = None;
        }
    }

    fn handle_reply_inner(&mut self, reply: Reply, now: Instant) {
        self.ping.note_packet(reply.packet_type, true, now);
        let id = reply.stream_id;
        tracing::trace!(
            packet_type = reply.packet_type,
            stream = id,
            seq = reply.seq,
            len = reply.payload.len(),
            "masterdns reply"
        );
        match reply.packet_type {
            PACKET_PONG => return,
            PACKET_ERROR_DROP | PACKET_SESSION_BUSY => {
                self.dead = Some(Error::SessionLost);
                return;
            }
            _ => {}
        }
        if id == 0 {
            return;
        }
        if !self.streams.contains_key(&id) {
            self.orphan(&reply, now);
            return;
        }

        // Every control packet is acknowledged at once, whatever else happens.
        if let Some(ack) = control_ack_for(reply.packet_type) {
            self.push_bare(id, ack, reply.seq, reply.fragment_id, reply.total_fragments);
        }

        let Some(entry) = self.streams.get_mut(&id) else {
            return;
        };
        entry.life.note_activity(now);

        // Acknowledgements of what we sent.
        if reply.packet_type == PACKET_STREAM_DATA_ACK {
            let outcome = entry.data.receive_ack(reply.seq, now);
            if outcome.freed {
                entry.life.note_drain_progress(now);
            }
            if outcome.window_freed {
                entry.waker.notify_waiters();
            }
            // A drain-first close may now be able to finish.
            let v = view(entry);
            let (actions, _) = entry.life.handle_terminal_retransmit_state(&v, now);
            self.apply(id, actions);
            return;
        }
        if reverse_control_ack_for(reply.packet_type).is_some() {
            let v = view(entry);
            let (_, actions) = entry.life.receive_control_ack(
                reply.packet_type,
                reply.seq,
                reply.fragment_id,
                &v,
                now,
            );
            self.apply(id, actions);
            return;
        }

        match reply.packet_type {
            PACKET_STREAM_DATA | PACKET_STREAM_RESEND => {
                if entry.life.is_closed() {
                    self.reset_orphan(id, now);
                    return;
                }
                let outcome = entry.data.receive_data(reply.seq, reply.payload, now);
                if !outcome.delivered.is_empty() {
                    if let Some(tx) = &entry.to_user {
                        let _ = tx.send(outcome.delivered);
                    }
                }
                for packet in outcome.packets {
                    self.push_send(id, packet);
                }
            }
            PACKET_STREAM_DATA_NACK => {
                if let Some(packet) = entry.data.receive_data_nack(reply.seq, now) {
                    self.push_send(id, packet);
                }
            }
            PACKET_STREAM_CONNECTED | PACKET_SOCKS5_CONNECTED => {
                let delivered = entry.data.set_io_ready(true);
                if !delivered.is_empty() {
                    if let Some(tx) = &entry.to_user {
                        let _ = tx.send(delivered);
                    }
                }
                if let Some(connect) = entry.connect.take() {
                    let _ = connect.send(Ok(()));
                }
            }
            PACKET_STREAM_CONNECT_FAIL => self.fail_connect(
                id,
                Error::Connect("the server could not connect".into()),
                now,
            ),
            t if socks_failure(t).is_some() => {
                self.fail_connect(id, socks_failure(t).expect("checked"), now)
            }
            PACKET_STREAM_CLOSE_READ => {
                let v = view(entry);
                let actions = entry.life.mark_close_read_received(&v);
                self.apply(id, actions);
            }
            PACKET_STREAM_CLOSE_WRITE => {
                let v = view(entry);
                let actions = entry.life.mark_close_write_received(&v, now);
                self.apply(id, actions);
            }
            PACKET_STREAM_RST => {
                let mut actions = entry.life.mark_rst_received();
                let v = view(entry);
                actions.extend(entry.life.close(
                    "the server reset the stream",
                    CloseOptions {
                        force: true,
                        ..CloseOptions::default()
                    },
                    &v,
                    now,
                ));
                self.apply(id, actions);
            }
            _ => {}
        }
    }

    fn fail_connect(&mut self, id: u16, error: Error, now: Instant) {
        let Some(entry) = self.streams.get_mut(&id) else {
            return;
        };
        if let Some(connect) = entry.connect.take() {
            let _ = connect.send(Err(error));
        }
        let v = view(entry);
        let actions = entry.life.close(
            "connect failure",
            CloseOptions {
                force: true,
                ..CloseOptions::default()
            },
            &v,
            now,
        );
        self.apply(id, actions);
    }

    /// A packet for a stream we do not have: tell the server to stop.
    fn orphan(&mut self, reply: &Reply, now: Instant) {
        let id = reply.stream_id;
        match reply.packet_type {
            PACKET_STREAM_DATA | PACKET_STREAM_RESEND => self.reset_orphan(id, now),
            // Acks and nacks need no answer.
            PACKET_STREAM_DATA_ACK | PACKET_STREAM_DATA_NACK => {}
            t if reverse_control_ack_for(t).is_some() => {}
            PACKET_STREAM_RST => self.push_bare(id, PACKET_STREAM_RST_ACK, reply.seq, 0, 0),
            t => match control_ack_for(t) {
                Some(ack) if is_close_stream_packet(t) => self.push_bare(id, ack, 0, 0, 0),
                _ => self.reset_orphan(id, now),
            },
        }
    }

    fn reset_orphan(&mut self, id: u16, now: Instant) {
        if self
            .rst_sent
            .get(&id)
            .is_some_and(|at| now.saturating_duration_since(*at) < RST_REPEAT)
        {
            return;
        }
        self.rst_sent.insert(id, now);
        self.push_bare(id, PACKET_STREAM_RST, 0, 0, 0);
    }

    // --------------------------------------------------------------- clocks

    /// How long a worker may sleep before something is due.
    pub fn next_check(&self, now: Instant) -> Duration {
        let ping = self.ping.poll(now).next_check;
        if self.streams.is_empty() {
            ping
        } else {
            ping.min(TICK_EVERY * 2)
        }
    }

    /// Run the retransmit, close and keep-alive clocks. Cheap to call often.
    pub fn tick(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_tick) < TICK_EVERY {
            return;
        }
        self.last_tick = now;
        self.rst_sent
            .retain(|_, at| now.saturating_duration_since(*at) < Duration::from_secs(30));

        let ids: Vec<u16> = self.streams.keys().copied().collect();
        for id in ids {
            let Some(entry) = self.streams.get_mut(&id) else {
                continue;
            };
            let v = view(entry);
            let (actions, closed) = entry.life.handle_terminal_retransmit_state(&v, now);
            self.apply(id, actions);
            if closed || !self.streams.contains_key(&id) {
                continue;
            }
            let Some(entry) = self.streams.get_mut(&id) else {
                continue;
            };
            match entry.data.poll_retransmits(now) {
                RetransmitOutcome::Resend(packets) => {
                    for packet in packets {
                        self.push_send(id, packet);
                    }
                }
                RetransmitOutcome::CloseTtlExpired | RetransmitOutcome::CloseMaxRetries => {
                    self.abort(id, "data retransmits exhausted", now);
                    continue;
                }
            }
            let Some(entry) = self.streams.get_mut(&id) else {
                continue;
            };
            let v = view(entry);
            let (resends, actions) = entry.life.poll_control_retransmits(&v, now);
            for control in resends {
                self.push_control(id, control);
            }
            self.apply(id, actions);
            let Some(entry) = self.streams.get_mut(&id) else {
                continue;
            };
            let v = view(entry);
            let actions = entry.life.run_final_ack_watchdog(&v, now);
            self.apply(id, actions);
            self.settle_eof(id);
        }

        if self.ping.poll(now).ping_due
            && !self.queues[PACKET_PRIORITY_IDLE]
                .iter()
                .any(|o| o.packet_type == PACKET_PING)
        {
            let sequence = self.ping.next_ping_sequence();
            let nonce: [u8; 4] = rand::random();
            self.push(
                PACKET_PRIORITY_IDLE,
                Out {
                    stream_id: 0,
                    packet_type: PACKET_PING,
                    seq: sequence,
                    fragment_id: 0,
                    total_fragments: 0,
                    compression: 0,
                    payload: ping_payload(nonce).to_vec(),
                },
            );
        }
    }
}

#[cfg(test)]
mod tests;
