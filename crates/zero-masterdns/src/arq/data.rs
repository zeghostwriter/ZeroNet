//! The reliable data path of one stream, as a pure (sans-IO) state machine.
//!
//! This is the heart of the ARQ overlay: it turns a lossy, reorder-prone DNS
//! tunnel into an ordered, retransmitted byte stream. It owns the two buffers
//! and the sequence counters that make that work, and nothing else — no socket,
//! no timer, no lock. Every decision that depends on the clock takes an
//! explicit `now: Instant`, and every decision that produces traffic returns a
//! list of [`SendPacket`]s for the caller to enqueue. That is what "sans-IO"
//! means here: the logic is a function of its inputs, so it can be driven step
//! by step in a test and matched against the Go server's behaviour without a
//! network.
//!
//! # The two sides of a stream
//!
//! * **Send side.** The local app produces bytes; [`DataArq::push_data`] gives
//!   each chunk the next send sequence number, parks it in the send buffer, and
//!   hands back the `STREAM_DATA` packet to transmit. The chunk stays parked
//!   until the peer acknowledges it ([`DataArq::receive_ack`]); if its
//!   retransmit timeout passes first, [`DataArq::poll_retransmits`] resends it
//!   with a grown timeout.
//! * **Receive side.** Inbound `STREAM_DATA` goes through
//!   [`DataArq::receive_data`], which buckets it (old / in-window / beyond the
//!   window), buffers in-window data, always answers with a `STREAM_DATA_ACK`,
//!   emits `STREAM_DATA_NACK`s for gaps it is still waiting on, and delivers the
//!   contiguous run that is now ready in order.
//!
//! # Invariants worth knowing
//!
//! * The send buffer is bounded by `limit` (80% of the window): a caller checks
//!   [`DataArq::can_send`] before producing more, which is the backpressure that
//!   keeps the window from overflowing.
//! * `rcv_nxt` only advances when data is actually delivered, and delivery only
//!   happens while the stream is "io ready" (a SOCKS stream starts paused until
//!   its upstream connects). ACKs, by contrast, go out for every in-window or
//!   already-delivered packet regardless of readiness, so the sender can always
//!   release what the receiver already holds.
//! * The retransmit timeout is adaptive (see [`super::rto`]) and is only sampled
//!   from a packet that was sent exactly once — a resent packet is marked
//!   ineligible so a late ACK cannot be mistaken for a fast round trip.
//!
//! The close handshake (CLOSE_WRITE / CLOSE_READ / RST and the terminal drain)
//! and the control-plane reliability live above this core; this module is only
//! the data path, which is the part whose arithmetic has to agree with the
//! server byte for byte.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use zero_protocol::masterdns::enums::{
    default_packet_priority, PACKET_STREAM_DATA, PACKET_STREAM_DATA_ACK, PACKET_STREAM_DATA_NACK,
    PACKET_STREAM_RESEND,
};

use super::rto::{clamp, grow, AdaptiveRto, DATA_RETRANSMIT_GROWTH};
use super::seq::{classify, nack_distance, seq_behind, Admit};

/// Tunables for one stream's data path. Field units are deliberately explicit
/// (`Duration`, counts) rather than the Go side's raw seconds/floats; the
/// constructor applies the same floors the Go `NewARQ` does, so a zeroed
/// `Config` lands on the same safe values.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Target send window. Floored to 300; the receive window is twice this and
    /// the send-side backpressure `limit` is 80% of it.
    pub window_size: usize,
    /// Starting retransmit timeout, before any round-trip sample refines it.
    pub initial_rto: Duration,
    /// Ceiling the adaptive timeout and its growth are clamped to.
    pub max_rto: Duration,
    /// How long a packet may sit unacknowledged before the stream is torn down,
    /// once it has also run out of retries. Floored to 120s.
    pub data_packet_ttl: Duration,
    /// Retransmit attempts a packet gets before the TTL can end the stream.
    /// Floored to 60.
    pub max_data_retries: u32,
    /// How many sequence numbers ahead of `rcv_nxt` the receiver will actively
    /// NACK. Zero disables gap NACKs entirely.
    pub data_nack_max_gap: usize,
    /// Grace period after a gap is first noticed before its first NACK goes out.
    pub data_nack_initial_delay: Duration,
    /// Minimum spacing between repeat NACKs for the same missing sequence.
    /// Floored to 100ms.
    pub data_nack_repeat_interval: Duration,
    /// Compression codec id stamped on outgoing data packets.
    pub compression_type: u8,
    /// Start with delivery paused (a SOCKS stream waits for its upstream before
    /// it will write received bytes to the local socket).
    pub start_paused: bool,
}

impl Config {
    /// The client-side defaults the Go config fills in when the TOML leaves the
    /// ARQ fields unset: a 600-packet window, 1s/5s initial/max RTO, a 2400s
    /// data TTL with 1200 retries, and a 16-wide NACK gap that waits 100ms then
    /// repeats at most once a second.
    pub fn client_defaults() -> Self {
        Config {
            window_size: 600,
            initial_rto: Duration::from_secs(1),
            max_rto: Duration::from_secs(5),
            data_packet_ttl: Duration::from_secs(2400),
            max_data_retries: 1200,
            data_nack_max_gap: 16,
            data_nack_initial_delay: Duration::from_millis(100),
            data_nack_repeat_interval: Duration::from_secs(1),
            compression_type: 0,
            start_paused: false,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::client_defaults()
    }
}

/// A packet the state machine wants put on the wire. The caller maps this onto
/// its real send queue (the MLQ); the fragment id and total-fragments fields the
/// Go enqueuer also takes are always zero on the data path, so they are omitted
/// here. `data` is empty and `compression_type` is 0 for the pure control acks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPacket {
    pub priority: usize,
    pub packet_type: u8,
    pub seq: u16,
    pub compression_type: u8,
    pub data: Vec<u8>,
}

impl SendPacket {
    fn ack(seq: u16) -> Self {
        SendPacket {
            priority: default_packet_priority(PACKET_STREAM_DATA_ACK),
            packet_type: PACKET_STREAM_DATA_ACK,
            seq,
            compression_type: 0,
            data: Vec::new(),
        }
    }

    fn nack(seq: u16) -> Self {
        SendPacket {
            priority: default_packet_priority(PACKET_STREAM_DATA_NACK),
            packet_type: PACKET_STREAM_DATA_NACK,
            seq,
            compression_type: 0,
            data: Vec::new(),
        }
    }

    fn data(seq: u16, compression_type: u8, data: Vec<u8>) -> Self {
        SendPacket {
            priority: default_packet_priority(PACKET_STREAM_DATA),
            packet_type: PACKET_STREAM_DATA,
            seq,
            compression_type,
            data,
        }
    }

    fn resend(seq: u16, compression_type: u8, data: Vec<u8>) -> Self {
        SendPacket {
            priority: default_packet_priority(PACKET_STREAM_RESEND),
            packet_type: PACKET_STREAM_RESEND,
            seq,
            compression_type,
            data,
        }
    }
}

/// What [`DataArq::receive_data`] decided about one inbound data packet.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReceiveOutcome {
    /// Packets to enqueue: the `STREAM_DATA_ACK`, followed by any gap NACKs.
    pub packets: Vec<SendPacket>,
    /// Contiguous bytes now ready to write to the local connection, in order.
    /// Empty while the stream is paused, even though the data is buffered.
    pub delivered: Vec<u8>,
    /// Sequences whose already-queued NACK should be cancelled because the data
    /// just arrived. The caller drops these from its send queue if present.
    pub cancel_queued_nacks: Vec<u16>,
}

/// What [`DataArq::receive_ack`] did with one inbound ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckOutcome {
    /// The sequence was outstanding and is now released from the send buffer.
    pub freed: bool,
    /// The send buffer dropped below `limit`, so a blocked sender may resume.
    pub window_freed: bool,
}

/// The sequences that were still live when the send side was wiped
/// ([`DataArq::clear_outbound_state`]). The owning stream uses these to evict
/// any copies still sitting in its outbound send queue: `send_seqs` were parked
/// unacknowledged in the send buffer, `nack_seqs` had gap-NACK bookkeeping.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ClearedOutbound {
    pub send_seqs: Vec<u16>,
    pub nack_seqs: Vec<u16>,
}

/// The verdict from a retransmit poll.
#[derive(Debug, PartialEq, Eq)]
pub enum RetransmitOutcome {
    /// Zero or more packets to resend. Empty means nothing was due yet.
    Resend(Vec<SendPacket>),
    /// A packet outlived its TTL; the stream must be reset.
    CloseTtlExpired,
    /// A packet exhausted its retries past the TTL; the stream must be reset.
    CloseMaxRetries,
}

/// One parked, sent-but-unacknowledged data chunk.
///
/// `last_sent_at` is `None` until the packet is actually dispatched (the send
/// queue is asynchronous, so a chunk can be buffered a moment before it leaves);
/// an undispatched chunk is never a retransmit candidate. `sample_eligible`
/// starts true and is cleared the first time the chunk is resent, so only a
/// cleanly round-tripped packet feeds the RTO estimate.
#[derive(Debug)]
struct DataItem {
    data: Vec<u8>,
    created_at: Instant,
    last_sent_at: Option<Instant>,
    dispatched: bool,
    last_nack_sent_at: Option<Instant>,
    retries: u32,
    current_rto_ns: i64,
    sample_eligible: bool,
    compression_type: u8,
}

/// The reliable data path for a single stream. Create it with [`DataArq::new`],
/// then drive it with the `push_*`/`receive_*`/`poll_*` methods, feeding each a
/// timestamp. It holds no lock of its own: the caller serialises access (in the
/// Go design the surrounding stream already holds its lock when it calls in).
pub struct DataArq {
    // Send side.
    snd_nxt: u16,
    snd_buf: HashMap<u16, DataItem>,
    data_adaptive_rto: AdaptiveRto,

    // Receive side.
    rcv_nxt: u16,
    rcv_buf: HashMap<u16, Vec<u8>>,
    io_ready: bool,

    // While the stream is draining toward a deferred terminal packet, every
    // retransmit timeout is capped so a stuck window cannot hold the close open
    // for the full (possibly multi-second) RTO. Set by the owning stream.
    draining: bool,

    // Gap-NACK bookkeeping, keyed by the missing sequence.
    first_data_nack_seen: HashMap<u16, Instant>,
    last_data_nack_sent: HashMap<u16, Instant>,

    // Derived, immutable tuning.
    window_size: usize,
    receive_window_size: usize,
    limit: usize,
    initial_rto_ns: i64,
    max_rto_ns: i64,
    data_packet_ttl: Duration,
    max_data_retries: u32,
    data_nack_max_gap: usize,
    data_nack_initial_delay: Duration,
    data_nack_repeat_interval: Duration,
    compression_type: u8,
}

/// 50ms, the floor the Go side clamps every RTO value to, in nanoseconds.
const RTO_FLOOR_NS: i64 = 50_000_000;

impl DataArq {
    /// Build a stream data path from `cfg`, applying the same floors the Go
    /// `NewARQ` does: the window is at least 300, the receive window is twice
    /// the window, the backpressure limit is 80% of the window (at least 50),
    /// the data TTL is at least 120s with at least 60 retries, and every RTO is
    /// at least 50ms with the initial value never above the max.
    pub fn new(cfg: Config) -> Self {
        let window_size = cfg.window_size.max(300);
        let receive_window_size = window_size.saturating_mul(2);
        let limit = ((window_size as f64 * 0.8) as usize).max(50);

        let max_rto_ns = (cfg.max_rto.as_nanos() as i64).max(RTO_FLOOR_NS);
        let initial_rto_ns = (cfg.initial_rto.as_nanos() as i64)
            .max(RTO_FLOOR_NS)
            .min(max_rto_ns);

        let data_packet_ttl = cfg.data_packet_ttl.max(Duration::from_secs(120));
        let max_data_retries = cfg.max_data_retries.max(60);
        let data_nack_initial_delay = cfg.data_nack_initial_delay;
        let data_nack_repeat_interval = cfg
            .data_nack_repeat_interval
            .max(Duration::from_millis(100));

        DataArq {
            snd_nxt: 0,
            snd_buf: HashMap::new(),
            data_adaptive_rto: AdaptiveRto::new(initial_rto_ns),

            rcv_nxt: 0,
            rcv_buf: HashMap::new(),
            io_ready: !cfg.start_paused,
            draining: false,

            first_data_nack_seen: HashMap::new(),
            last_data_nack_sent: HashMap::new(),

            window_size,
            receive_window_size,
            limit,
            initial_rto_ns,
            max_rto_ns,
            data_packet_ttl,
            max_data_retries,
            data_nack_max_gap: cfg.data_nack_max_gap,
            data_nack_initial_delay,
            data_nack_repeat_interval,
            compression_type: cfg.compression_type,
        }
    }

    /// Whether the send buffer has room for another chunk. A caller reads the
    /// local socket only while this holds, which is the window backpressure.
    pub fn can_send(&self) -> bool {
        self.snd_buf.len() < self.limit
    }

    /// How many chunks are sent but not yet acknowledged.
    pub fn outstanding(&self) -> usize {
        self.snd_buf.len()
    }

    /// How many out-of-order chunks are buffered on the receive side (including
    /// any gap holes not yet filled). The close machine uses this to tell
    /// whether the receive side has fully drained.
    pub fn recv_buffered(&self) -> usize {
        self.rcv_buf.len()
    }

    /// How many chunks starting at `rcv_nxt` are contiguously ready to deliver.
    /// Mirrors Go `contiguousReadyLocked`.
    pub fn contiguous_ready(&self) -> usize {
        let mut ready = 0;
        let mut sn = self.rcv_nxt;
        while self.rcv_buf.contains_key(&sn) {
            ready += 1;
            sn = sn.wrapping_add(1);
        }
        ready
    }

    /// Drop the receive buffer wholesale (a broken local writer or a sent
    /// CLOSE_WRITE means nothing more will ever be written locally). Mirrors the
    /// `a.rcvBuf = make(...)` in Go `MarkCloseWriteSent`/`markLocalWriterBroken`.
    pub fn clear_recv_buffer(&mut self) {
        self.rcv_buf.clear();
    }

    /// Wipe both buffers and the gap-NACK bookkeeping (RST / abort semantics).
    /// Mirrors Go `clearAllQueues` without the control table, which the owning
    /// stream clears separately.
    pub fn clear_all_queues(&mut self) {
        self.snd_buf.clear();
        self.rcv_buf.clear();
        self.first_data_nack_seen.clear();
        self.last_data_nack_sent.clear();
    }

    /// Wipe the send side (but keep the receive buffer) and report the sequences
    /// that were in flight plus the sequences we had NACK bookkeeping for, so
    /// the caller can evict any copies still queued in the send queue. Mirrors
    /// Go `clearOutboundStateLocked`.
    pub fn clear_outbound_state(&mut self) -> ClearedOutbound {
        let send_seqs: Vec<u16> = self.snd_buf.keys().copied().collect();
        let nack_seqs: Vec<u16> = self.last_data_nack_sent.keys().copied().collect();
        self.snd_buf.clear();
        self.first_data_nack_seen.clear();
        self.last_data_nack_sent.clear();
        ClearedOutbound {
            send_seqs,
            nack_seqs,
        }
    }

    /// The next sequence number that will be assigned to outgoing data.
    pub fn snd_nxt(&self) -> u16 {
        self.snd_nxt
    }

    /// The next sequence number the receiver is waiting to deliver.
    pub fn rcv_nxt(&self) -> u16 {
        self.rcv_nxt
    }

    /// Enter or leave drain mode. In drain mode [`DataArq::poll_retransmits`]
    /// caps each effective retransmit timeout (and the grown value) at
    /// [`DataArq::drain_rto_cap_ns`], so the terminal drain cannot stall on a
    /// long RTO. Mirrors the `draining` branch of Go `checkRetransmits`.
    pub fn set_draining(&mut self, draining: bool) {
        self.draining = draining;
    }

    /// The retransmit-timeout ceiling applied while draining: 2s clamped into
    /// the configured `[initial_rto, max_rto]`. Mirrors Go
    /// `clampDuration(2*time.Second, a.rto, a.maxRTO)`.
    fn drain_rto_cap_ns(&self) -> i64 {
        clamp(2_000_000_000, self.initial_rto_ns, self.max_rto_ns)
    }

    /// The adaptive data-RTO base right now, floored to the configured initial
    /// RTO and capped at the max. Mirrors Go `currentDataBaseRTO`.
    fn current_data_base_rto_ns(&self) -> i64 {
        let base = self.data_adaptive_rto.current_base;
        if base <= 0 {
            self.initial_rto_ns
        } else {
            clamp(base, self.initial_rto_ns, self.max_rto_ns)
        }
    }

    /// Queue a chunk of application data for sending: assign it the next
    /// sequence number, park it unacknowledged, and return the `STREAM_DATA`
    /// packet to transmit. The chunk is not yet counted as "in flight" for the
    /// retransmit timer — call [`DataArq::on_dispatched`] once it actually
    /// leaves (or [`DataArq::on_dispatch_failed`] if the queue rejected it).
    pub fn push_data(&mut self, data: Vec<u8>, now: Instant) -> SendPacket {
        let seq = self.snd_nxt;
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        let current_rto_ns = self.current_data_base_rto_ns();
        let packet = SendPacket::data(seq, self.compression_type, data.clone());
        self.snd_buf.insert(
            seq,
            DataItem {
                data,
                created_at: now,
                last_sent_at: None,
                dispatched: false,
                last_nack_sent_at: None,
                retries: 0,
                current_rto_ns,
                sample_eligible: true,
                compression_type: self.compression_type,
            },
        );
        packet
    }

    /// Mark a `STREAM_DATA`/`STREAM_RESEND` packet as actually sent, starting
    /// its retransmit clock. Mirrors Go `NoteTXPacketDequeued`.
    pub fn on_dispatched(&mut self, seq: u16, now: Instant) {
        if let Some(item) = self.snd_buf.get_mut(&seq) {
            item.last_sent_at = Some(now);
            item.dispatched = true;
        }
    }

    /// Record that the send queue could not accept a chunk: treat it as already
    /// overdue so the next poll resends it immediately. Mirrors the Go
    /// `PushTXPacket` failure path (`Dispatched=true, LastSentAt=now-RTO`).
    pub fn on_dispatch_failed(&mut self, seq: u16, now: Instant) {
        let rto = {
            let item = match self.snd_buf.get(&seq) {
                Some(item) => item,
                None => return,
            };
            Duration::from_nanos(item.current_rto_ns.max(0) as u64)
        };
        if let Some(item) = self.snd_buf.get_mut(&seq) {
            item.dispatched = true;
            item.last_sent_at = Some(now.checked_sub(rto).unwrap_or(now));
        }
    }

    /// Release the chunk `seq` acknowledges, folding its round trip into the RTO
    /// estimate when the chunk was sent exactly once. Mirrors Go `ReceiveAck`.
    pub fn receive_ack(&mut self, seq: u16, now: Instant) -> AckOutcome {
        let sample_ns = match self.snd_buf.get(&seq) {
            Some(item) if item.sample_eligible && item.dispatched => item
                .last_sent_at
                .map(|sent| now.saturating_duration_since(sent).as_nanos() as i64),
            _ => None,
        };

        if self.snd_buf.remove(&seq).is_none() {
            return AckOutcome {
                freed: false,
                window_freed: false,
            };
        }

        if let Some(sample) = sample_ns {
            self.data_adaptive_rto =
                self.data_adaptive_rto
                    .update(sample, self.initial_rto_ns, self.max_rto_ns);
        }

        AckOutcome {
            freed: true,
            window_freed: self.snd_buf.len() < self.limit,
        }
    }

    /// Resend the chunk a peer NACK asks for, rate-limited to one resend per
    /// repeat interval. Returns the `STREAM_RESEND` packet, or `None` if the
    /// chunk is unknown or was resent too recently. Mirrors Go `HandleDataNack`.
    pub fn receive_data_nack(&mut self, seq: u16, now: Instant) -> Option<SendPacket> {
        let item = self.snd_buf.get_mut(&seq)?;
        if let Some(prev) = item.last_nack_sent_at {
            if now.saturating_duration_since(prev) < self.data_nack_repeat_interval {
                return None;
            }
        }
        item.last_nack_sent_at = Some(now);
        item.sample_eligible = false;
        Some(SendPacket::resend(
            seq,
            item.compression_type,
            item.data.clone(),
        ))
    }

    /// Take one inbound `STREAM_DATA` packet: bucket it, buffer it if it belongs
    /// in the window, acknowledge it, raise NACKs for the gap ahead, and deliver
    /// whatever contiguous run is now ready. Mirrors Go `processReceivedData`.
    pub fn receive_data(&mut self, seq: u16, data: Vec<u8>, now: Instant) -> ReceiveOutcome {
        let mut out = ReceiveOutcome::default();

        match classify(seq, self.rcv_nxt, self.receive_window_size) {
            // Already delivered: re-ack so a lost ack still gets answered, but
            // do not buffer or deliver.
            Admit::BehindReAck => {
                out.packets.push(SendPacket::ack(seq));
                return out;
            }
            // Too far ahead: drop silently to push back on the sender.
            Admit::BeyondWindow => return out,
            Admit::InWindow => {}
        }

        let exists = self.rcv_buf.contains_key(&seq);
        // Buffer at capacity and this is not the leading edge: drop without an
        // ack, matching the Go guard.
        if !exists && self.rcv_buf.len() >= self.receive_window_size && seq != self.rcv_nxt {
            return out;
        }

        if !exists {
            self.rcv_buf.insert(seq, data);
        }

        // Every in-window packet is acknowledged, even a duplicate, so the
        // sender can release it.
        out.packets.push(SendPacket::ack(seq));

        if !exists {
            // Newly buffered: a NACK we may have queued for it is now moot.
            self.clear_sent_data_nack(seq);
            out.cancel_queued_nacks.push(seq);
        }

        for missing in self.gap_nacks(seq, now) {
            out.packets.push(SendPacket::nack(missing));
        }

        if self.io_ready {
            out.delivered = self.drain_contiguous();
        }

        out
    }

    /// Pause or resume delivery. Resuming flushes whatever contiguous run has
    /// piled up while paused and returns it; pausing returns nothing. The ack
    /// path is unaffected either way.
    pub fn set_io_ready(&mut self, ready: bool) -> Vec<u8> {
        self.io_ready = ready;
        if ready {
            self.drain_contiguous()
        } else {
            Vec::new()
        }
    }

    /// Pop the contiguous run starting at `rcv_nxt`, advancing it, and return
    /// the bytes concatenated in order (the Go write loop coalesces the same
    /// run into one write).
    fn drain_contiguous(&mut self) -> Vec<u8> {
        let mut delivered = Vec::new();
        while let Some(chunk) = self.rcv_buf.remove(&self.rcv_nxt) {
            delivered.extend_from_slice(&chunk);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        }
        delivered
    }

    /// Walk the send buffer and resend whatever has gone past its retransmit
    /// timeout, growing each resent packet's timeout. Reports a terminal verdict
    /// instead if any packet has outlived its TTL or exhausted its retries.
    /// Mirrors Go `checkRetransmits` (minus the drain-mode cap, which belongs to
    /// the close handshake above this core).
    pub fn poll_retransmits(&mut self, now: Instant) -> RetransmitOutcome {
        let drain_cap = if self.draining {
            Some(self.drain_rto_cap_ns())
        } else {
            None
        };
        let mut jobs: Vec<u16> = Vec::new();
        for (&seq, item) in self.snd_buf.iter() {
            if now.saturating_duration_since(item.created_at) >= self.data_packet_ttl
                && item.retries >= self.max_data_retries
            {
                return RetransmitOutcome::CloseMaxRetries;
            }
            // While draining, a timeout longer than the cap is treated as if it
            // were the cap, so an overdue packet still fires promptly.
            let effective_rto = match drain_cap {
                Some(cap) if item.current_rto_ns > cap => cap,
                _ => item.current_rto_ns,
            };
            let due = match item.last_sent_at {
                Some(sent) if item.dispatched => {
                    (now.saturating_duration_since(sent).as_nanos() as i64) >= effective_rto
                }
                _ => false,
            };
            if due {
                jobs.push(seq);
            }
        }

        let kinds = self.retransmit_priority_kinds(&jobs);
        let data_floor = self.current_data_base_rto_ns();
        // The grown timeout is clamped to the same drain cap while draining.
        let grow_max = match drain_cap {
            Some(cap) if self.max_rto_ns > cap => cap,
            _ => self.max_rto_ns,
        };
        let mut packets = Vec::with_capacity(jobs.len());

        for (i, &seq) in jobs.iter().enumerate() {
            let item = match self.snd_buf.get_mut(&seq) {
                Some(item) => item,
                None => continue,
            };
            if kinds[i] {
                packets.push(SendPacket::resend(
                    seq,
                    item.compression_type,
                    item.data.clone(),
                ));
            } else {
                packets.push(SendPacket::data(
                    seq,
                    item.compression_type,
                    item.data.clone(),
                ));
            }
            item.last_sent_at = Some(now);
            item.dispatched = false;
            item.retries += 1;
            item.sample_eligible = false;
            item.current_rto_ns = grow(
                item.current_rto_ns,
                DATA_RETRANSMIT_GROWTH,
                data_floor,
                grow_max,
            );
        }

        RetransmitOutcome::Resend(packets)
    }

    /// Decide which of the due retransmits ride at the higher `RESEND` priority
    /// rather than ordinary `DATA`. A lone retransmit always does; otherwise the
    /// oldest `window/10` (capped to `[1, 64]`) by distance behind `snd_nxt` are
    /// promoted, so recovery favours the packets holding up the receiver's
    /// window. Mirrors Go `retransmitPriorityKinds`.
    fn retransmit_priority_kinds(&self, jobs: &[u16]) -> Vec<bool> {
        let n = jobs.len();
        let mut kinds = vec![false; n];
        if n == 0 {
            return kinds;
        }
        if n == 1 {
            kinds[0] = true;
            return kinds;
        }

        let front_budget = (self.window_size / 10).clamp(1, 64).min(n);

        // Distance behind snd_nxt is a bijection with the sequence here (all
        // jobs are distinct keys), so ordering by distance alone is total; the
        // sequence tiebreak just mirrors the Go comparator exactly.
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by(|&a, &b| {
            let da = self.snd_nxt.wrapping_sub(jobs[a]);
            let db = self.snd_nxt.wrapping_sub(jobs[b]);
            db.cmp(&da).then_with(|| jobs[a].cmp(&jobs[b]))
        });
        for &idx in order.iter().take(front_budget) {
            kinds[idx] = true;
        }
        kinds
    }

    /// Which sequences ahead of `rcv_nxt` to NACK on receiving `sn`, applying
    /// the timing gates. Mirrors Go `maybeSendDataNacks` + `shouldSendDataNack`.
    fn gap_nacks(&mut self, sn: u16, now: Instant) -> Vec<u16> {
        if self.data_nack_max_gap == 0 {
            return Vec::new();
        }
        if nack_distance(sn, self.rcv_nxt).is_none() {
            return Vec::new();
        }

        let rcv_nxt = self.rcv_nxt;
        self.prune_data_nack_state(rcv_nxt);

        let candidates = self.gap_candidates(sn, rcv_nxt);

        let mut send = Vec::new();
        for missing in candidates {
            if self.should_send_data_nack(missing, now) {
                self.last_data_nack_sent.insert(missing, now);
                send.push(missing);
            }
        }
        send
    }

    /// The missing sequences in `[rcv_nxt, sn)`. For a gap within `max_gap` this
    /// is every hole; for a larger gap it is a ~5% sample from the front plus the
    /// deepest hole before the gap frontier, so a huge gap does not emit a flood
    /// of NACKs. Mirrors the two branches of Go `maybeSendDataNacks`.
    fn gap_candidates(&self, sn: u16, rcv_nxt: u16) -> Vec<u16> {
        let window_span = self.data_nack_max_gap as u16;
        let diff = sn.wrapping_sub(rcv_nxt);
        let mut missing = Vec::new();

        if diff <= window_span {
            let mut m = rcv_nxt;
            while m != sn {
                if !self.rcv_buf.contains_key(&m) {
                    missing.push(m);
                }
                m = m.wrapping_add(1);
            }
            return missing;
        }

        // Sampled: at least 1, about 5% of the configured gap (ceil(gap/20)).
        let sample_count = self.data_nack_max_gap.div_ceil(20).max(1);
        let mut seen = std::collections::HashSet::new();
        let mut m = rcv_nxt;
        let mut added = 0;
        while m != sn && added < sample_count {
            if !self.rcv_buf.contains_key(&m) {
                missing.push(m);
                seen.insert(m);
                added += 1;
            }
            m = m.wrapping_add(1);
        }

        let frontier = (rcv_nxt as u32 + window_span as u32 - 1) as u16;
        let mut candidate = frontier;
        loop {
            if !self.rcv_buf.contains_key(&candidate) {
                if !seen.contains(&candidate) {
                    missing.push(candidate);
                }
                break;
            }
            if candidate == rcv_nxt {
                break;
            }
            candidate = candidate.wrapping_sub(1);
        }
        missing
    }

    /// The timing gate for one missing sequence: suppress its first NACK until
    /// the initial delay passes, then allow a repeat only once per repeat
    /// interval. Records the first-seen time as a side effect, like the Go code.
    fn should_send_data_nack(&mut self, sn: u16, now: Instant) -> bool {
        match self.first_data_nack_seen.get(&sn) {
            None => {
                self.first_data_nack_seen.insert(sn, now);
                return self.data_nack_initial_delay.is_zero();
            }
            Some(&first_seen) => {
                if !self.data_nack_initial_delay.is_zero()
                    && now.saturating_duration_since(first_seen) < self.data_nack_initial_delay
                {
                    return false;
                }
            }
        }
        match self.last_data_nack_sent.get(&sn) {
            None => true,
            Some(&last_sent) => {
                now.saturating_duration_since(last_sent) >= self.data_nack_repeat_interval
            }
        }
    }

    /// Forget NACK bookkeeping for a sequence that has arrived or been delivered.
    fn clear_sent_data_nack(&mut self, sn: u16) {
        self.first_data_nack_seen.remove(&sn);
        self.last_data_nack_sent.remove(&sn);
    }

    /// Drop NACK bookkeeping for any sequence now behind `rcv_nxt`. Mirrors Go
    /// `pruneDataNackStateLocked`.
    fn prune_data_nack_state(&mut self, rcv_nxt: u16) {
        self.first_data_nack_seen
            .retain(|&sn, _| !seq_behind(rcv_nxt, sn));
        self.last_data_nack_sent
            .retain(|&sn, _| !seq_behind(rcv_nxt, sn));
    }
}

#[cfg(test)]
mod tests;
