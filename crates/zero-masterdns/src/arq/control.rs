//! The control-plane reliability layer of one stream, as a pure (sans-IO) state
//! machine.
//!
//! The data path ([`super::data`]) carries application bytes and acknowledges
//! them with its own sequence window. The *control* plane carries the handshake
//! and teardown packets — `STREAM_SYN`, `CLOSE_READ`, `CLOSE_WRITE`, `RST`, the
//! SOCKS result codes, the tunneled DNS queries — which are not part of that
//! window but still must not be lost on a lossy DNS tunnel. This module is the
//! small, self-contained engine that tracks each such packet until its matching
//! ACK comes back, resends it on an adaptive timeout, and gives up (closing the
//! stream) once it has exhausted its retries or outlived its TTL.
//!
//! # Why it is separate from the data path
//!
//! A control packet is tracked by a different key than a data chunk. Data is
//! keyed by its 16-bit sequence alone; a control packet is keyed by the triple
//! `(packet_type, sequence, fragment_id)` packed into a `u32`, because several
//! unrelated control packets can be in flight at once and a single logical
//! control message may be split into fragments. The ACK that releases a control
//! packet is a *different packet type* (`CLOSE_READ` is released by
//! `CLOSE_READ_ACK`), looked up through the fixed table in
//! [`zero_protocol::masterdns::enums`]. So the bookkeeping, the timers, and the
//! match logic are genuinely different from the data path and live here.
//!
//! # Sans-IO contract
//!
//! Like the data path, this holds no socket, timer, or lock. Every method that
//! depends on the clock takes an explicit `now: Instant`; every method that
//! wants to put bytes on the wire returns a [`ControlSend`] (or a list of them)
//! for the caller to enqueue. The caller then reports back when the packet
//! actually left the send queue ([`ControlReliability::on_dispatched`]) or
//! could not be queued ([`ControlReliability::on_dispatch_failed`]), exactly as
//! the Go server threads its `PushTXPacket` result and `NoteTXPacketDequeued`
//! callback through the same item. This is what lets the whole layer be driven
//! step by step in a test and matched against the Go behaviour without a
//! network.
//!
//! # The one subtlety a newcomer should know
//!
//! The close/reset packets ([`is_close_stream_packet`]) are matched
//! *sequence-agnostically*: when a `CLOSE_READ_ACK` arrives, any tracked
//! `CLOSE_READ` of any sequence is considered acknowledged and every tracked
//! copy is dropped. That is deliberate — a retransmit may have bumped the
//! sequence the peer echoes back, and we must not keep resending a close just
//! because the ack named an older sequence. Ordinary control packets
//! (`STREAM_SYN`, the SOCKS results) are matched by the exact `(type, seq,
//! frag)` key instead.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use zero_protocol::masterdns::enums::{
    control_ack_for, is_close_stream_packet, is_setup_control_packet, normalize_packet_priority,
    reverse_control_ack_for,
};

use super::rto::{clamp, AdaptiveRto, CONTROL_RETRANSMIT_GROWTH, SETUP_CONTROL_GROWTH};

/// Floor every configured RTO is clamped up to, matching Go `maxF(0.05, …)`
/// (50ms expressed in whole nanoseconds).
const RTO_FLOOR_NS: i64 = 50_000_000;

/// The tighter initial/floor RTO a *setup* control packet (`STREAM_SYN`,
/// `SOCKS5_SYN`) uses: it opens the stream, so a lost one should be retried
/// quickly rather than after the full configured control RTO. Matches the
/// `350 * time.Millisecond` alt-RTO in Go.
const SETUP_RTO_CAP_NS: i64 = 350_000_000;

/// Setup control packets get far more generous retry/TTL limits than ordinary
/// control packets, since the whole stream is blocked until they land. Matches
/// Go `checkControlRetransmits` (`maxRetries` floored to 120, `packetTTL`
/// floored to 300s).
const SETUP_MIN_RETRIES: u32 = 120;
const SETUP_MIN_PACKET_TTL: Duration = Duration::from_secs(300);

/// Tunables for one stream's control plane. As with the data [`Config`], the
/// units are explicit `Duration`/counts and the constructor applies the same
/// floors Go `NewARQ` does, so a zeroed config lands on safe values.
///
/// [`Config`]: super::data::Config
#[derive(Debug, Clone, Copy)]
pub struct ControlConfig {
    /// Starting retransmit timeout for a control packet, before any round-trip
    /// sample refines it. Floored to 50ms and capped at `control_max_rto`.
    pub control_rto: Duration,
    /// Ceiling the adaptive control timeout and its growth are clamped to.
    /// Floored to 50ms.
    pub control_max_rto: Duration,
    /// Retransmit attempts an ordinary control packet gets before its TTL ends
    /// the stream. Floored to 5. Setup packets override this up to 120.
    pub control_max_retries: u32,
    /// How long a control packet may sit unacknowledged before the stream is
    /// torn down. Floored to 120s. Setup packets override this up to 300s.
    pub control_packet_ttl: Duration,
}

impl ControlConfig {
    /// The client-side defaults the Go config fills in when the TOML leaves the
    /// control fields unset: a 0.5s/3s initial/max RTO, 400 retries, and a
    /// 1200s packet TTL.
    pub fn client_defaults() -> Self {
        ControlConfig {
            control_rto: Duration::from_millis(500),
            control_max_rto: Duration::from_secs(3),
            control_max_retries: 400,
            control_packet_ttl: Duration::from_secs(1200),
        }
    }
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self::client_defaults()
    }
}

/// A control packet the state machine wants put on the wire. Unlike the data
/// [`SendPacket`], it carries the fragment fields and an explicit TTL, because
/// control messages can be fragmented and some (the MTU-probe family) ride a
/// per-packet TTL rather than the stream-wide one.
///
/// [`SendPacket`]: super::data::SendPacket
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlSend {
    pub priority: usize,
    pub packet_type: u8,
    pub seq: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
    /// `Duration::ZERO` means "no explicit TTL": the packet uses the stream's
    /// control retry/TTL limits instead. A non-zero TTL expires the packet by
    /// wall-clock age alone.
    pub ttl: Duration,
    pub payload: Vec<u8>,
}

/// The verdict from [`ControlReliability::send_control`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlSendOutcome {
    /// The packet to enqueue, or `None` when nothing should go out: the type
    /// was requested tracked but has no known ACK mapping (Go drops it and
    /// reports success), or an identical `(type, seq, frag)` is already tracked
    /// (deduplicated).
    pub packet: Option<ControlSend>,
    /// Whether a fresh entry was recorded in the send buffer. When `true`, the
    /// caller must report the enqueue result back via [`on_dispatched`] or
    /// [`on_dispatch_failed`]; when `false` there is nothing to track (either
    /// an untracked direct send, a dedup, or a drop).
    ///
    /// [`on_dispatched`]: ControlReliability::on_dispatched
    /// [`on_dispatch_failed`]: ControlReliability::on_dispatch_failed
    pub tracked: bool,
}

/// What [`ControlReliability::receive_ack`] found for one inbound control ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckMatch {
    /// The ack type is not the ack of any tracked control packet type at all
    /// (`reverse_control_ack_for` returned nothing). The caller treats it as
    /// unrecognised.
    NotControlAck,
    /// A recognised control ack. `origin` is the control packet type it
    /// releases; `tracked` is whether a matching entry was actually found and
    /// removed from the send buffer. A recognised-but-untracked ack still lets
    /// the caller's close machine run its "waiting ack" fallback.
    Recognised { origin: u8, tracked: bool },
}

/// A control packet that ran out of road. The owning close machine maps this to
/// a teardown: a close/reset/SOCKS-result type (other than `CLOSE_READ` /
/// `CLOSE_WRITE`) finalizes the close directly, everything else sends an `RST`.
/// Mirrors Go `handleTrackedPacketTTLExpiry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlExpiry {
    pub packet_type: u8,
    pub reason: &'static str,
}

/// The result of one control retransmit poll.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ControlPollOutcome {
    /// Packets whose RTO elapsed and should be resent now.
    pub resends: Vec<ControlSend>,
    /// Set when a tracked packet outlived its TTL or exhausted its retries. The
    /// resends gathered before it was noticed are still returned alongside, and
    /// the caller must act on the expiry (tear the stream down).
    pub expired: Option<ControlExpiry>,
}

/// One parked, tracked-for-ack control packet. Mirrors Go `arqControlItem`.
///
/// `last_sent_at` is `None` until the packet is actually dispatched (the send
/// queue is asynchronous); an undispatched packet is never a retransmit
/// candidate. `sample_eligible` starts true and is cleared on the first resend,
/// so only a cleanly round-tripped packet feeds the control RTO estimate.
#[derive(Debug)]
struct ControlItem {
    packet_type: u8,
    seq: u16,
    fragment_id: u8,
    total_fragments: u8,
    payload: Vec<u8>,
    priority: usize,
    created_at: Instant,
    last_sent_at: Option<Instant>,
    dispatched: bool,
    retries: u32,
    current_rto_ns: i64,
    sample_eligible: bool,
    ttl: Duration,
}

/// Pack `(packet_type, sequence, fragment_id)` into the 32-bit send-buffer key,
/// identically to Go: `ptype << 24 | seq << 8 | fragID`.
#[inline]
fn control_key(packet_type: u8, seq: u16, fragment_id: u8) -> u32 {
    (packet_type as u32) << 24 | (seq as u32) << 8 | fragment_id as u32
}

/// The reliable control plane for a single stream. Create it with
/// [`ControlReliability::new`], then drive it with `send_control` /
/// `receive_ack` / `poll_retransmits`, feeding each a timestamp. It holds no
/// lock of its own; the owning stream serialises access.
pub struct ControlReliability {
    enabled: bool,
    snd_buf: HashMap<u32, ControlItem>,
    adaptive_rto: AdaptiveRto,

    // Derived, immutable tuning (whole nanoseconds for the RTO math, matching
    // the Go `time.Duration`).
    control_rto_ns: i64,
    control_max_rto_ns: i64,
    control_max_retries: u32,
    control_packet_ttl: Duration,
}

impl ControlReliability {
    /// Build the control plane. `enabled` mirrors Go `EnableControlReliability`:
    /// when false, every `send_control` is an untracked direct send and the
    /// retransmit/ack machinery is inert, matching a stream that opts out of
    /// control reliability entirely.
    pub fn new(cfg: ControlConfig, enabled: bool) -> Self {
        let max_rto_ns = (cfg.control_max_rto.as_nanos() as i64).max(RTO_FLOOR_NS);
        let rto_ns = (cfg.control_rto.as_nanos() as i64)
            .max(RTO_FLOOR_NS)
            .min(max_rto_ns);

        ControlReliability {
            enabled,
            snd_buf: HashMap::new(),
            adaptive_rto: AdaptiveRto::new(rto_ns),
            control_rto_ns: rto_ns,
            control_max_rto_ns: max_rto_ns,
            control_max_retries: cfg.control_max_retries.max(5),
            control_packet_ttl: cfg.control_packet_ttl.max(Duration::from_secs(120)),
        }
    }

    /// How many control packets are tracked and awaiting their ack. The close
    /// machine reads this to know when a drain is complete.
    pub fn pending(&self) -> usize {
        self.snd_buf.len()
    }

    /// Whether the control send buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.snd_buf.is_empty()
    }

    /// Whether a specific `(type, seq, frag)` is tracked. Used by the close
    /// machine (and tests) to reason about an in-flight terminal packet.
    pub fn contains(&self, packet_type: u8, seq: u16, fragment_id: u8) -> bool {
        self.snd_buf
            .contains_key(&control_key(packet_type, seq, fragment_id))
    }

    /// Wipe every tracked control packet, as an `RST`/abort does. Mirrors the
    /// `clearControl` branch of Go `clearAllQueues`.
    pub fn clear(&mut self) {
        self.snd_buf.clear();
    }

    /// The adaptive control-RTO base right now, floored to the configured
    /// control RTO and capped at the max. Mirrors Go `currentControlBaseRTO`.
    fn current_base_rto_ns(&self) -> i64 {
        let base = self.adaptive_rto.current_base;
        if base <= 0 {
            self.control_rto_ns
        } else {
            clamp(base, self.control_rto_ns, self.control_max_rto_ns)
        }
    }

    /// Queue a control packet for sending. `track_for_ack` asks for reliable
    /// delivery; `custom_ack` overrides the default ACK type lookup (the DNS
    /// query/response pair uses this). Mirrors Go `SendControlPacketWithTTL`.
    ///
    /// The returned [`ControlSendOutcome`] tells the caller whether to put a
    /// packet on the wire and whether a tracked entry now exists to report back
    /// on. A tracked packet starts undispatched: call [`on_dispatched`] once it
    /// leaves the queue, or [`on_dispatch_failed`] if the queue rejected it.
    ///
    /// [`on_dispatched`]: ControlReliability::on_dispatched
    /// [`on_dispatch_failed`]: ControlReliability::on_dispatch_failed
    // Mirrors the wide Go `SendControlPacketWithTTL` signature one-to-one; the
    // arguments are the wire fields of one control packet, not loose knobs.
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
        custom_ack: Option<u8>,
        ttl: Duration,
        now: Instant,
    ) -> ControlSendOutcome {
        let priority = normalize_packet_priority(packet_type, priority);

        // Untracked: a direct send with no bookkeeping (either reliability is
        // off, or the caller asked not to track this one).
        if !self.enabled || !track_for_ack {
            return ControlSendOutcome {
                packet: Some(ControlSend {
                    priority,
                    packet_type,
                    seq,
                    fragment_id,
                    total_fragments,
                    ttl,
                    payload,
                }),
                tracked: false,
            };
        }

        // A type with no ack mapping (and no custom override) can never be
        // acknowledged, so Go drops it and reports success rather than tracking
        // it forever.
        if custom_ack
            .or_else(|| control_ack_for(packet_type))
            .is_none()
        {
            return ControlSendOutcome {
                packet: None,
                tracked: false,
            };
        }

        let key = control_key(packet_type, seq, fragment_id);
        // An identical packet is already in flight: deduplicate.
        if self.snd_buf.contains_key(&key) {
            return ControlSendOutcome {
                packet: None,
                tracked: false,
            };
        }

        let mut initial_rto_ns = self.current_base_rto_ns();
        if is_setup_control_packet(packet_type) && SETUP_RTO_CAP_NS < initial_rto_ns {
            initial_rto_ns = SETUP_RTO_CAP_NS;
        }

        self.snd_buf.insert(
            key,
            ControlItem {
                packet_type,
                seq,
                fragment_id,
                total_fragments,
                payload: payload.clone(),
                priority,
                created_at: now,
                last_sent_at: None,
                dispatched: false,
                retries: 0,
                current_rto_ns: initial_rto_ns,
                sample_eligible: true,
                ttl,
            },
        );

        ControlSendOutcome {
            packet: Some(ControlSend {
                priority,
                packet_type,
                seq,
                fragment_id,
                total_fragments,
                ttl,
                payload,
            }),
            tracked: true,
        }
    }

    /// Mark a tracked control packet as actually sent, starting its retransmit
    /// clock. Mirrors the control branch of Go `NoteTXPacketDequeued`.
    pub fn on_dispatched(&mut self, packet_type: u8, seq: u16, fragment_id: u8, now: Instant) {
        if !self.enabled {
            return;
        }
        if let Some(item) = self
            .snd_buf
            .get_mut(&control_key(packet_type, seq, fragment_id))
        {
            item.last_sent_at = Some(now);
            item.dispatched = true;
        }
    }

    /// Record that the send queue rejected a tracked control packet: treat it as
    /// already overdue so the next poll resends it immediately. Mirrors the
    /// `!ok` branch of Go `SendControlPacketWithTTL`
    /// (`Dispatched=true, LastSentAt=now-initialRTO`).
    pub fn on_dispatch_failed(&mut self, packet_type: u8, seq: u16, fragment_id: u8, now: Instant) {
        let key = control_key(packet_type, seq, fragment_id);
        let rto = match self.snd_buf.get(&key) {
            Some(item) => Duration::from_nanos(item.current_rto_ns.max(0) as u64),
            None => return,
        };
        if let Some(item) = self.snd_buf.get_mut(&key) {
            item.dispatched = true;
            item.last_sent_at = Some(now.checked_sub(rto).unwrap_or(now));
        }
    }

    /// Take one inbound control ACK: find the packet it releases, fold its round
    /// trip into the control RTO estimate when the packet was sent exactly once,
    /// and drop it from the send buffer. Close/reset acks match every tracked
    /// copy of their type regardless of sequence; everything else matches the
    /// exact `(type, seq, frag)` key. Mirrors the send-buffer half of Go
    /// `ReceiveControlAck` (the close-state transitions it also triggers live in
    /// the owning close machine, which reads the returned [`AckMatch`]).
    pub fn receive_ack(
        &mut self,
        ack_packet_type: u8,
        seq: u16,
        fragment_id: u8,
        now: Instant,
    ) -> AckMatch {
        let origin = match reverse_control_ack_for(ack_packet_type) {
            Some(o) => o,
            None => return AckMatch::NotControlAck,
        };

        let key = control_key(origin, seq, fragment_id);
        let close_stream = is_close_stream_packet(origin);

        // The sample can only come from the exact-key entry; a close-stream ack
        // that only matched by scanning has no round-trip to measure.
        let sample_ns = match self.snd_buf.get(&key) {
            Some(item) if item.sample_eligible && item.dispatched => item
                .last_sent_at
                .map(|sent| now.saturating_duration_since(sent).as_nanos() as i64),
            _ => None,
        };

        let exact_tracked = self.snd_buf.contains_key(&key);
        let tracked = exact_tracked
            || (close_stream && self.snd_buf.values().any(|i| i.packet_type == origin));

        if !tracked {
            return AckMatch::Recognised {
                origin,
                tracked: false,
            };
        }

        if close_stream {
            self.snd_buf.retain(|_, i| i.packet_type != origin);
        } else {
            self.snd_buf.remove(&key);
        }

        if let Some(sample) = sample_ns {
            self.adaptive_rto =
                self.adaptive_rto
                    .update(sample, self.control_rto_ns, self.control_max_rto_ns);
        }

        AckMatch::Recognised {
            origin,
            tracked: true,
        }
    }

    /// Walk the control send buffer and decide what to resend now. Returns the
    /// due resends and, if one is found, the first packet that outlived its TTL
    /// or exhausted its retries. Mirrors Go `checkControlRetransmits`.
    ///
    /// The Go version iterates the map in nondeterministic order and returns at
    /// the first expiry it hits; this walks the keys in sorted order for a
    /// reproducible result, which is one of the orderings Go could itself
    /// produce. A rejected enqueue is modelled optimistically (the resend state
    /// is advanced as if the push succeeded) — the Go "push failed, skip" edge
    /// only changes the timing of the next attempt, never correctness.
    pub fn poll_retransmits(&mut self, now: Instant) -> ControlPollOutcome {
        let mut out = ControlPollOutcome::default();
        if !self.enabled {
            return out;
        }

        let mut keys: Vec<u32> = self.snd_buf.keys().copied().collect();
        keys.sort_unstable();

        for key in keys {
            let item = match self.snd_buf.get(&key) {
                Some(item) => item,
                None => continue,
            };
            let setup = is_setup_control_packet(item.packet_type);

            // Expiry check first, mirroring the top of each Go loop iteration.
            if !item.ttl.is_zero() {
                if now.saturating_duration_since(item.created_at) >= item.ttl {
                    let packet_type = item.packet_type;
                    self.snd_buf.remove(&key);
                    out.expired = Some(ControlExpiry {
                        packet_type,
                        reason: "Packet TTL expired",
                    });
                    return out;
                }
            } else {
                let mut max_retries = self.control_max_retries;
                let mut packet_ttl = self.control_packet_ttl;
                if setup {
                    max_retries = max_retries.max(SETUP_MIN_RETRIES);
                    packet_ttl = packet_ttl.max(SETUP_MIN_PACKET_TTL);
                }

                let expired_by_ttl = now.saturating_duration_since(item.created_at) >= packet_ttl;
                let exceeded_retries = item.retries >= max_retries;
                if expired_by_ttl || exceeded_retries {
                    let packet_type = item.packet_type;
                    self.snd_buf.remove(&key);
                    out.expired = Some(ControlExpiry {
                        packet_type,
                        reason: if exceeded_retries {
                            "Control packet max retransmissions exceeded"
                        } else {
                            "Control packet expired"
                        },
                    });
                    return out;
                }
            }

            // Not dispatched yet, or the RTO has not elapsed: leave it alone.
            let due = match item.last_sent_at {
                Some(sent) if item.dispatched => {
                    now.saturating_duration_since(sent).as_nanos() as i64 >= item.current_rto_ns
                }
                _ => false,
            };
            if !due {
                continue;
            }

            // Resend and advance the backoff. Setup packets grow more gently and
            // keep a tighter floor, matching the Go growth/floor selection.
            let floor_ns = if setup {
                self.current_base_rto_ns().min(SETUP_RTO_CAP_NS)
            } else {
                self.current_base_rto_ns()
            };
            let growth = if setup {
                SETUP_CONTROL_GROWTH
            } else {
                CONTROL_RETRANSMIT_GROWTH
            };

            let item = self.snd_buf.get_mut(&key).expect("item present");
            out.resends.push(ControlSend {
                priority: item.priority,
                packet_type: item.packet_type,
                seq: item.seq,
                fragment_id: item.fragment_id,
                total_fragments: item.total_fragments,
                ttl: item.ttl,
                payload: item.payload.clone(),
            });
            item.last_sent_at = Some(now);
            item.dispatched = false;
            item.retries += 1;
            item.sample_eligible = false;
            let grown = (item.current_rto_ns as f64 * growth) as i64;
            item.current_rto_ns = clamp(grown, floor_ns, self.control_max_rto_ns);
        }

        out
    }
}

#[cfg(test)]
mod tests;
