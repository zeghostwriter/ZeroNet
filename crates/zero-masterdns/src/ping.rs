//! The keepalive ping scheduler, as a pure (sans-IO) state machine.
//!
//! The tunnel sends a tiny PING on stream 0 every so often so the server knows
//! the client is still there and so round-trip health can be watched. How often
//! is not fixed: it speeds up when traffic is flowing and slows right down when
//! the link is idle, so an idle tunnel barely costs anything (important on a
//! phone on mobile data) while a busy one is probed tightly.
//!
//! This module is the deterministic half of that: it tracks when the last
//! ping/pong and the last ordinary packet went each way, and from those decides
//! the current ping interval and whether a ping is due *now*. It never touches a
//! socket, a clock, or a lock — every method that cares about time takes
//! `now: Instant`, and the async loop feeds it `Instant::now()`.
//!
//! # The one rule to remember (the invariant)
//!
//! [`poll`](PingScheduler::poll) tells you a ping is due but does **not** record
//! that one was sent. Exactly as in the Go client, `last_ping_sent` only moves
//! when the ping actually leaves through the sender, so after you act on a due
//! ping you must feed it back with
//! [`note_packet`](PingScheduler::note_packet)`(PACKET_PING, false, now)`. If you
//! forget, `poll` will keep reporting the ping as due (same as the Go loop would
//! if the packet never went out) — no ping is silently dropped, but none is
//! silently invented either.
//!
//! Ported from the Go client's `internal/client/ping_manager.go` at the pinned
//! release `v2026.06.13.234407-7de2476`, matching its interval tiers, idle
//! thresholds, wake throttle and sequence numbering exactly.

#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use zero_protocol::masterdns::enums::{PACKET_PING, PACKET_PONG};

/// How long [`note_packet`](PingScheduler::note_packet) collapses repeat wake
/// signals, so a flood of packets cannot spin the async loop. Matches the Go
/// `wake` throttle of 100ms.
const WAKE_THROTTLE: Duration = Duration::from_millis(100);

/// Floor and ceiling on the gap between `poll` checks. The loop re-arms its
/// timer to half the current interval, but never tighter than 100ms nor looser
/// than 1s, so it stays responsive without busy-spinning. Matches the Go
/// `checkInterval` clamp.
const MIN_CHECK: Duration = Duration::from_millis(100);
const MAX_CHECK: Duration = Duration::from_secs(1);

/// The interval tiers and the idle thresholds that pick between them. All of
/// these come straight from the client config; the defaults in
/// [`PingConfig::default`] are the Go client's defaults. `aggressive_interval`
/// is the one the session-accept policy may tighten, so set it from the
/// post-policy config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingConfig {
    /// Ping gap while traffic is warm (recent activity). Fastest tier.
    pub aggressive_interval: Duration,
    /// Ping gap once things cool off a little.
    pub lazy_interval: Duration,
    /// Ping gap when the link has been quiet for a while.
    pub cooldown_interval: Duration,
    /// Ping gap when the link is cold (long idle). Slowest tier.
    pub cold_interval: Duration,
    /// Below this idle time the link counts as warm (aggressive tier).
    pub warm_threshold: Duration,
    /// Below this idle time the link counts as cool (lazy tier).
    pub cool_threshold: Duration,
    /// Below this idle time the link counts as cooling (cooldown tier); at or
    /// above it the link is cold.
    pub cold_threshold: Duration,
}

impl Default for PingConfig {
    /// The Go client's shipped defaults (`internal/config/client.go`): 100ms /
    /// 750ms / 2s / 15s intervals, 8s / 20s / 30s thresholds.
    fn default() -> Self {
        Self {
            aggressive_interval: Duration::from_millis(100),
            lazy_interval: Duration::from_millis(750),
            cooldown_interval: Duration::from_secs(2),
            cold_interval: Duration::from_secs(15),
            warm_threshold: Duration::from_secs(8),
            cool_threshold: Duration::from_secs(20),
            cold_threshold: Duration::from_secs(30),
        }
    }
}

/// What [`poll`](PingScheduler::poll) decided this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingPoll {
    /// A ping is due by the timing rule. The caller still gates on the session
    /// being ready and stream 0 existing; only when it truly sends does it take
    /// a sequence with [`next_ping_sequence`](PingScheduler::next_ping_sequence)
    /// and then record the send via `note_packet`.
    pub ping_due: bool,
    /// How long to wait before polling again (the loop's re-arm interval).
    pub next_check: Duration,
}

/// The ping scheduler for one tunnel. Create it with [`new`](Self::new) at the
/// moment the tunnel comes up; drive it with [`note_packet`](Self::note_packet)
/// on every packet in or out and [`poll`](Self::poll) on each timer tick.
#[derive(Debug, Clone)]
pub struct PingScheduler {
    cfg: PingConfig,
    /// When the last PING was sent out. Drives the ping-due test.
    last_ping_sent: Instant,
    /// When the last PONG came in. Tracked for connection-health use by the
    /// caller; not part of the interval decision itself.
    last_pong_received: Instant,
    /// When the last non-PING packet was sent out. Half of the idle measure.
    last_non_ping_sent: Instant,
    /// When the last non-PONG packet came in. The other half of the idle
    /// measure.
    last_non_pong_received: Instant,
    /// When a wake was last signalled, for the throttle.
    last_woke: Instant,
    /// Monotonic ping sequence source. Stored wide; handed out truncated to
    /// `u16`, so it wraps 0xFFFF -> 0 exactly like the Go `uint16(Add(1))`.
    next_ping_seq: u32,
}

impl PingScheduler {
    /// Start a scheduler at `now`, stamping every activity clock to `now` (so a
    /// just-connected tunnel starts in the aggressive tier, like the Go
    /// `newPingManager`).
    pub fn new(cfg: PingConfig, now: Instant) -> Self {
        Self {
            cfg,
            last_ping_sent: now,
            last_pong_received: now,
            last_non_ping_sent: now,
            last_non_pong_received: now,
            last_woke: now,
            next_ping_seq: 0,
        }
    }

    /// Record that a packet of `packet_type` crossed the tunnel, `inbound` true
    /// for one arriving from the server. Returns `true` if this packet asks the
    /// loop to wake early (an ordinary, non-keepalive packet), subject to the
    /// 100ms throttle — the async wrapper uses that to nudge its select loop.
    ///
    /// Mirrors the Go `NotifyPacket`: a PONG in / PING out only updates its own
    /// clock quietly; any other packet updates the matching activity clock and
    /// requests a wake.
    pub fn note_packet(&mut self, packet_type: u8, inbound: bool, now: Instant) -> bool {
        let is_ping = packet_type == PACKET_PING;
        let is_pong = packet_type == PACKET_PONG;
        if inbound {
            if is_pong {
                self.last_pong_received = now;
                false
            } else {
                self.last_non_pong_received = now;
                self.wake(now)
            }
        } else if is_ping {
            self.last_ping_sent = now;
            false
        } else {
            self.last_non_ping_sent = now;
            self.wake(now)
        }
    }

    /// Decide, at `now`, whether a ping is due and how long until the next
    /// check. Does not change any clock (see the module invariant).
    pub fn poll(&self, now: Instant) -> PingPoll {
        let interval = self.next_interval(now);
        let ping_due = now.duration_since(self.last_ping_sent) >= interval;
        let next_check = clamp_duration(interval / 2, MIN_CHECK, MAX_CHECK);
        PingPoll {
            ping_due,
            next_check,
        }
    }

    /// The current ping interval at `now`, chosen from how recently traffic
    /// flowed. Warm (either direction active inside `warm_threshold`) -> the
    /// aggressive tier; otherwise the quieter of the two idle times picks lazy
    /// / cooldown / cold. Mirrors the Go `nextInterval`.
    pub fn next_interval(&self, now: Instant) -> Duration {
        let idle_sent = now.duration_since(self.last_non_ping_sent);
        let idle_recv = now.duration_since(self.last_non_pong_received);
        if idle_sent < self.cfg.warm_threshold || idle_recv < self.cfg.warm_threshold {
            return self.cfg.aggressive_interval;
        }
        let min_idle = idle_sent.min(idle_recv);
        if min_idle < self.cfg.cool_threshold {
            self.cfg.lazy_interval
        } else if min_idle < self.cfg.cold_threshold {
            self.cfg.cooldown_interval
        } else {
            self.cfg.cold_interval
        }
    }

    /// Take the next ping sequence number. Call this only when a ping is really
    /// being sent. Wraps 0xFFFF -> 0, first value is 1, matching the Go
    /// `nextPingSequence`.
    pub fn next_ping_sequence(&mut self) -> u16 {
        self.next_ping_seq = self.next_ping_seq.wrapping_add(1);
        self.next_ping_seq as u16
    }

    /// When the last inbound PONG arrived (for the caller's health checks).
    pub fn last_pong_received(&self) -> Instant {
        self.last_pong_received
    }

    /// The wake throttle: a wake is signalled at most once per
    /// [`WAKE_THROTTLE`]. Returns whether this call signalled one.
    fn wake(&mut self, now: Instant) -> bool {
        if now.duration_since(self.last_woke) < WAKE_THROTTLE {
            return false;
        }
        self.last_woke = now;
        true
    }
}

/// The 7-byte client ping payload: the ASCII tag `PO:` followed by four caller-
/// supplied random bytes. Randomness is injected (not drawn here) so the whole
/// scheduler stays pure and testable; the async wrapper fills `nonce` from the
/// system RNG. Mirrors the Go `buildClientPingPayload`.
pub fn ping_payload(nonce: [u8; 4]) -> [u8; 7] {
    [b'P', b'O', b':', nonce[0], nonce[1], nonce[2], nonce[3]]
}

/// Clamp a duration into `[lo, hi]`. (`Duration` is `Ord`, but spelling it out
/// keeps the intent obvious at the call site.)
fn clamp_duration(d: Duration, lo: Duration, hi: Duration) -> Duration {
    d.clamp(lo, hi)
}
