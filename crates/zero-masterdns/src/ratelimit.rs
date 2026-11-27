//! The SOCKS authentication rate limiter, as a pure (sans-IO) state machine.
//!
//! When the local SOCKS listener requires a username and password, a bad guess
//! is a failed auth. This module counts those failures per client IP inside a
//! sliding window and temporarily bans an IP that crosses the threshold, with
//! an exponential back-off on repeat offenders. It is the brake on credential
//! stuffing against the local proxy.
//!
//! It is deliberately clock-explicit: every method that cares about time takes
//! `now: Instant`, so the behaviour is fully testable without sleeping. The
//! async SOCKS listener passes `Instant::now()` and the client IP string.
//!
//! # The policy, in one place
//!
//!  * **window** — failures are counted over the last 2 minutes.
//!  * **threshold** — 10 failures in that window trips a ban. Set high so an
//!    honest user who fat-fingers a password a few times is never caught.
//!  * **ban** — first ban is 1 minute, doubling each repeat (2m, 4m, 8m…),
//!    capped at 15 minutes.
//!  * **decay** — stay clean for 10 minutes after a ban expires and the
//!    escalation counter resets, forgiving a user who fixed their mistake.
//!  * **exempt** — an empty IP or any loopback address is never limited (a
//!    local tool on the same machine is trusted).
//!  * **purge** — stale per-IP records are swept at most once a minute so the
//!    table cannot grow without bound.
//!
//! Ported from the Go client's `internal/client/socks_ratelimit.go` at the
//! pinned release `v2026.06.13.234407-7de2476`, matching its counts, windows,
//! back-off curve and decay exactly.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

/// Sliding window over which auth failures are counted.
const WINDOW: Duration = Duration::from_secs(120);
/// Failures within the window before an IP is banned.
const MAX_FAILURES: usize = 10;
/// Ban length after the first threshold breach; doubles on each repeat.
const BASE_BAN: Duration = Duration::from_secs(60);
/// Hard ceiling on any single ban.
const MAX_BAN: Duration = Duration::from_secs(900);
/// Clean time after a ban expires that resets the escalation counter.
const BAN_DECAY_AFTER: Duration = Duration::from_secs(600);
/// Shortest gap between stale-record sweeps.
const PURGE_INTERVAL: Duration = Duration::from_secs(60);

/// Per-IP failure bookkeeping.
#[derive(Debug, Clone, Default)]
struct Record {
    /// Failure instants still inside the sliding window.
    timestamps: Vec<Instant>,
    /// When the current ban ends, if the IP is banned.
    ban_until: Option<Instant>,
    /// How many times this IP has been banned (drives the back-off and decay).
    ban_count: u32,
}

/// The SOCKS auth rate limiter. One per client; not thread-safe by itself (the
/// Go original holds a mutex, but here the owning async task serialises access,
/// so the lock lives at the call site, not inside this pure core).
#[derive(Debug, Clone)]
pub struct SocksRateLimiter {
    records: HashMap<String, Record>,
    last_purge: Instant,
}

impl SocksRateLimiter {
    /// Create an empty limiter, stamping the first purge clock at `now`.
    pub fn new(now: Instant) -> Self {
        Self {
            records: HashMap::new(),
            last_purge: now,
        }
    }

    /// Whether `ip` is currently banned at `now`. Loopback and empty IPs are
    /// never banned.
    pub fn is_blocked(&self, ip: &str, now: Instant) -> bool {
        if is_exempt(ip) {
            return false;
        }
        match self.records.get(ip) {
            Some(rec) => rec.ban_until.is_some_and(|until| now < until),
            None => false,
        }
    }

    /// Record one auth failure for `ip` at `now`. Returns `true` if this
    /// failure is what pushed the IP over the threshold into a ban (or if it is
    /// already banned). Loopback and empty IPs are ignored and return `false`.
    pub fn record_failure(&mut self, ip: &str, now: Instant) -> bool {
        if is_exempt(ip) {
            return false;
        }

        // Sweep stale entries at most once per purge interval.
        if now.duration_since(self.last_purge) >= PURGE_INTERVAL {
            self.purge(now);
            self.last_purge = now;
        }

        let rec = self.records.entry(ip.to_string()).or_default();

        // Already inside an active ban: nothing to escalate, still "blocked".
        if rec.ban_until.is_some_and(|until| now < until) {
            return true;
        }

        // Decay the escalation counter if the IP stayed clean long enough after
        // its last ban expired.
        if rec.ban_count > 0 {
            if let Some(until) = rec.ban_until {
                if now > until && now.duration_since(until) >= BAN_DECAY_AFTER {
                    rec.ban_count = 0;
                }
            }
        }

        // Drop failures that have aged out of the window, then record this one.
        let cutoff = now.checked_sub(WINDOW);
        rec.timestamps.retain(|ts| cutoff.is_none_or(|c| *ts > c));
        rec.timestamps.push(now);

        if rec.timestamps.len() >= MAX_FAILURES {
            rec.ban_count += 1;
            rec.ban_until = Some(now + ban_duration(rec.ban_count));
            rec.timestamps.clear();
            return true;
        }
        false
    }

    /// Clear all failure/ban state for `ip` after a successful auth. Loopback
    /// and empty IPs are ignored.
    pub fn record_success(&mut self, ip: &str) {
        if is_exempt(ip) {
            return;
        }
        self.records.remove(ip);
    }

    /// Wipe every record (e.g. on a config reload).
    pub fn reset(&mut self, now: Instant) {
        self.records.clear();
        self.last_purge = now;
    }

    /// Number of IPs currently tracked. Exposed for tests and observability.
    pub fn tracked(&self) -> usize {
        self.records.len()
    }

    /// Remove records that are neither banned nor hold a recent failure.
    fn purge(&mut self, now: Instant) {
        let cutoff = now.checked_sub(WINDOW);
        self.records.retain(|_, rec| {
            // Keep anything under an active ban.
            if rec.ban_until.is_some_and(|until| now < until) {
                return true;
            }
            // Keep anything with a failure still inside the window.
            let has_recent = rec
                .timestamps
                .iter()
                .any(|ts| cutoff.is_none_or(|c| *ts > c));
            let ban_expired = rec.ban_until.is_none_or(|until| now > until);
            has_recent || !ban_expired
        });
    }
}

/// Whether an IP string is exempt from rate limiting: empty, or a loopback
/// address. Mirrors the Go `ip == "" || isLoopbackIP(ip)` guard, including that
/// an unparseable string is treated as non-loopback (so it *is* limited).
fn is_exempt(ip: &str) -> bool {
    if ip.is_empty() {
        return true;
    }
    IpAddr::from_str(ip).is_ok_and(|a| a.is_loopback())
}

/// The ban length for a given ban count: 1 minute doubling each step, capped at
/// 15 minutes. Mirrors the Go back-off loop exactly (`ban_count == 1` is the
/// base ban; the cap is reached at count 5 and holds there after).
fn ban_duration(ban_count: u32) -> Duration {
    let mut d = BASE_BAN;
    let mut i = 1;
    while i < ban_count {
        d *= 2;
        if d >= MAX_BAN {
            return MAX_BAN;
        }
        i += 1;
    }
    d
}
