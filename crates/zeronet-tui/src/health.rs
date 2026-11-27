//! The tunnel watchdog: is the live connection still carrying traffic, and
//! what should happen when it is not.
//!
//! The gap this closes is the laptop one: the connection is up, the machine
//! sleeps, the server's sockets are gone when it wakes, and nothing notices —
//! the client keeps drawing "connected" while every application hangs. The
//! same gap exists after the tunnel has been up for hours: the one profile in
//! use dies quietly and the client never tries another, so a user with five
//! working profiles is stuck on the broken one.
//!
//! What is in here is policy only — cadence, thresholds, and which profile to
//! move to. The caller runs the probe (one real request through the local
//! proxy) and reports the outcome. Keeping the decisions pure is what makes
//! the anti-flapping rules testable, and they are the whole point: a watchdog
//! that re-dials on one lost packet trades a working tunnel for churn, and
//! one that waits for ten failures leaves a dead tunnel on screen for ten
//! minutes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a healthy, idle connection goes between probes.
///
/// One request of a few hundred bytes a minute; a connection that is moving
/// bytes is never probed at all (the traffic is the proof), so this is the
/// cost of an *idle* tunnel, not of a working one.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(60);

/// Shortest gap between probes when the user has just come back to the
/// terminal. Resume-from-suspend is the case this exists for, and the user is
/// watching, so it must not wait out the full interval.
pub const RESUME_PROBE_GAP: Duration = Duration::from_secs(15);

/// No byte through the tunnel for this long counts as "quiet" — the state a
/// probe is meaningful in.
pub const QUIET_GAP: Duration = Duration::from_secs(20);

/// Upload rate (bytes/s) that counts as real use on its own. Below it, bytes
/// that only go *out* are no proof: a dead tunnel still counts every retry an
/// application writes into it, so upload-only traffic at a trickle is exactly
/// what a broken connection looks like.
pub const UPLOAD_ALIVE_BPS: u64 = 32 * 1024;

/// Whether a counter tick proves the tunnel carries traffic.
///
/// Bytes coming *back* are the proof — they had to cross the server. Bytes
/// going out are counted as soon as the outbound is dialled, before anything
/// answers, so on their own they only count when they move at a rate a real
/// upload does, not the trickle of an application retrying a dead path.
pub fn proves_traffic(prev_download: u64, next_download: u64, upload_bps: u64) -> bool {
    next_download > prev_download || upload_bps >= UPLOAD_ALIVE_BPS
}

/// No input for this long means the user left; the next keystroke is a
/// return, not a continuation.
pub const AWAY_GAP: Duration = Duration::from_secs(3);

/// Consecutive failed probes before a recovery is attempted on a cadence
/// probe. One failure is a lost packet.
pub const FAILS_BEFORE_RECOVER: u32 = 2;

/// How long a profile that failed is kept out of automatic recovery. Long
/// enough that a flapping server is not picked straight back, short enough
/// that a server which recovered is usable again in the same session.
pub const DEAD_COOLDOWN: Duration = Duration::from_secs(10 * 60);

/// Shortest gap between two automatic recoveries: switching a profile tears
/// down and re-dials the engine, and doing that repeatedly is worse than the
/// problem.
pub const RECOVER_GAP: Duration = Duration::from_secs(45);

/// Automatic recoveries in a row before the watchdog stops acting on its own.
/// Reset by any successful probe, so a session that recovers and works is not
/// penalised for earlier trouble.
pub const RECOVER_LIMIT: u32 = 4;

/// A profile the watchdog may move to.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Candidate {
    pub id: i64,
    /// Last measured latency, when the client has one.
    pub ping_ms: Option<f64>,
    /// Found by the config finder (public feed or the crowd's rankings) and
    /// therefore known to have worked on this network at some point.
    pub found: bool,
}

/// What the last probe did, from the watchdog's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The probe failed and the watchdog should keep watching.
    Failed,
    /// The probe failed and a recovery should run now.
    Recover,
}

/// Watchdog state: cadence, counters and the dead list.
#[derive(Debug, Default)]
pub struct TunnelWatch {
    last_probe: Option<Instant>,
    last_recover: Option<Instant>,
    failures: u32,
    recoveries: u32,
    /// Set when a recovery was attempted; the next success announces it once,
    /// so the user learns the tunnel came back without a toast per probe.
    report_on_success: bool,
    /// Profile id → instant it may be picked again.
    cooldowns: HashMap<i64, Instant>,
}

impl TunnelWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a probe is due, given that a connection is up and quiet.
    ///
    /// `resumed` marks the first probe after the user came back to the
    /// terminal; it shortens the gap rather than bypassing it, so a user who
    /// taps a key every few seconds does not queue a probe per keystroke.
    pub fn probe_due(&self, now: Instant, resumed: bool) -> bool {
        let gap = if resumed {
            RESUME_PROBE_GAP
        } else {
            PROBE_INTERVAL
        };
        self.last_probe
            .is_none_or(|last| now.duration_since(last) >= gap)
    }

    /// A probe has been started.
    pub fn mark_probed(&mut self, now: Instant) {
        self.last_probe = Some(now);
    }

    /// The probe passed.
    pub fn note_ok(&mut self) {
        self.failures = 0;
        self.recoveries = 0;
    }

    /// The probe failed; what to do about it.
    pub fn note_failure(&mut self, resumed: bool) -> Outcome {
        self.failures += 1;
        // A probe run because the user just came back is answered by acting on
        // its first failure: the user is looking at a stalled application, and
        // waiting one more minute to confirm what the probe already said is
        // the behaviour this module exists to remove.
        let threshold = if resumed { 1 } else { FAILS_BEFORE_RECOVER };
        if self.failures >= threshold {
            Outcome::Recover
        } else {
            Outcome::Failed
        }
    }

    /// Whether a recovery may start now: inside the gap and under the limit.
    pub fn recovery_allowed(&self, now: Instant) -> bool {
        self.recoveries < RECOVER_LIMIT
            && self
                .last_recover
                .is_none_or(|at| now.duration_since(at) >= RECOVER_GAP)
    }

    /// The watchdog has given up acting on its own for this session.
    pub fn exhausted(&self) -> bool {
        self.recoveries >= RECOVER_LIMIT
    }

    /// A recovery is being attempted now.
    pub fn note_recovery(&mut self, now: Instant) {
        self.last_recover = Some(now);
        self.recoveries += 1;
        self.failures = 0;
        self.report_on_success = true;
    }

    /// Whether a success should be announced (once per recovery episode).
    pub fn take_recovery_report(&mut self) -> bool {
        std::mem::take(&mut self.report_on_success)
    }

    /// Keep a profile out of automatic recovery for [`DEAD_COOLDOWN`].
    pub fn cool_down(&mut self, id: i64, now: Instant) {
        self.cooldowns.insert(id, now + DEAD_COOLDOWN);
    }

    fn cooling(&self, id: i64, now: Instant) -> bool {
        self.cooldowns.get(&id).is_some_and(|until| *until > now)
    }

    /// The best profile to move to, or `None` when there is nowhere to go.
    ///
    /// Measured latency first: the ping sweep already runs over every profile,
    /// so the fastest answering one is the best guess. Finder-verified
    /// profiles come before the rest at the same latency, because they were
    /// proven to carry traffic *on this network*. Profiles on the dead list
    /// are skipped — unless every candidate is on it, in which case a tunnel
    /// through a profile that failed once still beats no tunnel at all.
    pub fn pick(
        &self,
        candidates: &[Candidate],
        current: Option<i64>,
        now: Instant,
    ) -> Option<i64> {
        let mut usable: Vec<Candidate> = candidates
            .iter()
            .filter(|candidate| Some(candidate.id) != current)
            .copied()
            .collect();
        if usable.is_empty() {
            return None;
        }
        let fresh: Vec<Candidate> = usable
            .iter()
            .filter(|candidate| !self.cooling(candidate.id, now))
            .copied()
            .collect();
        if !fresh.is_empty() {
            usable = fresh;
        }
        usable.sort_by(|a, b| {
            a.ping_ms
                .is_none()
                .cmp(&b.ping_ms.is_none())
                .then_with(|| {
                    a.ping_ms
                        .unwrap_or(f64::MAX)
                        .total_cmp(&b.ping_ms.unwrap_or(f64::MAX))
                })
                .then_with(|| b.found.cmp(&a.found))
                .then_with(|| a.id.cmp(&b.id))
        });
        usable.first().map(|candidate| candidate.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed origin, so durations in the tests are plain arithmetic.
    fn at(secs: u64) -> Instant {
        Instant::now() + Duration::from_secs(secs)
    }

    fn candidate(id: i64, ping_ms: Option<f64>, found: bool) -> Candidate {
        Candidate { id, ping_ms, found }
    }

    #[test]
    fn upload_only_retries_do_not_count_as_a_working_tunnel() {
        // A dead tunnel: applications keep writing retries, nothing returns.
        assert!(!proves_traffic(1_000, 1_000, 900));
        // Anything coming back proves the path.
        assert!(proves_traffic(1_000, 1_001, 0));
        // A real upload with no reply yet still counts as use.
        assert!(proves_traffic(1_000, 1_000, UPLOAD_ALIVE_BPS));
    }

    #[test]
    fn a_fresh_watchdog_probes_at_once() {
        assert!(TunnelWatch::new().probe_due(at(0), false));
    }

    #[test]
    fn the_cadence_holds_until_the_interval_elapses() {
        let mut watch = TunnelWatch::new();
        let now = at(0);
        watch.mark_probed(now);
        assert!(!watch.probe_due(now + PROBE_INTERVAL - Duration::from_secs(1), false));
        assert!(watch.probe_due(now + PROBE_INTERVAL, false));
    }

    #[test]
    fn a_resume_probes_sooner_but_not_twice_a_second() {
        let mut watch = TunnelWatch::new();
        let now = at(0);
        watch.mark_probed(now);
        // A keystroke a second later does not queue a second probe...
        assert!(!watch.probe_due(now + Duration::from_secs(1), true));
        // ...and the shortened gap still applies to the next one.
        assert!(!watch.probe_due(now + RESUME_PROBE_GAP - Duration::from_secs(1), true));
        assert!(watch.probe_due(now + RESUME_PROBE_GAP, true));
    }

    #[test]
    fn one_failure_on_cadence_waits_but_two_recover() {
        let mut watch = TunnelWatch::new();
        assert_eq!(watch.note_failure(false), Outcome::Failed);
        assert_eq!(watch.note_failure(false), Outcome::Recover);
    }

    #[test]
    fn a_resume_failure_recovers_immediately() {
        let mut watch = TunnelWatch::new();
        assert_eq!(watch.note_failure(true), Outcome::Recover);
    }

    #[test]
    fn recovery_respects_the_gap_and_the_limit() {
        let mut watch = TunnelWatch::new();
        let mut now = at(0);
        for _ in 0..RECOVER_LIMIT {
            assert!(watch.recovery_allowed(now), "under the limit");
            watch.note_recovery(now);
            // A second recovery right away is refused; the gap has to pass.
            assert!(!watch.recovery_allowed(now + Duration::from_secs(1)));
            now += RECOVER_GAP;
        }
        assert!(watch.exhausted());
        assert!(
            !watch.recovery_allowed(now),
            "the limit stops the watchdog acting on its own"
        );
    }

    #[test]
    fn a_success_resets_the_counters_and_reports_once() {
        let mut watch = TunnelWatch::new();
        let now = at(0);
        watch.note_recovery(now);
        watch.note_failure(false);
        watch.note_ok();

        let after_ok = now + RECOVER_GAP;
        assert!(
            watch.recovery_allowed(after_ok),
            "a working tunnel is not penalised"
        );
        assert!(!watch.exhausted());
        // The recovery is announced once, not on every probe afterwards.
        assert!(watch.take_recovery_report());
        assert!(!watch.take_recovery_report());
    }

    #[test]
    fn pick_prefers_measured_latency_then_a_finder_verified_profile() {
        let watch = TunnelWatch::new();
        let now = at(0);
        let candidates = [
            candidate(1, None, true),
            candidate(2, Some(80.0), false),
            candidate(3, Some(40.0), false),
            candidate(4, None, false),
        ];
        assert_eq!(watch.pick(&candidates, None, now), Some(3));
        // With the fastest gone, measured order still wins over provenance.
        let candidates = [
            candidate(1, None, true),
            candidate(4, None, false),
            candidate(2, Some(90.0), false),
        ];
        assert_eq!(watch.pick(&candidates, None, now), Some(2));
        // Nothing measured: the finder-verified profile is the better guess.
        let candidates = [candidate(1, None, true), candidate(4, None, false)];
        assert_eq!(watch.pick(&candidates, None, now), Some(1));
    }

    #[test]
    fn pick_never_returns_the_profile_in_use() {
        let watch = TunnelWatch::new();
        let now = at(0);
        let candidates = [candidate(7, Some(10.0), false)];
        assert_eq!(watch.pick(&candidates, Some(7), now), None);
    }

    #[test]
    fn a_dead_profile_is_skipped_until_every_candidate_is_dead() {
        let mut watch = TunnelWatch::new();
        let now = at(0);
        watch.cool_down(1, now);
        let candidates = [
            candidate(1, Some(10.0), false),
            candidate(2, Some(500.0), false),
        ];
        assert_eq!(watch.pick(&candidates, None, now), Some(2));

        // Its cooldown expired: the fastest wins again.
        assert_eq!(watch.pick(&candidates, None, now + DEAD_COOLDOWN), Some(1));

        // Everything dead: the tunnel still gets a profile rather than none.
        watch.cool_down(1, now);
        watch.cool_down(2, now);
        assert_eq!(watch.pick(&candidates, None, now), Some(1));
    }
}
