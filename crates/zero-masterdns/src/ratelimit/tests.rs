//! Tests for the sans-IO SOCKS auth rate limiter. Time is explicit: every case
//! builds instants from one base far past the monotonic epoch (so the window
//! subtraction never underflows) and feeds them in, checking the ban decisions
//! and the back-off curve against the Go `socks_ratelimit.go` constants.

use super::*;

/// A base instant comfortably past the monotonic epoch, so `now - WINDOW` is
/// always representable.
fn base() -> Instant {
    Instant::now() + Duration::from_secs(1_000_000)
}

const IP: &str = "203.0.113.7";

/// Drive `count` failures for `IP`, all stamped at `at`, returning whether the
/// last one tripped a ban.
fn fail_n(limiter: &mut SocksRateLimiter, at: Instant, count: usize) -> bool {
    let mut banned = false;
    for _ in 0..count {
        banned = limiter.record_failure(IP, at);
    }
    banned
}

#[test]
fn fresh_limiter_blocks_nothing() {
    let now = base();
    let l = SocksRateLimiter::new(now);
    assert!(!l.is_blocked(IP, now));
    assert_eq!(l.tracked(), 0);
}

#[test]
fn below_threshold_does_not_ban() {
    let t = base();
    let mut l = SocksRateLimiter::new(t);
    // Nine failures is one short of the threshold.
    assert!(!fail_n(&mut l, t, 9));
    assert!(!l.is_blocked(IP, t));
}

#[test]
fn threshold_triggers_ban() {
    let t = base();
    let mut l = SocksRateLimiter::new(t);
    assert!(!fail_n(&mut l, t, 9));
    // The tenth failure in the window trips the ban.
    assert!(l.record_failure(IP, t));
    assert!(l.is_blocked(IP, t));
    // The first ban lasts one minute; the edge is exclusive.
    assert!(l.is_blocked(IP, t + Duration::from_secs(59)));
    assert!(!l.is_blocked(IP, t + Duration::from_secs(60)));
}

#[test]
fn ban_duration_curve() {
    // 1m, then doubling (2m, 4m, 8m), capped at 15m from count 5 on.
    assert_eq!(ban_duration(1), Duration::from_secs(60));
    assert_eq!(ban_duration(2), Duration::from_secs(120));
    assert_eq!(ban_duration(3), Duration::from_secs(240));
    assert_eq!(ban_duration(4), Duration::from_secs(480));
    assert_eq!(ban_duration(5), Duration::from_secs(900));
    assert_eq!(ban_duration(6), Duration::from_secs(900));
    assert_eq!(ban_duration(50), Duration::from_secs(900));
}

#[test]
fn repeat_offender_escalates() {
    let t = base();
    let mut l = SocksRateLimiter::new(t);
    // First ban: 10 failures at t => banned until t+60.
    assert!(fail_n(&mut l, t, 10));

    // The ban has just expired at t+60; a fresh batch escalates to a 2m ban.
    let t2 = t + Duration::from_secs(60);
    assert!(!l.is_blocked(IP, t2));
    assert!(fail_n(&mut l, t2, 10));
    // Second ban is two minutes (t2..t2+120), proving the escalation.
    assert!(l.is_blocked(IP, t2 + Duration::from_secs(119)));
    assert!(!l.is_blocked(IP, t2 + Duration::from_secs(120)));
}

#[test]
fn clean_gap_decays_back_to_base_ban() {
    let t = base();
    let mut l = SocksRateLimiter::new(t);
    assert!(fail_n(&mut l, t, 10)); // ban until t+60

    // Stay clean well past ban-expiry + decay (60s ban + 600s decay).
    let t2 = t + Duration::from_secs(700);
    assert!(!l.is_blocked(IP, t2));
    assert!(fail_n(&mut l, t2, 10));
    // Back to a one-minute base ban, not an escalated one.
    assert!(l.is_blocked(IP, t2 + Duration::from_secs(59)));
    assert!(!l.is_blocked(IP, t2 + Duration::from_secs(60)));
}

#[test]
fn window_counts_recent_failures() {
    let t = base();
    let mut l = SocksRateLimiter::new(t);
    // Nine at t, one more at t+119: all still inside the 120s window => ban.
    assert!(!fail_n(&mut l, t, 9));
    assert!(l.record_failure(IP, t + Duration::from_secs(119)));
}

#[test]
fn window_drops_stale_failures() {
    let t = base();
    let mut l = SocksRateLimiter::new(t);
    // Nine at t, one at t+121: the first nine have aged out of the window, so
    // the lone recent failure is not enough to ban.
    assert!(!fail_n(&mut l, t, 9));
    assert!(!l.record_failure(IP, t + Duration::from_secs(121)));
    assert!(!l.is_blocked(IP, t + Duration::from_secs(121)));
}

#[test]
fn loopback_is_exempt() {
    let t = base();
    let mut l = SocksRateLimiter::new(t);
    for ip in ["127.0.0.1", "::1"] {
        for _ in 0..50 {
            assert!(!l.record_failure(ip, t));
        }
        assert!(!l.is_blocked(ip, t));
    }
    assert_eq!(l.tracked(), 0);
}

#[test]
fn empty_ip_is_exempt() {
    let t = base();
    let mut l = SocksRateLimiter::new(t);
    for _ in 0..50 {
        assert!(!l.record_failure("", t));
    }
    assert!(!l.is_blocked("", t));
    assert_eq!(l.tracked(), 0);
}

#[test]
fn success_clears_failures() {
    let t = base();
    let mut l = SocksRateLimiter::new(t);
    assert!(!fail_n(&mut l, t, 9));
    l.record_success(IP);
    assert_eq!(l.tracked(), 0);
    // After clearing, it takes a fresh full run to ban again.
    assert!(!fail_n(&mut l, t, 9));
    assert!(l.record_failure(IP, t));
}

#[test]
fn already_banned_failure_still_reports_blocked() {
    let t = base();
    let mut l = SocksRateLimiter::new(t);
    assert!(fail_n(&mut l, t, 10));
    // A further failure while banned still returns true (blocked), without
    // changing the ban window.
    assert!(l.record_failure(IP, t + Duration::from_secs(5)));
    assert!(l.is_blocked(IP, t + Duration::from_secs(59)));
}

#[test]
fn reset_wipes_everything() {
    let t = base();
    let mut l = SocksRateLimiter::new(t);
    assert!(fail_n(&mut l, t, 10));
    assert!(l.is_blocked(IP, t));
    l.reset(t);
    assert_eq!(l.tracked(), 0);
    assert!(!l.is_blocked(IP, t));
}

#[test]
fn purge_drops_stale_records() {
    let t = base();
    let mut l = SocksRateLimiter::new(t);
    // A few failures for one IP that will go stale.
    assert!(!fail_n(&mut l, t, 3));
    assert_eq!(l.tracked(), 1);
    // A failure from a different IP well past the window triggers a purge that
    // sweeps the first IP's stale record.
    assert!(!l.record_failure("198.51.100.9", t + Duration::from_secs(200)));
    assert_eq!(l.tracked(), 1);
    assert!(!l.is_blocked(IP, t + Duration::from_secs(200)));
}
