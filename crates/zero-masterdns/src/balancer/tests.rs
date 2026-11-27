//! Tests for the sans-IO resolver balancer. These pin the scoring arithmetic,
//! the half-life, the eight selection strategies and the auto-disable rule to
//! the Go client's behaviour, driving everything through explicit `now` and a
//! fixed PRNG seed so each case is reproducible.

use std::time::{Duration, Instant};

use super::*;

/// A helper to give a path a definite loss score: `sent` sends and `lost`
/// timeouts, without ever recording window sends (so auto-disable stays inert).
fn with_loss(b: &mut Balancer, index: usize, sent: u64, lost: u64, now: Instant) {
    for _ in 0..sent {
        b.report_send(index);
    }
    for _ in 0..lost {
        b.report_timeout(index, now, 1_000, || true);
    }
}

/// A helper to give a path a latency signal: `n` successes at `rtt`.
fn with_latency(b: &mut Balancer, index: usize, n: usize, rtt: Duration) {
    for _ in 0..n {
        b.report_success(index, rtt);
    }
}

// --- scoring ---------------------------------------------------------------

#[test]
fn loss_score_probation_and_rate() {
    let mut s = ConnectionStats::new();
    // Fewer than five sends: neutral 200.
    s.sent = 4;
    s.lost = 4;
    assert_eq!(s.loss_score(), 200);
    // Five sends, no loss: 0.
    s.sent = 5;
    s.lost = 0;
    assert_eq!(s.loss_score(), 0);
    // Rate is per-mille, multiply before divide.
    s.sent = 10;
    s.lost = 1;
    assert_eq!(s.loss_score(), 100);
    s.sent = 1000;
    s.lost = 3;
    assert_eq!(s.loss_score(), 3);
}

#[test]
fn latency_score_needs_five_samples() {
    let mut s = ConnectionStats::new();
    s.rtt_count = 4;
    s.rtt_micros_sum = 40_000;
    assert_eq!(s.latency_score(), 999_000);
    s.rtt_count = 5;
    s.rtt_micros_sum = 50_000;
    assert_eq!(s.latency_score(), 10_000);
}

#[test]
fn hybrid_score_weights_loss_eight_times() {
    let mut s = ConnectionStats::new();
    // No latency signal -> penalty 200; loss 0 (5 sends, none lost).
    s.sent = 5;
    s.lost = 0;
    assert_eq!(s.hybrid_score(), 200);
    // loss 100, latency 10ms -> 100*8 + 10.
    s.sent = 10;
    s.lost = 1;
    s.rtt_count = 5;
    s.rtt_micros_sum = 50_000;
    assert_eq!(s.hybrid_score(), 100 * 8 + 10);
    // Latency penalty is capped at 1000ms.
    s.rtt_count = 5;
    s.rtt_micros_sum = 5_000_000_000;
    assert_eq!(s.hybrid_score(), 100 * 8 + 1000);
}

#[test]
fn half_life_halves_all_five() {
    let mut s = ConnectionStats::new();
    s.sent = 1001;
    s.acked = 800;
    s.lost = 10;
    s.rtt_micros_sum = 2000;
    s.rtt_count = 400;
    s.apply_half_life();
    assert_eq!(s.sent, 500);
    assert_eq!(s.acked, 400);
    assert_eq!(s.lost, 5);
    assert_eq!(s.rtt_micros_sum, 1000);
    assert_eq!(s.rtt_count, 200);
    // Below the threshold on every counter: untouched.
    let before = (s.sent, s.acked, s.lost, s.rtt_micros_sum, s.rtt_count);
    s.apply_half_life();
    assert_eq!(
        (s.sent, s.acked, s.lost, s.rtt_micros_sum, s.rtt_count),
        before
    );
}

#[test]
fn report_success_only_counts_positive_rtt() {
    let mut s = ConnectionStats::new();
    s.report_success(Duration::ZERO);
    assert_eq!(s.acked, 1);
    assert_eq!(s.rtt_count, 0);
    s.report_success(Duration::from_millis(5));
    assert_eq!(s.acked, 2);
    assert_eq!(s.rtt_count, 1);
    assert_eq!(s.rtt_micros_sum, 5000);
}

#[test]
fn seed_conservative_clears_probation() {
    let mut s = ConnectionStats::new();
    s.seed_conservative();
    assert_eq!(s.sent, 10);
    assert_eq!(s.acked, 8);
    assert_eq!(s.loss_score(), 0);
    assert_eq!(s.latency_score(), 999_000);
}

// --- strategy mapping ------------------------------------------------------

#[test]
fn strategy_from_id() {
    assert_eq!(Strategy::from_id(0), Strategy::RoundRobinDefault);
    assert_eq!(Strategy::from_id(1), Strategy::Random);
    assert_eq!(Strategy::from_id(2), Strategy::RoundRobin);
    assert_eq!(Strategy::from_id(3), Strategy::LeastLoss);
    assert_eq!(Strategy::from_id(4), Strategy::LowestLatency);
    assert_eq!(Strategy::from_id(5), Strategy::HybridScore);
    assert_eq!(Strategy::from_id(6), Strategy::LossThenLatency);
    assert_eq!(Strategy::from_id(7), Strategy::LeastLossTopRandom);
    assert_eq!(Strategy::from_id(8), Strategy::LeastLossTopRoundRobin);
    // Unknown ids clamp to plain round-robin.
    assert_eq!(Strategy::from_id(99), Strategy::RoundRobin);
    assert_eq!(Strategy::from_id(-1), Strategy::RoundRobin);
}

// --- round robin -----------------------------------------------------------

#[test]
fn round_robin_cycles_in_order() {
    let mut b = Balancer::new(3, Strategy::RoundRobin, Duration::from_secs(30), false, 1);
    let picks: Vec<usize> = (0..7).map(|_| b.best().unwrap()).collect();
    assert_eq!(picks, vec![0, 1, 2, 0, 1, 2, 0]);
}

#[test]
fn round_robin_select_multiple() {
    let mut b = Balancer::new(4, Strategy::RoundRobin, Duration::from_secs(30), false, 1);
    // First select of 2 starts at cursor 0: [0,1]. Cursor advances by 2.
    assert_eq!(b.select(2), vec![0, 1]);
    // Next select of 2 starts at cursor 2: [2,3].
    assert_eq!(b.select(2), vec![2, 3]);
    // Next select of 3 starts at cursor 0 (4 % 4): [0,1,2].
    assert_eq!(b.select(3), vec![0, 1, 2]);
}

#[test]
fn round_robin_excluding_skips_target() {
    let mut b = Balancer::new(3, Strategy::RoundRobin, Duration::from_secs(30), false, 1);
    // Cursor 0 would pick 0, but we exclude it, so the rotation yields 1.
    assert_eq!(b.best_excluding(Some(0)), Some(1));
}

// --- random ----------------------------------------------------------------

#[test]
fn random_is_seed_deterministic() {
    let mut a = Balancer::new(5, Strategy::Random, Duration::from_secs(30), false, 42);
    let mut b = Balancer::new(5, Strategy::Random, Duration::from_secs(30), false, 42);
    let pa: Vec<usize> = (0..20).map(|_| a.best().unwrap()).collect();
    let pb: Vec<usize> = (0..20).map(|_| b.best().unwrap()).collect();
    assert_eq!(pa, pb);
    // Every pick is a valid active index.
    assert!(pa.iter().all(|&i| i < 5));
}

#[test]
fn random_select_multiple_is_distinct() {
    let mut b = Balancer::new(5, Strategy::Random, Duration::from_secs(30), false, 7);
    let picks = b.select(3);
    assert_eq!(picks.len(), 3);
    // Partial Fisher-Yates: the three picks are distinct active ids.
    let mut sorted = picks.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 3);
}

// --- least loss / latency / hybrid -----------------------------------------

#[test]
fn least_loss_picks_lowest() {
    let mut b = Balancer::new(3, Strategy::LeastLoss, Duration::from_secs(30), false, 1);
    let now = Instant::now();
    with_loss(&mut b, 0, 10, 3, now); // 300
    with_loss(&mut b, 1, 10, 1, now); // 100
    with_loss(&mut b, 2, 10, 2, now); // 200
    assert_eq!(b.best(), Some(1));
}

#[test]
fn least_loss_without_signal_falls_back_to_round_robin() {
    // No path has five sends, so there is no loss signal: round-robin.
    let mut b = Balancer::new(3, Strategy::LeastLoss, Duration::from_secs(30), false, 1);
    let picks: Vec<usize> = (0..3).map(|_| b.best().unwrap()).collect();
    assert_eq!(picks, vec![0, 1, 2]);
}

#[test]
fn lowest_latency_picks_fastest() {
    let mut b = Balancer::new(
        3,
        Strategy::LowestLatency,
        Duration::from_secs(30),
        false,
        1,
    );
    with_latency(&mut b, 0, 5, Duration::from_millis(30));
    with_latency(&mut b, 1, 5, Duration::from_millis(10));
    with_latency(&mut b, 2, 5, Duration::from_millis(20));
    assert_eq!(b.best(), Some(1));
}

#[test]
fn hybrid_prefers_low_loss_then_low_latency() {
    let mut b = Balancer::new(3, Strategy::HybridScore, Duration::from_secs(30), false, 1);
    let now = Instant::now();
    // Path 0: no loss, slow. Path 1: a little loss, fast. Loss dominates (x8).
    with_loss(&mut b, 0, 10, 0, now);
    with_latency(&mut b, 0, 5, Duration::from_millis(100)); // 0*8 + 100 = 100
    with_loss(&mut b, 1, 10, 1, now);
    with_latency(&mut b, 1, 5, Duration::from_millis(1)); // 100*8 + 1 = 801
    with_loss(&mut b, 2, 10, 0, now);
    with_latency(&mut b, 2, 5, Duration::from_millis(50)); // 0*8 + 50 = 50
    assert_eq!(b.best(), Some(2));
}

// --- pool strategies -------------------------------------------------------

#[test]
fn loss_then_latency_narrows_tier() {
    let mut b = Balancer::new(
        4,
        Strategy::LossThenLatency,
        Duration::from_secs(30),
        false,
        3,
    );
    let now = Instant::now();
    // Losses: 0 -> 0, 1 -> ~20, 2 -> 100, 3 -> 0. Tier is loss within 25 of best(0):
    // paths 0, 1, 3 qualify (0, 20, 0); path 2 (100) is cut.
    with_loss(&mut b, 0, 100, 0, now);
    with_loss(&mut b, 1, 100, 2, now); // 20
    with_loss(&mut b, 2, 100, 10, now); // 100
    with_loss(&mut b, 3, 100, 0, now);
    with_latency(&mut b, 0, 5, Duration::from_millis(80));
    with_latency(&mut b, 1, 5, Duration::from_millis(5));
    with_latency(&mut b, 3, 5, Duration::from_millis(5));
    // The pick is always within the surviving tier, never the high-loss path 2.
    for _ in 0..20 {
        assert_ne!(b.best(), Some(2));
    }
}

#[test]
fn least_loss_top_round_robin_cycles_within_top_tier() {
    let mut b = Balancer::new(
        4,
        Strategy::LeastLossTopRoundRobin,
        Duration::from_secs(30),
        false,
        1,
    );
    let now = Instant::now();
    // topCount = max(2, ceil(4/10)) = 2. Lowest-loss two are 1 (100) and 3 (0)...
    with_loss(&mut b, 0, 10, 5, now); // 500
    with_loss(&mut b, 1, 10, 1, now); // 100
    with_loss(&mut b, 2, 10, 3, now); // 300
    with_loss(&mut b, 3, 10, 0, now); // 0
                                      // The two in the pool are {3, 1} (loss order). Round-robin stays inside it.
    for _ in 0..20 {
        let pick = b.best().unwrap();
        assert!(pick == 1 || pick == 3, "pick {pick} escaped the top tier");
    }
}

#[test]
fn least_loss_top_random_stays_in_tier() {
    let mut b = Balancer::new(
        5,
        Strategy::LeastLossTopRandom,
        Duration::from_secs(30),
        false,
        9,
    );
    let now = Instant::now();
    with_loss(&mut b, 0, 10, 0, now); // 0
    with_loss(&mut b, 1, 10, 1, now); // 100
    with_loss(&mut b, 2, 10, 5, now); // 500
    with_loss(&mut b, 3, 10, 4, now); // 400
    with_loss(&mut b, 4, 10, 3, now); // 300
                                      // topCount = max(2, ceil(5/10)) = 2 -> {0, 1}.
    for _ in 0..30 {
        let pick = b.best().unwrap();
        assert!(pick == 0 || pick == 1, "pick {pick} escaped the top tier");
    }
}

// --- helpers ---------------------------------------------------------------

#[test]
fn normalize_required_count_clamps() {
    assert_eq!(normalize_required_count(0, 5, 1), 0);
    assert_eq!(normalize_required_count(4, 0, 1), 1); // default
    assert_eq!(normalize_required_count(4, -3, 2), 2); // default
    assert_eq!(normalize_required_count(4, 10, 1), 4); // clamp to valid
    assert_eq!(normalize_required_count(4, 3, 1), 3);
}

#[test]
fn min_observations_table_and_scaling() {
    // Three or fewer active paths never auto-disable.
    assert_eq!(
        auto_disable_min_observations(3, Duration::from_secs(1)),
        1_000_000
    );
    // The 1_000_000 branch is not scaled by window.
    assert_eq!(
        auto_disable_min_observations(3, Duration::from_secs(60)),
        1_000_000
    );
    // 4 active, sub-30s window: base 48, x1.
    assert_eq!(
        auto_disable_min_observations(4, Duration::from_secs(10)),
        48
    );
    // 4 active, 30s window: x2.
    assert_eq!(
        auto_disable_min_observations(4, Duration::from_secs(30)),
        96
    );
    // 4 active, 60s window: x3.
    assert_eq!(
        auto_disable_min_observations(4, Duration::from_secs(60)),
        144
    );
    // Larger buckets.
    assert_eq!(
        auto_disable_min_observations(100, Duration::from_secs(1)),
        8
    );
    assert_eq!(
        auto_disable_min_observations(200, Duration::from_secs(1)),
        6
    );
}

// --- auto-disable ----------------------------------------------------------

#[test]
fn auto_disable_requires_full_window_loss() {
    let window = Duration::from_secs(10);
    let mut b = Balancer::new(4, Strategy::RoundRobin, window, false, 1);
    let now = Instant::now();
    // 4 active, 10s window -> needs 48 window sends, all timed out.
    for _ in 0..48 {
        b.record_window_send(0, now);
    }
    // 47 timeouts: window not 100% lost yet (one send still unaccounted).
    let mut disabled = false;
    for _ in 0..47 {
        disabled |= b.report_timeout(0, now, 2, || true);
    }
    assert!(!disabled);
    assert!(b.is_valid(0));
    // The 48th timeout makes it 48/48 -> disabled.
    let disabled = b.report_timeout(0, now, 2, || true);
    assert!(disabled);
    assert!(!b.is_valid(0));
    assert_eq!(b.active_count(), 3);
}

#[test]
fn auto_disable_respects_min_active() {
    let window = Duration::from_secs(10);
    // Only 3 active: the <=3 bucket demands 1_000_000 observations, so never.
    let mut b = Balancer::new(3, Strategy::RoundRobin, window, false, 1);
    let now = Instant::now();
    for _ in 0..100 {
        b.record_window_send(0, now);
    }
    let mut disabled = false;
    for _ in 0..100 {
        disabled |= b.report_timeout(0, now, 2, || true);
    }
    assert!(!disabled);
    assert!(b.is_valid(0));
}

#[test]
fn auto_disable_confirm_handler_can_veto() {
    let window = Duration::from_secs(10);
    let mut b = Balancer::new(4, Strategy::RoundRobin, window, true, 1);
    let now = Instant::now();
    for _ in 0..48 {
        b.record_window_send(0, now);
    }
    for _ in 0..47 {
        b.report_timeout(0, now, 2, || true);
    }
    // The confirm handler says the path is still alive (not down): keep it.
    let disabled = b.report_timeout(0, now, 2, || false);
    assert!(!disabled);
    assert!(b.is_valid(0));
    // The window was reset by the veto, so a fresh 48 sends are needed again.
    assert_eq!(b.stats(0).unwrap().window_lost, 0);
}

#[test]
fn retract_timeout_undoes_loss() {
    let window = Duration::from_secs(10);
    let mut b = Balancer::new(4, Strategy::RoundRobin, window, false, 1);
    let now = Instant::now();
    b.report_timeout(0, now, 2, || true);
    assert_eq!(b.stats(0).unwrap().lost, 1);
    assert!(b.retract_timeout(0, now));
    assert_eq!(b.stats(0).unwrap().lost, 0);
    // Nothing left to retract.
    assert!(!b.retract_timeout(0, now));
}

// --- set_valid list mutation -----------------------------------------------

#[test]
fn set_valid_uses_swap_remove_and_append() {
    let mut b = Balancer::new(4, Strategy::RoundRobin, Duration::from_secs(30), false, 1);
    // Disabling index 1 swaps the last (3) into its slot: [0, 3, 2].
    b.set_valid(1, false);
    assert_eq!(b.active_ids(), &[0, 3, 2]);
    assert!(!b.is_valid(1));
    // Re-enabling index 1 appends it to the end: [0, 3, 2, 1].
    b.set_valid(1, true);
    assert_eq!(b.active_ids(), &[0, 3, 2, 1]);
    assert!(b.is_valid(1));
}

#[test]
fn window_rolls_over_after_elapsed() {
    let window = Duration::from_secs(10);
    let mut b = Balancer::new(4, Strategy::RoundRobin, window, false, 1);
    let t0 = Instant::now();
    b.record_window_send(0, t0);
    assert_eq!(b.stats(0).unwrap().window_sent, 1);
    // Still inside the window: accumulates.
    b.record_window_send(0, t0 + Duration::from_secs(5));
    assert_eq!(b.stats(0).unwrap().window_sent, 2);
    // Past the window: resets then counts the new send.
    b.record_window_send(0, t0 + Duration::from_secs(11));
    assert_eq!(b.stats(0).unwrap().window_sent, 1);
}
