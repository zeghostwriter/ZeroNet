//! The resolver balancer: picking which DNS resolver path to send the next
//! query through, and deciding when one has gone dead.
//!
//! The client holds many resolver paths at once (a resolver address crossed
//! with a domain). Every query it sends has to choose one, and the choice is
//! what spreads load, steers around a lossy or slow resolver, and keeps the
//! tunnel alive when some paths are being filtered. This module is the pure,
//! sans-IO core of that choice: the per-path counters, the scores derived from
//! them, the eight selection strategies, and the auto-disable rule that retires
//! a path showing total loss. It owns no sockets and no clock — every
//! time-dependent call takes an explicit `now` — so the integer-exact scoring
//! and the rolling-window math can be unit-tested against the Go client
//! (`internal/client/balancer.go`) at the pinned release.
//!
//! # What is tracked and how it scores
//!
//! Each path keeps lifetime counters (`sent`, `acked`, `lost`, and a running
//! sum/count of round-trip microseconds) plus a short rolling window of
//! sends/timeouts used only for auto-disable. From the lifetime counters come
//! three scores, all "lower is better":
//!
//!  * **loss** — per-mille loss `(lost*1000)/sent`, with a neutral `200` while a
//!    path is still in probation (fewer than five sends) so one early loss does
//!    not condemn it.
//!  * **latency** — the mean RTT in microseconds, or a `999000` sentinel until
//!    there are five samples.
//!  * **hybrid** — `loss*8 + latency_penalty`, weighting loss about eight times
//!    heavier than a capped millisecond latency penalty.
//!
//! The counters are halved whenever any crosses 1000 (a half-life), so the
//! scores track recent behaviour instead of ancient history.
//!
//! # Determinism
//!
//! The only randomness is an xorshift64 PRNG, seeded once at construction. The
//! seed is injectable here precisely so the random strategies can be tested;
//! the round-robin strategies ride a single integer cursor. Both are part of
//! the state, so a given sequence of calls is fully reproducible.

#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

/// The counter value that triggers a half-life halving of every lifetime
/// counter. Mirrors Go `connectionStatsHalfLifeThreshold`.
const HALF_LIFE_THRESHOLD: u64 = 1000;

/// Loss/latency sentinels and probation thresholds, matching the Go scorers.
const UNKNOWN_LOSS_SCORE: u64 = 200;
const UNKNOWN_LATENCY_SCORE: u64 = 999_000;
const PROBATION_SENDS: u64 = 5;
const LATENCY_SAMPLES: u64 = 5;

/// The eight resolver-selection strategies. The default is round-robin; the
/// numbers match the Go `Balancing*` constants so a configured value maps
/// straight across.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// 0: plain round-robin (same as [`Strategy::RoundRobin`]).
    RoundRobinDefault,
    /// 1: uniform random pick.
    Random,
    /// 2: plain round-robin.
    RoundRobin,
    /// 3: lowest loss score.
    LeastLoss,
    /// 4: lowest latency score.
    LowestLatency,
    /// 5: lowest hybrid score (loss weighted ~8x latency).
    HybridScore,
    /// 6: narrow to a loss tier, then a latency sub-tier, random within it.
    LossThenLatency,
    /// 7: top-N by loss, random within.
    LeastLossTopRandom,
    /// 8: top-N by loss, round-robin within.
    LeastLossTopRoundRobin,
}

impl Strategy {
    /// Map a configured strategy id to a [`Strategy`], defaulting unknown ids to
    /// round-robin (id 2), the way the Go client clamps.
    pub fn from_id(id: i32) -> Strategy {
        match id {
            1 => Strategy::Random,
            3 => Strategy::LeastLoss,
            4 => Strategy::LowestLatency,
            5 => Strategy::HybridScore,
            6 => Strategy::LossThenLatency,
            7 => Strategy::LeastLossTopRandom,
            8 => Strategy::LeastLossTopRoundRobin,
            0 => Strategy::RoundRobinDefault,
            _ => Strategy::RoundRobin,
        }
    }
}

/// How a candidate pool should be narrowed to a single pick or a count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolPick {
    Random,
    RoundRobin,
}

/// A score function over one path's counters; lower is better. Each scoring
/// strategy supplies one of [`ConnectionStats::loss_score`],
/// [`ConnectionStats::latency_score`] or [`ConnectionStats::hybrid_score`].
type Scorer = fn(&ConnectionStats) -> u64;

/// The lifetime and rolling-window counters for one resolver path.
///
/// The five lifetime counters feed the scores and are subject to the half-life.
/// The three window fields (`window_started_at`, `window_sent`, `window_lost`)
/// are a separate, tumbling window used only by auto-disable: they are advanced
/// by [`ConnectionStats::record_window_send`] and
/// [`ConnectionStats::record_window_timeout`], not by the ordinary reports, so a
/// caller that never records window sends can never trip auto-disable.
#[derive(Debug, Default, Clone)]
pub struct ConnectionStats {
    sent: u64,
    acked: u64,
    lost: u64,
    rtt_micros_sum: u64,
    rtt_count: u64,
    window_started_at: Option<Instant>,
    window_sent: u32,
    window_lost: u32,
}

impl ConnectionStats {
    /// A fresh, all-zero set of counters.
    pub fn new() -> Self {
        ConnectionStats::default()
    }

    /// Zero every lifetime counter (window state untouched). Mirrors Go
    /// `ResetServerStats`.
    pub fn reset(&mut self) {
        self.sent = 0;
        self.acked = 0;
        self.lost = 0;
        self.rtt_micros_sum = 0;
        self.rtt_count = 0;
    }

    /// Seed the counters so a brand-new path starts out trusted but with no
    /// latency signal: 10 sends, 8 acked, no loss. This clears probation
    /// (`sent >= 5`) and gives a loss score of 0 without faking any RTT.
    /// Mirrors Go `SeedConservativeStats`.
    pub fn seed_conservative(&mut self) {
        self.sent = 10;
        self.acked = 8;
        self.lost = 0;
        self.rtt_micros_sum = 0;
        self.rtt_count = 0;
    }

    /// Per-mille loss, with a neutral `200` while in probation (fewer than five
    /// sends) and `0` once some sends have landed with no loss. Multiply before
    /// divide, truncating, exactly as Go `lossScoreLocked`.
    pub fn loss_score(&self) -> u64 {
        if self.sent < PROBATION_SENDS {
            return UNKNOWN_LOSS_SCORE;
        }
        if self.lost == 0 {
            return 0;
        }
        (self.lost * 1000) / self.sent
    }

    /// Mean RTT in microseconds, or the `999000` sentinel until five samples
    /// exist. Mirrors Go `latencyScoreLocked`.
    pub fn latency_score(&self) -> u64 {
        if self.rtt_count < LATENCY_SAMPLES {
            return UNKNOWN_LATENCY_SCORE;
        }
        self.rtt_micros_sum / self.rtt_count
    }

    /// The latency contribution to the hybrid score: `200` when there is no
    /// latency signal, otherwise the mean RTT in whole milliseconds capped at
    /// 1000. Mirrors Go `hybridLatencyPenaltyLocked`.
    fn hybrid_latency_penalty(&self) -> u64 {
        let latency_micros = self.latency_score();
        if latency_micros == UNKNOWN_LATENCY_SCORE {
            return 200;
        }
        let latency_millis = latency_micros / 1000;
        if latency_millis > 1000 {
            1000
        } else {
            latency_millis
        }
    }

    /// `loss*8 + latency_penalty`: loss dominates, latency breaks ties. Mirrors
    /// Go `hybridScoreLocked`.
    pub fn hybrid_score(&self) -> u64 {
        self.loss_score() * 8 + self.hybrid_latency_penalty()
    }

    /// Halve every lifetime counter once any of `sent`/`acked`/`lost`/`rtt_count`
    /// crosses [`HALF_LIFE_THRESHOLD`], so the scores reflect recent behaviour.
    /// `rtt_micros_sum` is halved alongside `rtt_count` to keep the average
    /// stable. Mirrors Go `applyHalfLife` (the CAS single-runner guard is not
    /// needed in this single-threaded core). Called after every mutation.
    fn apply_half_life(&mut self) {
        if self.sent <= HALF_LIFE_THRESHOLD
            && self.acked <= HALF_LIFE_THRESHOLD
            && self.lost <= HALF_LIFE_THRESHOLD
            && self.rtt_count <= HALF_LIFE_THRESHOLD
        {
            return;
        }
        self.sent /= 2;
        self.acked /= 2;
        self.lost /= 2;
        self.rtt_micros_sum /= 2;
        self.rtt_count /= 2;
    }

    /// Count one send: `sent += 1`, then half-life. Mirrors Go `ReportSend`.
    /// Deliberately does **not** touch the rolling window.
    fn report_send(&mut self) {
        self.sent += 1;
        self.apply_half_life();
    }

    /// Count one acknowledgement, folding in a positive RTT sample. Mirrors Go
    /// `ReportSuccess`.
    fn report_success(&mut self, rtt: Duration) {
        self.acked += 1;
        if rtt > Duration::ZERO {
            self.rtt_micros_sum += rtt.as_micros() as u64;
            self.rtt_count += 1;
        }
        self.apply_half_life();
    }

    /// Count one timeout on the lifetime counters: `lost += 1`, then half-life.
    /// The window side is advanced separately by
    /// [`ConnectionStats::record_window_timeout`]. Mirrors the first two lines
    /// of Go `ReportTimeout`.
    fn report_lost(&mut self) {
        self.lost += 1;
        self.apply_half_life();
    }

    /// Undo a timeout previously counted (a late success arrived): `lost -= 1`
    /// if positive, then half-life. Mirrors Go `RetractTimeout`.
    fn retract_lost(&mut self) {
        if self.lost > 0 {
            self.lost -= 1;
        }
        self.apply_half_life();
    }

    /// Lazily start the window, or roll it over if it has elapsed. A
    /// non-positive window only stamps the start once and never resets. Mirrors
    /// Go `ensureWindowLocked`.
    fn ensure_window(&mut self, now: Instant, window: Duration) {
        if window.is_zero() {
            if self.window_started_at.is_none() {
                self.window_started_at = Some(now);
            }
            return;
        }
        let rolled = match self.window_started_at {
            None => true,
            Some(started) => now.saturating_duration_since(started) >= window,
        };
        if rolled {
            self.window_started_at = Some(now);
            self.window_sent = 0;
            self.window_lost = 0;
        }
    }

    /// Record one send into the rolling window. Mirrors Go `recordWindowSend`
    /// (called only from the resolver-tracking path, not ordinary reports).
    pub fn record_window_send(&mut self, now: Instant, window: Duration) {
        self.ensure_window(now, window);
        self.window_sent = self.window_sent.saturating_add(1);
    }

    /// Record one timeout into the rolling window and return the window's
    /// `(timed_out, sent)` counts. Mirrors Go `recordWindowTimeout`.
    fn record_window_timeout(&mut self, now: Instant, window: Duration) -> (u32, u32) {
        self.ensure_window(now, window);
        self.window_lost = self.window_lost.saturating_add(1);
        (self.window_lost, self.window_sent)
    }

    /// Undo one windowed timeout if any. Mirrors Go `retractWindowTimeout`.
    fn retract_window_timeout(&mut self, now: Instant, window: Duration) -> bool {
        self.ensure_window(now, window);
        if self.window_lost == 0 {
            false
        } else {
            self.window_lost -= 1;
            true
        }
    }

    /// Clear the whole rolling window. Mirrors Go `resetWindow`.
    fn reset_window(&mut self) {
        self.window_started_at = None;
        self.window_sent = 0;
        self.window_lost = 0;
    }
}

/// The `window >= 60s -> x3`, `>= 30s -> x2`, else `x1` scale applied to an
/// auto-disable observation floor. A non-positive base is returned unchanged.
/// Mirrors Go `scaleAutoDisableMinObservations`.
pub fn scale_auto_disable_min_observations(base: i32, window: Duration) -> i32 {
    if base <= 0 {
        return base;
    }
    if window >= Duration::from_secs(60) {
        base * 3
    } else if window >= Duration::from_secs(30) {
        base * 2
    } else {
        base
    }
}

/// How many window sends a path must show (all timed out) before auto-disable
/// will even consider it, as a function of how many paths are still active.
/// Fewer active paths demand far more evidence; three or fewer never disable.
/// The base floors are scaled by the window length. Mirrors Go
/// `autoDisableMinObservationsForActiveCount`.
pub fn auto_disable_min_observations(active: usize, window: Duration) -> i32 {
    let base = match active {
        0..=3 => return 1_000_000,
        4..=5 => 48,
        6..=8 => 40,
        9..=10 => 34,
        11..=15 => 26,
        16..=20 => 22,
        21..=30 => 18,
        31..=40 => 15,
        41..=50 => 13,
        51..=75 => 10,
        76..=100 => 8,
        101..=150 => 7,
        _ => 6,
    };
    scale_auto_disable_min_observations(base, window)
}

/// The latency sub-tier tolerance (in ms) for strategy 6: zero when the best is
/// already unknown/high (>= 200), otherwise `best/4` clamped to `[2, 25]`.
/// Mirrors Go `latencyToleranceForTier`.
fn latency_tolerance_for_tier(best_latency: u64) -> u64 {
    if best_latency >= 200 {
        return 0;
    }
    (best_latency / 4).clamp(2, 25)
}

/// Clamp a requested pick count to `[0, valid]`, defaulting a non-positive
/// request. Mirrors Go `normalizeRequiredCount`.
fn normalize_required_count(valid_count: usize, required: i32, default_if_invalid: i32) -> usize {
    if valid_count == 0 {
        return 0;
    }
    let required = if required <= 0 {
        default_if_invalid
    } else {
        required
    };
    if required as usize > valid_count {
        valid_count
    } else {
        required as usize
    }
}

/// The index into an `n`-long list that a round-robin cursor currently points
/// at. Mirrors Go `roundRobinStartIndex`.
fn round_robin_start_index(counter: u64, n: usize) -> usize {
    if n == 0 {
        0
    } else {
        (counter % n as u64) as usize
    }
}

/// One step of the xorshift64 PRNG, with the Go zero-guard. Mirrors Go
/// `xorshift64`.
fn xorshift64(mut v: u64) -> u64 {
    if v == 0 {
        v = 0x9e37_79b9_7f4a_7c15;
    }
    v ^= v << 13;
    v ^= v >> 7;
    v ^= v << 17;
    v
}

/// Remove the first occurrence of `value` from `list` by swapping in the last
/// element (order is not preserved past the removed slot). Mirrors Go
/// `removeActiveIndexLocked` / `removeInactiveIndexLocked`, which the
/// round-robin order depends on being a swap-remove rather than a shift.
fn swap_remove_value(list: &mut Vec<usize>, value: usize) {
    if let Some(pos) = list.iter().position(|&i| i == value) {
        list.swap_remove(pos);
    }
}

/// The resolver balancer over a fixed set of paths identified by index.
///
/// Create it with [`Balancer::new`], mark paths valid/invalid, and drive it with
/// `report_*` after each query result and `select`/`best` to choose the next
/// path. The `confirm` callback into [`Balancer::report_timeout`] stands in for
/// the Go `confirmResolverDown` probe; pass a closure that re-checks liveness,
/// or one that always returns `true` when no such check is wired.
pub struct Balancer {
    stats: Vec<ConnectionStats>,
    valid: Vec<bool>,
    active_ids: Vec<usize>,
    inactive_ids: Vec<usize>,
    strategy: Strategy,
    window: Duration,
    confirm_enabled: bool,
    rr_counter: u64,
    rng_state: u64,
}

impl Balancer {
    /// Build a balancer over `num_connections` paths, all active to start. The
    /// `seed` seeds the PRNG; `window` is the auto-disable rolling-window length;
    /// `confirm_enabled` says whether a liveness re-check is wired (it is only
    /// ever consulted when 20 or fewer paths are active).
    pub fn new(
        num_connections: usize,
        strategy: Strategy,
        window: Duration,
        confirm_enabled: bool,
        seed: u64,
    ) -> Self {
        let stats = (0..num_connections)
            .map(|_| ConnectionStats::new())
            .collect();
        let valid = vec![true; num_connections];
        let active_ids = (0..num_connections).collect();
        Balancer {
            stats,
            valid,
            active_ids,
            inactive_ids: Vec::new(),
            strategy,
            window,
            confirm_enabled,
            rr_counter: 0,
            rng_state: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
        }
    }

    /// Shared, read-only access to one path's counters.
    pub fn stats(&self, index: usize) -> Option<&ConnectionStats> {
        self.stats.get(index)
    }

    /// Mutable access to one path's counters (for seeding).
    pub fn stats_mut(&mut self, index: usize) -> Option<&mut ConnectionStats> {
        self.stats.get_mut(index)
    }

    /// The indices currently active (eligible for selection), in insertion
    /// order rotated by none — the raw active list.
    pub fn active_ids(&self) -> &[usize] {
        &self.active_ids
    }

    /// How many paths are active right now.
    pub fn active_count(&self) -> usize {
        self.active_ids.len()
    }

    /// Whether a path is currently valid (active).
    pub fn is_valid(&self, index: usize) -> bool {
        self.valid.get(index).copied().unwrap_or(false)
    }

    fn next_random(&mut self) -> u64 {
        self.rng_state = xorshift64(self.rng_state);
        self.rng_state
    }

    /// Advance the round-robin cursor by `step` and return its pre-advance value,
    /// matching Go's `rrCounter.Add(step) - step`.
    fn rr_advance(&mut self, step: u64) -> u64 {
        let pre = self.rr_counter;
        self.rr_counter = self.rr_counter.wrapping_add(step);
        pre
    }

    // --- reporting ---------------------------------------------------------

    /// Record that a query was sent on `index`.
    pub fn report_send(&mut self, index: usize) {
        if let Some(s) = self.stats.get_mut(index) {
            s.report_send();
        }
    }

    /// Record that a query on `index` was answered, with its round-trip time.
    pub fn report_success(&mut self, index: usize, rtt: Duration) {
        if let Some(s) = self.stats.get_mut(index) {
            s.report_success(rtt);
        }
    }

    /// Record one send into `index`'s rolling auto-disable window.
    pub fn record_window_send(&mut self, index: usize, now: Instant) {
        let window = self.window;
        if let Some(s) = self.stats.get_mut(index) {
            s.record_window_send(now, window);
        }
    }

    /// Record a timeout on `index` and run the auto-disable rule. Returns `true`
    /// if the path was retired. `min_active` is the floor on how many paths must
    /// stay active (raised to at least 2); `confirm` is only invoked when a
    /// liveness re-check is wired and 20 or fewer paths are active, and should
    /// return `true` when the path is confirmed dead.
    ///
    /// Mirrors Go `ReportTimeout`. Disable requires, in order: the path is still
    /// valid; the window shows at least `auto_disable_min_observations` sends;
    /// 100% of the window's sends timed out; more than `min_active` paths active;
    /// and, if required, the confirm callback agrees.
    pub fn report_timeout(
        &mut self,
        index: usize,
        now: Instant,
        min_active: i32,
        mut confirm: impl FnMut() -> bool,
    ) -> bool {
        let window = self.window;
        let (total_timed_out, total_sent) = match self.stats.get_mut(index) {
            Some(s) => {
                s.report_lost();
                s.record_window_timeout(now, window)
            }
            None => return false,
        };

        if !self.is_valid(index) {
            return false;
        }

        let active_count = self.active_ids.len();
        let min_observations = auto_disable_min_observations(active_count, window);
        if (total_sent as i32) < min_observations || total_timed_out != total_sent {
            return false;
        }

        let mut min_active = min_active;
        if min_active < 2 {
            min_active = 2;
        }
        if active_count as i32 <= min_active {
            return false;
        }

        let confirm_required = self.confirm_enabled && active_count <= 20;
        if confirm_required && !confirm() {
            // The path answered the liveness probe; keep it, reset the window.
            if let Some(s) = self.stats.get_mut(index) {
                s.reset_window();
            }
            return false;
        }

        self.set_valid(index, false);
        if let Some(s) = self.stats.get_mut(index) {
            s.reset_window();
        }
        true
    }

    /// Undo a timeout on `index` (a late success arrived). Mirrors Go
    /// `RetractTimeout`; returns whether a windowed timeout was decremented.
    pub fn retract_timeout(&mut self, index: usize, now: Instant) -> bool {
        let window = self.window;
        match self.stats.get_mut(index) {
            Some(s) => {
                s.retract_lost();
                s.retract_window_timeout(now, window)
            }
            None => false,
        }
    }

    /// Set a path valid or invalid, moving it between the active and inactive
    /// lists and resetting its window when it becomes valid again. Mirrors the
    /// state move in Go `SetConnectionValidityWithLog` / `moveConnectionStateLocked`.
    ///
    /// The list mutation copies Go exactly, because the round-robin order
    /// depends on it: a removal is a *swap-remove* (the last id takes the
    /// vacated slot) and an insertion appends to the end. A path re-enabled
    /// after a disable therefore lands at the back of the active list, not back
    /// in its old numeric position, and the round-robin cursor sees the new
    /// order.
    pub fn set_valid(&mut self, index: usize, valid: bool) {
        if index >= self.valid.len() || self.valid[index] == valid {
            return;
        }
        self.valid[index] = valid;
        if valid {
            swap_remove_value(&mut self.inactive_ids, index);
            if !self.active_ids.contains(&index) {
                self.active_ids.push(index);
            }
            if let Some(s) = self.stats.get_mut(index) {
                s.reset_window();
            }
        } else {
            swap_remove_value(&mut self.active_ids, index);
            if !self.inactive_ids.contains(&index) {
                self.inactive_ids.push(index);
            }
        }
    }

    // --- signal gates ------------------------------------------------------

    fn has_loss_signal(&self) -> bool {
        self.active_ids
            .iter()
            .any(|&idx| self.stats[idx].sent >= PROBATION_SENDS)
    }

    fn has_latency_signal(&self) -> bool {
        self.active_ids
            .iter()
            .any(|&idx| self.stats[idx].rtt_count >= LATENCY_SAMPLES)
    }

    fn has_hybrid_signal(&self) -> bool {
        self.has_loss_signal() || self.has_latency_signal()
    }

    // --- selection ---------------------------------------------------------

    /// Pick the single best path for the next query, honouring the strategy, or
    /// `None` when no path is active. Mirrors Go `GetBestConnection`.
    pub fn best(&mut self) -> Option<usize> {
        self.best_excluding(None)
    }

    /// Like [`Balancer::best`] but never returns `exclude` (used to pick a
    /// different path for a racing retry). Mirrors Go `GetBestConnectionExcluding`.
    pub fn best_excluding(&mut self, exclude: Option<usize>) -> Option<usize> {
        if self.active_ids.is_empty() {
            return None;
        }
        if self.strategy == Strategy::Random {
            if exclude.is_none() {
                let n = self.active_ids.len();
                let r = self.next_random() as usize % n;
                return Some(self.active_ids[r]);
            }
            let ordered = self.rotated_active_indices(1);
            return ordered.into_iter().find(|&idx| Some(idx) != exclude);
        }

        if let Some((pool, pick)) = self.strategy_candidate_pool(exclude) {
            if pool.is_empty() {
                return self.round_robin_best(exclude);
            }
            return self.pick_from_pool(&pool, pick);
        }

        match self.strategy_scorer() {
            Some((scorer, has_signal)) if has_signal => self.best_scored(scorer, exclude),
            _ => self.round_robin_best(exclude),
        }
    }

    /// Pick up to `required` distinct paths. Mirrors Go
    /// `getUniqueConnectionsLocked`.
    pub fn select(&mut self, required: i32) -> Vec<usize> {
        let count = normalize_required_count(self.active_ids.len(), required, 1);
        if count == 0 {
            return Vec::new();
        }
        if self.strategy == Strategy::Random {
            return self.select_random(count);
        }
        if let Some((pool, pick)) = self.strategy_candidate_pool(None) {
            if pool.is_empty() {
                return self.select_round_robin(count);
            }
            return self.limit_connection_pool(&pool, count, pick);
        }
        match self.strategy_scorer() {
            Some((scorer, has_signal)) if has_signal => self.select_lowest_score(count, scorer),
            _ => self.select_round_robin(count),
        }
    }

    /// The scorer and its signal gate for the plain scoring strategies (3/4/5),
    /// or `None` for the round-robin/pool strategies. Mirrors Go
    /// `strategyScorerLocked`.
    fn strategy_scorer(&self) -> Option<(Scorer, bool)> {
        match self.strategy {
            Strategy::LeastLoss => Some((ConnectionStats::loss_score, self.has_loss_signal())),
            Strategy::LowestLatency => {
                Some((ConnectionStats::latency_score, self.has_latency_signal()))
            }
            Strategy::HybridScore => {
                Some((ConnectionStats::hybrid_score, self.has_hybrid_signal()))
            }
            _ => None,
        }
    }

    /// The candidate pool and pick mode for the pool strategies (6/7/8), or
    /// `None` for the others. An empty pool with `Some` means "no signal, fall
    /// back to round-robin". Mirrors Go `strategyCandidatePoolLocked`.
    fn strategy_candidate_pool(
        &mut self,
        exclude: Option<usize>,
    ) -> Option<(Vec<usize>, PoolPick)> {
        match self.strategy {
            Strategy::LossThenLatency => {
                if !self.has_hybrid_signal() {
                    return Some((Vec::new(), PoolPick::Random));
                }
                Some((self.loss_then_latency_candidates(exclude), PoolPick::Random))
            }
            Strategy::LeastLossTopRandom => {
                if !self.has_loss_signal() {
                    return Some((Vec::new(), PoolPick::Random));
                }
                Some((self.least_loss_top_candidates(exclude), PoolPick::Random))
            }
            Strategy::LeastLossTopRoundRobin => {
                if !self.has_loss_signal() {
                    return Some((Vec::new(), PoolPick::RoundRobin));
                }
                Some((
                    self.least_loss_top_candidates(exclude),
                    PoolPick::RoundRobin,
                ))
            }
            _ => None,
        }
    }

    /// The active indices rotated so the round-robin cursor's current position
    /// comes first. Advances the cursor by `step`. Mirrors Go
    /// `rotatedActiveIndicesLocked`.
    fn rotated_active_indices(&mut self, step: u64) -> Vec<usize> {
        let n = self.active_ids.len();
        if n == 0 {
            return Vec::new();
        }
        let step = step.max(1);
        let start = round_robin_start_index(self.rr_advance(step), n);
        (0..n).map(|i| self.active_ids[(start + i) % n]).collect()
    }

    fn round_robin_best(&mut self, exclude: Option<usize>) -> Option<usize> {
        if self.active_ids.is_empty() {
            return None;
        }
        if exclude.is_none() {
            let n = self.active_ids.len();
            let pos = round_robin_start_index(self.rr_advance(1), n);
            return Some(self.active_ids[pos]);
        }
        self.rotated_active_indices(1)
            .into_iter()
            .find(|&idx| Some(idx) != exclude)
    }

    fn best_scored(&mut self, scorer: Scorer, exclude: Option<usize>) -> Option<usize> {
        let ordered = self.rotated_active_indices(1);
        let mut best_index: Option<usize> = None;
        let mut best_score = 0u64;
        for idx in ordered {
            if Some(idx) == exclude {
                continue;
            }
            let score = scorer(&self.stats[idx]);
            if best_index.is_none() || score < best_score {
                best_index = Some(idx);
                best_score = score;
            }
        }
        best_index
    }

    fn pick_from_pool(&mut self, pool: &[usize], pick: PoolPick) -> Option<usize> {
        if pool.is_empty() {
            return None;
        }
        match pick {
            PoolPick::RoundRobin => {
                let pos = round_robin_start_index(self.rr_advance(1), pool.len());
                Some(pool[pos])
            }
            PoolPick::Random => {
                let r = self.next_random() as usize % pool.len();
                Some(pool[r])
            }
        }
    }

    fn select_round_robin(&mut self, count: usize) -> Vec<usize> {
        let n = self.active_ids.len();
        if n == 0 || count == 0 {
            return Vec::new();
        }
        let start = round_robin_start_index(self.rr_advance(count as u64), n);
        (0..count)
            .map(|i| self.active_ids[(start + i) % n])
            .collect()
    }

    fn select_random(&mut self, count: usize) -> Vec<usize> {
        let n = self.active_ids.len();
        if count == 0 || n == 0 {
            return Vec::new();
        }
        if count == 1 {
            let r = self.next_random() as usize % n;
            return vec![self.active_ids[r]];
        }
        let mut indices = self.active_ids.clone();
        for i in 0..count {
            let j = i + (self.next_random() as usize % (n - i));
            indices.swap(i, j);
        }
        indices.truncate(count);
        indices
    }

    fn select_lowest_score(&mut self, count: usize, scorer: Scorer) -> Vec<usize> {
        let n = self.active_ids.len();
        if count == 0 || n == 0 {
            return Vec::new();
        }
        if count == 1 {
            return self.best_scored(scorer, None).into_iter().collect();
        }
        let ordered = self.rotated_active_indices(count as u64);
        let mut scored: Vec<(usize, u64)> = ordered
            .iter()
            .map(|&idx| (idx, scorer(&self.stats[idx])))
            .collect();
        // Partial selection sort: pull the `count` lowest to the front, keeping
        // the rotated order as the tie-break (strict `<`).
        for i in 0..count.min(n) {
            let mut min_idx = i;
            for j in (i + 1)..n {
                if scored[j].1 < scored[min_idx].1 {
                    min_idx = j;
                }
            }
            scored.swap(i, min_idx);
        }
        scored.into_iter().take(count).map(|(idx, _)| idx).collect()
    }

    fn limit_connection_pool(
        &mut self,
        pool: &[usize],
        count: usize,
        pick: PoolPick,
    ) -> Vec<usize> {
        if pool.is_empty() {
            return Vec::new();
        }
        if count >= pool.len() {
            return pool.to_vec();
        }
        if pick == PoolPick::RoundRobin {
            let start = round_robin_start_index(self.rr_advance(count as u64), pool.len());
            return (0..count).map(|i| pool[(start + i) % pool.len()]).collect();
        }
        pool[..count].to_vec()
    }

    /// Strategy 6 pool: a loss tier (within 25 per-mille of the best, or exact
    /// when the best is still probation/unknown), then a latency sub-tier within
    /// a small ms tolerance of that tier's best. Mirrors Go
    /// `lossThenLatencyCandidatesLocked`.
    fn loss_then_latency_candidates(&self, exclude: Option<usize>) -> Vec<usize> {
        if !self.has_hybrid_signal() || self.active_ids.is_empty() {
            return Vec::new();
        }
        let mut candidates: Vec<(usize, u64, u64)> = Vec::with_capacity(self.active_ids.len());
        let mut best_loss = u64::MAX;
        for &idx in &self.active_ids {
            if Some(idx) == exclude {
                continue;
            }
            let loss = self.stats[idx].loss_score();
            let latency = self.stats[idx].hybrid_latency_penalty();
            if loss < best_loss {
                best_loss = loss;
            }
            candidates.push((idx, loss, latency));
        }
        if candidates.is_empty() {
            return Vec::new();
        }

        let loss_tolerance = if best_loss >= 200 { 0 } else { 25 };
        let loss_cutoff = best_loss + loss_tolerance;

        let mut shortlist: Vec<(usize, u64, u64)> = Vec::with_capacity(candidates.len());
        let mut best_latency = u64::MAX;
        for cand in candidates {
            if cand.1 > loss_cutoff {
                continue;
            }
            if cand.2 < best_latency {
                best_latency = cand.2;
            }
            shortlist.push(cand);
        }

        let latency_tolerance = latency_tolerance_for_tier(best_latency);
        let latency_cutoff = best_latency + latency_tolerance;

        let selected: Vec<usize> = shortlist
            .iter()
            .filter(|c| c.2 <= latency_cutoff)
            .map(|c| c.0)
            .collect();
        if !selected.is_empty() {
            selected
        } else {
            vec![shortlist[0].0]
        }
    }

    /// Strategy 7/8 pool: the `topCount = max(2, ceil(n/10))` lowest-loss paths
    /// (in active order, strict-`<` tie-break). Mirrors Go
    /// `leastLossTopTierCandidatesLocked`.
    fn least_loss_top_candidates(&self, exclude: Option<usize>) -> Vec<usize> {
        let mut candidates: Vec<(usize, u64)> = Vec::with_capacity(self.active_ids.len());
        for &idx in &self.active_ids {
            if Some(idx) == exclude {
                continue;
            }
            candidates.push((idx, self.stats[idx].loss_score()));
        }
        if candidates.is_empty() {
            return Vec::new();
        }
        let mut top_count = 2.max(candidates.len().div_ceil(10));
        if top_count > candidates.len() {
            top_count = candidates.len();
        }
        for i in 0..top_count {
            let mut min_idx = i;
            for j in (i + 1)..candidates.len() {
                if candidates[j].1 < candidates[min_idx].1 {
                    min_idx = j;
                }
            }
            candidates.swap(i, min_idx);
        }
        candidates
            .into_iter()
            .take(top_count)
            .map(|(idx, _)| idx)
            .collect()
    }
}
