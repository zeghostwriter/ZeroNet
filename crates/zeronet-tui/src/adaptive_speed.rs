//! The adaptive speed floor: learn what the user's connection actually
//! delivers and judge the config in use against *that*, instead of a fixed
//! Mbps number that is wrong on both ends — 3 Mbps rejects every server on a
//! throttled mobile network, and passes a visibly broken one on fibre.
//!
//! The idea: remember the best sustained throughput each recent config
//! reached, and set the floor to a fraction of that learned baseline. A config
//! that is *really* slow compared to the last few then trips the floor, while
//! a uniformly slow network simply lowers the baseline so the client does not
//! thrash between servers that are all the ISP allows right now.
//!
//! This module is pure policy (no I/O, no clock): the caller feeds it the
//! sustained speed of each config as it retires, and reads back an effective
//! floor in bytes per second to compare live throughput against. It is the
//! Rust reference for the same logic in the Android engine's slow-switch.

use std::collections::VecDeque;

/// How many recent configs' speeds shape the baseline.
const HISTORY: usize = 5;
/// The floor is this fraction of the learned baseline (2/5 = 40%): a config
/// under it is "really slow" next to what the user just had.
const SLOW_NUMERATOR: u64 = 2;
const SLOW_DENOMINATOR: u64 = 5;
/// Below this baseline (64 kbps) the whole path is slow enough that judging one
/// server against another only causes churn, so the floor switches off.
const MIN_BASELINE_BPS: u64 = 8_000;

/// A rolling memory of recent per-config sustained speeds, in bytes per second.
#[derive(Debug, Default, Clone)]
pub struct AdaptiveFloor {
    recent: VecDeque<u64>,
}

impl AdaptiveFloor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the best sustained speed (bytes/s) a config reached before it was
    /// left. Zero and near-zero samples are ignored: a config that never
    /// carried traffic says nothing about how fast the network is.
    pub fn record(&mut self, sustained_bps: u64) {
        if sustained_bps < MIN_BASELINE_BPS {
            return;
        }
        if self.recent.len() == HISTORY {
            self.recent.pop_front();
        }
        self.recent.push_back(sustained_bps);
    }

    /// The learned baseline: the median of recent speeds, once at least two
    /// configs have been seen (one is not a comparison).
    pub fn baseline(&self) -> Option<u64> {
        if self.recent.len() < 2 {
            return None;
        }
        let mut sorted: Vec<u64> = self.recent.iter().copied().collect();
        sorted.sort_unstable();
        let mid = sorted.len() / 2;
        Some(if sorted.len().is_multiple_of(2) {
            (sorted[mid - 1] + sorted[mid]) / 2
        } else {
            sorted[mid]
        })
    }

    /// The floor to compare live throughput against, in bytes per second. Zero
    /// means "do not judge": too little history, or a network slow enough that
    /// every server is near the baseline anyway.
    pub fn effective_floor_bps(&self) -> u64 {
        match self.baseline() {
            Some(base) if base >= MIN_BASELINE_BPS => base * SLOW_NUMERATOR / SLOW_DENOMINATOR,
            _ => 0,
        }
    }

    /// Whether `current_bps` is really slow compared to the last two configs —
    /// below the adaptive floor *and* slower than each of the previous two, so
    /// one lucky fast reading does not condemn a config on its own.
    pub fn too_slow(&self, current_bps: u64) -> bool {
        let floor = self.effective_floor_bps();
        if floor == 0 || current_bps >= floor {
            return false;
        }
        let n = self.recent.len();
        current_bps < self.recent[n - 1] && current_bps < self.recent[n - 2]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: u64 = 1_000_000;

    #[test]
    fn no_floor_until_two_configs_are_known() {
        let mut f = AdaptiveFloor::new();
        assert_eq!(f.effective_floor_bps(), 0);
        f.record(5 * MB);
        assert_eq!(f.baseline(), None, "one config is not a comparison");
        assert_eq!(f.effective_floor_bps(), 0);
        assert!(!f.too_slow(1)); // nothing to judge against
    }

    #[test]
    fn a_config_far_below_recent_fast_ones_is_too_slow() {
        let mut f = AdaptiveFloor::new();
        f.record(5 * MB);
        f.record(6 * MB);
        // baseline 5.5 MB/s → floor 40% ≈ 2.2 MB/s.
        assert_eq!(f.effective_floor_bps(), 5_500_000 * 2 / 5);
        assert!(f.too_slow(500_000), "half a MB/s next to ~5 is really slow");
        assert!(!f.too_slow(4 * MB), "a healthy config is kept");
    }

    #[test]
    fn a_uniformly_slow_network_does_not_thrash() {
        // Every recent config was ~240 kbps: the network is just slow, but
        // still above the minimum, so a baseline forms. A comparable-speed
        // current config must not be dropped, while one an order of magnitude
        // worse still trips.
        let mut f = AdaptiveFloor::new();
        f.record(30_000); // ~240 kbps
        f.record(28_000);
        assert!(!f.too_slow(27_000), "must not thrash on a slow network");
        assert!(
            f.too_slow(3_000),
            "a config far below even the slow baseline drops"
        );
    }

    #[test]
    fn a_baseline_below_the_minimum_switches_the_floor_off() {
        let mut f = AdaptiveFloor::new();
        // Both below MIN_BASELINE_BPS: ignored entirely.
        f.record(1_000);
        f.record(2_000);
        assert_eq!(f.baseline(), None, "sub-floor samples are not recorded");
        assert_eq!(f.effective_floor_bps(), 0);
    }

    #[test]
    fn the_baseline_follows_the_last_few_configs() {
        let mut f = AdaptiveFloor::new();
        for _ in 0..HISTORY {
            f.record(10 * MB);
        }
        assert_eq!(f.baseline(), Some(10 * MB));
        // The window rolls: newer, slower configs pull the baseline down.
        for _ in 0..HISTORY {
            f.record(MB);
        }
        assert_eq!(f.baseline(), Some(MB), "old fast readings age out");
    }

    #[test]
    fn one_fast_reading_alone_does_not_condemn_a_config() {
        let mut f = AdaptiveFloor::new();
        f.record(10 * MB);
        f.record(20_000); // a slow config recorded most recently
                          // Current is below the floor (40% of median 5.01MB ≈ 2MB) but it is
                          // NOT slower than both of the last two (the 20 kB/s one), so it holds.
        assert!(!f.too_slow(MB));
    }
}
