//! The adaptive retransmit timeout (RTO) and its growth on a retransmit.
//!
//! When a packet is sent and later acknowledged, the round-trip sample feeds a
//! smoothed estimate the same way TCP does (Jacobson/Karels): a smoothed RTT
//! (`srtt`), a smoothed variance (`rttvar`), and a base timeout of
//! `srtt + 4*rttvar`, all clamped to `[min, max]`. When a packet goes unacked
//! and has to be resent, its own timeout is multiplied by a fixed growth factor
//! (a mild backoff) and re-clamped.
//!
//! Everything here is whole-nanosecond integer math, matching the Go server's
//! `time.Duration` (an `i64` of nanoseconds) exactly, including the truncating
//! integer divisions. That byte-for-byte agreement is the whole point: a stream
//! that times out a fraction differently on each end desynchronises, so the
//! arithmetic is kept pure and is checked against values the Go code emits
//! (`cmd/arqvec`). The surrounding timer that reads `current_base` and arms the
//! retransmit lives in the ARQ state machine; this module only does the sums.
//!
//! Invariant: `update` is monotone in the clamp — the returned `current_base`
//! is always within `[min_rto, max_rto]`, and the first sample seeds the
//! estimate (`srtt = sample`, `rttvar = sample/2`) rather than blending against
//! an unset zero.

/// A retransmit multiplies a data packet's timeout by this each time it is
/// resent. Matches Go `dataRetransmitRTOGrowthFactor`.
pub const DATA_RETRANSMIT_GROWTH: f64 = 1.35;

/// Growth factor for an ordinary control packet's timeout on retransmit.
/// Matches Go `controlRetransmitRTOGrowthFactor`.
pub const CONTROL_RETRANSMIT_GROWTH: f64 = 1.25;

/// Growth factor for a *setup* control packet (the handshake ones). Gentler
/// than the ordinary control factor because those are already slow to begin
/// with. Matches Go `setupControlRTOGrowthFactor`.
pub const SETUP_CONTROL_GROWTH: f64 = 1.15;

/// The smoothed RTT estimate, in whole nanoseconds.
///
/// Held as an `i64` of nanoseconds to mirror Go's `time.Duration`. `srtt` and
/// `rttvar` are the smoothed mean and variance; `current_base` is the timeout
/// derived from them and clamped. `initialized` records whether a first sample
/// has seeded the estimate yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveRto {
    pub srtt: i64,
    pub rttvar: i64,
    pub current_base: i64,
    pub initialized: bool,
}

impl AdaptiveRto {
    /// A fresh estimate whose timeout starts at `initial_base` (the configured
    /// RTO) until the first sample arrives. Mirrors Go
    /// `adaptiveRTOState{currentBase: rto}`.
    pub fn new(initial_base: i64) -> Self {
        AdaptiveRto {
            srtt: 0,
            rttvar: 0,
            current_base: initial_base,
            initialized: false,
        }
    }

    /// Fold one round-trip `sample` (nanoseconds) into the estimate and return
    /// the updated state, re-clamping the derived base to `[min_rto, max_rto]`.
    /// The sample itself is clamped first, exactly as Go `updateAdaptiveRTO`.
    #[must_use]
    pub fn update(mut self, sample: i64, min_rto: i64, max_rto: i64) -> Self {
        let sample = clamp(sample, min_rto, max_rto);
        if !self.initialized {
            self.srtt = sample;
            self.rttvar = sample / 2;
            self.initialized = true;
        } else {
            let delta = (self.srtt - sample).abs();
            self.rttvar = (3 * self.rttvar + delta) / 4;
            self.srtt = (7 * self.srtt + sample) / 8;
        }
        self.current_base = clamp(self.srtt + 4 * self.rttvar, min_rto, max_rto);
        self
    }
}

/// Clamp `v` into `[lo, hi]`. Mirrors Go `clampDuration`; `lo` is assumed not
/// to exceed `hi`, the way the caller always arranges.
#[inline]
pub fn clamp(v: i64, lo: i64, hi: i64) -> i64 {
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

/// Grow a packet's `current` timeout by `factor` and clamp into `[floor, max]`.
/// The multiply is done in `f64` and truncated toward zero on the way back to
/// nanoseconds, matching Go's `time.Duration(float64(current) * factor)`.
#[inline]
pub fn grow(current: i64, factor: f64, floor: i64, max: i64) -> i64 {
    clamp((current as f64 * factor) as i64, floor, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Values emitted by the Go `cmd/arqvec` harness (whole nanoseconds), so a
    // pass means the Rust integer/float math lands on the same bytes as the
    // server's `time.Duration` arithmetic.
    const MIN: i64 = 50_000_000;
    const MAX: i64 = 5_000_000_000;
    const INIT: i64 = 1_000_000_000;

    // (sample, srtt, rttvar, current_base) after each update, in order.
    const UPDATE_STEPS: &[(i64, i64, i64, i64)] = &[
        (120_000_000, 120_000_000, 60_000_000, 360_000_000),
        (80_000_000, 115_000_000, 55_000_000, 335_000_000),
        (300_000_000, 138_125_000, 87_500_000, 488_125_000),
        (95_000_000, 132_734_375, 76_406_250, 438_359_375),
        (1_500_000_000, 303_642_578, 399_121_093, 1_900_126_950),
        (40_000_000, 271_937_255, 362_751_464, 1_722_943_111),
        (210_000_000, 264_195_098, 287_547_911, 1_414_386_742),
    ];

    #[test]
    fn adaptive_update_matches_go_vectors() {
        let mut state = AdaptiveRto::new(INIT);
        for &(sample, srtt, rttvar, base) in UPDATE_STEPS {
            state = state.update(sample, MIN, MAX);
            assert_eq!(state.srtt, srtt, "srtt after sample {sample}");
            assert_eq!(state.rttvar, rttvar, "rttvar after sample {sample}");
            assert_eq!(
                state.current_base, base,
                "current_base after sample {sample}"
            );
        }
    }

    #[test]
    fn first_sample_seeds_without_blending() {
        // The clamp applies to the sample before it seeds: a sub-min first
        // sample seeds at the floor, not at the raw value.
        let state = AdaptiveRto::new(INIT).update(10_000_000, MIN, MAX);
        assert_eq!(state.srtt, MIN);
        assert_eq!(state.rttvar, MIN / 2);
    }

    // (current, factor, floor, max, result) from the Go harness.
    const GROW_STEPS: &[(i64, f64, i64, i64, i64)] = &[
        (
            1_000_000_000,
            1.35,
            50_000_000,
            5_000_000_000,
            1_350_000_000,
        ),
        (
            4_000_000_000,
            1.35,
            50_000_000,
            5_000_000_000,
            5_000_000_000,
        ),
        (500_000_000, 1.25, 50_000_000, 3_000_000_000, 625_000_000),
        (300_000_000, 1.15, 350_000_000, 3_000_000_000, 350_000_000),
        (10_000_000, 1.35, 50_000_000, 5_000_000_000, 50_000_000),
    ];

    #[test]
    fn grow_matches_go_vectors() {
        for &(current, factor, floor, max, result) in GROW_STEPS {
            assert_eq!(
                grow(current, factor, floor, max),
                result,
                "grow({current}, {factor})"
            );
        }
    }

    #[test]
    fn clamp_bounds_both_ends() {
        assert_eq!(clamp(5, 10, 20), 10);
        assert_eq!(clamp(25, 10, 20), 20);
        assert_eq!(clamp(15, 10, 20), 15);
    }
}
