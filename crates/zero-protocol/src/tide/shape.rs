//! Keeping a session's up/down byte ratio inside what browsing looks like.
//!
//! How this works. A censor that watches a flow over time flags one that
//! sends far more than it receives: a browsing session pulls pages down and
//! pushes little up. A tunnel carrying an upload (a backup, a video call's
//! outgoing half, a link opened on a slow server) looks like the opposite. The
//! server cannot change how much the client uploads, but it can send *more*
//! in the other direction: padding frames the client's session skips.
//!
//! The [`Shaper`] keeps two decaying totals, bytes received (up) and bytes
//! sent (down), and a target `down >= ratio * up`. The shortfall is a *debt*.
//! Debt is paid in bursts, only at the moment a chunk is being cut anyway
//! (a phone's radio is already awake then; a constant trickle would keep it
//! awake for good), and never as a steady rate, which would be a signature of
//! its own. Burst sizes are random, so no two sessions show the same numbers.
//!
//! The rules it keeps:
//!  * with no upload there is no debt, so an idle or download-only session
//!    gets no padding at all and pays nothing for this;
//!  * padding is bounded by `ratio` times what was uploaded, so the overhead
//!    never exceeds that fraction of the upload (`Light` 0.5, `Full` 2.0);
//!  * the totals decay (half-life about 20 s), so the ratio is judged over
//!    the recent past, not over the session's whole life.
//!
//! The surprise: the numbers (`ratio`, the burst size, the half-life) are
//! hypotheses from the published measurements of what a censor looks for;
//! they have not been tuned against a real one. They are named constants so
//! that tuning is a one-line change.

use std::time::Instant;

use rand::Rng;

/// How much padding a server adds to keep the ratio browsing-like.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShapeLevel {
    /// None: the session sends only what it carries.
    Off,
    /// Down at least half of up. Costs at most half the upload as extra
    /// download.
    #[default]
    Light,
    /// Down at least twice up, for when a path is known to be watched.
    Full,
}

impl ShapeLevel {
    fn ratio(self) -> f64 {
        match self {
            Self::Off => 0.0,
            Self::Light => 0.5,
            Self::Full => 2.0,
        }
    }

    /// Parse a setting: `off`, `light` or `full`.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "off" => Some(Self::Off),
            "light" => Some(Self::Light),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

/// Debt below this is not worth a burst.
const BURST_MIN: f64 = 4096.0;
/// Seconds for the totals to halve.
const HALF_LIFE: f64 = 20.0;

pub struct Shaper {
    ratio: f64,
    up: f64,
    down: f64,
    at: Instant,
}

impl Shaper {
    /// `None` for `Off`, so a session that does not shape carries no state.
    pub fn new(level: ShapeLevel, now: Instant) -> Option<Self> {
        (level != ShapeLevel::Off).then_some(Self {
            ratio: level.ratio(),
            up: 0.0,
            down: 0.0,
            at: now,
        })
    }

    fn decay(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        if elapsed > 0.0 {
            let keep = 0.5f64.powf(elapsed / HALF_LIFE);
            self.up *= keep;
            self.down *= keep;
            self.at = now;
        }
    }

    /// `bytes` arrived from the peer.
    pub fn received(&mut self, bytes: usize, now: Instant) {
        self.decay(now);
        self.up += bytes as f64;
    }

    /// `bytes` went to the peer (real data or padding alike).
    pub fn sent(&mut self, bytes: usize, now: Instant) {
        self.decay(now);
        self.down += bytes as f64;
    }

    /// How many padding bytes to add to the chunk being cut, at most `room`.
    /// Zero when the ratio is already fine or the debt is still small.
    pub fn pad_wanted(&mut self, room: usize, now: Instant) -> usize {
        self.decay(now);
        let debt = self.ratio * self.up - self.down;
        if debt < BURST_MIN || (room as f64) < BURST_MIN / 4.0 {
            return 0;
        }
        let most = debt.min(room as f64) as usize;
        rand::thread_rng().gen_range(most / 4..=most).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(start: Instant, seconds: u64) -> Instant {
        start + Duration::from_secs(seconds)
    }

    #[test]
    fn off_keeps_no_state() {
        assert!(Shaper::new(ShapeLevel::Off, Instant::now()).is_none());
    }

    #[test]
    fn an_idle_or_download_only_session_is_never_padded() {
        let start = Instant::now();
        let mut shaper = Shaper::new(ShapeLevel::Full, start).unwrap();
        for second in 0..60 {
            shaper.sent(50_000, at(start, second));
            assert_eq!(shaper.pad_wanted(16_000, at(start, second)), 0);
        }
    }

    #[test]
    fn an_upload_with_no_answer_is_padded_but_never_above_the_ratio() {
        let start = Instant::now();
        let mut shaper = Shaper::new(ShapeLevel::Light, start).unwrap();
        let (mut up, mut padded) = (0usize, 0usize);
        // One second of 1 MB/s upload, with a chunk cut every 16 KB received.
        for step in 0..64 {
            let now = start + Duration::from_millis(step * 15);
            shaper.received(16_000, now);
            up += 16_000;
            let pad = shaper.pad_wanted(16_000, now);
            assert!(pad <= 16_000);
            shaper.sent(pad, now);
            padded += pad;
        }
        assert!(padded > 0, "an upload-only flow got no padding");
        assert!(
            padded as f64 <= 0.5 * up as f64 + 1.0,
            "{padded} bytes of padding for {up} up"
        );
    }

    #[test]
    fn real_downloads_pay_the_debt_so_no_padding_is_added() {
        let start = Instant::now();
        let mut shaper = Shaper::new(ShapeLevel::Light, start).unwrap();
        shaper.received(200_000, start);
        shaper.sent(150_000, start);
        assert_eq!(shaper.pad_wanted(16_000, start), 0);
    }

    #[test]
    fn the_past_fades_so_a_quiet_spell_clears_the_debt() {
        let start = Instant::now();
        let mut shaper = Shaper::new(ShapeLevel::Full, start).unwrap();
        shaper.received(1_000_000, start);
        assert!(shaper.pad_wanted(16_000, start) > 0);
        assert_eq!(shaper.pad_wanted(16_000, at(start, 400)), 0);
    }

    #[test]
    fn bursts_differ_from_one_call_to_the_next() {
        let start = Instant::now();
        let sizes: std::collections::HashSet<usize> = (0..50)
            .map(|_| {
                let mut shaper = Shaper::new(ShapeLevel::Full, start).unwrap();
                shaper.received(1_000_000, start);
                shaper.pad_wanted(16_000, start)
            })
            .collect();
        assert!(sizes.len() > 10);
    }

    #[test]
    fn levels_parse() {
        assert_eq!(ShapeLevel::parse("off"), Some(ShapeLevel::Off));
        assert_eq!(ShapeLevel::parse("light"), Some(ShapeLevel::Light));
        assert_eq!(ShapeLevel::parse("full"), Some(ShapeLevel::Full));
        assert_eq!(ShapeLevel::parse("x"), None);
    }
}
