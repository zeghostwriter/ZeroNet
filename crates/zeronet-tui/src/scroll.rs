//! Scrolling with momentum, acceleration and a rubber-band edge.
//!
//! A plain `scroll += 1` per wheel notch has three problems that make a TUI
//! feel unfinished:
//!
//! * **No acceleration.** Travelling a long list means spinning the wheel.
//!   Consecutive notches here build speed, and the speed decays once the
//!   wheel stops.
//! * **Nothing stops at the end.** An unclamped offset scrolls past the last
//!   line into empty space, and the content appears to vanish upwards.
//! * **No feedback at the limit.** Hitting the end silently is ambiguous —
//!   did it stop because that is the end, or because the input was ignored?
//!   Overscroll is absorbed into a rubber band that springs back, which is
//!   the convention every touch platform settled on.
//!
//! The band is tracked separately from the offset: `offset` is always a valid
//! line index, and `overscroll` is a transient visual displacement. That
//! keeps rendering honest — nothing ever draws a line that does not exist.

/// Notches within this many ticks of each other count as one gesture.
const GESTURE_GAP_TICKS: u64 = 6;
/// Fastest a single notch may move the view, in lines.
const MAX_STEP: f32 = 9.0;
/// Lines a single notch moves when the gesture starts.
const BASE_STEP: f32 = 1.0;
/// How much each consecutive notch adds.
const ACCEL_PER_NOTCH: f32 = 0.9;
/// How far past the end the view may stretch, in lines.
const MAX_OVERSCROLL: f32 = 3.0;
/// Fraction of the rubber band that remains after each tick.
const SPRING_DECAY: f32 = 0.72;
/// Fraction of the remaining distance the smoothed offset covers per tick.
const GLIDE_PER_TICK: f32 = 0.45;

#[derive(Debug, Clone, Copy, Default)]
pub struct ScrollState {
    /// First visible line. Always within `0..=max_offset`.
    offset: usize,
    /// Smooth continuous offset for interpolated frame-by-frame scrolling.
    smooth_offset: f32,
    /// Transient displacement past an edge, in lines. Negative is past the
    /// top, positive past the bottom.
    overscroll: f32,
    /// Notches in the current gesture, for acceleration.
    notches: u32,
    /// Tick of the last notch. `None` before the first one — a plain `0`
    /// sentinel collides with tick zero and made the very first notch look
    /// like a continuation, so it moved two lines instead of one.
    last_notch_tick: Option<u64>,
}

impl ScrollState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Continuous smoothed offset for frame-interpolated rendering.
    pub fn smooth_offset(&self) -> f32 {
        self.smooth_offset
    }

    /// Visual displacement past an edge, in lines.
    ///
    /// Renderers use this to shift content without changing which lines are
    /// considered visible.
    pub fn overscroll(&self) -> f32 {
        self.overscroll
    }

    /// Whether the rubber band is stretched enough to be worth drawing.
    pub fn is_springing(&self) -> bool {
        self.overscroll.abs() > 0.05
    }

    /// Whether anything is still in motion, so the frame loop keeps drawing.
    pub fn is_animating(&self) -> bool {
        self.is_springing() || (self.smooth_offset - self.offset as f32).abs() > 0.05
    }

    /// Apply one wheel notch. `delta` is `-1` for up, `+1` for down.
    ///
    /// `max_offset` is the largest valid offset — `content_lines` minus
    /// `visible_lines`, floored at zero. Passing it per call rather than
    /// storing it means the state cannot go stale when the terminal resizes.
    pub fn scroll(&mut self, delta: i32, max_offset: usize, tick: u64) {
        if delta == 0 {
            return;
        }

        // Consecutive notches accelerate; a pause resets to a single line, so
        // a deliberate one-notch nudge always moves exactly one line.
        let continues = self
            .last_notch_tick
            .is_some_and(|last| tick.saturating_sub(last) <= GESTURE_GAP_TICKS);
        if continues {
            self.notches = self.notches.saturating_add(1);
        } else {
            self.notches = 0;
        }
        self.last_notch_tick = Some(tick);

        let step = (BASE_STEP + self.notches as f32 * ACCEL_PER_NOTCH).min(MAX_STEP);
        let lines = (step.round() as i64) * delta.signum() as i64;

        let target = self.offset as i64 + lines;
        if target < 0 {
            self.offset = 0;
            self.stretch(target as f32);
        } else if target > max_offset as i64 {
            self.offset = max_offset;
            self.stretch((target - max_offset as i64) as f32);
        } else {
            self.offset = target as usize;
            // Moving back inside the content releases the band at once —
            // leaving it stretched while the view moves looks like a glitch.
            self.overscroll = 0.0;
        }
        // Do not snap `smooth_offset` here. `tick` eases it toward `offset`,
        // which is what makes a wheel notch glide instead of jumping a line.
    }

    /// Absorb movement past an edge into the rubber band.
    ///
    /// The band resists progressively: each extra line of overscroll buys
    /// less displacement than the last, so it never runs away.
    fn stretch(&mut self, past_edge: f32) {
        let resisted = past_edge.signum() * (past_edge.abs().sqrt() * 1.4);
        self.overscroll = (self.overscroll + resisted).clamp(-MAX_OVERSCROLL, MAX_OVERSCROLL);
    }

    /// Relax the rubber band and glide the smoothed position by one tick.
    pub fn tick(&mut self) {
        self.advance(1.0);
    }

    /// Relax the rubber band and glide the smoothed position by `dt` ticks
    /// of the animation clock.
    ///
    /// Frame-rate independent: the per-tick decay is raised to the power of
    /// the elapsed ticks, so two half-tick steps land exactly where one
    /// whole-tick step does and a slow terminal settles in the same time as
    /// a fast one.
    pub fn advance(&mut self, dt: f32) {
        if dt <= 0.0 {
            return;
        }
        if self.is_springing() {
            self.overscroll *= SPRING_DECAY.powf(dt);
        }
        if !self.is_springing() {
            self.overscroll = 0.0;
        }

        let target = self.offset as f32;
        let diff = target - self.smooth_offset;
        if diff.abs() > 0.01 {
            // Exponential ease-out towards the target.
            let remaining = (1.0 - GLIDE_PER_TICK).powf(dt);
            self.smooth_offset = target - diff * remaining;
            if (target - self.smooth_offset).abs() < 0.05 {
                self.smooth_offset = target;
            }
        } else {
            self.smooth_offset = target;
        }
    }

    /// Move by whole lines from a key press, with no acceleration.
    ///
    /// Keyboard scrolling is already discrete and repeat-rate limited, so
    /// adding momentum to it just makes the caret unpredictable.
    pub fn step(&mut self, lines: i32, max_offset: usize) {
        let target = (self.offset as i64 + lines as i64).clamp(0, max_offset as i64);
        self.offset = target as usize;
        self.smooth_offset = target as f32;
        self.overscroll = 0.0;
    }

    pub fn to_top(&mut self) {
        self.offset = 0;
        self.smooth_offset = 0.0;
        self.overscroll = 0.0;
    }

    pub fn to_bottom(&mut self, max_offset: usize) {
        self.offset = max_offset;
        self.smooth_offset = max_offset as f32;
        self.overscroll = 0.0;
    }

    /// Clamp the offset after the content or the viewport changed.
    ///
    /// Without this, shrinking the content — filtering a list, resizing the
    /// terminal — leaves the view scrolled past the end and apparently empty.
    pub fn clamp(&mut self, max_offset: usize) {
        if self.offset > max_offset {
            self.offset = max_offset;
            self.smooth_offset = self.smooth_offset.min(max_offset as f32);
            self.overscroll = 0.0;
        }
    }
}

/// Largest valid scroll offset for a body of content in a viewport.
pub fn max_offset(content_lines: usize, visible_lines: usize) -> usize {
    content_lines.saturating_sub(visible_lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_notch_moves_exactly_one_line() {
        // Acceleration must not make a deliberate nudge overshoot — including
        // the very first notch of the session, at tick zero.
        let mut s = ScrollState::new();
        s.scroll(1, 100, 0);
        assert_eq!(s.offset(), 1);

        let mut later = ScrollState::new();
        later.scroll(1, 100, 9_999);
        assert_eq!(later.offset(), 1);
    }

    #[test]
    fn consecutive_notches_accelerate() {
        let mut s = ScrollState::new();
        let mut offsets = Vec::new();
        for tick in 0..6 {
            s.scroll(1, 1000, tick);
            offsets.push(s.offset());
        }
        let steps: Vec<usize> = offsets.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(
            steps.last().unwrap() > steps.first().unwrap(),
            "no acceleration: steps were {steps:?}"
        );
        assert!(
            *steps.last().unwrap() <= MAX_STEP as usize,
            "acceleration exceeded the cap: {steps:?}"
        );
    }

    #[test]
    fn a_pause_resets_the_acceleration() {
        let mut s = ScrollState::new();
        for tick in 0..6 {
            s.scroll(1, 1000, tick);
        }
        let before = s.offset();
        // A long gap: the next notch is a fresh gesture.
        s.scroll(1, 1000, 500);
        assert_eq!(
            s.offset() - before,
            1,
            "acceleration carried across a pause"
        );
    }

    #[test]
    fn the_offset_never_leaves_the_content() {
        // The bug this prevents: scrolling past the end into blank space.
        let mut s = ScrollState::new();
        for tick in 0..60 {
            s.scroll(1, 20, tick);
            assert!(
                s.offset() <= 20,
                "offset {} escaped the content",
                s.offset()
            );
        }
        assert_eq!(s.offset(), 20);

        for tick in 60..120 {
            s.scroll(-1, 20, tick);
            assert!(s.offset() <= 20);
        }
        assert_eq!(s.offset(), 0);
    }

    #[test]
    fn hitting_the_bottom_stretches_a_rubber_band() {
        let mut s = ScrollState::new();
        s.to_bottom(10);
        assert!(!s.is_springing());

        s.scroll(1, 10, 0);
        assert_eq!(s.offset(), 10, "the offset moved past the end");
        assert!(s.overscroll() > 0.0, "no rubber band at the bottom");
        assert!(s.is_springing());
    }

    #[test]
    fn hitting_the_top_stretches_the_other_way() {
        let mut s = ScrollState::new();
        s.scroll(-1, 10, 0);
        assert_eq!(s.offset(), 0);
        assert!(s.overscroll() < 0.0, "no rubber band at the top");
    }

    #[test]
    fn the_band_is_bounded_however_hard_it_is_pushed() {
        let mut s = ScrollState::new();
        s.to_bottom(10);
        for tick in 0..200 {
            s.scroll(1, 10, tick);
            assert!(
                s.overscroll() <= MAX_OVERSCROLL + 1e-3,
                "overscroll ran away to {}",
                s.overscroll()
            );
        }
    }

    #[test]
    fn the_band_springs_back_and_settles() {
        let mut s = ScrollState::new();
        s.to_bottom(10);
        s.scroll(1, 10, 0);
        let stretched = s.overscroll();
        assert!(stretched > 0.0);

        for _ in 0..40 {
            s.tick();
        }
        assert!(
            !s.is_springing(),
            "the band never settled: {}",
            s.overscroll()
        );
        assert_eq!(s.overscroll(), 0.0);
        // And it settles without the offset moving.
        assert_eq!(s.offset(), 10);
    }

    #[test]
    fn scrolling_back_inside_releases_the_band_immediately() {
        let mut s = ScrollState::new();
        s.to_bottom(10);
        s.scroll(1, 10, 0);
        assert!(s.is_springing());

        s.scroll(-1, 10, 60);
        assert!(
            !s.is_springing(),
            "the band survived moving back into the content"
        );
    }

    #[test]
    fn keyboard_stepping_has_no_momentum() {
        let mut s = ScrollState::new();
        for _ in 0..5 {
            s.step(1, 100);
        }
        assert_eq!(s.offset(), 5, "keyboard scrolling accelerated");
        s.step(-99, 100);
        assert_eq!(s.offset(), 0);
    }

    #[test]
    fn clamping_rescues_a_view_left_past_the_end() {
        // Filtering a list or shrinking the terminal can leave the offset
        // beyond the new content, which renders as an empty panel.
        let mut s = ScrollState::new();
        s.to_bottom(100);
        assert_eq!(s.offset(), 100);

        s.clamp(4);
        assert_eq!(s.offset(), 4);
        assert!(!s.is_springing());
    }

    #[test]
    fn content_shorter_than_the_viewport_cannot_scroll() {
        assert_eq!(max_offset(5, 20), 0);
        let mut s = ScrollState::new();
        for tick in 0..10 {
            s.scroll(1, max_offset(5, 20), tick);
        }
        assert_eq!(s.offset(), 0);
        // But it still shows the band, so the gesture is acknowledged.
        assert!(s.is_springing());
    }

    #[test]
    fn max_offset_is_content_minus_viewport() {
        assert_eq!(max_offset(100, 20), 80);
        assert_eq!(max_offset(20, 20), 0);
        assert_eq!(max_offset(0, 20), 0);
    }

    #[test]
    fn wheel_scrolling_eases_instead_of_snapping() {
        let mut s = ScrollState::new();
        s.scroll(1, 100, 0);
        assert_eq!(s.offset(), 1);
        assert!(s.smooth_offset() < 1.0, "the view snapped to the new line");
        assert!(s.is_animating());

        for _ in 0..40 {
            s.tick();
        }
        assert!(!s.is_animating());
        assert!((s.smooth_offset() - 1.0).abs() < 1e-3);
    }

    #[test]
    fn to_top_and_to_bottom_clear_the_band() {
        let mut s = ScrollState::new();
        s.to_bottom(10);
        s.scroll(1, 10, 0);
        s.to_top();
        assert_eq!(s.offset(), 0);
        assert!(!s.is_springing());
    }

    #[test]
    fn settling_does_not_depend_on_the_frame_rate() {
        // Two half-tick steps must land where one whole tick does, or the
        // glide would run faster on a faster terminal.
        let mut coarse = ScrollState::new();
        let mut fine = ScrollState::new();
        coarse.scroll(1, 50, 0);
        fine.scroll(1, 50, 0);
        for _ in 0..3 {
            coarse.advance(1.0);
            fine.advance(0.5);
            fine.advance(0.5);
        }
        assert!((coarse.smooth_offset() - fine.smooth_offset()).abs() < 1e-3);

        let mut band = ScrollState::new();
        band.scroll(-1, 50, 0);
        let mut halves = band;
        band.advance(2.0);
        halves.advance(1.0);
        halves.advance(1.0);
        assert!((band.overscroll() - halves.overscroll()).abs() < 1e-4);
    }
}
