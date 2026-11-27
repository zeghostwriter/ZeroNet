//! Dialog open and close animation.
//!
//! A dialog cannot simply vanish when it is dismissed — that reads as a
//! glitch rather than an action. So dialogs have a lifecycle:
//!
//! ```text
//! None ──open──> Opening ──> Open ──dismiss──> Closing ──> None
//! ```
//!
//! The renderer draws whatever phase it is in; the frame loop drops the
//! dialog only once `Closing` has finished. That is the whole reason this is
//! a state machine and not a boolean.
//!
//! ## The animation
//!
//! Terminals have coarse rows and fine columns, so an effect that moves
//! mostly *vertically* reads as smooth while one that scales both axes
//! equally judders. The dialog therefore opens like a camera aperture:
//!
//! 1. **Slit** (first third) — a bright line at the dialog's centre row grows
//!    out horizontally to full width.
//! 2. **Unfold** (remaining two thirds) — the panel opens vertically from
//!    that line, easing out so it decelerates into place.
//! 3. **Content** fades in over the second half, so text never appears in a
//!    box that is still moving.
//!
//! Closing runs the same shape in reverse and faster — roughly two thirds the
//! duration — because a dismissal should feel immediate while still being
//! visible. The easing is flipped too: `ease_in` on the way out, so it lingers
//! for a frame and then snaps away.

use ratatui::layout::Rect;

/// Ticks the opening animation runs for, at 30 fps.
pub const OPEN_TICKS: u64 = 9;
/// Ticks the closing animation runs for. Deliberately shorter.
pub const CLOSE_TICKS: u64 = 6;
/// Fraction of the opening spent on the horizontal slit.
const SLIT_FRACTION: f64 = 0.34;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalPhase {
    Opening,
    Open,
    Closing,
}

/// Animation state for the dialog currently on screen.
#[derive(Debug, Clone, Copy)]
pub struct ModalAnimator {
    phase: ModalPhase,
    started_tick: u64,
    /// Set when the dialog is nudged instead of dismissed — a backdrop click
    /// on a form that holds typed input.
    nudge_tick: Option<u64>,
}

impl Default for ModalAnimator {
    fn default() -> Self {
        Self {
            phase: ModalPhase::Open,
            started_tick: 0,
            nudge_tick: None,
        }
    }
}

impl ModalAnimator {
    /// Begin opening a dialog.
    pub fn opening(tick: u64) -> Self {
        Self {
            phase: ModalPhase::Opening,
            started_tick: tick,
            nudge_tick: None,
        }
    }

    pub fn phase(&self) -> ModalPhase {
        self.phase
    }

    /// Ask the dialog to close. Idempotent: a second request while already
    /// closing does not restart the animation.
    pub fn begin_close(&mut self, tick: u64) {
        if self.phase != ModalPhase::Closing {
            self.phase = ModalPhase::Closing;
            self.started_tick = tick;
            self.nudge_tick = None;
        }
    }

    /// Flash the dialog's border without dismissing it.
    ///
    /// Used when a backdrop click lands on a dialog that holds unsaved input:
    /// silently discarding what someone typed is worse than not closing.
    pub fn nudge(&mut self, tick: u64) {
        self.nudge_tick = Some(tick);
    }

    /// How strongly the border should be flashing right now, `0.0..=1.0`.
    pub fn nudge_intensity(&self, tick: u64) -> f64 {
        const NUDGE_TICKS: u64 = 8;
        let Some(start) = self.nudge_tick else {
            return 0.0;
        };
        let elapsed = tick.saturating_sub(start);
        if elapsed >= NUDGE_TICKS {
            return 0.0;
        }
        // Two quick pulses, decaying.
        let t = elapsed as f64 / NUDGE_TICKS as f64;
        let pulse = (t * std::f64::consts::PI * 2.0).sin().abs();
        pulse * (1.0 - t)
    }

    /// Whether the animation has run its course.
    ///
    /// Only meaningful while closing: that is the signal for the frame loop
    /// to actually drop the dialog.
    pub fn is_finished(&self, tick: u64) -> bool {
        let elapsed = tick.saturating_sub(self.started_tick);
        match self.phase {
            ModalPhase::Opening => elapsed >= OPEN_TICKS,
            ModalPhase::Open => false,
            ModalPhase::Closing => elapsed >= CLOSE_TICKS,
        }
    }

    /// Promote `Opening` to `Open` once it has finished.
    pub fn settle(&mut self, tick: u64) {
        if self.phase == ModalPhase::Opening && self.is_finished(tick) {
            self.phase = ModalPhase::Open;
        }
    }

    /// Whether the dialog should still be drawn at all.
    pub fn is_visible(&self, tick: u64) -> bool {
        self.phase != ModalPhase::Closing || !self.is_finished(tick)
    }

    /// Linear progress through the current phase, `0.0..=1.0`.
    ///
    /// Easing is applied *per sub-phase* rather than to this, because easing
    /// the whole timeline compressed the slit into a single frame: an
    /// ease-out is already 30% complete after one tick of nine.
    fn linear_progress(&self, tick: u64) -> f64 {
        let elapsed = tick.saturating_sub(self.started_tick) as f64;
        match self.phase {
            ModalPhase::Open => 1.0,
            ModalPhase::Opening => (elapsed / OPEN_TICKS as f64).clamp(0.0, 1.0),
            // Reversed: 1.0 is fully open, 0.0 is gone.
            ModalPhase::Closing => 1.0 - (elapsed / CLOSE_TICKS as f64).clamp(0.0, 1.0),
        }
    }

    /// Whether this phase decelerates (opening) or accelerates (closing).
    fn ease(&self, t: f64) -> f64 {
        match self.phase {
            ModalPhase::Closing => ease_in_cubic(t),
            _ => ease_out_cubic(t),
        }
    }

    /// The rectangle the dialog occupies this frame.
    ///
    /// `target` is where it lives when fully open. During the slit phase the
    /// height collapses to a single row at the target's centre; afterwards it
    /// unfolds vertically to the full height. The width grows only during the
    /// slit, so the panel never looks squashed horizontally.
    pub fn rect(&self, target: Rect, tick: u64) -> Rect {
        let p = self.linear_progress(tick);
        if p >= 1.0 {
            return target;
        }
        if p <= 0.0 {
            // A single cell at the centre — the very start of the aperture.
            return Rect {
                x: target.x + target.width / 2,
                y: target.y + target.height / 2,
                width: 1,
                height: 1,
            };
        }

        let (width_t, height_t) = if p < SLIT_FRACTION {
            // Slit: widen, stay one row tall.
            (self.ease(p / SLIT_FRACTION), 0.0)
        } else {
            // Unfold: full width, grow vertically.
            (1.0, self.ease((p - SLIT_FRACTION) / (1.0 - SLIT_FRACTION)))
        };

        // At least one cell in each axis, so the panel is never zero-sized
        // and the border always has somewhere to draw.
        let width = ((target.width as f64 * width_t).round() as u16).max(1);
        let height = ((target.height as f64 * height_t).round() as u16).max(1);

        Rect {
            x: target.x + (target.width.saturating_sub(width)) / 2,
            y: target.y + (target.height.saturating_sub(height)) / 2,
            width,
            height,
        }
    }

    /// How visible the dialog's contents should be, `0.0..=1.0`.
    ///
    /// Content appears only in the second half of the opening, so text is
    /// never drawn into a box that is still growing — which would otherwise
    /// show it reflowing on every frame.
    pub fn content_alpha(&self, tick: u64) -> f64 {
        let p = self.linear_progress(tick);
        match self.phase {
            ModalPhase::Open => 1.0,
            // Content drops out immediately on close: fading text while the
            // panel shrinks under it looks like two separate animations.
            ModalPhase::Closing => 0.0,
            ModalPhase::Opening => ((p - 0.5) / 0.5).clamp(0.0, 1.0),
        }
    }

    /// Whether the contents are worth drawing at all this frame.
    pub fn shows_content(&self, tick: u64) -> bool {
        self.content_alpha(tick) > 0.05
    }
}

/// Decelerating ease — fast out of the gate, settling into place.
fn ease_out_cubic(t: f64) -> f64 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

/// Accelerating ease — hesitates, then snaps.
fn ease_in_cubic(t: f64) -> f64 {
    let t = t.clamp(0.0, 1.0);
    t * t * t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Rect {
        Rect {
            x: 20,
            y: 10,
            width: 60,
            height: 20,
        }
    }

    #[test]
    fn easing_curves_span_zero_to_one() {
        for f in [ease_out_cubic, ease_in_cubic] {
            assert!((f(0.0) - 0.0).abs() < 1e-9);
            assert!((f(1.0) - 1.0).abs() < 1e-9);
            // Monotonic.
            let mut previous = -1.0;
            for i in 0..=20 {
                let v = f(i as f64 / 20.0);
                assert!(v >= previous, "not monotonic at {i}");
                previous = v;
            }
        }
        // Ease-out is ahead of linear early on; ease-in is behind.
        assert!(ease_out_cubic(0.25) > 0.25);
        assert!(ease_in_cubic(0.25) < 0.25);
    }

    #[test]
    fn opening_grows_from_a_point_to_the_target() {
        let anim = ModalAnimator::opening(0);
        let first = anim.rect(target(), 0);
        assert_eq!((first.width, first.height), (1, 1));

        let last = anim.rect(target(), OPEN_TICKS);
        assert_eq!(last, target());
    }

    #[test]
    fn the_slit_phase_widens_before_it_unfolds() {
        let anim = ModalAnimator::opening(0);
        let t = target();

        // The slit occupies the first third of the opening, which at nine
        // ticks is three frames — long enough to actually see.
        for tick in 1..=2 {
            let frame = anim.rect(t, tick);
            assert_eq!(frame.height, 1, "height grew during the slit at {tick}");
            assert!(frame.width > 1, "the slit did not widen at {tick}");
        }

        // Then: full width, growing height.
        let later = anim.rect(t, 5);
        assert_eq!(later.width, t.width);
        assert!(later.height > 1);
        assert!(later.height < t.height);
    }

    #[test]
    fn the_opening_uses_its_whole_duration() {
        // Easing the global timeline made the panel effectively finished by
        // tick three of nine, which looked like a jump rather than a motion.
        let anim = ModalAnimator::opening(0);
        let t = target();
        let midpoint = anim.rect(t, OPEN_TICKS / 2);
        assert!(
            midpoint.height < t.height,
            "the panel was already full height halfway through"
        );

        // And it visibly moves on most frames.
        let heights: Vec<u16> = (0..=OPEN_TICKS).map(|k| anim.rect(t, k).height).collect();
        let distinct = heights
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(
            distinct >= 5,
            "only {distinct} distinct heights across the opening"
        );
    }

    #[test]
    fn every_frame_stays_inside_the_target_and_centred() {
        let anim = ModalAnimator::opening(0);
        let t = target();
        for tick in 0..=OPEN_TICKS {
            let r = anim.rect(t, tick);
            assert!(r.width <= t.width && r.height <= t.height);
            assert!(r.x >= t.x && r.y >= t.y);
            assert!(r.x + r.width <= t.x + t.width);
            assert!(r.y + r.height <= t.y + t.height);
            assert!(r.width >= 1 && r.height >= 1, "zero-sized frame at {tick}");

            // Centred within a cell of rounding.
            let centre_offset = (r.x + r.width / 2) as i32 - (t.x + t.width / 2) as i32;
            assert!(centre_offset.abs() <= 1, "off-centre at {tick}");
        }
    }

    #[test]
    fn content_appears_only_in_the_second_half_of_the_opening() {
        // Text drawn into a box that is still growing reflows every frame.
        let anim = ModalAnimator::opening(0);
        assert_eq!(anim.content_alpha(0), 0.0);
        assert!(!anim.shows_content(1));
        assert!(anim.shows_content(OPEN_TICKS));
        assert_eq!(anim.content_alpha(OPEN_TICKS), 1.0);
    }

    #[test]
    fn closing_shrinks_back_and_then_finishes() {
        let mut anim = ModalAnimator::opening(0);
        anim.settle(OPEN_TICKS);
        assert_eq!(anim.phase(), ModalPhase::Open);

        anim.begin_close(100);
        assert_eq!(anim.phase(), ModalPhase::Closing);
        assert!(anim.is_visible(100));

        // Shrinking.
        let mid = anim.rect(target(), 100 + CLOSE_TICKS / 2);
        assert!(mid.height < target().height);
        // Content is gone at once.
        assert!(!anim.shows_content(101));

        assert!(anim.is_finished(100 + CLOSE_TICKS));
        assert!(!anim.is_visible(100 + CLOSE_TICKS));
    }

    #[test]
    fn closing_is_quicker_than_opening() {
        // A dismissal that takes as long as an appearance feels sluggish.
        const _: () = assert!(CLOSE_TICKS < OPEN_TICKS);

        // And both are short enough to feel like part of the click: at 30 fps
        // anything past ~400ms reads as the app being slow.
        const _: () = assert!(OPEN_TICKS <= 12);
        const _: () = assert!(CLOSE_TICKS <= 9);
    }

    #[test]
    fn a_second_close_request_does_not_restart_the_animation() {
        let mut anim = ModalAnimator::opening(0);
        anim.begin_close(50);
        anim.begin_close(55);
        // Still measured from the first request, so it completes on time.
        assert!(anim.is_finished(50 + CLOSE_TICKS));
    }

    #[test]
    fn an_open_dialog_never_reports_finished() {
        let mut anim = ModalAnimator::opening(0);
        anim.settle(OPEN_TICKS);
        assert!(!anim.is_finished(10_000));
        assert!(anim.is_visible(10_000));
    }

    #[test]
    fn nudging_pulses_and_then_stops() {
        let mut anim = ModalAnimator::opening(0);
        anim.settle(OPEN_TICKS);
        assert_eq!(anim.nudge_intensity(20), 0.0);

        anim.nudge(20);
        let peak: f64 = (0..8)
            .map(|d| anim.nudge_intensity(20 + d))
            .fold(0.0, f64::max);
        assert!(peak > 0.3, "the nudge is too faint to notice: {peak}");
        assert_eq!(anim.nudge_intensity(40), 0.0, "the nudge never stopped");
    }

    #[test]
    fn closing_clears_a_pending_nudge() {
        // Otherwise a flashing border would follow the dialog out.
        let mut anim = ModalAnimator::opening(0);
        anim.nudge(10);
        anim.begin_close(11);
        assert_eq!(anim.nudge_intensity(12), 0.0);
    }

    #[test]
    fn tiny_targets_do_not_produce_zero_sized_frames() {
        let anim = ModalAnimator::opening(0);
        for (w, h) in [(1u16, 1u16), (2, 1), (3, 3), (5, 2)] {
            let t = Rect {
                x: 0,
                y: 0,
                width: w,
                height: h,
            };
            for tick in 0..=OPEN_TICKS {
                let r = anim.rect(t, tick);
                assert!(r.width >= 1 && r.height >= 1);
                assert!(r.width <= w && r.height <= h);
            }
        }
    }
}
