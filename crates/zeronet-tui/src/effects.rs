//! Time-driven visual effects.
//!
//! Everything here is a pure function of an animation clock plus a little
//! particle state, so a frame can be re-derived at any time and nothing has
//! to be torn down when the terminal resizes.
//!
//! ## The clock
//!
//! Time is measured in *ticks* of 1/[`TICKS_PER_SECOND`] s, but the clock is
//! driven by wall time ([`VisualEffects::advance_to`]), not by counting
//! frames. A slow terminal that only manages ten frames a second still sees
//! a dialog open in the same 300 ms, and a burst of input events never makes
//! anything run fast. Continuous effects (glows, sheens, the chromatic wave)
//! read the fractional clock so they move smoothly at any frame rate;
//! lifecycles that count whole steps (dialog open/close, embers) read the
//! integer tick.
//!
//! ## Ambient motion
//!
//! The breathing logo, the status sheen and the connected-orb pulse are
//! *ambient*: decoration that says "alive", not information. The app fades
//! them out (never snaps) when the user has been idle for a while or the
//! terminal loses focus, which is what lets an idle client draw nothing at
//! all. See [`VisualEffects::set_ambient`].
//!
//! Effects report whether they still have something to draw (`is_animating`),
//! which is what lets the main loop skip redraws while the screen is at rest.
//! When the terminal cannot afford animation (see [`crate::caps`]) every
//! animated colour collapses to its resting value and the particle systems
//! produce nothing.

use crate::caps::ColorDepth;
use crate::connect_orb::OrbState;
use crate::theme::{adapt, lerp_color, Palette, ThemeId};
use ratatui::layout::Rect;
use ratatui::style::Color;
use std::time::Instant;

/// Animation clock rate. Every tick-denominated duration in the UI — dialog
/// open/close, ember lifetime, the selection flash — is measured in these.
pub const TICKS_PER_SECOND: f64 = 30.0;

/// Ticks an ambient fade in or out takes (~0.5 s).
const AMBIENT_FADE_TICKS: f64 = 15.0;

/// Ticks the orb takes to cross-fade from one connection state to the next.
pub const ORB_TRANSITION_TICKS: f64 = 14.0;

/// Cells per tick the wavefront travels outwards.
///
/// Fast enough to cross a full-screen terminal in well under a second — the
/// wave should read as a burst, not a slow ripple.
const RAINBOW_SPEED: f64 = 8.0;
/// Thickness of the visible band, in cells.
///
/// Kept wider than `RAINBOW_SPEED` so consecutive frames overlap: a band
/// thinner than the per-tick travel would skip cells and read as a dotted
/// ring rather than a continuous front.
const RAINBOW_THICKNESS: f64 = 12.0;
/// Concurrent waves kept alive.
///
/// Clicking again starts another wave rather than restarting the current one,
/// so rapid clicks produce overlapping rings. The cap bounds the per-cell
/// cost of compositing them.
const MAX_RAINBOW_WAVES: usize = 8;

/// How long the ember particles of an opening dialog live.
const ASH_LIFETIME_TICKS: u64 = 18;

/// Ember glyphs, densest first.
///
/// The ramp runs dense to sparse so the effect *uncovers* the dialog's real
/// border as it settles. An earlier ramp ended on `═` and `║`, which left
/// counterfeit border segments sitting a cell inside the actual frame.
const ASH_SYMBOLS: [char; 5] = ['█', '▓', '▒', '░', '·'];

#[derive(Debug, Clone, Copy)]
pub struct RainbowWave {
    /// Clock time (in ticks, fractional) the wave was started at.
    pub start: f64,
    pub origin: (f64, f64),
    /// Distance the front must travel before the wave has left the screen.
    ///
    /// Computed from the origin and the viewport rather than fixed, so the
    /// ring always runs to the furthest corner instead of fading out
    /// somewhere in the middle.
    pub reach: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct AshParticle {
    pub x: u16,
    pub y: u16,
    pub born_tick: u64,
    pub seed: u16,
}

/// The orb's last observed state and when it changed.
#[derive(Debug, Clone, Copy)]
struct OrbTrack {
    current: OrbState,
    previous: Option<OrbState>,
    since: f64,
}

pub struct VisualEffects {
    /// Whole ticks elapsed: `time.floor()`.
    tick: u64,
    /// Continuous clock, in ticks.
    time: f64,
    /// Wall-clock anchor for [`Self::advance_to`]: the instant and the clock
    /// value it corresponds to. Set on first use.
    anchor: Option<(Instant, f64)>,
    depth: ColorDepth,
    animations: bool,
    rainbow_waves: Vec<RainbowWave>,
    ashes: Vec<AshParticle>,
    /// Terminal size, refreshed every frame by the renderer.
    viewport: (u16, u16),
    /// Whether ambient motion is wanted, and the fade towards that.
    ambient_on: bool,
    /// Ambient level at the moment of the last change, and when that was.
    ambient_from: (f64, f64),
    orb: Option<OrbTrack>,
    /// The active theme's colours, which every glow and ember is drawn from.
    palette: Palette,
}

impl Default for VisualEffects {
    fn default() -> Self {
        Self::new()
    }
}

impl VisualEffects {
    pub fn new() -> Self {
        Self::with_caps(ColorDepth::TrueColor, true)
    }

    pub fn with_caps(depth: ColorDepth, animations: bool) -> Self {
        Self {
            tick: 0,
            time: 0.0,
            anchor: None,
            depth,
            animations,
            rainbow_waves: Vec::new(),
            ashes: Vec::new(),
            viewport: (80, 24),
            // Ambient motion starts fully on: a freshly opened client is by
            // definition being looked at.
            ambient_on: true,
            ambient_from: (1.0, 0.0),
            orb: None,
            palette: Palette::of(ThemeId::GoldenDark),
        }
    }

    /// Switch the colours effects are drawn in. Takes effect next frame.
    pub fn set_palette(&mut self, palette: Palette) {
        self.palette = palette;
    }

    /// Tell the effects how big the screen is.
    ///
    /// Called once per frame by the renderer; a wave's lifetime is derived
    /// from this so it expires exactly when it leaves the visible area.
    pub fn set_viewport(&mut self, width: u16, height: u16) {
        self.viewport = (width.max(1), height.max(1));
    }

    pub fn animations_enabled(&self) -> bool {
        self.animations
    }

    pub fn set_animations_enabled(&mut self, enabled: bool) {
        self.animations = enabled;
        if !enabled {
            self.rainbow_waves.clear();
            self.ashes.clear();
        }
    }

    /// Step the clock by exactly one tick.
    ///
    /// Deterministic, for tests and for callers without a wall clock. The
    /// app itself uses [`Self::advance_to`].
    pub fn advance_tick(&mut self) {
        let next = self.time.floor() + 1.0;
        self.set_time(next);
    }

    /// Move the clock to wall time `now`.
    ///
    /// Monotonic: an earlier `now` is ignored. The clock is anchored on the
    /// first call, so the first frame starts from wherever the clock was.
    pub fn advance_to(&mut self, now: Instant) {
        let (anchor, base) = *self.anchor.get_or_insert((now, self.time));
        let t = base + now.saturating_duration_since(anchor).as_secs_f64() * TICKS_PER_SECOND;
        if t > self.time {
            self.set_time(t);
        }
    }

    fn set_time(&mut self, t: f64) {
        self.time = t;
        self.tick = t.floor() as u64;

        // A wave lives until its trailing edge has passed the furthest
        // corner it can reach, so it always completes rather than dimming out
        // part-way across.
        let now = self.time;
        self.rainbow_waves.retain(|wave| {
            let elapsed = (now - wave.start).max(0.0);
            elapsed * RAINBOW_SPEED - RAINBOW_THICKNESS <= wave.reach
        });

        let now = self.tick;
        self.ashes
            .retain(|p| now.saturating_sub(p.born_tick) < ASH_LIFETIME_TICKS);
    }

    pub fn current_tick(&self) -> u64 {
        self.tick
    }

    /// The continuous clock, in ticks.
    pub fn current_time(&self) -> f64 {
        self.time
    }

    /// Whether anything on screen is mid-animation.
    ///
    /// Covers the one-shot effects — waves, embers, an orb state change, an
    /// ambient fade — but *not* steady ambient motion, which the frame loop
    /// schedules separately (see [`Self::ambient_running`]). With nothing in
    /// flight an idle ZeroNet draws zero frames per second.
    pub fn is_animating(&self) -> bool {
        self.animations
            && (!self.rainbow_waves.is_empty()
                || !self.ashes.is_empty()
                || self.orb_transition().is_some()
                || self.ambient_fading())
    }

    // ---------------------------------------------------------------- ambient

    /// Ask for ambient motion to be on or off. The change fades in or out
    /// over about half a second rather than freezing mid-breath.
    pub fn set_ambient(&mut self, on: bool) {
        if on == self.ambient_on {
            return;
        }
        let level = self.ambient_level();
        self.ambient_on = on;
        self.ambient_from = (level, self.time);
    }

    /// Whether ambient motion has been asked for.
    pub fn ambient_wanted(&self) -> bool {
        self.ambient_on
    }

    /// How much ambient motion is showing, `0.0..=1.0`, eased.
    pub fn ambient_level(&self) -> f64 {
        if !self.animations {
            return 0.0;
        }
        let (from, at) = self.ambient_from;
        let target = if self.ambient_on { 1.0 } else { 0.0 };
        let t = ((self.time - at) / AMBIENT_FADE_TICKS).clamp(0.0, 1.0);
        let t = t * t * (3.0 - 2.0 * t); // smoothstep: no kink at either end
        from + (target - from) * t
    }

    fn ambient_fading(&self) -> bool {
        let level = self.ambient_level();
        let target = if self.ambient_on { 1.0 } else { 0.0 };
        (level - target).abs() > 1e-3
    }

    /// Whether ambient motion is visible at all, so a steady-state frame
    /// would differ from the last one.
    pub fn ambient_running(&self) -> bool {
        self.ambient_level() > 1e-3
    }

    /// Phase of the always-on sheen, in `0.0..1.0`.
    ///
    /// It advances continuously and wraps, so a highlight travelling from the
    /// top-left of a control to its bottom-right starts over without a jump.
    pub fn sheen_phase(&self) -> f64 {
        if !self.animations {
            return 0.0;
        }
        (self.time * 0.04).fract()
    }

    /// How strongly the sheen should be painted: the ambient level.
    pub fn sheen_strength(&self) -> f64 {
        self.ambient_level()
    }

    // -------------------------------------------------------------------- orb

    /// Tell the effects which state the orb is drawn in this frame.
    ///
    /// A change starts a short cross-fade from the old state's colours to the
    /// new one's, so connecting → connected reads as a transition rather
    /// than a cut.
    pub fn note_orb_state(&mut self, state: OrbState) {
        match self.orb {
            Some(track) if track.current == state => {}
            Some(track) => {
                self.orb = Some(OrbTrack {
                    current: state,
                    previous: Some(track.current),
                    since: self.time,
                });
            }
            // The first sighting is not a transition: nothing was on screen.
            None => {
                self.orb = Some(OrbTrack {
                    current: state,
                    previous: None,
                    since: self.time,
                });
            }
        }
    }

    /// The state the orb is leaving and how far through the change it is
    /// (`0.0..1.0`, eased), while a change is in flight.
    pub fn orb_transition(&self) -> Option<(OrbState, f64)> {
        if !self.animations {
            return None;
        }
        let track = self.orb?;
        let previous = track.previous?;
        let t = (self.time - track.since) / ORB_TRANSITION_TICKS;
        if !(0.0..1.0).contains(&t) {
            return None;
        }
        Some((previous, ease_out_cubic(t)))
    }

    /// A one-shot bloom, `1.0` fading to `0.0`, played when the orb arrives
    /// at `Connected`.
    pub fn orb_bloom(&self) -> f64 {
        match self.orb_transition() {
            Some((_, p)) if self.orb.is_some_and(|o| o.current == OrbState::Connected) => {
                (1.0 - p) * (1.0 - p)
            }
            _ => 0.0,
        }
    }

    // ---------------------------------------------------------------- rainbow

    /// Start an expanding chromatic ring centred on the clicked cell.
    ///
    /// Each call adds a wave; it never replaces the one in flight, so
    /// clicking repeatedly produces concentric rings chasing each other
    /// outwards instead of restarting from scratch.
    pub fn trigger_rainbow(&mut self, origin_x: f64, origin_y: f64) {
        if !self.animations {
            return;
        }
        if self.rainbow_waves.len() >= MAX_RAINBOW_WAVES {
            self.rainbow_waves.remove(0);
        }
        self.rainbow_waves.push(RainbowWave {
            start: self.time,
            origin: (origin_x, origin_y),
            reach: self.reach_from(origin_x, origin_y),
        });
    }

    /// Distance from `origin` to the furthest corner of the viewport, in the
    /// same aspect-corrected units `rainbow_color_at` measures in.
    fn reach_from(&self, x: f64, y: f64) -> f64 {
        let (w, h) = (self.viewport.0 as f64, self.viewport.1 as f64);
        [(0.0, 0.0), (w, 0.0), (0.0, h), (w, h)]
            .into_iter()
            .map(|(cx, cy)| {
                let dx = cx - x;
                let dy = (cy - y) * 2.0;
                (dx * dx + dy * dy).sqrt()
            })
            .fold(0.0, f64::max)
    }

    pub fn rainbow_active(&self) -> bool {
        !self.rainbow_waves.is_empty()
    }

    /// Number of waves currently in flight.
    pub fn rainbow_wave_count(&self) -> usize {
        self.rainbow_waves.len()
    }

    /// The colour the wave paints at a screen cell, if the wavefront is
    /// currently passing through it.
    ///
    /// Vertical distance is doubled because a terminal cell is about twice as
    /// tall as it is wide — without that correction the "circle" comes out as
    /// a wide ellipse.
    pub fn rainbow_color_at(&self, x: u16, y: u16) -> Option<Color> {
        // Overlapping waves composite by brightness: the crest of the nearest
        // front wins, so a later ring reads as passing over an earlier one.
        let mut best: Option<(f64, Color)> = None;

        for wave in &self.rainbow_waves {
            let elapsed = (self.time - wave.start).max(0.0);

            let dx = x as f64 - wave.origin.0;
            let dy = (y as f64 - wave.origin.1) * 2.0;
            let dist = (dx * dx + dy * dy).sqrt();

            let front = elapsed * RAINBOW_SPEED;
            let diff = (dist - front).abs();
            if diff >= RAINBOW_THICKNESS {
                continue;
            }

            // Brightness depends only on how close the cell is to the crest.
            // There is deliberately no fade with age: an age term made the
            // ring dim out before it reached the edge of the screen.
            let intensity = 1.0 - diff / RAINBOW_THICKNESS;
            if intensity <= 0.02 {
                continue;
            }

            if best.as_ref().is_none_or(|(b, _)| intensity > *b) {
                let hue = (dist * 9.0 + elapsed * 6.0) % 360.0;
                let (r, g, b) = hsl_to_rgb(hue, 0.95, 0.22 + 0.48 * intensity);
                best = Some((intensity, self.adapt(Color::Rgb(r, g, b))));
            }
        }

        best.map(|(_, color)| color)
    }

    // ------------------------------------------------------------------- logo

    /// The ZeroNet wordmark's resting colour: a slow breath between gold and
    /// orange and back.
    ///
    /// Hovering only deepens the swing and speeds it up — the logo never
    /// takes on button chrome, because it is not a button.
    pub fn logo_color(&self, hovered: bool) -> Color {
        let gold = self.palette.accent_bright;
        let orange = self.palette.accent_hot;

        if !self.animations {
            return self.adapt(if hovered { orange } else { gold });
        }

        let speed = if hovered { 0.085 } else { 0.035 };
        // sin maps to -1..1; shift into 0..1 so the cycle runs
        // gold -> orange -> gold with no discontinuity.
        let phase = (self.time * speed).sin() * 0.5 + 0.5;
        // Hover is interaction, not ambience: it always shows.
        let reach = if hovered {
            1.0
        } else {
            0.45 * self.ambient_level()
        };
        self.adapt(lerp_color(gold, orange, phase * reach))
    }

    /// Slightly brighter companion colour for the "CORE" half of the mark.
    pub fn logo_trail_color(&self, hovered: bool) -> Color {
        let base = self.palette.accent_dim;
        let lifted = lerp_color(self.palette.accent_dim, self.palette.accent_hot, 0.7);
        if !self.animations {
            return self.adapt(if hovered { lifted } else { base });
        }
        let phase = (self.time * 0.05 + 1.2).sin() * 0.5 + 0.5;
        self.adapt(lerp_color(
            base,
            lifted,
            if hovered {
                0.6 + phase * 0.4
            } else {
                phase * 0.5 * self.ambient_level()
            },
        ))
    }

    // ----------------------------------------------------------------- glows

    /// Amber that breathes; used for connecting states and focus rings.
    pub fn amber_glow(&self) -> Color {
        if !self.animations {
            return self.adapt(self.palette.accent);
        }
        let t = self.breath(0.08);
        self.adapt(lerp_color(
            lerp_color(self.palette.accent, self.palette.accent_hot, 0.5),
            self.palette.accent_bright,
            t,
        ))
    }

    /// Emerald that pulses slowly; used for the connected orb and status pill.
    pub fn emerald_glow(&self) -> Color {
        if !self.animations {
            return self.adapt(self.palette.ok);
        }
        let t = self.breath(0.05);
        self.adapt(lerp_color(
            lerp_color(self.palette.ok, self.palette.bg, 0.3),
            self.palette.ok_bright(),
            t,
        ))
    }

    /// 0.0..=1.0 pulse phase, for callers that want to drive their own
    /// interpolation (the orb interpolates its ring colour per frame).
    pub fn pulse_phase(&self, speed: f64) -> f64 {
        if !self.animations {
            return 0.5;
        }
        self.breath(speed)
    }

    /// A sine breath in `0.0..=1.0` whose swing is scaled by the ambient
    /// level, so it settles on the midpoint when ambient motion fades out.
    fn breath(&self, speed: f64) -> f64 {
        0.5 + (self.time * speed).sin() * 0.5 * self.ambient_level()
    }

    /// Rotation angle in radians for spinners and the connecting arc.
    ///
    /// Not ambient: a spinning arc is the "working on it" signal and runs for
    /// as long as there is work.
    pub fn spin_angle(&self, speed: f64) -> f64 {
        if !self.animations {
            return 0.0;
        }
        (self.time * speed) % std::f64::consts::TAU
    }

    /// Accent colour for a control, varying with its hover and active state.
    pub fn stateful_gold(&self, is_hovered: bool, is_active: bool, state_shift: usize) -> Color {
        if is_active {
            return self.adapt(self.palette.accent);
        }
        if is_hovered {
            return self.adapt(self.palette.accent_bright);
        }
        let rest = lerp_color(self.palette.accent, self.palette.accent_dim, 0.3);
        if !self.animations {
            return self.adapt(rest);
        }
        // A faint shimmer, offset per control so a row of them does not
        // pulse in lockstep.
        let t = ((self.time + state_shift as f64 * 15.0) * 0.05).sin() * self.ambient_level();
        self.adapt(lerp_color(
            rest,
            self.palette.accent_bright,
            0.06 + t * 0.06,
        ))
    }

    // ------------------------------------------------------------------ ashes

    /// Scatter ember particles around a dialog's perimeter as it opens.
    pub fn emit_ashes_burst(&mut self, area: Rect, count: usize) {
        if !self.animations || area.width < 2 || area.height < 2 {
            return;
        }
        let perimeter = 2 * (area.width as u32 + area.height as u32);
        if perimeter == 0 {
            return;
        }
        for i in 0..count {
            let pos = (i as u32 * 7 + self.tick as u32 * 3) % perimeter;
            let (x, y) = perimeter_point(area, pos);
            if y == area.y {
                continue;
            }
            self.ashes.push(AshParticle {
                x,
                y,
                born_tick: self.tick,
                seed: (i as u16).wrapping_mul(2654),
            });
        }
    }

    /// Live ember particles as `(x, y, glyph, colour)`.
    pub fn current_ashes(&self) -> Vec<(u16, u16, char, Color)> {
        self.ashes
            .iter()
            .filter_map(|p| {
                let age = self.tick.saturating_sub(p.born_tick);
                if age >= ASH_LIFETIME_TICKS {
                    return None;
                }
                let progress = age as f64 / ASH_LIFETIME_TICKS as f64;
                let jitter = (p.seed % 32) as f64 / 32.0;
                let heat = (progress + jitter * 0.15).min(1.0);
                let idx = ((progress * (ASH_SYMBOLS.len() - 1) as f64).floor() as usize)
                    .min(ASH_SYMBOLS.len() - 1);
                let color = self.ember(heat);
                Some((p.x, p.y, ASH_SYMBOLS[idx], self.adapt(color)))
            })
            .collect()
    }

    /// The perimeter crystallisation drawn over a dialog for its first few
    /// frames: ash and embers coalescing into a solid border.
    ///
    /// Returns an empty list once the animation has finished, so the border
    /// ends up perfectly crisp with no stray particles left behind.
    pub fn ashes_border_overlay(
        &self,
        area: Rect,
        elapsed_ticks: u64,
    ) -> Vec<(u16, u16, char, Color)> {
        if !self.animations || elapsed_ticks >= ASH_LIFETIME_TICKS {
            return Vec::new();
        }
        let perimeter = 2 * (area.width as u32 + area.height as u32);
        if perimeter == 0 {
            return Vec::new();
        }

        let progress = elapsed_ticks as f64 / ASH_LIFETIME_TICKS as f64;
        let count = ((perimeter as usize) * 2 / 3).max(10);

        let mut cells = Vec::with_capacity(count);
        for i in 0..count {
            let pos = (i as u32 * 3 + self.tick as u32 * 2) % perimeter;
            let (px, py) = perimeter_point(area, pos);

            // The dialog's title sits on the top border. Embers there would
            // shred it for the length of the animation, so that row is left
            // alone and the effect plays out on the other three sides.
            if py == area.y {
                continue;
            }

            // The per-cell offset is a *delay*, not a head start. Adding it
            // pushed most cells straight to "finished" on the first frame, so
            // the dialog appeared already dissolved into dots instead of
            // materialising out of them.
            let cell_progress = ((progress - i as f64 * 0.006) * 1.4).clamp(0.0, 1.0);
            let idx = ((cell_progress * (ASH_SYMBOLS.len() - 1) as f64).floor() as usize)
                .min(ASH_SYMBOLS.len() - 1);
            let color = self.ember(cell_progress);
            cells.push((px, py, ASH_SYMBOLS[idx], self.adapt(color)));
        }
        cells
    }

    // ------------------------------------------------------------- sparkline

    /// Braille-free block sparkline of recent latency samples.
    pub fn format_sparkline(pings: &[f64], max_len: usize) -> String {
        if pings.is_empty() || max_len == 0 {
            return String::new();
        }
        const SYMBOLS: [char; 8] = [' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        let max_val = pings.iter().copied().fold(10.0, f64::max);
        let slice = if pings.len() > max_len {
            &pings[pings.len() - max_len..]
        } else {
            pings
        };

        slice
            .iter()
            .map(|&val| {
                let ratio = (val / max_val).clamp(0.0, 1.0);
                SYMBOLS[((ratio * 7.0).round() as usize).min(7)]
            })
            .collect()
    }

    /// An ember's colour at `heat` (0 cold .. 1 hot), in the theme's accent.
    fn ember(&self, heat: f64) -> Color {
        let cold = lerp_color(self.palette.accent_dim, self.palette.accent_hot, 0.35);
        lerp_color(cold, self.palette.accent_bright, heat)
    }

    fn adapt(&self, color: Color) -> Color {
        adapt(color, self.depth)
    }
}

/// Walk `pos` cells clockwise around the border of `area`, starting at its
/// top-left corner.
fn perimeter_point(area: Rect, pos: u32) -> (u16, u16) {
    let w = area.width as u32;
    let h = area.height as u32;
    if w == 0 || h == 0 {
        return (area.x, area.y);
    }

    if pos < w {
        (area.x + pos as u16, area.y)
    } else if pos < w + h {
        (
            area.x + area.width.saturating_sub(1),
            area.y + (pos - w) as u16,
        )
    } else if pos < 2 * w + h {
        (
            area.x + area.width.saturating_sub(1 + (pos - (w + h)) as u16),
            area.y + area.height.saturating_sub(1),
        )
    } else {
        (
            area.x,
            area.y + area.height.saturating_sub(1 + (pos - (2 * w + h)) as u16),
        )
    }
}

fn ease_out_cubic(t: f64) -> f64 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

pub fn hsl_to_rgb(h: f64, s: f64, l: f64) -> (u8, u8, u8) {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;

    let (r, g, b) = if h < 60.0 {
        (c, x, 0.0)
    } else if h < 120.0 {
        (x, c, 0.0)
    } else if h < 180.0 {
        (0.0, c, x)
    } else if h < 240.0 {
        (0.0, x, c)
    } else if h < 300.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    (
        ((r + m) * 255.0).clamp(0.0, 255.0) as u8,
        ((g + m) * 255.0).clamp(0.0, 255.0) as u8,
        ((b + m) * 255.0).clamp(0.0, 255.0) as u8,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect() -> Rect {
        Rect {
            x: 5,
            y: 5,
            width: 30,
            height: 15,
        }
    }

    #[test]
    fn rainbow_spreads_outwards_and_expires() {
        let mut fx = VisualEffects::new();
        fx.set_viewport(120, 40);
        fx.trigger_rainbow(10.0, 10.0);
        fx.advance_tick();

        assert!(fx.rainbow_color_at(11, 10).is_some());
        // Far from the origin the front has not arrived yet.
        assert!(fx.rainbow_color_at(110, 10).is_none());

        for _ in 0..200 {
            fx.advance_tick();
        }
        assert!(!fx.rainbow_active());
        assert!(!fx.is_animating());
    }

    #[test]
    fn rainbow_wavefront_travels() {
        let mut fx = VisualEffects::new();
        fx.set_viewport(120, 40);
        fx.trigger_rainbow(40.0, 12.0);
        for _ in 0..6 {
            fx.advance_tick();
        }
        // The front has moved past the origin, which is now dark, and a ring
        // further out is lit.
        let front = (6.0 * RAINBOW_SPEED) as u16;
        assert!(fx.rainbow_color_at(40, 12).is_none());
        assert!(fx.rainbow_color_at(40 + front, 12).is_some());
    }

    #[test]
    fn a_wave_reaches_the_far_corner_of_the_screen() {
        // The bug this replaces: the ring faded with age and died somewhere
        // in the middle of the screen instead of running off the edge.
        let mut fx = VisualEffects::new();
        fx.set_viewport(130, 44);
        fx.trigger_rainbow(6.0, 1.0); // the wordmark, top-left

        let mut lit_far_corner = false;
        for _ in 0..200 {
            fx.advance_tick();
            if fx.rainbow_color_at(129, 43).is_some() {
                lit_far_corner = true;
                break;
            }
        }
        assert!(
            lit_far_corner,
            "the wave never reached the opposite corner of the screen"
        );
    }

    #[test]
    fn a_wave_crosses_the_screen_quickly() {
        // "Faster" is a requirement, so pin it: a full-width terminal should
        // be crossed in well under a second at 30 fps.
        let mut fx = VisualEffects::new();
        fx.set_viewport(130, 44);
        fx.trigger_rainbow(6.0, 1.0);

        let mut ticks = 0;
        while fx.rainbow_color_at(129, 43).is_none() && ticks < 200 {
            fx.advance_tick();
            ticks += 1;
        }
        assert!(
            ticks <= 24,
            "took {ticks} ticks (~{:.1}s at 30fps) to cross the screen",
            ticks as f64 / 30.0
        );
    }

    #[test]
    fn clicking_again_adds_a_wave_instead_of_restarting() {
        let mut fx = VisualEffects::new();
        fx.set_viewport(130, 44);

        fx.trigger_rainbow(6.0, 1.0);
        for _ in 0..4 {
            fx.advance_tick();
        }
        fx.trigger_rainbow(6.0, 1.0);
        assert_eq!(
            fx.rainbow_wave_count(),
            2,
            "the second click reset the first wave"
        );

        // Both rings are on screen at once, at different radii.
        fx.advance_tick();
        let inner = (1.0 * RAINBOW_SPEED) as u16;
        let outer = (5.0 * RAINBOW_SPEED) as u16;
        assert!(fx.rainbow_color_at(6 + inner, 1).is_some());
        assert!(fx.rainbow_color_at(6 + outer, 1).is_some());
    }

    #[test]
    fn concurrent_waves_are_capped() {
        let mut fx = VisualEffects::new();
        fx.set_viewport(130, 44);
        for _ in 0..40 {
            fx.trigger_rainbow(10.0, 10.0);
        }
        assert_eq!(fx.rainbow_wave_count(), MAX_RAINBOW_WAVES);
    }

    #[test]
    fn the_sheen_keeps_moving_and_wraps() {
        let mut fx = VisualEffects::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..80 {
            fx.advance_tick();
            let phase = fx.sheen_phase();
            assert!((0.0..1.0).contains(&phase), "phase escaped 0..1: {phase}");
            seen.insert((phase * 100.0) as i32);
        }
        assert!(seen.len() > 10, "the sheen did not travel");
    }

    #[test]
    fn logo_breathes_between_gold_and_orange() {
        let mut fx = VisualEffects::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..120 {
            fx.advance_tick();
            seen.insert(format!("{:?}", fx.logo_color(true)));
        }
        assert!(
            seen.len() > 5,
            "hovered logo should cycle through colours, saw {}",
            seen.len()
        );
    }

    #[test]
    fn disabling_animations_freezes_every_colour() {
        let mut fx = VisualEffects::with_caps(ColorDepth::TrueColor, false);
        let first = (fx.logo_color(true), fx.amber_glow(), fx.emerald_glow());
        for _ in 0..50 {
            fx.advance_tick();
        }
        let later = (fx.logo_color(true), fx.amber_glow(), fx.emerald_glow());
        assert_eq!(first, later);

        // ...and no particle system produces anything.
        fx.trigger_rainbow(5.0, 5.0);
        fx.emit_ashes_burst(rect(), 40);
        assert!(!fx.is_animating());
        assert!(fx.current_ashes().is_empty());
        assert!(fx.ashes_border_overlay(rect(), 1).is_empty());
    }

    #[test]
    fn ashes_burst_populates_then_expires() {
        let mut fx = VisualEffects::new();
        fx.emit_ashes_burst(rect(), 24);
        assert!(!fx.current_ashes().is_empty());
        assert!(fx.is_animating());

        for _ in 0..ASH_LIFETIME_TICKS + 2 {
            fx.advance_tick();
        }
        assert!(fx.current_ashes().is_empty());
    }

    #[test]
    fn ashes_border_overlay_clears_once_settled() {
        let fx = VisualEffects::new();
        assert!(!fx.ashes_border_overlay(rect(), 1).is_empty());
        assert!(fx
            .ashes_border_overlay(rect(), ASH_LIFETIME_TICKS)
            .is_empty());
    }

    #[test]
    fn ashes_start_dense_and_thin_out() {
        // The first frame should be mostly solid embers and the last mostly
        // faint ones. Getting this backwards made a dialog look like it was
        // framed in stray dots the moment it opened.
        let fx = VisualEffects::new();
        let density = |elapsed| -> f64 {
            let cells = fx.ashes_border_overlay(rect(), elapsed);
            let dense = cells
                .iter()
                .filter(|(_, _, ch, _)| *ch == '█' || *ch == '▓')
                .count();
            dense as f64 / cells.len() as f64
        };
        assert!(density(0) > 0.8, "opening frame should be solid embers");
        assert!(
            density(ASH_LIFETIME_TICKS - 1) < 0.2,
            "final frame should be nearly faded"
        );
    }

    #[test]
    fn ashes_never_touch_the_title_row() {
        // A dialog's title lives on its top border; embers there shred it.
        let r = rect();
        let fx = VisualEffects::new();
        for elapsed in 0..ASH_LIFETIME_TICKS {
            for (_, y, _, _) in fx.ashes_border_overlay(r, elapsed) {
                assert_ne!(y, r.y, "ember landed on the title row");
            }
        }

        let mut fx = VisualEffects::new();
        fx.emit_ashes_burst(r, 128);
        for (_, y, _, _) in fx.current_ashes() {
            assert_ne!(y, r.y, "burst ember landed on the title row");
        }
    }

    #[test]
    fn ash_particles_stay_on_the_perimeter() {
        let mut fx = VisualEffects::new();
        let r = rect();
        fx.emit_ashes_burst(r, 64);
        for (x, y, _, _) in fx.current_ashes() {
            let on_edge = x == r.x || x == r.x + r.width - 1 || y == r.y || y == r.y + r.height - 1;
            assert!(on_edge, "particle at ({x},{y}) left the border of {r:?}");
        }
    }

    #[test]
    fn sparkline_length_matches_samples() {
        let s = VisualEffects::format_sparkline(&[10.0, 50.0, 100.0, 25.0], 10);
        assert_eq!(s.chars().count(), 4);
        assert!(VisualEffects::format_sparkline(&[], 10).is_empty());
    }

    #[test]
    fn colours_quantise_on_a_256_colour_terminal() {
        let fx = VisualEffects::with_caps(ColorDepth::Ansi256, true);
        assert!(matches!(fx.amber_glow(), Color::Indexed(_)));
        assert!(matches!(fx.logo_color(false), Color::Indexed(_)));
    }

    #[test]
    fn the_clock_follows_wall_time_not_frame_count() {
        use std::time::Duration;
        // One call or thirty, the same wall time is the same clock reading:
        // a burst of events must never make animations run fast.
        let start = Instant::now();
        let mut once = VisualEffects::new();
        let mut often = VisualEffects::new();
        once.advance_to(start);
        often.advance_to(start);
        once.advance_to(start + Duration::from_millis(500));
        for ms in (0..=500).step_by(17) {
            often.advance_to(start + Duration::from_millis(ms));
        }
        often.advance_to(start + Duration::from_millis(500));
        assert_eq!(once.current_tick(), often.current_tick());
        assert_eq!(once.current_tick(), 15, "500 ms is 15 ticks at 30/s");

        // Monotonic: an older instant is ignored.
        once.advance_to(start);
        assert_eq!(once.current_tick(), 15);
    }

    #[test]
    fn ambient_motion_fades_rather_than_snapping() {
        let mut fx = VisualEffects::new();
        assert!((fx.ambient_level() - 1.0).abs() < 1e-9);
        fx.set_ambient(false);
        assert!(fx.is_animating(), "the fade-out needs frames");

        let mut previous = fx.ambient_level();
        for _ in 0..(AMBIENT_FADE_TICKS as usize) {
            fx.advance_tick();
            let level = fx.ambient_level();
            assert!(level <= previous, "the fade went backwards");
            assert!(previous - level < 0.25, "the fade jumped");
            previous = level;
        }
        assert!(fx.ambient_level() < 1e-6);
        assert!(!fx.ambient_running());
        assert!(!fx.is_animating(), "a faded-out client should be at rest");

        // At rest the breathing colours settle on a fixed value.
        let still = (fx.emerald_glow(), fx.logo_color(false), fx.sheen_strength());
        for _ in 0..20 {
            fx.advance_tick();
        }
        assert_eq!(
            still,
            (fx.emerald_glow(), fx.logo_color(false), fx.sheen_strength())
        );
    }

    #[test]
    fn a_fade_reversed_midway_continues_from_where_it_was() {
        let mut fx = VisualEffects::new();
        fx.set_ambient(false);
        for _ in 0..5 {
            fx.advance_tick();
        }
        let mid = fx.ambient_level();
        fx.set_ambient(true);
        assert!((fx.ambient_level() - mid).abs() < 1e-9, "reversing snapped");
    }
}
