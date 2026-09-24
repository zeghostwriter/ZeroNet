//! The connect orb: a real circle drawn with Braille dots.
//!
//! Drawn on a ratatui [`Canvas`] with [`Marker::Braille`], which gives a 2×4
//! dot grid per cell — enough resolution for a smooth ring rather than the
//! dotted blob a character-cell approximation produces.
//!
//! **Aspect.** A terminal cell is roughly twice as tall as it is wide. The
//! canvas bounds are therefore set so that one unit means one cell-width in
//! both axes: `x` spans `width` units and `y` spans `2 × height` units. A
//! circle of radius `r` then comes out round on screen instead of squashed
//! into a wide ellipse.
//!
//! **States.**
//! * `Idle` — a single dim ring.
//! * `Connecting` — a bright arc sweeping around the ring.
//! * `Connected` — a green ring whose colour is interpolated every frame, so
//!   it breathes slowly rather than blinking.
//! * `Error` — a broken red ring.

use crate::daemon::ConnectionStatus;
use crate::effects::VisualEffects;
use crate::theme::{lerp_color, Theme};
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::symbols::Marker;
use ratatui::widgets::canvas::{Canvas, Context, Points};
use ratatui::widgets::Block;
use ratatui::Frame;

/// Fraction of the available half-extent the outer ring occupies.
const OUTER_RING_SCALE: f64 = 0.92;
/// Radii of the concentric rings, as fractions of the outer ring.
const RING_SCALES: [f64; 3] = [1.0, 0.80, 0.62];
/// Arc swept by the connecting indicator, in radians.
const ARC_SWEEP: f64 = std::f64::consts::FRAC_PI_2;

/// Geometry of a rendered orb, in terminal cells.
///
/// Returned by [`render`] so the caller can register a matching circular hit
/// region — the orb is hit-tested against its own centre and radius, not
/// against the panel it sits in.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OrbGeometry {
    pub center_x: f32,
    pub center_y: f32,
    /// Horizontal radius in cells.
    pub radius_x: f32,
    /// Vertical radius in rows — about half `radius_x`, because rows are tall.
    pub radius_y: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrbState {
    Idle,
    Connecting,
    Connected,
    Error,
}

impl From<ConnectionStatus> for OrbState {
    fn from(status: ConnectionStatus) -> Self {
        match status {
            ConnectionStatus::Connected => OrbState::Connected,
            ConnectionStatus::Connecting | ConnectionStatus::Reconnecting => OrbState::Connecting,
            ConnectionStatus::Error => OrbState::Error,
            ConnectionStatus::Disconnected => OrbState::Idle,
        }
    }
}

impl OrbState {
    /// The label shown inside the ring.
    pub fn label(&self) -> &'static str {
        match self {
            OrbState::Idle => "CONNECT",
            OrbState::Connecting => "CONNECTING",
            OrbState::Connected => "CONNECTED",
            OrbState::Error => "FAILED",
        }
    }
}

/// Compute where the orb will be drawn inside `area` without drawing it.
///
/// Split out from [`render`] so hit regions and layout can be resolved even
/// on frames where the orb is not repainted.
pub fn geometry(area: Rect) -> OrbGeometry {
    let w = area.width as f64;
    let h = area.height as f64;

    // Canvas units are cell-widths in both axes (see the module docs), so the
    // usable half-extents are `w / 2` horizontally and `h` vertically.
    let radius = (w / 2.0).min(h) * OUTER_RING_SCALE;

    OrbGeometry {
        center_x: area.x as f32 + w as f32 / 2.0,
        center_y: area.y as f32 + h as f32 / 2.0,
        radius_x: radius as f32,
        radius_y: (radius / 2.0) as f32,
    }
}

/// Draw the orb and return its on-screen geometry.
pub fn render(
    frame: &mut Frame,
    area: Rect,
    state: OrbState,
    hovered: bool,
    theme: &Theme,
    effects: &VisualEffects,
) -> OrbGeometry {
    let geo = geometry(area);
    if area.width < 4 || area.height < 3 {
        return geo;
    }

    let w = area.width as f64;
    let h = area.height as f64;
    let radius = (w / 2.0).min(h) * OUTER_RING_SCALE;

    let mut palette = RingPalette::for_state(state, hovered, theme, effects);
    // A state change cross-fades the rings from the old colours to the new
    // ones instead of cutting between them.
    if let Some((previous, progress)) = effects.orb_transition() {
        palette = RingPalette::for_state(previous, hovered, theme, effects).mix(palette, progress);
    }
    let spin = effects.spin_angle(0.10);

    let canvas = Canvas::default()
        .block(Block::default())
        .background_color(theme.surface)
        .marker(Marker::Braille)
        .x_bounds([-w / 2.0, w / 2.0])
        .y_bounds([-h, h])
        .paint(move |ctx| {
            paint_rings(ctx, radius, state, spin, &palette);
        });

    frame.render_widget(canvas, area);
    geo
}

/// Colours for each concentric ring plus the sweeping arc.
#[derive(Debug, Clone, Copy)]
struct RingPalette {
    rings: [Color; RING_SCALES.len()],
    arc: Color,
}

impl RingPalette {
    /// `self` blended towards `to` by `t`.
    fn mix(self, to: Self, t: f64) -> Self {
        let mut rings = self.rings;
        for (ring, target) in rings.iter_mut().zip(to.rings) {
            *ring = lerp_color(*ring, target, t);
        }
        Self {
            rings,
            arc: lerp_color(self.arc, to.arc, t),
        }
    }

    fn for_state(state: OrbState, hovered: bool, theme: &Theme, effects: &VisualEffects) -> Self {
        match state {
            OrbState::Idle => {
                // A dim ring at rest; hovering lifts it to the accent without
                // changing its shape.
                let outer = if hovered { theme.accent } else { theme.border };
                let mid = if hovered {
                    theme.accent_dim
                } else {
                    theme.border
                };
                Self {
                    rings: [outer, mid, theme.border],
                    arc: outer,
                }
            }
            OrbState::Connecting => {
                let glow = effects.amber_glow();
                Self {
                    rings: [theme.accent_dim, theme.border, theme.border],
                    arc: glow,
                }
            }
            OrbState::Connected => {
                // Interpolate the ring colour every frame so the orb breathes
                // instead of stepping between two fixed greens.
                let phase = effects.pulse_phase(0.05);
                let raw = &theme.raw;
                let bright = theme.adapt(lerp_color(
                    lerp_color(raw.ok, raw.bg, 0.3),
                    raw.ok_bright(),
                    phase,
                ));
                let soft = theme.adapt(lerp_color(raw.ok_deep(), raw.ok, phase));
                Self {
                    rings: [
                        bright,
                        soft,
                        theme.adapt(lerp_color(raw.ok_deep(), raw.bg, 0.3)),
                    ],
                    arc: bright,
                }
            }
            OrbState::Error => Self {
                rings: [theme.err, theme.adapt(theme.raw.err_deep()), theme.border],
                arc: theme.err,
            },
        }
    }
}

fn paint_rings(ctx: &mut Context, radius: f64, state: OrbState, spin: f64, palette: &RingPalette) {
    for (idx, scale) in RING_SCALES.iter().enumerate() {
        let r = radius * scale;
        if r < 1.0 {
            continue;
        }

        // The error state shows a broken ring: the gaps read as damage even
        // before the colour registers.
        let dashed = matches!(state, OrbState::Error) && idx == 0;
        let points = ring_points(r, dashed);
        ctx.draw(&Points {
            coords: &points,
            color: palette.rings[idx],
        });
    }

    if state == OrbState::Connecting {
        let arc = arc_points(radius, spin, ARC_SWEEP);
        ctx.draw(&Points {
            coords: &arc,
            color: palette.arc,
        });
        // A trailing, shorter arc gives the sweep a sense of direction.
        let tail = arc_points(radius * 0.80, spin - 0.5, ARC_SWEEP * 0.6);
        ctx.draw(&Points {
            coords: &tail,
            color: palette.arc,
        });
    }
}

/// Sample a full circle densely enough that the Braille grid has no gaps.
///
/// The canvas bounds put two Braille dots in every unit on both axes, so a
/// ring of radius `r` spans about `4 * pi * r` dots. Sampling at `16 * r`
/// keeps it comfortably oversampled — at `8 * r` the ring came out as a
/// dotted trail rather than a line.
fn ring_points(radius: f64, dashed: bool) -> Vec<(f64, f64)> {
    let steps = ((radius * 16.0) as usize).clamp(64, 1440);
    let dash_period = (steps / 16).max(2);
    (0..steps)
        .filter(|i| !dashed || (i / dash_period).is_multiple_of(2))
        .map(|i| {
            let theta = i as f64 / steps as f64 * std::f64::consts::TAU;
            (radius * theta.cos(), radius * theta.sin())
        })
        .collect()
}

fn arc_points(radius: f64, start: f64, sweep: f64) -> Vec<(f64, f64)> {
    let steps = ((radius * 16.0 * (sweep / std::f64::consts::TAU)) as usize).clamp(24, 480);
    (0..steps)
        .map(|i| {
            let theta = start + sweep * (i as f64 / steps as f64);
            (radius * theta.cos(), radius * theta.sin())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_is_centred_in_its_area() {
        let area = Rect {
            x: 10,
            y: 4,
            width: 40,
            height: 11,
        };
        let geo = geometry(area);
        assert_eq!(geo.center_x, 30.0);
        assert!((geo.center_y - 9.5).abs() < 0.01);
    }

    #[test]
    fn vertical_radius_is_half_the_horizontal_one() {
        // This is what makes the orb look round: a row is about twice the
        // height of a column's width, so the same visual radius spans half as
        // many rows as columns.
        let geo = geometry(Rect {
            x: 0,
            y: 0,
            width: 40,
            height: 20,
        });
        assert!((geo.radius_x / geo.radius_y - 2.0).abs() < 0.01);
    }

    #[test]
    fn radius_is_bounded_by_the_shorter_axis() {
        // A wide, short panel must not produce an orb taller than the panel.
        let geo = geometry(Rect {
            x: 0,
            y: 0,
            width: 120,
            height: 9,
        });
        assert!(
            geo.radius_y <= 9.0 / 2.0,
            "orb of half-height {} overflows a 9-row panel",
            geo.radius_y
        );
    }

    #[test]
    fn ring_points_form_a_closed_circle_of_constant_radius() {
        let pts = ring_points(12.0, false);
        assert!(pts.len() >= 64);
        for (x, y) in pts {
            let r = (x * x + y * y).sqrt();
            assert!((r - 12.0).abs() < 1e-9, "point off the ring: r={r}");
        }
    }

    #[test]
    fn ring_is_oversampled_enough_to_leave_no_braille_gaps() {
        // Two dots per unit on each axis means a ring of radius r needs about
        // 4*pi*r samples to be continuous.
        for radius in [4.0_f64, 8.0, 13.8, 30.0] {
            let needed = (4.0 * std::f64::consts::PI * radius).ceil() as usize;
            assert!(
                ring_points(radius, false).len() >= needed,
                "radius {radius} sampled too sparsely"
            );
        }
    }

    #[test]
    fn dashed_ring_has_gaps() {
        let solid = ring_points(12.0, false).len();
        let dashed = ring_points(12.0, true).len();
        assert!(dashed < solid, "dashed ring should drop points");
        assert!(dashed > 0);
    }

    #[test]
    fn arc_covers_only_its_sweep() {
        let start = 0.0;
        let sweep = std::f64::consts::FRAC_PI_2;
        for (x, y) in arc_points(10.0, start, sweep) {
            let theta = y.atan2(x);
            assert!(
                (-1e-6..=sweep + 1e-6).contains(&theta),
                "arc point at {theta} rad escaped its sweep"
            );
        }
    }

    #[test]
    fn status_maps_onto_orb_states() {
        assert_eq!(
            OrbState::from(ConnectionStatus::Connected),
            OrbState::Connected
        );
        assert_eq!(
            OrbState::from(ConnectionStatus::Connecting),
            OrbState::Connecting
        );
        assert_eq!(
            OrbState::from(ConnectionStatus::Reconnecting),
            OrbState::Connecting
        );
        assert_eq!(
            OrbState::from(ConnectionStatus::Disconnected),
            OrbState::Idle
        );
        assert_eq!(OrbState::from(ConnectionStatus::Error), OrbState::Error);
    }

    #[test]
    fn a_state_change_cross_fades_the_ring_colours() {
        let theme = Theme::default();
        let mut fx = VisualEffects::new();
        fx.note_orb_state(OrbState::Connecting);
        fx.advance_tick();
        fx.note_orb_state(OrbState::Connected);

        let (previous, start) = fx.orb_transition().expect("a transition started");
        assert_eq!(previous, OrbState::Connecting);
        assert!(start < 0.05);

        let from = RingPalette::for_state(OrbState::Connecting, false, &theme, &fx);
        let to = RingPalette::for_state(OrbState::Connected, false, &theme, &fx);
        assert_eq!(from.mix(to, 0.0).rings, from.rings);
        assert_eq!(from.mix(to, 1.0).rings, to.rings);
        assert_ne!(from.mix(to, 0.5).rings[0], from.rings[0]);

        for _ in 0..(crate::effects::ORB_TRANSITION_TICKS as usize + 1) {
            fx.advance_tick();
        }
        assert!(fx.orb_transition().is_none(), "the cross-fade never ended");
        assert!(!fx.is_animating(), "nothing should be left in flight");
    }

    #[test]
    fn the_first_state_seen_is_not_a_transition() {
        let mut fx = VisualEffects::new();
        fx.note_orb_state(OrbState::Connected);
        assert!(fx.orb_transition().is_none());
        assert_eq!(fx.orb_bloom(), 0.0);
    }

    #[test]
    fn tiny_areas_do_not_panic() {
        for (w, h) in [(0, 0), (1, 1), (3, 2), (4, 3)] {
            let _ = geometry(Rect {
                x: 0,
                y: 0,
                width: w,
                height: h,
            });
        }
    }
}
