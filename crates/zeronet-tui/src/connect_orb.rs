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
//! **The globe.** Inside the ring turns a wireframe Earth (see
//! [`crate::globe`]) that sways around the user's country. With a server
//! chosen, a route runs from there to the server's country.
//!
//! **States.**
//! * `Idle` — a dim ring; the route, if any, is previewed as dots.
//! * `Connecting` — a bright arc sweeping around the ring, and a comet
//!   running along the route (radar rings when there is no route to follow).
//! * `Connected` — a green ring whose colour is interpolated every frame, so
//!   it breathes slowly rather than blinking; the route is solid with a light
//!   travelling along it.
//! * `Error` — a broken red ring and a broken red route.

use crate::daemon::ConnectionStatus;
use crate::effects::{VisualEffects, ORB_CAMERA_TICKS, TICKS_PER_SECOND};
use crate::globe::{self, Earth, GlobePalette, LatLon, Route};
use crate::theme::{lerp_color, Theme};
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::symbols::Marker;
use ratatui::widgets::canvas::{Canvas, Context, Points};
use ratatui::widgets::Block;
use ratatui::Frame;

/// Fraction of the available half-extent the outer ring occupies.
const OUTER_RING_SCALE: f64 = 0.92;
/// Radii of the rings, as fractions of the outer ring. The globe fills the
/// inside, so there is one.
const RING_SCALES: [f64; 1] = [1.0];
/// Radius of the globe, as a fraction of the outer ring.
const GLOBE_SCALE: f64 = 0.86;
/// Ticks the route takes to draw in once connected.
const ROUTE_DRAW_TICKS: f64 = 33.0;
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

/// What the globe inside the orb shows: where the user is, and the route to
/// the server when one is chosen.
pub struct GlobeView<'a> {
    pub home: LatLon,
    pub route: Option<&'a Route>,
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
    view: &GlobeView,
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
    let (focus, reveal) = camera_progress(
        state,
        effects.orb_track().and_then(|(_, previous, _)| previous),
        effects.orb_track().map_or(0.0, |(_, _, age)| age),
        effects.animations_enabled(),
        view.route.is_some(),
    );
    let seconds = effects.current_time() / TICKS_PER_SECOND;
    let ambient = effects.ambient_level();
    let home = view.home;
    let route = view.route;

    let canvas = Canvas::default()
        .block(Block::default())
        .background_color(theme.surface)
        .marker(Marker::Braille)
        .x_bounds([-w / 2.0, w / 2.0])
        .y_bounds([-h, h])
        .paint(move |ctx| {
            paint_rings(ctx, radius, state, spin, &palette);
            let scene = globe::Scene {
                earth: Earth::get(),
                home,
                route,
                state,
                palette: palette.globe,
                seconds,
                ambient,
                focus,
                reveal,
            };
            globe::paint(ctx, &scene, radius * GLOBE_SCALE);
        });

    frame.render_widget(canvas, area);
    geo
}

/// How far the camera has turned to the route and how much of the route is
/// drawn, both `0..=1`, from the state, the one before it and how long ago it
/// changed. Turning takes [`ORB_CAMERA_TICKS`]; the first state seen is
/// already settled. With animations off everything is settled at once.
fn camera_progress(
    state: OrbState,
    previous: Option<OrbState>,
    age_ticks: f64,
    animations: bool,
    has_route: bool,
) -> (f64, f64) {
    let settled = !animations || previous.is_none();
    let turn = if settled {
        1.0
    } else {
        globe::smoothstep(age_ticks / ORB_CAMERA_TICKS)
    };
    let focus = if !has_route {
        0.0
    } else if state != OrbState::Idle {
        turn
    } else if previous.is_some_and(|p| p != OrbState::Idle) && !settled {
        1.0 - turn
    } else {
        0.0
    };
    let reveal = if state == OrbState::Connected && !settled {
        globe::smoothstep(age_ticks / ROUTE_DRAW_TICKS)
    } else {
        1.0
    };
    (focus, reveal)
}

/// Colours for the ring, the sweeping arc and the globe.
#[derive(Debug, Clone, Copy)]
struct RingPalette {
    rings: [Color; RING_SCALES.len()],
    arc: Color,
    globe: GlobePalette,
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
            globe: self.globe.mix(to.globe, t),
        }
    }

    fn for_state(state: OrbState, hovered: bool, theme: &Theme, effects: &VisualEffects) -> Self {
        match state {
            OrbState::Idle => {
                // A dim ring at rest; hovering lifts it to the accent without
                // changing its shape.
                let outer = if hovered { theme.accent } else { theme.border };
                let land = if hovered {
                    theme.accent
                } else {
                    theme.accent_dim
                };
                Self {
                    rings: [outer],
                    arc: outer,
                    globe: GlobePalette {
                        rim: land,
                        coast: land,
                        grid: theme.border,
                        route: theme.accent_dim,
                        spark: theme.accent_bright,
                    },
                }
            }
            OrbState::Connecting => {
                let glow = effects.amber_glow();
                Self {
                    rings: [theme.accent_dim],
                    arc: glow,
                    globe: GlobePalette {
                        rim: theme.accent_dim,
                        coast: theme.accent,
                        grid: theme.border,
                        route: glow,
                        spark: theme.accent_bright,
                    },
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
                    rings: [bright],
                    arc: bright,
                    globe: GlobePalette {
                        rim: soft,
                        coast: lerp_color(soft, bright, 0.5),
                        grid: theme.adapt(lerp_color(raw.ok_deep(), raw.bg, 0.3)),
                        route: bright,
                        spark: theme.adapt(lerp_color(raw.ok_bright(), raw.text, 0.5)),
                    },
                }
            }
            OrbState::Error => {
                let deep = theme.adapt(theme.raw.err_deep());
                Self {
                    rings: [theme.err],
                    arc: theme.err,
                    globe: GlobePalette {
                        rim: deep,
                        coast: deep,
                        grid: theme.border,
                        route: theme.err,
                        spark: theme.err,
                    },
                }
            }
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
        // The colours are done, but the globe is still turning to its route.
        assert!(fx.is_animating(), "the camera turn was cut short");
        for _ in 0..(crate::effects::ORB_CAMERA_TICKS as usize) {
            fx.advance_tick();
        }
        assert!(!fx.is_animating(), "nothing should be left in flight");
    }

    #[test]
    fn the_camera_turns_to_the_route_when_a_connection_starts_and_back_when_it_ends() {
        let ticks = ORB_CAMERA_TICKS;
        // Connecting: starts at home, ends facing the route.
        let (start, _) =
            camera_progress(OrbState::Connecting, Some(OrbState::Idle), 0.0, true, true);
        let (end, _) = camera_progress(
            OrbState::Connecting,
            Some(OrbState::Idle),
            ticks,
            true,
            true,
        );
        assert_eq!(start, 0.0);
        assert_eq!(end, 1.0);
        // Back to idle: starts facing the route, ends at home.
        let (out, _) = camera_progress(OrbState::Idle, Some(OrbState::Connected), 0.0, true, true);
        let (home, _) =
            camera_progress(OrbState::Idle, Some(OrbState::Connected), ticks, true, true);
        assert_eq!(out, 1.0);
        assert_eq!(home, 0.0);
        // No route, nothing to face.
        let (none, _) = camera_progress(
            OrbState::Connected,
            Some(OrbState::Connecting),
            ticks,
            true,
            false,
        );
        assert_eq!(none, 0.0);
    }

    #[test]
    fn a_state_seen_first_or_without_animations_is_already_settled() {
        assert_eq!(
            camera_progress(OrbState::Connected, None, 0.0, true, true),
            (1.0, 1.0)
        );
        assert_eq!(
            camera_progress(
                OrbState::Connected,
                Some(OrbState::Connecting),
                0.0,
                false,
                true
            ),
            (1.0, 1.0)
        );
        assert_eq!(
            camera_progress(OrbState::Idle, Some(OrbState::Connected), 0.0, false, true),
            (0.0, 1.0)
        );
    }

    #[test]
    fn the_route_draws_in_only_after_connecting() {
        let drawing = camera_progress(
            OrbState::Connected,
            Some(OrbState::Connecting),
            5.0,
            true,
            true,
        )
        .1;
        let drawn = camera_progress(
            OrbState::Connected,
            Some(OrbState::Connecting),
            ROUTE_DRAW_TICKS,
            true,
            true,
        )
        .1;
        assert!(drawing > 0.0 && drawing < 1.0);
        assert_eq!(drawn, 1.0);
        // While connecting or failed the whole route is shown.
        assert_eq!(
            camera_progress(OrbState::Error, Some(OrbState::Connecting), 0.0, true, true).1,
            1.0
        );
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
