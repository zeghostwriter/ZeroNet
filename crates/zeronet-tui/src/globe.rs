//! The globe inside the connect orb.
//!
//! A wireframe Earth drawn with Braille dots: a 15° graticule and the real
//! coastlines, seen from a camera that sways around the user's own country,
//! with a great-circle route from there to the server's country. It is the
//! same picture the Android app draws, from the same data files, so the two
//! apps look like one product.
//!
//! Everything here is geometry: a function of the camera, the route and the
//! clock. The colours and the state come from [`crate::connect_orb`], which
//! owns the orb; this module only paints into its canvas.
//!
//! **Cost.** About 5 000 coastline points are projected per frame and joined
//! into short lines. That is a few dozen microseconds; the frame loop already
//! stops redrawing when nothing moves, so an unattended terminal costs
//! nothing.

use std::collections::HashMap;
use std::f32::consts::{PI, TAU};
use std::sync::OnceLock;

use ratatui::style::Color;
use ratatui::widgets::canvas::{Context, Line, Points};

use crate::connect_orb::OrbState;
use crate::theme::lerp_color;

/// The coastlines, shared with the Android app so both draw the same Earth:
/// `u16` ring count, then per ring a `u16` point count and `i16` latitude and
/// longitude in 1/100 degree, little-endian. Natural Earth, public domain.
static LAND: &[u8] = include_bytes!("../../../ZeroNet-Mobile/app/src/main/assets/globe/land.bin");

/// `CC latitude longitude` per line: a label point for each country.
static COUNTRIES: &str =
    include_str!("../../../ZeroNet-Mobile/app/src/main/assets/globe/countries.txt");

/// Points along a route.
const ARC_POINTS: usize = 72;

/// Where Iran's users are, when nothing says otherwise.
pub const CENTER: LatLon = LatLon {
    lat: 35.7,
    lon: 51.4,
};

/// A point on the Earth, in degrees.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LatLon {
    pub lat: f32,
    pub lon: f32,
}

type Vec3 = [f32; 3];

/// The unit vector for a latitude and longitude: x toward 0°E, z toward the
/// North Pole.
pub fn unit_vector(at: LatLon) -> Vec3 {
    let phi = at.lat.to_radians();
    let lambda = at.lon.to_radians();
    [
        phi.cos() * lambda.cos(),
        phi.cos() * lambda.sin(),
        phi.sin(),
    ]
}

/// The latitude and longitude of a vector that need not be unit length.
pub fn lat_lon_of(v: Vec3) -> LatLon {
    let len = (v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).sqrt().max(1e-6);
    LatLon {
        lat: (v[2] / len).clamp(-1.0, 1.0).asin().to_degrees(),
        lon: v[1].atan2(v[0]).to_degrees(),
    }
}

/// The Earth's lines and label points.
pub struct Earth {
    coast: Vec<Vec<Vec3>>,
    graticule: Vec<Vec<Vec3>>,
    countries: HashMap<[u8; 2], LatLon>,
}

impl Earth {
    /// The one shared copy, decoded on first use.
    pub fn get() -> &'static Earth {
        static EARTH: OnceLock<Earth> = OnceLock::new();
        EARTH.get_or_init(|| Earth {
            coast: decode_land(LAND),
            graticule: graticule(),
            countries: parse_countries(COUNTRIES),
        })
    }

    /// Where to draw a country: its label point, or `None` when unknown.
    pub fn country(&self, code: &str) -> Option<LatLon> {
        let code = code.trim().to_ascii_uppercase();
        let bytes = code.as_bytes();
        if bytes.len() != 2 {
            return None;
        }
        self.countries.get(&[bytes[0], bytes[1]]).copied()
    }
}

fn decode_land(bytes: &[u8]) -> Vec<Vec<Vec3>> {
    let mut at = 0;
    let mut u16_at = |bytes: &[u8]| -> Option<u16> {
        let v = u16::from_le_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]);
        at += 2;
        Some(v)
    };
    let Some(rings) = u16_at(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(rings as usize);
    for _ in 0..rings {
        let Some(n) = u16_at(bytes) else { break };
        let mut ring = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let (Some(lat), Some(lon)) = (u16_at(bytes), u16_at(bytes)) else {
                return out;
            };
            ring.push(unit_vector(LatLon {
                lat: lat as i16 as f32 / 100.0,
                lon: lon as i16 as f32 / 100.0,
            }));
        }
        out.push(ring);
    }
    out
}

/// Meridians and parallels every 30°, sampled every 3°: on a terminal's dot
/// grid a finer net drowns the coastlines.
fn graticule() -> Vec<Vec<Vec3>> {
    let mut lines = Vec::new();
    for lon in (-180..180).step_by(30) {
        lines.push(
            (-84..=84)
                .step_by(3)
                .map(|lat| {
                    unit_vector(LatLon {
                        lat: lat as f32,
                        lon: lon as f32,
                    })
                })
                .collect(),
        );
    }
    for lat in (-60..=60).step_by(30) {
        lines.push(
            (-180..=180)
                .step_by(3)
                .map(|lon| {
                    unit_vector(LatLon {
                        lat: lat as f32,
                        lon: lon as f32,
                    })
                })
                .collect(),
        );
    }
    lines
}

fn parse_countries(text: &str) -> HashMap<[u8; 2], LatLon> {
    text.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let code = parts.next()?.as_bytes();
            if code.len() != 2 {
                return None;
            }
            let lat = parts.next()?.parse().ok()?;
            let lon = parts.next()?.parse().ok()?;
            Some(([code[0], code[1]], LatLon { lat, lon }))
        })
        .collect()
}

/// Where the user is, without asking: the country of the language setting
/// (`fa_IR.UTF-8` is Iran), and Iran when there is none. `Center` stands for
/// the whole country because that is where most people are.
pub fn home_from_locale(earth: &Earth, locale: Option<&str>) -> LatLon {
    let code = locale
        .and_then(|value| value.split('.').next())
        .and_then(|value| value.split('_').nth(1))
        .map(|value| {
            value
                .split('@')
                .next()
                .unwrap_or(value)
                .to_ascii_uppercase()
        });
    match code.as_deref() {
        Some("IR") | None => CENTER,
        Some(code) => earth.country(code).unwrap_or(CENTER),
    }
}

/// [`home_from_locale`] for this process's own language setting, worked out
/// once.
pub fn home() -> LatLon {
    static HOME: OnceLock<LatLon> = OnceLock::new();
    *HOME.get_or_init(|| {
        let locale = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()));
        home_from_locale(Earth::get(), locale.as_deref())
    })
}

/// The route from home to the country a profile's remark names, when the
/// remark names one and it is not the user's own.
pub fn route_to(remark: &str) -> Option<Route> {
    let code = zero_discovery::link::guess_country(remark);
    let target = Earth::get().country(&code)?;
    let home = home();
    let (a, b) = (unit_vector(home), unit_vector(target));
    // Under about 3° apart there is no route to draw.
    (dot(a, b) < 0.9986).then(|| Route::new(home, target))
}

/// An orthographic camera looking at a point: screen x points east, screen y
/// north, and depth toward the viewer. A point is on the visible side when
/// its depth is positive.
#[derive(Debug, Clone, Copy)]
pub struct Camera {
    east: Vec3,
    north: Vec3,
    view: Vec3,
}

impl Camera {
    pub fn looking_at(lat: f32, lon: f32) -> Self {
        let (sl, cl) = lon.to_radians().sin_cos();
        let (sp, cp) = lat.to_radians().sin_cos();
        Self {
            east: [-sl, cl, 0.0],
            north: [-sp * cl, -sp * sl, cp],
            view: [cp * cl, cp * sl, sp],
        }
    }

    /// Screen position (x east, y north, in units of the globe's radius) and
    /// depth of a point.
    pub fn project(&self, p: Vec3) -> (f32, f32, f32) {
        (dot(p, self.east), dot(p, self.north), dot(p, self.view))
    }
}

fn dot(a: Vec3, b: Vec3) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

/// Shortest-way interpolation between two longitudes, in degrees.
pub fn lerp_longitude(from: f32, to: f32, t: f32) -> f32 {
    let mut delta = (to - from) % 360.0;
    if delta > 180.0 {
        delta -= 360.0;
    }
    if delta < -180.0 {
        delta += 360.0;
    }
    from + delta * t
}

/// A great-circle route, lifted off the surface in the middle.
#[derive(Debug, Clone)]
pub struct Route {
    pub from: LatLon,
    pub to: LatLon,
    points: Vec<Vec3>,
    /// The middle of the route, where the camera looks when it follows it.
    pub center: LatLon,
}

impl Route {
    pub fn new(from: LatLon, to: LatLon) -> Self {
        let a = unit_vector(from);
        let b = unit_vector(to);
        let omega = dot(a, b).clamp(-1.0, 1.0).acos();
        let lift = 0.05 + 0.16 * omega / PI;
        let points = (0..ARC_POINTS)
            .map(|i| {
                let t = i as f32 / (ARC_POINTS - 1) as f32;
                let (wa, wb) = if omega < 1e-4 {
                    (1.0 - t, t)
                } else {
                    let s = omega.sin();
                    (((1.0 - t) * omega).sin() / s, (t * omega).sin() / s)
                };
                let v = [
                    wa * a[0] + wb * b[0],
                    wa * a[1] + wb * b[1],
                    wa * a[2] + wb * b[2],
                ];
                let len = dot(v, v).sqrt().max(1e-6);
                let h = (1.0 + lift * (PI * t).sin()) / len;
                [v[0] * h, v[1] * h, v[2] * h]
            })
            .collect();
        let mid = [a[0] + b[0], a[1] + b[1], a[2] + b[2]];
        let center = if dot(mid, mid) < 1e-4 {
            from
        } else {
            lat_lon_of(mid)
        };
        Self {
            from,
            to,
            points,
            center,
        }
    }

    /// The route at fraction `f` of its length.
    fn at(&self, f: f32) -> Vec3 {
        let last = ARC_POINTS - 1;
        let k = f.clamp(0.0, 1.0) * last as f32;
        let lo = (k as usize).min(last);
        let hi = (lo + 1).min(last);
        let fr = k - lo as f32;
        let (a, b) = (self.points[lo], self.points[hi]);
        [
            a[0] + (b[0] - a[0]) * fr,
            a[1] + (b[1] - a[1]) * fr,
            a[2] + (b[2] - a[2]) * fr,
        ]
    }
}

/// Colours the globe is drawn in.
#[derive(Debug, Clone, Copy)]
pub struct GlobePalette {
    /// The outline, the route ends and the radar.
    pub rim: Color,
    /// The coastlines.
    pub coast: Color,
    /// The graticule.
    pub grid: Color,
    /// The route.
    pub route: Color,
    /// The head of the light that travels along the route.
    pub spark: Color,
}

impl GlobePalette {
    pub fn mix(self, to: Self, t: f64) -> Self {
        Self {
            rim: lerp_color(self.rim, to.rim, t),
            coast: lerp_color(self.coast, to.coast, t),
            grid: lerp_color(self.grid, to.grid, t),
            route: lerp_color(self.route, to.route, t),
            spark: lerp_color(self.spark, to.spark, t),
        }
    }
}

/// Everything a frame of the globe needs.
pub struct Scene<'a> {
    pub earth: &'a Earth,
    pub home: LatLon,
    pub route: Option<&'a Route>,
    pub state: OrbState,
    pub palette: GlobePalette,
    /// Clock in seconds.
    pub seconds: f64,
    /// How much ambient motion is showing, `0..=1`; the sway scales with it
    /// so the camera settles instead of freezing mid-swing.
    pub ambient: f64,
    /// How far the camera has turned to face the route, `0..=1`.
    pub focus: f64,
    /// How much of the route is drawn, `0..=1`.
    pub reveal: f64,
}

/// The camera for a scene: a slow sway around home, turning toward the route
/// once there is one to follow.
pub fn camera_for(scene: &Scene) -> Camera {
    let sway = scene.ambient as f32;
    let t = scene.seconds as f32;
    let sway_lon = scene.home.lon + 32.0 * sway * (t / 11.0 * TAU).sin();
    let sway_lat = 22.0 + 4.0 * sway * (t / 7.0 * TAU).sin();
    let (focus_lat, focus_lon) = match scene.route {
        Some(route) => (
            route.center.lat.clamp(-35.0, 55.0),
            route.center.lon + 6.0 * sway * (t / 6.0 * TAU).sin(),
        ),
        None => (sway_lat, sway_lon),
    };
    let f = scene.focus as f32;
    Camera::looking_at(
        sway_lat + (focus_lat - sway_lat) * f,
        lerp_longitude(sway_lon, focus_lon, f),
    )
}

/// Draw the globe into `ctx`. `radius` is the globe's radius in canvas units
/// (one unit is one cell wide and half a row tall, so a circle is round).
pub fn paint(ctx: &mut Context, scene: &Scene, radius: f64) {
    if radius < 2.0 {
        return;
    }
    let camera = camera_for(scene);
    let r = radius as f32;

    lines(
        ctx,
        &scene.earth.graticule,
        &camera,
        r,
        scene.palette.grid,
        false,
    );
    lines(
        ctx,
        &scene.earth.coast,
        &camera,
        r,
        scene.palette.coast,
        true,
    );
    rim(ctx, radius, scene.palette.rim);

    if let Some(route) = scene.route {
        paint_route(ctx, scene, route, &camera, r);
    }
    if scene.state == OrbState::Connecting && scene.route.is_none() {
        radar(ctx, scene, &camera, r);
    }
    marker(
        ctx,
        &camera,
        r,
        unit_vector(scene.home),
        scene.palette.spark,
        pulse_at(scene, 0.0),
    );
}

/// Where in its 1.6 second cycle a marker's ring is, or `None` when ambient
/// motion is off and the marker should be a still dot.
fn pulse_at(scene: &Scene, offset: f64) -> Option<f64> {
    (scene.ambient > 0.01).then(|| ((scene.seconds + offset) % 1.6) / 1.6)
}

/// Rings with fewer points than this are islands too small to read as
/// anything but specks on a terminal's dot grid.
const MIN_RING_POINTS: usize = 14;

/// A vertex closer than this (canvas units) to the last one drawn is skipped:
/// on the dot grid the extra points only fill the coastline in.
const MIN_STEP: f64 = 1.1;

/// Polylines, front side only, joined into short lines.
fn lines(ctx: &mut Context, set: &[Vec<Vec3>], camera: &Camera, r: f32, color: Color, thin: bool) {
    for line in set {
        if thin && line.len() < MIN_RING_POINTS {
            continue;
        }
        let mut last: Option<(f64, f64)> = None;
        for (i, &p) in line.iter().enumerate() {
            let (sx, sy, depth) = camera.project(p);
            if depth < 0.0 {
                last = None;
                continue;
            }
            let here = ((sx * r) as f64, (sy * r) as f64);
            if let Some(previous) = last {
                let far = (here.0 - previous.0).hypot(here.1 - previous.1) >= MIN_STEP;
                if thin && !far && i + 1 < line.len() {
                    continue;
                }
                ctx.draw(&Line {
                    x1: previous.0,
                    y1: previous.1,
                    x2: here.0,
                    y2: here.1,
                    color,
                });
            }
            last = Some(here);
        }
    }
}

/// The globe's outline.
fn rim(ctx: &mut Context, radius: f64, color: Color) {
    let steps = ((radius * 16.0) as usize).clamp(64, 1440);
    let points: Vec<(f64, f64)> = (0..steps)
        .map(|i| {
            let theta = i as f64 / steps as f64 * std::f64::consts::TAU;
            (radius * theta.cos(), radius * theta.sin())
        })
        .collect();
    ctx.draw(&Points {
        coords: &points,
        color,
    });
}

/// How the route reads in each state: previewed as dots while idle, a comet
/// while connecting, solid with a light travelling along it once connected,
/// broken into dashes when it failed.
fn paint_route(ctx: &mut Context, scene: &Scene, route: &Route, camera: &Camera, r: f32) {
    let shown = scene.reveal as f32;
    let seconds = scene.seconds as f32;
    let palette = &scene.palette;
    match scene.state {
        OrbState::Idle => arc(ctx, route, camera, r, 0.0, shown, palette.route, Dash::Dots),
        OrbState::Error => arc(
            ctx,
            route,
            camera,
            r,
            0.0,
            shown,
            palette.route,
            Dash::Broken,
        ),
        OrbState::Connecting => {
            let head = (seconds % 1.4) / 1.4;
            arc(
                ctx,
                route,
                camera,
                r,
                (head - 0.35).max(0.0),
                head,
                palette.route,
                Dash::Solid,
            );
            head_dot(ctx, route, camera, r, head, palette.spark);
        }
        OrbState::Connected => {
            arc(
                ctx,
                route,
                camera,
                r,
                0.0,
                shown,
                palette.route,
                Dash::Solid,
            );
            if shown >= 1.0 && scene.ambient > 0.01 {
                let head = (seconds % 1.7) / 1.7;
                arc(
                    ctx,
                    route,
                    camera,
                    r,
                    (head - 0.12).max(0.0),
                    head,
                    palette.spark,
                    Dash::Solid,
                );
                head_dot(ctx, route, camera, r, head, palette.spark);
            }
        }
    }
    marker(
        ctx,
        camera,
        r,
        unit_vector(route.to),
        palette.route,
        pulse_at(scene, 0.7),
    );
}

#[derive(Clone, Copy)]
enum Dash {
    Solid,
    /// Sparse dots: a route that is planned, not used.
    Dots,
    /// Dashes: a route that broke.
    Broken,
}

/// The part of the route between fractions `from` and `to`.
#[allow(clippy::too_many_arguments)]
fn arc(
    ctx: &mut Context,
    route: &Route,
    camera: &Camera,
    r: f32,
    from: f32,
    to: f32,
    color: Color,
    dash: Dash,
) {
    if to <= from {
        return;
    }
    let steps = (((to - from) * ARC_POINTS as f32 * 2.0) as usize).max(2);
    let mut last: Option<(f64, f64)> = None;
    for i in 0..=steps {
        let f = from + (to - from) * i as f32 / steps as f32;
        let keep = match dash {
            Dash::Solid => true,
            Dash::Dots => i % 4 == 0,
            Dash::Broken => (i / 3) % 2 == 0,
        };
        let (sx, sy, depth) = camera.project(route.at(f));
        // Lifted points behind the globe are still seen outside its outline.
        let visible = depth >= 0.0 || sx * sx + sy * sy > 1.0;
        if !visible || !keep {
            if let (Dash::Dots, true, true) = (dash, visible, keep) {
                ctx.draw(&Points {
                    coords: &[((sx * r) as f64, (sy * r) as f64)],
                    color,
                });
            }
            last = None;
            continue;
        }
        let here = ((sx * r) as f64, (sy * r) as f64);
        match (last, dash) {
            (Some(previous), Dash::Solid | Dash::Broken) => ctx.draw(&Line {
                x1: previous.0,
                y1: previous.1,
                x2: here.0,
                y2: here.1,
                color,
            }),
            _ => ctx.draw(&Points {
                coords: &[here],
                color,
            }),
        }
        last = Some(here);
    }
}

/// A bright head where the light on the route is now.
fn head_dot(ctx: &mut Context, route: &Route, camera: &Camera, r: f32, at: f32, color: Color) {
    let (sx, sy, depth) = camera.project(route.at(at));
    if depth < 0.0 && sx * sx + sy * sy <= 1.0 {
        return;
    }
    let (x, y) = ((sx * r) as f64, (sy * r) as f64);
    ctx.draw(&Points {
        coords: &[
            (x, y),
            (x + 0.5, y),
            (x - 0.5, y),
            (x, y + 0.5),
            (x, y - 0.5),
        ],
        color,
    });
}

/// A place on the globe: a dot that gives off a ring every 1.6 seconds.
fn marker(ctx: &mut Context, camera: &Camera, r: f32, at: Vec3, color: Color, pulse: Option<f64>) {
    let (sx, sy, depth) = camera.project(at);
    if depth < 0.0 {
        return;
    }
    let (x, y) = ((sx * r) as f64, (sy * r) as f64);
    if let Some(pulse) = pulse.filter(|p| *p < 0.85) {
        let reach = 0.6 + pulse * 2.6;
        let ring: Vec<(f64, f64)> = (0..20)
            .map(|i| {
                let theta = i as f64 / 20.0 * std::f64::consts::TAU;
                (x + reach * theta.cos(), y + reach * theta.sin())
            })
            .collect();
        ctx.draw(&Points {
            coords: &ring,
            color,
        });
    }
    ctx.draw(&Points {
        coords: &[(x, y), (x + 0.4, y), (x - 0.4, y)],
        color,
    });
}

/// Rings that spread out from home while a server is being looked for.
fn radar(ctx: &mut Context, scene: &Scene, camera: &Camera, r: f32) {
    let seconds = scene.seconds as f32;
    for k in 0..2 {
        let frac = (seconds / 1.8 + k as f32 * 0.5) % 1.0;
        let degrees = frac * 32.0;
        let u = unit_vector(scene.home);
        // A tangent basis at home.
        let (ax, az) = if u[2].abs() < 0.9 {
            (0.0, 1.0)
        } else {
            (1.0, 0.0)
        };
        let t1 = normalize([-az * u[1], az * u[0] - ax * u[2], ax * u[1]]);
        let t2 = [
            u[1] * t1[2] - u[2] * t1[1],
            u[2] * t1[0] - u[0] * t1[2],
            u[0] * t1[1] - u[1] * t1[0],
        ];
        let (sr, cr) = degrees.to_radians().sin_cos();
        let mut points = Vec::with_capacity(48);
        for step in 0..48 {
            let theta = step as f32 / 48.0 * TAU;
            let (st, ct) = theta.sin_cos();
            let p = [
                cr * u[0] + sr * (ct * t1[0] + st * t2[0]),
                cr * u[1] + sr * (ct * t1[1] + st * t2[1]),
                cr * u[2] + sr * (ct * t1[2] + st * t2[2]),
            ];
            let (sx, sy, depth) = camera.project(p);
            if depth >= 0.0 {
                points.push(((sx * r) as f64, (sy * r) as f64));
            }
        }
        // The ring fades by thinning out.
        let keep = ((1.0 - frac) * 3.0).ceil() as usize;
        let thinned: Vec<(f64, f64)> = points
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 3 < keep)
            .map(|(_, p)| *p)
            .collect();
        ctx.draw(&Points {
            coords: &thinned,
            color: scene.palette.rim,
        });
    }
}

fn normalize(v: Vec3) -> Vec3 {
    let len = dot(v, v).sqrt().max(1e-6);
    [v[0] / len, v[1] / len, v[2] / len]
}

/// Ease used for the camera turning toward the route and the route drawing in.
pub fn smoothstep(t: f64) -> f64 {
    let t = t.clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shared_land_file_decodes_to_real_coastlines() {
        let earth = Earth::get();
        assert!(
            earth.coast.len() > 100,
            "{} rings is too few",
            earth.coast.len()
        );
        let points: usize = earth.coast.iter().map(Vec::len).sum();
        assert!((3_000..12_000).contains(&points), "{points} points");
        for ring in &earth.coast {
            for p in ring {
                assert!((dot(*p, *p) - 1.0).abs() < 1e-3, "off the unit sphere");
            }
        }
    }

    #[test]
    fn a_truncated_land_file_gives_what_it_holds_instead_of_panicking() {
        assert!(decode_land(&[]).is_empty());
        let rings = decode_land(&LAND[..LAND.len() / 2]);
        assert!(!rings.is_empty());
    }

    #[test]
    fn countries_are_found_by_code_in_any_case() {
        let earth = Earth::get();
        let de = earth.country("de").expect("Germany");
        assert!(
            (de.lat - 51.0).abs() < 6.0 && (de.lon - 10.0).abs() < 8.0,
            "{de:?}"
        );
        assert!(earth.country("IR").is_some());
        assert!(earth.country("").is_none());
        assert!(earth.country("XYZ").is_none());
        assert!(earth.country("ZZ").is_none());
    }

    #[test]
    fn home_follows_the_language_region_and_falls_back_to_iran() {
        let earth = Earth::get();
        assert_eq!(home_from_locale(earth, Some("fa_IR.UTF-8")), CENTER);
        assert_eq!(home_from_locale(earth, None), CENTER);
        assert_eq!(home_from_locale(earth, Some("C")), CENTER);
        assert_eq!(home_from_locale(earth, Some("garbage_QQ.UTF-8")), CENTER);
        let de = home_from_locale(earth, Some("de_DE.UTF-8@euro"));
        assert_eq!(Some(de), earth.country("DE"));
    }

    #[test]
    fn the_point_the_camera_looks_at_is_in_the_middle_of_the_screen() {
        for (lat, lon) in [(0.0, 0.0), (35.7, 51.4), (-33.0, 151.0), (60.0, -120.0)] {
            let camera = Camera::looking_at(lat, lon);
            let (x, y, depth) = camera.project(unit_vector(LatLon { lat, lon }));
            assert!(x.abs() < 1e-4 && y.abs() < 1e-4, "({x}, {y})");
            assert!((depth - 1.0).abs() < 1e-4);
            let (_, _, behind) = camera.project(unit_vector(LatLon {
                lat: -lat,
                lon: lon + 180.0,
            }));
            assert!(behind < -0.99, "the far side must face away");
        }
    }

    #[test]
    fn east_is_to_the_right_and_north_is_up() {
        let camera = Camera::looking_at(0.0, 0.0);
        let (east, _, _) = camera.project(unit_vector(LatLon {
            lat: 0.0,
            lon: 20.0,
        }));
        let (_, north, _) = camera.project(unit_vector(LatLon {
            lat: 20.0,
            lon: 0.0,
        }));
        assert!(east > 0.3 && north > 0.3);
    }

    #[test]
    fn a_route_runs_from_home_to_the_server_and_lifts_in_the_middle() {
        let route = Route::new(
            CENTER,
            LatLon {
                lat: 52.5,
                lon: 13.4,
            },
        );
        let start = lat_lon_of(route.at(0.0));
        let end = lat_lon_of(route.at(1.0));
        assert!((start.lat - CENTER.lat).abs() < 0.01 && (start.lon - CENTER.lon).abs() < 0.01);
        assert!((end.lat - 52.5).abs() < 0.01 && (end.lon - 13.4).abs() < 0.01);
        let mid = route.at(0.5);
        assert!(
            dot(mid, mid).sqrt() > 1.03,
            "the middle should rise off the surface"
        );
        let a = dot(route.at(0.0), route.at(0.0)).sqrt();
        assert!((a - 1.0).abs() < 1e-3, "the ends sit on the surface");
    }

    #[test]
    fn a_route_to_the_same_place_and_to_the_far_side_do_not_break() {
        let same = Route::new(CENTER, CENTER);
        assert!(same.points.iter().all(|p| p.iter().all(|c| c.is_finite())));
        let antipode = Route::new(
            LatLon {
                lat: 10.0,
                lon: 20.0,
            },
            LatLon {
                lat: -10.0,
                lon: -160.0,
            },
        );
        assert!(antipode
            .points
            .iter()
            .all(|p| p.iter().all(|c| c.is_finite())));
        assert!(antipode.center.lat.is_finite() && antipode.center.lon.is_finite());
    }

    #[test]
    fn longitudes_turn_the_short_way_round() {
        assert!((lerp_longitude(170.0, -170.0, 0.5) - 180.0).abs() < 1e-3);
        assert!((lerp_longitude(-170.0, 170.0, 0.5) + 180.0).abs() < 1e-3);
        assert_eq!(lerp_longitude(10.0, 50.0, 0.0), 10.0);
        assert_eq!(lerp_longitude(10.0, 50.0, 1.0), 50.0);
    }

    fn scene<'a>(
        earth: &'a Earth,
        route: Option<&'a Route>,
        ambient: f64,
        focus: f64,
    ) -> Scene<'a> {
        let color = Color::Rgb(200, 160, 40);
        Scene {
            earth,
            home: CENTER,
            route,
            state: OrbState::Idle,
            palette: GlobePalette {
                rim: color,
                coast: color,
                grid: color,
                route: color,
                spark: color,
            },
            seconds: 3.0,
            ambient,
            focus,
            reveal: 1.0,
        }
    }

    #[test]
    fn the_camera_sways_while_ambient_motion_is_on_and_settles_when_it_is_off() {
        let earth = Earth::get();
        let mut moving = scene(earth, None, 1.0, 0.0);
        let mut at = Vec::new();
        for s in 0..40 {
            moving.seconds = s as f64;
            at.push(camera_for(&moving).view);
        }
        assert!(at.windows(2).any(|w| w[0] != w[1]), "it never moved");
        let mut still = scene(earth, None, 0.0, 0.0);
        let first = {
            still.seconds = 0.0;
            camera_for(&still).view
        };
        for s in 1..40 {
            still.seconds = s as f64;
            assert_eq!(camera_for(&still).view, first, "it moved with ambient off");
        }
    }

    #[test]
    fn following_the_route_turns_the_camera_toward_its_middle() {
        let earth = Earth::get();
        let route = Route::new(CENTER, earth.country("US").unwrap());
        let away = camera_for(&scene(earth, Some(&route), 0.0, 0.0));
        let facing = camera_for(&scene(earth, Some(&route), 0.0, 1.0));
        let mid = unit_vector(route.center);
        assert!(dot(facing.view, mid) > dot(away.view, mid));
        assert!(dot(facing.view, mid) > 0.9);
    }

    #[test]
    fn painting_never_panics_at_any_size_or_state() {
        use ratatui::backend::TestBackend;
        use ratatui::symbols::Marker;
        use ratatui::widgets::canvas::Canvas;
        use ratatui::Terminal;

        let earth = Earth::get();
        let route = Route::new(CENTER, earth.country("NL").unwrap());
        for (w, h) in [(4u16, 3u16), (12, 6), (40, 20), (90, 30)] {
            for state in [
                OrbState::Idle,
                OrbState::Connecting,
                OrbState::Connected,
                OrbState::Error,
            ] {
                for with_route in [false, true] {
                    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
                    terminal
                        .draw(|frame| {
                            let radius = (w as f64 / 2.0).min(h as f64) * 0.8;
                            let mut s = scene(earth, with_route.then_some(&route), 1.0, 1.0);
                            s.state = state;
                            let canvas = Canvas::default()
                                .marker(Marker::Braille)
                                .x_bounds([-(w as f64) / 2.0, w as f64 / 2.0])
                                .y_bounds([-(h as f64), h as f64])
                                .paint(move |ctx| paint(ctx, &s, radius));
                            frame.render_widget(canvas, frame.area());
                        })
                        .unwrap();
                }
            }
        }
    }

    #[test]
    fn the_globe_leaves_ink_on_the_canvas_and_stays_inside_its_outline() {
        use ratatui::backend::TestBackend;
        use ratatui::symbols::Marker;
        use ratatui::widgets::canvas::Canvas;
        use ratatui::Terminal;

        let earth = Earth::get();
        let (w, h) = (40u16, 20u16);
        let radius = 16.0;
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal
            .draw(|frame| {
                let s = scene(earth, None, 1.0, 0.0);
                let canvas = Canvas::default()
                    .marker(Marker::Braille)
                    .x_bounds([-(w as f64) / 2.0, w as f64 / 2.0])
                    .y_bounds([-(h as f64), h as f64])
                    .paint(move |ctx| paint(ctx, &s, radius));
                frame.render_widget(canvas, frame.area());
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut inked = 0;
        for y in 0..h {
            for x in 0..w {
                let cell = &buffer[(x, y)];
                if cell.symbol() != " " {
                    inked += 1;
                    let dx = (x as f64 + 0.5 - w as f64 / 2.0) / (radius + 1.5);
                    let dy = (y as f64 + 0.5 - h as f64 / 2.0) / ((radius + 1.5) / 2.0);
                    assert!(
                        dx * dx + dy * dy < 1.25,
                        "ink at ({x}, {y}) is outside the globe"
                    );
                }
            }
        }
        assert!(inked > 200, "only {inked} cells drawn");
    }

    #[test]
    fn smoothstep_is_flat_at_both_ends() {
        assert_eq!(smoothstep(-1.0), 0.0);
        assert_eq!(smoothstep(2.0), 1.0);
        assert!((smoothstep(0.5) - 0.5).abs() < 1e-9);
        assert!(smoothstep(0.1) < 0.1);
    }
}
