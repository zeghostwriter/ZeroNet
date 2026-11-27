//! Design tokens for ZeroNet TUI.
//!
//! The whole interface is built from a deliberately small palette:
//!
//! * one **accent** (amber/gold) in three weights — dim, base, bright,
//! * **ok** (emerald), **warn** (amber-orange) and **err** (crimson) for state,
//! * two **greys** — `border` for structure and `muted` for de-emphasised text,
//! * plus the three surfaces they sit on (`bg`, `surface`, `surface_hi`).
//!
//! Every colour is authored as 24-bit RGB and then passed through [`adapt`],
//! which quantises down to the xterm-256 cube or the 16 ANSI slots when the
//! terminal cannot do truecolor. Animated colours produced at runtime go
//! through the same function, so a 256-colour terminal gets a coherent
//! palette rather than an approximation of half of one.

use crate::caps::{ColorDepth, TerminalCaps};
use ratatui::style::{Color, Modifier, Style};

/// The palettes the client ships with.
///
/// `key` is what is stored in the settings table, so it must never change
/// once released; `label` is what the Settings page shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThemeId {
    GoldenDark,
    Nightshade,
    Arctic,
    Sakura,
    Paper,
    Contrast,
    /// Not in the normal rotation. The Konami code unlocks it.
    Phosphor,
}

impl ThemeId {
    /// Every palette, in Settings order.
    pub const ALL: [ThemeId; 7] = [
        ThemeId::GoldenDark,
        ThemeId::Nightshade,
        ThemeId::Arctic,
        ThemeId::Sakura,
        ThemeId::Paper,
        ThemeId::Contrast,
        ThemeId::Phosphor,
    ];

    pub fn key(self) -> &'static str {
        match self {
            ThemeId::GoldenDark => "golden-dark",
            ThemeId::Nightshade => "nightshade",
            ThemeId::Arctic => "arctic",
            ThemeId::Sakura => "sakura",
            ThemeId::Paper => "paper",
            ThemeId::Contrast => "contrast",
            ThemeId::Phosphor => "phosphor",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ThemeId::GoldenDark => "GOLDEN DARK",
            ThemeId::Nightshade => "NIGHTSHADE",
            ThemeId::Arctic => "ARCTIC",
            ThemeId::Sakura => "SAKURA",
            ThemeId::Paper => "PAPER",
            ThemeId::Contrast => "CONTRAST",
            ThemeId::Phosphor => "PHOSPHOR",
        }
    }

    /// One-line description for the Settings hint column.
    pub fn blurb(self) -> &'static str {
        match self {
            ThemeId::GoldenDark => "amber on charcoal",
            ThemeId::Nightshade => "violet, late-night",
            ThemeId::Arctic => "cool blue, calm",
            ThemeId::Sakura => "pink, soft",
            ThemeId::Paper => "light, for bright rooms",
            ThemeId::Contrast => "maximum legibility",
            ThemeId::Phosphor => "green CRT, 1983",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|id| id.key().eq_ignore_ascii_case(value.trim()))
    }

    /// Hidden palettes only join the rotation once unlocked.
    pub fn is_hidden(self) -> bool {
        self == ThemeId::Phosphor
    }

    /// The next palette in the Settings rotation.
    pub fn next(self, include_hidden: bool) -> Self {
        let order: Vec<ThemeId> = Self::ALL
            .into_iter()
            .filter(|id| include_hidden || !id.is_hidden())
            .collect();
        let at = order.iter().position(|id| *id == self);
        match at {
            Some(i) => order[(i + 1) % order.len()],
            None => order[0],
        }
    }
}

/// A palette as authored: plain 24-bit colours, before any quantising.
///
/// Kept on the [`Theme`] so animation can blend between true colours and
/// quantise the result once, instead of blending already-rounded indices.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    pub bg: Color,
    pub surface: Color,
    pub surface_hi: Color,
    pub border: Color,
    pub muted: Color,
    pub text: Color,
    pub accent: Color,
    pub accent_bright: Color,
    pub accent_dim: Color,
    /// The warm end of the accent's breath (logo, connecting glow).
    pub accent_hot: Color,
    pub ok: Color,
    pub warn: Color,
    pub err: Color,
    pub info: Color,
}

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb(r, g, b)
}

impl Palette {
    /// The success colour lifted towards the text colour: the bright end of
    /// the connected pulse.
    pub fn ok_bright(&self) -> Color {
        lerp_color(self.ok, self.text, 0.3)
    }

    /// The success colour sunk into the background: the dim end of the
    /// connected pulse, and the orb's innermost ring.
    pub fn ok_deep(&self) -> Color {
        lerp_color(self.ok, self.bg, 0.55)
    }

    /// The error colour sunk into the background, for broken-ring shading.
    pub fn err_deep(&self) -> Color {
        lerp_color(self.err, self.bg, 0.5)
    }

    pub const fn of(id: ThemeId) -> Self {
        match id {
            ThemeId::GoldenDark => Palette {
                bg: rgb(13, 15, 18),
                surface: rgb(22, 25, 32),
                surface_hi: rgb(36, 41, 52),
                border: rgb(45, 52, 66),
                muted: rgb(110, 124, 148),
                text: rgb(226, 232, 240),
                accent: rgb(245, 158, 11),
                accent_bright: rgb(251, 191, 36),
                accent_dim: rgb(146, 92, 12),
                accent_hot: rgb(249, 115, 22),
                ok: rgb(16, 185, 129),
                warn: rgb(249, 115, 22),
                err: rgb(239, 68, 68),
                info: rgb(56, 152, 233),
            },
            ThemeId::Nightshade => Palette {
                bg: rgb(17, 15, 26),
                surface: rgb(27, 24, 40),
                surface_hi: rgb(42, 37, 62),
                border: rgb(56, 50, 84),
                muted: rgb(138, 132, 168),
                text: rgb(236, 233, 248),
                accent: rgb(139, 110, 255),
                accent_bright: rgb(176, 156, 255),
                accent_dim: rgb(84, 62, 176),
                accent_hot: rgb(214, 92, 255),
                ok: rgb(29, 196, 137),
                warn: rgb(240, 164, 64),
                err: rgb(237, 85, 101),
                info: rgb(96, 170, 255),
            },
            ThemeId::Arctic => Palette {
                bg: rgb(12, 17, 25),
                surface: rgb(19, 28, 40),
                surface_hi: rgb(30, 44, 62),
                border: rgb(42, 60, 84),
                muted: rgb(116, 140, 168),
                text: rgb(226, 236, 246),
                accent: rgb(56, 152, 233),
                accent_bright: rgb(125, 196, 255),
                accent_dim: rgb(30, 88, 146),
                accent_hot: rgb(45, 212, 191),
                ok: rgb(34, 197, 94),
                warn: rgb(245, 158, 11),
                err: rgb(239, 68, 68),
                info: rgb(45, 212, 191),
            },
            ThemeId::Sakura => Palette {
                bg: rgb(21, 15, 19),
                surface: rgb(32, 23, 29),
                surface_hi: rgb(48, 34, 44),
                border: rgb(70, 48, 62),
                muted: rgb(168, 138, 156),
                text: rgb(250, 236, 244),
                accent: rgb(244, 114, 182),
                accent_bright: rgb(251, 168, 212),
                accent_dim: rgb(150, 58, 108),
                accent_hot: rgb(255, 88, 140),
                ok: rgb(52, 211, 153),
                warn: rgb(251, 146, 60),
                err: rgb(248, 80, 80),
                info: rgb(129, 140, 248),
            },
            ThemeId::Paper => Palette {
                bg: rgb(244, 241, 234),
                surface: rgb(252, 250, 246),
                surface_hi: rgb(230, 225, 214),
                border: rgb(200, 193, 180),
                muted: rgb(112, 104, 94),
                text: rgb(32, 30, 28),
                accent: rgb(176, 98, 8),
                accent_bright: rgb(206, 120, 14),
                accent_dim: rgb(214, 184, 140),
                accent_hot: rgb(190, 68, 10),
                ok: rgb(4, 132, 88),
                warn: rgb(194, 88, 12),
                err: rgb(196, 40, 40),
                info: rgb(28, 100, 182),
            },
            ThemeId::Contrast => Palette {
                bg: rgb(0, 0, 0),
                surface: rgb(10, 10, 10),
                surface_hi: rgb(44, 44, 44),
                border: rgb(128, 128, 128),
                muted: rgb(190, 190, 190),
                text: rgb(255, 255, 255),
                accent: rgb(255, 214, 0),
                accent_bright: rgb(255, 240, 110),
                accent_dim: rgb(150, 126, 0),
                accent_hot: rgb(255, 160, 0),
                ok: rgb(0, 230, 118),
                warn: rgb(255, 160, 0),
                err: rgb(255, 82, 82),
                info: rgb(64, 196, 255),
            },
            ThemeId::Phosphor => Palette {
                bg: rgb(4, 9, 5),
                surface: rgb(7, 17, 9),
                surface_hi: rgb(14, 34, 18),
                border: rgb(22, 64, 32),
                muted: rgb(66, 140, 86),
                text: rgb(176, 255, 188),
                accent: rgb(51, 255, 102),
                accent_bright: rgb(170, 255, 190),
                accent_dim: rgb(20, 118, 48),
                accent_hot: rgb(126, 255, 60),
                ok: rgb(51, 255, 102),
                warn: rgb(222, 222, 64),
                err: rgb(255, 88, 88),
                info: rgb(90, 224, 206),
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub id: ThemeId,
    pub depth: ColorDepth,
    /// The palette before quantising, for animation to blend in.
    pub raw: Palette,

    // Surfaces
    pub bg: Color,
    pub surface: Color,
    pub surface_hi: Color,

    // Greys
    pub border: Color,
    pub border_focus: Color,
    pub muted: Color,
    pub text: Color,

    // Accent
    pub accent: Color,
    pub accent_bright: Color,
    pub accent_dim: Color,

    // State
    pub ok: Color,
    pub warn: Color,
    pub err: Color,
    pub info: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self::golden_dark(ColorDepth::TrueColor)
    }
}

impl Theme {
    /// The signature palette: warm gold on near-black with faint borders.
    pub fn golden_dark(depth: ColorDepth) -> Self {
        Self::new(ThemeId::GoldenDark, depth)
    }

    pub fn new(id: ThemeId, depth: ColorDepth) -> Self {
        let raw = Palette::of(id);
        Self {
            id,
            depth,
            raw,
            bg: adapt(raw.bg, depth),
            surface: adapt(raw.surface, depth),
            surface_hi: adapt(raw.surface_hi, depth),
            border: adapt(raw.border, depth),
            border_focus: adapt(raw.accent, depth),
            muted: adapt(raw.muted, depth),
            text: adapt(raw.text, depth),
            accent: adapt(raw.accent, depth),
            accent_bright: adapt(raw.accent_bright, depth),
            accent_dim: adapt(raw.accent_dim, depth),
            ok: adapt(raw.ok, depth),
            warn: adapt(raw.warn, depth),
            err: adapt(raw.err, depth),
            info: adapt(raw.info, depth),
        }
    }

    pub fn from_caps(caps: &TerminalCaps) -> Self {
        Self::golden_dark(caps.depth)
    }

    /// The theme named in settings, falling back to the default for an
    /// unknown or empty key.
    pub fn from_setting(caps: &TerminalCaps, key: &str) -> Self {
        Self::new(
            ThemeId::parse(key).unwrap_or(ThemeId::GoldenDark),
            caps.depth,
        )
    }

    /// Whether this is a light palette. Glows brighten towards white on a
    /// dark theme; on a light one they deepen instead.
    pub fn is_light(&self) -> bool {
        self.id == ThemeId::Paper
    }

    /// Quantise a runtime-computed colour to what this terminal can show.
    pub fn adapt(&self, color: Color) -> Color {
        adapt(color, self.depth)
    }

    pub fn page_style(&self) -> Style {
        Style::default().bg(self.bg).fg(self.text)
    }

    pub fn card_style(&self) -> Style {
        Style::default().bg(self.surface).fg(self.text)
    }

    pub fn card_hover_style(&self) -> Style {
        Style::default()
            .bg(self.surface_hi)
            .fg(self.accent_bright)
            .add_modifier(Modifier::BOLD)
    }

    pub fn title_style(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn border_style(&self, focused: bool) -> Style {
        Style::default().fg(if focused {
            self.border_focus
        } else {
            self.border
        })
    }

    /// The colour a latency reading should be drawn in: green under 100 ms,
    /// amber under 250 ms, red beyond that, grey when unmeasured.
    pub fn latency_color(&self, ping_ms: Option<f64>) -> Color {
        match ping_ms {
            Some(p) if p < 100.0 => self.ok,
            Some(p) if p < 250.0 => self.warn,
            Some(_) => self.err,
            None => self.muted,
        }
    }
}

/// Reduce `color` to something the given depth can render faithfully.
///
/// Non-RGB colours pass through untouched — they are already indexed.
pub fn adapt(color: Color, depth: ColorDepth) -> Color {
    let Color::Rgb(r, g, b) = color else {
        return color;
    };
    match depth {
        ColorDepth::TrueColor => color,
        ColorDepth::Ansi256 => Color::Indexed(rgb_to_xterm256(r, g, b)),
        ColorDepth::Ansi16 => rgb_to_ansi16(r, g, b),
    }
}

/// Map an RGB triple onto the xterm-256 palette.
///
/// Tries both the 6×6×6 colour cube and the 24-step grey ramp and keeps
/// whichever lands closer, which matters for this theme: the near-black
/// surfaces and the mid greys are far better served by the grey ramp than by
/// the cube's coarse 0/95/135/175/215/255 steps.
pub fn rgb_to_xterm256(r: u8, g: u8, b: u8) -> u8 {
    const CUBE: [u8; 6] = [0, 95, 135, 175, 215, 255];

    let nearest_cube_index = |v: u8| -> usize {
        let mut best = 0usize;
        let mut best_err = i32::MAX;
        for (i, level) in CUBE.iter().enumerate() {
            let err = (*level as i32 - v as i32).abs();
            if err < best_err {
                best_err = err;
                best = i;
            }
        }
        best
    };

    let (ri, gi, bi) = (
        nearest_cube_index(r),
        nearest_cube_index(g),
        nearest_cube_index(b),
    );
    let cube_index = 16 + 36 * ri as u16 + 6 * gi as u16 + bi as u16;
    let cube_err = dist_sq(r, g, b, CUBE[ri], CUBE[gi], CUBE[bi]);

    // Grey ramp: indices 232..=255 are 8, 18, 28, ... 238.
    let luma = (r as u32 * 299 + g as u32 * 587 + b as u32 * 114) / 1000;
    let grey_step = (((luma as i32 - 8) + 5) / 10).clamp(0, 23) as u8;
    let grey_value = (8 + grey_step as u32 * 10).min(255) as u8;
    let grey_err = dist_sq(r, g, b, grey_value, grey_value, grey_value);

    if grey_err < cube_err {
        232 + grey_step
    } else {
        cube_index as u8
    }
}

fn dist_sq(r1: u8, g1: u8, b1: u8, r2: u8, g2: u8, b2: u8) -> i32 {
    let dr = r1 as i32 - r2 as i32;
    let dg = g1 as i32 - g2 as i32;
    let db = b1 as i32 - b2 as i32;
    dr * dr + dg * dg + db * db
}

/// Last-resort mapping onto the 16 ANSI slots.
fn rgb_to_ansi16(r: u8, g: u8, b: u8) -> Color {
    let luma = (r as u32 * 299 + g as u32 * 587 + b as u32 * 114) / 1000;
    if luma < 40 {
        return Color::Black;
    }
    if luma > 220 && r.abs_diff(g) < 30 && g.abs_diff(b) < 30 {
        return Color::White;
    }

    let bright = luma > 128;
    let max = r.max(g).max(b);
    // A near-neutral colour has no dominant channel to pick from.
    if max.abs_diff(r.min(g).min(b)) < 30 {
        return if bright { Color::Gray } else { Color::DarkGray };
    }

    match (r == max, g == max, b == max) {
        (true, _, _) if g > 120 && g > b => {
            if bright {
                Color::LightYellow
            } else {
                Color::Yellow
            }
        }
        (true, _, _) if b > 120 => {
            if bright {
                Color::LightMagenta
            } else {
                Color::Magenta
            }
        }
        (true, _, _) => {
            if bright {
                Color::LightRed
            } else {
                Color::Red
            }
        }
        (_, true, _) if b > 120 => {
            if bright {
                Color::LightCyan
            } else {
                Color::Cyan
            }
        }
        (_, true, _) => {
            if bright {
                Color::LightGreen
            } else {
                Color::Green
            }
        }
        _ => {
            if bright {
                Color::LightBlue
            } else {
                Color::Blue
            }
        }
    }
}

/// Linear interpolation between two colours; `t` is clamped to `0.0..=1.0`.
///
/// Used by the connect orb's pulse and the logo's gold→orange breathing, both
/// of which need a new colour every frame rather than a fixed set of stops.
///
/// The result stays in the colour space of its inputs, so a caller never gets
/// a 24-bit colour back on a terminal that cannot show one:
///
/// * two RGB colours blend in RGB;
/// * if either side is an xterm-256 index, the blend is done in RGB and
///   re-quantised to the nearest index — a 256-colour terminal still gets a
///   (stepped) gradient rather than a hard switch half-way;
/// * the 16 named ANSI colours have no reliable RGB value (every terminal
///   theme redefines them), so they snap at the midpoint.
pub fn lerp_color(from: Color, to: Color, t: f64) -> Color {
    let t = t.clamp(0.0, 1.0);
    if t <= 0.0 {
        return from;
    }
    if t >= 1.0 {
        return to;
    }
    match (from, to) {
        (Color::Rgb(r1, g1, b1), Color::Rgb(r2, g2, b2)) => {
            Color::Rgb(lerp_u8(r1, r2, t), lerp_u8(g1, g2, t), lerp_u8(b1, b2, t))
        }
        _ => match (indexed_or_rgb(from), indexed_or_rgb(to)) {
            (Some((r1, g1, b1)), Some((r2, g2, b2))) => Color::Indexed(rgb_to_xterm256(
                lerp_u8(r1, r2, t),
                lerp_u8(g1, g2, t),
                lerp_u8(b1, b2, t),
            )),
            _ => {
                if t < 0.5 {
                    from
                } else {
                    to
                }
            }
        },
    }
}

/// The RGB value of a truecolor or xterm-256 cube/grey colour.
///
/// Indices 0–15 and the named colours are deliberately `None`: those are the
/// slots terminal themes repaint, so their "real" RGB is unknowable.
fn indexed_or_rgb(color: Color) -> Option<(u8, u8, u8)> {
    match color {
        Color::Rgb(r, g, b) => Some((r, g, b)),
        Color::Indexed(i) => xterm256_to_rgb(i),
        _ => None,
    }
}

/// Inverse of [`rgb_to_xterm256`] for the fixed part of the palette.
pub fn xterm256_to_rgb(index: u8) -> Option<(u8, u8, u8)> {
    const CUBE: [u8; 6] = [0, 95, 135, 175, 215, 255];
    match index {
        0..=15 => None,
        16..=231 => {
            let i = index - 16;
            Some((
                CUBE[(i / 36) as usize],
                CUBE[((i / 6) % 6) as usize],
                CUBE[(i % 6) as usize],
            ))
        }
        232..=255 => {
            let v = 8 + (index - 232) * 10;
            Some((v, v, v))
        }
    }
}

fn lerp_u8(a: u8, b: u8, t: f64) -> u8 {
    (a as f64 + (b as f64 - a as f64) * t)
        .round()
        .clamp(0.0, 255.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truecolor_passes_rgb_through_unchanged() {
        let c = Color::Rgb(245, 158, 11);
        assert_eq!(adapt(c, ColorDepth::TrueColor), c);
    }

    #[test]
    fn ansi256_quantises_to_an_index() {
        let c = adapt(Color::Rgb(245, 158, 11), ColorDepth::Ansi256);
        assert!(matches!(c, Color::Indexed(_)), "got {c:?}");
    }

    #[test]
    fn near_black_prefers_the_grey_ramp_over_the_cube() {
        // #0d0f12 is far closer to grey index 232 (#080808) than to the
        // cube's pure black, and using the cube would flatten every surface
        // in the UI to the same colour.
        let idx = rgb_to_xterm256(13, 15, 18);
        assert!(idx >= 232, "expected a grey-ramp index, got {idx}");
    }

    #[test]
    fn distinct_surfaces_stay_distinct_at_256_colors() {
        let theme = Theme::golden_dark(ColorDepth::Ansi256);
        assert_ne!(theme.bg, theme.surface);
        assert_ne!(theme.surface, theme.surface_hi);
        assert_ne!(theme.accent, theme.ok);
        assert_ne!(theme.ok, theme.err);
    }

    #[test]
    fn lerp_moves_between_endpoints() {
        let a = Color::Rgb(0, 0, 0);
        let b = Color::Rgb(255, 255, 255);
        assert_eq!(lerp_color(a, b, 0.0), a);
        assert_eq!(lerp_color(a, b, 1.0), b);
        assert_eq!(lerp_color(a, b, 0.5), Color::Rgb(128, 128, 128));
    }

    #[test]
    fn indexed_colours_blend_through_rgb_and_stay_indexed() {
        // On a 256-colour terminal every theme colour is an index. Snapping
        // at the midpoint turned every glow into a hard two-frame flicker.
        let from = adapt(Color::Rgb(9, 121, 85), ColorDepth::Ansi256);
        let to = adapt(Color::Rgb(52, 211, 153), ColorDepth::Ansi256);
        let mut seen = std::collections::HashSet::new();
        for i in 0..=20 {
            let c = lerp_color(from, to, i as f64 / 20.0);
            assert!(
                matches!(c, Color::Indexed(_)),
                "left the 256 palette: {c:?}"
            );
            seen.insert(format!("{c:?}"));
        }
        assert!(seen.len() >= 3, "only {} steps in the gradient", seen.len());
        assert_eq!(lerp_color(from, to, 0.0), from);
        assert_eq!(lerp_color(from, to, 1.0), to);
    }

    #[test]
    fn named_ansi_colours_still_snap() {
        assert_eq!(lerp_color(Color::Red, Color::Green, 0.3), Color::Red);
        assert_eq!(lerp_color(Color::Red, Color::Green, 0.7), Color::Green);
    }

    #[test]
    fn xterm_round_trip_is_exact_for_cube_and_greys() {
        for i in 16..=255u8 {
            let (r, g, b) = xterm256_to_rgb(i).unwrap();
            assert_eq!(rgb_to_xterm256(r, g, b), i, "index {i} did not round-trip");
        }
        assert_eq!(xterm256_to_rgb(3), None);
    }

    #[test]
    fn every_theme_keeps_its_surfaces_and_states_apart() {
        for id in ThemeId::ALL {
            for depth in [ColorDepth::TrueColor, ColorDepth::Ansi256] {
                let t = Theme::new(id, depth);
                assert_ne!(t.bg, t.text, "{id:?} {depth:?}: text on bg");
                assert_ne!(t.surface, t.surface_hi, "{id:?} {depth:?}: hover");
                assert_ne!(t.ok, t.err, "{id:?} {depth:?}: ok vs err");
                assert_ne!(t.accent, t.surface, "{id:?} {depth:?}: accent");
            }
        }
    }

    /// WCAG relative luminance of an RGB colour.
    fn luminance(c: Color) -> f64 {
        let Color::Rgb(r, g, b) = c else {
            panic!("palettes are authored in RGB, got {c:?}");
        };
        let lin = |v: u8| {
            let v = v as f64 / 255.0;
            if v <= 0.04045 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
    }

    fn contrast(a: Color, b: Color) -> f64 {
        let (x, y) = (luminance(a), luminance(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    #[test]
    fn every_theme_is_readable() {
        for id in ThemeId::ALL {
            let p = Palette::of(id);
            let body = contrast(p.text, p.bg);
            assert!(body >= 7.0, "{id:?}: text/bg {body:.2}");
            let card = contrast(p.text, p.surface_hi);
            assert!(card >= 4.5, "{id:?}: text on a hovered row {card:.2}");
            let muted = contrast(p.muted, p.surface);
            assert!(muted >= 3.0, "{id:?}: muted/surface {muted:.2}");
            let accent = contrast(p.accent, p.surface);
            assert!(accent >= 3.0, "{id:?}: accent/surface {accent:.2}");
        }
    }

    #[test]
    fn theme_keys_round_trip_and_hidden_themes_stay_out_of_rotation() {
        for id in ThemeId::ALL {
            assert_eq!(ThemeId::parse(id.key()), Some(id));
        }
        assert_eq!(ThemeId::parse("nonsense"), None);
        let mut id = ThemeId::GoldenDark;
        for _ in 0..20 {
            id = id.next(false);
            assert!(!id.is_hidden());
        }
        assert_eq!(ThemeId::Contrast.next(true), ThemeId::Phosphor);
        assert_eq!(ThemeId::Phosphor.next(false), ThemeId::GoldenDark);
    }

    #[test]
    fn latency_colors_follow_thresholds() {
        let t = Theme::default();
        assert_eq!(t.latency_color(Some(42.0)), t.ok);
        assert_eq!(t.latency_color(Some(180.0)), t.warn);
        assert_eq!(t.latency_color(Some(900.0)), t.err);
        assert_eq!(t.latency_color(None), t.muted);
    }
}
