//! Small drawing pieces for the "My server" page, kept apart from the screens
//! so each can be tested on its own: a text box with a caret and a selection,
//! a sparkline, a progress bar, a spinner, and the fade that lets a new screen
//! settle in.
//!
//! None of these touch the terminal. They return spans, strings or numbers;
//! the screens in `ui_servers` decide where they go and in what colours.

use crate::caret::Caret;
use crate::theme::lerp_color;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use unicode_width::UnicodeWidthChar;

/// The braille frames of the "working" spinner.
const SPIN: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// The spinner frame for the clock `ticks` (30 to the second): about ten
/// frames a second, the same pace on every machine.
pub fn spinner(ticks: f64) -> &'static str {
    SPIN[(ticks / 3.0).max(0.0) as usize % SPIN.len()]
}

const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// `width` characters showing the last `width` of `values` as bars, the tallest
/// being the largest value seen. Shorter history is padded on the left, and an
/// all-zero history is a flat line of the lowest bar so the graph is still
/// visible as a graph.
pub fn sparkline(values: &[u64], width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let shown = &values[values.len().saturating_sub(width)..];
    let top = shown.iter().copied().max().unwrap_or(0).max(1);
    let mut out: String = std::iter::repeat_n(' ', width - shown.len()).collect();
    for value in shown {
        let level = (*value as f64 / top as f64 * 7.0).round() as usize;
        out.push(BLOCKS[level.min(7)]);
    }
    out
}

/// How many bytes arrived between each reading and the one before it: the
/// shape of the traffic over time. A counter that went down (the server
/// restarted) counts as no traffic for that step.
pub fn rates(totals: &[u64]) -> Vec<u64> {
    totals
        .windows(2)
        .map(|pair| pair[1].saturating_sub(pair[0]))
        .collect()
}

/// A horizontal bar `width` wide that is `fraction` full: the number of full
/// cells, and whether a half cell follows. The fraction is clamped to 0..=1.
pub fn bar_cells(fraction: f64, width: usize) -> (usize, bool) {
    let eighths = (fraction.clamp(0.0, 1.0) * width as f64 * 2.0).round() as usize;
    (
        (eighths / 2).min(width),
        eighths % 2 == 1 && eighths / 2 < width,
    )
}

/// A progress bar as spans. `glow` (0..=1) brightens the leading cells, which
/// is what makes a bar look alive while it waits; pass 0 for a still bar.
pub fn progress_bar(
    fraction: f64,
    width: usize,
    fill: Color,
    glow_color: Color,
    empty: Color,
    glow: f64,
) -> Vec<Span<'static>> {
    let (full, half) = bar_cells(fraction, width);
    let mut spans = Vec::with_capacity(width);
    for i in 0..full {
        // A bright patch that travels along the filled part.
        let distance = (i as f64 - glow * full as f64).abs();
        let near = (1.0 - distance / 4.0).clamp(0.0, 1.0);
        let color = lerp_color(fill, glow_color, near);
        spans.push(Span::styled("█", Style::default().fg(color)));
    }
    if half {
        spans.push(Span::styled("▌", Style::default().fg(fill)));
    }
    let used = full + usize::from(half);
    if width > used {
        spans.push(Span::styled(
            "░".repeat(width - used),
            Style::default().fg(empty),
        ));
    }
    spans
}

/// Everything a text box needs to be drawn.
pub struct InputView<'a> {
    pub text: &'a str,
    /// Draw a dot for each character instead of the text.
    pub masked: bool,
    pub focused: bool,
    pub caret: Caret,
    /// The width of the box in cells, caret and padding included.
    pub width: usize,
    /// Dim text shown while the box is empty and has no focus.
    pub placeholder: &'a str,
}

/// The colours of a text box.
pub struct InputColors {
    pub text: Color,
    pub placeholder: Color,
    pub background: Color,
    pub selection_bg: Color,
    pub selection_fg: Color,
}

/// The spans of one text box, exactly `view.width` cells wide.
///
/// The text scrolls sideways so the caret stays in view. A selection is drawn
/// as a block of the selection colour; the caret is the character under it
/// reversed (or a block at the end of the text).
pub fn input_spans(view: &InputView, colors: &InputColors) -> Vec<Span<'static>> {
    let base = Style::default().fg(colors.text).bg(colors.background);
    let width = view.width.max(2);
    if view.text.is_empty() && !view.focused {
        let shown: String = view.placeholder.chars().take(width - 1).collect();
        let pad = width.saturating_sub(1 + shown.chars().count());
        return vec![Span::styled(
            format!(" {shown}{}", " ".repeat(pad)),
            Style::default()
                .fg(colors.placeholder)
                .bg(colors.background),
        )];
    }
    let chars: Vec<char> = view
        .text
        .chars()
        .map(|c| if view.masked { '•' } else { c })
        .collect();
    // The caret and selection in characters, not bytes.
    let to_char = |byte: usize| view.text[..byte.min(view.text.len())].chars().count();
    let cursor = to_char(view.caret.cursor);
    let selection = view
        .caret
        .selection()
        .map(|(a, b)| (to_char(a), to_char(b)));
    // One cell on the left for breathing room, one on the right for the caret.
    let room = width - 2;
    let start = if cursor >= room { cursor + 1 - room } else { 0 };
    let end = (start + room).min(chars.len());
    let mut spans = vec![Span::styled(" ", base)];
    let mut used = 0;
    for (i, c) in chars.iter().enumerate().take(end).skip(start) {
        let selected = selection.is_some_and(|(a, b)| i >= a && i < b);
        let at_caret = view.focused && selection.is_none() && i == cursor;
        let style = if selected && view.focused {
            Style::default()
                .fg(colors.selection_fg)
                .bg(colors.selection_bg)
        } else if at_caret {
            base.add_modifier(Modifier::REVERSED)
        } else {
            base
        };
        spans.push(Span::styled(c.to_string(), style));
        used += 1;
    }
    // The caret past the last character.
    if view.focused && selection.is_none() && cursor >= chars.len() && used < width - 1 {
        spans.push(Span::styled(" ", base.add_modifier(Modifier::REVERSED)));
        used += 1;
    }
    let pad = (width - 1).saturating_sub(used);
    if pad > 0 {
        spans.push(Span::styled(" ".repeat(pad), base));
    }
    spans
}

/// Let `area` of `buf` settle in: each row's text is blended from the
/// background towards its own colour as `t` goes from 0 to 1, the rows
/// starting one after another from the top. `t >= 1` changes nothing.
pub fn fade_in(buf: &mut Buffer, area: Rect, t: f64, background: Color) {
    if t >= 1.0 || area.height == 0 {
        return;
    }
    let rows = f64::from(area.height);
    for y in area.y..area.y.saturating_add(area.height) {
        let row = f64::from(y - area.y) / rows;
        // Each row lags the one above it by a fraction of the whole fade.
        let local = ((t * 1.6) - row * 0.6).clamp(0.0, 1.0);
        if local >= 1.0 {
            continue;
        }
        for x in area.x..area.x.saturating_add(area.width) {
            let Some(cell) = buf.cell_mut((x, y)) else {
                continue;
            };
            if cell.symbol().trim().is_empty() {
                continue;
            }
            if !matches!(cell.fg, Color::Reset) {
                cell.fg = lerp_color(background, cell.fg, local);
            }
        }
    }
}

/// How many terminal columns `text` takes.
pub fn width_of(text: &str) -> usize {
    text.chars().map(|c| c.width().unwrap_or(0)).sum()
}

/// `text` cut to `max` columns with an ellipsis when it is longer.
pub fn clip(text: &str, max: usize) -> String {
    if width_of(text) <= max {
        return text.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in text.chars() {
        let w = c.width().unwrap_or(0);
        if used + w + 1 > max {
            break;
        }
        out.push(c);
        used += w;
    }
    out.push('…');
    out
}

/// `1.4 MB`, `820 B`.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(spans: &[Span]) -> String {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn colors() -> InputColors {
        InputColors {
            text: Color::White,
            placeholder: Color::DarkGray,
            background: Color::Black,
            selection_bg: Color::Blue,
            selection_fg: Color::White,
        }
    }

    #[test]
    fn a_sparkline_is_as_wide_as_asked_and_scaled_to_its_peak() {
        assert_eq!(sparkline(&[0, 4, 8], 5), "  ▁▅█");
        assert_eq!(
            sparkline(&[1, 2, 3, 4, 5, 6], 3),
            "▆▇█",
            "only the last three, scaled to their peak"
        );
        assert_eq!(sparkline(&[], 4), "    ");
        assert_eq!(sparkline(&[0, 0], 2), "▁▁", "flat but still a graph");
        assert_eq!(sparkline(&[3], 0), "");
    }

    #[test]
    fn rates_are_the_steps_between_readings_and_never_negative() {
        assert_eq!(rates(&[10, 25, 25, 100]), vec![15, 0, 75]);
        assert_eq!(
            rates(&[100, 4]),
            vec![0],
            "a restarted counter is no traffic"
        );
        assert_eq!(rates(&[5]), Vec::<u64>::new());
    }

    #[test]
    fn a_bar_fills_in_half_cells_and_stays_inside_its_width() {
        assert_eq!(bar_cells(0.0, 10), (0, false));
        assert_eq!(bar_cells(1.0, 10), (10, false));
        assert_eq!(bar_cells(0.55, 10), (5, true));
        assert_eq!(bar_cells(7.0, 10), (10, false), "clamped");
        assert_eq!(bar_cells(-1.0, 10), (0, false));
        let bar = progress_bar(0.5, 10, Color::Green, Color::White, Color::Gray, 0.0);
        assert_eq!(text_of(&bar).chars().count(), 10);
    }

    #[test]
    fn a_text_box_is_exactly_its_width_and_marks_the_caret() {
        let text = "root";
        let spans = input_spans(
            &InputView {
                text,
                masked: false,
                focused: true,
                caret: Caret::at_end(text),
                width: 12,
                placeholder: "",
            },
            &colors(),
        );
        assert_eq!(width_of(&text_of(&spans)), 12);
        // The caret past the end is a reversed blank.
        let last_visible = spans
            .iter()
            .rev()
            .find(|s| s.style.add_modifier.contains(Modifier::REVERSED));
        assert!(last_visible.is_some(), "no caret drawn");
    }

    #[test]
    fn a_selection_is_drawn_in_the_selection_colour() {
        let text = "hello";
        let mut caret = Caret::at_end(text);
        caret.select_all(text);
        let spans = input_spans(
            &InputView {
                text,
                masked: false,
                focused: true,
                caret,
                width: 12,
                placeholder: "",
            },
            &colors(),
        );
        let selected: String = spans
            .iter()
            .filter(|s| s.style.bg == Some(Color::Blue))
            .map(|s| s.content.as_ref())
            .collect();
        assert_eq!(selected, "hello");
    }

    #[test]
    fn a_password_box_shows_dots_never_the_text() {
        let text = "hunter2";
        let spans = input_spans(
            &InputView {
                text,
                masked: true,
                focused: false,
                caret: Caret::default(),
                width: 14,
                placeholder: "",
            },
            &colors(),
        );
        let drawn = text_of(&spans);
        assert!(!drawn.contains("hunter2"));
        assert_eq!(drawn.matches('•').count(), 7);
    }

    #[test]
    fn long_text_scrolls_so_the_caret_stays_in_view() {
        let text = "0123456789abcdefghij";
        let spans = input_spans(
            &InputView {
                text,
                masked: false,
                focused: true,
                caret: Caret::at_end(text),
                width: 10,
                placeholder: "",
            },
            &colors(),
        );
        let drawn = text_of(&spans);
        assert_eq!(width_of(&drawn), 10);
        assert!(drawn.contains('j'), "the end is in view: {drawn:?}");
        assert!(!drawn.contains('0'), "the start scrolled out: {drawn:?}");
    }

    #[test]
    fn an_empty_unfocused_box_shows_its_hint() {
        let spans = input_spans(
            &InputView {
                text: "",
                masked: false,
                focused: false,
                caret: Caret::default(),
                width: 20,
                placeholder: "203.0.113.7",
            },
            &colors(),
        );
        assert!(text_of(&spans).contains("203.0.113.7"));
        assert_eq!(width_of(&text_of(&spans)), 20);
    }

    #[test]
    fn the_fade_leaves_a_finished_screen_alone_and_dims_a_new_one() {
        let area = Rect::new(0, 0, 4, 2);
        let mut buf = Buffer::empty(area);
        for y in 0..2 {
            for x in 0..4 {
                let cell = buf.cell_mut((x, y)).unwrap();
                cell.set_char('x');
                cell.fg = Color::Rgb(200, 200, 200);
            }
        }
        let mut done = buf.clone();
        fade_in(&mut done, area, 1.0, Color::Rgb(0, 0, 0));
        assert_eq!(done.cell((0, 0)).unwrap().fg, Color::Rgb(200, 200, 200));
        fade_in(&mut buf, area, 0.0, Color::Rgb(0, 0, 0));
        assert_eq!(buf.cell((0, 0)).unwrap().fg, Color::Rgb(0, 0, 0));
        assert_eq!(buf.cell((0, 1)).unwrap().fg, Color::Rgb(0, 0, 0));
    }

    #[test]
    fn the_spinner_moves_and_wraps() {
        assert_ne!(spinner(0.0), spinner(3.0));
        assert_eq!(spinner(0.0), spinner(30.0));
    }

    #[test]
    fn clipping_counts_columns_and_adds_an_ellipsis() {
        assert_eq!(clip("short", 10), "short");
        assert_eq!(clip("a very long server name", 10), "a very lo…");
        assert_eq!(human_bytes(1_572_864), "1.5 MB");
    }
}
