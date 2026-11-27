//! The connection test as a path.
//!
//! The phone, the provider, the filter and the open internet in a row, and the
//! tunnel as an arc over the filter. Each step lights up as its checks finish;
//! a failed step shows the line breaking where it broke, and one plain
//! sentence says what that means. The Android app draws the same picture
//! (`ui/effects/PathMap.kt`) from the same rules.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use zero_discovery::selftest::{Check, Id, Problem, Status};

use crate::theme::Theme;

/// The steps of the path, in the order the direct path runs; `Bypass` is the
/// tunnel around the filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Device,
    Provider,
    Filter,
    Bypass,
}

const NODE: usize = 10;
const SEG: usize = 8;
/// Columns the picture takes.
pub const WIDTH: usize = 4 * NODE + 3 * SEG;
/// Rows the picture takes.
pub const HEIGHT: usize = 4;

/// The worst of several statuses: a failure outranks a warning, which
/// outranks unfinished work.
pub fn combine(statuses: &[Status]) -> Status {
    let has = |s| statuses.contains(&s);
    if statuses.is_empty() {
        Status::Pending
    } else if has(Status::Bad) {
        Status::Bad
    } else if has(Status::Warn) {
        Status::Warn
    } else if has(Status::Running) {
        Status::Running
    } else if has(Status::Pending) {
        Status::Pending
    } else if has(Status::Ok) {
        Status::Ok
    } else {
        Status::Skipped
    }
}

pub fn status(step: Step, checks: &[Check]) -> Status {
    let of = |ids: &[Id]| -> Vec<Status> {
        checks
            .iter()
            .filter(|c| ids.contains(&c.id))
            .map(|c| c.status)
            .collect()
    };
    combine(&match step {
        Step::Device => of(&[Id::Network]),
        Step::Provider => of(&[Id::Internet, Id::Dns]),
        Step::Filter => of(&[Id::Tls]),
        Step::Bypass => of(&[Id::Tunnel]),
    })
}

/// The step a problem sits at, where the picture shows the break.
pub fn step_of(problem: Problem) -> Option<Step> {
    match problem {
        Problem::None => None,
        Problem::NoNetwork => Some(Step::Device),
        Problem::NoInternet | Problem::Redirected | Problem::FakeDns => Some(Step::Provider),
        Problem::NameFilter => Some(Step::Filter),
        Problem::NoServer => Some(Step::Bypass),
    }
}

/// What is wrong, in the words a person would use.
pub fn headline(problem: Problem) -> &'static str {
    match problem {
        Problem::None => "Nothing is blocking you right now.",
        Problem::NoNetwork => "Your computer has no network.",
        Problem::NoInternet => "This network does not let traffic through to the internet.",
        Problem::Redirected => {
            "Something on this network redirects your traffic, like a login page or a filter."
        }
        Problem::FakeDns => "Your provider gives fake answers for blocked sites.",
        Problem::NameFilter => {
            "The filter reads site names in secure connections and cuts the ones it dislikes."
        }
        Problem::NoServer => "The tunnel did not carry a request right now.",
    }
}

/// What to do, or what ZeroNet does about it.
pub fn action(problem: Problem) -> Option<&'static str> {
    match problem {
        Problem::None => None,
        Problem::NoNetwork | Problem::NoInternet => {
            Some("Connect to a network that has internet, then run the test again.")
        }
        Problem::Redirected => {
            Some("Open your browser once to check for a login page, then run the test again.")
        }
        Problem::FakeDns => {
            Some("ZeroNet uses its own DNS inside the tunnel, so this does not stop it.")
        }
        Problem::NameFilter => {
            Some("ZeroNet prefers servers that hide the name, so they still get through.")
        }
        Problem::NoServer => Some("Try another profile, or press F to find servers."),
    }
}

fn color_of(status: Status, theme: &Theme) -> Color {
    match status {
        Status::Ok => theme.ok,
        Status::Warn => theme.warn,
        Status::Bad => theme.err,
        Status::Running => theme.accent,
        Status::Pending | Status::Skipped => theme.border,
    }
}

type Grid = Vec<Vec<(char, Color)>>;

fn put(grid: &mut Grid, row: usize, col: usize, ch: char, color: Color) {
    if let Some(cell) = grid.get_mut(row).and_then(|r| r.get_mut(col)) {
        *cell = (ch, color);
    }
}

/// One step of the direct path, in the eight columns between two nodes.
fn segment(grid: &mut Grid, row: usize, x: usize, status: Status, tick: u64, theme: &Theme) {
    let color = color_of(status, theme);
    let dim = theme.border;
    match status {
        Status::Pending | Status::Skipped => (0..SEG).for_each(|i| put(grid, row, x + i, '┄', dim)),
        Status::Running => {
            (0..SEG).for_each(|i| put(grid, row, x + i, '╌', dim));
            put(grid, row, x + (tick / 2) as usize % SEG, '●', color);
        }
        Status::Ok => (0..SEG).for_each(|i| put(grid, row, x + i, '━', color)),
        Status::Warn => {
            (0..SEG).for_each(|i| put(grid, row, x + i, if i % 2 == 0 { '━' } else { '╸' }, color))
        }
        Status::Bad => {
            (0..SEG / 2).for_each(|i| put(grid, row, x + i, '━', color));
            put(grid, row, x + SEG / 2, '╳', color);
            (SEG / 2 + 1..SEG).for_each(|i| put(grid, row, x + i, '╌', dim));
        }
    }
}

/// The picture: [`HEIGHT`] lines of [`WIDTH`] columns.
pub fn lines(checks: &[Check], tick: u64, theme: &Theme, finished: bool) -> Vec<Line<'static>> {
    let mut grid: Grid = vec![vec![(' ', theme.border); WIDTH]; HEIGHT];
    let statuses =
        [Step::Device, Step::Provider, Step::Filter, Step::Bypass].map(|s| status(s, checks));
    let node_x = |i: usize| i * (NODE + SEG);
    let centre = |i: usize| node_x(i) + NODE / 2;
    let row = HEIGHT - 1;

    // The direct path.
    for (i, status) in statuses.iter().take(3).enumerate() {
        segment(&mut grid, row, node_x(i) + NODE, *status, tick, theme);
    }

    // The way around the filter: a square arc from the provider to the internet.
    let (left, right) = (centre(1), centre(3));
    let arc = statuses[3];
    let arc_color = color_of(arc, theme);
    let dim = theme.border;
    let top = right - left - 1;
    let broken_at = top * 6 / 10;
    for i in 0..top {
        let x = left + 1 + i;
        let (ch, color) = match arc {
            Status::Pending | Status::Skipped => ('┄', dim),
            Status::Running => ('┄', dim),
            Status::Ok | Status::Warn => ('─', arc_color),
            Status::Bad if i < broken_at => ('─', arc_color),
            Status::Bad if i == broken_at => ('╳', arc_color),
            Status::Bad => ('╌', dim),
        };
        put(&mut grid, 0, x, ch, color);
    }
    let (corner_l, corner_r, side) = match arc {
        Status::Ok | Status::Warn => ('╭', '╮', arc_color),
        Status::Bad => ('╭', '╮', arc_color),
        _ => ('╭', '╮', dim),
    };
    put(&mut grid, 0, left, corner_l, side);
    put(
        &mut grid,
        0,
        right,
        corner_r,
        if arc == Status::Bad { dim } else { side },
    );
    for r in 1..row {
        put(&mut grid, r, left, '│', side);
        put(
            &mut grid,
            r,
            right,
            '│',
            if arc == Status::Bad { dim } else { side },
        );
    }
    match arc {
        Status::Running => {
            let at = (tick / 2) as usize % top.max(1);
            put(&mut grid, 0, left + 1 + at, '●', arc_color);
        }
        Status::Ok => {
            for k in 0..3 {
                let at = ((tick / 2) as usize + k * top / 3) % top.max(1);
                put(&mut grid, 0, left + 1 + at, '•', theme.text);
            }
        }
        _ => {}
    }
    // The words on the arc.
    let label = " tunnel ";
    let start = left + 1 + (top.saturating_sub(label.len())) / 2;
    if !matches!(arc, Status::Bad) || start + label.len() < left + 1 + broken_at {
        for (i, ch) in label.chars().enumerate() {
            put(
                &mut grid,
                0,
                start + i,
                ch,
                if arc == Status::Pending {
                    dim
                } else {
                    arc_color
                },
            );
        }
    }

    // The nodes.
    let direct_clear = statuses[..3]
        .iter()
        .all(|s| matches!(s, Status::Ok | Status::Warn));
    let world_status = if statuses[3] == Status::Ok || (direct_clear && finished) {
        Status::Ok
    } else if finished {
        Status::Bad
    } else {
        Status::Pending
    };
    let names = ["▯ Phone", "◠ Provider", "▦ Filter", "◍ Internet"];
    let node_status = [statuses[0], statuses[1], statuses[2], world_status];
    for i in 0..4 {
        let color = color_of(node_status[i], theme);
        let name: Vec<char> = names[i].chars().collect();
        let start = node_x(i) + (NODE - name.len().min(NODE)) / 2;
        for (k, ch) in name.iter().take(NODE).enumerate() {
            put(&mut grid, row, start + k, *ch, color);
        }
    }

    grid.into_iter()
        .map(|cells| {
            let mut spans: Vec<Span<'static>> = Vec::new();
            let mut run = String::new();
            let mut current: Option<Color> = None;
            for (ch, color) in cells {
                if current != Some(color) && !run.is_empty() {
                    spans.push(Span::styled(
                        std::mem::take(&mut run),
                        Style::default().fg(current.unwrap_or(color)),
                    ));
                }
                current = Some(color);
                run.push(ch);
            }
            if !run.is_empty() {
                spans.push(Span::styled(
                    run,
                    Style::default()
                        .fg(current.unwrap_or(theme.text))
                        .add_modifier(Modifier::BOLD),
                ));
            }
            Line::from(spans)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_discovery::selftest::{Check, Id, Status};

    fn checks(s: [Status; 5]) -> Vec<Check> {
        Id::ALL
            .iter()
            .zip(s)
            .map(|(id, status)| Check {
                id: *id,
                status,
                detail: String::new(),
            })
            .collect()
    }

    fn text(lines: &[Line]) -> Vec<String> {
        lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.to_string()).collect())
            .collect()
    }

    use Status::{Bad, Ok as Good, Pending, Running, Skipped};

    #[test]
    fn a_step_takes_the_worst_of_its_checks() {
        assert_eq!(combine(&[Good, Bad, Status::Warn]), Bad);
        assert_eq!(combine(&[Good, Running, Pending]), Running);
        assert_eq!(combine(&[Good, Skipped]), Good);
        assert_eq!(combine(&[]), Pending);
        let c = checks([Good, Good, Bad, Good, Skipped]);
        assert_eq!(status(Step::Provider, &c), Bad);
        assert_eq!(status(Step::Bypass, &c), Skipped);
    }

    #[test]
    fn every_problem_has_words_and_a_place_on_the_path() {
        use zero_discovery::selftest::Problem::*;
        for problem in [
            None, NoNetwork, NoInternet, Redirected, FakeDns, NameFilter, NoServer,
        ] {
            assert!(!headline(problem).is_empty());
            assert_eq!(step_of(problem).is_some(), problem != None);
            assert_eq!(action(problem).is_some(), problem != None);
        }
    }

    #[test]
    fn the_picture_is_always_the_same_size() {
        let theme = Theme::default();
        for statuses in [
            [Pending; 5],
            [Running, Pending, Pending, Pending, Pending],
            [Good, Good, Good, Good, Good],
            [Good, Bad, Bad, Bad, Bad],
            [Good, Good, Good, Bad, Good],
        ] {
            for tick in [0, 1, 7, 63, 1000] {
                let drawn = text(&lines(&checks(statuses), tick, &theme, true));
                assert_eq!(drawn.len(), HEIGHT);
                for row in drawn {
                    assert_eq!(row.chars().count(), WIDTH, "{row:?}");
                }
            }
        }
    }

    #[test]
    fn a_failed_step_shows_where_the_line_broke_and_a_working_one_does_not() {
        let theme = Theme::default();
        let broken = text(&lines(
            &checks([Good, Good, Good, Bad, Good]),
            0,
            &theme,
            true,
        ));
        assert!(broken[3].contains('╳'), "{broken:?}");
        let fine = text(&lines(
            &checks([Good, Good, Good, Good, Good]),
            0,
            &theme,
            true,
        ));
        assert!(!fine.iter().any(|row| row.contains('╳')));
        // The tunnel around the filter is a second break when it fails too.
        let both = text(&lines(
            &checks([Good, Good, Good, Bad, Bad]),
            0,
            &theme,
            true,
        ));
        assert!(both[0].contains('╳') && both[3].contains('╳'));
    }

    #[test]
    fn a_running_step_moves_and_a_finished_one_does_not() {
        let theme = Theme::default();
        let running = checks([Good, Running, Pending, Pending, Pending]);
        assert_ne!(
            text(&lines(&running, 0, &theme, false)),
            text(&lines(&running, 2, &theme, false))
        );
        let done = checks([Good, Good, Good, Good, Skipped]);
        assert_eq!(
            text(&lines(&done, 0, &theme, true)),
            text(&lines(&done, 2, &theme, true))
        );
        // The working tunnel carries light along its arc.
        let tunnel = checks([Good, Good, Good, Bad, Good]);
        assert_ne!(
            text(&lines(&tunnel, 0, &theme, true)),
            text(&lines(&tunnel, 4, &theme, true))
        );
    }

    #[test]
    fn the_nodes_are_named() {
        let theme = Theme::default();
        let drawn = text(&lines(&checks([Pending; 5]), 0, &theme, false)).join("\n");
        for name in ["Phone", "Provider", "Filter", "Internet"] {
            assert!(drawn.contains(name), "{name}");
        }
    }
}
