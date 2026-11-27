//! How the last WARP connection was made, drawn as lanes.
//!
//! The core races the routes to Cloudflare (WireGuard, HTTP/2, HTTP/3) a
//! moment apart and keeps a record of when each one finished and why the
//! others did not (`zero_runtime::warp::last_race`). A race is usually over
//! before the screen draws it, so a new one is replayed from those times,
//! slowed enough to follow. Nothing here is made up: every bar ends where the
//! route it stands for ended.
//!
//! The timeline is a pure function of the record and a time, the same as the
//! Android app's `RaceTimeline.kt`; the constants match.

use std::sync::Mutex;

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use zero_config::WarpRoute;
use zero_runtime::warp::{Fail, LaneState, RaceReport};

use crate::theme::Theme;

/// A route taking this long to give up would reach the end of its track.
const TRACK_MS: f32 = 1500.0;
/// A route still trying gets this far along its track, never all the way.
const TRYING_CAP: f32 = 0.92;
/// Time a winner takes to fill the rest of its track.
const FILL_MS: f32 = 260.0;
/// The shortest replay of a finished race, and the most it is slowed.
const MIN_REPLAY_MS: f32 = 2400.0;
const MAX_SLOWDOWN: f32 = 8.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Waiting,
    Trying,
    Won,
    Lost,
    Skipped,
}

/// What to draw for one route at one moment.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LaneView {
    pub route: WarpRoute,
    pub phase: Phase,
    /// How far along its track, `0..=1`.
    pub progress: f32,
    pub fail: Option<Fail>,
    /// When it finished, in race milliseconds, once it has.
    pub ended_ms: u32,
}

/// The time the whole race spans, in race milliseconds.
pub fn span(report: &RaceReport) -> u32 {
    report
        .lanes
        .iter()
        .map(|lane| match lane.state {
            LaneState::Won | LaneState::Lost(_) => lane.ended_ms,
            LaneState::Trying => report.now_ms,
            _ => 0,
        })
        .max()
        .unwrap_or(0)
}

/// How much a finished race is slowed when replayed.
pub fn replay_scale(report: &RaceReport) -> f32 {
    (MIN_REPLAY_MS / span(report).max(1) as f32).clamp(1.0, MAX_SLOWDOWN)
}

fn along(elapsed_ms: f32) -> f32 {
    TRYING_CAP * (1.0 - (-elapsed_ms.max(0.0) / TRACK_MS).exp())
}

/// The routes as they stood `at_ms` into the race.
pub fn at(report: &RaceReport, at_ms: f32) -> Vec<LaneView> {
    report
        .lanes
        .iter()
        .map(|lane| {
            let (start, end) = (lane.started_ms as f32, lane.ended_ms as f32);
            let view = |phase, progress, fail, ended_ms| LaneView {
                route: lane.route,
                phase,
                progress,
                fail,
                ended_ms,
            };
            match lane.state {
                LaneState::Skipped => view(Phase::Skipped, 0.0, None, 0),
                LaneState::Waiting => view(Phase::Waiting, 0.0, None, 0),
                _ if at_ms < start => view(Phase::Waiting, 0.0, None, 0),
                LaneState::Trying => view(Phase::Trying, along(at_ms - start), None, 0),
                LaneState::Won => {
                    if at_ms < end {
                        view(Phase::Trying, along(at_ms - start), None, 0)
                    } else {
                        let from = along(end - start);
                        let fill = ((at_ms - end) / FILL_MS).clamp(0.0, 1.0);
                        view(Phase::Won, from + (1.0 - from) * fill, None, lane.ended_ms)
                    }
                }
                LaneState::Lost(fail) => {
                    if at_ms < end {
                        view(Phase::Trying, along(at_ms - start), None, 0)
                    } else {
                        view(Phase::Lost, along(end - start), Some(fail), lane.ended_ms)
                    }
                }
            }
        })
        .collect()
}

/// Whether the network stopped the route, as opposed to another being faster.
pub fn is_blocked(fail: Option<Fail>) -> bool {
    matches!(fail, Some(Fail::NoAnswer | Fail::Refused | Fail::NoTraffic))
}

/// The winner, and how many routes the network stopped.
pub fn verdict(report: &RaceReport) -> (Option<WarpRoute>, usize) {
    let winner = report.winner();
    let blocked = report
        .lanes
        .iter()
        .filter(|lane| matches!(lane.state, LaneState::Lost(f) if is_blocked(Some(f))))
        .count();
    (winner, blocked)
}

// ------------------------------------------------------------------ replay

/// The race being shown and the clock tick it was first seen on.
static SEEN: Mutex<Option<(u64, f64)>> = Mutex::new(None);

fn seen() -> std::sync::MutexGuard<'static, Option<(u64, f64)>> {
    SEEN.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Race time to show now: from zero when a race is first seen, then advancing
/// at real speed while it runs and slowed while a finished one is replayed.
pub fn shown_ms(report: &RaceReport, now_ticks: f64, ticks_per_second: f64) -> f32 {
    let mut seen = seen();
    let start = match *seen {
        Some((serial, start)) if serial == report.serial => start,
        _ => {
            *seen = Some((report.serial, now_ticks));
            now_ticks
        }
    };
    let real_ms = ((now_ticks - start) / ticks_per_second * 1000.0) as f32;
    let rate = if report.finished {
        replay_scale(report)
    } else {
        1.0
    };
    real_ms * rate
}

/// How long the card stays after the replay has finished.
const HOLD_MS: f32 = 12_000.0;

/// Whether the card is up: from the moment a race is first drawn until a while
/// after its replay ends. A race no one has drawn yet counts, so the frame
/// that starts the replay is asked for.
pub fn visible(now_ticks: f64, ticks_per_second: f64) -> bool {
    let Some(report) = zero_runtime::warp::last_race() else {
        return false;
    };
    if report.lanes.len() < 2 {
        return false;
    }
    let start = match *seen() {
        Some((serial, start)) if serial == report.serial => start,
        _ => return true,
    };
    if !report.finished {
        return true;
    }
    let real_ms = ((now_ticks - start) / ticks_per_second * 1000.0) as f32;
    let replay_ms = (span(&report) as f32 + FILL_MS + 400.0) / replay_scale(&report);
    real_ms < replay_ms + HOLD_MS
}

// ------------------------------------------------------------------ drawing

fn route_name(route: WarpRoute) -> &'static str {
    match route {
        WarpRoute::WireGuard => "WireGuard",
        WarpRoute::MasqueHttp2 => "Web (HTTP/2)",
        _ => "QUIC (HTTP/3)",
    }
}

fn result_text(lane: &LaneView) -> String {
    match lane.phase {
        Phase::Waiting => "waiting".into(),
        Phase::Trying => "trying…".into(),
        Phase::Won => format!("connected {:.1}s", lane.ended_ms as f32 / 1000.0),
        Phase::Skipped => "not needed".into(),
        Phase::Lost => match lane.fail {
            Some(Fail::NoAnswer) => "no answer",
            Some(Fail::Refused) => "blocked",
            Some(Fail::NoTraffic) => "nothing passed",
            Some(Fail::Beaten) => "not needed",
            _ => "failed",
        }
        .into(),
    }
}

/// One lane as a line: name, a track with a head where the route is, result.
fn lane_line<'a>(lane: &LaneView, theme: &Theme, name_w: usize, bar_w: usize) -> Line<'a> {
    let color = match lane.phase {
        Phase::Won => theme.ok,
        Phase::Lost if is_blocked(lane.fail) => theme.err,
        Phase::Lost => theme.muted,
        Phase::Trying => theme.accent,
        Phase::Waiting | Phase::Skipped => theme.border,
    };
    let head = ((lane.progress.clamp(0.0, 1.0)) * (bar_w - 1) as f32).round() as usize;
    let mut track = String::new();
    for i in 0..bar_w {
        track.push(match lane.phase {
            Phase::Waiting | Phase::Skipped => '╌',
            _ if i < head => '━',
            _ if i == head => match lane.phase {
                Phase::Won => '●',
                Phase::Lost => '×',
                _ => '●',
            },
            _ => '╌',
        });
    }
    let name = format!("{:<name_w$}", route_name(lane.route));
    let dim = matches!(lane.phase, Phase::Waiting | Phase::Skipped);
    Line::from(vec![
        Span::styled(
            name,
            Style::default().fg(if dim { theme.muted } else { theme.text }),
        ),
        Span::styled(track, Style::default().fg(color)),
        Span::styled(
            format!(" {}", result_text(lane)),
            Style::default().fg(if lane.phase == Phase::Won {
                theme.ok
            } else {
                theme.muted
            }),
        ),
    ])
}

fn verdict_text(report: &RaceReport, done_showing: bool) -> String {
    if !report.finished || !done_showing {
        return format!(
            "Trying {} ways to reach Cloudflare at once…",
            report.lanes.len()
        );
    }
    match verdict(report) {
        (None, _) => {
            "None of the ways got through. Try another network, or another account.".into()
        }
        (Some(route), blocked) if blocked > 0 => format!(
            "Connected through {}. The network blocked the other ways.",
            route_name(route)
        ),
        (Some(route), _) => format!(
            "Connected through {}, the fastest way right now.",
            route_name(route)
        ),
    }
}

/// Columns the block needs.
pub const WIDTH: u16 = 48;
/// Rows the card needs, border included.
pub const HEIGHT: u16 = 8;

/// Draw the card at the bottom middle of `area`, over the globe, when there is
/// room for it.
pub fn render(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    now_ticks: f64,
    ticks_per_second: f64,
    animate: bool,
) {
    let Some(report) = zero_runtime::warp::last_race() else {
        return;
    };
    if report.lanes.len() < 2 || area.width < WIDTH + 2 || area.height < HEIGHT + 2 {
        return;
    }
    let shown = if animate {
        shown_ms(&report, now_ticks, ticks_per_second)
    } else {
        f32::MAX
    };
    let done_showing = report.finished && shown >= span(&report) as f32 + FILL_MS;
    let views = at(&report, shown);
    let mut lines: Vec<Line> = views
        .iter()
        .map(|lane| lane_line(lane, theme, 14, 10))
        .collect();
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        verdict_text(&report, done_showing),
        Style::default().fg(theme.text),
    )));
    let card = Rect {
        x: area.x + (area.width - WIDTH) / 2,
        y: area.y + area.height - HEIGHT - 1,
        width: WIDTH,
        height: HEIGHT,
    };
    frame.render_widget(ratatui::widgets::Clear, card);
    let block = ratatui::widgets::Block::default()
        .borders(ratatui::widgets::Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            " How it connected ",
            Style::default()
                .fg(theme.muted)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme.surface));
    let inner = block.inner(card);
    frame.render_widget(block, card);
    frame.render_widget(
        Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: true }),
        inner,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_runtime::warp::{Lane, RaceReport};

    fn lane(route: WarpRoute, state: LaneState, a: u32, b: u32) -> Lane {
        Lane {
            route,
            state,
            started_ms: a,
            ended_ms: b,
        }
    }

    fn race() -> RaceReport {
        RaceReport {
            serial: 3,
            finished: true,
            now_ms: 1500,
            lanes: vec![
                lane(
                    WarpRoute::WireGuard,
                    LaneState::Lost(Fail::NoAnswer),
                    0,
                    900,
                ),
                lane(
                    WarpRoute::MasqueHttp3,
                    LaneState::Lost(Fail::Refused),
                    200,
                    260,
                ),
                lane(WarpRoute::MasqueHttp2, LaneState::Won, 400, 1300),
            ],
        }
    }

    #[test]
    fn routes_start_when_they_started_and_finish_when_they_finished() {
        let r = race();
        let early = at(&r, 100.0);
        assert_eq!(early[0].phase, Phase::Trying);
        assert_eq!(early[1].phase, Phase::Waiting);
        assert_eq!(at(&r, 230.0)[1].phase, Phase::Trying);
        let later = at(&r, 500.0);
        assert_eq!(later[1].phase, Phase::Lost);
        assert_eq!(later[1].fail, Some(Fail::Refused));
        assert_eq!(later[2].phase, Phase::Trying);
        let end = at(&r, 1700.0);
        assert_eq!(end[2].phase, Phase::Won);
        assert!((end[2].progress - 1.0).abs() < 1e-4);
    }

    #[test]
    fn a_route_still_trying_never_reaches_the_end_and_a_loser_stops_where_it_fell() {
        let trying = RaceReport {
            lanes: vec![lane(WarpRoute::WireGuard, LaneState::Trying, 0, 0)],
            finished: false,
            ..race()
        };
        let mut last = 0.0;
        for t in (0..20_000).step_by(250) {
            let p = at(&trying, t as f32)[0].progress;
            assert!(p >= last && p < 1.0);
            last = p;
        }
        let r = race();
        assert_eq!(at(&r, 950.0)[0].progress, at(&r, 5000.0)[0].progress);
    }

    #[test]
    fn a_quick_race_is_slowed_to_be_watchable_and_a_long_one_is_not() {
        assert!(replay_scale(&race()) > 1.0);
        let slow = RaceReport {
            lanes: vec![lane(WarpRoute::WireGuard, LaneState::Won, 0, 6000)],
            ..race()
        };
        assert_eq!(replay_scale(&slow), 1.0);
        let instant = RaceReport {
            lanes: vec![lane(WarpRoute::WireGuard, LaneState::Won, 0, 1)],
            ..race()
        };
        assert_eq!(replay_scale(&instant), MAX_SLOWDOWN);
    }

    #[test]
    fn the_verdict_names_the_winner_and_counts_only_routes_the_network_stopped() {
        assert_eq!(verdict(&race()), (Some(WarpRoute::MasqueHttp2), 2));
        let fast = RaceReport {
            lanes: vec![
                lane(WarpRoute::WireGuard, LaneState::Won, 0, 200),
                lane(
                    WarpRoute::MasqueHttp3,
                    LaneState::Lost(Fail::Beaten),
                    200,
                    250,
                ),
            ],
            ..race()
        };
        assert_eq!(verdict(&fast), (Some(WarpRoute::WireGuard), 0));
        assert!(verdict_text(&fast, true).contains("fastest"));
        assert!(verdict_text(&race(), true).contains("blocked the other ways"));
        assert!(verdict_text(&race(), false).starts_with("Trying 3 ways"));
        let none = RaceReport {
            lanes: vec![lane(
                WarpRoute::WireGuard,
                LaneState::Lost(Fail::NoAnswer),
                0,
                6000,
            )],
            ..race()
        };
        assert!(verdict_text(&none, true).contains("None of the ways"));
    }

    #[test]
    fn a_new_race_is_replayed_from_the_start() {
        let mut r = race();
        r.serial = 90_001;
        assert_eq!(shown_ms(&r, 1000.0, 30.0), 0.0);
        // Half a second later, a finished race runs at its replay speed.
        let later = shown_ms(&r, 1015.0, 30.0);
        assert!((later - 500.0 * replay_scale(&r)).abs() < 1.0, "{later}");
        // Another race starts over.
        r.serial = 90_002;
        assert_eq!(shown_ms(&r, 1500.0, 30.0), 0.0);
    }

    #[test]
    fn a_lane_is_one_line_with_its_track_and_its_result() {
        let theme = Theme::default();
        let r = race();
        let text = |t: f32| -> Vec<String> {
            at(&r, t)
                .iter()
                .map(|lane| {
                    lane_line(lane, &theme, 14, 10)
                        .spans
                        .iter()
                        .map(|s| s.content.to_string())
                        .collect()
                })
                .collect()
        };
        let end = text(5000.0);
        assert!(
            end[0].contains("WireGuard") && end[0].contains("no answer") && end[0].contains('×')
        );
        assert!(end[1].contains("blocked"));
        assert!(end[2].contains("connected 1.3s") && end[2].contains('●'));
        assert!(text(0.0)[2].contains("waiting"));
        // Lines are the same width however far along a lane is.
        let widths: Vec<usize> = text(700.0)
            .iter()
            .map(|l| l.chars().count().min(24))
            .collect();
        assert!(widths.iter().all(|w| *w == widths[0]));
    }
}
