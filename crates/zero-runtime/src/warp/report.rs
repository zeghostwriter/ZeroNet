//! What the last route race looked like, for a screen to draw.
//!
//! The race itself lives in [`super`]. This is only its record: which routes
//! started when, which won, and why each of the others did not. It is
//! updated as the race runs, so a screen polling [`last_race`] sees the same
//! thing happen that the connection does.

use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use zero_config::WarpRoute;

/// Why a route lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fail {
    /// The network dropped it: nothing came back before the deadline.
    NoAnswer,
    /// Something answered and closed the connection: a reset or a refusal.
    Refused,
    /// It connected, and could not fetch a page through the tunnel.
    NoTraffic,
    /// Another route won first while this one was still trying.
    Beaten,
    /// Anything else (a key the server did not accept, a setup error).
    Other,
}

impl Fail {
    /// Sort an error message from a route attempt into a reason.
    pub fn of(error: &str) -> Self {
        let error = error.to_ascii_lowercase();
        if error.contains("fetch") || error.contains("probe") || error.contains("carry") {
            Self::NoTraffic
        } else if error.contains("timed out") || error.contains("timeout") {
            Self::NoAnswer
        } else if error.contains("reset")
            || error.contains("refused")
            || error.contains("closed")
            || error.contains("eof")
        {
            Self::Refused
        } else {
            Self::Other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneState {
    /// Not started yet: routes start a moment apart.
    Waiting,
    Trying,
    Won,
    Lost(Fail),
    /// The race ended before this route was due to start.
    Skipped,
}

/// One route in a race. Times are milliseconds since the race began.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lane {
    pub route: WarpRoute,
    pub state: LaneState,
    pub started_ms: u32,
    /// When it finished, or the time of the snapshot while it is still going.
    pub ended_ms: u32,
}

/// A race, as it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaceReport {
    /// Counts up with each race, so a screen can tell a new one from the same.
    pub serial: u64,
    pub lanes: Vec<Lane>,
    pub finished: bool,
    /// Milliseconds since the race began, at the time of this snapshot.
    pub now_ms: u32,
}

impl Fail {
    /// The word a screen keys its message on.
    pub fn word(self) -> &'static str {
        match self {
            Self::NoAnswer => "no_answer",
            Self::Refused => "refused",
            Self::NoTraffic => "no_traffic",
            Self::Beaten => "beaten",
            Self::Other => "other",
        }
    }
}

impl LaneState {
    fn word(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Trying => "trying",
            Self::Won => "won",
            Self::Lost(_) => "lost",
            Self::Skipped => "skipped",
        }
    }
}

impl RaceReport {
    /// The report as the hosts pass it on: routes by name (`wireguard`,
    /// `masque-h2`, `masque-h3`), states as words, times in milliseconds.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "serial": self.serial,
            "done": self.finished,
            "now": self.now_ms,
            "lanes": self.lanes.iter().map(|lane| {
                let mut value = serde_json::json!({
                    "r": lane.route.name(),
                    "s": lane.state.word(),
                    "a": lane.started_ms,
                    "b": lane.ended_ms,
                });
                if let LaneState::Lost(fail) = lane.state {
                    value["f"] = fail.word().into();
                }
                value
            }).collect::<Vec<_>>(),
        })
    }

    pub fn winner(&self) -> Option<WarpRoute> {
        self.lanes
            .iter()
            .find(|lane| lane.state == LaneState::Won)
            .map(|lane| lane.route)
    }
}

struct Live {
    serial: u64,
    began: Instant,
    lanes: Vec<Lane>,
    finished: bool,
    frozen_ms: u32,
}

impl Live {
    fn report(&self) -> RaceReport {
        let now_ms = if self.finished {
            self.frozen_ms
        } else {
            elapsed_ms(self.began)
        };
        let lanes = self
            .lanes
            .iter()
            .map(|lane| match lane.state {
                LaneState::Trying => Lane {
                    ended_ms: now_ms,
                    ..*lane
                },
                _ => *lane,
            })
            .collect();
        RaceReport {
            serial: self.serial,
            lanes,
            finished: self.finished,
            now_ms,
        }
    }
}

type Shared = Arc<Mutex<Live>>;

/// The race a screen would draw: the newest one started.
static LAST: LazyLock<Mutex<Option<Shared>>> = LazyLock::new(Default::default);
static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The most recent race, or `None` before any.
pub fn last_race() -> Option<RaceReport> {
    let shared = locked(&LAST).clone()?;
    let report = locked(&shared).report();
    Some(report)
}

fn elapsed_ms(since: Instant) -> u32 {
    since.elapsed().as_millis().min(u32::MAX as u128) as u32
}

/// The writing end, held by the race while it runs.
pub(super) struct RaceLog {
    live: Shared,
}

impl RaceLog {
    /// Begin a record with `routes` waiting, `stagger_ms` apart, and make it
    /// the one [`last_race`] reports.
    pub(super) fn begin(routes: &[WarpRoute], stagger_ms: u32) -> Self {
        let lanes = routes
            .iter()
            .enumerate()
            .map(|(index, route)| Lane {
                route: *route,
                state: if index == 0 {
                    LaneState::Trying
                } else {
                    LaneState::Waiting
                },
                started_ms: stagger_ms * index as u32,
                ended_ms: stagger_ms * index as u32,
            })
            .collect();
        // The number is taken under the same lock that publishes the race, so
        // the newest number is always the one screens see.
        let mut last = locked(&LAST);
        let serial = SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        let live = Arc::new(Mutex::new(Live {
            serial,
            began: Instant::now(),
            lanes,
            finished: false,
            frozen_ms: 0,
        }));
        *last = Some(Arc::clone(&live));
        Self { live }
    }

    /// This race as it stands.
    #[cfg(test)]
    fn report(&self) -> RaceReport {
        locked(&self.live).report()
    }

    /// Route number `index` has started.
    pub(super) fn trying(&self, index: usize) {
        let mut live = locked(&self.live);
        let now = elapsed_ms(live.began);
        if let Some(lane) = live.lanes.get_mut(index) {
            if lane.state == LaneState::Waiting {
                lane.state = LaneState::Trying;
                lane.started_ms = now;
            }
        }
    }

    /// Route number `index` has finished, and how.
    pub(super) fn finished(&self, index: usize, outcome: Result<(), &str>) {
        let mut live = locked(&self.live);
        let now = elapsed_ms(live.began);
        if let Some(lane) = live.lanes.get_mut(index) {
            if matches!(lane.state, LaneState::Won | LaneState::Lost(_)) {
                return;
            }
            lane.ended_ms = now;
            lane.state = match outcome {
                Ok(()) => LaneState::Won,
                Err(error) => LaneState::Lost(Fail::of(error)),
            };
        }
    }

    /// The race is over: whatever has not finished did not get the chance.
    pub(super) fn end(&self) {
        let mut live = locked(&self.live);
        let now = elapsed_ms(live.began);
        let won = live.lanes.iter().any(|lane| lane.state == LaneState::Won);
        for lane in &mut live.lanes {
            match lane.state {
                LaneState::Waiting => lane.state = LaneState::Skipped,
                LaneState::Trying if won => {
                    lane.state = LaneState::Lost(Fail::Beaten);
                    lane.ended_ms = now;
                }
                _ => {}
            }
        }
        live.finished = true;
        live.frozen_ms = now;
    }
}

/// Stage a race as if it had run, so a test of a screen can draw it.
#[cfg(feature = "test-util")]
pub fn stage(lanes: Vec<Lane>, finished: bool, now_ms: u32) -> RaceReport {
    let serial = SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let began = Instant::now()
        .checked_sub(std::time::Duration::from_millis(now_ms as u64))
        .unwrap_or_else(Instant::now);
    let live = Arc::new(Mutex::new(Live {
        serial,
        began,
        lanes,
        finished,
        frozen_ms: now_ms,
    }));
    let report = locked(&live).report();
    *locked(&LAST) = Some(live);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_sorted_into_reasons_a_person_can_act_on() {
        assert_eq!(Fail::of("timed out"), Fail::NoAnswer);
        assert_eq!(Fail::of("connection reset by peer"), Fail::Refused);
        assert_eq!(Fail::of("connection refused"), Fail::Refused);
        assert_eq!(
            Fail::of("the probe could not fetch a page"),
            Fail::NoTraffic
        );
        assert_eq!(Fail::of("something odd"), Fail::Other);
    }

    #[test]
    fn a_race_is_recorded_as_it_runs() {
        let routes = [
            WarpRoute::WireGuard,
            WarpRoute::MasqueHttp3,
            WarpRoute::MasqueHttp2,
        ];
        let log = RaceLog::begin(&routes, 200);
        let start = log.report();
        assert!(!start.finished);
        assert_eq!(start.lanes[0].state, LaneState::Trying);
        assert_eq!(start.lanes[1].state, LaneState::Waiting);
        assert_eq!(start.lanes[2].started_ms, 400);

        log.trying(1);
        log.finished(0, Err("timed out"));
        log.finished(1, Err("connection reset"));
        log.trying(2);
        log.finished(2, Ok(()));
        log.end();

        let done = log.report();
        assert!(done.finished);
        assert_eq!(done.winner(), Some(WarpRoute::MasqueHttp2));
        assert_eq!(done.lanes[0].state, LaneState::Lost(Fail::NoAnswer));
        assert_eq!(done.lanes[1].state, LaneState::Lost(Fail::Refused));
        assert!(done.serial >= start.serial);
    }

    #[test]
    fn the_newest_race_is_the_one_reported_to_screens() {
        let first = RaceLog::begin(&[WarpRoute::WireGuard], 200);
        let second = RaceLog::begin(&[WarpRoute::MasqueHttp2], 200);
        second.finished(0, Ok(()));
        second.end();
        // Other tests may start races too, so only check the relation.
        let seen = last_race().expect("a race was recorded");
        assert!(seen.serial >= second.report().serial);
        assert!(first.report().serial < second.report().serial);
    }

    #[test]
    fn the_route_still_trying_when_another_wins_is_beaten_and_one_not_yet_started_is_skipped() {
        let routes = [
            WarpRoute::WireGuard,
            WarpRoute::MasqueHttp3,
            WarpRoute::MasqueHttp2,
        ];
        let log = RaceLog::begin(&routes, 200);
        log.finished(0, Ok(()));
        log.end();
        let report = log.report();
        assert_eq!(report.lanes[0].state, LaneState::Won);
        assert_eq!(report.lanes[1].state, LaneState::Skipped);
        assert_eq!(report.lanes[2].state, LaneState::Skipped);

        let log = RaceLog::begin(&routes, 200);
        log.trying(1);
        log.finished(1, Ok(()));
        log.end();
        let report = log.report();
        assert_eq!(report.lanes[0].state, LaneState::Lost(Fail::Beaten));
        assert_eq!(report.lanes[2].state, LaneState::Skipped);
    }

    #[test]
    fn a_report_is_passed_on_as_plain_json() {
        let log = RaceLog::begin(&[WarpRoute::WireGuard, WarpRoute::MasqueHttp2], 200);
        log.finished(0, Err("timed out"));
        log.trying(1);
        log.finished(1, Ok(()));
        log.end();
        let json = log.report().to_json();
        assert_eq!(json["done"], true);
        assert_eq!(json["lanes"][0]["r"], "wireguard");
        assert_eq!(json["lanes"][0]["s"], "lost");
        assert_eq!(json["lanes"][0]["f"], "no_answer");
        assert_eq!(json["lanes"][1]["r"], "masque-h2");
        assert_eq!(json["lanes"][1]["s"], "won");
        assert!(json["lanes"][1].get("f").is_none());
    }

    #[test]
    fn a_finished_lane_is_not_rewritten_by_a_late_report() {
        let log = RaceLog::begin(&[WarpRoute::WireGuard, WarpRoute::MasqueHttp2], 200);
        log.finished(0, Ok(()));
        log.finished(0, Err("timed out"));
        log.end();
        assert_eq!(log.report().lanes[0].state, LaneState::Won);
    }

    #[test]
    fn a_race_that_has_not_finished_reports_a_growing_clock() {
        let log = RaceLog::begin(&[WarpRoute::WireGuard, WarpRoute::MasqueHttp2], 200);
        let first = log.report();
        std::thread::sleep(std::time::Duration::from_millis(15));
        let second = log.report();
        assert!(second.now_ms > first.now_ms);
        assert_eq!(second.lanes[0].ended_ms, second.now_ms);
    }
}
