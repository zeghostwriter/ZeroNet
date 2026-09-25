//! The client side of updating: when to check, the dialog's buttons, and
//! folding the background download's reports into what is on screen. The
//! network and file work itself is `zeronet_tui::update`.

use std::path::PathBuf;
use std::time::Duration;

use super::*;
use app_tasks::BgEvent;
use zeronet_tui::modal::UpdatePhase;
use zeronet_tui::update::{self, Release, Status, Target};

/// How long after start the automatic check waits, so it never competes
/// with the first frames or an auto-connect.
const STARTUP_CHECK_DELAY: Duration = Duration::from_secs(4);

/// What the client knows about updates.
#[derive(Default)]
pub(crate) struct Updater {
    pub(crate) status: Status,
    /// The newer release found by the last check.
    release: Option<Release>,
    /// The route (local proxy port or direct) that reached GitHub.
    route: Option<u16>,
    /// Bytes received and expected while downloading.
    progress: (u64, u64),
    /// Why the last download failed, until the next attempt.
    error: Option<String>,
    /// Where the new version was installed.
    installed: Option<PathBuf>,
}

impl App<'_> {
    /// Schedule the check a release build makes at start, if it is wanted.
    pub(crate) fn schedule_startup_update_check(&self) {
        if !update::is_release_build() || !self.settings.auto_update_check {
            return;
        }
        let events = self.bg.tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(STARTUP_CHECK_DELAY).await;
            let _ = events.send(BgEvent::UpdateDue);
        });
    }

    /// The local HTTP proxy while a connection is up: GitHub is often
    /// filtered, and the tunnel reaches it when the open network does not.
    fn update_route(&self) -> Option<u16> {
        (self.stats.status == ConnectionStatus::Connected).then_some(self.settings.http_port)
    }

    /// Ask GitHub for a newer release. `manual` checks report every outcome;
    /// the automatic one only speaks up when there is something new.
    pub(crate) fn check_for_update(&mut self, manual: bool) {
        match self.updater.status {
            Status::Checking => return,
            Status::Available(_) | Status::Downloading(_) | Status::Installed(_) if manual => {
                self.open_update_dialog();
                return;
            }
            Status::Downloading(_) | Status::Installed(_) => return,
            _ => {}
        }
        self.updater.status = Status::Checking;
        let route = self.update_route();
        let events = self.bg.tx.clone();
        tokio::spawn(async move {
            let result = update::check(route).await;
            let _ = events.send(BgEvent::UpdateChecked { manual, result });
        });
    }

    pub(crate) fn on_update_checked(
        &mut self,
        manual: bool,
        result: Result<(Option<Release>, Option<u16>), String>,
    ) {
        match result {
            Ok((Some(release), route)) => {
                self.updater.status = Status::Available(release.version.clone());
                self.updater.route = route;
                self.updater.error = None;
                let version = release.version.clone();
                self.updater.release = Some(release);
                if self.modal_state.is_active() {
                    self.toasts.info(format!(
                        "ZeroNet {version} is out. Settings → Version to update."
                    ));
                } else {
                    self.open_update_dialog();
                }
            }
            Ok((None, _)) => {
                self.updater.status = Status::UpToDate;
                if manual {
                    self.toasts.success(format!(
                        "ZeroNet {} is the latest version.",
                        update::CURRENT_VERSION
                    ));
                }
            }
            Err(e) => {
                self.updater.status = if manual { Status::Failed } else { Status::Idle };
                if manual {
                    self.toasts
                        .error(format!("Could not check for updates: {e}"));
                }
            }
        }
    }

    /// Show the update dialog for whatever stage the update is at.
    pub(crate) fn open_update_dialog(&mut self) {
        let Some(release) = self.updater.release.clone() else {
            return;
        };
        let phase = self.update_phase(&release);
        self.modal_state = ModalState::Update {
            release: Box::new(release),
            phase,
            created_tick: self.effects.current_tick(),
        };
        self.open_modal_effect();
    }

    fn update_phase(&self, release: &Release) -> UpdatePhase {
        if self.updater.installed.is_some() {
            return UpdatePhase::Installed;
        }
        if let Status::Downloading(_) = self.updater.status {
            let (received, total) = self.updater.progress;
            return UpdatePhase::Downloading { received, total };
        }
        if release.asset.is_none() || Target::current().is_none() {
            return UpdatePhase::Manual(
                "This system has no automatic update. Get the new version from the release page."
                    .into(),
            );
        }
        match &self.updater.error {
            Some(e) => UpdatePhase::Failed(e.clone()),
            None => UpdatePhase::Available,
        }
    }

    /// Put `phase` into the dialog, if the update dialog is the one open.
    fn show_update_phase(&mut self, phase: UpdatePhase) {
        if let ModalState::Update { phase: shown, .. } = &mut self.modal_state {
            *shown = phase;
        }
    }

    /// The dialog's main button: Enter, or a click.
    pub(crate) fn update_primary(&mut self) {
        let ModalState::Update { phase, release, .. } = &self.modal_state else {
            return;
        };
        let (phase, page) = (phase.clone(), release.page.clone());
        match phase {
            UpdatePhase::Available | UpdatePhase::Failed(_) => self.start_update_download(),
            UpdatePhase::Downloading { .. } => {}
            UpdatePhase::Installed => {
                if let Some(path) = self.updater.installed.clone() {
                    self.relaunch = Some(path);
                    self.should_quit = true;
                }
            }
            UpdatePhase::Manual(_) => {
                if let Err(e) = update::open_in_browser(&page) {
                    self.toasts
                        .error(format!("Could not open a browser: {e}. The page is {page}"));
                }
                self.close_modal();
            }
        }
    }

    fn start_update_download(&mut self) {
        let (Some(release), Some(target)) = (self.updater.release.clone(), Target::current())
        else {
            return;
        };
        let total = release.asset.as_ref().map_or(0, |a| a.size);
        self.updater.status = Status::Downloading(0);
        self.updater.progress = (0, total);
        self.updater.error = None;
        self.show_update_phase(UpdatePhase::Downloading { received: 0, total });

        // The engine may have come up or gone down since the check.
        let route = self.update_route().or(self.updater.route);
        let events = self.bg.tx.clone();
        tokio::spawn(async move {
            // One report per 1% (and the last byte) is plenty for a bar a
            // few dozen cells wide.
            let last = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
            let progress_events = events.clone();
            let progress = move |received: u64, total: u64| {
                let step = (received * 100)
                    .checked_div(total)
                    .unwrap_or(received >> 18);
                if last.swap(step, std::sync::atomic::Ordering::Relaxed) != step {
                    let _ = progress_events.send(BgEvent::UpdateProgress { received, total });
                }
            };
            let result = update::download_and_install(&release, &target, route, progress).await;
            let _ = events.send(BgEvent::UpdateInstalled(result));
        });
    }

    pub(crate) fn on_update_progress(&mut self, received: u64, total: u64) {
        if !matches!(self.updater.status, Status::Downloading(_)) {
            return;
        }
        self.updater.progress = (received, total);
        let percent = (received * 100).checked_div(total).unwrap_or(0).min(100) as u8;
        self.updater.status = Status::Downloading(percent);
        self.show_update_phase(UpdatePhase::Downloading { received, total });
    }

    pub(crate) fn on_update_installed(&mut self, result: Result<PathBuf, String>) {
        let version = self
            .updater
            .release
            .as_ref()
            .map(|r| r.version.clone())
            .unwrap_or_default();
        let dialog_open = matches!(self.modal_state, ModalState::Update { .. });
        match result {
            Ok(path) => {
                self.updater.installed = Some(path);
                self.updater.status = Status::Installed(version.clone());
                self.show_update_phase(UpdatePhase::Installed);
                if dialog_open {
                    self.effects.emit_ashes_burst(
                        ratatui::layout::Rect {
                            x: 0,
                            y: 0,
                            width: 60,
                            height: 18,
                        },
                        32,
                    );
                } else {
                    self.toasts.success(format!(
                        "ZeroNet {version} is installed. Restart to use it (Settings → Version)."
                    ));
                }
            }
            Err(e) => {
                self.updater.status = Status::Available(version);
                self.updater.error = Some(e.clone());
                self.show_update_phase(UpdatePhase::Failed(e.clone()));
                if !dialog_open {
                    self.toasts.error(format!("The update failed: {e}"));
                }
            }
        }
    }
}
