//! ZeroNet-TUI — terminal client for Zray-Core.
//!
//! ## Frame loop
//!
//! Input and rendering are decoupled. A dedicated thread delivers keys and
//! mouse events the moment they arrive; animation is driven by a wall-clock
//! animation clock (see `zeronet_tui::effects`), not by counting frames.
//!
//! A frame is drawn only when something changed — an event, a daemon
//! transition, a ping result — or while an animation is in flight, paced to
//! ~30 fps (60 while the chromatic wave crosses the screen). Between frames
//! the loop sleeps until the next deadline it actually has: an animation
//! frame, a toast expiring, the ambient-idle cutoff. With nothing moving it
//! does not wake at all, so an idle client costs no CPU.

use std::io::{stdout, IsTerminal, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
        MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use throbber_widgets_tui::ThrobberState;

use zeronet_tui::caps::{ColorDepth, TerminalCaps};
use zeronet_tui::clipboard::{Clipboard, CopyRoute};
use zeronet_tui::connection::{ConnectionManager, EngineAction};
use zeronet_tui::ctxmenu::{ContextMenu, MenuAction, MenuTarget};
use zeronet_tui::daemon::{ConnectionStatus, DaemonStats, EngineOptions, ZeroNetDaemon};
use zeronet_tui::db::{AppSettings, ConfigRecord, Database, SubscriptionRecord};
use zeronet_tui::dragselect::{self, DragSelect};
use zeronet_tui::effects::VisualEffects;
use zeronet_tui::elevate::{self, ElevationError, PrivilegedTun};
use zeronet_tui::imageview::{ImageSupport, TerminalImage};
use zeronet_tui::interaction::{ComponentId, InteractionEngine};
use zeronet_tui::keymap::{self, Command, EditAction, InputContext};
use zeronet_tui::manual_profile::{ManualProfileForm, FLOWS, PROTOCOLS, SECURITIES, TRANSPORTS};
use zeronet_tui::modal::{ConfirmAction, ModalState, TextPurpose};
use zeronet_tui::modal_anim::ModalAnimator;
use zeronet_tui::ping::{ping_all, PingResult, PingTarget};
use zeronet_tui::qr::{self, QrStyle};
use zeronet_tui::scroll::{self, ScrollState};
use zeronet_tui::scrollbar::{ScrollPart, ScrollTarget, ThumbDrag};
use zeronet_tui::sharelink;
use zeronet_tui::subscription;
use zeronet_tui::sysproxy::{self, PacServer, ProxyEndpoints, SystemProxyMode};
use zeronet_tui::theme::Theme;
use zeronet_tui::toast::{ToastKind, ToastManager};
use zeronet_tui::ui::{ActiveTab, UiRenderer};

mod app_tasks;
mod app_update;
mod launcher;

/// Frame spacing while something animates (~30 fps).
const FRAME_INTERVAL: Duration = Duration::from_millis(33);
/// Frame spacing while the chromatic wave is on screen (~60 fps).
const FAST_FRAME_INTERVAL: Duration = Duration::from_millis(16);
/// Shortest gap between two event-driven frames (~120 fps cap). Input that
/// arrives inside it is folded into the next frame instead of each event
/// paying for a full redraw.
const MIN_FRAME_GAP: Duration = Duration::from_millis(8);
/// Ambient motion fades out after this long without input.
const AMBIENT_IDLE: Duration = Duration::from_secs(20);
/// How often scanner counters are sampled while a scan runs.
const SCANNER_POLL: Duration = Duration::from_millis(250);
/// One step of the braille spinner (~2 turns a second).
const SPINNER_STEP: Duration = Duration::from_millis(80);
/// Ticks a freshly selected profile row stays flashed.
const SELECTION_FLASH_TICKS: u64 = 8;

/// Frame-loop bookkeeping: when the last frame went out, when the user last
/// did anything, and the clocks the time-based animations step from.
struct FramePacer {
    last_frame: Option<Instant>,
    last_input: Instant,
    focused: bool,
    /// Animation-clock reading at the last scroll step.
    clock: f64,
    /// When the spinner last advanced.
    spinner_at: Instant,
}

impl FramePacer {
    fn new(now: Instant) -> Self {
        Self {
            last_frame: None,
            last_input: now,
            focused: true,
            clock: 0.0,
            spinner_at: now,
        }
    }

    fn touch(&mut self, now: Instant) {
        self.last_input = now;
    }

    fn set_focused(&mut self, focused: bool) {
        self.focused = focused;
    }

    fn ambient_wanted(&self, now: Instant) -> bool {
        self.focused && now.saturating_duration_since(self.last_input) < AMBIENT_IDLE
    }

    fn ambient_deadline(&self) -> Instant {
        self.last_input + AMBIENT_IDLE
    }

    /// Whether at least `gap` has passed since the last frame.
    fn frame_due(&self, now: Instant, gap: Duration) -> bool {
        self.last_frame
            .is_none_or(|last| now.saturating_duration_since(last) >= gap)
    }

    fn next_frame(&self, gap: Duration) -> Instant {
        self.last_frame.map_or_else(Instant::now, |last| last + gap)
    }

    fn drew(&mut self, now: Instant) {
        self.last_frame = Some(now);
    }

    /// Clock ticks elapsed since the previous call, capped so a long idle
    /// gap cannot fling a scroll animation.
    fn clock_step(&mut self, clock: f64) -> f32 {
        let dt = (clock - self.clock).clamp(0.0, 8.0);
        self.clock = clock;
        dt as f32
    }

    /// Spinner steps due by `now`, at most one revolution's worth.
    fn spinner_steps(&mut self, now: Instant) -> u32 {
        let mut steps = 0;
        while now.saturating_duration_since(self.spinner_at) >= SPINNER_STEP && steps < 6 {
            self.spinner_at += SPINNER_STEP;
            steps += 1;
        }
        if steps == 6 {
            self.spinner_at = now;
        }
        steps
    }

    fn reset_spinner(&mut self, now: Instant) {
        self.spinner_at = now;
    }
}

/// Parting message. Gold when the terminal can colour it.
const GOODBYE: &str = "Zero is now Zero, Goodbye!";

fn main() -> Result<()> {
    // The privileged helper is this same binary re-executed under sudo. It
    // must be dealt with before the terminal, the database or the async
    // runtime exist: it draws nothing, owns no state, and putting an
    // alternate screen or a WAL journal in root's hands would be a way to
    // leave root-owned files in the user's home.
    if std::env::args().any(|arg| arg == elevate::HELPER_FLAG) {
        std::process::exit(elevate::run_helper());
    }
    // Double-clicked from a file manager, an app menu or a `.app` bundle:
    // there is no terminal yet, so open one and continue in it.
    if let launcher::Launch::Relaunched = launcher::ensure_terminal() {
        return Ok(());
    }
    zero_runtime::tune_allocator();
    zeronet_tui::update::clean_leftovers();
    let result = client_main();
    match result {
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "ZeroNet could not start: {err:?}");
            launcher::hold_window_on_error();
            Err(err)
        }
        // An update was installed and the user chose to restart into it.
        // The runtime and terminal are gone by now; only the process is
        // replaced.
        Ok(Some(updated)) => {
            let err = zeronet_tui::update::relaunch(&updated);
            let _ = writeln!(
                std::io::stderr(),
                "The update is installed, but ZeroNet could not restart ({err}). Start it again to use the new version."
            );
            Ok(())
        }
        Ok(None) => Ok(()),
    }
}

/// Runs the app. Returns the installed update to restart into, if the
/// user asked for that.
#[tokio::main]
async fn client_main() -> Result<Option<std::path::PathBuf>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let caps = TerminalCaps::detect();

    let priv_status = zero_tun::check_tun_permissions();
    let is_elevated = priv_status.is_ready();
    let elevation_prompt = priv_status.prompt_message();

    let db = Database::open_default().context("Failed to open SQLite database")?;

    // A previous run that died without cleaning up (SIGKILL, power loss) may
    // have left the desktop pointed at its proxy. The snapshot it kept on
    // disk is replayed before anything else happens.
    if let Some(dir) = db.path().parent() {
        sysproxy::set_state_file(dir.join("sysproxy-restore.json"));
    }
    let recovered_proxy = match tokio::task::spawn_blocking(sysproxy::recover_stale).await {
        Ok(Some(Ok(backend))) => Some(format!(
            "Restored the system proxy a previous session left behind ({backend})."
        )),
        Ok(Some(Err(e))) => Some(format!(
            "A previous session left the system proxy changed and it could not be restored: {e}"
        )),
        _ => None,
    };

    let existing = db.get_configs().unwrap_or_default();
    if existing.is_empty() || !existing.iter().any(|c| c.remark.contains("AmneziaVPN")) {
        let _ = seed_sample_configs(&db);
    }

    // Probe terminal graphics *before* raw mode: the query writes an escape
    // sequence and reads the reply, which would collide with the frame loop.
    let images = ImageSupport::detect();

    let daemon = ZeroNetDaemon::spawn();

    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)?;
    // The window's title bar and taskbar entry read "ZeroNet", like an app.
    let _ = execute!(out, crossterm::terminal::SetTitle("ZeroNet"));
    // Best effort, each on its own: not every terminal (or the legacy
    // Windows console) supports them, and a refusal must not stop the app.
    // Bracketed paste is what makes a pasted share link arrive as one
    // `Event::Paste` instead of a stream of key presses whose embedded
    // newline would trigger Enter. Focus reports let the frame loop stop
    // animating while the window is in the background.
    let _ = execute!(out, crossterm::event::EnableBracketedPaste);
    let _ = execute!(out, crossterm::event::EnableFocusChange);
    install_panic_restore();
    let mut terminal = Terminal::new(CrosstermBackend::new(out))?;

    let mut app = App::new(&db, &daemon, caps, is_elevated, elevation_prompt, images)?;
    if let Some(message) = recovered_proxy {
        app.toasts.info(message);
    }
    app.schedule_startup_update_check();
    let result = app.run(&mut terminal).await;
    let relaunch = app.relaunch.take();

    // Every way out of the loop ends here — the quit dialog, a signal, a
    // terminal that went away, an error — so this is where the machine is
    // put back: system proxy, engine, TUN.
    app.shutdown().await;

    let restored = restore_terminal(&mut terminal);
    if relaunch.is_none() {
        print_goodbye(caps);
    }

    if let Err(err) = result {
        // `eprintln!` panics when stderr is gone (the terminal was closed).
        let _ = writeln!(
            std::io::stderr(),
            "ZeroNet-TUI exited with an error: {err:?}"
        );
    }
    // A terminal that has gone away cannot be restored, and that is not an
    // error worth reporting to nobody.
    if let Err(err) = restored {
        tracing::debug!(error = %err, "terminal restore failed");
    }
    Ok(relaunch)
}

fn restore_terminal<B: ratatui::backend::Backend + Write>(
    terminal: &mut Terminal<B>,
) -> Result<()> {
    // Every step is attempted even if an earlier one fails: a terminal that
    // refuses one sequence should still get the others.
    let raw = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        crossterm::event::DisableBracketedPaste
    );
    let _ = execute!(terminal.backend_mut(), crossterm::event::DisableFocusChange);
    let screen = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        crossterm::cursor::Show,
    );
    raw?;
    screen?;
    Ok(())
}

/// Put the terminal back before a panic message is printed.
///
/// Without this a panic anywhere in the UI leaves the shell in raw mode on
/// the alternate screen with mouse reporting on — the message is invisible
/// and the terminal unusable until `reset`.
fn install_panic_restore() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Only a panic on the UI thread ends the UI. A panic inside a
        // background task is caught by Tokio and the interface carries on,
        // so tearing the terminal down for it would break a working app —
        // unless panics abort (the release profile sets `panic = "abort"`),
        // in which case every panic, on any thread, ends the process.
        let fatal = cfg!(panic = "abort") || std::thread::current().name() == Some("main");
        if !fatal {
            previous(info);
            return;
        }
        // No destructor and no `shutdown` will run after this, so the one
        // change that would leave the machine broken — the desktop pointed
        // at a proxy about to vanish — is undone here. (A TUN helper needs
        // nothing: its stdin closes with this process and it cleans up.)
        sysproxy::emergency_restore();
        let _ = disable_raw_mode();
        let mut out = stdout();
        let _ = execute!(out, crossterm::event::DisableBracketedPaste);
        let _ = execute!(out, crossterm::event::DisableFocusChange);
        let _ = execute!(
            out,
            LeaveAlternateScreen,
            DisableMouseCapture,
            crossterm::cursor::Show
        );
        previous(info);
    }));
}

/// Print the parting line in gold.
///
/// The alternate screen has already been left at this point, so the message
/// lands in the user's normal scrollback. The SGR sequence is chosen from the
/// detected colour depth and always closed with a reset, so a terminal that
/// cannot do truecolor still gets a gold line rather than a literal escape
/// sequence — and a pipe gets plain text.
fn print_goodbye(caps: TerminalCaps) {
    let colored = stdout().is_terminal();
    let (open, close) = if !colored {
        ("", "")
    } else {
        match caps.depth {
            // Amber 400 (#fbbf24), bold.
            ColorDepth::TrueColor => ("\x1b[1;38;2;251;191;36m", "\x1b[0m"),
            ColorDepth::Ansi256 => ("\x1b[1;38;5;220m", "\x1b[0m"),
            ColorDepth::Ansi16 => ("\x1b[1;33m", "\x1b[0m"),
        }
    };
    // Not `println!`: it panics if stdout is gone, which is exactly the case
    // after the terminal window was closed.
    let mut out = stdout();
    let _ = write!(out, "\r\n{open}{GOODBYE}{close}\r\n\n");
    let _ = out.flush();
}

/// The outcome of one background subscription fetch, with the nodes
/// already compiled off the frame loop.
struct FeedUpdate {
    id: i64,
    name: String,
    result: Result<app_tasks::FeedRows, String>,
}

/// Everything the frame loop needs, in one place.
struct App<'a> {
    db: &'a Database,
    daemon: &'a ZeroNetDaemon,
    caps: TerminalCaps,
    theme: Theme,
    interaction: InteractionEngine,
    effects: VisualEffects,
    toasts: ToastManager,
    throbber: ThrobberState,
    settings: AppSettings,
    status_rx: tokio::sync::watch::Receiver<DaemonStats>,
    stats: DaemonStats,
    /// Revision of the last daemon transition already reported to the user.
    reported_revision: u64,
    active_tab: ActiveTab,
    configs: Vec<ConfigRecord>,
    subscriptions: Vec<SubscriptionRecord>,
    selected_config_idx: usize,
    node_scroll: usize,
    latency_history: Vec<f64>,
    is_elevated: bool,
    elevation_prompt: Option<&'static str>,
    modal_state: ModalState,
    /// Scroll position of the settings page.
    settings_scroll: ScrollState,
    /// Scroll position of the help overlay.
    help_scroll: ScrollState,
    /// The right-click menu, when one is open.
    context_menu: Option<ContextMenu>,
    /// An in-progress rubber-band selection.
    drag: Option<DragSelect>,
    /// A scrollbar thumb currently being dragged. While this is set, a pointer
    /// move scrolls instead of selecting rows.
    thumb_drag: Option<ThumbDrag>,
    /// Advanced settings stay folded until the user opens the group.
    advanced_open: bool,
    /// Tick at which the current profile row was selected, for the brief
    /// highlight that confirms the click landed.
    selection_tick: u64,
    /// Last drawn terminal size, so scroll bounds match what is on screen.
    viewport: (u16, u16),
    /// Open/close animation for the dialog on screen.
    ///
    /// A dialog is not removed the moment it is dismissed; it plays a closing
    /// animation first and the frame loop drops it when that finishes.
    modal_anim: ModalAnimator,

    /// What the user has asked the connection to be, as distinct from what
    /// the engine is currently doing. See `zeronet_tui::connection`.
    connection: ConnectionManager,
    clipboard: Clipboard,
    /// Terminal graphics capability, probed once before raw mode.
    images: ImageSupport,
    /// The image behind an open `ImageView` dialog.
    image_view: Option<TerminalImage>,
    /// Profiles ticked for a bulk action.
    marked: std::collections::HashSet<i64>,
    /// Active list filter; empty means everything is shown.
    filter: String,
    /// Whether the filter box has keyboard focus.
    filter_focused: bool,
    /// Whether all text in the filter box is selected.
    filter_select_all: bool,
    /// Active inline renaming state for a profile.
    inline_rename: Option<zeronet_tui::InlineRename>,
    /// Set when a full latency sweep has been requested.
    pending_ping_sweep: bool,
    /// The system proxy mode actually in force.
    ///
    /// Distinct from the saved setting: applying it can fail (an unsupported
    /// desktop, a PAC port already taken), and the header must show what is
    /// true rather than what was asked for.
    system_proxy: SystemProxyMode,
    /// The PAC server, alive only while PAC mode is applied.
    pac_server: Option<PacServer>,
    /// A mode to apply on the next frame.
    ///
    /// Status transitions are handled in a synchronous callback, so the work
    /// is deferred to the loop where it can await.
    pending_system_proxy: Option<SystemProxyMode>,

    // Scanner
    is_scanning: bool,
    scanner_tested: u64,
    scanner_healthy: u64,
    scanner_speed: f64,
    scanner_results: Vec<zero_scanner::types::ProbeResult>,
    scan_handle: Option<tokio::task::JoinHandle<()>>,
    scanner_stats: Arc<std::sync::Mutex<Option<Arc<zero_scanner::types::AtomicStats>>>>,
    scan_tx: tokio::sync::mpsc::UnboundedSender<zero_scanner::types::ProbeResult>,
    scan_rx: tokio::sync::mpsc::UnboundedReceiver<zero_scanner::types::ProbeResult>,

    /// Completed subscription fetches, reported back from their tasks.
    feed_tx: tokio::sync::mpsc::UnboundedSender<FeedUpdate>,
    feed_rx: tokio::sync::mpsc::UnboundedReceiver<FeedUpdate>,

    // Elevation
    /// How privileges can be obtained on this machine, decided once.
    elevator: elevate::Elevator,
    /// The root helper holding the current TUN interface up, if any.
    ///
    /// Dropping it tears the interface down, so it is deliberately owned here
    /// and nowhere else: whatever path disconnects also releases it.
    privileged_tun: Option<Box<PrivilegedTun>>,
    /// The connect that is waiting for a password.
    pending_elevation: Option<EngineAction>,
    /// Whether the user has declined to elevate for this session.
    ///
    /// Remembered so a decline is not re-asked on every reconnect — the
    /// answer was "proxy only", and asking again would be nagging.
    elevation_declined: bool,

    /// Background jobs and their bookkeeping; see `app_tasks`.
    bg: app_tasks::Background,

    /// Set whenever something that affects the picture has changed.
    dirty: bool,
    /// Whether the previous pass had something in motion. The pass where
    /// motion stops must still draw once: the last paced frame showed an
    /// in-between state, and without a settling frame it stays on screen.
    was_animating: bool,
    should_quit: bool,

    /// CPU and memory sampling for the Activity page and the status bar.
    usage: zeronet_tui::usage::UsageMonitor,
    /// What the status bar's usage readout last said, so a new sample only
    /// costs a frame when the words on screen would change.
    usage_label: String,
    activity_sort: zeronet_tui::ui_activity::ActivitySort,
    /// The last few keys, for the Konami code.
    konami: SecretSequence,
    /// When the current connection came up, for the session clock.
    connected_since: Option<Instant>,
    /// Transfer rates once a second while connected, for the speed graphs.
    speed_history: SpeedHistory,
    /// Frame timing, shown by F12.
    perf: PerfMeter,
    /// Update checks and downloads; see `app_update`.
    updater: app_update::Updater,
    /// An installed update to start in place of this process on exit.
    relaunch: Option<std::path::PathBuf>,
}

/// Upload and download rates, one sample a second, newest last.
#[derive(Default)]
struct SpeedHistory {
    up: Vec<u64>,
    down: Vec<u64>,
    next_sample: Option<Instant>,
}

impl SpeedHistory {
    const LEN: usize = 60;

    fn push(&mut self, up: u64, down: u64) {
        for (series, value) in [(&mut self.up, up), (&mut self.down, down)] {
            if series.len() == Self::LEN {
                series.remove(0);
            }
            series.push(value);
        }
    }

    fn clear(&mut self) {
        self.up.clear();
        self.down.clear();
        self.next_sample = None;
    }
}

/// Recognises ↑ ↑ ↓ ↓ ← → ← → B A anywhere in the key stream.
#[derive(Default)]
struct SecretSequence {
    recent: std::collections::VecDeque<KeyCode>,
}

impl SecretSequence {
    const CODE: [KeyCode; 10] = [
        KeyCode::Up,
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Char('b'),
        KeyCode::Char('a'),
    ];

    /// Feed one key; true exactly when it completes the sequence.
    fn feed(&mut self, code: KeyCode) -> bool {
        let code = match code {
            KeyCode::Char(c) => KeyCode::Char(c.to_ascii_lowercase()),
            other => other,
        };
        if self.recent.len() == Self::CODE.len() {
            self.recent.pop_front();
        }
        self.recent.push_back(code);
        if self.recent.iter().eq(Self::CODE.iter()) {
            self.recent.clear();
            return true;
        }
        false
    }
}

/// Frames drawn and how long drawing took, over the last second.
#[derive(Default)]
struct PerfMeter {
    visible: bool,
    /// When the overlay next needs redrawing to age its numbers; `None`
    /// while hidden, so a closed overlay never wakes the loop.
    next_refresh: Option<Instant>,
    frames: std::collections::VecDeque<(Instant, Duration)>,
    total: u64,
}

impl PerfMeter {
    fn toggle(&mut self) {
        self.visible = !self.visible;
        self.frames.clear();
        self.next_refresh = self.visible.then(Instant::now);
    }

    /// Whether the overlay's own twice-a-second refresh is due.
    fn refresh_due(&mut self, now: Instant) -> bool {
        match self.next_refresh {
            Some(at) if now >= at => {
                self.next_refresh = Some(now + Duration::from_millis(500));
                true
            }
            _ => false,
        }
    }

    fn record(&mut self, at: Instant, took: Duration) {
        self.total += 1;
        if !self.visible {
            return;
        }
        self.frames.push_back((at, took));
        self.expire(at);
    }

    fn expire(&mut self, now: Instant) {
        while let Some((at, _)) = self.frames.front() {
            if now.saturating_duration_since(*at) > Duration::from_secs(1) {
                self.frames.pop_front();
            } else {
                break;
            }
        }
    }

    fn snapshot(&mut self, now: Instant) -> Option<zeronet_tui::ui::PerfHud> {
        if !self.visible {
            return None;
        }
        self.expire(now);
        let fps = self.frames.len() as u32;
        let (sum, worst) = self
            .frames
            .iter()
            .fold((Duration::ZERO, Duration::ZERO), |(s, w), (_, d)| {
                (s + *d, w.max(*d))
            });
        Some(zeronet_tui::ui::PerfHud {
            fps,
            avg_draw: if fps == 0 { Duration::ZERO } else { sum / fps },
            worst_draw: worst,
            total_frames: self.total,
        })
    }
}

impl<'a> App<'a> {
    fn new(
        db: &'a Database,
        daemon: &'a ZeroNetDaemon,
        mut caps: TerminalCaps,
        is_elevated: bool,
        elevation_prompt: Option<&'static str>,
        images: ImageSupport,
    ) -> Result<Self> {
        let settings = db.load_settings();
        // The terminal decides whether motion is affordable; the setting
        // decides whether it is wanted.
        let terminal_allows_motion = caps.animations;
        caps.animations &= settings.animations;
        let (scan_tx, scan_rx) = tokio::sync::mpsc::unbounded_channel();
        let (feed_tx, feed_rx) = tokio::sync::mpsc::unbounded_channel();
        let status_rx = daemon.status_receiver();
        let stats = status_rx.borrow().clone();

        let elevator = elevate::detect();
        let mut toasts = ToastManager::new();
        toasts.set_muted(
            settings
                .muted_notices
                .split(',')
                .filter(|key| !key.is_empty())
                .map(str::to_owned),
        );
        if is_elevated {
            toasts.notice(
                "startup.elevated",
                "Running as administrator. TUN is available.",
                ToastKind::Success,
            );
        } else if elevate::privileges_ready() {
            toasts.notice(
                "startup.tun-ready",
                "TUN is available without a password on this machine.",
                ToastKind::Success,
            );
        } else if !elevator.can_prompt() {
            toasts.notice(
                "startup.no-elevator",
                "No sudo or doas found, so TUN is off. Proxy mode still works.",
                ToastKind::Warning,
            );
        }
        if !terminal_allows_motion {
            toasts.notice(
                "startup.animations-off",
                format!("Animations are off: {}.", caps.describe()),
                ToastKind::Info,
            );
        }
        let theme = Theme::from_setting(&caps, &settings.theme);
        let mut effects = VisualEffects::with_caps(caps.depth, caps.animations);
        effects.set_palette(theme.raw);

        let configs = db.get_configs()?;
        let restore = configs
            .iter()
            .find(|c| c.is_active)
            .or_else(|| configs.first())
            .map(|c| c.id);
        let mut connection = ConnectionManager::new();
        connection.restore_selection(restore);

        Ok(Self {
            db,
            daemon,
            caps,
            theme,
            interaction: InteractionEngine::new(),
            effects,
            toasts,
            throbber: ThrobberState::default(),
            settings,
            status_rx,
            stats,
            reported_revision: 0,
            active_tab: ActiveTab::Dashboard,
            configs,
            subscriptions: db.get_subscriptions()?,
            selected_config_idx: 0,
            node_scroll: 0,
            latency_history: Vec::new(),
            is_elevated,
            elevation_prompt,
            modal_state: ModalState::None,
            modal_anim: ModalAnimator::default(),
            settings_scroll: ScrollState::new(),
            help_scroll: ScrollState::new(),
            context_menu: None,
            drag: None,
            thumb_drag: None,
            advanced_open: false,
            selection_tick: 0,
            viewport: (80, 24),
            connection,
            clipboard: Clipboard::new(),
            images,
            image_view: None,
            marked: std::collections::HashSet::new(),
            filter: String::new(),
            filter_focused: false,
            filter_select_all: false,
            inline_rename: None,
            pending_ping_sweep: false,
            system_proxy: SystemProxyMode::Unmanaged,
            pac_server: None,
            pending_system_proxy: None,
            is_scanning: false,
            scanner_tested: 0,
            scanner_healthy: 0,
            scanner_speed: 0.0,
            scanner_results: Vec::new(),
            scan_handle: None,
            scanner_stats: Arc::new(std::sync::Mutex::new(None)),
            scan_tx,
            scan_rx,
            elevator,
            privileged_tun: None,
            pending_elevation: None,
            elevation_declined: false,
            feed_tx,
            feed_rx,
            bg: app_tasks::Background::new(),
            dirty: true,
            was_animating: false,
            should_quit: false,
            usage: zeronet_tui::usage::UsageMonitor::start(zeronet_tui::usage::UsageScope::Off),
            usage_label: String::new(),
            activity_sort: zeronet_tui::ui_activity::ActivitySort::default(),
            konami: SecretSequence::default(),
            connected_since: None,
            speed_history: SpeedHistory::default(),
            perf: PerfMeter::default(),
            updater: app_update::Updater::default(),
            relaunch: None,
        })
    }

    /// Where the local proxy is listening, for the system-proxy backends.
    fn proxy_endpoints(&self) -> ProxyEndpoints {
        ProxyEndpoints {
            http_port: self.settings.http_port,
            socks_port: self.settings.socks_port,
            pac_port: self.settings.pac_port,
        }
    }

    /// Apply a system proxy mode; the outcome is reported when the worker
    /// finishes (see `app_tasks`).
    ///
    /// Hands-off mode undoes an earlier change and then stays out of the
    /// way — leaving the desktop pointed at a tunnel we have stopped managing
    /// would be a trap. PAC mode needs a local web server for the script, so
    /// the server's lifetime is tied to the mode being active.
    ///
    /// The desktop tools (`gsettings`, `kwriteconfig`, `networksetup`, `reg`)
    /// used to be driven right here, on the frame loop, freezing the UI for
    /// as long as a dozen subprocesses took.
    async fn apply_system_proxy(&mut self, mode: SystemProxyMode) {
        self.queue_system_proxy(mode).await;
    }

    /// Undo any change this client made to the system proxy.
    ///
    /// Used on disconnect and on a failed connection. A mode that never wrote
    /// anything has nothing to undo, which is the whole point of `Unmanaged`.
    async fn revert_system_proxy(&mut self) {
        self.queue_proxy_revert(true);
    }

    /// Save settings, and say so if the disk refused rather than letting the
    /// change quietly vanish at the next launch.
    fn persist_settings(&mut self) {
        if let Err(error) = self.db.save_settings(&self.settings) {
            self.toasts
                .error(format!("Couldn't save settings: {error}"));
        }
    }

    /// Switch palettes: the chrome, the effects and the saved choice.
    fn apply_theme(&mut self, id: zeronet_tui::theme::ThemeId) {
        self.theme = Theme::new(id, self.caps.depth);
        self.effects.set_palette(self.theme.raw);
        self.settings.theme = id.key().to_string();
        self.persist_settings();
    }

    /// Cycle the system proxy mode and persist the choice.
    async fn cycle_system_proxy(&mut self) {
        let next = SystemProxyMode::parse(&self.settings.system_proxy_mode)
            .unwrap_or_default()
            .next();
        self.settings.system_proxy_mode = next.as_str().to_string();
        self.persist_settings();
        self.apply_system_proxy(next).await;
    }

    /// Set a specific system proxy mode directly from dropdown.
    async fn set_system_proxy_mode(&mut self, mode: SystemProxyMode) {
        self.settings.system_proxy_mode = mode.as_str().to_string();
        self.persist_settings();
        self.apply_system_proxy(mode).await;
        self.toasts.info(format!("System proxy: {}", mode.label()));
    }

    /// Engine options assembled from current settings.
    ///
    /// Built fresh on every connect so a port changed in Settings takes
    /// effect on the next dial instead of being ignored.
    fn engine_options(&self) -> EngineOptions {
        EngineOptions {
            tun_mode: self.settings.tun_enabled,
            socks_port: self.settings.socks_port,
            http_port: self.settings.http_port,
            tun_mtu: self.settings.tun_mtu,
            tun_device_name: self.settings.tun_device_name.clone(),
            tun_auto_route: self.settings.tun_auto_route,
            tun_strict_route: self.settings.tun_strict_route,
            allow_lan: self.settings.allow_lan,
            udp_enabled: self.settings.udp_enabled,
            sniffing_enabled: self.settings.sniffing_enabled,
            sniffing_route_only: self.settings.sniffing_route_only,
            log_level: self.settings.log_level.clone(),
            utls_fingerprint: self.settings.utls_fingerprint.clone(),
            mux_enabled: self.settings.mux_enabled,
            mux_concurrency: self.settings.mux_concurrency,
            fragment_enabled: self.settings.fragment_enabled,
            tls_fragment_size: self.settings.tls_fragment_size,
            keepalive_interval_secs: self.settings.keepalive_interval_secs,
            tcp_congestion: self.settings.tcp_congestion.clone(),
            custom_dns: self.settings.custom_dns.trim().to_string(),
            clean_ip_rotation: self.settings.clean_ip_rotation,
            clean_ip_candidates: zeronet_tui::daemon::clean_ip_candidates(
                &self.scanner_results,
                self.settings.scanner_require_ws,
            ),
            domain_strategy: self.settings.domain_strategy.clone(),
            ipv6_enabled: self.settings.ipv6_enabled,
            // Set for real once a descriptor exists (see `app_tasks`); claiming it
            // here would put a green "TUN ON" over untunnelled traffic.
            tun_ready: self.is_elevated,
        }
    }

    async fn run<B: ratatui::backend::Backend>(
        &mut self,
        terminal: &mut Terminal<B>,
    ) -> Result<()> {
        // Terminal input is read on a dedicated OS thread and forwarded over
        // a channel.
        //
        // Two problems ruled out the obvious alternatives. Polling inside the
        // `select!` below re-creates the read future every iteration and
        // drops it whenever another branch wins — and at 30 frames a second
        // the frame tick wins almost always, so key presses were silently
        // lost and commands appeared to do nothing at random. Parking a
        // `crossterm::EventStream` in a Tokio task still dropped the first
        // events of a session. A blocking `event::read()` on its own thread
        // has neither failure mode: it is the oldest, most exercised path in
        // crossterm, and `Receiver::recv` is properly cancel-safe.
        //
        // The thread parks in `read()` forever and is never joined; the
        // process exits immediately after the loop ends, so that is a
        // deliberate leak of one blocked thread rather than a lost wakeup.
        let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
        std::thread::Builder::new()
            .name("zeronet-input".into())
            .spawn(move || loop {
                match event::read() {
                    Ok(event) => {
                        if input_tx.send(event).is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "terminal input failed");
                        break;
                    }
                }
            })
            .context("spawning the input thread")?;

        let mut ping_tick = tokio::time::interval(Duration::from_secs(2));
        let mut node_ping_tick = tokio::time::interval(Duration::from_secs(60));

        let (ping_tx, mut ping_rx) = tokio::sync::mpsc::unbounded_channel::<PingResult>();

        // Every node shows `---` until something measures it, so measure them
        // all on startup rather than waiting for the user to connect.
        self.spawn_node_pings(ping_tx.clone());

        let mut pacer = FramePacer::new(Instant::now());

        loop {
            let now = Instant::now();
            self.effects.advance_to(now);
            // Ambient motion is for a user who is looking: it fades out after
            // a spell without input, or as soon as the window loses focus.
            self.effects
                .set_ambient(pacer.ambient_wanted(now) && self.caps.animations);
            // Follows the Animations setting, which can change at runtime.
            self.toasts.set_animated(self.caps.animations);

            self.run_deferred_work(&ping_tx).await;
            self.step_animations(&mut pacer, now);
            self.usage.set_scope(self.wanted_usage_scope());

            if self.perf.refresh_due(now) {
                self.dirty = true;
            }
            // Once a second while connected: a speed sample, and the session
            // clock in the header moves on.
            if let Some(at) = self.speed_history.next_sample {
                if now >= at {
                    self.speed_history
                        .push(self.stats.upload_speed_bps, self.stats.download_speed_bps);
                    // Stay on the one-second grid, unless the loop slept
                    // through a whole tick; then restart from now.
                    let next = at + Duration::from_secs(1);
                    self.speed_history.next_sample = Some(if next > now {
                        next
                    } else {
                        now + Duration::from_secs(1)
                    });
                    self.dirty = true;
                }
            }
            let animating = self.animation_active(now);
            if self.was_animating && !animating {
                self.dirty = true;
            }
            self.was_animating = animating;
            if self.dirty || animating {
                // Event-driven frames go out almost at once; animation frames
                // are paced. Either way bursts coalesce into one draw.
                let gap = if self.dirty {
                    MIN_FRAME_GAP
                } else {
                    self.frame_interval()
                };
                if pacer.frame_due(now, gap) {
                    let started = Instant::now();
                    terminal.draw(|frame| self.draw(frame))?;
                    self.perf.record(started, started.elapsed());
                    pacer.drew(now);
                    self.dirty = false;
                    // The pointer turned out to be over something else once
                    // this frame's layout was known: draw once more.
                    if self.interaction.take_hover_stale() {
                        self.dirty = true;
                    }
                }
            }

            let deadline = self.next_wake(&pacer, Instant::now());
            let wake = async move {
                match deadline {
                    Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                    None => std::future::pending::<()>().await,
                }
            };

            tokio::select! {
                _ = wake => {}

                maybe_event = input_rx.recv() => {
                    let Some(event) = maybe_event else { break };
                    // Handlers stamp dialogs and flashes with the animation
                    // clock, so it must be current before they run — after
                    // an idle wait it would otherwise be seconds stale and
                    // every opening animation would be skipped.
                    self.effects.advance_to(Instant::now());
                    if self.dispatch_input(event, &mut pacer).await? {
                        self.dirty = true;
                    }

                    // Input can arrive faster than the frame rate — a paste,
                    // a held key, a mouse sweep. Drain whatever else is
                    // already queued so it all lands in a single frame.
                    while let Ok(event) = input_rx.try_recv() {
                        if self.dispatch_input(event, &mut pacer).await? {
                            self.dirty = true;
                        }
                    }
                }

                Ok(()) = self.usage.receiver().changed() => {
                    if self.on_usage_sample() {
                        self.dirty = true;
                    }
                }

                Ok(()) = self.status_rx.changed() => {
                    let next = self.status_rx.borrow().clone();
                    self.on_status_change(next);
                    self.dirty = true;
                }

                Some(result) = ping_rx.recv() => {
                    self.apply_ping_result(result);
                    self.dirty = true;
                }

                Some(update) = self.feed_rx.recv() => {
                    self.apply_feed_update(update);
                    // A refreshed feed brings new endpoints worth measuring.
                    self.pending_ping_sweep = true;
                    self.dirty = true;
                }

                // Finished background jobs: system proxy, TUN, password
                // checks, housekeeping, termination signals.
                Some(event) = self.bg.rx.recv() => {
                    if self.on_background(event).await {
                        self.dirty = true;
                    }
                }

                _ = ping_tick.tick() => {
                    if self.stats.status == ConnectionStatus::Connected {
                        if let Some(active) = self.configs.iter().find(|c| c.is_active) {
                            let (id, host, port) = (active.id, active.address.clone(), active.port);
                            let tx = ping_tx.clone();
                            tokio::spawn(async move {
                                let latency_ms = zeronet_tui::ping::tcp_ping(
                                    &host,
                                    port,
                                    zeronet_tui::ping::PING_TIMEOUT,
                                )
                                .await;
                                let _ = tx.send(PingResult { config_id: id, latency_ms });
                            });
                        }
                    }
                }

                _ = node_ping_tick.tick() => {
                    self.spawn_node_pings(ping_tx.clone());
                }
            }

            if self.should_quit {
                // The cleanup — system proxy, engine, TUN — is `shutdown`,
                // run by the caller on every way out of this loop, including
                // the error paths that never reach this line.
                break;
            }
        }
        Ok(())
    }

    /// How much the usage sampler should look at right now: the whole
    /// process table only while the Activity page is up, just this process
    /// while the status bar shows it, otherwise nothing at all.
    fn wanted_usage_scope(&self) -> zeronet_tui::usage::UsageScope {
        use zeronet_tui::usage::UsageScope;
        if self.active_tab == ActiveTab::Activity {
            UsageScope::Everything
        } else if self.settings.show_usage {
            UsageScope::SelfOnly
        } else {
            UsageScope::Off
        }
    }

    /// Fold a fresh sample in. Returns whether anything on screen changed.
    fn on_usage_sample(&mut self) -> bool {
        let Some(snapshot) = self.usage.latest() else {
            return false;
        };
        self.usage.record(&snapshot);
        if self.active_tab == ActiveTab::Activity {
            return true;
        }
        let label = zeronet_tui::ui::usage_label(&snapshot);
        if label == self.usage_label {
            return false;
        }
        self.usage_label = label;
        true
    }

    /// Work handlers queue for the loop, where it can await or reach the
    /// channels it needs.
    async fn run_deferred_work(
        &mut self,
        ping_tx: &tokio::sync::mpsc::UnboundedSender<PingResult>,
    ) {
        // A sweep requested from a command runs here, where the result
        // channel lives.
        if std::mem::take(&mut self.pending_ping_sweep) {
            self.spawn_node_pings(ping_tx.clone());
        }
        if let Some(mode) = self.pending_system_proxy.take() {
            self.apply_system_proxy(mode).await;
            self.dirty = true;
        }
        self.poll_scanner();
    }

    /// Advance everything that moves by elapsed time, marking the frame dirty
    /// where a state change (not just motion) happened.
    fn step_animations(&mut self, pacer: &mut FramePacer, now: Instant) {
        // A dialog that has finished closing needs removing, and one that
        // finished opening becomes interactive.
        if self.modal_state.is_active() {
            let before = self.modal_anim.phase();
            self.advance_modal_animation();
            if before != self.modal_anim.phase() || !self.modal_state.is_active() {
                self.dirty = true;
            }
        }

        // Rubber bands and smooth scrolling relax by elapsed clock time, so
        // they settle in the same time whatever the frame rate.
        let dt = pacer.clock_step(self.effects.current_time());
        if self.help_scroll.is_animating() || self.settings_scroll.is_animating() {
            self.help_scroll.advance(dt);
            self.settings_scroll.advance(dt);
        }

        if self.toasts.prune() {
            self.dirty = true;
        }

        if self.spinner_visible() {
            for _ in 0..pacer.spinner_steps(now) {
                self.throbber.calc_next();
            }
        } else {
            pacer.reset_spinner(now);
        }
    }

    /// Whether the braille spinner is on screen.
    fn spinner_visible(&self) -> bool {
        self.caps.animations
            && (self.is_scanning
                || matches!(
                    self.stats.status,
                    ConnectionStatus::Connecting | ConnectionStatus::Reconnecting
                ))
    }

    /// Whether the next frame would differ from the last one on its own.
    fn animation_active(&self, now: Instant) -> bool {
        use zeronet_tui::modal_anim::ModalPhase;

        // Dialog open/close runs whether or not decorative animation is on:
        // it is also what removes a dismissed dialog.
        let tick = self.effects.current_tick();
        if self.modal_state.is_active()
            && (self.modal_anim.phase() != ModalPhase::Open
                || self.modal_anim.nudge_intensity(tick) > 0.0)
        {
            return true;
        }
        if self.help_scroll.is_animating() || self.settings_scroll.is_animating() {
            return true;
        }
        // The click-confirming flash has to be taken down again even with
        // animation off, or the row would stay lit until the next event.
        if tick.saturating_sub(self.selection_tick) < SELECTION_FLASH_TICKS {
            return true;
        }
        if !self.caps.animations {
            return false;
        }
        // The update dialog's light sweep and progress sheen.
        if matches!(self.modal_state, ModalState::Update { .. })
            && self.effects.animations_enabled()
        {
            return true;
        }
        self.effects.is_animating()
            // A dimmed backdrop hides the ambient sheen and glows entirely.
            || (self.effects.ambient_running() && !self.modal_state.is_active())
            || self.spinner_visible()
            || self.toasts.is_animating(now)
    }

    /// Frame spacing while animating: faster while the chromatic wave is
    /// crossing the screen, since it moves several cells a frame.
    fn frame_interval(&self) -> Duration {
        if self.effects.rainbow_active() {
            FAST_FRAME_INTERVAL
        } else {
            FRAME_INTERVAL
        }
    }

    /// When the loop must wake next with no input, or `None` to sleep until
    /// something arrives. An idle client at rest never wakes on its own.
    fn next_wake(&self, pacer: &FramePacer, now: Instant) -> Option<Instant> {
        if self.dirty {
            return Some(pacer.next_frame(MIN_FRAME_GAP));
        }
        if self.animation_active(now) {
            return Some(pacer.next_frame(self.frame_interval()));
        }
        let mut wake: Option<Instant> = self.toasts.next_deadline(now);
        let mut sooner = |at: Instant| wake = Some(wake.map_or(at, |w| w.min(at)));
        // The moment ambient motion should start fading out.
        if self.caps.animations && self.effects.ambient_wanted() {
            sooner(pacer.ambient_deadline());
        }
        // Scanner progress arrives through shared counters, not a channel.
        if self.is_scanning {
            sooner(now + SCANNER_POLL);
        }
        if let Some(at) = self.speed_history.next_sample {
            sooner(at);
        }
        // The frame-stats overlay counts down to 0 fps on its own.
        if let Some(at) = self.perf.next_refresh {
            sooner(at);
        }
        wake
    }

    /// Feed one terminal event to the app. Returns whether the picture may
    /// have changed.
    async fn dispatch_input(&mut self, event: Event, pacer: &mut FramePacer) -> Result<bool> {
        match event {
            Event::FocusLost => {
                pacer.set_focused(false);
                // Nothing should stay lit under a pointer that is now in
                // another window.
                self.interaction.clear_pointer();
                return Ok(true);
            }
            Event::FocusGained => {
                pacer.set_focused(true);
                pacer.touch(Instant::now());
                return Ok(true);
            }
            _ => {}
        }
        pacer.touch(Instant::now());

        // A pointer sweep reports every cell it crosses. Most of those land
        // on the same control, and redrawing the whole screen for each would
        // be pure waste; only a change of hover target (or a drag) matters.
        if let Event::Mouse(mouse) = &event {
            if mouse.kind == MouseEventKind::Moved {
                let before = self.interaction.hovered_component;
                self.handle_event(event).await?;
                return Ok(self.interaction.hovered_component != before);
            }
        }
        self.handle_event(event).await?;
        Ok(true)
    }

    fn draw(&mut self, frame: &mut ratatui::Frame) {
        let size = frame.area();
        self.viewport = (size.width, size.height);
        let snapshot = self.usage.latest();
        let usage = zeronet_tui::ui_activity::UsageView {
            snapshot: snapshot.as_deref(),
            cpu_history: &self.usage.cpu_history,
            memory_history: &self.usage.memory_history,
            system_history: &self.usage.system_history,
            sort: self.activity_sort,
        };
        let mut renderer = UiRenderer {
            theme: &self.theme,
            caps: &self.caps,
            interaction: &mut self.interaction,
            effects: &mut self.effects,
            settings: &self.settings,
            stats: &self.stats,
            active_tab: self.active_tab,
            configs: &self.configs,
            subscriptions: &self.subscriptions,
            selected_config_idx: self.selected_config_idx,
            node_scroll: self.node_scroll,
            marked: &self.marked,
            filter: &self.filter,
            filter_focused: self.filter_focused,
            advanced_open: self.advanced_open,
            filter_select_all: self.filter_select_all,
            inline_rename: self.inline_rename.as_ref(),
            system_proxy: self.system_proxy,
            latency_history: &self.latency_history,
            is_elevated: self.is_elevated,
            elevation_prompt: self.elevation_prompt,
            modal_state: &self.modal_state,
            modal_anim: self.modal_anim,
            settings_scroll: self.settings_scroll,
            help_scroll: self.help_scroll,
            selection_tick: self.selection_tick,
            context_menu: self.context_menu.as_ref(),
            drag: self.drag,
            image_view: self.image_view.as_mut(),
            throbber_state: &mut self.throbber,
            scanner_tested: self.scanner_tested,
            scanner_healthy: self.scanner_healthy,
            scanner_speed: self.scanner_speed,
            is_scanning: self.is_scanning,
            scanner_results: &self.scanner_results,
            toasts: &mut self.toasts,
            usage,
            perf: self.perf.snapshot(Instant::now()),
            session: self.connected_since.map(|since| since.elapsed()),
            speed_history: (&self.speed_history.up, &self.speed_history.down),
            update_status: &self.updater.status,
        };
        renderer.render(frame);
    }

    /// Turn a daemon transition into user-visible feedback.
    ///
    /// Failures used to be written to a field nothing read, so a connect that
    /// could not bind its ports looked identical to one that simply had not
    /// finished. Each transition is reported exactly once, keyed on the
    /// daemon's revision counter.
    fn on_status_change(&mut self, next: DaemonStats) {
        let previous_status = self.stats.status;
        let new_revision = next.revision > self.reported_revision;
        self.stats = next;

        // The session clock runs through a reconnect, like any VPN client's:
        // it measures the session, not the current socket.
        match self.stats.status {
            ConnectionStatus::Connected | ConnectionStatus::Reconnecting => {
                if self.connected_since.is_none()
                    && self.stats.status == ConnectionStatus::Connected
                {
                    let now = Instant::now();
                    self.connected_since = Some(now);
                    self.speed_history.clear();
                    self.speed_history.next_sample = Some(now + Duration::from_secs(1));
                }
            }
            _ => {
                self.connected_since = None;
                self.speed_history.next_sample = None;
            }
        }

        if !new_revision {
            return;
        }
        self.reported_revision = self.stats.revision;

        match self.stats.status {
            ConnectionStatus::Connected if previous_status != ConnectionStatus::Connected => {
                self.toasts.info(format!(
                    "Connected to {}. Checking it carries traffic…",
                    self.stats.active_node_name
                ));
                self.begin_health_check();
                // The configured mode is applied on connect, not on launch:
                // pointing the desktop at a proxy that is not yet listening
                // would break networking for as long as it took to dial.
                let wanted =
                    SystemProxyMode::parse(&self.settings.system_proxy_mode).unwrap_or_default();
                if wanted.writes_settings() && self.system_proxy != wanted {
                    self.pending_system_proxy = Some(wanted);
                }
                if self.settings.tun_enabled && !self.stats.tun_active {
                    self.toasts.warning(
                        "Couldn't create TUN, so this is proxy mode only. Start with sudo to route the whole system.",
                    );
                }
            }
            ConnectionStatus::Error => {
                let reason = self
                    .stats
                    .error_msg
                    .as_deref()
                    .map(zeronet_tui::daemon::describe_config_error)
                    .unwrap_or_else(|| "unknown error".into());
                self.toasts.error(format!("Connection failed: {reason}"));
                // Nothing is listening any more. Unless a newer connect is
                // already on its way, stop claiming a connection: clear the
                // intent (so the connect control means "connect" again),
                // drop the TUN helper whose routes now lead nowhere, and put
                // the desktop's proxy back — it points at dead ports.
                if !self.connect_in_progress() {
                    self.connection.on_engine_failed();
                    self.release_privileged_tun();
                    self.pending_system_proxy = None;
                    self.queue_proxy_revert(true);
                }
            }
            ConnectionStatus::Disconnected if previous_status == ConnectionStatus::Connected => {
                self.toasts.info("Disconnected.");
            }
            _ => {}
        }
    }

    fn spawn_node_pings(&mut self, tx: tokio::sync::mpsc::UnboundedSender<PingResult>) {
        let targets: Vec<PingTarget> = self
            .configs
            .iter()
            .map(|c| PingTarget {
                config_id: c.id,
                host: c.address.clone(),
                port: c.port,
            })
            .collect();
        if targets.is_empty() {
            return;
        }
        // Replaces a sweep still running rather than overlapping it.
        self.start_ping_sweep(targets, tx);
    }

    fn apply_ping_result(&mut self, result: PingResult) {
        if let Some(cfg) = self.configs.iter_mut().find(|c| c.id == result.config_id) {
            cfg.ping_ms = result.latency_ms;
            if cfg.is_active {
                if let Some(ms) = result.latency_ms {
                    if self.latency_history.len() >= 120 {
                        self.latency_history.remove(0);
                    }
                    self.latency_history.push(ms);
                }
            }
        }
        // Buffered and written in batches off the frame loop; a sweep over
        // a large feed used to be hundreds of synchronous writes here.
        if let Some(ms) = result.latency_ms {
            self.record_ping(result.config_id, ms);
        }
    }

    fn poll_scanner(&mut self) {
        if !self.is_scanning {
            return;
        }
        if let Some(handle) = &self.scan_handle {
            if handle.is_finished() {
                self.is_scanning = false;
                *self.scanner_stats.lock().unwrap() = None;
                self.toasts.success(format!(
                    "Scan done: {} clean endpoints.",
                    self.scanner_results.len()
                ));
                self.dirty = true;
            }
        }
        while let Ok(hit) = self.scan_rx.try_recv() {
            self.scanner_results.push(hit);
            self.dirty = true;
        }
        if let Some(stats) = self.scanner_stats.lock().unwrap().as_ref() {
            let (tested, healthy, _failed, _in_flight, speed) = stats.snapshot();
            if tested != self.scanner_tested || healthy != self.scanner_healthy {
                self.dirty = true;
            }
            self.scanner_tested = tested;
            self.scanner_healthy = healthy;
            self.scanner_speed = speed;
        }
    }

    // ------------------------------------------------------------- input

    /// Handle one terminal event.
    ///
    /// A handler's error is reported and the session carries on. It used to
    /// propagate out of the frame loop, so a single failed database write or
    /// a daemon hiccup ended the whole client.
    async fn handle_event(&mut self, event: Event) -> Result<()> {
        if let Err(error) = self.handle_event_inner(event).await {
            tracing::error!(error = %format!("{error:#}"), "event handler failed");
            self.toasts.error(format!("{error:#}"));
        }
        Ok(())
    }

    async fn handle_event_inner(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Mouse(mouse) => {
                self.interaction
                    .update_mouse_position(mouse.column, mouse.row);
                match mouse.kind {
                    MouseEventKind::Down(crossterm::event::MouseButton::Right) => {
                        self.open_context_menu(mouse.column, mouse.row);
                    }
                    MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                        let hit = self.interaction.hit_test(mouse.column, mouse.row);
                        self.interaction.pressed = hit;
                        if self.begin_scrollbar_gesture(hit, mouse.column, mouse.row) {
                            // The bar owns this gesture. Starting a rubber
                            // band as well would select every row the pointer
                            // crosses on its way down the thumb.
                            self.drag = None;
                        } else {
                            // A press might become a drag, so the click is not
                            // performed until the button is released.
                            let additive = mouse
                                .modifiers
                                .intersects(KeyModifiers::CONTROL | KeyModifiers::SHIFT);
                            self.drag = Some(DragSelect::press(mouse.column, mouse.row, additive));
                        }
                    }
                    MouseEventKind::Drag(crossterm::event::MouseButton::Left) => {
                        if self.thumb_drag.is_some() {
                            self.scrub_scrollbar(mouse.row);
                        } else if let Some(drag) = self.drag.as_mut() {
                            if drag.moved(mouse.column, mouse.row) {
                                self.apply_drag_selection();
                            }
                        }
                    }
                    MouseEventKind::Up(crossterm::event::MouseButton::Left) => {
                        self.interaction.pressed = None;
                        if self.thumb_drag.take().is_some() {
                            // The drag already moved the list. A click on
                            // release would also fire whatever sits under the
                            // pointer now.
                            return Ok(());
                        }
                        let drag = self.drag.take();
                        match drag {
                            // A real drag has already updated the selection;
                            // releasing just ends it.
                            Some(d) if d.is_active() => {}
                            _ => {
                                if let Some(hit) =
                                    self.interaction.handle_click(mouse.column, mouse.row)
                                {
                                    self.on_click(hit, mouse.column, mouse.row, mouse.modifiers)
                                        .await?;
                                } else {
                                    // A click on empty space/background deselects all selected
                                    // configs and un-focuses the filter box, matching desktop apps.
                                    self.marked.clear();
                                    self.filter_focused = false;
                                }
                            }
                        }
                    }
                    MouseEventKind::ScrollDown => self.scroll(1),
                    MouseEventKind::ScrollUp => self.scroll(-1),
                    _ => {}
                }
            }
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                self.on_key(key).await?;
            }
            Event::Paste(text) => {
                // Bracketed paste: the terminal hands over the whole payload
                // at once, which is how a pasted share link arrives without
                // being retyped character by character.
                self.handle_pasted_text(&text).await?;
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
        Ok(())
    }

    /// Route a key press by context.
    ///
    /// Context comes first: a dialog with a text field consumes printable
    /// characters before any global binding sees them, so typing `q` into a
    /// field types a `q` instead of quitting.
    /// Whether the dialog on screen is still interactive.
    ///
    /// False while it animates out: the state lingers for a few frames after
    /// dismissal, and without this a second Enter in that window would run
    /// the dialog's action a second time.
    fn modal_accepts_input(&self) -> bool {
        self.modal_state.is_active()
            && self.modal_anim.phase() != zeronet_tui::modal_anim::ModalPhase::Closing
    }

    async fn on_key(&mut self, key: crossterm::event::KeyEvent) -> Result<()> {
        // The inline rename field owns the keyboard while editing a name.
        if self.inline_rename.is_some() {
            return self.on_inline_rename_key(key).await;
        }

        // The context menu owns the keyboard while it is open.
        if self.context_menu.is_some() {
            return self.on_menu_key(key).await;
        }

        // Input is suspended for the few frames a dialog takes to close.
        // At 200ms this is imperceptible, and it removes any chance of a
        // keystroke landing between dismissal and removal.
        if self.modal_state.is_active() && !self.modal_accepts_input() {
            return Ok(());
        }

        let context = if self.filter_focused {
            InputContext::Editing
        } else {
            self.modal_state.input_context()
        };

        if context == InputContext::Browsing {
            if key.code == KeyCode::F(12) {
                self.perf.toggle();
                return Ok(());
            }
            if self.konami.feed(key.code) {
                self.on_secret_sequence();
            }
        }

        match context {
            InputContext::Editing => {
                let action = keymap::resolve_editing(key);
                self.on_edit_action(action).await
            }
            InputContext::Dialog => {
                // A dialog resolves its own small set of keys, then falls
                // through to the form controls it owns.
                if let Some(command) = keymap::resolve(key, InputContext::Dialog) {
                    return self.run_command(command).await;
                }
                self.on_dialog_key(key).await
            }
            InputContext::Browsing => {
                let Some(command) = keymap::resolve(key, InputContext::Browsing) else {
                    return Ok(());
                };
                self.run_command(command).await
            }
        }
    }

    /// Keys inside a text field.
    async fn on_edit_action(&mut self, action: EditAction) -> Result<()> {
        // The filter box is a text field that lives outside the dialog stack.
        if self.filter_focused {
            match action {
                EditAction::SelectAll => {
                    self.filter_select_all = true;
                }
                EditAction::InsertChar(c) => {
                    if self.filter_select_all {
                        self.filter.clear();
                        self.filter_select_all = false;
                    }
                    self.filter.push(c);
                }
                EditAction::Backspace => {
                    if self.filter_select_all {
                        self.filter.clear();
                        self.filter_select_all = false;
                    } else {
                        self.filter.pop();
                    }
                }
                EditAction::DeleteForward => {
                    if self.filter_select_all {
                        self.filter.clear();
                        self.filter_select_all = false;
                    }
                }
                EditAction::ClearLine => {
                    self.filter.clear();
                    self.filter_select_all = false;
                }
                EditAction::DeleteWord => {
                    if self.filter_select_all {
                        self.filter.clear();
                        self.filter_select_all = false;
                    } else {
                        while self.filter.pop().is_some_and(|c| !c.is_whitespace()) {}
                    }
                }
                EditAction::Copy => {
                    if !self.filter.is_empty() {
                        let text = self.filter.clone();
                        self.copy_to_clipboard(&text, "Filter");
                    }
                }
                EditAction::Cut => {
                    if !self.filter.is_empty() {
                        let text = std::mem::take(&mut self.filter);
                        self.copy_to_clipboard(&text, "Filter");
                        self.filter_select_all = false;
                    }
                }
                EditAction::Paste => {
                    if let Ok(text) = self.clipboard.paste() {
                        if self.filter_select_all {
                            self.filter.clear();
                            self.filter_select_all = false;
                        }
                        self.filter.push_str(text.trim());
                    }
                }
                EditAction::MoveLeft
                | EditAction::MoveRight
                | EditAction::MoveHome
                | EditAction::MoveEnd => {
                    self.filter_select_all = false;
                }
                EditAction::Submit | EditAction::Cancel => {
                    if action == EditAction::Cancel {
                        self.filter.clear();
                    }
                    self.filter_select_all = false;
                    self.filter_focused = false;
                }
                _ => {}
            }
            self.clamp_selection();
            return Ok(());
        }

        let mut copy_req = None;
        match &mut self.modal_state {
            ModalState::TextInput {
                buffer, select_all, ..
            } => match action {
                EditAction::SelectAll => *select_all = true,
                EditAction::InsertChar(c) => {
                    if *select_all {
                        buffer.clear();
                        *select_all = false;
                    }
                    buffer.push(c);
                }
                EditAction::Backspace => {
                    if *select_all {
                        buffer.clear();
                        *select_all = false;
                    } else {
                        buffer.pop();
                    }
                }
                EditAction::DeleteForward => {
                    if *select_all {
                        buffer.clear();
                        *select_all = false;
                    }
                }
                EditAction::ClearLine => {
                    buffer.clear();
                    *select_all = false;
                }
                EditAction::DeleteWord => {
                    if *select_all {
                        buffer.clear();
                        *select_all = false;
                    } else {
                        while buffer.pop().is_some_and(|c| !c.is_whitespace()) {}
                    }
                }
                EditAction::Copy => {
                    copy_req = Some((buffer.clone(), "Field"));
                }
                EditAction::Cut => {
                    let text = std::mem::take(buffer);
                    *select_all = false;
                    copy_req = Some((text, "Field"));
                }
                EditAction::Paste => match self.clipboard.paste() {
                    Ok(text) => {
                        if let ModalState::TextInput {
                            buffer, select_all, ..
                        } = &mut self.modal_state
                        {
                            if *select_all {
                                buffer.clear();
                                *select_all = false;
                            }
                            buffer.push_str(text.trim());
                        }
                    }
                    Err(e) => self.toasts.warning(e),
                },
                EditAction::MoveLeft
                | EditAction::MoveRight
                | EditAction::MoveHome
                | EditAction::MoveEnd => {
                    *select_all = false;
                }
                EditAction::Submit => {
                    let text = buffer.trim().to_string();
                    self.submit_text_modal(&text).await?;
                }
                EditAction::Cancel => self.close_modal(),
                _ => {}
            },

            // A password field takes typing and nothing else. Copy and Cut
            // are deliberately absent: putting a password on the system
            // clipboard is a leak the user did not ask for, and every other
            // dialog here offers exactly that on the same keys.
            ModalState::SudoPassword { buffer, error, .. } => match action {
                EditAction::InsertChar(c) => {
                    *error = None;
                    buffer.push(c);
                }
                EditAction::Backspace => {
                    buffer.pop();
                }
                EditAction::DeleteWord | EditAction::ClearLine => {
                    // No word boundaries are visible in a masked field, so
                    // both keys clear the whole thing.
                    zeroize(buffer);
                }
                // Pasting from a password manager is the normal way to enter
                // one, so it is allowed inwards even though copying outwards
                // is not.
                EditAction::Paste => match self.clipboard.paste() {
                    Ok(text) => {
                        if let ModalState::SudoPassword { buffer, error, .. } =
                            &mut self.modal_state
                        {
                            *error = None;
                            buffer.push_str(text.trim_end_matches(['\n', '\r']));
                        }
                    }
                    Err(e) => self.toasts.warning(e),
                },
                EditAction::Submit => self.submit_sudo_password().await?,
                EditAction::Cancel => self.cancel_sudo_dialog().await?,
                _ => {}
            },

            ModalState::NumberEdit {
                setting_key,
                min,
                max,
                buffer,
                select_all,
                ..
            } => match action {
                EditAction::SelectAll => *select_all = true,
                EditAction::InsertChar(c) if c.is_ascii_digit() => {
                    if *select_all {
                        buffer.clear();
                        *select_all = false;
                    }
                    buffer.push(c);
                }
                EditAction::Backspace => {
                    if *select_all {
                        buffer.clear();
                        *select_all = false;
                    } else {
                        buffer.pop();
                    }
                }
                EditAction::DeleteForward => {
                    if *select_all {
                        buffer.clear();
                        *select_all = false;
                    }
                }
                EditAction::ClearLine => {
                    buffer.clear();
                    *select_all = false;
                }
                EditAction::MoveLeft
                | EditAction::MoveRight
                | EditAction::MoveHome
                | EditAction::MoveEnd => {
                    *select_all = false;
                }
                EditAction::Submit => {
                    let (key, min, max, value) =
                        (setting_key.clone(), *min, *max, buffer.parse::<u64>().ok());
                    self.commit_number(&key, min, max, value).await?;
                }
                EditAction::Cancel => self.close_modal(),
                _ => {}
            },

            ModalState::ManualProfile {
                form, input_buffer, ..
            } => match action {
                EditAction::InsertChar(c) => push_form_field(form, c),
                EditAction::Backspace => backspace_form_field(form),
                EditAction::ClearLine => clear_form_field(form),
                EditAction::NextField => {
                    form.focused_field =
                        (form.focused_field + 1) % ManualProfileForm::field_count();
                    input_buffer.clear();
                }
                EditAction::PrevField => {
                    form.focused_field = (form.focused_field + ManualProfileForm::field_count()
                        - 1)
                        % ManualProfileForm::field_count();
                    input_buffer.clear();
                }
                EditAction::Paste => match self.clipboard.paste() {
                    Ok(text) => {
                        if let ModalState::ManualProfile { form, .. } = &mut self.modal_state {
                            for c in text.trim().chars() {
                                push_form_field(form, c);
                            }
                        }
                    }
                    Err(e) => self.toasts.warning(e),
                },
                EditAction::Submit => self.save_manual_profile().await?,
                EditAction::Cancel => self.close_modal(),
                _ => {}
            },

            _ => {}
        }
        if let Some((text, label)) = copy_req {
            self.copy_to_clipboard(&text, label);
        }
        Ok(())
    }

    /// Keys while the right-click menu is open.
    async fn on_menu_key(&mut self, key: crossterm::event::KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc => self.close_context_menu(),
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(m) = self.context_menu.as_mut() {
                    m.move_highlight(-1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(m) = self.context_menu.as_mut() {
                    m.move_highlight(1);
                }
            }
            KeyCode::Enter => {
                let action = self
                    .context_menu
                    .as_ref()
                    .and_then(|m| m.highlighted_action());
                if let Some(action) = action {
                    self.run_menu_action(action).await?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Keys while inline renaming a profile in the list.
    async fn on_inline_rename_key(&mut self, key: crossterm::event::KeyEvent) -> Result<()> {
        use crossterm::event::KeyCode;
        let ctrl = key
            .modifiers
            .contains(crossterm::event::KeyModifiers::CONTROL);

        let Some(rename) = self.inline_rename.as_mut() else {
            return Ok(());
        };

        let mut copy_text = None;
        match key.code {
            KeyCode::Enter => {
                let rename = self.inline_rename.take().unwrap();
                let text = rename.buffer.trim();
                if !text.is_empty() {
                    match self.db.rename_config(rename.config_id, text) {
                        Ok(()) => {
                            if let Some(c) =
                                self.configs.iter_mut().find(|c| c.id == rename.config_id)
                            {
                                c.remark = text.to_string();
                            }
                            self.toasts.success(format!("Renamed to {text}"));
                        }
                        Err(e) => {
                            self.toasts.error(format!("Rename failed: {e}"));
                        }
                    }
                }
            }
            KeyCode::Esc => {
                self.inline_rename = None;
            }
            KeyCode::Char('a') | KeyCode::Char('A') if ctrl => {
                rename.select_all = true;
            }
            KeyCode::Char('c') | KeyCode::Char('C') if ctrl => {
                copy_text = Some(rename.buffer.clone());
            }
            KeyCode::Char('v') | KeyCode::Char('V') if ctrl => {
                if let Ok(paste_text) = self.clipboard.paste() {
                    let clean = paste_text.trim();
                    if rename.select_all {
                        rename.buffer = clean.to_string();
                        rename.cursor = rename.buffer.chars().count();
                        rename.select_all = false;
                    } else {
                        let cursor = rename.cursor.min(rename.buffer.chars().count());
                        let chars: Vec<char> = rename.buffer.chars().collect();
                        let mut new_chars = chars[..cursor].to_vec();
                        new_chars.extend(clean.chars());
                        new_chars.extend_from_slice(&chars[cursor..]);
                        rename.buffer = new_chars.into_iter().collect();
                        rename.cursor += clean.chars().count();
                    }
                }
            }
            KeyCode::Char('x') | KeyCode::Char('X') if ctrl => {
                if rename.select_all {
                    let text = std::mem::take(&mut rename.buffer);
                    rename.cursor = 0;
                    rename.select_all = false;
                    copy_text = Some(text);
                }
            }
            KeyCode::Char(c) => {
                if rename.select_all {
                    rename.buffer.clear();
                    rename.cursor = 0;
                    rename.select_all = false;
                }
                let cursor = rename.cursor.min(rename.buffer.chars().count());
                let chars: Vec<char> = rename.buffer.chars().collect();
                let mut new_chars = chars[..cursor].to_vec();
                new_chars.push(c);
                new_chars.extend_from_slice(&chars[cursor..]);
                rename.buffer = new_chars.into_iter().collect();
                rename.cursor += 1;
            }
            KeyCode::Backspace => {
                if rename.select_all {
                    rename.buffer.clear();
                    rename.cursor = 0;
                    rename.select_all = false;
                } else if rename.cursor > 0 {
                    let cursor = rename.cursor.min(rename.buffer.chars().count());
                    let mut chars: Vec<char> = rename.buffer.chars().collect();
                    chars.remove(cursor - 1);
                    rename.buffer = chars.into_iter().collect();
                    rename.cursor -= 1;
                }
            }
            KeyCode::Delete => {
                if rename.select_all {
                    rename.buffer.clear();
                    rename.cursor = 0;
                    rename.select_all = false;
                } else {
                    let cursor = rename.cursor.min(rename.buffer.chars().count());
                    let mut chars: Vec<char> = rename.buffer.chars().collect();
                    if cursor < chars.len() {
                        chars.remove(cursor);
                        rename.buffer = chars.into_iter().collect();
                    }
                }
            }
            KeyCode::Left => {
                rename.select_all = false;
                rename.cursor = rename.cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                rename.select_all = false;
                rename.cursor = (rename.cursor + 1).min(rename.buffer.chars().count());
            }
            KeyCode::Home => {
                rename.select_all = false;
                rename.cursor = 0;
            }
            KeyCode::End => {
                rename.select_all = false;
                rename.cursor = rename.buffer.chars().count();
            }
            _ => {}
        }
        if let Some(text) = copy_text {
            self.copy_to_clipboard(&text, "Name");
        }
        Ok(())
    }

    /// Keys inside a dialog that has no text field.
    async fn on_dialog_key(&mut self, key: crossterm::event::KeyEvent) -> Result<()> {
        match &mut self.modal_state {
            ModalState::ManualProfile {
                form, input_buffer, ..
            } => match key.code {
                KeyCode::Tab => {
                    form.focused_field =
                        (form.focused_field + 1) % ManualProfileForm::field_count();
                    input_buffer.clear();
                }
                KeyCode::BackTab => {
                    form.focused_field = (form.focused_field + ManualProfileForm::field_count()
                        - 1)
                        % ManualProfileForm::field_count();
                    input_buffer.clear();
                }
                KeyCode::Char(' ')
                | KeyCode::Right
                | KeyCode::Left
                | KeyCode::Up
                | KeyCode::Down => {
                    cycle_form_field(form);
                }
                _ => {}
            },
            ModalState::Help { .. } => {
                let max = scroll::max_offset(UiRenderer::help_content_height(), self.help_rows());
                match key.code {
                    KeyCode::Down | KeyCode::Char('j') => self.help_scroll.step(1, max),
                    KeyCode::Up | KeyCode::Char('k') => self.help_scroll.step(-1, max),
                    KeyCode::PageDown => self.help_scroll.step(10, max),
                    KeyCode::PageUp => self.help_scroll.step(-10, max),
                    KeyCode::Home => self.help_scroll.to_top(),
                    KeyCode::End => self.help_scroll.to_bottom(max),
                    _ => {}
                }
            }
            // Copying is the whole point of the share dialog, so Ctrl+C is
            // handled here rather than falling through to the global binding.
            ModalState::ShareConfig { uri, .. }
                if key.code == KeyCode::Char('c')
                    && key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                let uri = uri.clone();
                self.copy_to_clipboard(&uri, "Share link");
            }
            _ => {}
        }
        Ok(())
    }

    // ------------------------------------------------------- connection

    /// Carry out whatever the connection manager decided.
    ///
    /// Every connection change funnels through here, so there is exactly one
    /// place that can start or stop the engine — and it only ever acts on an
    /// explicit decision, never as a side effect of browsing the list.
    async fn apply_engine_action(&mut self, action: EngineAction) -> Result<()> {
        match action {
            EngineAction::None => {}
            EngineAction::Connect(id) | EngineAction::Switch(id) => {
                if self.config_by_id(id).is_none() {
                    return Ok(());
                }
                self.mark_active(id);
                let mut options = self.engine_options();

                // TUN needs privileges this process may not have, and the
                // descriptor is handed over rather than opened, so it has to
                // exist before the engine starts. Getting it — sudo, maybe a
                // password dialog, the helper — runs in the background and
                // resumes the dial when done (see `app_tasks`); the frame
                // loop used to sit in it for up to twenty seconds.
                if options.tun_mode && !self.is_elevated {
                    self.begin_tun_connect(action, None);
                    return Ok(());
                }
                // Nothing to hand over when the process can open the device
                // itself; and a newer request supersedes any TUN job still
                // running for an older one.
                options.tun_ready = options.tun_mode && self.is_elevated;
                self.cancel_pending_connect();
                self.dial(action, options).await?;
            }
            EngineAction::Disconnect => {
                // A connect still being prepared must not complete after this.
                self.cancel_pending_connect();
                self.pending_elevation = None;
                self.daemon.disconnect().await?;
                // The helper holds the interface up; releasing it is what
                // removes the routes again. Doing it on every disconnect —
                // rather than only on quit — means a machine is never left
                // routing through an interface with nothing behind it.
                self.release_privileged_tun();
                // Leaving the desktop pointed at a dead proxy would break
                // every application's networking.
                self.revert_system_proxy().await;
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------- elevation

    fn open_sudo_dialog(&mut self, error: Option<String>) {
        self.modal_state = ModalState::SudoPassword {
            prompt: format!(
                "Zray needs to create the {} interface and install routes. \
                 Without it, only applications pointed at the SOCKS/HTTP proxy \
                 are tunnelled.",
                self.settings.tun_device_name
            ),
            buffer: String::new(),
            error,
            created_tick: self.effects.current_tick(),
        };
        self.open_modal_effect();
    }

    /// Enter pressed in the password dialog.
    ///
    /// The password is checked before it is used, so a typo produces "that
    /// password was not accepted" rather than a TUN failure indistinguishable
    /// from a missing kernel module. It is zeroed either way.
    async fn submit_sudo_password(&mut self) -> Result<()> {
        let ModalState::SudoPassword { buffer, .. } = &mut self.modal_state else {
            return Ok(());
        };
        if buffer.is_empty() {
            return Ok(());
        }
        let password = std::mem::take(buffer);
        // `sudo -v` runs on the blocking pool; a wrong password costs sudo's
        // own delay of a couple of seconds, which the frame loop used to sit
        // through. The answer arrives as a background event.
        self.begin_password_check(password);
        Ok(())
    }

    /// The user chose proxy-only. Remember it, and stop asking.
    fn decline_elevation(&mut self) {
        self.elevation_declined = true;
        self.pending_elevation = None;
    }

    /// Esc, or "Proxy only", in the password dialog.
    ///
    /// The button says proxy only, so that is what happens: the dial that was
    /// parked goes ahead without TUN rather than being silently dropped.
    /// Being asked for a password and then getting no connection at all would
    /// be the worst of both.
    async fn cancel_sudo_dialog(&mut self) -> Result<()> {
        let pending = self.pending_elevation.take();
        self.elevation_declined = true;
        self.close_modal();
        match pending {
            Some(action) => {
                self.toasts
                    .warning("Carrying on in proxy mode. TUN stays off this session.");
                self.cancel_pending_connect();
                let mut options = self.engine_options();
                options.tun_ready = false;
                self.dial(action, options).await
            }
            None => Ok(()),
        }
    }

    /// Tear down the helper and discard any descriptor nobody adopted.
    fn release_privileged_tun(&mut self) {
        if let Some(stale) = zero_tun::inherited::clear() {
            close_descriptor(stale.fd);
        }
        // Dropping the helper closes its stdin, which is how it is told to
        // remove the addresses and routes it installed. The drop waits for
        // the helper to finish (up to two seconds), so it happens off the
        // frame loop; a new helper for the same device waits for it.
        if let Some(helper) = self.privileged_tun.take() {
            self.retire_helper(helper);
        }
    }

    fn config_by_id(&self, id: i64) -> Option<&ConfigRecord> {
        self.configs.iter().find(|c| c.id == id)
    }

    /// Record which profile is in use, in memory and on disk.
    fn mark_active(&mut self, id: i64) {
        let _ = self.db.set_active_config(id);
        for c in self.configs.iter_mut() {
            c.is_active = c.id == id;
        }
    }

    /// Highlight a profile.
    ///
    /// While offline this is navigation only. While online it switches
    /// servers — the behaviour every desktop VPN client has.
    async fn select_profile(&mut self, id: i64) -> Result<()> {
        let action = self.connection.select(id);
        if let Some(idx) = self.visible_configs().iter().position(|c| c.id == id) {
            self.selected_config_idx = idx;
            self.selection_tick = self.effects.current_tick();
            self.follow_selection();
        }
        self.apply_engine_action(action).await
    }

    /// The connect control, in all its forms.
    async fn toggle_connection(&mut self) -> Result<()> {
        if self.connection.selected().is_none() {
            let first = self.visible_configs().first().map(|c| c.id);
            match first {
                Some(id) => {
                    self.connection.select(id);
                }
                None => {
                    self.toasts
                        .warning("No profiles yet. Press Ctrl+V to paste a share link.");
                    return Ok(());
                }
            }
        }
        let action = self.connection.toggle();
        self.apply_engine_action(action).await
    }

    /// Rebuild a live connection after an engine setting changed.
    async fn reapply_engine_settings(&mut self) -> Result<()> {
        let action = self.connection.reapply();
        if action != EngineAction::None {
            self.toasts.info("Applying new engine settings…");
        }
        self.apply_engine_action(action).await
    }

    // --------------------------------------------------------- commands

    async fn run_command(&mut self, command: Command) -> Result<()> {
        match command {
            // ---- connection
            Command::ToggleConnection | Command::Confirm if self.modal_state.is_active() => {
                self.confirm_modal().await?;
            }
            Command::ToggleConnection => self.toggle_connection().await?,
            Command::Connect => {
                let action = self.connection.connect();
                self.apply_engine_action(action).await?;
            }
            Command::Disconnect => {
                let action = self.connection.disconnect();
                self.apply_engine_action(action).await?;
            }
            Command::Confirm => self.confirm_modal().await?,

            // ---- cancel / quit
            Command::Cancel => {
                if self.modal_state.is_active() {
                    self.close_modal();
                } else if self.filter_focused || !self.filter.is_empty() {
                    self.filter.clear();
                    self.filter_focused = false;
                    self.clamp_selection();
                } else if !self.marked.is_empty() {
                    self.marked.clear();
                } else {
                    self.open_quit_dialog();
                }
            }
            Command::Quit => self.open_quit_dialog(),

            // ---- navigation
            Command::NextView => self.active_tab = next_tab(self.active_tab),
            Command::PrevView => self.active_tab = prev_tab(self.active_tab),
            Command::GoDashboard => self.active_tab = ActiveTab::Dashboard,
            Command::GoProfiles => self.active_tab = ActiveTab::Subscriptions,
            Command::GoScanner => self.active_tab = ActiveTab::IpScanner,
            Command::GoSettings => self.active_tab = ActiveTab::Settings,
            Command::GoActivity => self.active_tab = ActiveTab::Activity,

            Command::MoveUp => self.move_selection(-1),
            Command::MoveDown => self.move_selection(1),
            Command::PageUp => self.move_selection(-10),
            Command::PageDown => self.move_selection(10),
            Command::MoveToTop => {
                self.selected_config_idx = 0;
                self.node_scroll = 0;
                self.sync_selection_to_connection();
            }
            Command::MoveToBottom => {
                self.selected_config_idx = self.visible_configs().len().saturating_sub(1);
                self.sync_selection_to_connection();
            }

            // ---- selection
            Command::SelectAll => {
                self.marked = self.visible_configs().iter().map(|c| c.id).collect();
                self.toasts
                    .info(format!("Selected {} profiles", self.marked.len()));
            }
            Command::SelectNone => {
                self.marked.clear();
            }
            Command::ToggleSelection => {
                if let Some(id) = self.selected_profile_id() {
                    if !self.marked.remove(&id) {
                        self.marked.insert(id);
                    }
                }
            }

            // ---- clipboard
            Command::Copy => self.copy_selection(),
            Command::Paste => {
                let text = match self.clipboard.paste() {
                    Ok(t) => t,
                    Err(e) => {
                        self.toasts.warning(e);
                        return Ok(());
                    }
                };
                self.handle_pasted_text(&text).await?;
            }
            Command::Cut => {
                self.copy_selection();
                self.request_delete();
            }

            // ---- profiles
            Command::NewProfile => {
                self.modal_state = ModalState::ManualProfile {
                    form: ManualProfileForm::new(),
                    editing_text: false,
                    input_buffer: String::new(),
                    created_tick: self.effects.current_tick(),
                };
                self.open_modal_effect();
            }
            Command::OpenFile => self.open_text_modal(
                "Import From File",
                "Path to a config, subscription or QR image",
                TextPurpose::ImportFilePath,
            ),
            Command::SaveAs => self.open_text_modal(
                "Export Profile",
                "Path to write the share link to",
                TextPurpose::ExportFilePath,
            ),
            Command::Duplicate => self.duplicate_selection(),
            Command::Delete => self.request_delete(),
            Command::Rename => self.request_rename(),
            Command::ShowQrCode => self.show_qr_code(),
            Command::ScanQrImage => self.open_text_modal(
                "Scan QR Image",
                "Path to a PNG/JPEG containing a config QR code",
                TextPurpose::ScanImagePath,
            ),

            // ---- system proxy
            Command::CycleSystemProxy => self.cycle_system_proxy().await,
            Command::ClearSystemProxy => {
                self.settings.system_proxy_mode = SystemProxyMode::Clear.as_str().to_string();
                self.persist_settings();
                self.apply_system_proxy(SystemProxyMode::Clear).await;
            }

            // ---- data
            Command::Refresh => {
                self.refresh_subscriptions();
                self.refresh_latencies();
            }
            Command::TestLatency => self.refresh_latencies(),
            Command::ExportAll => self.export_all_profiles(),
            Command::AddSubscription => self.open_text_modal(
                "Add Subscription Feed",
                "Enter the feed URL",
                TextPurpose::AddSubscription,
            ),

            // ---- search
            Command::Find => {
                self.filter_focused = true;
                self.active_tab = ActiveTab::Dashboard;
            }
            Command::ClearFilter => {
                self.filter.clear();
                self.filter_focused = false;
                self.clamp_selection();
            }

            // ---- app
            Command::Help => {
                self.modal_state = ModalState::Help {
                    scroll: 0,
                    created_tick: self.effects.current_tick(),
                };
                self.open_modal_effect();
            }
            Command::Feedback => self.send_feedback(),
            Command::CycleTheme => {
                let next = self.theme.id.next(self.settings.secret_theme_unlocked);
                self.apply_theme(next);
                self.toasts.info(format!("Theme: {}", next.label()));
            }
        }
        Ok(())
    }

    // ------------------------------------------------------ list helpers

    /// The profiles currently shown, after the filter.
    fn visible_configs(&self) -> Vec<&ConfigRecord> {
        if self.filter.trim().is_empty() {
            return self.configs.iter().collect();
        }
        let needle = self.filter.to_lowercase();
        self.configs
            .iter()
            .filter(|c| {
                c.remark.to_lowercase().contains(&needle)
                    || c.address.to_lowercase().contains(&needle)
                    || c.protocol.to_lowercase().contains(&needle)
            })
            .collect()
    }

    fn selected_profile_id(&self) -> Option<i64> {
        self.visible_configs()
            .get(self.selected_config_idx)
            .map(|c| c.id)
    }

    /// Profiles a bulk command should act on: the ticked set, or the
    /// highlighted row when nothing is ticked.
    fn action_targets(&self) -> Vec<i64> {
        if !self.marked.is_empty() {
            // Preserve list order rather than the set's arbitrary order, so
            // messages and deletions are predictable.
            return self
                .visible_configs()
                .iter()
                .map(|c| c.id)
                .filter(|id| self.marked.contains(id))
                .collect();
        }
        self.selected_profile_id().into_iter().collect()
    }

    fn move_selection(&mut self, delta: i32) {
        let len = self.visible_configs().len();
        if len == 0 {
            return;
        }
        let next = (self.selected_config_idx as i32 + delta).clamp(0, len as i32 - 1) as usize;
        self.selected_config_idx = next;
        self.follow_selection();
        self.sync_selection_to_connection();
    }

    /// Mirror keyboard navigation into the connection manager.
    ///
    /// Moving the highlight is navigation while offline and a server switch
    /// while online — the same rule the mouse follows.
    fn sync_selection_to_connection(&mut self) {
        let Some(id) = self.selected_profile_id() else {
            return;
        };
        // Arrow-key browsing must not thrash the tunnel, so while connected
        // the highlight moves without switching; Enter commits the change.
        if !self.connection.wants_connection() {
            self.connection.select(id);
        }
    }

    fn clamp_selection(&mut self) {
        let len = self.visible_configs().len();
        if len == 0 {
            self.selected_config_idx = 0;
            self.node_scroll = 0;
        } else if self.selected_config_idx >= len {
            self.selected_config_idx = len - 1;
            self.follow_selection();
        }
    }

    // ------------------------------------------------ context menu & drag

    /// Open the right-click menu for whatever is under the cursor.
    fn open_context_menu(&mut self, x: u16, y: u16) {
        // A dialog owns the screen; right-clicking behind it would act on
        // something the user cannot see.
        if self.modal_state.is_active() {
            return;
        }

        let target = match self.interaction.hit_test(x, y) {
            Some(ComponentId::ConfigItem(i)) | Some(ComponentId::ConfigShare(i)) => {
                // Right-clicking a row also selects it. In Windows/Linux/macOS desktop apps:
                // if right-clicking an item that is NOT currently part of the multi-selection,
                // the existing selection is cleared and this single item is selected.
                // If it IS already part of the selection, the multi-selection is preserved!
                if let Some(id) = self.visible_configs().get(i).map(|c| c.id) {
                    if !self.marked.contains(&id) {
                        self.marked.clear();
                    }
                    self.selected_config_idx = i;
                    self.connection.select(id);
                }
                MenuTarget::Profile(i)
            }
            Some(ComponentId::SubItem(i)) => {
                self.marked.clear();
                MenuTarget::Subscription(i)
            }
            Some(ComponentId::ScannerItem(i)) => {
                self.marked.clear();
                MenuTarget::ScannerResult(i)
            }
            Some(ComponentId::SystemProxyChip) => MenuTarget::ProxySwitcher,
            _ => {
                // Right-clicking empty background deselects any selected profiles!
                self.marked.clear();
                MenuTarget::Background
            }
        };

        self.context_menu = Some(ContextMenu::for_target(
            target,
            (x, y),
            self.effects.current_tick(),
            self.stats.status == ConnectionStatus::Connected,
            !self.marked.is_empty(),
        ));
    }

    fn open_proxy_menu(&mut self, x: u16, y: u16) {
        self.context_menu = Some(ContextMenu::for_target(
            MenuTarget::ProxySwitcher,
            (x, y.saturating_add(1)),
            self.effects.current_tick(),
            self.stats.status == ConnectionStatus::Connected,
            false,
        ));
    }

    fn close_context_menu(&mut self) {
        self.context_menu = None;
    }

    /// Carry out a menu entry.
    async fn run_menu_action(&mut self, action: MenuAction) -> Result<()> {
        let target = self.context_menu.as_ref().map(|m| m.target);
        self.close_context_menu();

        match action {
            MenuAction::Connect | MenuAction::Disconnect => self.toggle_connection().await?,
            MenuAction::Copy => self.copy_selection(),
            MenuAction::Paste => self.run_command(Command::Paste).await?,
            MenuAction::ShowQr => self.show_qr_code(),
            MenuAction::Rename => self.request_rename(),
            MenuAction::Duplicate => self.duplicate_selection(),
            MenuAction::Delete => match target {
                Some(MenuTarget::Subscription(i)) => self.request_delete_subscription(i),
                _ => self.request_delete(),
            },
            MenuAction::TestLatency => self.refresh_latencies(),
            MenuAction::SelectAll => self.run_command(Command::SelectAll).await?,
            MenuAction::ClearSelection => self.marked.clear(),
            MenuAction::ShowLogs => self.show_logs(),
            MenuAction::RefreshSubscriptions => self.refresh_subscriptions(),
            MenuAction::ImportFromFile => self.run_command(Command::OpenFile).await?,
            MenuAction::ExportSelected => self.run_command(Command::SaveAs).await?,
            MenuAction::NewProfile => self.run_command(Command::NewProfile).await?,
            MenuAction::ApplyEndpoint => {
                if let Some(MenuTarget::ScannerResult(i)) = target {
                    self.apply_scanner_endpoint(i).await?;
                }
            }
            MenuAction::Settings => self.active_tab = ActiveTab::Settings,
            MenuAction::Help => self.run_command(Command::Help).await?,
            MenuAction::SetProxyManual => self.set_system_proxy_mode(SystemProxyMode::Manual).await,
            MenuAction::SetProxyUnmanaged => {
                self.set_system_proxy_mode(SystemProxyMode::Unmanaged).await
            }
            MenuAction::SetProxyPac => self.set_system_proxy_mode(SystemProxyMode::Pac).await,
            MenuAction::SetProxyClear => self.set_system_proxy_mode(SystemProxyMode::Clear).await,
        }
        Ok(())
    }

    /// Delete a subscription, with confirmation.
    fn request_delete_subscription(&mut self, index: usize) {
        let Some(sub) = self.subscriptions.get(index) else {
            return;
        };
        let (id, name) = (sub.id, sub.remark.clone());
        self.modal_state = ModalState::Confirm {
            title: "CONFIRM DELETE".into(),
            message: format!("Delete the feed \"{name}\" and the nodes it added?"),
            action: ConfirmAction::DeleteSubscription(id),
            created_tick: self.effects.current_tick(),
        };
        self.open_modal_effect();
    }

    /// Show the recent log lines.
    fn show_logs(&mut self) {
        let path =
            std::path::PathBuf::from(std::env::var("ZERONET_DATA_DIR").unwrap_or_else(|_| {
                std::env::var("HOME")
                    .map(|h| format!("{h}/.zeronet"))
                    .unwrap_or_default()
            }))
            .join("zeronet.log");

        // Only the end of the file is read: a log left at `debug` for a few
        // days runs to hundreds of megabytes, all of which used to be read
        // into memory on the frame loop to show 200 lines.
        let body = match read_log_tail(&path, 200) {
            Ok(text) => text,
            Err(_) => format!(
                "No log file at {}.\n\nRun with RUST_LOG=info to record one.",
                path.display()
            ),
        };

        self.modal_state = ModalState::TextInput {
            title: "LOGS".into(),
            prompt: "recent log lines".into(),
            buffer: body,
            purpose: TextPurpose::ViewOnly,
            created_tick: self.effects.current_tick(),
            select_all: false,
        };
        self.open_modal_effect();
    }

    /// Update the ticked set from the current rubber band.
    fn apply_drag_selection(&mut self) {
        let Some(drag) = self.drag else {
            return;
        };
        if !drag.is_active() {
            return;
        }

        let first_row = self.node_list_first_row();
        let visible: Vec<i64> = self.visible_configs().iter().map(|c| c.id).collect();
        let swept = {
            let from_interaction = self.interaction.swept_config_items(drag.rect());
            if !from_interaction.is_empty() || self.interaction.has_config_item_regions() {
                from_interaction
            } else {
                dragselect::swept_indices(&drag, first_row, visible.len())
            }
        };

        // A plain drag replaces the selection; Ctrl or Shift adds to it.
        // In desktop software, dragging over 0 items clears the selection.
        if !drag.is_additive() {
            self.marked.clear();
        }
        for i in &swept {
            if let Some(id) = visible.get(*i) {
                self.marked.insert(*id);
            }
        }
        if let Some(&first_idx) = swept.first() {
            self.selected_config_idx = first_idx;
        }
    }

    /// Screen row of the first profile row.
    fn node_list_first_row(&self) -> u16 {
        // header(3) + metrics(5) + orb + filter(1) + panel border(1) + column
        // header(1). The orb's height is what the dashboard layout gives it.
        let orb = self.viewport.1.saturating_sub(3 + 1 + 5 + 9).clamp(9, 19);
        3 + 5 + orb + 1 + 1 + 1
    }

    /// A press on a scrollbar starts a page or a thumb drag.
    ///
    /// Returns whether the bar claimed the gesture.
    fn begin_scrollbar_gesture(&mut self, hit: Option<ComponentId>, x: u16, y: u16) -> bool {
        let Some(ComponentId::Scrollbar { which, part }) = hit else {
            return false;
        };
        let target = match which {
            0 => ScrollTarget::Profiles,
            1 => ScrollTarget::Settings,
            _ => ScrollTarget::Help,
        };
        let Some(region) = self.scrollbar_track(target) else {
            return false;
        };
        let part = match part {
            0 => ScrollPart::TrackUp,
            1 => ScrollPart::Thumb,
            _ => ScrollPart::TrackDown,
        };
        match part {
            ScrollPart::TrackUp => self.page_scroll(target, -1),
            ScrollPart::TrackDown => self.page_scroll(target, 1),
            ScrollPart::Thumb => {
                let grab = y.saturating_sub(self.thumb_top(target, &region));
                self.thumb_drag = Some(ThumbDrag {
                    target,
                    track: region.track,
                    thumb_height: region.thumb_height,
                    grab,
                    max_offset: region.max_offset,
                });
                let _ = x;
            }
        }
        true
    }

    /// Move the list so the grabbed point of the thumb stays under the pointer.
    fn scrub_scrollbar(&mut self, pointer_y: u16) {
        let Some(drag) = self.thumb_drag else {
            return;
        };
        let offset = drag.offset_at(pointer_y);
        match drag.target {
            ScrollTarget::Profiles => {
                let max = self.profile_max_offset();
                self.node_scroll = offset.min(max);
            }
            ScrollTarget::Settings => self.settings_scroll.step(offset as i32, offset),
            ScrollTarget::Help => self.help_scroll.step(offset as i32, offset),
        }
    }

    /// Page the list by roughly one viewport.
    fn page_scroll(&mut self, target: ScrollTarget, sign: i32) {
        match target {
            ScrollTarget::Profiles => {
                let page = self.profile_viewport().max(1) as i32;
                let max = self.profile_max_offset();
                let next = (self.node_scroll as i32 + sign * page).clamp(0, max as i32);
                self.node_scroll = next as usize;
            }
            ScrollTarget::Settings => {
                let page = self.settings_rows().max(1) as i32;
                let max = scroll::max_offset(
                    UiRenderer::settings_content_height_for(self.advanced_open),
                    self.settings_rows(),
                );
                self.settings_scroll.step(sign * page, max);
            }
            ScrollTarget::Help => {
                let page = self.help_rows().max(1) as i32;
                let max = scroll::max_offset(UiRenderer::help_content_height(), self.help_rows());
                self.help_scroll.step(sign * page, max);
            }
        }
    }

    fn profile_viewport(&self) -> usize {
        // Derived from the renderer's own layout, not estimated: an estimate
        // of "height minus 16" overshot by half a screen, so the highlight
        // could walk off the bottom of the list without it scrolling.
        UiRenderer::profile_list_rows(self.viewport.0, self.viewport.1).max(1)
    }

    fn profile_max_offset(&self) -> usize {
        self.visible_configs()
            .len()
            .saturating_sub(self.profile_viewport())
    }

    /// The bar currently on screen for `target`, in the coordinates the last
    /// frame registered. Recomputed rather than stored so a resize cannot
    /// leave a stale rectangle behind.
    fn scrollbar_track(&self, target: ScrollTarget) -> Option<BarGeom> {
        let which = match target {
            ScrollTarget::Profiles => 0,
            ScrollTarget::Settings => 1,
            ScrollTarget::Help => 2,
        };
        let thumb = self
            .interaction
            .region(ComponentId::Scrollbar { which, part: 1 })?;
        let up = self
            .interaction
            .region(ComponentId::Scrollbar { which, part: 0 });
        let down = self
            .interaction
            .region(ComponentId::Scrollbar { which, part: 2 });
        let y = up.map(|r| r.y).unwrap_or(thumb.y);
        let bottom = down
            .map(|r| r.y + r.height)
            .unwrap_or(thumb.y + thumb.height);
        let max_offset = match target {
            ScrollTarget::Profiles => self.profile_max_offset(),
            ScrollTarget::Settings => scroll::max_offset(
                UiRenderer::settings_content_height_for(self.advanced_open),
                self.settings_rows(),
            ),
            ScrollTarget::Help => {
                scroll::max_offset(UiRenderer::help_content_height(), self.help_rows())
            }
        };
        Some(BarGeom {
            track: ratatui::layout::Rect {
                x: thumb.x,
                y,
                width: thumb.width,
                height: bottom.saturating_sub(y),
            },
            thumb_height: thumb.height,
            max_offset,
        })
    }

    fn thumb_top(&self, target: ScrollTarget, geom: &BarGeom) -> u16 {
        let offset = match target {
            ScrollTarget::Profiles => self.node_scroll,
            ScrollTarget::Settings => self.settings_scroll.offset(),
            ScrollTarget::Help => self.help_scroll.offset(),
        };
        let travel = geom.track.height.saturating_sub(geom.thumb_height) as usize;
        if travel == 0 || geom.max_offset == 0 {
            return geom.track.y;
        }
        geom.track.y + ((offset.min(geom.max_offset) * travel) / geom.max_offset) as u16
    }
}

/// Where a scrollbar was drawn last frame.
struct BarGeom {
    track: ratatui::layout::Rect,
    thumb_height: u16,
    max_offset: usize,
}

impl App<'_> {
    /// Route a wheel notch to whatever is under the pointer.
    fn scroll(&mut self, delta: i32) {
        let tick = self.effects.current_tick();

        if let ModalState::Help { .. } = self.modal_state {
            let max = scroll::max_offset(UiRenderer::help_content_height(), self.help_rows());
            self.help_scroll.scroll(delta, max, tick);
            return;
        }
        if self.modal_state.is_active() {
            return;
        }
        if self.active_tab == ActiveTab::Settings {
            let max = scroll::max_offset(
                UiRenderer::settings_content_height_for(self.advanced_open),
                self.settings_rows(),
            );
            self.settings_scroll.scroll(delta, max, tick);
            return;
        }

        // Clamped to the last full page, which is where the renderer stops;
        // clamping further out left dead wheel notches on the way back up.
        let max = self.profile_max_offset();
        // The node list has no rubber band of its own; it is a plain offset.
        let next = (self.node_scroll as i32 + delta.signum()).clamp(0, max as i32);
        self.node_scroll = next as usize;
    }

    /// Rows the help overlay can show, for its scroll bounds.
    ///
    /// Derived from the last drawn terminal size rather than guessed, so the
    /// end of the list is exactly where the content runs out.
    fn help_rows(&self) -> usize {
        UiRenderer::help_viewport_height(self.viewport.1)
    }

    fn settings_rows(&self) -> usize {
        // Header, footer and the panel border.
        (self.viewport.1 as usize).saturating_sub(6).max(4)
    }

    /// Keep the selected row inside the visible window.
    fn follow_selection(&mut self) {
        let rows = self.profile_viewport();
        if self.selected_config_idx < self.node_scroll {
            self.node_scroll = self.selected_config_idx;
        } else if self.selected_config_idx >= self.node_scroll + rows {
            // Moving down past the last visible row scrolls just enough to
            // keep it on screen, like every list widget.
            self.node_scroll = self.selected_config_idx + 1 - rows;
        }
    }

    // ------------------------------------------------- clipboard & share

    /// Everything a bug report needs, copied, with where to send it.
    ///
    /// Nothing leaves the machine on its own: the report goes to the
    /// clipboard and the person decides whether to post it. Server addresses
    /// and keys are deliberately left out.
    fn send_feedback(&mut self) {
        let status = format!("{:?}", self.stats.status);
        let report = format!(
            "ZeroNet {version}\n\
             OS: {os} ({arch})\n\
             Terminal: {caps}\n\
             Theme: {theme}\n\
             Status: {status}{tun}\n\
             Last error: {error}\n\
             Profiles: {profiles}, feeds: {feeds}\n\
             \n\
             What happened:\n\n\
             What you expected:\n",
            version = env!("CARGO_PKG_VERSION"),
            os = std::env::consts::OS,
            arch = std::env::consts::ARCH,
            caps = self.caps.describe(),
            theme = self.theme.id.label(),
            tun = if self.stats.tun_active {
                ", TUN up"
            } else {
                ""
            },
            error = self.stats.error_msg.as_deref().unwrap_or("none"),
            profiles = self.configs.len(),
            feeds = self.subscriptions.len(),
        );
        match self.clipboard.copy(&report) {
            Ok(_) => self.toasts.success(format!(
                "Bug report copied. Paste it into a new issue at {}/issues",
                env!("CARGO_PKG_REPOSITORY")
            )),
            Err(e) => self.toasts.error(format!("Could not copy the report: {e}")),
        }
    }

    /// The Konami code. Unlocks the palette nobody is told about.
    fn on_secret_sequence(&mut self) {
        let first_time = !self.settings.secret_theme_unlocked;
        self.settings.secret_theme_unlocked = true;
        self.apply_theme(zeronet_tui::theme::ThemeId::Phosphor);
        let (w, h) = self.viewport;
        self.effects.trigger_rainbow(w as f64 / 2.0, h as f64 / 2.0);
        if first_time {
            self.toasts
                .success("You found PHOSPHOR. It lives in Settings → Theme now.");
        } else {
            self.toasts.info("Back to 1983.");
        }
    }

    fn copy_to_clipboard(&mut self, text: &str, what: &str) {
        match self.clipboard.copy(text) {
            Ok(CopyRoute::System) => self.toasts.success(format!("{what} copied.")),
            Ok(CopyRoute::TerminalOsc52) => self
                .toasts
                .success(format!("{what} copied via the terminal.")),
            Err(e) => self.toasts.error(format!("Could not copy: {e}")),
        }
    }

    /// Copy the selected profiles as share links.
    ///
    /// One profile copies its link; several copy a base64 subscription body,
    /// which is what other clients expect when importing a set at once.
    fn copy_selection(&mut self) {
        let targets = self.action_targets();
        if targets.is_empty() {
            self.toasts.warning("Nothing selected to copy.");
            return;
        }

        let mut links = Vec::new();
        let mut failures = Vec::new();
        for id in &targets {
            let Some(cfg) = self.config_by_id(*id) else {
                continue;
            };
            match sharelink::share_uri(&cfg.raw_content, &cfg.remark) {
                Ok(share) => links.push(share.uri),
                Err(e) => failures.push(format!("{}: {e}", cfg.remark)),
            }
        }

        if links.is_empty() {
            self.toasts
                .error(failures.first().cloned().unwrap_or_else(|| {
                    "None of the selected profiles can be shared as a link.".into()
                }));
            return;
        }

        if links.len() == 1 {
            let link = links.remove(0);
            self.copy_to_clipboard(&link, "Share link");
        } else {
            let body = sharelink::subscription_body(&links);
            let count = links.len();
            self.copy_to_clipboard(&body, &format!("{count} profiles"));
        }

        if !failures.is_empty() {
            self.toasts.warning(format!(
                "{} couldn't be shared.",
                count(failures.len(), "profile", "profiles")
            ));
        }
    }

    /// Show the selected profile as a QR code.
    fn show_qr_code(&mut self) {
        let Some(id) = self.selected_profile_id() else {
            self.toasts.warning("Select a profile first.");
            return;
        };
        let Some(cfg) = self.config_by_id(id) else {
            return;
        };
        let (remark, raw) = (cfg.remark.clone(), cfg.raw_content.clone());

        let share = match sharelink::share_uri(&raw, &remark) {
            Ok(s) => s,
            Err(e) => {
                self.toasts.error(format!("Cannot build a link: {e}"));
                return;
            }
        };

        // Half-blocks keep the code compact enough to fit an ordinary
        // terminal; a long link at double width would not fit on screen.
        match qr::render(&share.uri, QrStyle::HalfBlock) {
            Ok(code) => {
                self.modal_state = ModalState::ShareConfig {
                    profile: remark,
                    uri: share.uri,
                    code: Box::new(code),
                    created_tick: self.effects.current_tick(),
                };
                self.open_modal_effect();
            }
            Err(e) => self.toasts.error(format!("Cannot render a QR code: {e}")),
        }
    }

    /// Import whatever was pasted: a share link, a subscription blob, a raw
    /// config, or several links at once.
    async fn handle_pasted_text(&mut self, text: &str) -> Result<()> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            self.toasts.warning("Clipboard is empty.");
            return Ok(());
        }

        // Whatever has keyboard focus takes the paste as literal input. With
        // bracketed paste on, this is the only route a terminal paste takes,
        // so a field that is not handled here would import the text as a
        // profile instead of typing it.
        if let Some(rename) = self.inline_rename.as_mut() {
            let line = trimmed.lines().next().unwrap_or_default();
            if rename.select_all {
                rename.buffer.clear();
                rename.cursor = 0;
                rename.select_all = false;
            }
            let cursor = rename.cursor.min(rename.buffer.chars().count());
            let at = rename
                .buffer
                .char_indices()
                .nth(cursor)
                .map_or(rename.buffer.len(), |(i, _)| i);
            rename.buffer.insert_str(at, line);
            rename.cursor = cursor + line.chars().count();
            return Ok(());
        }
        if self.filter_focused {
            if self.filter_select_all {
                self.filter.clear();
                self.filter_select_all = false;
            }
            self.filter
                .push_str(trimmed.lines().next().unwrap_or_default());
            self.clamp_selection();
            return Ok(());
        }
        if self.modal_state.is_active() {
            if !self.modal_accepts_input() {
                return Ok(());
            }
            match &mut self.modal_state {
                ModalState::TextInput {
                    buffer,
                    select_all,
                    purpose,
                    ..
                } => {
                    if *purpose != TextPurpose::ViewOnly {
                        if *select_all {
                            buffer.clear();
                            *select_all = false;
                        }
                        buffer.push_str(trimmed);
                    }
                }
                ModalState::SudoPassword { buffer, error, .. } => {
                    *error = None;
                    buffer.push_str(text.trim_end_matches(['\n', '\r']));
                }
                ModalState::NumberEdit {
                    buffer, select_all, ..
                } => {
                    if *select_all {
                        buffer.clear();
                        *select_all = false;
                    }
                    buffer.extend(trimmed.chars().filter(char::is_ascii_digit));
                }
                ModalState::ManualProfile { form, .. } => {
                    for c in trimmed.chars().filter(|c| !c.is_control()) {
                        push_form_field(form, c);
                    }
                }
                // Other dialogs have nothing to type into; importing behind
                // them would act on something the user cannot see.
                _ => {}
            }
            return Ok(());
        }

        self.import_text(trimmed)?;
        Ok(())
    }

    // ------------------------------------------------ profile management

    fn duplicate_selection(&mut self) {
        let targets = self.action_targets();
        if targets.is_empty() {
            self.toasts.warning("Nothing selected to duplicate.");
            return;
        }
        let mut made = 0;
        for id in targets {
            if self.db.duplicate_config(id).is_ok() {
                made += 1;
            }
        }
        self.reload_configs();
        self.toasts.success(format!(
            "Duplicated {}.",
            count(made, "profile", "profiles")
        ));
    }

    fn request_delete(&mut self) {
        let targets = self.action_targets();
        if targets.is_empty() {
            self.toasts.warning("Nothing selected to delete.");
            return;
        }

        let message = if targets.len() == 1 {
            let name = self
                .config_by_id(targets[0])
                .map(|c| c.remark.clone())
                .unwrap_or_else(|| "this profile".into());
            format!("Delete \"{name}\"?")
        } else {
            format!("Delete {} profiles?", targets.len())
        };

        self.modal_state = ModalState::Confirm {
            title: "CONFIRM DELETE".into(),
            message,
            action: ConfirmAction::DeleteProfiles(targets),
            created_tick: self.effects.current_tick(),
        };
        self.open_modal_effect();
    }

    fn request_rename(&mut self) {
        let Some(id) = self.selected_profile_id() else {
            self.toasts.warning("Select a profile to rename.");
            return;
        };
        let current = self
            .config_by_id(id)
            .map(|c| c.remark.clone())
            .unwrap_or_default();
        let len = current.chars().count();

        self.inline_rename = Some(zeronet_tui::InlineRename {
            config_id: id,
            cursor: len,
            buffer: current,
            select_all: true,
        });
    }

    /// Re-fetch every subscription feed in the background.
    fn refresh_subscriptions(&mut self) {
        if self.subscriptions.is_empty() {
            self.toasts.info("No feeds yet. Ctrl+Shift+S adds one.");
            return;
        }

        let feeds: Vec<(i64, String, String)> = self
            .subscriptions
            .iter()
            .map(|sub| (sub.id, sub.remark.clone(), sub.url.clone()))
            .collect();
        // A feed already being fetched is not fetched a second time: two
        // overlapping refreshes of one feed each replaced its nodes.
        let started = feeds
            .into_iter()
            .filter(|(id, name, url)| self.spawn_feed_fetch(*id, name.clone(), url.clone()))
            .count();
        if started == 0 {
            self.toasts.info("Subscription feeds are already updating…");
        } else {
            self.toasts
                .info(format!("Updating {}…", count(started, "feed", "feeds")));
        }
    }

    /// Apply a fetched feed, replacing exactly the profiles it owns.
    ///
    /// The nodes were compiled in the background; only the one database
    /// transaction happens here.
    fn apply_feed_update(&mut self, update: FeedUpdate) {
        let FeedUpdate { id, name, result } = update;
        self.bg.feeds_in_flight.remove(&id);

        let feed = match result {
            Ok(f) => f,
            Err(e) => {
                self.toasts.error(format!("{name}: {e}"));
                return;
            }
        };

        if feed.rows.is_empty() {
            self.toasts
                .warning(format!("{name}: feed returned no usable nodes."));
            return;
        }

        // Replacing a feed's nodes gives them new ids. The selection and the
        // running profile are carried across by name, or the connection
        // manager would go on pointing at rows that no longer exist — and a
        // later settings change would silently rebuild nothing.
        let carried: Vec<(i64, String)> = [self.connection.selected(), self.connection.dialled()]
            .into_iter()
            .flatten()
            .filter_map(|old| {
                self.config_by_id(old)
                    .filter(|c| c.subscription_id == Some(id))
                    .map(|c| (old, c.remark.clone()))
            })
            .collect();

        match self.db.replace_subscription_configs(id, &feed.rows) {
            Ok(n) => {
                self.reload_configs();
                self.subscriptions = self.db.get_subscriptions().unwrap_or_default();
                for (old, remark) in carried {
                    let new = self
                        .configs
                        .iter()
                        .find(|c| c.subscription_id == Some(id) && c.remark == remark)
                        .map(|c| c.id);
                    if let Some(new) = new {
                        self.connection.on_profile_replaced(old, new);
                    }
                }
                if feed.skipped > 0 {
                    self.toasts.success(format!(
                        "{name}: {n} nodes updated, {} unreadable.",
                        feed.skipped
                    ));
                } else {
                    self.toasts.success(format!("{name}: {n} nodes updated."));
                }
            }
            Err(e) if self.subscriptions.iter().all(|s| s.id != id) => {
                // Deleted while the fetch was in flight; nothing to update.
                tracing::debug!(error = %e, "feed removed during refresh");
            }
            Err(e) => self.toasts.error(format!("{name}: couldn't save ({e})")),
        }
    }

    fn refresh_latencies(&mut self) {
        for cfg in self.configs.iter_mut() {
            cfg.ping_ms = None;
        }
        self.pending_ping_sweep = true;
        self.toasts.info("Re-probing every node…");
    }

    fn export_all_profiles(&mut self) {
        let links: Vec<String> = self
            .configs
            .iter()
            .filter_map(|c| {
                sharelink::share_uri(&c.raw_content, &c.remark)
                    .ok()
                    .map(|s| s.uri)
            })
            .collect();

        if links.is_empty() {
            self.toasts.warning("No shareable profiles to export.");
            return;
        }

        let dir = std::path::PathBuf::from("./zeronet-export");
        if let Err(e) = std::fs::create_dir_all(&dir) {
            self.toasts.error(format!("Cannot create export dir: {e}"));
            return;
        }

        let body = sharelink::subscription_body(&links);
        let writes = [("links.txt", links.join("\n")), ("subscription.txt", body)];
        for (name, content) in writes {
            if let Err(e) = std::fs::write(dir.join(name), content) {
                self.toasts.error(format!("Failed writing {name}: {e}"));
                return;
            }
        }
        self.toasts.success(format!(
            "Exported {} profiles to ./zeronet-export/",
            links.len()
        ));
    }

    fn reload_configs(&mut self) {
        self.configs = self.db.get_configs().unwrap_or_default();
        self.marked
            .retain(|id| self.configs.iter().any(|c| c.id == *id));
        self.clamp_selection();
    }

    fn open_quit_dialog(&mut self) {
        self.modal_state = ModalState::QuitConfirmation {
            created_tick: self.effects.current_tick(),
        };
        self.open_modal_effect();
    }

    fn open_text_modal(&mut self, title: &str, prompt: &str, purpose: TextPurpose) {
        self.modal_state = ModalState::TextInput {
            title: title.into(),
            prompt: prompt.into(),
            buffer: String::new(),
            purpose,
            created_tick: self.effects.current_tick(),
            select_all: false,
        };
        self.open_modal_effect();
    }

    /// Start a dialog's opening animation and its ember burst.
    ///
    /// Called from every place that sets `modal_state`, which is what
    /// guarantees no dialog can appear without animating in.
    fn open_modal_effect(&mut self) {
        // A dialog takes the keyboard. Leaving the filter focused sent every
        // keystroke to the search box instead — which is why pasting a
        // subscription URL appeared to do nothing.
        self.filter_focused = false;
        self.context_menu = None;
        self.modal_anim = ModalAnimator::opening(self.effects.current_tick());
        let area = ratatui::layout::Rect {
            x: 0,
            y: 0,
            width: 60,
            height: 18,
        };
        self.effects.emit_ashes_burst(area, 24);
    }

    /// Dismiss the dialog on screen, with its closing animation.
    ///
    /// Replaces the assignments that used to set `ModalState::None` directly:
    /// those made the dialog vanish between frames, which reads as a glitch.
    fn close_modal(&mut self) {
        if !self.modal_state.is_active() {
            return;
        }
        self.modal_anim.begin_close(self.effects.current_tick());
    }

    /// Handle a click on the dimmed area outside the dialog.
    fn on_backdrop_click(&mut self) {
        if self.modal_state.dismiss_on_backdrop() {
            self.close_modal();
        } else {
            // The manual form holds typed input; flash rather than discard.
            self.modal_anim.nudge(self.effects.current_tick());
            self.toasts.info("Press Esc or [✕] to discard this form.");
        }
    }

    /// Drop a dialog whose closing animation has finished, and promote a
    /// finished opening to the settled state.
    fn advance_modal_animation(&mut self) {
        let tick = self.effects.current_tick();
        self.modal_anim.settle(tick);
        if self.modal_state.is_active() && !self.modal_anim.is_visible(tick) {
            self.modal_state = ModalState::None;
            self.image_view = None;
        }
    }

    /// Enter pressed on a dialog.
    async fn confirm_modal(&mut self) -> Result<()> {
        match &self.modal_state {
            ModalState::QuitConfirmation { .. } => self.should_quit = true,
            ModalState::Update { .. } => self.update_primary(),
            ModalState::AshesWarning { .. }
            | ModalState::Help { .. }
            | ModalState::ShareConfig { .. } => self.close_modal(),
            ModalState::ImageView { findings, .. } => {
                let findings = findings.clone();
                self.close_modal();
                self.import_scanned(&findings);
            }
            ModalState::Confirm { action, .. } => {
                let action = action.clone();
                self.close_modal();
                self.perform_confirmed(action).await?;
            }
            ModalState::ManualProfile { .. } => self.save_manual_profile().await?,
            ModalState::SudoPassword { .. } => self.submit_sudo_password().await?,
            ModalState::TextInput { buffer, .. } => {
                let text = buffer.trim().to_string();
                self.submit_text_modal(&text).await?;
            }
            ModalState::NumberEdit {
                setting_key,
                min,
                max,
                buffer,
                ..
            } => {
                let (key, min, max, value) =
                    (setting_key.clone(), *min, *max, buffer.parse::<u64>().ok());
                self.commit_number(&key, min, max, value).await?;
            }
            ModalState::None => {}
        }
        Ok(())
    }

    async fn perform_confirmed(&mut self, action: ConfirmAction) -> Result<()> {
        match action {
            ConfirmAction::DeleteProfiles(ids) => {
                // Deleting the profile in use has to take the tunnel down
                // with it, or the client would keep proxying through a node
                // the user can no longer see.
                let mut engine_action = EngineAction::None;
                for id in &ids {
                    let a = self.connection.on_profile_removed(*id);
                    if a != EngineAction::None {
                        engine_action = a;
                    }
                }

                match self.db.delete_configs(&ids) {
                    Ok(n) => {
                        self.marked.clear();
                        self.reload_configs();
                        self.toasts
                            .success(format!("Deleted {}.", count(n, "profile", "profiles")));
                    }
                    Err(e) => self.toasts.error(format!("Delete failed: {e}")),
                }
                self.apply_engine_action(engine_action).await?;
            }
            ConfirmAction::DeleteSubscription(id) => {
                let _ = self.db.delete_subscription(id);
                self.subscriptions = self.db.get_subscriptions().unwrap_or_default();
                self.reload_configs();
                self.toasts.success("Subscription removed.");
            }
        }
        Ok(())
    }

    async fn commit_number(
        &mut self,
        key: &str,
        min: u64,
        max: u64,
        value: Option<u64>,
    ) -> Result<()> {
        match value {
            Some(v) if (min..=max).contains(&v) => {
                apply_number_setting(key, v, &mut self.settings);
                self.persist_settings();
                self.toasts.success(format!("{key} set to {v}"));
                self.close_modal();
                // Ports, MTU and the evasion knobs are engine parameters; a
                // live tunnel has to be rebuilt for the new value to take
                // effect.
                if matches!(
                    key,
                    "socks_port"
                        | "http_port"
                        | "tun_mtu"
                        | "mux_concurrency"
                        | "tls_fragment_size"
                        | "keepalive_interval_secs"
                ) {
                    self.reapply_engine_settings().await?;
                }
            }
            Some(v) => {
                self.modal_state = ModalState::AshesWarning {
                    title: "LIMIT VIOLATION".into(),
                    message: format!("{v} is outside the allowed range {min}–{max}."),
                    created_tick: self.effects.current_tick(),
                };
            }
            None => {
                self.modal_state = ModalState::AshesWarning {
                    title: "LIMIT VIOLATION".into(),
                    message: format!("Enter a whole number between {min} and {max}."),
                    created_tick: self.effects.current_tick(),
                };
            }
        }
        Ok(())
    }

    async fn save_manual_profile(&mut self) -> Result<()> {
        let ModalState::ManualProfile { form, .. } = &self.modal_state else {
            return Ok(());
        };
        match form.to_json() {
            Ok(json) => {
                let remark = form.remark.clone();
                let proto = PROTOCOLS[form.protocol_idx % PROTOCOLS.len()].to_string();
                let (addr, port) = (form.address.clone(), form.port);

                let id = self
                    .db
                    .insert_config(&remark, &proto, &addr, port, &json, None)?;
                self.reload_configs();
                self.close_modal();

                // Creating a profile selects it. Whether that connects is up
                // to the current intent, not to the act of creating it.
                self.select_profile(id).await?;
                self.toasts.success(format!("Created {remark}"));
            }
            Err(e) => self.toasts.error(format!("Profile invalid: {e}")),
        }
        Ok(())
    }

    async fn submit_text_modal(&mut self, text: &str) -> Result<()> {
        let ModalState::TextInput { purpose, .. } = &self.modal_state else {
            return Ok(());
        };
        let purpose = purpose.clone();

        // Only the DNS field is meaningfully clearable; everything else
        // treats an empty submission as a cancel.
        // A blank submission is a cancel, except where blank is itself a
        // meaningful value — "no custom DNS", "rotate the known SNIs".
        let blank_is_a_value = matches!(purpose, TextPurpose::CustomDns | TextPurpose::ScannerSni);
        if text.is_empty() && !blank_is_a_value {
            self.close_modal();
            return Ok(());
        }

        self.close_modal();

        match purpose {
            TextPurpose::Feedback => match self.db.insert_feedback(None, text) {
                Ok(_) => self.toasts.success("Saved. Thanks for writing it down."),
                Err(e) => self.toasts.error(format!("Couldn't save that: {e}")),
            },
            TextPurpose::AddSubscription => match self.db.insert_subscription("Sub Feed", text) {
                Ok(id) => {
                    self.subscriptions = self.db.get_subscriptions().unwrap_or_default();
                    // Fetched straight away: a feed that shows no nodes until
                    // the user finds the refresh control looks broken.
                    self.spawn_feed_fetch(id, "Sub Feed".to_string(), text.to_string());
                    self.toasts.success("Feed saved. Fetching its servers…");
                }
                Err(e) => self.toasts.error(format!("Could not save the feed: {e}")),
            },
            TextPurpose::CustomDns => {
                // Validated here rather than at connect time: a resolver the
                // engine cannot parse would fail the whole config, hours and
                // many screens away from the typo.
                let value = text.trim();
                if value.is_empty() || zero_config::dns::ResolverEndpoint::parse(value).is_some() {
                    self.settings.custom_dns = value.to_string();
                    self.persist_settings();
                    self.toasts.success(if value.is_empty() {
                        "Custom DNS cleared. Back to the preset's resolvers.".to_string()
                    } else {
                        format!("Custom DNS: {value}")
                    });
                    self.reapply_engine_settings().await?;
                } else {
                    self.toasts.error(
                        "That isn't a resolver. Try 9.9.9.9 or https://dns.google/dns-query.",
                    );
                }
            }
            TextPurpose::ImportConfig => {
                self.import_text(text)?;
            }
            TextPurpose::RenameProfile(id) => match self.db.rename_config(id, text) {
                Ok(()) => {
                    self.reload_configs();
                    self.toasts.success(format!("Renamed to {text}"));
                }
                Err(e) => self.toasts.error(format!("Rename failed: {e}")),
            },
            // Read-only text has nothing to submit.
            TextPurpose::ViewOnly => {}
            TextPurpose::TunDeviceName => {
                // An interface name the kernel will not accept would fail at
                // connect time, long after the typo was made.
                let name = text.trim();
                let acceptable = (1..=15).contains(&name.len())
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
                if acceptable {
                    self.settings.tun_device_name = name.to_string();
                    self.persist_settings();
                    self.toasts.success(format!("TUN device: {name}"));
                    self.reapply_engine_settings().await?;
                } else {
                    self.toasts
                        .error("Device name must be 1–15 letters, digits, '-' or '_'.");
                }
            }
            TextPurpose::ScannerSni => {
                self.settings.scanner_sni = text.to_string();
                self.persist_settings();
                self.toasts.success(if text.is_empty() {
                    "Probe SNI: rotating known edge names.".to_string()
                } else {
                    format!("Probe SNI: {text}")
                });
            }
            TextPurpose::ScannerWsPath => {
                // A path the server never sees is a path that always fails
                // the upgrade, and a leading slash is the easiest thing to
                // leave off.
                let path = if text.starts_with('/') {
                    text.to_string()
                } else {
                    format!("/{text}")
                };
                self.settings.scanner_ws_path = path.clone();
                self.persist_settings();
                self.toasts.success(format!("WebSocket path: {path}"));
            }
            TextPurpose::ScanImagePath => self.scan_qr_image(text),
            TextPurpose::ImportFilePath => self.import_from_file(text),
            TextPurpose::ExportFilePath => self.export_to_file(text),
        }
        Ok(())
    }

    /// Read a QR image, show it, and offer to import what it holds.
    ///
    /// Showing the picture matters when nothing is found: the user can see
    /// at once whether they opened the wrong file or the code is unreadable.
    fn scan_qr_image(&mut self, path: &str) {
        let path = std::path::PathBuf::from(shellexpand(path));

        let scan = qr::scan_file(&path);
        let findings = match &scan {
            Ok(result) => qr::config_payloads(result),
            Err(_) => Vec::new(),
        };

        // Load the picture for display; a terminal that cannot show images
        // still gets the scan result.
        self.image_view = self.images.load(&path).ok();

        if self.image_view.is_some() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string());
            self.modal_state = ModalState::ImageView {
                title: format!("SCAN · {name}"),
                findings: findings.clone(),
                created_tick: self.effects.current_tick(),
            };
            self.open_modal_effect();
        }

        match scan {
            Err(e) => self.toasts.error(e),
            Ok(result) if findings.is_empty() => self.toasts.warning(format!(
                "Read {}, but none held a config.",
                count(result.payloads.len(), "QR code", "QR codes")
            )),
            Ok(_) => {
                // With a dialog up the import waits for Enter; without one it
                // is the only thing the user asked for, so do it now.
                if self.image_view.is_none() {
                    self.import_scanned(&findings);
                }
            }
        }
    }

    fn import_scanned(&mut self, findings: &[String]) {
        if findings.is_empty() {
            return;
        }
        let joined = findings.join("\n");
        if let Err(e) = self.import_text(&joined) {
            self.toasts.error(format!("Import failed: {e}"));
        }
    }

    /// Import a config, subscription, or QR image from a file on disk.
    fn import_from_file(&mut self, path: &str) {
        let path = std::path::PathBuf::from(shellexpand(path));

        // An image is decoded as a QR; anything else is read as text. The
        // extension is only a hint, so a mis-named image still falls through
        // to the text path rather than failing outright.
        let is_image = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| {
                matches!(
                    e.to_ascii_lowercase().as_str(),
                    "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp"
                )
            })
            .unwrap_or(false);

        if is_image {
            self.scan_qr_image(path.to_string_lossy().as_ref());
            return;
        }

        match std::fs::read_to_string(&path) {
            Ok(text) => {
                if let Err(e) = self.import_text(&text) {
                    self.toasts.error(format!("Import failed: {e}"));
                }
            }
            Err(e) => self
                .toasts
                .error(format!("Cannot read {}: {e}", path.display())),
        }
    }

    fn export_to_file(&mut self, path: &str) {
        let targets = self.action_targets();
        if targets.is_empty() {
            self.toasts.warning("Nothing selected to export.");
            return;
        }
        let links: Vec<String> = targets
            .iter()
            .filter_map(|id| self.config_by_id(*id))
            .filter_map(|c| {
                sharelink::share_uri(&c.raw_content, &c.remark)
                    .ok()
                    .map(|s| s.uri)
            })
            .collect();

        if links.is_empty() {
            self.toasts.error("Selected profiles cannot be shared.");
            return;
        }

        let path = std::path::PathBuf::from(shellexpand(path));
        match std::fs::write(&path, links.join("\n")) {
            Ok(()) => self.toasts.success(format!(
                "Wrote {} to {}",
                count(links.len(), "link", "links"),
                path.display()
            )),
            Err(e) => self.toasts.error(format!("Write failed: {e}")),
        }
    }

    /// Import one or more configs from arbitrary text.
    ///
    /// Handles a single share link, several links at once, a base64
    /// subscription body, and a raw Xray JSON config — because all four are
    /// things people actually paste.
    fn import_text(&mut self, text: &str) -> Result<()> {
        let trimmed = text.trim();

        // Raw JSON config.
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let json = serde_json::to_string_pretty(&value)?;
                // Verify it before storing. A profile that cannot compile
                // used to sit in the list looking normal and only fail at
                // connect time, with a raw engine message.
                if let Err(reason) =
                    zeronet_tui::daemon::validate_profile(&json, &self.engine_options())
                {
                    self.toasts
                        .error(format!("That config will not run: {reason}"));
                    return Ok(());
                }
                let id = self.db.insert_config(
                    "Imported JSON Profile",
                    "custom",
                    "proxy",
                    443,
                    &json,
                    None,
                )?;
                self.reload_configs();
                self.focus_profile(id);
                self.toasts.success("Imported a raw JSON profile.");
                return Ok(());
            }
        }

        // One or many share links, plain or base64-wrapped.
        let parsed = zero_config::parse_subscription(trimmed);
        if parsed.is_empty() {
            self.toasts.error("Nothing importable in that text.");
            return Ok(());
        }

        let mut imported = Vec::new();
        let mut failures = 0usize;
        for entry in parsed {
            match entry {
                Ok(link) => match self.store_share_link(&link) {
                    Ok(id) => imported.push(id),
                    Err(_) => failures += 1,
                },
                Err(_) => failures += 1,
            }
        }

        if imported.is_empty() {
            self.toasts
                .error(format!("Could not import any of {failures} entries."));
            return Ok(());
        }

        self.reload_configs();
        if let Some(first) = imported.first() {
            self.focus_profile(*first);
        }

        if failures == 0 {
            self.toasts.success(format!(
                "Imported {}.",
                count(imported.len(), "profile", "profiles")
            ));
        } else {
            self.toasts.success(format!(
                "Imported {}, skipped {failures} unreadable.",
                imported.len()
            ));
        }
        Ok(())
    }

    /// Turn a parsed share link into a stored profile.
    fn store_share_link(&self, link: &zero_config::ShareLink) -> Result<i64> {
        let proto_name = link.outbound.protocol.name().to_string();
        let preset = zero_config::IranPreset {
            outbounds: zero_config::presets::outbounds_from_links([link.link.as_str()]),
            socks_port: self.settings.socks_port,
            http_port: Some(self.settings.http_port),
            remote_dns: zero_config::RemoteDns::parse(&self.settings.remote_dns)
                .unwrap_or(zero_config::RemoteDns::Google),
            // The local resolver is engine policy, not a profile setting —
            // see the DNS gap noted in `daemon.rs`. Until it is wired, every
            // import gets the same one rather than reading a setting that
            // goes nowhere.
            local_dns: zero_config::LocalDns::Google,
            anti_sanction_dns: zero_config::AntiSanctionDns::parse(&self.settings.anti_sanction)
                .unwrap_or(zero_config::AntiSanctionDns::Shecan),
            manage_assets: false,
            ..zero_config::IranPreset::default()
        };
        let json = serde_json::to_string_pretty(&preset.build())?;

        let remark = if link.remark.trim().is_empty() {
            format!("{}-Node", proto_name.to_uppercase())
        } else {
            link.remark.clone()
        };
        // Reject anything that would not actually run, with the reason.
        zeronet_tui::daemon::validate_profile(&json, &self.engine_options())
            .map_err(|reason| anyhow::anyhow!("{remark}: {reason}"))?;

        let (address, port) = endpoint_of(&link.outbound.protocol);
        Ok(self
            .db
            .insert_config(&remark, &proto_name, &address, port, &json, None)?)
    }

    /// Highlight a profile by id without changing the connection.
    fn focus_profile(&mut self, id: i64) {
        if let Some(idx) = self.visible_configs().iter().position(|c| c.id == id) {
            self.selected_config_idx = idx;
            self.follow_selection();
        }
        if !self.connection.wants_connection() {
            self.connection.select(id);
        }
    }

    async fn on_click(
        &mut self,
        hit: ComponentId,
        x: u16,
        y: u16,
        modifiers: KeyModifiers,
    ) -> Result<()> {
        if self.modal_state.is_active() && !self.modal_accepts_input() {
            return Ok(());
        }

        // A menu entry acts; a click anywhere else closes the menu first and
        // then does whatever it would normally do.
        if self.context_menu.is_some() {
            if let ComponentId::ContextMenuItem(i) = hit {
                let action = self
                    .context_menu
                    .as_ref()
                    .and_then(|m| match m.items.get(i) {
                        Some(zeronet_tui::ctxmenu::MenuItem::Action(a)) => Some(*a),
                        _ => None,
                    });
                if let Some(action) = action {
                    self.run_menu_action(action).await?;
                }
                return Ok(());
            }
            self.close_context_menu();
            return Ok(());
        }

        // Clicking anything other than the filter box gives focus back to the
        // list. This is what stopped a pasted subscription URL from landing
        // in the search field.
        if hit != ComponentId::FilterBox {
            self.filter_focused = false;
        }

        // Clicking any component outside the config items deselects any selected
        // configs, matching Windows / Linux / macOS desktop behavior.
        if !matches!(
            hit,
            ComponentId::ConfigItem(_) | ComponentId::ConfigShare(_)
        ) {
            self.marked.clear();
        }

        match hit {
            ComponentId::LogoButton => {
                // The wave starts from the cell the user actually clicked, so
                // it reads as the click causing it.
                self.effects.trigger_rainbow(x as f64, y as f64);
            }
            ComponentId::NavDashboard => self.active_tab = ActiveTab::Dashboard,
            ComponentId::NavSubscriptions => self.active_tab = ActiveTab::Subscriptions,
            ComponentId::NavScanner => self.active_tab = ActiveTab::IpScanner,
            ComponentId::NavSettings => self.active_tab = ActiveTab::Settings,
            ComponentId::NavActivity | ComponentId::FooterUsage => {
                self.active_tab = ActiveTab::Activity;
            }
            ComponentId::ActivitySortCpu => {
                self.activity_sort = zeronet_tui::ui_activity::ActivitySort::Cpu;
            }
            ComponentId::ActivitySortMemory => {
                self.activity_sort = zeronet_tui::ui_activity::ActivitySort::Memory;
            }

            ComponentId::ConnectButton | ComponentId::FooterConnect => {
                self.toggle_connection().await?
            }

            ComponentId::ConfigItem(idx) => {
                let visible_ids: Vec<i64> = self.visible_configs().iter().map(|c| c.id).collect();
                if let Some(&cfg_id) = visible_ids.get(idx) {
                    let ctrl = modifiers.contains(KeyModifiers::CONTROL);
                    let shift = modifiers.contains(KeyModifiers::SHIFT);

                    if ctrl {
                        // Desktop Ctrl+Click: toggle this item in the multi-selection
                        if self.marked.is_empty() {
                            if let Some(&prev_id) = visible_ids.get(self.selected_config_idx) {
                                self.marked.insert(prev_id);
                            }
                        }
                        if !self.marked.remove(&cfg_id) {
                            self.marked.insert(cfg_id);
                        }
                        self.selected_config_idx = idx;
                        self.selection_tick = self.effects.current_tick();
                        self.follow_selection();
                    } else if shift {
                        // Desktop Shift+Click: range selection from anchor to clicked item
                        let anchor = self.selected_config_idx;
                        let start = anchor.min(idx);
                        let end = anchor.max(idx);
                        self.marked.clear();
                        for i in start..=end {
                            if let Some(&id) = visible_ids.get(i) {
                                self.marked.insert(id);
                            }
                        }
                        self.selected_config_idx = idx;
                        self.selection_tick = self.effects.current_tick();
                        self.follow_selection();
                    } else {
                        // Desktop plain click: deselect all others, select only this item!
                        self.marked.clear();
                        self.select_profile(cfg_id).await?;
                    }
                }
            }

            ComponentId::TunToggle | ComponentId::SettingTunToggle => {
                self.settings.tun_enabled = !self.settings.tun_enabled;
                self.persist_settings();
                if self.settings.tun_enabled {
                    // Switching TUN on is a fresh request, so an earlier
                    // "proxy only" no longer stands: the dialog is offered
                    // again rather than the toggle quietly doing nothing.
                    self.elevation_declined = false;
                    // No `sudo -n` probe here: it is a subprocess on the
                    // frame loop, and the connect path asks the real question
                    // in the background anyway.
                    if self.is_elevated || self.elevator == elevate::Elevator::NotNeeded {
                        self.toasts.info("TUN on");
                    } else if self.elevator.can_prompt() {
                        self.toasts
                            .info("TUN on. You'll be asked for your password if sudo needs it.");
                    } else if self.elevator == elevate::Elevator::Doas {
                        self.toasts.info(
                            "TUN on. doas will be used if it allows this without a password.",
                        );
                    } else {
                        self.toasts.warning(
                            "TUN on, but no sudo was found: this will fall back to proxy mode.",
                        );
                    }
                } else {
                    self.release_privileged_tun();
                    self.toasts.info("TUN off");
                }
                // TUN is part of the engine config, so a live connection has
                // to be rebuilt for the change to mean anything — and an
                // offline one must stay offline.
                self.reapply_engine_settings().await?;
            }

            ComponentId::SystemProxyChip => {
                self.open_proxy_menu(x, y);
            }
            ComponentId::SettingSystemProxyCycle => {
                self.cycle_system_proxy().await;
            }

            ComponentId::SettingAdvancedToggle => {
                self.advanced_open = !self.advanced_open;
            }
            ComponentId::SettingAnimationsToggle => {
                let enabled = !self.effects.animations_enabled();
                self.effects.set_animations_enabled(enabled);
                self.caps.animations = enabled;
                self.settings.animations = enabled;
                self.persist_settings();
            }
            ComponentId::SettingThemeCycle => {
                let next = self.theme.id.next(self.settings.secret_theme_unlocked);
                self.apply_theme(next);
            }
            ComponentId::SettingUsageToggle => {
                self.settings.show_usage = !self.settings.show_usage;
                self.persist_settings();
            }

            ComponentId::FeedbackButton | ComponentId::FooterFeedback => self.send_feedback(),
            ComponentId::AddConfigButton | ComponentId::FooterAddConfig => self.open_text_modal(
                "Import Config",
                "Paste a share link (vless://…) or raw JSON",
                TextPurpose::ImportConfig,
            ),
            ComponentId::AddSubButton | ComponentId::FooterAddSub => self.open_text_modal(
                "Add Subscription Feed",
                "Enter the feed URL",
                TextPurpose::AddSubscription,
            ),
            ComponentId::AddManualConfigButton => {
                self.modal_state = ModalState::ManualProfile {
                    form: ManualProfileForm::new(),
                    editing_text: false,
                    input_buffer: String::new(),
                    created_tick: self.effects.current_tick(),
                };
                self.open_modal_effect();
            }
            ComponentId::RefreshSubsButton => self.refresh_subscriptions(),

            ComponentId::RunScannerButton => self.toggle_scanner(),
            ComponentId::ExportScannerButton => self.export_scanner_results(),
            ComponentId::ScannerItem(idx) => self.apply_scanner_endpoint(idx).await?,

            ComponentId::FooterTab => self.active_tab = next_tab(self.active_tab),
            ComponentId::FooterShowQr => self.show_qr_code(),
            ComponentId::FooterFind => {
                self.filter_focused = true;
                self.active_tab = ActiveTab::Dashboard;
            }
            ComponentId::FooterHelp => {
                self.modal_state = ModalState::Help {
                    scroll: 0,
                    created_tick: self.effects.current_tick(),
                };
                self.open_modal_effect();
            }
            ComponentId::FooterQuit => {
                self.modal_state = ModalState::QuitConfirmation {
                    created_tick: self.effects.current_tick(),
                };
                self.open_modal_effect();
            }
            ComponentId::QuitConfirmYes => self.confirm_modal().await?,
            ComponentId::UpdatePrimary => self.update_primary(),
            ComponentId::SudoConfirm => self.submit_sudo_password().await?,
            ComponentId::SudoCancel => self.cancel_sudo_dialog().await?,

            ComponentId::QuitConfirmNo
            | ComponentId::ModalCancel
            | ComponentId::NumberInputCancel
            | ComponentId::AshesWarningDismiss
            | ComponentId::ManualFormCancel
            | ComponentId::UpdateSecondary
            | ComponentId::ModalClose => self.close_modal(),

            ComponentId::ModalBackdrop => self.on_backdrop_click(),

            ComponentId::ShareCopyLink => {
                if let ModalState::ShareConfig { uri, .. } = &self.modal_state {
                    let uri = uri.clone();
                    self.copy_to_clipboard(&uri, "Share link");
                }
            }
            ComponentId::ShareCopySubscription => {
                if let ModalState::ShareConfig { uri, .. } = &self.modal_state {
                    // A base64 subscription body is what another client
                    // expects when importing by URL rather than by link.
                    let body = sharelink::subscription_body(std::slice::from_ref(uri));
                    self.copy_to_clipboard(&body, "Subscription body");
                }
            }

            ComponentId::FilterBox => {
                self.filter_focused = true;
            }

            ComponentId::ConfigShare(idx) => {
                // Share the row that was clicked, deselecting previous bulk selections.
                self.marked.clear();
                if let Some(id) = self.visible_configs().get(idx).map(|c| c.id) {
                    self.selected_config_idx = idx;
                    self.selection_tick = self.effects.current_tick();
                    self.connection.select(id);
                }
                self.show_qr_code();
            }

            // The dialog's own body: inert, but it must absorb the click so
            // it is not read as a click on the backdrop.
            ComponentId::ModalSurface => {}

            ComponentId::ToastClose(idx) => self.toasts.dismiss(idx),
            ComponentId::ToastMute(idx) => {
                if self.toasts.mute(idx) {
                    self.settings.muted_notices = self.toasts.muted().collect::<Vec<_>>().join(",");
                    self.persist_settings();
                }
            }
            ComponentId::SettingCheckUpdates => self.check_for_update(true),
            ComponentId::SettingAutoUpdateToggle => {
                self.settings.auto_update_check = !self.settings.auto_update_check;
                self.persist_settings();
            }
            ComponentId::SettingMutedNotices => {
                if !self.settings.muted_notices.is_empty() {
                    self.settings.muted_notices.clear();
                    self.toasts.set_muted(Vec::<String>::new());
                    self.persist_settings();
                    self.toasts.info("Muted notices will show again.");
                }
            }

            ComponentId::ModalConfirm => {
                if let ModalState::TextInput { buffer, .. } = &self.modal_state {
                    let text = buffer.trim().to_string();
                    self.submit_text_modal(&text).await?;
                }
            }
            ComponentId::NumberInputConfirm => {
                if let ModalState::NumberEdit {
                    setting_key,
                    min,
                    max,
                    buffer,
                    ..
                } = &self.modal_state
                {
                    let (key, min, max, value) =
                        (setting_key.clone(), *min, *max, buffer.parse::<u64>().ok());
                    self.commit_number(&key, min, max, value).await?;
                }
            }
            ComponentId::ManualFormSave => self.save_manual_profile().await?,
            ComponentId::ManualField(idx) => {
                if let ModalState::ManualProfile { form, .. } = &mut self.modal_state {
                    form.focused_field = idx;
                    cycle_form_field(form);
                }
            }

            other => self.on_setting_click(other).await?,
        }
        Ok(())
    }

    /// Numeric and cycling settings rows.
    ///
    /// Async because most of these are engine settings, and a setting that
    /// only takes effect after a manual reconnect is a setting the user
    /// reasonably believes is broken — so anything the engine reads is
    /// re-applied to a live connection straight away.
    async fn on_setting_click(&mut self, hit: ComponentId) -> Result<()> {
        let tick = self.effects.current_tick();
        let number =
            |title: &str, key: &str, min: u64, max: u64, current: u64| ModalState::NumberEdit {
                title: title.into(),
                setting_key: key.into(),
                min,
                max,
                buffer: current.to_string(),
                created_tick: tick,
                select_all: true,
            };

        match hit {
            ComponentId::SettingTunMtu => {
                self.modal_state = number(
                    "TUN Device MTU",
                    "tun_mtu",
                    576,
                    9000,
                    self.settings.tun_mtu as u64,
                )
            }
            ComponentId::SettingSocksPort => {
                self.modal_state = number(
                    "SOCKS5 Port",
                    "socks_port",
                    1024,
                    65535,
                    self.settings.socks_port as u64,
                )
            }
            ComponentId::SettingHttpPort => {
                self.modal_state = number(
                    "HTTP Proxy Port",
                    "http_port",
                    1024,
                    65535,
                    self.settings.http_port as u64,
                )
            }
            ComponentId::SettingFragmentValue => {
                self.modal_state = number(
                    "TLS Fragment Size",
                    "tls_fragment_size",
                    20,
                    1500,
                    self.settings.tls_fragment_size as u64,
                )
            }
            ComponentId::SettingJitterValue => {
                self.modal_state = number(
                    "Jitter Delay (ms)",
                    "jitter_delay_ms",
                    1,
                    200,
                    self.settings.jitter_delay_ms,
                )
            }
            ComponentId::SettingConcurrencyValue => {
                self.modal_state = number(
                    "Scanner Workers",
                    "scanner_concurrency",
                    1,
                    1000,
                    self.settings.scanner_concurrency as u64,
                )
            }
            ComponentId::SettingMuxConcurrency => {
                self.modal_state = number(
                    "Mux Streams",
                    "mux_concurrency",
                    1,
                    128,
                    self.settings.mux_concurrency as u64,
                )
            }
            ComponentId::SettingKeepaliveSecs => {
                self.modal_state = number(
                    "Keepalive (seconds, 0 = off)",
                    "keepalive_interval_secs",
                    0,
                    300,
                    self.settings.keepalive_interval_secs,
                )
            }
            ComponentId::SettingSubUpdateHours => {
                self.modal_state = number(
                    "Sub Auto-Update (hours)",
                    "sub_update_interval_hours",
                    1,
                    168,
                    self.settings.sub_update_interval_hours as u64,
                )
            }
            ComponentId::SettingPacPort => {
                self.modal_state = number(
                    "PAC Server Port",
                    "pac_port",
                    1024,
                    65535,
                    self.settings.pac_port as u64,
                )
            }
            ComponentId::SettingScannerPort => {
                self.modal_state = number(
                    "Scanner Probe Port",
                    "scanner_port",
                    1,
                    65535,
                    self.settings.scanner_port as u64,
                )
            }
            ComponentId::SettingScannerTries => {
                self.modal_state = number(
                    "Probes per IP",
                    "scanner_tries",
                    1,
                    20,
                    self.settings.scanner_tries as u64,
                )
            }
            ComponentId::SettingScannerTimeout => {
                self.modal_state = number(
                    "Probe Timeout (seconds)",
                    "scanner_timeout_secs",
                    1,
                    30,
                    self.settings.scanner_timeout_secs,
                )
            }
            ComponentId::SettingScannerTargetCount => {
                self.modal_state = number(
                    "Candidates to test (0 = until stopped)",
                    "scanner_target_count",
                    0,
                    1_000_000,
                    self.settings.scanner_target_count as u64,
                )
            }
            ComponentId::SettingScannerSpeedBytes => {
                self.modal_state = number(
                    "Speed sample bytes (0 = skip)",
                    "scanner_speed_bytes",
                    0,
                    16_777_216,
                    self.settings.scanner_speed_bytes as u64,
                )
            }
            ComponentId::SettingTunDeviceName => {
                self.modal_state = ModalState::TextInput {
                    title: "TUN Device Name".into(),
                    prompt: "Interface name (letters, digits, - or _)".into(),
                    buffer: self.settings.tun_device_name.clone(),
                    purpose: TextPurpose::TunDeviceName,
                    created_tick: tick,
                    select_all: true,
                };
            }
            ComponentId::SettingScannerSni => {
                self.modal_state = ModalState::TextInput {
                    title: "Probe SNI".into(),
                    prompt: "TLS server name to present (blank rotates known edge names)".into(),
                    buffer: self.settings.scanner_sni.clone(),
                    purpose: TextPurpose::ScannerSni,
                    created_tick: tick,
                    select_all: true,
                };
            }
            ComponentId::SettingScannerWsPath => {
                self.modal_state = ModalState::TextInput {
                    title: "WebSocket Path".into(),
                    prompt: "Path to upgrade on, e.g. /ws".into(),
                    buffer: self.settings.scanner_ws_path.clone(),
                    purpose: TextPurpose::ScannerWsPath,
                    created_tick: tick,
                    select_all: true,
                };
            }
            ComponentId::SettingCustomDns => {
                self.modal_state = ModalState::TextInput {
                    title: "Custom Remote DNS".into(),
                    prompt: "IP or DoH URL (8.8.8.8, https://dns.google/dns-query)".into(),
                    buffer: self.settings.custom_dns.clone(),
                    purpose: TextPurpose::CustomDns,
                    created_tick: tick,
                    select_all: true,
                };
            }

            ComponentId::SettingFragmentMinus => {
                self.settings.tls_fragment_size =
                    self.settings.tls_fragment_size.saturating_sub(25).max(20);
                self.save_and_report(format!("TLS fragment {}B", self.settings.tls_fragment_size));
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingFragmentPlus => {
                self.settings.tls_fragment_size = (self.settings.tls_fragment_size + 25).min(1500);
                self.save_and_report(format!("TLS fragment {}B", self.settings.tls_fragment_size));
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingJitterMinus => {
                self.settings.jitter_delay_ms =
                    self.settings.jitter_delay_ms.saturating_sub(5).max(1);
                self.save_and_report(format!("Jitter {}ms", self.settings.jitter_delay_ms));
            }
            ComponentId::SettingJitterPlus => {
                self.settings.jitter_delay_ms = (self.settings.jitter_delay_ms + 5).min(200);
                self.save_and_report(format!("Jitter {}ms", self.settings.jitter_delay_ms));
            }
            ComponentId::SettingConcurrencyMinus => {
                self.settings.scanner_concurrency =
                    self.settings.scanner_concurrency.saturating_sub(20).max(1);
                self.save_and_report(format!(
                    "Scanner workers {}",
                    self.settings.scanner_concurrency
                ));
            }
            ComponentId::SettingConcurrencyPlus => {
                self.settings.scanner_concurrency =
                    (self.settings.scanner_concurrency + 20).min(1000);
                self.save_and_report(format!(
                    "Scanner workers {}",
                    self.settings.scanner_concurrency
                ));
            }

            ComponentId::SettingDnsCycle => {
                self.settings.remote_dns = cycle(
                    &self.settings.remote_dns,
                    &["google", "cloudflare", "quad9", "adguard"],
                );
                self.save_and_report(format!("Remote DNS: {}", self.settings.remote_dns));
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingAntiSanctionCycle => {
                self.settings.anti_sanction = cycle(
                    &self.settings.anti_sanction,
                    &["shecan", "electro", "begzar", "none"],
                );
                self.save_and_report(format!(
                    "Anti-sanction DNS: {}",
                    self.settings.anti_sanction
                ));
            }
            ComponentId::SettingDomainStrategyCycle => {
                self.settings.domain_strategy = cycle(
                    &self.settings.domain_strategy,
                    &["IPIfNonMatch", "AsIs", "IPOnDemand"],
                );
                self.save_and_report(format!(
                    "Domain strategy: {}",
                    self.settings.domain_strategy
                ));
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingTcpCongestionCycle => {
                self.settings.tcp_congestion =
                    cycle(&self.settings.tcp_congestion, &["bbr", "cubic", "reno"]);
                self.save_and_report(format!(
                    "Congestion control: {}",
                    self.settings.tcp_congestion.to_uppercase()
                ));
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingAntiCensorshipCycle => {
                self.settings.anti_censorship_level = cycle(
                    &self.settings.anti_censorship_level,
                    &["IranEvasion", "Aggressive", "Standard"],
                );
                // A preset is only honest if it actually moves the knobs it
                // names, so it writes the three settings it summarises and
                // the toast says what they became.
                let level = self.settings.anti_censorship_level.as_str();
                let (shredding, size, keepalive) = match level {
                    "Standard" => (false, 150u16, 0u64),
                    "Aggressive" => (true, 60, 15),
                    _ => (true, 150, 30),
                };
                self.settings.fragment_enabled = shredding;
                self.settings.tls_fragment_size = size;
                self.settings.keepalive_interval_secs = keepalive;
                self.save_and_report(format!(
                    "Evasion: {level} (shredding {}, keepalive {})",
                    if shredding {
                        format!("{size}B")
                    } else {
                        "off".to_string()
                    },
                    if keepalive == 0 {
                        "off".to_string()
                    } else {
                        format!("{keepalive}s")
                    }
                ));
                self.reapply_engine_settings().await?;
            }

            ComponentId::SettingLogLevelCycle => {
                self.settings.log_level = cycle(
                    &self.settings.log_level,
                    &["none", "error", "warning", "info", "debug"],
                );
                self.save_and_report(format!("Log level: {}", self.settings.log_level));
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingFingerprintCycle => {
                self.settings.utls_fingerprint = cycle(
                    &self.settings.utls_fingerprint,
                    &[
                        "chrome",
                        "firefox",
                        "safari",
                        "edge",
                        "ios",
                        "android",
                        "random",
                        "randomized",
                    ],
                );
                self.save_and_report(format!(
                    "uTLS fingerprint: {}",
                    self.settings.utls_fingerprint
                ));
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingScannerModeCycle => {
                self.settings.scanner_mode =
                    cycle(&self.settings.scanner_mode, &["tcp", "tls", "http"]);
                self.save_and_report(format!(
                    "Probe mode: {}",
                    self.settings.scanner_mode.to_uppercase()
                ));
            }
            ComponentId::SettingAllowLanToggle => {
                self.settings.allow_lan = !self.settings.allow_lan;
                if self.settings.allow_lan {
                    // Worth spelling out: the proxy stops being private to
                    // this machine, and nothing else on the page does that.
                    self.toasts.warning(
                        "The proxy is open to your LAN now. Anyone on this network can use it.",
                    );
                    self.persist_settings();
                } else {
                    self.save_and_report("Proxy bound to localhost only".to_string());
                }
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingUdpToggle => {
                self.settings.udp_enabled = !self.settings.udp_enabled;
                self.save_and_report(format!("UDP {}", on_off(self.settings.udp_enabled)));
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingSniffRouteOnlyToggle => {
                self.settings.sniffing_route_only = !self.settings.sniffing_route_only;
                self.save_and_report(if self.settings.sniffing_route_only {
                    "Sniffed domains steer routing only".to_string()
                } else {
                    "Sniffed domains rewrite the destination".to_string()
                });
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingFragmentToggle => {
                self.settings.fragment_enabled = !self.settings.fragment_enabled;
                self.save_and_report(format!(
                    "TLS fragmentation {}",
                    on_off(self.settings.fragment_enabled)
                ));
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingTunAutoRouteToggle => {
                self.settings.tun_auto_route = !self.settings.tun_auto_route;
                self.save_and_report(format!(
                    "TUN auto-route {}",
                    on_off(self.settings.tun_auto_route)
                ));
                if !self.settings.tun_auto_route && self.settings.tun_strict_route {
                    self.toasts
                        .warning("Strict routing is inert without auto-route.");
                }
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingTunStrictRouteToggle => {
                self.settings.tun_strict_route = !self.settings.tun_strict_route;
                if self.settings.tun_strict_route && !self.settings.tun_auto_route {
                    self.persist_settings();
                    self.toasts.warning(
                        "Strict routing does nothing without auto-route. Turn that on too.",
                    );
                } else {
                    self.save_and_report(format!(
                        "TUN strict route {}",
                        on_off(self.settings.tun_strict_route)
                    ));
                }
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingScannerRequireWsToggle => {
                self.settings.scanner_require_ws = !self.settings.scanner_require_ws;
                self.save_and_report(format!(
                    "WebSocket upgrade {}",
                    if self.settings.scanner_require_ws {
                        "required"
                    } else {
                        "optional"
                    }
                ));
            }
            ComponentId::SettingScannerNeighborsToggle => {
                self.settings.scanner_neighbors = !self.settings.scanner_neighbors;
                self.save_and_report(format!(
                    "Neighbour sweep {}",
                    on_off(self.settings.scanner_neighbors)
                ));
            }
            // At least one address family has to stay on, or the scanner has
            // no candidates to draw and would sit at zero for ever.
            ComponentId::SettingScannerIpv4Toggle => {
                if self.settings.scanner_ipv4 && !self.settings.scanner_ipv6 {
                    self.toasts
                        .warning("Keep at least one address family enabled to scan.");
                } else {
                    self.settings.scanner_ipv4 = !self.settings.scanner_ipv4;
                    self.save_and_report(format!(
                        "IPv4 ranges {}",
                        on_off(self.settings.scanner_ipv4)
                    ));
                }
            }
            ComponentId::SettingScannerIpv6Toggle => {
                if self.settings.scanner_ipv6 && !self.settings.scanner_ipv4 {
                    self.toasts
                        .warning("Keep at least one address family enabled to scan.");
                } else {
                    self.settings.scanner_ipv6 = !self.settings.scanner_ipv6;
                    self.save_and_report(format!(
                        "IPv6 ranges {}",
                        on_off(self.settings.scanner_ipv6)
                    ));
                }
            }
            ComponentId::SettingMuxToggle => {
                self.settings.mux_enabled = !self.settings.mux_enabled;
                self.save_and_report(format!(
                    "Multiplexing {}",
                    on_off(self.settings.mux_enabled)
                ));
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingSniffingToggle => {
                self.settings.sniffing_enabled = !self.settings.sniffing_enabled;
                self.save_and_report(format!(
                    "Sniffing {}",
                    on_off(self.settings.sniffing_enabled)
                ));
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingIpv6Toggle => {
                self.settings.ipv6_enabled = !self.settings.ipv6_enabled;
                self.save_and_report(format!("IPv6 {}", on_off(self.settings.ipv6_enabled)));
                self.reapply_engine_settings().await?;
            }
            ComponentId::SettingAutoReconnectToggle => {
                self.settings.auto_reconnect = !self.settings.auto_reconnect;
                self.save_and_report(format!(
                    "Auto-reconnect {}",
                    on_off(self.settings.auto_reconnect)
                ));
            }
            ComponentId::SettingCleanIpToggle => {
                self.settings.clean_ip_rotation = !self.settings.clean_ip_rotation;
                self.save_and_report(format!(
                    "Clean IP rotation {}",
                    on_off(self.settings.clean_ip_rotation)
                ));
                self.reapply_engine_settings().await?;
            }
            _ => {}
        }

        if self.modal_state.is_active() {
            self.open_modal_effect();
        }
        Ok(())
    }

    fn save_and_report(&mut self, message: String) {
        self.persist_settings();
        self.toasts.info(message);
    }

    // ------------------------------------------------------------ scanner

    fn toggle_scanner(&mut self) {
        if self.is_scanning {
            if let Some(handle) = self.scan_handle.take() {
                handle.abort();
            }
            self.is_scanning = false;
            *self.scanner_stats.lock().unwrap() = None;
            self.toasts.warning("Scanner stopped.");
            return;
        }

        self.is_scanning = true;
        self.scanner_tested = 0;
        self.scanner_healthy = 0;
        self.scanner_speed = 0.0;
        self.scanner_results.clear();

        // Every one of these used to be hard-coded here, which meant the
        // whole EDGE SCANNER section of Settings — mode, port, tries,
        // timeout, SNI, WebSocket, neighbours, address family — described a
        // scan that never ran.
        let s = &self.settings;
        let mode = s
            .scanner_mode
            .parse::<zero_scanner::types::ProbeMode>()
            .unwrap_or(zero_scanner::types::ProbeMode::Http);
        let ip_src = Arc::new(zero_scanner::ip::IpSource::new(
            s.scanner_ipv4,
            s.scanner_ipv6,
            &[],
            true,
        ));
        let probe_cfg = zero_scanner::types::ProbeConfig {
            port: s.scanner_port,
            mode,
            tries: s.scanner_tries.max(1),
            timeout: Duration::from_secs(s.scanner_timeout_secs.max(1)),
            // Blank means "rotate the well-known edge names", which is what
            // `None` asks the prober to do.
            sni: if s.scanner_sni.trim().is_empty() {
                None
            } else {
                Some(s.scanner_sni.trim().to_string())
            },
            speed_bytes: s.scanner_speed_bytes,
            ws_host: None,
            ws_path: if s.scanner_ws_path.trim().is_empty() {
                None
            } else {
                Some(s.scanner_ws_path.trim().to_string())
            },
            require_ws: s.scanner_require_ws,
            check_dpi_hold: true,
            // The jitter between probes is the evasion setting, reused here
            // so one dial does not have two different meanings.
            jitter_range_ms: (s.jitter_delay_ms.max(1), s.jitter_delay_ms.max(1) * 3),
        };
        let target = s.scanner_target_count;
        self.toasts.success(format!(
            "Scanning Cloudflare edges: {} on :{}{}",
            mode,
            probe_cfg.port,
            if target == 0 {
                String::new()
            } else {
                format!(", {target} candidates")
            }
        ));
        let engine = Arc::new(zero_scanner::engine::ScanEngine::new(
            zero_scanner::engine::ScanEngineConfig {
                concurrency: self.settings.scanner_concurrency.max(1),
                target_count: target,
                probe_config: probe_cfg,
                neighbor_scan: self.settings.scanner_neighbors,
                proxy_config: None,
            },
            ip_src,
        ));
        *self.scanner_stats.lock().unwrap() = Some(engine.stats());

        let tx = self.scan_tx.clone();
        let eng = Arc::clone(&engine);
        self.scan_handle = Some(tokio::spawn(async move {
            let _ = eng
                .run(move |hit| {
                    let _ = tx.send(hit.clone());
                })
                .await;
        }));
    }

    fn export_scanner_results(&mut self) {
        if self.scanner_results.is_empty() {
            self.toasts
                .warning("Nothing to export yet. Run a scan first.");
            return;
        }
        let exports = zero_scanner::export::generate_exports(&self.scanner_results, None);
        let out_dir = std::path::PathBuf::from("./clean_endpoints");
        if let Err(e) = std::fs::create_dir_all(&out_dir) {
            self.toasts
                .error(format!("Could not create export dir: {e}"));
            return;
        }
        let writes = [
            ("endpoints.txt", &exports.endpoints_text),
            ("clash.yaml", &exports.clash_yaml),
            ("singbox.json", &exports.singbox_json),
            ("subscription.txt", &exports.subscription_base64),
        ];
        for (name, body) in writes {
            if let Err(e) = std::fs::write(out_dir.join(name), body) {
                self.toasts.error(format!("Failed writing {name}: {e}"));
                return;
            }
        }
        self.toasts.success(format!(
            "Exported {} endpoints to ./clean_endpoints/",
            self.scanner_results.len()
        ));
    }

    /// Put a scanned clean edge to use.
    ///
    /// A copy of the active profile is pointed at the edge, so the original
    /// stays intact, and — when connected — the connection moves onto it
    /// through the connection manager like any other switch (TUN included).
    /// It used to write a copy nobody could find, change the in-memory
    /// original without saving it, and dial the daemon directly behind the
    /// connection manager's back.
    async fn apply_scanner_endpoint(&mut self, idx: usize) -> Result<()> {
        let Some(hit) = self.scanner_results.get(idx) else {
            return Ok(());
        };
        let (ip_str, port) = (hit.ip.to_string(), hit.port);
        let colo = hit.colo.clone().unwrap_or_else(|| "Edge".into());

        let Some(active) = self.configs.iter().find(|c| c.is_active) else {
            self.toasts.info(format!(
                "Picked {ip_str}:{port} ({colo}). Select a server to apply it to."
            ));
            return Ok(());
        };
        let (remark, proto, raw) = (
            active.remark.clone(),
            active.protocol.clone(),
            active.raw_content.clone(),
        );
        let mut val = match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(val) => val,
            Err(_) => {
                self.toasts.error(format!(
                    "{remark} is not a JSON profile; it cannot be retargeted."
                ));
                return Ok(());
            }
        };
        retarget_outbound(&mut val, &ip_str, port);
        let raw = serde_json::to_string_pretty(&val)?;
        let name = format!("{remark} @ {ip_str}");
        let id = self
            .db
            .insert_config(&name, &proto, &ip_str, port, &raw, None)?;
        self.reload_configs();
        self.focus_profile(id);
        let action = self.connection.select(id);
        self.apply_engine_action(action).await?;
        self.toasts.success(format!(
            "Applied clean edge {ip_str}:{port} ({colo}) as \"{name}\""
        ));
        Ok(())
    }
}

// --------------------------------------------------------------- helpers

/// Overwrite a string's bytes before releasing them.
///
/// Not a guarantee — `String` may have reallocated while it was being typed,
/// and those older buffers are beyond reach — but it keeps the live copy of a
/// password from sitting in the heap for the rest of the session, which is
/// the part that is actually in this code's control.
fn zeroize(secret: &mut String) {
    // SAFETY: the bytes are overwritten with ASCII zeros, which is valid
    // UTF-8, so the string stays well-formed. It is cleared immediately after.
    unsafe {
        for byte in secret.as_bytes_mut() {
            *byte = 0;
        }
    }
    secret.clear();
    secret.shrink_to_fit();
}

/// Close a descriptor this process was handed but is not going to use.
fn close_descriptor(fd: i32) {
    #[cfg(unix)]
    if fd >= 0 {
        // SAFETY: the descriptor came from a handover that transferred
        // ownership, and nothing else holds it at this point.
        unsafe {
            libc::close(fd);
        }
    }
    #[cfg(not(unix))]
    let _ = fd;
}

/// `1 profile`, `3 profiles`.
fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn next_tab(tab: ActiveTab) -> ActiveTab {
    match tab {
        ActiveTab::Dashboard => ActiveTab::Subscriptions,
        ActiveTab::Subscriptions => ActiveTab::IpScanner,
        ActiveTab::IpScanner => ActiveTab::Activity,
        ActiveTab::Activity => ActiveTab::Settings,
        ActiveTab::Settings => ActiveTab::Dashboard,
    }
}

fn prev_tab(tab: ActiveTab) -> ActiveTab {
    match tab {
        ActiveTab::Dashboard => ActiveTab::Settings,
        ActiveTab::Subscriptions => ActiveTab::Dashboard,
        ActiveTab::IpScanner => ActiveTab::Subscriptions,
        ActiveTab::Activity => ActiveTab::IpScanner,
        ActiveTab::Settings => ActiveTab::Activity,
    }
}

fn on_off(v: bool) -> &'static str {
    if v {
        "on"
    } else {
        "off"
    }
}

/// Advance `current` to the next entry in `options`, wrapping around.
fn cycle(current: &str, options: &[&str]) -> String {
    let idx = options.iter().position(|o| *o == current).unwrap_or(0);
    options[(idx + 1) % options.len()].to_string()
}

fn apply_number_setting(key: &str, val: u64, settings: &mut AppSettings) {
    match key {
        "tun_mtu" => settings.tun_mtu = val as u16,
        "socks_port" => settings.socks_port = val as u16,
        "http_port" => settings.http_port = val as u16,
        "tls_fragment_size" => settings.tls_fragment_size = val as u16,
        "jitter_delay_ms" => settings.jitter_delay_ms = val,
        "scanner_concurrency" => settings.scanner_concurrency = val as usize,
        "mux_concurrency" => settings.mux_concurrency = val as u16,
        "keepalive_interval_secs" => settings.keepalive_interval_secs = val,
        "sub_update_interval_hours" => settings.sub_update_interval_hours = val as u32,
        "pac_port" => settings.pac_port = val as u16,
        "scanner_port" => settings.scanner_port = val as u16,
        "scanner_tries" => settings.scanner_tries = val as usize,
        "scanner_timeout_secs" => settings.scanner_timeout_secs = val,
        "scanner_target_count" => settings.scanner_target_count = val as usize,
        "scanner_speed_bytes" => settings.scanner_speed_bytes = val as usize,
        _ => {}
    }
}

fn endpoint_of(protocol: &zero_config::OutboundProtocol) -> (String, u16) {
    match protocol {
        zero_config::OutboundProtocol::Vless(v) => (v.address.to_string(), v.port),
        zero_config::OutboundProtocol::Trojan(t) => (t.address.to_string(), t.port),
        zero_config::OutboundProtocol::Shadowsocks(s) => (s.address.to_string(), s.port),
        zero_config::OutboundProtocol::Vmess(m) => (m.address.to_string(), m.port),
        _ => ("proxy".into(), 443),
    }
}

/// Point the first outbound at a new endpoint, covering both the `vnext`
/// shape used by VLESS/VMess and the flat `servers` shape used by
/// Trojan/Shadowsocks.
fn retarget_outbound(val: &mut serde_json::Value, ip: &str, port: u16) {
    let Some(first) = val
        .get_mut("outbounds")
        .and_then(|o| o.as_array_mut())
        .and_then(|a| a.first_mut())
    else {
        return;
    };
    // A profile imported from a share link keeps the link itself, and that
    // is what the engine dials; rewriting only `settings` left it pointed at
    // the old server while the list showed the new one.
    if let Some(link) = first.get("link").and_then(|l| l.as_str()) {
        if let Some(rewritten) = retarget_link(link, ip, port) {
            first["link"] = serde_json::Value::String(rewritten);
        }
    }
    let Some(settings) = first.get_mut("settings") else {
        return;
    };

    for key in ["vnext", "servers"] {
        if let Some(server) = settings
            .get_mut(key)
            .and_then(|v| v.as_array_mut())
            .and_then(|a| a.first_mut())
        {
            server["address"] = serde_json::Value::String(ip.to_string());
            server["port"] = serde_json::json!(port);
        }
    }
}

/// Point a share link at `ip:port`, keeping everything else.
///
/// A CDN-fronted node still has to present its original name: when the link
/// does not already say so, the old host becomes the TLS `sni` and the
/// transport `host`, exactly what hand-editing a clean IP into a link means.
fn retarget_link(link: &str, ip: &str, port: u16) -> Option<String> {
    use base64::Engine as _;
    let (scheme, rest) = link.split_once("://")?;
    let bracketed = if ip.contains(':') {
        format!("[{ip}]")
    } else {
        ip.to_string()
    };

    if scheme.eq_ignore_ascii_case("vmess") {
        let (payload, fragment) = match rest.split_once('#') {
            Some((p, f)) => (p, Some(f)),
            None => (rest, None),
        };
        let cleaned: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(cleaned.trim_end_matches('='))
            .or_else(|_| {
                base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(cleaned.trim_end_matches('='))
            })
            .or_else(|_| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(cleaned.trim_end_matches('='))
            })
            .ok()?;
        let mut obj: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
        let original = obj
            .get("add")
            .and_then(|a| a.as_str())
            .unwrap_or_default()
            .to_string();
        let is_name = !original.is_empty() && original.parse::<std::net::IpAddr>().is_err();
        obj["add"] = serde_json::Value::String(ip.to_string());
        obj["port"] = serde_json::Value::String(port.to_string());
        for key in ["host", "sni"] {
            let empty = obj
                .get(key)
                .and_then(|v| v.as_str())
                .is_none_or(str::is_empty);
            if is_name && empty {
                obj[key] = serde_json::Value::String(original.clone());
            }
        }
        let mut out = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(obj.to_string())
        );
        if let Some(fragment) = fragment {
            out.push('#');
            out.push_str(fragment);
        }
        return Some(out);
    }

    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((user, hp)) => (Some(user), hp),
        None => (None, authority),
    };
    let original = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split_once(']')?.0
    } else {
        hostport.rsplit_once(':').map_or(hostport, |(h, _)| h)
    };
    let is_name = !original.is_empty() && original.parse::<std::net::IpAddr>().is_err();

    let (before_fragment, fragment) = match tail.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (tail, None),
    };
    let (path, query) = match before_fragment.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (before_fragment, None),
    };
    let mut fields: Vec<String> = query
        .unwrap_or_default()
        .split('&')
        .filter(|f| !f.is_empty())
        .map(str::to_string)
        .collect();
    let has = |fields: &[String], key: &str| {
        fields
            .iter()
            .any(|f| f.split_once('=').map_or(f.as_str(), |(k, _)| k) == key)
    };
    let value_of = |fields: &[String], key: &str| {
        fields.iter().find_map(|f| {
            f.split_once('=')
                .filter(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        })
    };
    // Shadowsocks has no TLS of its own, and its SIP002 query is plugin
    // options rather than transport parameters.
    if is_name && !scheme.eq_ignore_ascii_case("ss") {
        if !has(&fields, "sni") && !has(&fields, "peer") {
            fields.push(format!("sni={original}"));
        }
        let transport = value_of(&fields, "type").unwrap_or_default();
        if matches!(
            transport.as_str(),
            "ws" | "httpupgrade" | "xhttp" | "splithttp"
        ) && !has(&fields, "host")
        {
            fields.push(format!("host={original}"));
        }
    }

    let mut out = format!("{scheme}://");
    if let Some(user) = userinfo {
        out.push_str(user);
        out.push('@');
    }
    out.push_str(&format!("{bracketed}:{port}{path}"));
    if !fields.is_empty() {
        out.push('?');
        out.push_str(&fields.join("&"));
    }
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    Some(out)
}

/// Advance the focused cycler field to its next value.
///
/// Text fields are left alone: the key router sends printable characters to
/// them instead, so Space types a space rather than cycling nothing.
fn cycle_form_field(form: &mut ManualProfileForm) {
    match form.focused_field {
        1 => form.protocol_idx = (form.protocol_idx + 1) % PROTOCOLS.len(),
        5 => form.security_idx = (form.security_idx + 1) % SECURITIES.len(),
        9 => form.flow_idx = (form.flow_idx + 1) % FLOWS.len(),
        10 => form.transport_idx = (form.transport_idx + 1) % TRANSPORTS.len(),
        _ => {}
    }
}

/// Empty the focused text field.
fn clear_form_field(form: &mut ManualProfileForm) {
    match form.focused_field {
        0 => form.remark.clear(),
        2 => form.address.clear(),
        3 => form.port = 0,
        4 => form.uuid_or_password.clear(),
        6 => form.sni.clear(),
        7 => form.pbk.clear(),
        8 => form.sid.clear(),
        11 => form.ws_path.clear(),
        _ => {}
    }
}

fn backspace_form_field(form: &mut ManualProfileForm) {
    match form.focused_field {
        0 => {
            form.remark.pop();
        }
        2 => {
            form.address.pop();
        }
        3 => form.port /= 10,
        4 => {
            form.uuid_or_password.pop();
        }
        6 => {
            form.sni.pop();
        }
        7 => {
            form.pbk.pop();
        }
        8 => {
            form.sid.pop();
        }
        11 => {
            form.ws_path.pop();
        }
        _ => {}
    }
}

fn push_form_field(form: &mut ManualProfileForm, c: char) {
    match form.focused_field {
        0 => form.remark.push(c),
        2 => form.address.push(c),
        3 => {
            if let Some(digit) = c.to_digit(10) {
                form.port = form.port.saturating_mul(10).saturating_add(digit as u16);
            }
        }
        4 => form.uuid_or_password.push(c),
        6 => form.sni.push(c),
        7 => form.pbk.push(c),
        8 => form.sid.push(c),
        11 => form.ws_path.push(c),
        _ => {}
    }
}

fn seed_sample_configs(db: &Database) -> Result<()> {
    let amnezia_link = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@155.117.13.26:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.googletagmanager.com&fp=chrome&pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY&sid=7963d08380d47375&type=tcp&headerType=none#AmneziaVPN";

    let preset = zero_config::IranPreset {
        outbounds: zero_config::presets::outbounds_from_links([amnezia_link]),
        socks_port: 10808,
        http_port: Some(10809),
        remote_dns: zero_config::RemoteDns::Google,
        local_dns: zero_config::LocalDns::Google,
        anti_sanction_dns: zero_config::AntiSanctionDns::Shecan,
        manage_assets: false,
        ..zero_config::IranPreset::default()
    };
    let amnezia_json = serde_json::to_string_pretty(&preset.build())?;
    let id = db.insert_config(
        "AmneziaVPN (VLESS-Reality)",
        "vless",
        "155.117.13.26",
        443,
        &amnezia_json,
        None,
    )?;
    db.set_active_config(id)?;
    Ok(())
}

/// The last `lines` lines of a file, reading at most the final 256 KiB.
fn read_log_tail(path: &std::path::Path, lines: usize) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    const WINDOW: u64 = 256 * 1024;
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(WINDOW);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::with_capacity((len - start) as usize);
    file.read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    // A window that starts mid-file starts mid-line; drop the fragment.
    let text = if start > 0 {
        text.split_once('\n').map_or("", |(_, rest)| rest)
    } else {
        &text
    };
    let tail: Vec<&str> = text.lines().rev().take(lines).collect();
    Ok(tail.into_iter().rev().collect::<Vec<_>>().join("\n"))
}

/// Expand a leading `~` to the user's home directory.
///
/// People type `~/Downloads/qr.png`; without this the path is taken
/// literally and the file is never found.
fn shellexpand(path: &str) -> String {
    let trimmed = path.trim();
    let Some(rest) = trimmed.strip_prefix('~') else {
        return trimmed.to_string();
    };
    let Some(home) = std::env::var_os("HOME") else {
        return trimmed.to_string();
    };
    let home = home.to_string_lossy().to_string();
    if rest.is_empty() {
        home
    } else if let Some(tail) = rest.strip_prefix('/') {
        format!("{home}/{tail}")
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_sequence_fires_once_and_tolerates_extra_presses() {
        let mut seq = SecretSequence::default();
        let mut keys = vec![KeyCode::Up, KeyCode::Up]; // a false start
        keys.extend(SecretSequence::CODE);
        let fired: Vec<bool> = keys.iter().map(|k| seq.feed(*k)).collect();
        assert_eq!(fired.iter().filter(|f| **f).count(), 1);
        assert!(*fired.last().unwrap());
        // Capital B/A count too; anything else in between breaks it.
        let mut seq = SecretSequence::default();
        for k in &SecretSequence::CODE[..8] {
            assert!(!seq.feed(*k));
        }
        assert!(!seq.feed(KeyCode::Char('B')));
        assert!(seq.feed(KeyCode::Char('A')));
        let mut seq = SecretSequence::default();
        for k in &SecretSequence::CODE[..9] {
            seq.feed(*k);
        }
        assert!(!seq.feed(KeyCode::Char('x')));
    }

    #[test]
    fn the_frame_overlay_only_wakes_the_loop_while_open() {
        let mut perf = PerfMeter::default();
        assert!(perf.next_refresh.is_none());
        perf.toggle();
        let now = Instant::now();
        assert!(perf.refresh_due(now));
        assert!(!perf.refresh_due(now), "twice a second, not every pass");
        perf.record(now, Duration::from_micros(400));
        let hud = perf.snapshot(now).unwrap();
        assert_eq!(hud.fps, 1);
        let later = hud;
        assert_eq!(perf.snapshot(now + Duration::from_secs(2)).unwrap().fps, 0);
        assert_eq!(later.total_frames, 1);
        perf.toggle();
        assert!(perf.next_refresh.is_none());
        assert!(perf.snapshot(now).is_none());
    }

    #[test]
    fn tabs_cycle_forwards_and_backwards() {
        // Every page is visited exactly once per lap, in sidebar order.
        let mut tab = ActiveTab::Dashboard;
        let mut seen = vec![tab];
        for _ in 0..4 {
            tab = next_tab(tab);
            seen.push(tab);
        }
        assert_eq!(
            seen,
            [
                ActiveTab::Dashboard,
                ActiveTab::Subscriptions,
                ActiveTab::IpScanner,
                ActiveTab::Activity,
                ActiveTab::Settings,
            ]
        );
        assert_eq!(next_tab(tab), ActiveTab::Dashboard);
        for tab in seen {
            assert_eq!(prev_tab(next_tab(tab)), tab);
        }
    }

    #[test]
    fn cycle_wraps_and_tolerates_unknown_values() {
        let options = ["google", "cloudflare", "quad9"];
        assert_eq!(cycle("google", &options), "cloudflare");
        assert_eq!(cycle("quad9", &options), "google");
        // A value saved by an older build falls back to the first entry.
        assert_eq!(cycle("something-else", &options), "cloudflare");
    }

    #[test]
    fn number_settings_land_in_the_right_field() {
        let mut s = AppSettings::default();
        apply_number_setting("socks_port", 21080, &mut s);
        apply_number_setting("tun_mtu", 1400, &mut s);
        apply_number_setting("jitter_delay_ms", 42, &mut s);
        assert_eq!(s.socks_port, 21080);
        assert_eq!(s.tun_mtu, 1400);
        assert_eq!(s.jitter_delay_ms, 42);
    }

    /// Every key a number dialog can be opened with has to be handled.
    ///
    /// An unhandled key is invisible: the dialog opens, accepts a value,
    /// reports "set to 12080" and changes nothing. `pac_port` was exactly
    /// that for as long as the PAC row existed.
    #[test]
    fn every_number_dialog_key_actually_writes_something() {
        const KEYS: &[&str] = &[
            "tun_mtu",
            "socks_port",
            "http_port",
            "tls_fragment_size",
            "jitter_delay_ms",
            "scanner_concurrency",
            "mux_concurrency",
            "keepalive_interval_secs",
            "sub_update_interval_hours",
            "pac_port",
            "scanner_port",
            "scanner_tries",
            "scanner_timeout_secs",
            "scanner_target_count",
            "scanner_speed_bytes",
        ];
        for key in KEYS {
            let mut settings = AppSettings::default();
            // 7 differs from every default in the struct, so any write shows.
            apply_number_setting(key, 7, &mut settings);
            assert_ne!(
                settings,
                AppSettings::default(),
                "the {key} dialog reports success and changes nothing"
            );
        }
    }

    #[test]
    fn an_unknown_number_key_is_a_no_op_rather_than_a_panic() {
        let mut settings = AppSettings::default();
        apply_number_setting("not_a_setting", 9, &mut settings);
        assert_eq!(settings, AppSettings::default());
    }

    #[test]
    fn retarget_rewrites_vnext_endpoints() {
        let mut val = serde_json::json!({
            "outbounds": [{
                "settings": {"vnext": [{"address": "1.1.1.1", "port": 443}]}
            }]
        });
        retarget_outbound(&mut val, "104.16.1.9", 8443);
        assert_eq!(
            val["outbounds"][0]["settings"]["vnext"][0]["address"],
            "104.16.1.9"
        );
        assert_eq!(val["outbounds"][0]["settings"]["vnext"][0]["port"], 8443);
    }

    #[test]
    fn retarget_also_handles_the_flat_servers_shape() {
        // Trojan and Shadowsocks use `servers`, not `vnext`; the old code
        // only understood `vnext`, so applying a clean IP to those silently
        // did nothing.
        let mut val = serde_json::json!({
            "outbounds": [{
                "settings": {"servers": [{"address": "1.1.1.1", "port": 443}]}
            }]
        });
        retarget_outbound(&mut val, "104.16.1.9", 8443);
        assert_eq!(
            val["outbounds"][0]["settings"]["servers"][0]["address"],
            "104.16.1.9"
        );
    }

    #[test]
    fn retarget_rewrites_the_link_the_engine_actually_dials() {
        let mut val = serde_json::json!({
            "outbounds": [{
                "tag": "proxy",
                "link": "vless://id@cdn.example.com:443?security=tls&type=ws&path=%2Fws#Node"
            }]
        });
        retarget_outbound(&mut val, "104.16.1.9", 8443);
        let link = val["outbounds"][0]["link"].as_str().unwrap();
        assert!(link.starts_with("vless://id@104.16.1.9:8443?"), "{link}");
        // The original name is kept for TLS and the WebSocket Host.
        assert!(link.contains("sni=cdn.example.com"), "{link}");
        assert!(link.contains("host=cdn.example.com"), "{link}");
        assert!(link.ends_with("#Node"), "{link}");
    }

    #[test]
    fn retarget_keeps_an_explicit_sni_and_handles_vmess() {
        let link = "trojan://pw@a.example:443?security=tls&sni=front.example#T";
        let out = retarget_link(link, "2606:4700::1", 443).unwrap();
        assert_eq!(
            out,
            "trojan://pw@[2606:4700::1]:443?security=tls&sni=front.example#T"
        );

        use base64::Engine as _;
        let vmess = serde_json::json!({"v": "2", "add": "v.example", "port": "443", "id": "x", "tls": "tls", "sni": ""});
        let link = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(vmess.to_string())
        );
        let out = retarget_link(&link, "1.2.3.4", 2053).unwrap();
        let body = base64::engine::general_purpose::STANDARD
            .decode(out.trim_start_matches("vmess://"))
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(obj["add"], "1.2.3.4");
        assert_eq!(obj["port"], "2053");
        assert_eq!(obj["sni"], "v.example");
    }

    #[test]
    fn retarget_ignores_configs_without_outbounds() {
        let mut val = serde_json::json!({"inbounds": []});
        retarget_outbound(&mut val, "1.2.3.4", 443);
        assert_eq!(val, serde_json::json!({"inbounds": []}));
    }

    #[test]
    fn form_port_editing_is_digit_only() {
        let mut form = ManualProfileForm::new();
        form.focused_field = 3;
        form.port = 0;
        push_form_field(&mut form, '4');
        push_form_field(&mut form, 'x');
        push_form_field(&mut form, '3');
        assert_eq!(form.port, 43);
        backspace_form_field(&mut form);
        assert_eq!(form.port, 4);
    }

    #[test]
    fn form_cycling_only_touches_cycler_fields() {
        let mut form = ManualProfileForm::new();

        for field in ManualProfileForm::CYCLER_FIELDS {
            form.focused_field = field;
            let before = format!("{form:?}");
            cycle_form_field(&mut form);
            assert_ne!(format!("{form:?}"), before, "field {field} did not cycle");
        }

        // A text field must not be mutated by the cycle key.
        form.focused_field = 0;
        let remark = form.remark.clone();
        cycle_form_field(&mut form);
        assert_eq!(form.remark, remark);
    }

    #[test]
    fn clearing_a_field_only_clears_the_focused_one() {
        let mut form = ManualProfileForm::new();
        form.focused_field = 2; // Server host
        let sni = form.sni.clone();
        clear_form_field(&mut form);
        assert!(form.address.is_empty());
        assert_eq!(form.sni, sni, "clearing one field wiped another");
    }

    #[test]
    fn a_log_tail_reads_only_the_end() {
        let dir = std::env::temp_dir().join(format!("zeronet-logtail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.log");
        let mut body = String::new();
        for i in 0..40_000 {
            body.push_str(&format!("line number {i}\n"));
        }
        std::fs::write(&path, &body).unwrap();
        let tail = read_log_tail(&path, 3).unwrap();
        assert_eq!(
            tail,
            "line number 39997\nline number 39998\nline number 39999"
        );
        std::fs::write(&path, "only\n").unwrap();
        assert_eq!(read_log_tail(&path, 200).unwrap(), "only");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tilde_paths_expand_to_the_home_directory() {
        let home = std::env::var("HOME").unwrap_or_default();
        if home.is_empty() {
            return;
        }
        assert_eq!(shellexpand("~/qr.png"), format!("{home}/qr.png"));
        assert_eq!(shellexpand("~"), home);
        // A bare path and a `~user` form are left alone.
        assert_eq!(shellexpand("/tmp/x.png"), "/tmp/x.png");
        assert_eq!(shellexpand("~other/x.png"), "~other/x.png");
    }
}
