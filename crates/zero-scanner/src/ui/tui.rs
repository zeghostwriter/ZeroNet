use crate::dns::FastResolver;
use crate::engine::{rank_results, ScanEngine, ScanEngineConfig};
use crate::export::generate_exports;
use crate::ip::IpSource;
use crate::proxy::ProxyConfig;
use crate::speed::{SpeedTestResult, SpeedTester};
use crate::types::{AtomicStats, ProbeConfig, ProbeMode, ProbeResult};
use crate::ui::diagnostics::{run_diagnostics, DiagnosticReport};
use crate::ui::file_browser::{scan_for_ip_files, IpFileInfo};
use crossterm::cursor::Show;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, Tabs, Wrap};
use ratatui::{Frame, Terminal};
use std::io::stdout;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiPage {
    Home,
    AutoScanDiag,
    Config,
    TestIps,
    Scanning,
    SpeedTest,
    Export,
    About,
}

const PORTS_AVAILABLE: [u16; 7] = [443, 80, 2053, 2083, 2087, 2096, 8443];

/// Redraw cadence while something is animating or live-updating. When the
/// app is idle nothing is redrawn until an input event arrives.
const LIVE_FRAME: Duration = Duration::from_millis(100);

/// Braille spinner, advanced by wall-clock time (not frame count) so its
/// speed does not depend on how often the UI happens to redraw.
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_STEP_MS: u128 = 80;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// State of one scan run. Every run gets fresh flags and counters, so a
/// previous (possibly still unwinding) run can never write into the new one.
struct ScanRun {
    handle: JoinHandle<()>,
    done: Arc<AtomicBool>,
}

pub struct TuiApp {
    pub page: TuiPage,
    pub menu_idx: usize,

    // Auto Mode & Diagnostics
    pub diag_report: Option<DiagnosticReport>,
    pub is_diagnosing: bool,

    // File Browser / Test IPs
    pub discovered_files: Vec<IpFileInfo>,
    pub selected_file_idx: usize,
    pub custom_file_path: String,
    pub file_input_mode: bool,

    // Advanced Config
    pub source_mode: usize, // 0 = Random CF, 1 = Custom IP/CIDR, 2 = File
    pub custom_input: String,
    pub count_idx: usize,
    pub custom_count: String,
    pub workers_idx: usize,
    pub custom_workers: String,
    pub timeout_idx: usize,
    pub custom_timeout: String,
    pub port_selected: [bool; 7],
    pub port_focus: usize,
    pub mode_idx: usize,
    pub require_ws: bool,
    pub neighbor_scan: bool,
    pub proxy_url_input: String,
    pub config_row: usize,
    pub text_editing: bool,
    pub status_msg: Option<String>,

    // Runtime state
    pub stats: Arc<AtomicStats>,
    pub results: Arc<Mutex<Vec<ProbeResult>>>,
    /// Bumped on every change to `results`, so views are rebuilt only then.
    pub results_version: Arc<AtomicU64>,
    pub cancelled: Arc<AtomicBool>,
    pub paused: Arc<AtomicBool>,
    pub selected_result_idx: usize,
    pub sort_mode: usize,
    pub is_scanning: bool,
    pub scan_target: usize,

    // Speed test state
    pub speed_results: Vec<SpeedTestResult>,
    pub is_speed_testing: bool,

    // Export tab
    pub export_tab: usize,

    // Background work and derived views
    scan: Option<ScanRun>,
    diag_task: Option<JoinHandle<DiagnosticReport>>,
    speed_task: Option<JoinHandle<Vec<SpeedTestResult>>>,
    /// Results in display order for the current sort mode.
    sorted_view: Vec<ProbeResult>,
    view_key: Option<(u64, usize)>,
    export_preview: String,
    export_key: Option<(u64, usize, String)>,
    anim_start: Instant,
    last_stats: (u64, u64, u64, u64),
}

impl Default for TuiApp {
    fn default() -> Self {
        Self::new()
    }
}

impl TuiApp {
    pub fn new() -> Self {
        let mut port_selected = [false; 7];
        port_selected[0] = true;

        let search_dirs = vec![PathBuf::from("."), PathBuf::from("./data"), dirs_hint()];
        let discovered_files = scan_for_ip_files(&search_dirs);

        Self {
            page: TuiPage::Home,
            menu_idx: 0,

            diag_report: None,
            is_diagnosing: false,

            discovered_files,
            selected_file_idx: 0,
            custom_file_path: String::new(),
            file_input_mode: false,

            source_mode: 0,
            custom_input: String::new(),
            count_idx: 0,
            custom_count: "500".to_string(),
            workers_idx: 1,
            custom_workers: "50".to_string(),
            timeout_idx: 2,
            custom_timeout: "5".to_string(),
            port_selected,
            port_focus: 0,
            mode_idx: 0,
            require_ws: false,
            neighbor_scan: false,
            proxy_url_input: String::new(),
            config_row: 0,
            text_editing: false,
            status_msg: None,

            stats: Arc::new(AtomicStats::new()),
            results: Arc::new(Mutex::new(Vec::new())),
            results_version: Arc::new(AtomicU64::new(0)),
            cancelled: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            selected_result_idx: 0,
            sort_mode: 0,
            is_scanning: false,
            scan_target: 0,

            speed_results: Vec::new(),
            is_speed_testing: false,

            export_tab: 0,

            scan: None,
            diag_task: None,
            speed_task: None,
            sorted_view: Vec::new(),
            view_key: None,
            export_preview: String::new(),
            export_key: None,
            anim_start: Instant::now(),
            last_stats: (0, 0, 0, 0),
        }
    }

    pub fn get_count(&self) -> usize {
        match self.count_idx {
            0 => 500,
            1 => 1000,
            2 => 5000,
            3 => 20000,
            _ => self.custom_count.parse().unwrap_or(500),
        }
    }

    pub fn get_workers(&self) -> usize {
        match self.workers_idx {
            0 => 25,
            1 => 50,
            2 => 100,
            3 => 200,
            _ => self.custom_workers.parse().unwrap_or(50),
        }
        .max(1)
    }

    pub fn get_timeout(&self) -> Duration {
        match self.timeout_idx {
            0 => Duration::from_secs(2),
            1 => Duration::from_secs(3),
            2 => Duration::from_secs(5),
            _ => Duration::from_secs(self.custom_timeout.parse().unwrap_or(5).max(1)),
        }
    }

    pub fn get_mode(&self) -> ProbeMode {
        match self.mode_idx {
            0 => ProbeMode::Http,
            1 => ProbeMode::Tls,
            _ => ProbeMode::Tcp,
        }
    }

    pub fn get_selected_ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();
        for (i, &sel) in self.port_selected.iter().enumerate() {
            if sel {
                ports.push(PORTS_AVAILABLE[i]);
            }
        }
        if ports.is_empty() {
            ports.push(443);
        }
        ports
    }

    fn is_busy(&self) -> bool {
        self.is_diagnosing
            || self.is_speed_testing
            || (self.is_scanning && !self.paused.load(Ordering::Relaxed))
    }

    fn spinner(&self) -> &'static str {
        let step = self.anim_start.elapsed().as_millis() / SPINNER_STEP_MS;
        SPINNER[(step % SPINNER.len() as u128) as usize]
    }

    /// Collects finished background work. Returns true if anything the UI
    /// shows has changed.
    fn poll_background(&mut self) -> bool {
        let mut changed = false;

        if self.diag_task.as_ref().is_some_and(|h| h.is_finished()) {
            if let Some(handle) = self.diag_task.take() {
                match futures_lite_now(handle) {
                    Some(report) => self.diag_report = Some(report),
                    None => self.status_msg = Some("Diagnostics failed".to_string()),
                }
            }
            self.is_diagnosing = false;
            changed = true;
        }

        if self.speed_task.as_ref().is_some_and(|h| h.is_finished()) {
            if let Some(handle) = self.speed_task.take() {
                self.speed_results = futures_lite_now(handle).unwrap_or_default();
                self.status_msg = Some(format!(
                    "Completed speed testing for {} endpoints",
                    self.speed_results.len()
                ));
            }
            self.is_speed_testing = false;
            changed = true;
        }

        if let Some(run) = &self.scan {
            if run.done.load(Ordering::Acquire) || run.handle.is_finished() {
                self.scan = None;
                self.is_scanning = false;
                self.status_msg = Some(format!(
                    "Scan finished: {} healthy endpoints",
                    lock(&self.results).len()
                ));
                changed = true;
            }
        }

        let (tested, healthy, failed, in_flight, _) = self.stats.snapshot();
        let snap = (tested, healthy, failed, in_flight);
        if snap != self.last_stats {
            self.last_stats = snap;
            changed = true;
        }

        let version = self.results_version.load(Ordering::Acquire);
        if self.view_key.map(|(v, _)| v) != Some(version) {
            changed = true;
        }
        changed
    }

    /// Rebuilds derived views (sorted table, export preview) only when their
    /// inputs changed, instead of cloning and sorting every result on every
    /// frame.
    fn refresh_views(&mut self) {
        let version = self.results_version.load(Ordering::Acquire);
        let key = (version, self.sort_mode);
        if self.view_key != Some(key) {
            let mut view = lock(&self.results).clone();
            let by = |f: fn(&ProbeResult) -> f64| {
                move |a: &ProbeResult, b: &ProbeResult| f(a).total_cmp(&f(b))
            };
            match self.sort_mode {
                0 => view.sort_by(by(ProbeResult::avg_latency_ms)),
                1 => view.sort_by(by(ProbeResult::packet_loss_percent)),
                2 => view.sort_by(by(ProbeResult::jitter_ms)),
                _ => view.sort_by(|a, b| a.colo.cmp(&b.colo)),
            }
            self.sorted_view = view;
            self.view_key = Some(key);
            if self.selected_result_idx >= self.sorted_view.len() {
                self.selected_result_idx = self.sorted_view.len().saturating_sub(1);
            }
        }

        if self.page == TuiPage::Export {
            let ekey = (version, self.export_tab, self.proxy_url_input.clone());
            if self.export_key.as_ref() != Some(&ekey) {
                self.export_preview = self.export_text(self.export_tab);
                self.export_key = Some(ekey);
            }
        }
    }

    fn parsed_proxy(&self) -> Option<ProxyConfig> {
        let raw = self.proxy_url_input.trim();
        if raw.is_empty() {
            None
        } else {
            ProxyConfig::parse(raw).ok()
        }
    }

    fn ranked_results(&self) -> Vec<ProbeResult> {
        let mut res = lock(&self.results).clone();
        res.sort_by(rank_results);
        res
    }

    fn export_text(&self, tab: usize) -> String {
        let exp = generate_exports(&self.ranked_results(), self.parsed_proxy().as_ref());
        match tab {
            0 => exp.endpoints_text,
            1 => exp.subscription_base64,
            2 => exp.clash_yaml,
            _ => exp.singbox_json,
        }
    }

    fn abort_background(&mut self) {
        if let Some(run) = self.scan.take() {
            self.cancelled.store(true, Ordering::SeqCst);
            run.handle.abort();
        }
        if let Some(h) = self.diag_task.take() {
            h.abort();
        }
        if let Some(h) = self.speed_task.take() {
            h.abort();
        }
    }
}

/// Takes the output of a `JoinHandle` that is known to be finished.
fn futures_lite_now<T>(handle: JoinHandle<T>) -> Option<T> {
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};
    let mut fut = pin!(handle);
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Ok(v)) => Some(v),
        _ => None,
    }
}

fn dirs_hint() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join("Desktop")
    } else {
        PathBuf::from(".")
    }
}

/// Puts the terminal into TUI mode and restores it on drop, so every exit
/// path - normal quit, `?` on an I/O error, or a panic unwinding through
/// `run_interactive_tui` - leaves the user's shell usable.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> std::io::Result<Self> {
        enable_raw_mode()?;
        if let Err(e) = execute!(stdout(), EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(e);
        }
        Ok(Self)
    }
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen, Show);
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static>;

/// Installs a panic hook that restores the terminal before the panic message
/// is printed (otherwise it lands in the alternate screen and is lost), and
/// puts the previous hook back when dropped.
struct PanicHookGuard {
    previous: Option<Arc<PanicHook>>,
}

impl PanicHookGuard {
    fn install() -> Self {
        let previous: Arc<PanicHook> = Arc::new(std::panic::take_hook());
        let chained = previous.clone();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            chained(info);
        }));
        Self {
            previous: Some(previous),
        }
    }
}

impl Drop for PanicHookGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        // Drop our wrapper (and its clone of the previous hook) first.
        let _ = std::panic::take_hook();
        if let Some(prev) = self.previous.take().and_then(|p| Arc::try_unwrap(p).ok()) {
            std::panic::set_hook(prev);
        }
    }
}

/// Reads terminal events on a dedicated thread. `crossterm::event::poll`
/// and `read` block, and calling them from the async loop stalled a tokio
/// worker thread (and every task scheduled on it) for up to the poll timeout
/// on each iteration.
fn spawn_event_reader(stop: Arc<AtomicBool>) -> mpsc::Receiver<std::io::Result<Event>> {
    let (tx, rx) = mpsc::channel(64);
    std::thread::Builder::new()
        .name("tui-input".into())
        .spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let ev = match event::poll(Duration::from_millis(100)) {
                    Ok(true) => event::read(),
                    Ok(false) => continue,
                    Err(e) => Err(e),
                };
                let is_err = ev.is_err();
                if tx.blocking_send(ev).is_err() || is_err {
                    break;
                }
            }
        })
        .expect("spawning the TUI input thread");
    rx
}

pub async fn run_interactive_tui() -> Result<(), Box<dyn std::error::Error>> {
    let _panic_guard = PanicHookGuard::install();
    let _term_guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let stop_input = Arc::new(AtomicBool::new(false));
    let mut events = spawn_event_reader(stop_input.clone());

    let mut app = TuiApp::new();
    let mut frame_tick = tokio::time::interval(LIVE_FRAME);
    frame_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let result = async {
        let mut dirty = true;
        loop {
            if app.poll_background() {
                dirty = true;
            }
            if dirty {
                app.refresh_views();
                terminal.draw(|f| render_ui(f, &app))?;
                dirty = false;
            }

            tokio::select! {
                ev = events.recv() => {
                    let ev = match ev {
                        Some(ev) => ev?,
                        None => break,
                    };
                    match ev {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            if handle_key(&mut app, key.code, key.modifiers) {
                                break;
                            }
                            dirty = true;
                        }
                        Event::Resize(_, _) => dirty = true,
                        _ => {}
                    }
                }
                _ = frame_tick.tick() => {
                    // Animations and live counters only; idle screens stay
                    // untouched.
                    if app.is_busy() {
                        dirty = true;
                    }
                }
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    stop_input.store(true, Ordering::Relaxed);
    app.abort_background();
    drop(_term_guard);
    let _ = terminal.show_cursor();
    result
}

/// Handles one key press. Returns true when the app should quit.
fn handle_key(app: &mut TuiApp, code: KeyCode, modifiers: KeyModifiers) -> bool {
    // Global Ctrl+C: quit from anywhere (raw mode swallows SIGINT).
    if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
        return true;
    }

    if app.text_editing {
        let target = match app.config_row {
            1 => Some(&mut app.custom_input),
            9 => Some(&mut app.proxy_url_input),
            _ => None,
        };
        match code {
            KeyCode::Esc | KeyCode::Enter => app.text_editing = false,
            KeyCode::Backspace => {
                if let Some(t) = target {
                    t.pop();
                }
            }
            KeyCode::Char(c) if !modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(t) = target {
                    t.push(c);
                }
            }
            _ => {}
        }
        return false;
    }

    if app.file_input_mode {
        match code {
            KeyCode::Esc | KeyCode::Enter => app.file_input_mode = false,
            KeyCode::Backspace => {
                app.custom_file_path.pop();
            }
            KeyCode::Char(c) if !modifiers.contains(KeyModifiers::CONTROL) => {
                app.custom_file_path.push(c)
            }
            _ => {}
        }
        return false;
    }

    // Any deliberate key press acknowledges the previous status message.
    app.status_msg = None;

    match code {
        KeyCode::Char('q') => {
            if app.page == TuiPage::Home {
                return true;
            }
            app.page = TuiPage::Home;
            false
        }
        KeyCode::Esc => {
            app.page = TuiPage::Home;
            false
        }
        _ => handle_page_keys(app, code),
    }
}

fn handle_page_keys(app: &mut TuiApp, key: KeyCode) -> bool {
    match app.page {
        TuiPage::Home => match key {
            KeyCode::Up | KeyCode::Char('k') => {
                app.menu_idx = app.menu_idx.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if app.menu_idx < 5 {
                    app.menu_idx += 1;
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => match app.menu_idx {
                0 => {
                    // Auto Mode: diagnostics run in the background so the UI
                    // keeps drawing (and can be quit) while they take their
                    // several seconds.
                    app.page = TuiPage::AutoScanDiag;
                    start_diagnostics(app);
                }
                1 => {
                    // Advanced Mode
                    app.source_mode = 0;
                    app.page = TuiPage::Config;
                }
                2 => {
                    // Test IPs Mode (File picker & custom inspector)
                    let search_dirs =
                        vec![PathBuf::from("."), PathBuf::from("./data"), dirs_hint()];
                    app.discovered_files = scan_for_ip_files(&search_dirs);
                    app.selected_file_idx = 0;
                    app.page = TuiPage::TestIps;
                }
                3 => {
                    // Live Results Table
                    app.page = TuiPage::Scanning;
                }
                4 => {
                    // Architecture & About
                    app.page = TuiPage::About;
                }
                5 => {
                    // Quit
                    return true;
                }
                _ => {}
            },
            _ => {}
        },

        TuiPage::AutoScanDiag => match key {
            KeyCode::Enter | KeyCode::Char('s') => {
                if let Some(ref r) = app.diag_report {
                    app.workers_idx = 4; // Custom
                    app.custom_workers = r.recommended_workers.to_string();
                    app.timeout_idx = 3;
                    app.custom_timeout = r.recommended_timeout_secs.to_string();
                    app.count_idx = 4;
                    app.custom_count = r.recommended_count.to_string();
                    if start_scan_from_tui(app) {
                        app.page = TuiPage::Scanning;
                    }
                } else if !app.is_diagnosing {
                    start_diagnostics(app);
                }
            }
            KeyCode::Char('a') => {
                app.page = TuiPage::Config;
            }
            _ => {}
        },

        TuiPage::TestIps => match key {
            KeyCode::Up | KeyCode::Char('k') => {
                app.selected_file_idx = app.selected_file_idx.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if app.selected_file_idx + 1 < app.discovered_files.len() {
                    app.selected_file_idx += 1;
                }
            }
            KeyCode::Char('f') => {
                app.file_input_mode = true;
            }
            KeyCode::Enter => {
                // Test selected file or typed custom file
                let path = if !app.custom_file_path.trim().is_empty() {
                    PathBuf::from(app.custom_file_path.trim())
                } else if let Some(info) = app.discovered_files.get(app.selected_file_idx) {
                    info.path.clone()
                } else {
                    PathBuf::from("ips.txt")
                };

                app.source_mode = 2;
                app.custom_input = path.to_string_lossy().to_string();
                if start_scan_from_tui(app) {
                    app.page = TuiPage::Scanning;
                }
            }
            _ => {}
        },

        TuiPage::Config => match key {
            KeyCode::Up | KeyCode::Char('k') => {
                app.config_row = app.config_row.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if app.config_row < 10 {
                    app.config_row += 1;
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                let field = match app.config_row {
                    0 => Some(&mut app.source_mode),
                    2 => Some(&mut app.count_idx),
                    3 => Some(&mut app.workers_idx),
                    4 => Some(&mut app.timeout_idx),
                    5 => Some(&mut app.port_focus),
                    6 => Some(&mut app.mode_idx),
                    _ => None,
                };
                if let Some(v) = field {
                    *v = v.saturating_sub(1);
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                let field = match app.config_row {
                    0 => Some((&mut app.source_mode, 2)),
                    2 => Some((&mut app.count_idx, 4)),
                    3 => Some((&mut app.workers_idx, 4)),
                    4 => Some((&mut app.timeout_idx, 3)),
                    5 => Some((&mut app.port_focus, PORTS_AVAILABLE.len() - 1)),
                    6 => Some((&mut app.mode_idx, 2)),
                    _ => None,
                };
                if let Some((v, max)) = field {
                    if *v < max {
                        *v += 1;
                    }
                }
            }
            KeyCode::Char(' ') => match app.config_row {
                5 => {
                    let idx = app.port_focus;
                    app.port_selected[idx] = !app.port_selected[idx];
                }
                7 => app.require_ws = !app.require_ws,
                8 => app.neighbor_scan = !app.neighbor_scan,
                _ => {}
            },
            KeyCode::Enter => match app.config_row {
                1 | 9 => {
                    app.text_editing = true;
                }
                10 => {
                    let started = start_scan_from_tui(app);
                    app.page = if started { TuiPage::Scanning } else { app.page };
                }
                _ => {}
            },
            _ => {}
        },

        TuiPage::Scanning => match key {
            KeyCode::Tab => {
                app.page = TuiPage::Export;
            }
            KeyCode::Char('s') | KeyCode::Char(' ') => {
                if app.is_scanning {
                    let was_paused = app.paused.fetch_xor(true, Ordering::SeqCst);
                    app.status_msg = Some(
                        if was_paused {
                            "Scan resumed"
                        } else {
                            "Scan paused"
                        }
                        .to_string(),
                    );
                } else {
                    app.status_msg = Some("No scan is running".to_string());
                }
            }
            KeyCode::Char('x') => {
                if app.is_scanning {
                    app.cancelled.store(true, Ordering::SeqCst);
                    app.status_msg = Some("Stopping scan...".to_string());
                }
            }
            KeyCode::Char('o') => {
                app.sort_mode = (app.sort_mode + 1) % 4;
            }
            KeyCode::Char('c') => {
                app.refresh_views();
                if let Some(r) = app.sorted_view.get(app.selected_result_idx) {
                    let text = format!("{}:{}", r.ip, r.port);
                    app.status_msg = Some(clipboard_status(copy_to_clipboard(&text), &text));
                }
            }
            KeyCode::Char('t') => {
                start_speed_test_from_tui(app);
                app.page = TuiPage::SpeedTest;
            }
            KeyCode::Char('e') => {
                app.page = TuiPage::Export;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.selected_result_idx = app.selected_result_idx.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.refresh_views();
                if app.selected_result_idx + 1 < app.sorted_view.len() {
                    app.selected_result_idx += 1;
                }
            }
            KeyCode::Home => app.selected_result_idx = 0,
            KeyCode::End => {
                app.refresh_views();
                app.selected_result_idx = app.sorted_view.len().saturating_sub(1);
            }
            _ => {}
        },

        TuiPage::SpeedTest => match key {
            KeyCode::Tab | KeyCode::Char('r') => {
                app.page = TuiPage::Scanning;
            }
            KeyCode::Char('e') => {
                app.page = TuiPage::Export;
            }
            KeyCode::Char('c') => {
                if let Some(s) = app.speed_results.first() {
                    let text = format!("{}:{}", s.ip, s.port);
                    app.status_msg = Some(clipboard_status(copy_to_clipboard(&text), &text));
                }
            }
            _ => {}
        },

        TuiPage::Export => match key {
            KeyCode::Tab => {
                app.export_tab = (app.export_tab + 1) % 4;
            }
            KeyCode::Char('1') => app.export_tab = 0,
            KeyCode::Char('2') => app.export_tab = 1,
            KeyCode::Char('3') => app.export_tab = 2,
            KeyCode::Char('4') => app.export_tab = 3,
            KeyCode::Char('e') | KeyCode::Enter => {
                app.status_msg = Some(match save_exports(app) {
                    Ok(dir) => format!("Saved all exports to {}", dir.display()),
                    Err(e) => format!("Export failed: {}", e),
                });
            }
            KeyCode::Char('c') => {
                let text = app.export_text(app.export_tab);
                app.status_msg = Some(if copy_to_clipboard(&text) {
                    "Copied active export format to clipboard".to_string()
                } else {
                    "No clipboard tool found (install wl-copy, xclip or xsel)".to_string()
                });
            }
            _ => {}
        },

        TuiPage::About => {
            if matches!(key, KeyCode::Enter | KeyCode::Char(' ')) {
                app.page = TuiPage::Home;
            }
        }
    }
    false
}

fn start_diagnostics(app: &mut TuiApp) {
    if app.is_diagnosing {
        return;
    }
    app.is_diagnosing = true;
    app.diag_report = None;
    app.diag_task = Some(tokio::spawn(async move {
        let resolver = FastResolver::new();
        run_diagnostics(&resolver).await
    }));
}

/// Writes every export format to `./zero_ip_export/`. The exports contain the
/// proxy credentials, so they are no longer written to a fixed, predictable
/// directory under the world-writable `/tmp`.
fn save_exports(app: &TuiApp) -> std::io::Result<PathBuf> {
    let out_dir = std::env::current_dir()?.join("zero_ip_export");
    std::fs::create_dir_all(&out_dir)?;
    let exp = generate_exports(&app.ranked_results(), app.parsed_proxy().as_ref());
    std::fs::write(out_dir.join("endpoints.txt"), &exp.endpoints_text)?;
    std::fs::write(out_dir.join("clash.yaml"), &exp.clash_yaml)?;
    std::fs::write(out_dir.join("singbox.json"), &exp.singbox_json)?;
    std::fs::write(out_dir.join("subscription.txt"), &exp.subscription_base64)?;
    Ok(out_dir)
}

/// Starts a scan with the current settings. Returns false (with a status
/// message) if there is nothing to scan.
fn start_scan_from_tui(app: &mut TuiApp) -> bool {
    let mut custom_cidrs = Vec::new();

    if app.source_mode == 1 {
        for piece in app.custom_input.split([',', ' ', '\n']) {
            let trimmed = piece.trim();
            if !trimmed.is_empty() {
                custom_cidrs.push(trimmed.to_string());
            }
        }
    } else if app.source_mode == 2 {
        let path = PathBuf::from(app.custom_input.trim());
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        // Accept "ip,extra,columns" and "ip:port" style lines.
                        let field = trimmed.split(',').next().unwrap_or("").trim();
                        custom_cidrs.push(field.to_string());
                    }
                }
            }
            Err(e) => {
                app.status_msg = Some(format!("Cannot read {}: {}", path.display(), e));
                return false;
            }
        }
    }

    let parsed_proxy = app.parsed_proxy();
    if !app.proxy_url_input.trim().is_empty() && parsed_proxy.is_none() {
        app.status_msg =
            Some("Proxy link could not be parsed; scanning without Phase 2 validation".to_string());
    }

    let use_builtin = app.source_mode == 0;
    let ip_source = Arc::new(IpSource::new(true, false, &custom_cidrs, use_builtin));
    if ip_source.is_exhausted() {
        app.status_msg = Some("No valid IPv4 addresses or CIDRs to scan".to_string());
        return false;
    }

    let ports = app.get_selected_ports();
    let port = ports.first().copied().unwrap_or(443);

    let probe_config = ProbeConfig {
        port,
        mode: app.get_mode(),
        tries: 1,
        timeout: app.get_timeout(),
        sni: parsed_proxy.as_ref().map(|p| p.sni.clone()),
        speed_bytes: 0,
        ws_host: parsed_proxy.as_ref().map(|p| p.host.clone()),
        ws_path: parsed_proxy.as_ref().map(|p| p.path.clone()),
        require_ws: app.require_ws || parsed_proxy.as_ref().is_some_and(|p| p.transport == "ws"),
        check_dpi_hold: true,
        jitter_range_ms: (5, 15),
    };

    let target = app.get_count();
    let engine_config = ScanEngineConfig {
        concurrency: app.get_workers(),
        target_count: target,
        probe_config,
        neighbor_scan: app.neighbor_scan,
        proxy_config: parsed_proxy,
    };

    // Stop any previous run, then give the new one its own state. Reusing
    // the old flags let a still-running engine keep writing into the new
    // scan's counters, and never reset the rate clock.
    if let Some(run) = app.scan.take() {
        app.cancelled.store(true, Ordering::SeqCst);
        run.handle.abort();
    }
    app.stats = Arc::new(AtomicStats::new());
    app.cancelled = Arc::new(AtomicBool::new(false));
    app.paused = Arc::new(AtomicBool::new(false));
    app.results = Arc::new(Mutex::new(Vec::new()));
    app.results_version = Arc::new(AtomicU64::new(0));
    app.view_key = None;
    app.export_key = None;
    app.selected_result_idx = 0;
    app.scan_target = target;
    app.last_stats = (0, 0, 0, 0);

    let engine = ScanEngine::new_with_state(
        engine_config,
        ip_source,
        app.stats.clone(),
        app.cancelled.clone(),
    )
    .with_pause_flag(app.paused.clone());

    let results = app.results.clone();
    let version = app.results_version.clone();
    let done = Arc::new(AtomicBool::new(false));
    let done_flag = done.clone();

    let handle = tokio::spawn(async move {
        let on_hit = {
            let results = results.clone();
            let version = version.clone();
            // Pushed synchronously: the old code spawned a task per hit,
            // which could land after the final list was stored and
            // duplicate entries.
            move |hit: &ProbeResult| {
                lock(&results).push(hit.clone());
                version.fetch_add(1, Ordering::Release);
            }
        };
        let final_results = engine.run(on_hit).await;
        *lock(&results) = final_results;
        version.fetch_add(1, Ordering::Release);
        done_flag.store(true, Ordering::Release);
    });

    app.scan = Some(ScanRun { handle, done });
    app.is_scanning = true;
    true
}

fn start_speed_test_from_tui(app: &mut TuiApp) {
    if app.is_speed_testing {
        app.status_msg = Some("Speed test already running".to_string());
        return;
    }
    let shortlist: Vec<ProbeResult> = app.ranked_results().into_iter().take(10).collect();
    if shortlist.is_empty() {
        app.status_msg = Some("No green endpoints to speed test".to_string());
        return;
    }

    app.is_speed_testing = true;
    app.speed_results.clear();
    let sni = app.parsed_proxy().map(|p| p.sni).filter(|s| !s.is_empty());
    app.speed_task = Some(tokio::spawn(async move {
        let tester = SpeedTester::new(sni, 256 * 1024, Duration::from_secs(6));
        tester.test_shortlist(&shortlist, 4).await
    }));
}

fn clipboard_status(ok: bool, text: &str) -> String {
    if ok {
        format!("Copied {} to clipboard", text)
    } else {
        "No clipboard tool found (install wl-copy, xclip or xsel)".to_string()
    }
}

/// Copies `text` using the first available clipboard tool. The child is
/// waited for, so no zombie processes accumulate.
fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let candidates: &[(&str, &[&str])] = &[
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
        ("pbcopy", &[]),
        ("clip.exe", &[]),
    ];
    for (cmd, args) in candidates {
        let Ok(mut child) = Command::new(cmd)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        let wrote = child
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(text.as_bytes()).is_ok());
        // stdin is closed here, so the tool sees EOF and exits (wl-copy and
        // xclip fork a server and return immediately).
        if child.wait().is_ok_and(|s| s.success()) && wrote {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// DYNAMIC RESPONSIVE RATATUI RENDERING ENGINE
// ---------------------------------------------------------------------------

fn render_ui(f: &mut Frame, app: &TuiApp) {
    let area = f.area();

    // Responsive dynamic layout: If terminal is extremely compact (< 60 cols or < 12 lines),
    // render a clean condensed status view showing vital metrics rather than crashing or overflowing.
    if area.width < 60 || area.height < 12 {
        let (tested, healthy, failed, in_flight, speed) = app.stats.snapshot();
        let compact_lines = vec![
            Line::from(vec![Span::styled(
                "⚡ ZERO-IP-SCANNER [COMPACT MODE]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(format!(
                "Size: {}x{} (Resize for full desk)",
                area.width, area.height
            )),
            Line::from(format!(
                "Stats: Tested: {} | OK: {} | Fail: {}",
                tested, healthy, failed
            )),
            Line::from(format!(
                "Speed: {:.1} ip/s | In-Flight: {}",
                speed, in_flight
            )),
            Line::from("Hotkeys: [q] quit  [s] pause/resume  [x] stop  [Esc] home"),
        ];
        let p = Paragraph::new(compact_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Zero-IP Compact "),
        );
        f.render_widget(p, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Top Navigation Bar
            Constraint::Min(8),    // Main Dynamic Content Area
            Constraint::Length(2), // Status Bar & Hotkeys
        ])
        .split(area);

    let nav_titles = vec![
        Line::from(" [H] Home "),
        Line::from(" [A] Auto Mode "),
        Line::from(" [C] Advanced "),
        Line::from(" [T] Test IPs "),
        Line::from(" [R] Results "),
        Line::from(" [E] Export "),
    ];
    let active_nav_idx = match app.page {
        TuiPage::Home => 0,
        TuiPage::AutoScanDiag => 1,
        TuiPage::Config => 2,
        TuiPage::TestIps => 3,
        TuiPage::Scanning => 4,
        TuiPage::SpeedTest => 4,
        TuiPage::Export => 5,
        TuiPage::About => 0,
    };
    let nav_tabs = Tabs::new(nav_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Zero-IP-Scanner (Responsive Signal Desk) "),
        )
        .select(active_nav_idx)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(nav_tabs, chunks[0]);

    match app.page {
        TuiPage::Home => render_home_page(f, chunks[1], app),
        TuiPage::AutoScanDiag => render_auto_diag_page(f, chunks[1], app),
        TuiPage::Config => render_config_page(f, chunks[1], app),
        TuiPage::TestIps => render_test_ips_page(f, chunks[1], app),
        TuiPage::Scanning => render_scanning_page(f, chunks[1], app),
        TuiPage::SpeedTest => render_speed_test_page(f, chunks[1], app),
        TuiPage::Export => render_export_page(f, chunks[1], app),
        TuiPage::About => render_about_page(f, chunks[1]),
    }

    let status_hint = if let Some(ref msg) = app.status_msg {
        format!("  [!] {}    ", msg)
    } else {
        match app.page {
            TuiPage::Home => "  ↑/↓ select   Enter launch   q quit".to_string(),
            TuiPage::AutoScanDiag => {
                "  s start auto-scan   a open advanced config   Esc home".to_string()
            }
            TuiPage::TestIps => {
                "  ↑/↓ choose file   f type custom path   Enter scan file   Esc home".to_string()
            }
            TuiPage::Config => {
                if app.text_editing {
                    "  [EDITING TEXT] Type value, Enter/Esc to confirm".to_string()
                } else {
                    "  ↑/↓ row   ←/→ option   Space toggle   Enter edit/start   Esc home"
                        .to_string()
                }
            }
            TuiPage::Scanning => {
                "  s pause/resume   x stop   t speed-test   c copy   o sort   Tab export   Esc home"
                    .to_string()
            }
            TuiPage::SpeedTest => {
                "  c copy fastest   Tab results   e export   Esc home".to_string()
            }
            TuiPage::Export => {
                "  1-4 format   e save all to disk   c copy active   Tab switch   Esc home"
                    .to_string()
            }
            TuiPage::About => "  Enter / Esc back to home".to_string(),
        }
    };

    let status_para = Paragraph::new(Line::from(vec![Span::styled(
        status_hint,
        Style::default().fg(Color::Yellow),
    )]));
    f.render_widget(status_para, chunks[2]);
}

fn render_home_page(f: &mut Frame, area: Rect, app: &TuiApp) {
    let main_chunks = if area.width > 90 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area)
    };

    let menu_items = [
        (
            "1. 🚀 Auto Mode (Speed Diagnostic & Auto-Tune)",
            "Test connection & auto-configure optimal workers",
        ),
        (
            "2. ⚙️  Advanced Scan Mode",
            "Full manual control: ports, timeout, workers, SNI, WebSocket",
        ),
        (
            "3. 📁 Test Custom IPs / File Inspector",
            "Scan & inspect ips.txt or system IP lists",
        ),
        (
            "4. 📊 View Live Results Table",
            "Inspect discovered endpoints, latency, and colo",
        ),
        (
            "5. 📖 Cloudflare DNS Architecture & About",
            "Big Pineapple wire cache & DPI countermeasures",
        ),
        ("6. ❌ Quit Scanner", "Exit to terminal cleanly"),
    ];

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  ⚡ ZERO-IP-SCANNER ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("- Cloudflare Edge Discovery Engine in Rust"),
        ]),
        Line::from(""),
    ];

    for (idx, (title, desc)) in menu_items.iter().enumerate() {
        let is_selected = idx == app.menu_idx;
        let style = if is_selected {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
                .bg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        };

        lines.push(Line::from(vec![Span::styled(
            format!("  {} {:<48}", if is_selected { "▶" } else { " " }, title),
            style,
        )]));
        if area.width > 80 {
            lines.push(Line::from(vec![
                Span::raw("     "),
                Span::styled(format!("└─ {}", desc), Style::default().fg(Color::Gray)),
            ]));
        }
    }

    let menu_para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Choose Mode "),
    );
    f.render_widget(menu_para, main_chunks[0]);

    let info_text = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "Engine Telemetry:",
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Green),
        )]),
        Line::from("  • Cloudflare Big Pineapple DNS Wire Cache"),
        Line::from("  • Single-Flight DNS query coalescing"),
        Line::from("  • Offline Iranian ISP Database (9,804 CIDRs)"),
        Line::from("  • Iranian DPI Idle-Hold Stability Check"),
        Line::from("  • Native VLESS & Trojan validation"),
        Line::from("  • Zero TIME_WAIT sockets (SO_LINGER=0)"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Quick Start:",
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Yellow),
        )]),
        Line::from("  Press Enter on [Auto Mode] for automatic network profiling!"),
    ];
    let info_para = Paragraph::new(info_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" System Status "),
    );
    f.render_widget(info_para, main_chunks[1]);
}

fn render_auto_diag_page(f: &mut Frame, area: Rect, app: &TuiApp) {
    let mut lines = Vec::new();

    if app.is_diagnosing {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            format!(
                "  {} Running Live Network Diagnostics to Cloudflare Edge...",
                app.spinner()
            ),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]));
        lines.push(Line::from(""));
        lines.push(Line::from(
            "  • Measuring TCP connect latency to Anycast...",
        ));
        lines.push(Line::from(
            "  • Testing TLS handshake & cipher negotiation...",
        ));
        lines.push(Line::from(
            "  • Sampling download throughput & packet loss...",
        ));
        lines.push(Line::from(
            "  • Querying offline Iranian ISP Radix table...",
        ));
        lines.push(Line::from(""));
        lines.push(Line::from("  Please wait a few seconds..."));
    } else if let Some(ref r) = app.diag_report {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "  ⚡ Network Profile & Auto-Tune Report",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::raw("  Detected Provider:       "),
            Span::styled(
                &r.isp_name,
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        if let Some(ref cip) = r.client_ip {
            lines.push(Line::from(vec![
                Span::raw("  Your Public WAN IP:      "),
                Span::styled(
                    cip,
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        }
        lines.push(Line::from(format!(
            "  Anycast RTT:             {:.1} ms",
            r.ping_ms
        )));
        lines.push(Line::from(format!(
            "  TLS Handshake Time:      {:.1} ms",
            r.tls_handshake_ms
        )));
        lines.push(Line::from(format!(
            "  Edge Download Speed:     {:.2} Mbps",
            r.download_mbps
        )));
        lines.push(Line::from(format!(
            "  Packet Loss:             {:.0}%",
            r.packet_loss_pct
        )));
        lines.push(Line::from(vec![
            Span::raw("  Network Classification:  "),
            Span::styled(
                r.network_quality,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "  Recommended Auto-Tuned Settings:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]));
        lines.push(Line::from(format!(
            "  • Concurrency Workers:   {} parallel tasks",
            r.recommended_workers
        )));
        lines.push(Line::from(format!(
            "  • Per-Probe Timeout:     {} seconds",
            r.recommended_timeout_secs
        )));
        lines.push(Line::from(format!(
            "  • Scan Candidate Pool:   {} endpoints",
            r.recommended_count
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(
                "  ▶ Press Enter or 's' to START AUTO-SCAN NOW",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  or 'a' for Advanced Config"),
        ]));
    } else {
        lines.push(Line::from(
            "  No diagnostic report generated. Press Enter to run diagnostics.",
        ));
    }

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Auto-Scan Diagnostics & Profiler "),
    );
    f.render_widget(p, area);
}

fn render_test_ips_page(f: &mut Frame, area: Rect, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Custom input header
            Constraint::Min(8),    // Discovered files list
        ])
        .split(area);

    let input_display = if app.custom_file_path.is_empty() {
        "Type or paste custom path (press 'f' to edit)...".to_string()
    } else {
        app.custom_file_path.clone()
    };
    let input_style = if app.file_input_mode {
        Style::default().fg(Color::Green).bg(Color::DarkGray)
    } else {
        Style::default().fg(Color::White)
    };

    let input_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  Custom File Path: "),
            Span::styled(format!(" {} ", input_display), input_style),
            Span::styled(
                " [Press 'f' to type, Enter to scan]",
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ];
    let input_p = Paragraph::new(input_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Direct File Destination "),
    );
    f.render_widget(input_p, chunks[0]);

    // Table of inspected files
    let header_cells = [
        "#",
        "Filename",
        "Path",
        "Valid IPs / CIDRs",
        "Size",
        "Preview Samples",
    ]
    .iter()
    .map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).height(1);

    let rows = app.discovered_files.iter().enumerate().map(|(i, f_info)| {
        let is_sel = i == app.selected_file_idx;
        let style = if is_sel {
            Style::default()
                .fg(Color::Yellow)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        let preview = f_info.sample_ips.join(", ");

        Row::new(vec![
            Cell::from(format!("{}", i + 1)),
            Cell::from(f_info.name.clone()).style(style),
            Cell::from(f_info.path.to_string_lossy().to_string()),
            Cell::from(format!("{} entries", f_info.valid_count))
                .style(Style::default().fg(Color::Green)),
            Cell::from(format!("{} B", f_info.size_bytes)),
            Cell::from(preview).style(Style::default().fg(Color::Gray)),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(16),
            Constraint::Length(24),
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Valid IP Files Detected on System (↑/↓ choose, Enter test) "),
    );
    f.render_widget(table, chunks[1]);
}

fn render_config_page(f: &mut Frame, area: Rect, app: &TuiApp) {
    let mut rows = Vec::new();

    let sources = [
        "Random Cloudflare Ranges",
        "Custom IP / CIDR Input",
        "From File (ips.txt)",
    ];
    let mut src_spans = Vec::new();
    for (i, &s) in sources.iter().enumerate() {
        if i == app.source_mode {
            src_spans.push(Span::styled(
                format!(" [✓ {}] ", s),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            src_spans.push(Span::raw(format!("  {}  ", s)));
        }
    }
    rows.push((0, "IP Source:", Line::from(src_spans)));

    let input_hint = if app.source_mode == 1 {
        if app.custom_input.is_empty() {
            "Type IPs or CIDRs (e.g. 104.16.1.1, 172.64.0.0/16)".to_string()
        } else {
            app.custom_input.clone()
        }
    } else if app.source_mode == 2 {
        if app.custom_input.is_empty() {
            "Path to IP list file (e.g. ./ips.txt)".to_string()
        } else {
            app.custom_input.clone()
        }
    } else {
        "(Disabled: Using 632 embedded Cloudflare subnets)".to_string()
    };
    let input_style = if app.config_row == 1 && app.text_editing {
        Style::default().fg(Color::Green).bg(Color::DarkGray)
    } else if app.source_mode == 0 {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::White)
    };
    rows.push((
        1,
        "Custom Input:",
        Line::from(vec![Span::styled(
            format!("  {}  ", input_hint),
            input_style,
        )]),
    ));

    let counts = ["500", "1,000", "5,000", "20,000", "Custom"];
    let mut cnt_spans = Vec::new();
    for (i, &c) in counts.iter().enumerate() {
        if i == app.count_idx {
            cnt_spans.push(Span::styled(
                format!(" [{}] ", c),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            cnt_spans.push(Span::raw(format!("  {}  ", c)));
        }
    }
    rows.push((2, "Scan Count:", Line::from(cnt_spans)));

    let workers = [
        "25 (Safe)",
        "50 (Default)",
        "100 (Fast)",
        "200 (Extreme)",
        "Custom",
    ];
    let mut wrk_spans = Vec::new();
    for (i, &w) in workers.iter().enumerate() {
        if i == app.workers_idx {
            wrk_spans.push(Span::styled(
                format!(" [{}] ", w),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            wrk_spans.push(Span::raw(format!("  {}  ", w)));
        }
    }
    rows.push((3, "Workers:", Line::from(wrk_spans)));

    let timeouts = ["2s (Aggressive)", "3s (Balanced)", "5s (Default)", "Custom"];
    let mut to_spans = Vec::new();
    for (i, &t) in timeouts.iter().enumerate() {
        if i == app.timeout_idx {
            to_spans.push(Span::styled(
                format!(" [{}] ", t),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            to_spans.push(Span::raw(format!("  {}  ", t)));
        }
    }
    rows.push((4, "Timeout:", Line::from(to_spans)));

    let mut port_spans = Vec::new();
    for (i, &port) in PORTS_AVAILABLE.iter().enumerate() {
        let is_sel = app.port_selected[i];
        let is_foc = app.config_row == 5 && app.port_focus == i;
        let prefix = if is_sel { "✓ " } else { "  " };
        let style = if is_foc {
            Style::default()
                .fg(Color::Yellow)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else if is_sel {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Gray)
        };
        port_spans.push(Span::styled(format!(" {}{} ", prefix, port), style));
    }
    rows.push((5, "Target Ports:", Line::from(port_spans)));

    let modes = ["HTTP (/cdn-cgi/trace)", "TLS Handshake", "TCP Connect Only"];
    let mut mode_spans = Vec::new();
    for (i, &m) in modes.iter().enumerate() {
        if i == app.mode_idx {
            mode_spans.push(Span::styled(
                format!(" [{}] ", m),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            mode_spans.push(Span::raw(format!("  {}  ", m)));
        }
    }
    rows.push((6, "Probe Mode:", Line::from(mode_spans)));

    let ws_span = if app.require_ws {
        Span::styled(
            " [ON (Required for health)] ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" [OFF] ", Style::default().fg(Color::DarkGray))
    };
    rows.push((7, "WebSocket:", Line::from(vec![ws_span])));

    let n_span = if app.neighbor_scan {
        Span::styled(
            " [ON (Scan +-32 adjacent on hit)] ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" [OFF] ", Style::default().fg(Color::DarkGray))
    };
    rows.push((8, "Neighbors:", Line::from(vec![n_span])));

    let proxy_hint = if app.proxy_url_input.is_empty() {
        "Paste VLESS / Trojan / VMess link (Optional for Phase 2 validation)".to_string()
    } else {
        app.proxy_url_input.clone()
    };
    let proxy_style = if app.config_row == 9 && app.text_editing {
        Style::default().fg(Color::Green).bg(Color::DarkGray)
    } else {
        Style::default().fg(Color::White)
    };
    rows.push((
        9,
        "Proxy Link:",
        Line::from(vec![Span::styled(
            format!("  {}  ", proxy_hint),
            proxy_style,
        )]),
    ));

    let btn_style = if app.config_row == 10 {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    };
    rows.push((
        10,
        "",
        Line::from(vec![Span::styled(
            "   ▶ [ PRESS ENTER TO START SCAN ]   ",
            btn_style,
        )]),
    ));

    let mut form_lines = Vec::new();
    form_lines.push(Line::from(""));
    for (row_num, label, content) in rows {
        let is_active_row = app.config_row == row_num;
        let label_style = if is_active_row {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };

        let pointer = if is_active_row { "▶ " } else { "  " };
        form_lines.push(Line::from(vec![
            Span::styled(pointer, label_style),
            Span::styled(format!("{:<14}", label), label_style),
            Span::raw(" "),
        ]));
        let mut spans = vec![Span::raw("                 ")];
        spans.extend(content.spans);
        form_lines.push(Line::from(spans));
        form_lines.push(Line::from(""));
    }

    let form_para = Paragraph::new(form_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Advanced Scan Configuration "),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(form_para, area);
}

fn render_scanning_page(f: &mut Frame, area: Rect, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(6)])
        .split(area);

    let (tested, healthy, failed, in_flight, speed) = app.stats.snapshot();
    let ratio = if app.scan_target > 0 {
        tested as f64 / app.scan_target as f64
    } else if tested + in_flight > 0 {
        tested as f64 / (tested + in_flight) as f64
    } else {
        0.0
    }
    .clamp(0.0, 1.0);

    let status = if !app.is_scanning {
        if tested > 0 {
            "DONE".to_string()
        } else {
            "IDLE".to_string()
        }
    } else if app.cancelled.load(Ordering::Relaxed) {
        "STOPPING".to_string()
    } else if app.paused.load(Ordering::Relaxed) {
        "PAUSED".to_string()
    } else {
        format!("{} ACTIVE", app.spinner())
    };
    let gauge_text = format!(
        "Tested: {} | Green: {} | Failed: {} | In-Flight: {} | Rate: {:.1} ip/s | {}",
        tested, healthy, failed, in_flight, speed, status
    );
    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Engine Telemetry "),
        )
        .gauge_style(Style::default().fg(Color::Green).bg(Color::Black))
        .ratio(ratio)
        .label(gauge_text);
    f.render_widget(gauge, chunks[0]);

    let results = &app.sorted_view;
    let header_cells = [
        "#",
        "Endpoint",
        "Latency",
        "Loss",
        "Jitter",
        "Colo",
        "ISP / ASN",
    ]
    .iter()
    .map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).height(1);

    // Keep the selected row visible, centred when possible, without scrolling
    // past the end of the list.
    let visible_rows = chunks[1].height.saturating_sub(3).max(1) as usize;
    let selected = app.selected_result_idx.min(results.len().saturating_sub(1));
    let offset = selected
        .saturating_sub(visible_rows / 2)
        .min(results.len().saturating_sub(visible_rows));

    let rows = results
        .iter()
        .enumerate()
        .skip(offset)
        .take(visible_rows)
        .map(|(i, r)| {
            let isp = if let Some(ref s) = r.isp {
                s.clone()
            } else if let Some(asn) = r.asn {
                format!("AS{}", asn)
            } else {
                "Cloudflare".to_string()
            };
            let row = Row::new(vec![
                Cell::from(format!("{}", i + 1)),
                Cell::from(format!("{}:{}", r.ip, r.port)).style(Style::default().fg(Color::Green)),
                Cell::from(format!("{:.1}ms", r.avg_latency_ms())),
                Cell::from(format!("{:.0}%", r.packet_loss_percent())),
                Cell::from(format!("{:.1}ms", r.jitter_ms())),
                Cell::from(r.colo.as_deref().unwrap_or("---").to_string())
                    .style(Style::default().fg(Color::Cyan)),
                Cell::from(isp),
            ]);
            if i == selected {
                row.style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                row
            }
        });

    let sort_label = match app.sort_mode {
        0 => "Latency (Asc)",
        1 => "Packet Loss (Asc)",
        2 => "Jitter (Asc)",
        _ => "Colo",
    };

    let col_constraints = if chunks[1].width < 80 {
        vec![
            Constraint::Length(4),
            Constraint::Length(18),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Min(6),
        ]
    } else {
        vec![
            Constraint::Length(5),
            Constraint::Length(22),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(16),
        ]
    };

    let table = Table::new(rows, col_constraints).header(header).block(
        Block::default().borders(Borders::ALL).title(format!(
            " Discovered Endpoints ({}) [Sort: {}] ",
            results.len(),
            sort_label
        )),
    );

    f.render_widget(table, chunks[1]);
}

fn render_speed_test_page(f: &mut Frame, area: Rect, app: &TuiApp) {
    let header_cells = ["#", "Endpoint", "Download Speed", "TTFB", "Colo"]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells).height(1);

    let rows = app.speed_results.iter().enumerate().map(|(i, s)| {
        Row::new(vec![
            Cell::from(format!("{}", i + 1)),
            Cell::from(format!("{}:{}", s.ip, s.port)).style(Style::default().fg(Color::Green)),
            Cell::from(format!("{:.2} Mbps", s.download_mbps)).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from(format!("{:.1}ms", s.ttfb_ms)),
            Cell::from(s.colo.as_deref().unwrap_or("---")).style(Style::default().fg(Color::Cyan)),
        ])
    });

    let title = if app.is_speed_testing {
        format!(" {} Post-Stop Speed Testing in Progress... ", app.spinner())
    } else {
        " Post-Stop Speed Test Leaderboard ".to_string()
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(22),
            Constraint::Length(18),
            Constraint::Length(12),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title));

    f.render_widget(table, area);
}

fn render_export_page(f: &mut Frame, area: Rect, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(area);

    let tabs = Tabs::new(vec![
        Line::from(" [1] Raw Endpoints "),
        Line::from(" [2] Subscription (Base64) "),
        Line::from(" [3] Clash Meta YAML "),
        Line::from(" [4] Sing-box JSON "),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Export Formats "),
    )
    .select(app.export_tab)
    .style(Style::default().fg(Color::DarkGray))
    .highlight_style(
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(tabs, chunks[0]);

    // Built by `refresh_views` only when results/tab/proxy change.
    let para = Paragraph::new(app.export_preview.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Export Preview (Press 'e' to save to ./zero_ip_export, 'c' to copy) "),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(para, chunks[1]);
}

fn render_about_page(f: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from(vec![Span::styled("  Zero-IP-Scanner v0.1.0 (Rust Edition)", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))]),
        Line::from("  Engineered for hostile, filtered, and DPI-throttled networks."),
        Line::from(""),
        Line::from(vec![Span::styled("  Key Architectural Upgrades from Cloudflare DNS (1.1.1.1):", Style::default().add_modifier(Modifier::BOLD))]),
        Line::from("  • Box<[u8]> contiguous wire cache stripping allocator capacity overhead"),
        Line::from("  • Single-flight query coalescing (eliminating redundant upstream queries)"),
        Line::from("  • RFC 8767 Stale-While-Revalidate resilient DNS resolution"),
        Line::from("  • O(log N) weighted mathematical candidate sampling with RoaringBitmap deduplication"),
        Line::from("  • 9,804 Iranian ISP prefixes embedded for offline 0ms detection"),
        Line::from("  • DPI idle-hold stability testing to defeat TCP RST packet injection"),
        Line::from(""),
        Line::from(vec![Span::styled("  Press Enter or Esc to return to Home Menu", Style::default().fg(Color::Yellow))]),
    ];

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Architecture & Engine Notes "),
    );
    f.render_widget(para, area);
}
