//! How much CPU and memory the client uses, next to everything else running.
//!
//! Sampling happens on its own thread, never on the render loop: walking the
//! process table costs a few milliseconds and a syscall per process. How
//! much it walks depends on [`UsageScope`]:
//!
//! * `Off` — the thread sleeps on its control channel and costs nothing.
//! * `SelfOnly` — only this process, every two seconds, for the status bar.
//! * `Everything` — every process, grouped into apps, while the Activity page
//!   is on screen.
//!
//! CPU figures are a share of the whole machine (all cores = 100 %), the way
//! Task Manager reports them, so the client's number and a browser's number
//! can be compared directly.

use std::collections::HashMap;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sysinfo::{Pid, Process, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

/// Samples kept for the history graphs: two minutes at the self-only rate.
pub const HISTORY_LEN: usize = 60;

const SELF_INTERVAL: Duration = Duration::from_secs(2);
const ALL_INTERVAL: Duration = Duration::from_secs(2);

/// How much the sampler should look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageScope {
    Off,
    SelfOnly,
    Everything,
}

/// One app: every process sharing a name, summed.
#[derive(Debug, Clone, PartialEq)]
pub struct AppUsage {
    pub name: String,
    /// Share of the whole machine, 0..=100.
    pub cpu: f32,
    /// Resident memory, bytes.
    pub memory: u64,
    pub processes: u32,
    pub is_self: bool,
}

/// What the Activity page and the status bar draw from.
#[derive(Debug, Clone, Default)]
pub struct UsageSnapshot {
    /// Share of the whole machine, 0..=100.
    pub self_cpu: f32,
    pub self_memory: u64,
    /// OS threads in this process, where the platform exposes it cheaply.
    pub self_threads: Option<u32>,
    /// Filled only for an `Everything` sample.
    pub system: Option<SystemUsage>,
}

#[derive(Debug, Clone, Default)]
pub struct SystemUsage {
    pub cpu: f32,
    pub memory_used: u64,
    pub memory_total: u64,
    pub cores: usize,
    pub process_count: usize,
    /// Every app, highest CPU first.
    pub apps: Vec<AppUsage>,
}

impl SystemUsage {
    /// This client's 1-based position among all apps by CPU and by memory,
    /// and how many apps there are.
    pub fn self_rank(&self) -> Option<(usize, usize, usize)> {
        let by_cpu = self.apps.iter().position(|a| a.is_self)? + 1;
        let own_memory = self.apps[by_cpu - 1].memory;
        let by_memory = 1 + self.apps.iter().filter(|a| a.memory > own_memory).count();
        Some((by_cpu, by_memory, self.apps.len()))
    }
}

/// Handle to the sampling thread. Dropping it stops the thread.
pub struct UsageMonitor {
    control: mpsc::Sender<UsageScope>,
    scope: UsageScope,
    latest: tokio::sync::watch::Receiver<Option<Arc<UsageSnapshot>>>,
    /// Recent self CPU, oldest first.
    pub cpu_history: Vec<f32>,
    /// Recent self memory in bytes, oldest first.
    pub memory_history: Vec<u64>,
    /// Recent whole-machine CPU, oldest first (Activity page only).
    pub system_history: Vec<f32>,
}

impl UsageMonitor {
    pub fn start(scope: UsageScope) -> Self {
        let (control, control_rx) = mpsc::channel();
        let (tx, latest) = tokio::sync::watch::channel(None);
        let spawned = std::thread::Builder::new()
            .name("zeronet-usage".into())
            .spawn(move || sample_loop(control_rx, tx, scope));
        if spawned.is_err() {
            tracing::warn!("usage sampler thread could not start; usage stays blank");
        }
        Self {
            control,
            scope,
            latest,
            cpu_history: Vec::with_capacity(HISTORY_LEN),
            memory_history: Vec::with_capacity(HISTORY_LEN),
            system_history: Vec::with_capacity(HISTORY_LEN),
        }
    }

    pub fn scope(&self) -> UsageScope {
        self.scope
    }

    /// Change what is sampled. A no-op when nothing changes, so the render
    /// loop can call it every pass.
    pub fn set_scope(&mut self, scope: UsageScope) {
        if scope != self.scope {
            self.scope = scope;
            let _ = self.control.send(scope);
        }
    }

    /// The channel the event loop waits on for fresh samples.
    pub fn receiver(&mut self) -> &mut tokio::sync::watch::Receiver<Option<Arc<UsageSnapshot>>> {
        &mut self.latest
    }

    pub fn latest(&self) -> Option<Arc<UsageSnapshot>> {
        self.latest.borrow().clone()
    }

    /// Fold the newest sample into the history graphs.
    pub fn record(&mut self, snapshot: &UsageSnapshot) {
        push_bounded(&mut self.cpu_history, snapshot.self_cpu);
        push_bounded(&mut self.memory_history, snapshot.self_memory);
        if let Some(system) = &snapshot.system {
            push_bounded(&mut self.system_history, system.cpu);
        }
    }
}

fn push_bounded<T>(history: &mut Vec<T>, value: T) {
    if history.len() == HISTORY_LEN {
        history.remove(0);
    }
    history.push(value);
}

fn sample_loop(
    control: mpsc::Receiver<UsageScope>,
    out: tokio::sync::watch::Sender<Option<Arc<UsageSnapshot>>>,
    mut scope: UsageScope,
) {
    // sysinfo keeps each process's stat file open on Linux by default. In a
    // proxy those descriptors are better spent on sockets.
    sysinfo::set_open_files_limit(0);
    let own_pid = sysinfo::get_current_pid().ok();
    let mut system = System::new();
    let mut next_at = Instant::now();

    loop {
        let wait = match scope {
            UsageScope::Off => None,
            _ => Some(next_at.saturating_duration_since(Instant::now())),
        };
        let message = match wait {
            None => control.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(wait) => control.recv_timeout(wait),
        };
        match message {
            Ok(new_scope) => {
                // Widening the scope should show numbers at once, not after
                // a full interval.
                if new_scope != scope {
                    next_at = Instant::now();
                }
                scope = new_scope;
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => {}
        }

        let snapshot = match scope {
            UsageScope::Off => continue,
            UsageScope::SelfOnly => {
                next_at = Instant::now() + SELF_INTERVAL;
                sample_self(&mut system, own_pid)
            }
            UsageScope::Everything => {
                next_at = Instant::now() + ALL_INTERVAL;
                sample_everything(&mut system, own_pid)
            }
        };
        if out.send(Some(Arc::new(snapshot))).is_err() {
            return;
        }
    }
}

fn process_kind() -> ProcessRefreshKind {
    // `nothing()` still lists Linux threads as processes; they would appear
    // as hundreds of duplicate rows.
    ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .without_tasks()
}

fn cores(system: &mut System) -> usize {
    if system.cpus().is_empty() {
        system.refresh_cpu_usage();
    }
    system.cpus().len().max(1)
}

fn sample_self(system: &mut System, own_pid: Option<Pid>) -> UsageSnapshot {
    let cores = cores(system);
    let Some(pid) = own_pid else {
        return UsageSnapshot::default();
    };
    system.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), true, process_kind());
    let (cpu, memory) = system
        .process(pid)
        .map(|p| (p.cpu_usage() / cores as f32, p.memory()))
        .unwrap_or_default();
    UsageSnapshot {
        self_cpu: cpu.clamp(0.0, 100.0),
        self_memory: memory,
        self_threads: own_threads(),
        system: None,
    }
}

fn sample_everything(system: &mut System, own_pid: Option<Pid>) -> UsageSnapshot {
    let cores = cores(system);
    // The executable path is read once per process, not every sample.
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        process_kind().with_exe(UpdateKind::OnlyIfNotSet),
    );
    system.refresh_cpu_usage();
    system.refresh_memory();

    let apps = group_apps(
        system
            .processes()
            .iter()
            // Kernel threads have no executable and no memory of their own;
            // they are not apps anyone could close.
            .filter(|(_, process)| process.memory() > 0 || process.exe().is_some())
            .map(|(pid, process)| {
                (
                    app_name(process),
                    process.cpu_usage() / cores as f32,
                    process.memory(),
                    Some(*pid) == own_pid,
                )
            }),
    );
    let (self_cpu, self_memory) = own_pid
        .and_then(|pid| system.process(pid))
        .map(|p| (p.cpu_usage() / cores as f32, p.memory()))
        .unwrap_or_default();

    UsageSnapshot {
        self_cpu: self_cpu.clamp(0.0, 100.0),
        self_memory,
        self_threads: own_threads(),
        system: Some(SystemUsage {
            cpu: system.global_cpu_usage().clamp(0.0, 100.0),
            memory_used: system.used_memory(),
            memory_total: system.total_memory(),
            cores,
            process_count: system.processes().len(),
            apps,
        }),
    }
}

/// Group processes into apps by name, highest CPU first (memory breaks
/// ties, then name, so the order is stable between samples).
///
/// A process counts as this client if any of its group is; the group keeps
/// its real name so the row reads the same as in any other process list.
pub fn group_apps<'a, I, S>(processes: I) -> Vec<AppUsage>
where
    I: IntoIterator<Item = (S, f32, u64, bool)>,
    S: AsRef<str> + 'a,
{
    let mut groups: HashMap<String, AppUsage> = HashMap::new();
    for (name, cpu, memory, is_self) in processes {
        let name = display_name(name.as_ref());
        let entry = groups.entry(name.clone()).or_insert_with(|| AppUsage {
            name,
            cpu: 0.0,
            memory: 0,
            processes: 0,
            is_self: false,
        });
        entry.cpu += cpu.max(0.0);
        entry.memory = entry.memory.saturating_add(memory);
        entry.processes += 1;
        entry.is_self |= is_self;
    }
    let mut apps: Vec<AppUsage> = groups.into_values().collect();
    for app in &mut apps {
        app.cpu = app.cpu.min(100.0);
    }
    apps.sort_by(|a, b| {
        b.cpu
            .total_cmp(&a.cpu)
            .then(b.memory.cmp(&a.memory))
            .then_with(|| a.name.cmp(&b.name))
    });
    apps
}

/// The name an app is grouped under: its executable's name where known.
///
/// The kernel's process name is cut at 15 bytes on Linux ("plasma-systemmo")
/// and is freely renamed by multi-process apps (Firefox's content processes
/// call themselves "Isolated Web Co"); the executable is neither.
fn app_name(process: &Process) -> String {
    let from_exe = process
        .exe()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy());
    match from_exe {
        Some(name) if !name.trim().is_empty() => {
            // A binary replaced on disk while running reads "foo (deleted)".
            name.trim_end_matches(" (deleted)").to_string()
        }
        _ => process.name().to_string_lossy().into_owned(),
    }
}

/// A process name as a person would recognise it: no `.exe`, and never
/// empty.
fn display_name(raw: &str) -> String {
    let trimmed = raw.trim();
    let base = trimmed
        .strip_suffix(".exe")
        .or_else(|| trimmed.strip_suffix(".EXE"))
        .unwrap_or(trimmed);
    if base.is_empty() {
        "(unnamed)".to_string()
    } else {
        base.to_string()
    }
}

#[cfg(target_os = "linux")]
fn own_threads() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|n| n.trim().parse().ok())
}

#[cfg(not(target_os = "linux"))]
fn own_threads() -> Option<u32> {
    None
}

/// `1.4 GB`, `312 MB`, `88 KB`: memory the way a system monitor prints it.
pub fn format_memory(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if b >= KB * KB * KB {
        format!("{:.1} GB", b / (KB * KB * KB))
    } else if b >= KB * KB * 100.0 {
        format!("{:.0} MB", b / (KB * KB))
    } else if b >= KB * KB {
        format!("{:.1} MB", b / (KB * KB))
    } else {
        format!("{:.0} KB", b / KB)
    }
}

/// `0.4%`, `12%`: one decimal only where it carries information.
pub fn format_cpu(percent: f32) -> String {
    if percent < 10.0 {
        format!("{percent:.1}%")
    } else {
        format!("{percent:.0}%")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processes_with_one_name_become_one_app() {
        let apps = group_apps([
            ("firefox", 3.0, 300, false),
            ("firefox", 2.0, 200, false),
            ("zeronet-tui", 0.2, 20, true),
            ("chrome.exe", 1.0, 900, false),
        ]);
        assert_eq!(apps.len(), 3);
        assert_eq!(apps[0].name, "firefox");
        assert_eq!(apps[0].processes, 2);
        assert_eq!(apps[0].memory, 500);
        assert!((apps[0].cpu - 5.0).abs() < f32::EPSILON);
        assert_eq!(apps[1].name, "chrome");
        assert!(apps[2].is_self);
    }

    #[test]
    fn ranks_count_from_one_and_ties_share_a_place() {
        let system = SystemUsage {
            apps: group_apps([
                ("a", 5.0, 100, false),
                ("self", 1.0, 100, true),
                ("b", 0.5, 50, false),
            ]),
            ..SystemUsage::default()
        };
        // Second by CPU; memory ties with `a`, so nobody is strictly ahead.
        assert_eq!(system.self_rank(), Some((2, 1, 3)));
    }

    #[test]
    fn a_share_can_never_pass_the_whole_machine() {
        let apps = group_apps([("busy", 80.0, 1, false), ("busy", 80.0, 1, false)]);
        assert_eq!(apps[0].cpu, 100.0);
    }

    #[test]
    fn memory_and_cpu_read_like_a_system_monitor() {
        assert_eq!(format_memory(512 * 1024), "512 KB");
        assert_eq!(format_memory(12 * 1024 * 1024 + 300 * 1024), "12.3 MB");
        assert_eq!(format_memory(450 * 1024 * 1024), "450 MB");
        assert_eq!(format_memory(3 * 1024 * 1024 * 1024 / 2), "1.5 GB");
        assert_eq!(format_cpu(0.04), "0.0%");
        assert_eq!(format_cpu(3.25), "3.2%");
        assert_eq!(format_cpu(42.6), "43%");
    }

    #[test]
    fn history_is_bounded() {
        let mut history = Vec::new();
        for i in 0..(HISTORY_LEN * 3) {
            push_bounded(&mut history, i);
        }
        assert_eq!(history.len(), HISTORY_LEN);
        assert_eq!(*history.last().unwrap(), HISTORY_LEN * 3 - 1);
    }

    #[test]
    fn the_sampler_reports_this_process_and_stops_when_dropped() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut monitor = UsageMonitor::start(UsageScope::Everything);
            let snapshot = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    monitor.receiver().changed().await.unwrap();
                    if let Some(s) = monitor.latest() {
                        return s;
                    }
                }
            })
            .await
            .expect("a sample within ten seconds");
            assert!(snapshot.self_memory > 0, "own memory should be visible");
            let system = snapshot.system.as_ref().expect("full sample");
            assert!(system.apps.iter().any(|a| a.is_self));
            assert!(system.memory_total >= system.memory_used);
        });
    }
}
