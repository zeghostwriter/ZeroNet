//! System proxy integration.
//!
//! Starting the engine only opens a local SOCKS/HTTP listener; nothing on the
//! machine uses it until the system proxy is pointed at it. v2rayN and Clash
//! Verge both expose the same four choices, and so does this:
//!
//! | Mode        | Effect                                                     |
//! |-------------|------------------------------------------------------------|
//! | `Unmanaged` | Never write anything. Whatever is configured stays.        |
//! | `Manual`    | Point the desktop at the local HTTP and SOCKS ports.       |
//! | `Pac`       | Point the desktop at a local PAC script.                   |
//! | `Clear`     | Actively force the desktop back to "no proxy".             |
//!
//! `Unmanaged` and `Clear` are genuinely different, and conflating them was a
//! bug: a machine whose proxy is managed by some *other* tool would have had
//! that configuration wiped every time this client disconnected.
//!
//! ## Restoring, not clearing
//!
//! Before the first change, the existing settings are captured into a
//! [`ProxySnapshot`]. Undoing a change replays that snapshot, so a user who
//! already had a proxy configured gets their own settings back rather than
//! "no proxy" — see [`restore`].
//!
//! ## Platforms
//!
//! Linux has no single proxy setting, so the desktop environment is detected
//! and the matching tool is used: `gsettings` for the GNOME family (GNOME,
//! Cinnamon, Budgie, Pantheon, Unity) and `kwriteconfig` for KDE. Anything
//! else reports honestly that it could not be applied rather than silently
//! doing nothing — a VPN client that claims to have set the system proxy when
//! it has not is actively dangerous.
//!
//! macOS uses `networksetup`; Windows writes the WinINET registry keys.

use std::fmt;
use std::process::Command;

/// What the system proxy should be pointed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SystemProxyMode {
    /// Never touch the desktop's proxy settings.
    ///
    /// The default, because it is the only choice that cannot surprise a
    /// user who already has a proxy configured by something else.
    #[default]
    Unmanaged,
    /// Manual host/port for HTTP, HTTPS and SOCKS.
    Manual,
    /// Automatic configuration from a locally served PAC script.
    Pac,
    /// Force the desktop back to "no proxy" and keep it there.
    Clear,
}

impl SystemProxyMode {
    /// Short label for the settings row.
    pub fn label(self) -> &'static str {
        match self {
            SystemProxyMode::Unmanaged => "DO NOT CHANGE",
            SystemProxyMode::Manual => "SET SYSTEM",
            SystemProxyMode::Pac => "PAC MODE",
            SystemProxyMode::Clear => "CLEAR",
        }
    }

    /// Even shorter label, for the header chip.
    pub fn chip_label(self) -> &'static str {
        match self {
            SystemProxyMode::Unmanaged => "PROXY KEEP",
            SystemProxyMode::Manual => "PROXY SYS",
            SystemProxyMode::Pac => "PROXY PAC",
            SystemProxyMode::Clear => "PROXY NONE",
        }
    }

    /// One line explaining what this mode does, for the settings screen.
    pub fn describe(self) -> &'static str {
        match self {
            SystemProxyMode::Unmanaged => "keeps your settings",
            SystemProxyMode::Manual => "apps use local ports",
            SystemProxyMode::Pac => "apps use the local PAC",
            SystemProxyMode::Clear => "forces no proxy",
        }
    }

    /// Whether this mode writes to the desktop's settings at all.
    pub fn writes_settings(self) -> bool {
        !matches!(self, SystemProxyMode::Unmanaged)
    }

    /// Cycle through the modes, the way the settings row does.
    pub fn next(self) -> Self {
        match self {
            SystemProxyMode::Unmanaged => SystemProxyMode::Manual,
            SystemProxyMode::Manual => SystemProxyMode::Pac,
            SystemProxyMode::Pac => SystemProxyMode::Clear,
            SystemProxyMode::Clear => SystemProxyMode::Unmanaged,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            // "off" is accepted for settings written by an earlier build,
            // where it meant the clearing behaviour.
            "unmanaged" | "keep" | "nochange" => Some(SystemProxyMode::Unmanaged),
            "manual" | "system" => Some(SystemProxyMode::Manual),
            "pac" | "auto" => Some(SystemProxyMode::Pac),
            "clear" | "off" | "none" => Some(SystemProxyMode::Clear),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SystemProxyMode::Unmanaged => "unmanaged",
            SystemProxyMode::Manual => "manual",
            SystemProxyMode::Pac => "pac",
            SystemProxyMode::Clear => "clear",
        }
    }
}

/// Where the local proxy is listening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyEndpoints {
    pub http_port: u16,
    pub socks_port: u16,
    /// Port the PAC script is served on, when PAC mode is in use.
    pub pac_port: u16,
}

/// Which desktop's proxy settings are being driven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Backend {
    /// `gsettings org.gnome.system.proxy`.
    Gnome,
    /// `kwriteconfig` into `kioslaverc`.
    Kde,
    /// `networksetup` on macOS.
    MacOs,
    /// WinINET registry keys.
    Windows,
    /// Nothing usable was found.
    Unsupported,
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Backend::Gnome => "GNOME",
            Backend::Kde => "KDE",
            Backend::MacOs => "macOS",
            Backend::Windows => "Windows",
            Backend::Unsupported => "unsupported desktop",
        })
    }
}

/// Pick the backend for this machine.
pub fn detect_backend() -> Backend {
    if cfg!(target_os = "macos") {
        return Backend::MacOs;
    }
    if cfg!(target_os = "windows") {
        return Backend::Windows;
    }

    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .or_else(|_| std::env::var("DESKTOP_SESSION"))
        .unwrap_or_default()
        .to_ascii_uppercase();

    // KDE first: a KDE session can still have `gsettings` installed, and
    // writing GNOME keys there would silently do nothing.
    if (desktop.contains("KDE") || desktop.contains("PLASMA"))
        && (which("kwriteconfig6").is_some() || which("kwriteconfig5").is_some())
    {
        return Backend::Kde;
    }

    const GNOME_LIKE: [&str; 6] = ["GNOME", "UNITY", "CINNAMON", "BUDGIE", "PANTHEON", "XFCE"];
    if GNOME_LIKE.iter().any(|d| desktop.contains(d)) && which("gsettings").is_some() {
        return Backend::Gnome;
    }

    // No recognised desktop, but the tool exists — worth trying, since many
    // GTK applications read the GNOME keys regardless of the session.
    if which("gsettings").is_some() {
        return Backend::Gnome;
    }
    if which("kwriteconfig6").is_some() || which("kwriteconfig5").is_some() {
        return Backend::Kde;
    }

    Backend::Unsupported
}

fn which(binary: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

// ------------------------------------------------------ desktop session

/// The desktop session the proxy settings belong to.
///
/// Desktop proxy settings are per user and reach applications over that
/// user's session bus. Two ordinary situations broke that link, and every
/// write then "succeeded" into a store nobody reads:
///
/// * the client was started with `sudo` (the obvious way to get TUN), so
///   `gsettings` wrote root's dconf and `systemctl --user` spoke to root's
///   manager, while the user's Firefox and Telegram saw nothing;
/// * the client was started from somewhere without `DBUS_SESSION_BUS_ADDRESS`
///   (a TTY, `ssh`, some terminal launchers), so GLib silently fell back to
///   its in-memory settings backend.
///
/// Both are fixed by pointing every tool at the real user's session bus,
/// and running it as that user.
#[derive(Debug, Clone)]
struct SessionTarget {
    /// Present when running as root on behalf of another user.
    #[cfg_attr(not(unix), allow(dead_code))]
    ids: Option<(u32, u32)>,
    home: Option<std::path::PathBuf>,
    runtime_dir: Option<std::path::PathBuf>,
}

fn session_target() -> &'static SessionTarget {
    static TARGET: std::sync::OnceLock<SessionTarget> = std::sync::OnceLock::new();
    TARGET.get_or_init(detect_session_target)
}

#[cfg(unix)]
fn detect_session_target() -> SessionTarget {
    let env_home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let invoking_uid = ["SUDO_UID", "PKEXEC_UID", "DOAS_UID"]
        .iter()
        .find_map(|var| std::env::var(var).ok()?.parse::<u32>().ok())
        .filter(|uid| *uid != 0);

    let (ids, home, uid) = match (euid, invoking_uid) {
        (0, Some(uid)) => {
            let (gid, home) = passwd_entry(uid).unwrap_or((uid, None));
            (Some((uid, gid)), home.or(env_home), uid)
        }
        _ => (None, env_home, euid),
    };
    let runtime_dir = std::path::PathBuf::from(format!("/run/user/{uid}"));
    SessionTarget {
        ids,
        home,
        runtime_dir: runtime_dir.is_dir().then_some(runtime_dir),
    }
}

#[cfg(not(unix))]
fn detect_session_target() -> SessionTarget {
    SessionTarget {
        ids: None,
        home: std::env::var_os("HOME").map(std::path::PathBuf::from),
        runtime_dir: None,
    }
}

/// Group id and home directory of `uid`, from the password database.
#[cfg(unix)]
fn passwd_entry(uid: u32) -> Option<(u32, Option<std::path::PathBuf>)> {
    use std::ffi::CStr;
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer refers to live, correctly sized storage.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    let home = (!entry.pw_dir.is_null()).then(|| {
        // SAFETY: getpwuid_r succeeded, so pw_dir is a C string in `buffer`.
        let dir = unsafe { CStr::from_ptr(entry.pw_dir) };
        std::path::PathBuf::from(dir.to_string_lossy().into_owned())
    });
    Some((entry.pw_gid, home))
}

/// A command for a desktop-settings tool, aimed at the user's session.
fn tool(binary: &str) -> Command {
    let mut command = Command::new(binary);
    if !cfg!(target_os = "linux") {
        return command;
    }
    let target = session_target();
    if let Some(runtime_dir) = &target.runtime_dir {
        let bus = runtime_dir.join("bus");
        let bus_missing = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none();
        if (target.ids.is_some() || bus_missing) && bus.exists() {
            command.env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", bus.display()),
            );
        }
        if target.ids.is_some() || std::env::var_os("XDG_RUNTIME_DIR").is_none() {
            command.env("XDG_RUNTIME_DIR", runtime_dir);
        }
    }
    #[cfg(unix)]
    if let Some((uid, gid)) = target.ids {
        use std::os::unix::process::CommandExt;
        command.uid(uid).gid(gid);
        if let Some(home) = &target.home {
            command.env("HOME", home);
        }
    }
    command
}

/// The home directory of the session user.
fn session_home() -> Option<std::path::PathBuf> {
    session_target().home.clone()
}

/// Hand a file this process created back to the session user, so a file
/// written while running under sudo is not left owned by root in their home.
fn session_chown(path: &std::path::Path) {
    #[cfg(unix)]
    if let Some((uid, gid)) = session_target().ids {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return;
        };
        // SAFETY: c_path is a valid NUL-terminated string.
        unsafe {
            libc::chown(c_path.as_ptr(), uid, gid);
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// The desktop's proxy configuration as it was found.
///
/// Opaque on purpose: what needs preserving differs per backend, and callers
/// only ever hand it back to [`restore`].
///
/// On Linux the manual and PAC modes write to *every* proxy store that is
/// present — KDE's `kioslaverc`, GNOME's `gsettings` and the systemd user
/// environment — because applications read whichever one their toolkit
/// knows. The snapshot therefore captures each of those stores, not only the
/// one belonging to the detected desktop: capturing just that one left a KDE
/// machine with `gsettings` installed pointed at a dead proxy for every GTK
/// application after "restore".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProxySnapshot {
    backend: Backend,
    /// KDE `kioslaverc` keys. An empty value means "the key was not set",
    /// which is restored by deleting it rather than writing a blank.
    kde: Vec<(String, String)>,
    /// GNOME `schema|key` pairs, as `gsettings get` printed them.
    gnome: Vec<(String, String)>,
    /// The proxy variables of the systemd user environment; `None` means
    /// the variable was not set.
    env: Vec<(String, Option<String>)>,
}

impl ProxySnapshot {
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Whether anything was captured. A snapshot of an unsupported desktop is
    /// empty, and restoring it is a no-op rather than an error.
    pub fn is_empty(&self) -> bool {
        self.kde.is_empty() && self.gnome.is_empty()
    }
}

/// Environment variables the Linux modes set in the systemd user manager.
const ENV_KEYS: [&str; 9] = [
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
    "auto_proxy",
];

fn kde_tool_present() -> bool {
    which("kwriteconfig6").is_some() || which("kwriteconfig5").is_some()
}

/// Capture the current proxy configuration so it can be put back later.
///
/// Taken before the first change. Restoring this is what makes undoing a
/// change non-destructive: a user whose proxy is managed by another tool
/// gets their own values back, not "no proxy".
pub fn snapshot() -> ProxySnapshot {
    let backend = detect_backend();
    let linux = matches!(backend, Backend::Kde | Backend::Gnome);
    // macOS and Windows expose their state through the same tools used to set
    // it, but not in a form that round-trips cleanly; those backends fall
    // back to clearing, which is what they did before.
    let kde = if linux && kde_tool_present() {
        KDE_KEYS
            .iter()
            .map(|key| (key.to_string(), kde_read(key)))
            .collect()
    } else {
        Vec::new()
    };
    let gnome = if linux && which("gsettings").is_some() {
        GNOME_KEYS
            .iter()
            .map(|(schema, key)| (format!("{schema}|{key}"), gsettings_read(schema, key)))
            .collect()
    } else {
        Vec::new()
    };
    let env = if linux {
        systemd_env_read()
    } else {
        Vec::new()
    };
    ProxySnapshot {
        backend,
        kde,
        gnome,
        env,
    }
}

/// How a snapshot will be put back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreStrategy {
    /// Write the captured values back.
    Replay,
    /// Nothing was captured, so fall back to forcing "no proxy".
    Clear,
}

/// What [`restore`] would do, without doing it.
///
/// Split out so the decision is testable without a test writing to the real
/// desktop — a unit test that mutates the machine it runs on is not a unit
/// test.
pub fn restore_strategy(snapshot: &ProxySnapshot) -> RestoreStrategy {
    match snapshot.backend {
        Backend::Kde | Backend::Gnome if !snapshot.is_empty() => RestoreStrategy::Replay,
        _ => RestoreStrategy::Clear,
    }
}

/// Put back a configuration captured by [`snapshot`].
///
/// Every captured store is restored even when an earlier one fails, so one
/// broken tool cannot leave the others pointed at a proxy that is gone; the
/// first failure is what gets reported.
pub fn restore(snapshot: &ProxySnapshot) -> Result<Backend, String> {
    if restore_strategy(snapshot) == RestoreStrategy::Clear {
        // Nothing usable was captured, so the honest fallback is "no proxy".
        return clear();
    }

    let mut first_error: Option<String> = None;
    let mut note = |result: Result<(), String>| {
        if let Err(e) = result {
            first_error.get_or_insert(e);
        }
    };

    if !snapshot.kde.is_empty() {
        for (key, value) in &snapshot.kde {
            note(kde_write(key, value));
        }
        notify_kde();
    }
    for (compound, value) in &snapshot.gnome {
        let Some((schema, key)) = compound.split_once('|') else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        note(gsettings(&["set", schema, key, value]));
    }
    restore_linux_env(&snapshot.env);

    match first_error {
        Some(e) => Err(e),
        None => Ok(snapshot.backend),
    }
}

// ------------------------------------------------------ restore tracking

/// The configuration to put back, while this process has one outstanding.
///
/// Process-wide rather than owned by the UI so that the panic hook — which
/// runs before a `panic = "abort"` build tears the process down, and before
/// any destructor could — can still undo the change.
static OUTSTANDING: std::sync::Mutex<Option<ProxySnapshot>> = std::sync::Mutex::new(None);

/// Where the outstanding snapshot is mirrored on disk.
static STATE_FILE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Mirror outstanding changes to `path`, so a client that dies without
/// running any cleanup at all (SIGKILL, power loss) can undo them on its
/// next launch through [`recover_stale`]. Set once, at startup.
pub fn set_state_file(path: std::path::PathBuf) {
    let _ = STATE_FILE.set(path);
}

fn persist(snapshot: Option<&ProxySnapshot>) {
    let Some(path) = STATE_FILE.get() else {
        return;
    };
    match snapshot {
        Some(snapshot) => {
            let Ok(body) = serde_json::to_vec(snapshot) else {
                return;
            };
            // Written to a sibling and renamed, so a crash mid-write cannot
            // leave a half file that fails to parse and is then discarded.
            let tmp = path.with_extension("tmp");
            let written = std::fs::write(&tmp, body).and_then(|()| std::fs::rename(&tmp, path));
            if let Err(error) = written {
                tracing::warn!(%error, "could not record the system proxy snapshot");
            }
        }
        None => {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn outstanding() -> std::sync::MutexGuard<'static, Option<ProxySnapshot>> {
    OUTSTANDING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Whether a change made by this process is waiting to be undone.
pub fn has_outstanding_change() -> bool {
    outstanding().is_some()
}

/// What [`apply_tracked`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// `mode` is now in force through this backend.
    Set(Backend),
    /// Hands-off mode: an earlier change was undone through this backend.
    Restored(Backend),
    /// Hands-off mode with nothing to undo; nothing was touched.
    Untouched,
}

/// Apply `mode`, capturing what it replaces the first time anything is
/// written, so [`revert_tracked`] can put it back exactly.
///
/// Blocking: every backend is driven through external tools. Call it off
/// the UI thread.
pub fn apply_tracked(mode: SystemProxyMode, endpoints: ProxyEndpoints) -> Result<Applied, String> {
    if mode == SystemProxyMode::Unmanaged {
        return Ok(match revert_tracked()? {
            Some(backend) => Applied::Restored(backend),
            None => Applied::Untouched,
        });
    }

    let mut guard = outstanding();
    let fresh = guard.is_none();
    if fresh {
        let captured = snapshot();
        // On disk before the first write, not after: a crash between the
        // two must still be recoverable.
        persist(Some(&captured));
        *guard = Some(captured);
    }
    match apply(mode, endpoints) {
        Ok(backend) => Ok(Applied::Set(backend)),
        Err(error) => {
            if fresh {
                // Some keys may have been written before the failure; undo
                // them now rather than leaving a half-applied proxy that
                // nothing claims to own.
                if let Some(captured) = guard.take() {
                    let _ = restore(&captured);
                }
                persist(None);
            }
            Err(error)
        }
    }
}

/// Undo every change this process made, if there is one.
///
/// Returns the backend that was restored, or `None` when nothing was
/// outstanding. A failed restore stays outstanding, so a later attempt — the
/// exit path, the panic hook, or the next launch — tries again.
pub fn revert_tracked() -> Result<Option<Backend>, String> {
    let mut guard = outstanding();
    let Some(captured) = guard.as_ref() else {
        return Ok(None);
    };
    let backend = restore(captured)?;
    *guard = None;
    persist(None);
    Ok(Some(backend))
}

/// Last-ditch restore for the panic hook.
///
/// Never blocks on the lock: a panic raised while it was held must not turn
/// into a deadlock inside the hook. When it cannot run, the on-disk copy is
/// still there for the next launch.
pub fn emergency_restore() {
    let mut guard = match OUTSTANDING.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return,
    };
    if let Some(captured) = guard.take() {
        match restore(&captured) {
            Ok(_) => persist(None),
            Err(_) => *guard = Some(captured),
        }
    }
}

/// Undo a change left behind by a previous run that never cleaned up.
///
/// Called once at startup, after [`set_state_file`]. Returns what happened,
/// or `None` when there was nothing to recover.
pub fn recover_stale() -> Option<Result<Backend, String>> {
    let path = STATE_FILE.get()?;
    let body = std::fs::read(path).ok()?;
    let Ok(captured) = serde_json::from_slice::<ProxySnapshot>(&body) else {
        // Unreadable: nothing can be replayed from it, and keeping it would
        // retry the same failure on every launch.
        let _ = std::fs::remove_file(path);
        return None;
    };
    let outcome = restore(&captured);
    if outcome.is_ok() {
        let _ = std::fs::remove_file(path);
    }
    Some(outcome)
}

/// Apply `mode` to the system proxy.
///
/// [`SystemProxyMode::Unmanaged`] deliberately does nothing at all — not even
/// a read — so a machine whose proxy belongs to another tool is untouched.
pub fn apply(mode: SystemProxyMode, endpoints: ProxyEndpoints) -> Result<Backend, String> {
    let backend = detect_backend();
    match mode {
        SystemProxyMode::Unmanaged => Ok(backend),
        SystemProxyMode::Clear => clear(),
        SystemProxyMode::Manual => set_manual(backend, endpoints).map(|()| backend),
        SystemProxyMode::Pac => {
            let url = pac_url(endpoints.pac_port);
            set_pac(backend, &url).map(|()| backend)
        }
    }
}

/// Restore "no proxy".
pub fn clear() -> Result<Backend, String> {
    let backend = detect_backend();
    match backend {
        Backend::Gnome | Backend::Kde => clear_linux(backend),
        Backend::MacOs => {
            for service in macos_services()? {
                let _ = networksetup(&["-setwebproxystate", &service, "off"]);
                let _ = networksetup(&["-setsecurewebproxystate", &service, "off"]);
                let _ = networksetup(&["-setsocksfirewallproxystate", &service, "off"]);
                let _ = networksetup(&["-setautoproxystate", &service, "off"]);
            }
            Ok(backend)
        }
        Backend::Windows => {
            windows_set(None, None)?;
            Ok(backend)
        }
        Backend::Unsupported => Err(unsupported_message()),
    }
}

fn unsupported_message() -> String {
    "no supported desktop proxy backend found — set the proxy manually, or \
     export http_proxy/https_proxy/all_proxy in your shell"
        .to_string()
}

fn set_manual(backend: Backend, endpoints: ProxyEndpoints) -> Result<(), String> {
    let host = "127.0.0.1";
    match backend {
        Backend::Gnome | Backend::Kde => apply_linux_manual(endpoints),
        Backend::MacOs => {
            for service in macos_services()? {
                networksetup(&[
                    "-setwebproxy",
                    &service,
                    host,
                    &endpoints.http_port.to_string(),
                ])?;
                networksetup(&[
                    "-setsecurewebproxy",
                    &service,
                    host,
                    &endpoints.http_port.to_string(),
                ])?;
                networksetup(&[
                    "-setsocksfirewallproxy",
                    &service,
                    host,
                    &endpoints.socks_port.to_string(),
                ])?;
            }
            Ok(())
        }
        Backend::Windows => windows_set(Some(&format!("{host}:{}", endpoints.http_port)), None),
        Backend::Unsupported => Err(unsupported_message()),
    }
}

fn set_pac(backend: Backend, url: &str) -> Result<(), String> {
    match backend {
        Backend::Gnome | Backend::Kde => apply_linux_pac(url),
        Backend::MacOs => {
            for service in macos_services()? {
                networksetup(&["-setautoproxyurl", &service, url])?;
                networksetup(&["-setautoproxystate", &service, "on"])?;
            }
            Ok(())
        }
        Backend::Windows => windows_set(None, Some(url)),
        Backend::Unsupported => Err(unsupported_message()),
    }
}

fn apply_linux_manual(endpoints: ProxyEndpoints) -> Result<(), String> {
    let host = "127.0.0.1";
    let mut applied: Vec<&str> = Vec::new();
    let mut first_error: Option<String> = None;

    // 1. KDE kioslaverc (Dolphin, Konqueror and other KIO applications).
    if kde_tool_present() {
        let written = [
            kwriteconfig(&["--key", "ProxyType", "1"]),
            kwriteconfig(&[
                "--key",
                "httpProxy",
                &format!("http://{host} {}", endpoints.http_port),
            ]),
            kwriteconfig(&[
                "--key",
                "httpsProxy",
                &format!("http://{host} {}", endpoints.http_port),
            ]),
            kwriteconfig(&[
                "--key",
                "socksProxy",
                &format!("socks://{host} {}", endpoints.socks_port),
            ]),
            kwriteconfig(&["--key", "NoProxyFor", "localhost,127.0.0.1,::1"]),
        ];
        notify_kde();
        match written.into_iter().find_map(Result::err) {
            None => applied.push("KDE"),
            Some(e) => {
                first_error.get_or_insert(e);
            }
        }
    }

    // 2. GSettings — what Firefox, Chromium, Brave and every GTK application
    //    read for "use system proxy settings", on KDE as well as GNOME.
    if which("gsettings").is_some() {
        let _ = gsettings(&["set", "org.gnome.system.proxy", "mode", "'manual'"]);
        for (schema, port) in [
            ("org.gnome.system.proxy.http", endpoints.http_port),
            ("org.gnome.system.proxy.https", endpoints.http_port),
            ("org.gnome.system.proxy.socks", endpoints.socks_port),
        ] {
            let _ = gsettings(&["set", schema, "host", host]);
            let _ = gsettings(&["set", schema, "port", &port.to_string()]);
        }
        let _ = gsettings(&[
            "set",
            "org.gnome.system.proxy",
            "ignore-hosts",
            "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']",
        ]);
        match verify_gsettings("'manual'") {
            Ok(()) => applied.push("GSettings"),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }

    // 3. Environment variables. Telegram Desktop (Qt without libproxy) and
    //    terminal tools only ever read these, and only at start-up.
    set_linux_env(endpoints);

    if applied.is_empty() {
        return Err(first_error.unwrap_or_else(unsupported_message));
    }
    Ok(())
}

fn apply_linux_pac(url: &str) -> Result<(), String> {
    let mut applied = false;
    let mut first_error: Option<String> = None;
    if which("gsettings").is_some() {
        let _ = gsettings(&["set", "org.gnome.system.proxy", "mode", "'auto'"]);
        let _ = gsettings(&["set", "org.gnome.system.proxy", "autoconfig-url", url]);
        match verify_gsettings("'auto'") {
            Ok(()) => applied = true,
            Err(e) => first_error = Some(e),
        }
    }
    if kde_tool_present() {
        let written = [
            kwriteconfig(&["--key", "ProxyType", "2"]),
            kwriteconfig(&["--key", "Proxy Config Script", url]),
        ];
        notify_kde();
        match written.into_iter().find_map(Result::err) {
            None => applied = true,
            Some(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    let _ = tool("systemctl")
        .args(["--user", "set-environment", &format!("auto_proxy={url}")])
        .output();
    update_activation_env(&[format!("auto_proxy={url}")]);
    if !applied {
        return Err(first_error.unwrap_or_else(unsupported_message));
    }
    Ok(())
}

fn clear_linux(backend: Backend) -> Result<Backend, String> {
    if which("gsettings").is_some() {
        let _ = gsettings(&["set", "org.gnome.system.proxy", "mode", "'none'"]);
    }
    if kde_tool_present() {
        let _ = kwriteconfig(&["--key", "ProxyType", "0"]);
        notify_kde();
    }
    clear_linux_env();
    Ok(backend)
}

/// Read the GNOME proxy mode back and make sure the write stuck.
///
/// `gsettings set` exits 0 even when it had nowhere to write: with no
/// session bus, or no dconf installed (common on KDE and minimal desktops),
/// GLib silently falls back to its in-memory backend and the value vanishes
/// the moment the tool exits. Firefox then keeps reading "none", which is
/// exactly the "system proxy does nothing" report this check exists for.
fn verify_gsettings(expected: &str) -> Result<(), String> {
    let actual = gsettings_read("org.gnome.system.proxy", "mode");
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "GSettings did not keep the proxy (mode is {}); install dconf \
             (dconf-service / dconf-gsettings-backend) so Firefox and GTK apps \
             can see it",
            if actual.is_empty() {
                "unreadable"
            } else {
                &actual
            }
        ))
    }
}

/// The proxy environment in `KEY=value` form.
fn proxy_env_pairs(endpoints: ProxyEndpoints) -> Vec<String> {
    let host = "127.0.0.1";
    let http_val = format!("http://{host}:{}", endpoints.http_port);
    let socks_val = format!("socks5://{host}:{}", endpoints.socks_port);
    let no_proxy_val = "localhost,127.0.0.1,::1";
    vec![
        format!("http_proxy={http_val}"),
        format!("https_proxy={http_val}"),
        format!("all_proxy={socks_val}"),
        format!("HTTP_PROXY={http_val}"),
        format!("HTTPS_PROXY={http_val}"),
        format!("ALL_PROXY={socks_val}"),
        format!("no_proxy={no_proxy_val}"),
        format!("NO_PROXY={no_proxy_val}"),
    ]
}

fn set_linux_env(endpoints: ProxyEndpoints) {
    let pairs = proxy_env_pairs(endpoints);

    // The systemd user manager: services and anything it starts.
    let _ = tool("systemctl")
        .args(["--user", "set-environment"])
        .args(&pairs)
        .output();
    // The D-Bus activation environment: applications the desktop starts
    // through D-Bus (Telegram's .desktop entry is DBusActivatable) inherit
    // this, so a freshly started Telegram picks the proxy up without a
    // re-login.
    update_activation_env(&pairs);

    // environment.d: the next login session, for everything else.
    if let Some(home) = session_home() {
        let env_d = home.join(".config/environment.d");
        let _ = std::fs::create_dir_all(&env_d);
        let conf_file = env_d.join("10-zeronet-proxy.conf");
        let content: String = pairs
            .iter()
            .filter_map(|pair| pair.split_once('='))
            .map(|(key, value)| format!("{key}=\"{value}\"\n"))
            .collect();
        if std::fs::write(&conf_file, content).is_ok() {
            session_chown(&env_d.join(".."));
            session_chown(&env_d);
            session_chown(&conf_file);
        }
    }
}

/// Push `KEY=value` pairs into the D-Bus activation environment (and the
/// systemd one, which `--systemd` also updates). An empty value is the only
/// way to "unset" through this tool, and every reader treats it as unset.
fn update_activation_env(pairs: &[String]) {
    if pairs.is_empty() || which("dbus-update-activation-environment").is_none() {
        return;
    }
    let _ = tool("dbus-update-activation-environment")
        .arg("--systemd")
        .args(pairs)
        .output();
}

fn clear_linux_env() {
    // `auto_proxy` included: PAC mode sets it, and leaving it behind pointed
    // applications at a PAC server that no longer exists. The activation
    // environment goes first because its `--systemd` flag writes empties
    // into systemd, which the unset below then removes properly.
    let empties: Vec<String> = ENV_KEYS.iter().map(|key| format!("{key}=")).collect();
    update_activation_env(&empties);
    let _ = tool("systemctl")
        .arg("--user")
        .arg("unset-environment")
        .args(ENV_KEYS)
        .output();
    remove_env_file();
}

fn remove_env_file() {
    if let Some(home) = session_home() {
        let conf_file = home.join(".config/environment.d/10-zeronet-proxy.conf");
        let _ = std::fs::remove_file(conf_file);
    }
}

/// The proxy variables currently set in the systemd user manager.
fn systemd_env_read() -> Vec<(String, Option<String>)> {
    let Ok(output) = tool("systemctl")
        .args(["--user", "show-environment"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_env_listing(&text)
}

/// Pick [`ENV_KEYS`] out of `systemctl --user show-environment` output.
///
/// Values systemd had to escape are printed as `$'…'`; those cannot be fed
/// back verbatim, so they are treated as unset rather than restored mangled.
fn parse_env_listing(text: &str) -> Vec<(String, Option<String>)> {
    ENV_KEYS
        .iter()
        .map(|key| {
            let value = text.lines().find_map(|line| {
                let (name, value) = line.split_once('=')?;
                (name == *key && !value.starts_with("$'")).then(|| value.to_string())
            });
            (key.to_string(), value)
        })
        .collect()
}

/// Put the systemd user environment back as captured.
fn restore_linux_env(captured: &[(String, Option<String>)]) {
    let mut set: Vec<String> = Vec::new();
    let mut unset: Vec<&str> = Vec::new();
    for key in ENV_KEYS {
        match captured.iter().find(|(k, _)| k == key) {
            Some((_, Some(value))) => set.push(format!("{key}={value}")),
            _ => unset.push(key),
        }
    }
    let activation: Vec<String> = set
        .iter()
        .cloned()
        .chain(unset.iter().map(|key| format!("{key}=")))
        .collect();
    update_activation_env(&activation);
    if !unset.is_empty() {
        let _ = tool("systemctl")
            .args(["--user", "unset-environment"])
            .args(&unset)
            .output();
    }
    if !set.is_empty() {
        let _ = tool("systemctl")
            .args(["--user", "set-environment"])
            .args(&set)
            .output();
    }
    remove_env_file();
}

// ------------------------------------------------------------- backends

fn gsettings(args: &[&str]) -> Result<(), String> {
    run("gsettings", args)
}

/// KDE keys this module writes, and therefore has to preserve.
const KDE_KEYS: [&str; 6] = [
    "ProxyType",
    "httpProxy",
    "httpsProxy",
    "socksProxy",
    "NoProxyFor",
    "Proxy Config Script",
];

/// GNOME schema/key pairs this module writes.
const GNOME_KEYS: [(&str, &str); 9] = [
    ("org.gnome.system.proxy", "mode"),
    ("org.gnome.system.proxy", "autoconfig-url"),
    ("org.gnome.system.proxy", "ignore-hosts"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
    ("org.gnome.system.proxy.socks", "host"),
    ("org.gnome.system.proxy.socks", "port"),
];

fn kde_read_binary() -> &'static str {
    if which("kreadconfig6").is_some() {
        "kreadconfig6"
    } else {
        "kreadconfig5"
    }
}

fn kde_read(key: &str) -> String {
    let output = tool(kde_read_binary())
        .args([
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            key,
        ])
        .output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(_) => String::new(),
    }
}

/// Write one KDE key, deleting it when the captured value was absent.
fn kde_write(key: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        // Writing an empty string is not the same as the key being unset.
        kwriteconfig(&["--key", key, "--delete"])
    } else {
        kwriteconfig(&["--key", key, value])
    }
}

fn gsettings_read(schema: &str, key: &str) -> String {
    let output = tool("gsettings").args(["get", schema, key]).output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(_) => String::new(),
    }
}

fn kwriteconfig(extra: &[&str]) -> Result<(), String> {
    let binary = if which("kwriteconfig6").is_some() {
        "kwriteconfig6"
    } else {
        "kwriteconfig5"
    };
    let mut args = vec!["--file", "kioslaverc", "--group", "Proxy Settings"];
    args.extend_from_slice(extra);
    run(binary, &args)
}

/// Tell running KDE applications to re-read the proxy settings.
///
/// Best-effort: without it, already-open apps keep the old configuration
/// until they restart, but failing to notify is not a reason to report the
/// change itself as failed.
fn notify_kde() {
    let _ = run(
        "dbus-send",
        &[
            "--type=signal",
            "/KIO/Scheduler",
            "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
            "string:''",
        ],
    );
}

fn networksetup(args: &[&str]) -> Result<(), String> {
    run("networksetup", args)
}

/// Network services that are actually present, so a machine without Wi-Fi is
/// not reported as a failure.
fn macos_services() -> Result<Vec<String>, String> {
    let output = tool("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .map_err(|e| format!("cannot run networksetup: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let services: Vec<String> = text
        .lines()
        .skip(1) // a header line explaining the asterisk
        .map(|l| l.trim_start_matches('*').trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if services.is_empty() {
        return Err("no network services found".into());
    }
    Ok(services)
}

/// Hosts that must never go through the proxy on Windows, in WinINET's
/// `ProxyOverride` syntax. `<local>` covers plain host names.
const WINDOWS_BYPASS: &str = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;\
172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;\
172.29.*;172.30.*;172.31.*;192.168.*;<local>";

/// Point Windows at a manual proxy, a PAC URL, or nothing.
///
/// The per-connection WinINET API is the primary path: it writes the
/// `DefaultConnectionSettings` blob that WinHTTP reads (Qt, and so Telegram's
/// "use system proxy"), and then broadcasts the change so running browsers —
/// Firefox with "use system proxy settings", Chrome, Edge — switch at once.
/// Writing only the `ProxyEnable`/`ProxyServer` registry values, as before,
/// updated neither: those applications kept going direct until a restart,
/// and WinHTTP-based ones never noticed at all.
fn windows_set(manual: Option<&str>, pac: Option<&str>) -> Result<(), String> {
    let registry = windows_set_registry(manual, pac);
    #[cfg(windows)]
    {
        match wininet::apply(manual, pac, WINDOWS_BYPASS) {
            Ok(()) => return Ok(()),
            Err(error) => tracing::warn!(%error, "WinINET refused the proxy; registry only"),
        }
    }
    registry
}

fn windows_set_registry(manual: Option<&str>, pac: Option<&str>) -> Result<(), String> {
    const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    let enable = if manual.is_some() { "1" } else { "0" };
    run(
        "reg",
        &[
            "add",
            KEY,
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            enable,
            "/f",
        ],
    )?;

    match manual {
        Some(server) => {
            run(
                "reg",
                &[
                    "add",
                    KEY,
                    "/v",
                    "ProxyServer",
                    "/t",
                    "REG_SZ",
                    "/d",
                    server,
                    "/f",
                ],
            )?;
            run(
                "reg",
                &[
                    "add",
                    KEY,
                    "/v",
                    "ProxyOverride",
                    "/t",
                    "REG_SZ",
                    "/d",
                    WINDOWS_BYPASS,
                    "/f",
                ],
            )?;
        }
        None => {
            let _ = run("reg", &["delete", KEY, "/v", "ProxyServer", "/f"]);
        }
    }
    match pac {
        Some(url) => run(
            "reg",
            &[
                "add",
                KEY,
                "/v",
                "AutoConfigURL",
                "/t",
                "REG_SZ",
                "/d",
                url,
                "/f",
            ],
        )?,
        None => {
            let _ = run("reg", &["delete", KEY, "/v", "AutoConfigURL", "/f"]);
        }
    }
    Ok(())
}

/// The WinINET per-connection proxy API, declared by hand: three calls do
/// not justify a bindings crate.
#[cfg(windows)]
mod wininet {
    use std::ffi::c_void;

    const INTERNET_OPTION_REFRESH: u32 = 37;
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    const INTERNET_OPTION_PER_CONNECTION_OPTION: u32 = 75;

    const INTERNET_PER_CONN_FLAGS: u32 = 1;
    const INTERNET_PER_CONN_PROXY_SERVER: u32 = 2;
    const INTERNET_PER_CONN_PROXY_BYPASS: u32 = 3;
    const INTERNET_PER_CONN_AUTOCONFIG_URL: u32 = 4;

    const PROXY_TYPE_DIRECT: u32 = 0x1;
    const PROXY_TYPE_PROXY: u32 = 0x2;
    const PROXY_TYPE_AUTO_PROXY_URL: u32 = 0x4;

    /// `INTERNET_PER_CONN_OPTIONW`. The value is a union of a DWORD, a
    /// string pointer and a FILETIME; a pointer-sized field with 8-byte
    /// alignment has the same size and layout on both 32- and 64-bit.
    #[repr(C)]
    struct Option_ {
        option: u32,
        value: OptionValue,
    }

    #[repr(C)]
    union OptionValue {
        dword: u32,
        string: *mut u16,
        _filetime: u64,
    }

    /// `INTERNET_PER_CONN_OPTION_LISTW`.
    #[repr(C)]
    struct OptionList {
        size: u32,
        connection: *mut u16,
        count: u32,
        error: u32,
        options: *mut Option_,
    }

    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(
            internet: *mut c_void,
            option: u32,
            buffer: *mut c_void,
            length: u32,
        ) -> i32;
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(super) fn apply(
        manual: Option<&str>,
        pac: Option<&str>,
        bypass: &str,
    ) -> Result<(), String> {
        let mut server = wide(manual.unwrap_or(""));
        let mut bypass = wide(bypass);
        let mut url = wide(pac.unwrap_or(""));

        let flags = match (manual, pac) {
            (Some(_), _) => PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY,
            (None, Some(_)) => PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL,
            (None, None) => PROXY_TYPE_DIRECT,
        };
        let mut options = vec![Option_ {
            option: INTERNET_PER_CONN_FLAGS,
            value: OptionValue { dword: flags },
        }];
        if manual.is_some() {
            options.push(Option_ {
                option: INTERNET_PER_CONN_PROXY_SERVER,
                value: OptionValue {
                    string: server.as_mut_ptr(),
                },
            });
            options.push(Option_ {
                option: INTERNET_PER_CONN_PROXY_BYPASS,
                value: OptionValue {
                    string: bypass.as_mut_ptr(),
                },
            });
        }
        if pac.is_some() {
            options.push(Option_ {
                option: INTERNET_PER_CONN_AUTOCONFIG_URL,
                value: OptionValue {
                    string: url.as_mut_ptr(),
                },
            });
        }

        let mut list = OptionList {
            size: std::mem::size_of::<OptionList>() as u32,
            // Null is the LAN connection, which is what every modern Windows
            // uses for Wi-Fi and Ethernet alike.
            connection: std::ptr::null_mut(),
            count: options.len() as u32,
            error: 0,
            options: options.as_mut_ptr(),
        };

        // SAFETY: `list` and everything it points at outlive the calls, and
        // the sizes are the ones the API documents for these structures.
        unsafe {
            let ok = InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_PER_CONNECTION_OPTION,
                (&mut list as *mut OptionList).cast(),
                list.size,
            );
            if ok == 0 {
                return Err(format!(
                    "InternetSetOption failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null_mut(),
                0,
            );
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null_mut(),
                0,
            );
        }
        Ok(())
    }
}

fn run(binary: &str, args: &[&str]) -> Result<(), String> {
    let output = tool(binary)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run {binary}: {e}"))?;

    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.lines().next().unwrap_or("unknown error").trim();
    Err(format!("{binary} failed: {detail}"))
}

// ------------------------------------------------------------------ PAC

/// The URL the PAC script is served on.
pub fn pac_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/proxy.pac")
}

/// Build the PAC script.
///
/// Everything goes through the proxy except loopback, the local network and
/// plain hostnames — the same carve-outs the manual mode's ignore list has,
/// expressed as code because that is all PAC offers.
pub fn pac_script(endpoints: ProxyEndpoints) -> String {
    format!(
        r#"// Generated by ZeroNet. Do not edit; it is rebuilt on every launch.
function FindProxyForURL(url, host) {{
    // A bare hostname with no dots is a local machine.
    if (isPlainHostName(host)) return "DIRECT";

    if (host === "localhost" || host === "127.0.0.1" || host === "::1") return "DIRECT";

    if (isInNet(host, "127.0.0.0", "255.0.0.0")) return "DIRECT";
    if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
    if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT";
    if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";
    if (isInNet(host, "169.254.0.0", "255.255.0.0")) return "DIRECT";

    // SOCKS first so UDP-capable clients use it; HTTP is the fallback for
    // applications that speak nothing else.
    return "SOCKS5 127.0.0.1:{socks}; PROXY 127.0.0.1:{http}; DIRECT";
}}
"#,
        socks = endpoints.socks_port,
        http = endpoints.http_port,
    )
}

/// A tiny HTTP server that serves the PAC script and nothing else.
pub struct PacServer {
    port: u16,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl PacServer {
    /// Start serving `script` on `port`.
    pub async fn start(port: u16, script: String) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| format!("cannot serve the PAC file on port {port}: {e}"))?;
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(port);

        let (shutdown, mut rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { continue };
                        let script = script.clone();
                        tokio::spawn(async move {
                            // A client that connects and never sends would
                            // otherwise pin this task for ever.
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                serve_pac(stream, &script),
                            )
                            .await;
                        });
                    }
                }
            }
        });

        Ok(Self { port, shutdown })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn url(&self) -> String {
        pac_url(self.port)
    }
}

impl Drop for PacServer {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

async fn serve_pac(mut stream: tokio::net::TcpStream, script: &str) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read and discard the request line; this server has exactly one answer.
    let mut scratch = [0u8; 2048];
    let _ = stream.read(&mut scratch).await?;

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/x-ns-proxy-autoconfig\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n{script}",
        script.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> ProxyEndpoints {
        ProxyEndpoints {
            http_port: 10809,
            socks_port: 10808,
            pac_port: 11080,
        }
    }

    const ALL_MODES: [SystemProxyMode; 4] = [
        SystemProxyMode::Unmanaged,
        SystemProxyMode::Manual,
        SystemProxyMode::Pac,
        SystemProxyMode::Clear,
    ];

    #[test]
    fn modes_cycle_through_all_four_and_wrap() {
        let mut mode = SystemProxyMode::Unmanaged;
        for expected in [
            SystemProxyMode::Manual,
            SystemProxyMode::Pac,
            SystemProxyMode::Clear,
            SystemProxyMode::Unmanaged,
        ] {
            mode = mode.next();
            assert_eq!(mode, expected);
        }
    }

    #[test]
    fn every_mode_round_trips_and_is_labelled() {
        for m in ALL_MODES {
            assert_eq!(SystemProxyMode::parse(m.as_str()), Some(m));
            assert!(!m.label().is_empty());
            assert!(!m.chip_label().is_empty());
            assert!(!m.describe().is_empty());
        }
        assert_eq!(SystemProxyMode::parse("nonsense"), None);
    }

    #[test]
    fn labels_are_short_enough_for_their_widgets() {
        for m in ALL_MODES {
            // The settings hint column gets what is left after a 22-column
            // label and a 16-column value, which on a 150-column terminal is
            // about 24. Anything longer is clipped.
            assert!(
                m.describe().chars().count() <= 24,
                "{:?} description {:?} is too long ({} chars)",
                m,
                m.describe(),
                m.describe().chars().count()
            );
            // The header chip has 11 usable columns inside its border.
            assert!(
                m.chip_label().chars().count() <= 11,
                "{:?} chip label {:?} is too wide",
                m,
                m.chip_label()
            );
            // The settings value column is 16 wide.
            assert!(m.label().chars().count() <= 16, "{:?} label too wide", m);
        }
    }

    #[test]
    fn only_unmanaged_leaves_the_desktop_alone() {
        // This is the distinction the mode exists for: "do not change" must
        // never write, while "clear" actively forces no-proxy.
        assert!(!SystemProxyMode::Unmanaged.writes_settings());
        assert!(SystemProxyMode::Clear.writes_settings());
        assert!(SystemProxyMode::Manual.writes_settings());
        assert!(SystemProxyMode::Pac.writes_settings());
    }

    #[test]
    fn unmanaged_and_clear_are_distinct_modes() {
        assert_ne!(SystemProxyMode::Unmanaged, SystemProxyMode::Clear);
        assert_ne!(
            SystemProxyMode::Unmanaged.chip_label(),
            SystemProxyMode::Clear.chip_label()
        );
        assert_ne!(
            SystemProxyMode::Unmanaged.describe(),
            SystemProxyMode::Clear.describe()
        );
    }

    #[test]
    fn the_default_is_hands_off() {
        // A client that rewrites the system proxy on first launch, before the
        // user has asked for anything, is a client that breaks machines.
        assert_eq!(SystemProxyMode::default(), SystemProxyMode::Unmanaged);
        assert!(!SystemProxyMode::default().writes_settings());
    }

    #[test]
    fn settings_written_by_an_earlier_build_still_parse() {
        // "off" used to mean the clearing behaviour, so it maps to Clear
        // rather than silently becoming hands-off.
        assert_eq!(SystemProxyMode::parse("off"), Some(SystemProxyMode::Clear));
        assert_eq!(SystemProxyMode::parse("none"), Some(SystemProxyMode::Clear));
    }

    #[test]
    fn applying_unmanaged_is_a_no_op_on_every_backend() {
        // Including the unsupported one: doing nothing cannot fail.
        assert!(apply(SystemProxyMode::Unmanaged, endpoints()).is_ok());
    }

    #[test]
    fn an_empty_snapshot_falls_back_to_clearing() {
        // macOS and Windows capture nothing, so restore falls back to
        // clearing rather than pretending it put something back. Checked
        // through `restore_strategy` so the test does not write to the real
        // desktop.
        for backend in [Backend::Unsupported, Backend::MacOs, Backend::Windows] {
            let empty = snapshot_of(backend, Vec::new(), Vec::new());
            assert!(empty.is_empty());
            assert_eq!(restore_strategy(&empty), RestoreStrategy::Clear);
        }
    }

    #[test]
    fn a_populated_snapshot_is_replayed_verbatim() {
        for backend in [Backend::Kde, Backend::Gnome] {
            let snap = snapshot_of(backend, vec![("ProxyType".into(), "1".into())], Vec::new());
            assert!(!snap.is_empty());
            assert_eq!(restore_strategy(&snap), RestoreStrategy::Replay);
        }
    }

    #[test]
    fn a_backend_with_no_captured_keys_is_not_replayed() {
        // Replaying an empty list would leave the desktop pointed at our
        // ports while reporting that it had been put back.
        let snap = snapshot_of(Backend::Kde, Vec::new(), Vec::new());
        assert_eq!(restore_strategy(&snap), RestoreStrategy::Clear);
    }

    #[test]
    fn a_snapshot_captures_the_keys_this_module_writes() {
        // Anything written but not captured would be lost on restore.
        // On Linux that is every store `apply` writes to that is present on
        // the machine, whichever desktop is running.
        let snap = snapshot();
        match snap.backend() {
            Backend::Kde | Backend::Gnome => {
                if kde_tool_present() {
                    assert_eq!(snap.kde.len(), KDE_KEYS.len());
                    for key in KDE_KEYS {
                        assert!(
                            snap.kde.iter().any(|(k, _)| k == key),
                            "{key} was not captured"
                        );
                    }
                }
                if which("gsettings").is_some() {
                    assert_eq!(snap.gnome.len(), GNOME_KEYS.len());
                }
            }
            _ => assert!(snap.is_empty()),
        }
    }

    fn snapshot_of(
        backend: Backend,
        kde: Vec<(String, String)>,
        gnome: Vec<(String, String)>,
    ) -> ProxySnapshot {
        ProxySnapshot {
            backend,
            kde,
            gnome,
            env: Vec::new(),
        }
    }

    #[test]
    fn either_linux_store_alone_is_enough_to_replay() {
        // A GNOME session with only the GNOME store captured, and the other
        // way round, must both be replayed rather than cleared.
        let gnome_only = snapshot_of(
            Backend::Kde,
            Vec::new(),
            vec![("org.gnome.system.proxy|mode".into(), "'none'".into())],
        );
        assert_eq!(restore_strategy(&gnome_only), RestoreStrategy::Replay);
    }

    #[test]
    fn a_snapshot_survives_the_trip_to_disk() {
        // The crash-recovery file is only useful if it reads back verbatim.
        let snap = ProxySnapshot {
            backend: Backend::Gnome,
            kde: vec![("ProxyType".into(), String::new())],
            gnome: vec![("org.gnome.system.proxy|mode".into(), "'auto'".into())],
            env: vec![
                ("http_proxy".into(), Some("http://10.0.0.1:3128".into())),
                ("https_proxy".into(), None),
            ],
        };
        let body = serde_json::to_vec(&snap).unwrap();
        assert_eq!(
            serde_json::from_slice::<ProxySnapshot>(&body).unwrap(),
            snap
        );
    }

    #[test]
    fn the_env_listing_is_read_without_mangling_escaped_values() {
        let listing = "HOME=/home/u\nhttp_proxy=http://10.0.0.1:3128\nno_proxy=$'a\\tb'\nALL_PROXY=socks5://h:1\n";
        let parsed = parse_env_listing(listing);
        let get = |k: &str| parsed.iter().find(|(key, _)| key == k).unwrap().1.clone();
        assert_eq!(get("http_proxy").as_deref(), Some("http://10.0.0.1:3128"));
        assert_eq!(get("ALL_PROXY").as_deref(), Some("socks5://h:1"));
        assert_eq!(
            get("no_proxy"),
            None,
            "an escaped value must not be replayed verbatim"
        );
        assert_eq!(get("https_proxy"), None);
        // PAC mode's variable is tracked too.
        assert!(parsed.iter().any(|(k, _)| k == "auto_proxy"));
    }

    #[test]
    fn the_pac_script_keeps_local_traffic_direct() {
        let script = pac_script(endpoints());
        assert!(script.contains("isPlainHostName"));
        assert!(script.contains("127.0.0.0"));
        assert!(script.contains("10.0.0.0"));
        assert!(script.contains("192.168.0.0"));
        // Link-local, so a captive portal check does not go through the
        // tunnel.
        assert!(script.contains("169.254.0.0"));
    }

    #[test]
    fn the_pac_script_points_at_the_configured_ports() {
        let script = pac_script(endpoints());
        assert!(script.contains("SOCKS5 127.0.0.1:10808"));
        assert!(script.contains("PROXY 127.0.0.1:10809"));
        // A fallback to DIRECT, so a dead proxy does not black-hole the
        // machine's networking.
        assert!(script.contains("; DIRECT"));
    }

    #[test]
    fn pac_urls_are_well_formed() {
        assert_eq!(pac_url(11080), "http://127.0.0.1:11080/proxy.pac");
    }

    #[tokio::test]
    async fn the_pac_server_serves_the_script_with_the_right_content_type() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Port 0 lets the OS choose, so the test cannot collide with
        // anything else on the machine.
        let server = PacServer::start(0, pac_script(endpoints()))
            .await
            .expect("PAC server starts");
        assert!(server.port() != 0);
        assert!(server.url().contains(&server.port().to_string()));

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port()))
            .await
            .expect("connects");
        stream
            .write_all(b"GET /proxy.pac HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        let text = String::from_utf8_lossy(&body);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("application/x-ns-proxy-autoconfig"));
        assert!(text.contains("FindProxyForURL"));
        assert!(text.contains("SOCKS5 127.0.0.1:10808"));
    }

    #[tokio::test]
    async fn dropping_the_server_releases_its_port() {
        let server = PacServer::start(0, "// pac".into()).await.unwrap();
        let port = server.port();
        drop(server);

        // The listener is closed when the accept loop observes the shutdown.
        let mut released = false;
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .is_ok()
            {
                released = true;
                break;
            }
        }
        assert!(
            released,
            "the PAC server kept port {port} after being dropped"
        );
    }

    #[test]
    fn an_unsupported_desktop_reports_rather_than_pretending() {
        // The important property: `set_manual` on an unsupported backend must
        // return an error. Silently succeeding would tell the user their
        // traffic is proxied when it is not.
        let err = set_manual(Backend::Unsupported, endpoints()).unwrap_err();
        assert!(err.contains("no supported desktop"), "{err}");
        assert!(set_pac(Backend::Unsupported, "http://x/proxy.pac").is_err());
    }

    #[test]
    fn backend_detection_returns_something_nameable() {
        // Whatever this machine is, the result must be printable — it goes on
        // the settings screen.
        let backend = detect_backend();
        assert!(!backend.to_string().is_empty());
    }
}
