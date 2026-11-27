//! Starting from a double-click.
//!
//! A terminal application opened from a file manager, an application menu,
//! an AppImage or a macOS `.app` bundle has no terminal to draw in: stdin and
//! stdout are `/dev/null` or a pipe to the desktop's log. Rather than exit
//! silently — which looks exactly like "the app is broken" — the client
//! reopens itself inside a terminal window.
//!
//! Windows needs none of this: a console-subsystem executable always gets a
//! console window, double-clicked or not. What it does need is for that
//! window not to vanish the instant the app fails to start, taking the error
//! message with it — see [`hold_window_on_error`].

use std::io::IsTerminal;

/// Set on the relaunched copy so a terminal that still gives no TTY cannot
/// turn this into an endless chain of windows.
const RELAUNCHED: &str = "ZERONET_RELAUNCHED";

/// What `main` should do next.
pub enum Launch {
    /// A terminal is attached: run the interface here.
    Run,
    /// The interface has been opened in a new terminal window; exit.
    Relaunched,
}

/// Make sure the interface has a terminal, opening one if necessary.
pub fn ensure_terminal() -> Launch {
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        return Launch::Run;
    }
    if cfg!(windows) || std::env::var_os(RELAUNCHED).is_some() {
        return Launch::Run;
    }
    match relaunch_in_terminal() {
        Ok(()) => Launch::Relaunched,
        Err(error) => {
            // Nobody may see stderr, but a desktop notification is seen.
            notify(&format!("ZeroNet needs a terminal: {error}"));
            eprintln!("ZeroNet needs a terminal to run: {error}");
            Launch::Run
        }
    }
}

/// The file to run again. Inside an AppImage the executable lives on a
/// mount that disappears when this process exits, so the AppImage itself is
/// what has to be started.
#[cfg(unix)]
fn self_path() -> std::io::Result<std::path::PathBuf> {
    if let Some(appimage) = std::env::var_os("APPIMAGE") {
        return Ok(appimage.into());
    }
    std::env::current_exe()
}

#[cfg(target_os = "macos")]
fn relaunch_in_terminal() -> Result<(), String> {
    let exe = self_path().map_err(|e| e.to_string())?;
    // Terminal runs an executable handed to it the same way Finder does
    // when a bare Unix binary is double-clicked.
    let status = std::process::Command::new("open")
        .args(["-a", "Terminal"])
        .arg(&exe)
        .status()
        .map_err(|e| format!("cannot run open: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("Terminal.app refused to start ZeroNet".into())
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn relaunch_in_terminal() -> Result<(), String> {
    let exe = self_path().map_err(|e| e.to_string())?;
    let exe = exe.to_string_lossy().into_owned();

    // (program, arguments placed before the command). The user's own
    // choice first, then the Debian alternative, then the common desktops'
    // defaults, then the rest.
    let mut candidates: Vec<(String, Vec<&str>)> = Vec::new();
    if let Ok(terminal) = std::env::var("TERMINAL") {
        if !terminal.trim().is_empty() {
            candidates.push((terminal, vec!["-e"]));
        }
    }
    for (program, args) in [
        ("x-terminal-emulator", vec!["-e"]),
        ("ptyxis", vec!["--"]),
        ("kgx", vec!["--"]),
        ("gnome-terminal", vec!["--"]),
        ("konsole", vec!["-e"]),
        ("xfce4-terminal", vec!["-x"]),
        ("mate-terminal", vec!["-x"]),
        ("tilix", vec!["-e"]),
        ("lxterminal", vec!["-e"]),
        ("qterminal", vec!["-e"]),
        ("deepin-terminal", vec!["-e"]),
        ("terminator", vec!["-x"]),
        ("kitty", vec![]),
        ("alacritty", vec!["-e"]),
        ("wezterm", vec!["start", "--"]),
        ("foot", vec![]),
        ("xterm", vec!["-e"]),
    ] {
        candidates.push((program.to_string(), args));
    }

    for (program, args) in candidates {
        if which(&program).is_none() {
            continue;
        }
        let spawned = std::process::Command::new(&program)
            .args(&args)
            .arg(&exe)
            .env(RELAUNCHED, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if spawned.is_ok() {
            return Ok(());
        }
    }
    Err(
        "no terminal emulator was found; install one (for example xterm) or run \
         ZeroNet from a terminal"
            .into(),
    )
}

#[cfg(not(unix))]
fn relaunch_in_terminal() -> Result<(), String> {
    Err("unsupported platform".into())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn which(program: &str) -> Option<std::path::PathBuf> {
    if program.contains('/') {
        let path = std::path::PathBuf::from(program);
        return path.is_file().then_some(path);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

fn notify(message: &str) {
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("notify-send")
        .args(["ZeroNet", message])
        .status();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("osascript")
        .args([
            "-e",
            &format!("display notification {:?} with title \"ZeroNet\"", message),
        ])
        .status();
    #[cfg(not(unix))]
    let _ = message;
}

/// Keep a double-clicked console window open long enough to read an error.
///
/// Only when this process is the console's sole user — i.e. Windows created
/// the window for it. Started from an existing terminal, the terminal
/// already keeps the message, and waiting would only be in the way.
pub fn hold_window_on_error() {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
        }
        let mut ids = [0u32; 4];
        // SAFETY: the buffer and its length match.
        let attached = unsafe { GetConsoleProcessList(ids.as_mut_ptr(), ids.len() as u32) };
        if attached <= 1 {
            use std::io::{BufRead, Write};
            let mut err = std::io::stderr();
            let _ = writeln!(err, "\nPress Enter to close this window.");
            let _ = err.flush();
            let mut line = String::new();
            let _ = std::io::stdin().lock().read_line(&mut line);
        }
    }
}
