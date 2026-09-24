//! Getting a TUN interface without running the whole client as root.
//!
//! ## Why a helper process
//!
//! Opening `/dev/net/tun` and installing routes needs `CAP_NET_ADMIN`.
//! Nothing a process can do at runtime grants it that: `sudo` elevates a
//! *child*, and a child's capabilities do not flow back to its parent. So
//! "ask for the password, then open the device" is not a thing a single
//! process can do — which is why turning TUN on in an unprivileged session
//! used to silently fall back to proxy mode no matter what the user typed.
//!
//! An open descriptor, on the other hand, needs no privileges at all to read
//! and write. That asymmetry is the whole design:
//!
//! 1. The client spawns itself again through `sudo`, in [`HELPER_FLAG`] mode,
//!    and feeds the user's password to `sudo` on stdin.
//! 2. The helper — now root — opens the device, assigns the addresses, raises
//!    the link and installs the routes.
//! 3. It passes the descriptor back over a unix socket with `SCM_RIGHTS`, and
//!    then *stays alive*, holding the link configuration.
//! 4. The client adopts the descriptor through [`zero_tun::inherited`], which
//!    is the same path Android and iOS use for a host-created interface, so
//!    the engine already knows not to reconfigure the link underneath it.
//!
//! Teardown follows from the same structure rather than needing its own
//! privileges: the helper's stdin is a pipe held by the client, so when the
//! client disconnects — or exits, or crashes — the helper reaches EOF, drops
//! its guard and removes the routes. The kernel then deletes the interface
//! once the last descriptor closes.
//!
//! ## What is deliberately not done here
//!
//! The password is never written to disk, never passed as an argument (where
//! it would be visible in `ps`), and never logged. It goes to `sudo`'s stdin
//! and the buffer is zeroed after use. `sudo -v` is used to validate it,
//! which also primes sudo's own timestamp, so a reconnect inside the ticket
//! window needs no second prompt.

#![cfg_attr(not(unix), allow(dead_code))]

use std::io;

/// Argument that turns this binary into the privileged helper.
pub const HELPER_FLAG: &str = "--tun-helper";

/// Why TUN cannot be brought up, in words a user can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevationError {
    /// No `sudo`, `doas` or equivalent on this machine.
    NoBackend(String),
    /// The password was wrong, or the account may not use sudo.
    Rejected,
    /// Everything was in place and the helper still failed.
    Failed(String),
    /// This platform does not do password elevation at all.
    Unsupported,
}

impl std::fmt::Display for ElevationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ElevationError::NoBackend(what) => write!(f, "{what}"),
            ElevationError::Rejected => {
                write!(f, "That password was not accepted.")
            }
            ElevationError::Failed(why) => write!(f, "{why}"),
            ElevationError::Unsupported => write!(
                f,
                "This system can't be elevated with a password. Restart ZeroNet as administrator."
            ),
        }
    }
}

/// How privileges can be obtained on this machine, decided once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevator {
    /// Already root, or already holding `CAP_NET_ADMIN`.
    NotNeeded,
    /// `sudo` is present and will be driven with the password on stdin.
    Sudo,
    /// `doas` is present. Same protocol: password on stdin.
    Doas,
    /// Nothing usable was found.
    None,
}

impl Elevator {
    fn program(self) -> Option<&'static str> {
        match self {
            Elevator::Sudo => Some("sudo"),
            Elevator::Doas => Some("doas"),
            _ => None,
        }
    }

    /// Whether a password dialog is worth showing at all.
    ///
    /// Only `sudo` can be handed a password on stdin (`-S`). `doas` has no
    /// such option — it reads from the controlling terminal, which the TUI
    /// owns in raw mode — so it is used exactly when it needs no password
    /// (`nopass`, or a `persist` ticket), and a dialog would only collect a
    /// password that could never be delivered.
    pub fn can_prompt(self) -> bool {
        matches!(self, Elevator::Sudo)
    }

    /// Arguments that make the elevation tool run a command without ever
    /// touching the terminal: `sudo` reads the password from stdin with no
    /// prompt, `doas` refuses rather than prompting.
    fn noninteractive_args(self) -> &'static [&'static str] {
        match self {
            Elevator::Sudo => &["-S", "-p", ""],
            Elevator::Doas => &["-n"],
            _ => &[],
        }
    }
}

/// Look for a way to elevate, without running anything privileged.
pub fn detect() -> Elevator {
    if zero_tun::check_tun_permissions().is_ready() {
        return Elevator::NotNeeded;
    }
    #[cfg(unix)]
    {
        if which("sudo").is_some() {
            return Elevator::Sudo;
        }
        if which("doas").is_some() {
            return Elevator::Doas;
        }
    }
    Elevator::None
}

/// Whether privileges are already available without asking for anything.
///
/// True when the process is root or holds `CAP_NET_ADMIN`, and also when
/// `sudo` is configured to need no password — either by policy or because a
/// ticket from an earlier prompt is still valid. Checked before a dialog is
/// raised, because asking for a password that is not needed trains people to
/// type it at anything that asks.
pub fn privileges_ready() -> bool {
    if zero_tun::check_tun_permissions().is_ready() {
        return true;
    }
    #[cfg(unix)]
    {
        let elevator = detect();
        if let Some(program) = elevator.program() {
            // `-n` never prompts: it succeeds only if no password is wanted.
            return std::process::Command::new(program)
                .arg("-n")
                .arg("true")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
        }
    }
    false
}

/// Check a password and prime the sudo ticket with it.
///
/// Validating separately from using it is what lets the dialog say "wrong
/// password" instead of "TUN failed": by the time the helper runs, a refusal
/// is indistinguishable from a dozen other failures.
pub fn validate_password(password: &str) -> Result<(), ElevationError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let elevator = detect();
        if elevator == Elevator::NotNeeded {
            return Ok(());
        }
        let Some(program) = elevator.program() else {
            return Err(ElevationError::NoBackend(
                "No sudo or doas on this machine. TUN needs one of them, or ZeroNet started as root.".into(),
            ));
        };
        if !elevator.can_prompt() {
            return Err(ElevationError::NoBackend(format!(
                "{program} cannot take a password from this client — allow it without one \
                 (`permit persist` or `nopass` in doas.conf), or install sudo."
            )));
        }

        // `-v` only refreshes the timestamp. It runs no command, so a typo
        // cannot have side effects, and on success every later `-n` call
        // inside the ticket window needs no password.
        let mut child = Command::new(program)
            .args(["-S", "-p", "", "-v"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ElevationError::NoBackend(format!("could not run {program}: {e}")))?;

        if let Some(stdin) = child.stdin.as_mut() {
            // A trailing newline is what sudo's prompt reader waits for.
            let _ = stdin.write_all(password.as_bytes());
            let _ = stdin.write_all(b"\n");
            let _ = stdin.flush();
        }
        // The pipe has to close, or sudo waits for a second attempt.
        drop(child.stdin.take());

        let output = child
            .wait_with_output()
            .map_err(|e| ElevationError::Failed(format!("{program} did not finish: {e}")))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("incorrect password")
            || stderr.contains("Sorry, try again")
            || stderr.contains("Authentication failure")
            || stderr.contains("authentication failure")
        {
            return Err(ElevationError::Rejected);
        }
        let trimmed = stderr.trim();
        Err(if trimmed.is_empty() {
            ElevationError::Rejected
        } else {
            ElevationError::Failed(trimmed.to_string())
        })
    }
    #[cfg(not(unix))]
    {
        let _ = password;
        Err(ElevationError::Unsupported)
    }
}

/// What the helper needs in order to build the interface.
///
/// Sent as one JSON line on the helper's stdin. Nothing here is secret — the
/// password goes to `sudo`, not to the helper — so it is safe to have it in
/// a pipe, and being a single line keeps the framing trivial on both sides.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TunRequest {
    pub name: String,
    pub mtu: usize,
    pub addresses: Vec<String>,
    pub routes: Vec<String>,
    pub auto_route: bool,
    pub strict_route: bool,
    /// Addresses that must keep reaching the network directly, or the tunnel
    /// would route its own transport into itself.
    pub bypass_ips: Vec<String>,
    /// Where to send the descriptor back.
    pub socket_path: String,
}

/// What came back: the adopted descriptor and the interface it belongs to.
#[derive(Debug)]
pub struct TunHandover {
    pub fd: i32,
    pub header_len: usize,
    pub mtu: usize,
    pub device: String,
    /// The physical interface traffic used before the tunnel's routes went
    /// in. The engine's own sockets are pinned to it, or anything it
    /// connects to directly would be routed back into the tunnel.
    pub uplink: Option<String>,
}

/// Derive a helper request from the TUN inbound of a built engine config.
///
/// Read out of the config rather than rebuilt from settings, so the interface
/// the helper creates is the one the engine is about to expect. Two sources
/// of truth for addresses and routes would be a silent misconfiguration
/// waiting to happen.
pub fn request_from_config(config_json: &str, socket_path: &str) -> Option<TunRequest> {
    let value: serde_json::Value = serde_json::from_str(config_json).ok()?;
    let tun = value
        .get("inbounds")?
        .as_array()?
        .iter()
        .find(|i| i.get("protocol").and_then(|p| p.as_str()) == Some("tun"))?;
    let settings = tun.get("settings")?;

    let strings = |key: &str| -> Vec<String> {
        settings
            .get(key)
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|i| i.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };

    // Whatever the profile dials has to stay reachable off-tunnel.
    let bypass_ips = value
        .get("outbounds")
        .and_then(|o| o.as_array())
        .map(|outbounds| {
            outbounds
                .iter()
                .filter_map(outbound_server_ip)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(TunRequest {
        name: settings
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("zeronet0")
            .to_string(),
        mtu: settings.get("mtu").and_then(|m| m.as_u64()).unwrap_or(1500) as usize,
        addresses: strings("addresses"),
        routes: strings("routes"),
        auto_route: settings
            .get("autoRoute")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        strict_route: settings
            .get("strictRoute")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        bypass_ips,
        socket_path: socket_path.to_string(),
    })
}

/// A literal server address from an outbound, if it has one.
///
/// Only literals are useful: a hostname cannot be given a bypass route
/// without resolving it, and resolution at this point would go through the
/// DNS the tunnel is about to take over.
fn outbound_server_ip(outbound: &serde_json::Value) -> Option<String> {
    if let Some(link) = outbound.get("link").and_then(|l| l.as_str()) {
        return host_from_link(link);
    }
    let settings = outbound.get("settings")?;
    for key in ["vnext", "servers"] {
        if let Some(entries) = settings.get(key).and_then(|v| v.as_array()) {
            for entry in entries {
                if let Some(address) = entry.get("address").and_then(|a| a.as_str()) {
                    if address.parse::<std::net::IpAddr>().is_ok() {
                        return Some(address.to_string());
                    }
                }
            }
        }
    }
    None
}

/// The host of a share link, when it is a literal address.
fn host_from_link(link: &str) -> Option<String> {
    let after_scheme = link.split_once("://")?.1;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // An IPv6 literal is bracketed, so the port cannot be split off by the
    // last colon until the brackets are dealt with.
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']').map(|(inner, _)| inner)?
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    host.parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

// -------------------------------------------------------------- client side

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    /// A running helper, and the interface it is holding up.
    ///
    /// Dropping this closes the helper's stdin, which is how the helper is
    /// told to undo what it installed. Teardown therefore cannot be forgotten
    /// by a caller, and survives the client being killed.
    pub struct PrivilegedTun {
        child: Child,
        socket_path: PathBuf,
        pub device: String,
        /// What the interface was built from, to tell whether a new profile
        /// can reuse it.
        request: TunRequest,
        /// This process's own descriptor to the device. The engine is given
        /// a duplicate and closes it when it stops; keeping one here is what
        /// keeps the interface (and its routes) alive between engines, so a
        /// server switch does not have to rebuild it.
        kept_fd: i32,
        header_len: usize,
        /// Where the tunnel's own traffic has to leave by; see
        /// [`TunHandover::uplink`].
        uplink: Option<String>,
        /// The helper's replies to route updates.
        replies: Option<std::io::BufReader<std::process::ChildStdout>>,
    }

    impl PrivilegedTun {
        /// Whether the helper is still alive.
        pub fn is_running(&mut self) -> bool {
            matches!(self.child.try_wait(), Ok(None))
        }

        /// Whether this interface can carry `request` as it stands: the same
        /// device, addresses and routes. Only the servers kept off the
        /// tunnel may differ, and those can be changed in place.
        pub fn serves(&self, request: &TunRequest) -> bool {
            let mine = &self.request;
            mine.name == request.name
                && mine.mtu == request.mtu
                && mine.addresses == request.addresses
                && mine.routes == request.routes
                && mine.auto_route == request.auto_route
                && mine.strict_route == request.strict_route
        }

        /// Point the interface at a new server: swap the bypass routes and
        /// hand out a fresh descriptor for the next engine.
        ///
        /// Blocking (it waits up to five seconds for the helper's answer), so
        /// call it off the frame loop.
        pub fn retarget(&mut self, request: &TunRequest) -> Result<TunHandover, ElevationError> {
            let update = serde_json::json!({ "bypass_ips": request.bypass_ips }).to_string();
            let stdin = self
                .child
                .stdin
                .as_mut()
                .ok_or_else(|| ElevationError::Failed("the TUN helper has gone".into()))?;
            stdin
                .write_all(update.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.flush())
                .map_err(|e| ElevationError::Failed(format!("the TUN helper has gone: {e}")))?;
            let replies = self
                .replies
                .as_mut()
                .ok_or_else(|| ElevationError::Failed("the TUN helper cannot answer".into()))?;
            let answer =
                read_line_within(replies, std::time::Duration::from_secs(5)).map_err(|e| {
                    ElevationError::Failed(format!("the TUN helper did not answer: {e}"))
                })?;
            match answer.trim() {
                "ok" => {}
                other => {
                    let reason = other.strip_prefix("err ").unwrap_or(other);
                    return Err(ElevationError::Failed(format!(
                        "could not reroute the tunnel: {reason}"
                    )));
                }
            }
            // SAFETY: `kept_fd` is a descriptor this struct owns and has not
            // closed; F_DUPFD_CLOEXEC returns a new one or -1.
            let fd = unsafe { libc::fcntl(self.kept_fd, libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                return Err(ElevationError::Failed(format!(
                    "duplicating the TUN descriptor: {}",
                    io::Error::last_os_error()
                )));
            }
            self.request.bypass_ips = request.bypass_ips.clone();
            Ok(TunHandover {
                fd,
                header_len: self.header_len,
                mtu: self.request.mtu,
                device: self.request.name.clone(),
                uplink: self.uplink.clone(),
            })
        }
    }

    /// Read one line, giving up after `timeout` instead of blocking forever
    /// on a helper that has wedged.
    fn read_line_within(
        reader: &mut std::io::BufReader<std::process::ChildStdout>,
        timeout: std::time::Duration,
    ) -> io::Result<String> {
        use std::io::BufRead;
        use std::os::fd::AsRawFd;
        let deadline = std::time::Instant::now() + timeout;
        let mut line = String::new();
        loop {
            // Whatever is already buffered needs no waiting.
            if !reader.buffer().is_empty() {
                reader.read_line(&mut line)?;
                if line.ends_with('\n') {
                    return Ok(line);
                }
                continue;
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "no reply"));
            }
            let mut poll = libc::pollfd {
                fd: reader.get_ref().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd for the duration of the call.
            let ready =
                unsafe { libc::poll(&mut poll, 1, left.as_millis().min(i32::MAX as u128) as i32) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            if reader.read_line(&mut line)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the helper exited",
                ));
            }
            if line.ends_with('\n') {
                return Ok(line);
            }
        }
    }

    impl Drop for PrivilegedTun {
        fn drop(&mut self) {
            if self.kept_fd >= 0 {
                // SAFETY: owned descriptor, closed exactly once.
                unsafe { libc::close(self.kept_fd) };
                self.kept_fd = -1;
            }
            // Closing stdin is the ordinary signal; the kill is for a helper
            // that is wedged, and it is a no-op once the process has gone.
            drop(self.child.stdin.take());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) if std::time::Instant::now() >= deadline => {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        break;
                    }
                    Ok(None) => std::thread::sleep(std::time::Duration::from_millis(25)),
                }
            }
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }

    /// Bring up a TUN interface through a privileged helper.
    ///
    /// `password` is `None` when sudo needs none — see [`privileges_ready`].
    /// It is written to sudo's stdin and nowhere else.
    pub fn open_privileged_tun(
        request: &TunRequest,
        password: Option<&str>,
    ) -> Result<(PrivilegedTun, TunHandover), ElevationError> {
        // Already privileged means there is nothing to elevate through: the
        // helper is spawned as a plain child. The handover then works exactly
        // as it does under sudo, which is also what makes this path testable
        // inside a user namespace, where no setuid binary would run.
        let elevator = detect();
        let program = match elevator {
            Elevator::NotNeeded => None,
            _ => Some(elevator.program().ok_or_else(|| {
                ElevationError::NoBackend(
                    "No sudo or doas on this machine, and TUN needs one of them.".into(),
                )
            })?),
        };

        let socket_path = PathBuf::from(&request.socket_path);
        if let Some(parent) = socket_path.parent() {
            prepare_private_dir(parent)?;
        }
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).map_err(|e| {
            ElevationError::Failed(format!(
                "could not listen on {}: {e}",
                socket_path.display()
            ))
        })?;
        // The socket is how the descriptor arrives; anyone who can connect to
        // it before the helper does would be handed the tunnel.
        restrict_to_owner(&socket_path);
        listener
            .set_nonblocking(false)
            .map_err(|e| ElevationError::Failed(e.to_string()))?;

        // Normally the helper is this very binary re-executed. `ZERONET_TUN_HELPER`
        // overrides that, which is what lets a package ship a separate,
        // minimal helper — and what lets the handover be tested without a
        // terminal client in the loop.
        let exe = match std::env::var_os("ZERONET_TUN_HELPER") {
            Some(path) => PathBuf::from(path),
            None => std::env::current_exe()
                .map_err(|e| ElevationError::Failed(format!("cannot locate this binary: {e}")))?,
        };

        let mut command = match program {
            Some(program) => {
                let mut command = Command::new(program);
                // sudo: `-S` reads the password from stdin and `-p ""`
                // suppresses the prompt, which would otherwise be written to
                // the terminal the TUI has taken over. doas: `-n`, since it
                // cannot read a password from anywhere but that terminal.
                command.args(elevator.noninteractive_args());
                command.arg(&exe);
                command
            }
            None => Command::new(&exe),
        };
        command
            .arg(HELPER_FLAG)
            .stdin(Stdio::piped())
            // Replies to route updates after the handover.
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().map_err(|e| {
            ElevationError::NoBackend(format!(
                "could not run {}: {e}",
                program.unwrap_or("the privileged helper")
            ))
        })?;

        {
            let Some(stdin) = child.stdin.as_mut() else {
                return Err(ElevationError::Failed("helper has no stdin".into()));
            };
            // Only feed the password when sudo still needs it. `validate_password`
            // may have already cached a ticket (via `sudo -v`), in which case
            // `privileges_ready()` is true and `sudo -S` does not read the password
            // — leaving it in the pipe would corrupt the JSON request the helper
            // parses from stdin.
            if let (true, Some(password)) = (elevator.can_prompt(), password) {
                if !privileges_ready() {
                    let _ = stdin.write_all(password.as_bytes());
                    let _ = stdin.write_all(b"\n");
                }
            }
            let line = serde_json::to_string(request)
                .map_err(|e| ElevationError::Failed(e.to_string()))?;
            stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.flush())
                .map_err(|e| ElevationError::Failed(format!("sending the request: {e}")))?;
        }

        // Accept with a deadline, and give up the moment the helper dies. A
        // refused password is the common case, and waiting out the full
        // timeout for it would freeze the frame loop for twenty seconds on
        // the most ordinary mistake there is.
        let accepted =
            accept_with_timeout(&listener, &mut child, std::time::Duration::from_secs(20));
        let stream = match accepted {
            Ok(stream) => stream,
            Err(_) => {
                let reason = helper_failure(&mut child);
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_file(&socket_path);
                return Err(reason);
            }
        };

        // A helper that connects and then stalls must not wedge the caller:
        // `recvmsg` honours the receive timeout.
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let (fd, header_len, uplink) = recv_descriptor(&stream).map_err(|e| {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&socket_path);
            ElevationError::Failed(format!("receiving the TUN descriptor: {e}"))
        })?;

        let handover = TunHandover {
            fd,
            header_len,
            mtu: request.mtu,
            device: request.name.clone(),
            uplink: uplink.clone(),
        };
        // SAFETY: `fd` was just received and is open; F_DUPFD_CLOEXEC
        // returns a new descriptor or -1.
        let kept_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if kept_fd < 0 {
            let error = io::Error::last_os_error();
            // SAFETY: the received descriptor is ours to close.
            unsafe { libc::close(fd) };
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&socket_path);
            return Err(ElevationError::Failed(format!(
                "keeping the TUN descriptor: {error}"
            )));
        }
        let replies = child.stdout.take().map(std::io::BufReader::new);
        Ok((
            PrivilegedTun {
                child,
                socket_path,
                device: request.name.clone(),
                request: request.clone(),
                kept_fd,
                header_len,
                uplink,
                replies,
            },
            handover,
        ))
    }

    /// Whatever the helper managed to say before failing.
    fn helper_failure(child: &mut Child) -> ElevationError {
        let mut message = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            use std::io::Read;
            let mut buf = Vec::new();
            let _ = stderr.read_to_end(&mut buf);
            message = String::from_utf8_lossy(&buf).trim().to_string();
        }
        let lowered = message.to_ascii_lowercase();
        if lowered.contains("incorrect password")
            || lowered.contains("sorry, try again")
            || lowered.contains("authentication failure")
        {
            return ElevationError::Rejected;
        }
        if message.is_empty() {
            ElevationError::Failed(
                "the privileged helper didn't start. Check that sudo works for this account".into(),
            )
        } else {
            // Only the last line: sudo's lecture is several lines of advice
            // that would bury the actual reason.
            ElevationError::Failed(
                message
                    .lines()
                    .rfind(|l| !l.trim().is_empty())
                    .unwrap_or(&message)
                    .to_string(),
            )
        }
    }

    /// Accept one connection, or give up.
    ///
    /// `UnixListener` has no timeout of its own, so the wait is done on the
    /// listener's own descriptor with `poll`.
    fn accept_with_timeout(
        listener: &UnixListener,
        child: &mut Child,
        timeout: std::time::Duration,
    ) -> io::Result<std::os::unix::net::UnixStream> {
        use std::os::fd::AsRawFd;
        let mut pollfd = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the privileged helper never connected",
                ));
            }
            // Woken at least every 100 ms so a helper that has already exited
            // is noticed promptly rather than at the deadline.
            let ms = left.as_millis().min(100) as libc::c_int;
            // SAFETY: one initialised pollfd, a count matching it, and a
            // timeout in milliseconds — the whole contract of poll(2).
            let ready = unsafe { libc::poll(&mut pollfd, 1, ms) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready > 0 {
                return listener.accept().map(|(stream, _)| stream);
            }
            // Nothing connected, and nothing ever will if the helper has
            // gone. Its stderr is read back by the caller for the reason.
            if matches!(child.try_wait(), Ok(Some(_))) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the privileged helper exited before handing anything over",
                ));
            }
        }
    }

    /// Read one descriptor and its header length off a connected socket.
    ///
    /// The header length travels as the ordinary payload of the same message
    /// that carries the descriptor, because a descriptor with the wrong
    /// framing assumption produces garbled packets rather than an error.
    fn recv_descriptor(
        stream: &std::os::unix::net::UnixStream,
    ) -> io::Result<(std::os::fd::RawFd, usize, Option<String>)> {
        use std::os::fd::AsRawFd;

        let mut payload = [0u8; 32];
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        // One descriptor's worth of control buffer, sized by CMSG_SPACE so
        // the kernel's alignment requirements are met rather than guessed.
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
        let mut control = vec![0u8; space];

        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len() as _;

        // SAFETY: `message` points at live storage that outlives the call,
        // and the lengths describe exactly that storage.
        let read = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, 0) };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the helper closed the socket without sending a descriptor",
            ));
        }

        // SAFETY: `message` was just filled in by a successful recvmsg.
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if header.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the helper's message carried no descriptor",
            ));
        }
        // SAFETY: CMSG_FIRSTHDR returned a header inside `control`.
        let header = unsafe { &*header };
        if header.cmsg_level != libc::SOL_SOCKET || header.cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the helper sent something other than a descriptor",
            ));
        }
        // SAFETY: an SCM_RIGHTS payload is an array of ints; one was sent.
        let fd = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>()) };
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the helper sent an invalid descriptor",
            ));
        }
        let read = read as usize;
        let uplink = std::str::from_utf8(&payload[1..read.min(payload.len())])
            .ok()
            .filter(|name| !name.is_empty())
            .map(str::to_owned);
        Ok((fd, payload[0] as usize, uplink))
    }

    /// Create (or adopt) the directory the handover socket lives in, and
    /// make sure nobody else controls it.
    ///
    /// The descriptor that crosses this socket carries every packet the
    /// machine sends. In a shared temporary directory the name is guessable,
    /// so another local user could create it first; owning the directory
    /// would let them swap the socket for their own and be handed the
    /// tunnel by the root helper. An existing directory is therefore only
    /// used when it is a real directory (not a symlink) owned by this user,
    /// and it is locked down to owner-only access either way.
    pub(super) fn prepare_private_dir(dir: &std::path::Path) -> Result<(), ElevationError> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let refuse = |why: String| ElevationError::Failed(format!("{}: {why}", dir.display()));

        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(refuse(format!("could not create it: {e}"))),
        }
        let meta = std::fs::symlink_metadata(dir).map_err(|e| refuse(e.to_string()))?;
        // SAFETY: getuid has no failure mode and touches no memory.
        let uid = unsafe { libc::getuid() };
        if !meta.file_type().is_dir() || meta.uid() != uid {
            return Err(refuse(
                "it exists but is not a directory owned by this user; refusing to hand the TUN device over through it"
                    .into(),
            ));
        }
        restrict_to_owner(dir);
        Ok(())
    }

    /// Owner-only permissions, so nothing else on the machine can reach the
    /// socket the descriptor travels over.
    fn restrict_to_owner(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }

    // ---------------------------------------------------------- helper side

    /// Run as the privileged helper. Never returns to the caller's UI.
    ///
    /// Everything is reported on stderr, which the parent reads back when the
    /// handover fails, so a failure here surfaces in the client's own error
    /// message instead of vanishing.
    pub fn run_helper() -> i32 {
        use std::io::BufRead;

        // Teardown is driven by stdin reaching EOF, which happens however
        // the client goes away. A hang-up or interrupt aimed at the whole
        // terminal session (closing the window sends SIGHUP to everything
        // on it, and sudo relays it) would otherwise kill the helper before
        // it could remove what it installed — the bypass routes outlive the
        // interface. Ignoring them leaves EOF as the one way out.
        // SAFETY: installing SIG_IGN for these signals has no preconditions.
        unsafe {
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
            libc::signal(libc::SIGINT, libc::SIG_IGN);
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }

        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).is_err() || line.trim().is_empty() {
            eprintln!("tun-helper: no request on stdin");
            return 2;
        }
        let request: TunRequest = match serde_json::from_str(line.trim()) {
            Ok(request) => request,
            Err(error) => {
                eprintln!("tun-helper: malformed request: {error}");
                return 2;
            }
        };

        // SAFETY-adjacent sanity check, not a security boundary: the socket
        // was created by the unprivileged side, so refusing to run when we
        // are not actually root turns a confusing packet-level failure into a
        // clear message.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("tun-helper: not running as root");
            return 3;
        }

        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("tun-helper: {error}");
                return 4;
            }
        };

        // `open` registers the descriptor with a reactor, so it needs to run
        // inside the runtime even though nothing here is async.
        let guard = runtime.enter();
        let device = match zero_tun::TunDevice::open(zero_tun::TunConfig {
            name: request.name.clone(),
            no_packet_info: true,
            max_packet_size: 65_535,
            mtu: request.mtu,
        }) {
            Ok(device) => device,
            Err(error) => {
                eprintln!("tun-helper: opening {}: {error}", request.name);
                return 5;
            }
        };

        let addresses = match request
            .addresses
            .iter()
            .map(|value| zero_tun::TunAddress::parse(value))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(addresses) => addresses,
            Err(error) => {
                eprintln!("tun-helper: address rejected: {error}");
                return 6;
            }
        };
        let routes = match request
            .routes
            .iter()
            .map(|value| zero_tun::TunRoute::parse(value))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(routes) => routes,
            Err(error) => {
                eprintln!("tun-helper: route rejected: {error}");
                return 6;
            }
        };
        let bypass_ips = request
            .bypass_ips
            .iter()
            .filter_map(|ip| ip.parse::<std::net::IpAddr>().ok())
            .collect();

        // The guard is held for the helper's whole life: dropping it is what
        // removes the addresses and routes again.
        let network = match device.configure_network(zero_tun::TunNetworkConfig {
            addresses,
            routes,
            bypass_ips,
            auto_route: request.auto_route,
            strict_route: request.strict_route,
        }) {
            Ok(network) => network,
            Err(error) => {
                eprintln!("tun-helper: configuring {}: {error}", request.name);
                return 7;
            }
        };

        if let Err(error) = send_descriptor(
            &request.socket_path,
            &device,
            network.uplink_interface().as_deref(),
        ) {
            eprintln!("tun-helper: handing over the descriptor: {error}");
            return 8;
        }
        drop(guard);

        // Hold everything up until the client goes away. Reading stdin to EOF
        // is the signal, and it arrives whether the client disconnected
        // politely or was killed. Each line before that is a route update
        // for a server switch, answered on stdout.
        let mut line = String::new();
        let stdin = std::io::stdin();
        let mut locked = stdin.lock();
        let mut out = std::io::stdout();
        while matches!(locked.read_line(&mut line), Ok(n) if n > 0) {
            if !line.trim().is_empty() {
                let reply = match apply_route_update(&network, line.trim()) {
                    Ok(()) => "ok".to_string(),
                    Err(error) => format!("err {}", error.replace('\n', " ")),
                };
                let _ = writeln!(out, "{reply}");
                let _ = out.flush();
            }
            line.clear();
        }
        drop(network);
        0
    }

    /// One route update from the client: the servers to keep off the tunnel.
    fn apply_route_update(network: &zero_tun::TunNetworkGuard, line: &str) -> Result<(), String> {
        #[derive(serde::Deserialize)]
        struct Update {
            bypass_ips: Vec<String>,
        }
        let update: Update =
            serde_json::from_str(line).map_err(|e| format!("malformed update: {e}"))?;
        let ips = update
            .bypass_ips
            .iter()
            .map(|ip| {
                ip.parse::<std::net::IpAddr>()
                    .map_err(|e| format!("{ip}: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        network.set_bypass(&ips).map_err(|e| e.to_string())
    }

    /// Send the open device to whoever is listening on `path`.
    fn send_descriptor(
        path: &str,
        device: &zero_tun::TunDevice,
        uplink: Option<&str>,
    ) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let stream = UnixStream::connect(path)?;
        let fd = device.as_raw_fd();
        // The framing assumption travels with the descriptor: a reader that
        // guesses it wrong mangles every packet without ever erroring.
        // Then the uplink's name, which is at most IFNAMSIZ - 1 bytes.
        let mut payload = vec![device.header_len() as u8];
        if let Some(uplink) = uplink.filter(|name| name.len() < 16) {
            payload.extend_from_slice(uplink.as_bytes());
        }

        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
        let mut control = vec![0u8; space];

        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len() as _;

        // SAFETY: the control buffer was sized with CMSG_SPACE for exactly
        // one descriptor, and `message` describes live storage.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>(), fd);

            let sent = libc::sendmsg(stream.as_raw_fd(), &message, 0);
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
pub use unix_impl::{open_privileged_tun, run_helper, PrivilegedTun};

#[cfg(not(unix))]
mod stub {
    use super::*;

    /// Placeholder so the client compiles on platforms with no `sudo`.
    pub struct PrivilegedTun {
        pub device: String,
    }

    impl PrivilegedTun {
        pub fn is_running(&mut self) -> bool {
            false
        }

        pub fn serves(&self, _request: &TunRequest) -> bool {
            false
        }

        pub fn retarget(&mut self, _request: &TunRequest) -> Result<TunHandover, ElevationError> {
            Err(ElevationError::Unsupported)
        }
    }

    pub fn open_privileged_tun(
        _request: &TunRequest,
        _password: Option<&str>,
    ) -> Result<(PrivilegedTun, TunHandover), ElevationError> {
        Err(ElevationError::Unsupported)
    }

    pub fn run_helper() -> i32 {
        eprintln!("tun-helper: not supported on this platform");
        1
    }
}

#[cfg(not(unix))]
pub use stub::{open_privileged_tun, run_helper, PrivilegedTun};

/// A private path for the handover socket, unique per attempt.
///
/// Per-attempt because a stale socket from a helper that was killed would
/// otherwise be connected to instead of the new one. The per-user runtime
/// directory is preferred: it is already private to this user, where the
/// shared temporary directory is only made so after the fact.
pub fn handover_socket_path() -> String {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .filter(|dir| dir.is_absolute() && dir.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("zeronet-tun-{pid}"));
    dir.join(format!("{unique}.sock"))
        .to_string_lossy()
        .into_owned()
}

/// Locate an executable on `PATH`.
#[cfg(unix)]
fn which(program: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(candidate)
                .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@155.117.13.26:443?encryption=none&security=reality&sni=a.example&fp=chrome&type=tcp#Node";

    fn config_with_tun() -> String {
        serde_json::json!({
            "inbounds": [
                {"tag": "socks-in", "protocol": "socks", "port": 10808},
                {"tag": "tun-in", "protocol": "tun", "settings": {
                    "name": "zray7",
                    "mtu": 1360,
                    "autoRoute": true,
                    "strictRoute": true,
                    "addresses": ["10.254.0.1/30", "fdfe:dcba:9876::1/126"],
                    "routes": ["0.0.0.0/1", "128.0.0.0/1"]
                }}
            ],
            "outbounds": [
                {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [
                    {"address": "155.117.13.26", "port": 443, "users": [{"id": "x"}]}
                ]}},
                {"tag": "direct", "protocol": "freedom"}
            ]
        })
        .to_string()
    }

    #[test]
    fn a_request_mirrors_the_tun_inbound_the_engine_will_expect() {
        // Two sources of truth for addresses and routes would be a silent
        // misconfiguration: the helper would build one interface and the
        // engine would assume another.
        let request = request_from_config(&config_with_tun(), "/tmp/x.sock").expect("request");
        assert_eq!(request.name, "zray7");
        assert_eq!(request.mtu, 1360);
        assert!(request.auto_route);
        assert!(request.strict_route);
        assert_eq!(
            request.addresses,
            vec![
                "10.254.0.1/30".to_string(),
                "fdfe:dcba:9876::1/126".to_string()
            ]
        );
        assert_eq!(
            request.routes,
            vec!["0.0.0.0/1".to_string(), "128.0.0.0/1".to_string()]
        );
        assert_eq!(request.socket_path, "/tmp/x.sock");
    }

    #[test]
    fn the_proxy_server_is_given_a_bypass_route() {
        // Without this the tunnel routes its own transport into itself and
        // nothing moves at all.
        let request = request_from_config(&config_with_tun(), "/tmp/x.sock").unwrap();
        assert_eq!(request.bypass_ips, vec!["155.117.13.26".to_string()]);
    }

    #[test]
    fn a_config_with_no_tun_inbound_produces_no_request() {
        let proxy_only = serde_json::json!({
            "inbounds": [{"tag": "socks-in", "protocol": "socks", "port": 10808}],
            "outbounds": [{"tag": "proxy", "protocol": "freedom"}]
        })
        .to_string();
        assert!(request_from_config(&proxy_only, "/tmp/x.sock").is_none());
        assert!(request_from_config("not json", "/tmp/x.sock").is_none());
    }

    #[test]
    fn a_link_form_outbound_still_yields_its_bypass_address() {
        let config = serde_json::json!({
            "inbounds": [{"tag": "tun-in", "protocol": "tun", "settings": {"name": "z0"}}],
            "outbounds": [{"tag": "proxy", "link": LINK}]
        })
        .to_string();
        let request = request_from_config(&config, "/tmp/x.sock").unwrap();
        assert_eq!(request.bypass_ips, vec!["155.117.13.26".to_string()]);
    }

    #[test]
    fn a_hostname_is_not_mistaken_for_a_bypass_address() {
        // A name cannot be given a route without resolving it, and resolving
        // it here would go through the DNS the tunnel is about to take over.
        assert_eq!(host_from_link("vless://id@example.com:443?x=1#N"), None);
        assert_eq!(
            host_from_link("vless://id@1.2.3.4:443?x=1#N"),
            Some("1.2.3.4".to_string())
        );
        // An IPv6 literal is bracketed, so the port is not the last colon.
        assert_eq!(
            host_from_link("vless://id@[2606:4700::1111]:443?x=1#N"),
            Some("2606:4700::1111".to_string())
        );
        assert_eq!(host_from_link("nonsense"), None);
    }

    #[test]
    fn a_request_round_trips_through_the_pipe_encoding() {
        // The helper reads one JSON line; a field that does not survive the
        // encoding would produce a differently-configured interface.
        let request = request_from_config(&config_with_tun(), "/tmp/x.sock").unwrap();
        let line = serde_json::to_string(&request).unwrap();
        assert!(!line.contains('\n'), "the request must fit on one line");
        assert_eq!(serde_json::from_str::<TunRequest>(&line).unwrap(), request);
    }

    #[test]
    fn each_attempt_gets_its_own_socket_path() {
        // A stale socket from a killed helper must not be connected to
        // instead of the new one.
        let first = handover_socket_path();
        let second = handover_socket_path();
        assert_ne!(first, second);
        assert!(first.ends_with(".sock"), "{first}");
    }

    #[test]
    fn errors_say_what_the_user_can_do_about_them() {
        assert!(ElevationError::Rejected.to_string().contains("password"));
        assert_eq!(
            ElevationError::Failed("tun module missing".into()).to_string(),
            "tun module missing"
        );
        assert!(!ElevationError::Unsupported.to_string().is_empty());
    }

    #[test]
    fn only_a_real_backend_offers_to_prompt() {
        assert!(Elevator::Sudo.can_prompt());
        // doas has no way to take a password on stdin (no `-S`), so a
        // password dialog in front of it would collect a password that could
        // never be delivered.
        assert!(!Elevator::Doas.can_prompt());
        assert_eq!(Elevator::Doas.noninteractive_args(), &["-n"]);
        assert_eq!(Elevator::Sudo.noninteractive_args(), &["-S", "-p", ""]);
        // Already privileged: asking for a password would train people to
        // type it at anything that asks.
        assert!(!Elevator::NotNeeded.can_prompt());
        assert!(!Elevator::None.can_prompt());
    }

    #[cfg(unix)]
    #[test]
    fn a_handover_directory_owned_by_someone_else_is_refused() {
        // A symlink planted where the directory should be is the simplest
        // form of the attack; it must not be followed.
        let base = std::env::temp_dir().join(format!(
            "zeronet-dir-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let target = base.join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        let planted = base.join("planted");
        std::os::unix::fs::symlink(&target, &planted).unwrap();
        let outcome = unix_impl::prepare_private_dir(&planted);
        let Err(ElevationError::Failed(why)) = outcome else {
            panic!("a symlinked handover directory was accepted");
        };
        assert!(why.contains("not a directory owned by this user"), "{why}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn which_finds_a_program_that_is_certainly_there() {
        assert!(which("sh").is_some());
        assert!(which("definitely-not-a-real-program-zzz").is_none());
    }
}
