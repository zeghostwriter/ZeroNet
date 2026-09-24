//! The C ABI a mobile host application drives Zray through.
//!
//! Android and iOS do not run a proxy the way a desktop does. There is no
//! process to launch, no config file on a path the user can edit, and no TUN
//! device to open. Instead a `VpnService` (Kotlin/Java) or an
//! `NEPacketTunnelProvider` (Swift) owns the tunnel, and the proxy is a
//! library inside it. Three things have to cross that boundary, and all three
//! are awkward in a config file:
//!
//! 1. **The TUN descriptor**, created by the platform after the user approved
//!    a system dialog. It is an integer that means nothing outside this
//!    process.
//! 2. **Socket protection.** The host process sits behind its own VPN, so
//!    every outbound socket must be exempted through a platform call this
//!    library cannot make (`zero_core::platform`).
//! 3. **Start and stop**, driven by the platform's lifecycle rather than by a
//!    signal.
//!
//! So this crate is deliberately thin: it does no proxying, no configuration
//! and no policy. It converts C types to Rust ones, keeps the runtime alive
//! between calls, and turns every failure into a code plus a message the host
//! can log or show.
//!
//! ## Contract
//!
//! Every function is safe to call from any thread and none of them block for
//! longer than starting or stopping takes. Strings are NUL-terminated UTF-8,
//! borrowed for the duration of the call and never retained. A returned string
//! is owned by the caller and must be released with [`zray_string_free`].
//!
//! ```c
//! // Android, from VpnService.
//! zray_set_protect_callback(protect_via_vpnservice, NULL);
//! zray_set_tun_descriptor(tunFd, /* header_len */ 0, /* mtu */ 1500);
//! if (zray_start(config_json) != ZRAY_OK) {
//!     char *why = zray_last_error();
//!     ...
//!     zray_string_free(why);
//! }
//! ```
//!
//! On iOS the descriptor comes from the packet-tunnel provider and carries
//! four bytes of address-family framing, so `header_len` is 4 there.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use zero_core::SocketProtector;

/// The JNI surface for Android (`Java_com_zeronet_mobile_core_ZrayNative_*`),
/// built on the same entry points as the C ABI below.
#[cfg(feature = "jni")]
pub mod android;

// ------------------------------------------------------------------ status

/// Started, stopped, or configured successfully.
pub const ZRAY_OK: c_int = 0;
/// A pointer argument was null, or a string was not valid UTF-8.
pub const ZRAY_ERR_INVALID_ARGUMENT: c_int = 1;
/// The configuration was rejected. [`zray_last_error`] says why.
pub const ZRAY_ERR_CONFIG: c_int = 2;
/// The runtime is already running, or is not running and was asked to stop.
pub const ZRAY_ERR_STATE: c_int = 3;
/// Starting the runtime failed. [`zray_last_error`] says why.
pub const ZRAY_ERR_START: c_int = 4;
/// A hook could not be installed, because one already was.
pub const ZRAY_ERR_ALREADY_SET: c_int = 5;
/// A call panicked. The library caught it so the host process survives;
/// [`zray_last_error`] names the entry point.
pub const ZRAY_ERR_PANIC: c_int = 6;

/// Run an FFI entry point with panics contained.
///
/// A panic that crosses an `extern "C"` boundary aborts the process — and the
/// process here belongs to somebody's application, not to us. Whatever went
/// wrong inside this library, taking the host down with it is never the right
/// answer, so every entry point returns a code instead.
fn guard<F>(name: &'static str, body: F) -> c_int
where
    F: FnOnce() -> c_int,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(code) => code,
        Err(_) => {
            set_last_error(format!("{name} panicked; the host process was not aborted"));
            ZRAY_ERR_PANIC
        }
    }
}

/// The same, for entry points that return an owned string.
fn guard_string<F>(body: F) -> *mut c_char
where
    F: FnOnce() -> *mut c_char,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or(std::ptr::null_mut())
}

// ------------------------------------------------------------- last error

static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn set_last_error(message: impl Into<String>) {
    let message = message.into();
    tracing::error!(%message, "zray-mobile");
    *LAST_ERROR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(message);
}

fn clear_last_error() {
    *LAST_ERROR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

/// The recorded failure message, for callers inside this crate that return
/// it by value rather than through [`zray_last_error`].
#[cfg_attr(not(feature = "jni"), allow(dead_code))]
fn last_error_message() -> Option<String> {
    LAST_ERROR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// The most recent failure, or null if the last call succeeded.
///
/// The returned string is owned by the caller: release it with
/// [`zray_string_free`].
///
/// # Safety
///
/// The result must be freed exactly once and not used afterwards.
#[no_mangle]
pub extern "C" fn zray_last_error() -> *mut c_char {
    guard_string(|| {
        let message = LAST_ERROR
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        match message {
            Some(message) => CString::new(message)
                .map(CString::into_raw)
                .unwrap_or(std::ptr::null_mut()),
            None => std::ptr::null_mut(),
        }
    })
}

/// Release a string returned by this library.
///
/// # Safety
///
/// `value` must be a pointer this library returned and not yet freed, or null.
#[no_mangle]
pub unsafe extern "C" fn zray_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    // SAFETY: the caller guarantees this came from `CString::into_raw` here.
    drop(unsafe { CString::from_raw(value) });
}

// -------------------------------------------------------- socket protection

/// The host's socket-protection callback.
///
/// Called with the descriptor and the context pointer supplied alongside it.
/// Must return non-zero on success — the C convention of "zero is failure" is
/// used here because it matches Android's `VpnService.protect`, which returns
/// a boolean.
pub type ProtectCallback = extern "C" fn(fd: c_int, context: *mut c_void) -> c_int;

struct HostProtector {
    callback: ProtectCallback,
    context: usize,
}

// SAFETY: the host promises the callback is safe to call from any thread, and
// the context is an opaque value passed straight back to it. It is stored as a
// `usize` rather than a pointer so this type is `Send`/`Sync` without a raw
// pointer field that would need a manual unsafe impl for the wrong reason.
unsafe impl Send for HostProtector {}
unsafe impl Sync for HostProtector {}

impl SocketProtector for HostProtector {
    fn protect(&self, fd: i32) -> io::Result<()> {
        let accepted = (self.callback)(fd as c_int, self.context as *mut c_void);
        if accepted == 0 {
            return Err(io::Error::other(
                "the host refused to protect a socket; it would have been \
                 routed back into the tunnel",
            ));
        }
        Ok(())
    }
}

/// Install the host's socket-protection callback.
///
/// Must be called before [`zray_start`], and can be called only once per
/// process — a second host handle taking over the first's sockets is not
/// something to allow quietly.
///
/// On iOS this is usually unnecessary: a packet-tunnel provider's own sockets
/// are already exempt. Pass null to leave sockets alone.
///
/// # Safety
///
/// `callback` must remain valid for the lifetime of the process, and
/// `context` must be valid whenever it is called.
#[no_mangle]
pub unsafe extern "C" fn zray_set_protect_callback(
    callback: Option<ProtectCallback>,
    context: *mut c_void,
) -> c_int {
    guard("zray_set_protect_callback", || {
        clear_last_error();
        let Some(callback) = callback else {
            // Explicitly no protection. Legitimate on iOS and on a simulator.
            return ZRAY_OK;
        };
        let protector = Arc::new(HostProtector {
            callback,
            context: context as usize,
        });
        match zero_core::set_socket_protector(protector) {
            Ok(()) => ZRAY_OK,
            Err(reason) => {
                set_last_error(reason);
                ZRAY_ERR_ALREADY_SET
            }
        }
    })
}

// ------------------------------------------------------------ TUN handover

/// Hand the platform's TUN descriptor to the runtime.
///
/// Ownership moves: after [`zray_start`] succeeds the host must not read,
/// write or close the descriptor. If `zray_start` fails, the descriptor is
/// still the host's and should be closed by it.
///
/// `header_len` is the platform's framing in front of each packet — `0` for
/// Android's `VpnService`, `4` for iOS's `NEPacketTunnelProvider`. `mtu` is
/// the MTU the host configured on the interface; the proxy cannot query it,
/// and guessing wrong either wastes payload or produces packets the host
/// silently drops.
#[no_mangle]
pub extern "C" fn zray_set_tun_descriptor(fd: c_int, header_len: c_int, mtu: c_int) -> c_int {
    guard("zray_set_tun_descriptor", || {
        clear_last_error();
        if fd < 0 || header_len < 0 || mtu <= 0 {
            set_last_error("fd and mtu must be positive and header_len non-negative");
            return ZRAY_ERR_INVALID_ARGUMENT;
        }
        let descriptor = zero_tun::inherited::InheritedTun {
            fd,
            header_len: header_len as usize,
            mtu: mtu as usize,
        };
        match zero_tun::inherited::set(descriptor) {
            Ok(()) => ZRAY_OK,
            Err(reason) => {
                set_last_error(reason);
                ZRAY_ERR_ALREADY_SET
            }
        }
    })
}

// --------------------------------------------------------------- lifecycle

/// A running instance: the tokio runtime plus the server driving it.
struct Running {
    runtime: tokio::runtime::Runtime,
    server: Arc<zero_runtime::Server>,
    /// The configuration currently installed, kept so a network change can
    /// re-install it (see [`zray_network_changed`]).
    config: Arc<zero_config::RuntimeConfig>,
}

static INSTANCE: Mutex<Option<Running>> = Mutex::new(None);

/// The instance slot for a *query*: `None` while another call holds it.
///
/// `start` keeps the slot locked while it waits (up to
/// [`START_TIMEOUT_SECONDS`]) for the listeners, so that two starts cannot
/// race. A status poll arriving meanwhile must not wait that long — the
/// mobile contract promises it returns at once — and "not running yet" is the
/// truthful answer to it.
fn try_instance() -> Option<std::sync::MutexGuard<'static, Option<Running>>> {
    match INSTANCE.try_lock() {
        Ok(guard) => Some(guard),
        Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

/// Configuration generations handed to the runtime. Every start, reload and
/// network change installs a new one, so sessions can tell them apart.
static GENERATION: AtomicU64 = AtomicU64::new(1);

fn next_generation() -> zero_core::GenerationId {
    zero_core::GenerationId(GENERATION.fetch_add(1, Ordering::Relaxed))
}

/// Worker threads for the proxy runtime.
///
/// Tokio's default is one per core — eight on most phones — and every idle
/// worker is a thread the scheduler wakes. A mobile proxy is I/O bound and
/// saturates a cellular link long before three cores, so more workers only
/// cost battery.
fn proxy_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(2)
        .clamp(1, 3)
}

/// Parse and compile one configuration document, logging its diagnostics.
fn compile_document(
    text: &str,
    generation: zero_core::GenerationId,
) -> Result<zero_config::RuntimeGeneration, (c_int, String)> {
    let document: serde_json::Value = serde_json::from_str(text).map_err(|error| {
        (
            ZRAY_ERR_CONFIG,
            format!("configuration is not valid JSON: {error}"),
        )
    })?;
    let (generation, diagnostics) = zero_config::compile_config(&document, generation)
        .map_err(|error| (ZRAY_ERR_CONFIG, format!("configuration rejected: {error}")))?;
    for note in &diagnostics.diagnostics {
        tracing::warn!(path = %note.path, message = %note.message, "configuration note");
    }
    Ok(generation)
}

fn logging() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        // The host owns the log destination; on Android `tracing` output is
        // picked up by whatever subscriber the application installed, and
        // installing one here would fight it. Only set one up if nothing has.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_env("ZRAY_LOG")
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .try_init();
    });
}

/// Start the proxy with a configuration document.
///
/// `config_json` is Xray-shaped JSON, the same document the desktop build
/// reads from a file. Returns [`ZRAY_OK`], or a code with the reason available
/// from [`zray_last_error`].
///
/// # Safety
///
/// `config_json` must be a NUL-terminated UTF-8 string valid for the duration
/// of the call.
#[no_mangle]
pub unsafe extern "C" fn zray_start(config_json: *const c_char) -> c_int {
    // SAFETY: the caller guarantees a NUL-terminated string valid for the call;
    // it is read inside the guard and never retained.
    guard("zray_start", || unsafe { start_inner(config_json) })
}

/// SAFETY: `config_json` must be a NUL-terminated UTF-8 string valid for the
/// duration of the call.
unsafe fn start_inner(config_json: *const c_char) -> c_int {
    clear_last_error();

    if config_json.is_null() {
        set_last_error("config_json is null");
        return ZRAY_ERR_INVALID_ARGUMENT;
    }
    // SAFETY: guaranteed by this function's contract.
    let text = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(text) => text,
        Err(error) => {
            set_last_error(format!("config_json is not valid UTF-8: {error}"));
            return ZRAY_ERR_INVALID_ARGUMENT;
        }
    };
    start_text(text)
}

/// Start from a configuration already known to be UTF-8. Shared by the C and
/// JNI entry points.
fn start_text(text: &str) -> c_int {
    clear_last_error();
    logging();

    let mut slot = INSTANCE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_some() {
        set_last_error("the runtime is already started");
        return ZRAY_ERR_STATE;
    }

    let generation = match compile_document(text, next_generation()) {
        Ok(generation) => generation,
        Err((code, message)) => {
            set_last_error(message);
            return code;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(proxy_worker_threads())
        .thread_name("zray-rt")
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            set_last_error(format!("could not start a runtime: {error}"));
            return ZRAY_ERR_START;
        }
    };
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));

    let running = Arc::clone(&server);
    runtime.spawn(async move {
        if let Err(error) = running.run().await {
            set_last_error(format!("the runtime stopped: {error}"));
        }
    });

    // Wait for the listeners through a plain channel rather than `block_on`.
    //
    // `block_on` panics when the calling thread is already driving a tokio
    // runtime, and across an `extern "C"` boundary that panic aborts the host
    // application. A host is free to call this from wherever its lifecycle
    // callback runs, and "do not call us from an async context" is not a
    // contract a C API can enforce or a caller can reasonably discover.
    let (ready, is_ready) = std::sync::mpsc::sync_channel::<()>(1);
    let waiting = Arc::clone(&server);
    runtime.spawn(async move {
        waiting.wait_until_listening().await;
        let _ = ready.send(());
    });
    let listening = is_ready
        .recv_timeout(std::time::Duration::from_secs(START_TIMEOUT_SECONDS))
        .is_ok();

    if !listening {
        // The descriptor was offered but never adopted, so it goes back to the
        // host to close; the alternative is leaking the user's tunnel.
        let _ = zero_tun::inherited::clear();
        set_last_error(format!(
            "no inbound started listening within {START_TIMEOUT_SECONDS} seconds"
        ));
        return ZRAY_ERR_START;
    }

    *slot = Some(Running {
        runtime,
        config: Arc::clone(&generation.config),
        server,
    });
    ZRAY_OK
}

/// How long `zray_start` waits for the listeners before giving up. Long enough
/// for a cold start on a slow device, short enough that a platform lifecycle
/// callback is not held past its own deadline.
const START_TIMEOUT_SECONDS: u64 = 10;

/// Whether the proxy is running.
#[no_mangle]
pub extern "C" fn zray_is_running() -> c_int {
    guard("zray_is_running", || {
        let running = try_instance().is_some_and(|slot| slot.is_some());
        c_int::from(running)
    })
}

/// Replace the running configuration without dropping the tunnel.
///
/// Routing, DNS, outbounds and authentication switch atomically; sessions
/// already open finish on the configuration they started with. The listener
/// topology — which inbounds exist, their addresses, ports and protocols —
/// cannot change this way: that returns [`ZRAY_ERR_CONFIG`] and needs a
/// stop and start.
///
/// # Safety
///
/// `config_json` must be a NUL-terminated UTF-8 string valid for the duration
/// of the call.
#[no_mangle]
pub unsafe extern "C" fn zray_reload(config_json: *const c_char) -> c_int {
    guard("zray_reload", || {
        clear_last_error();
        if config_json.is_null() {
            set_last_error("config_json is null");
            return ZRAY_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: guaranteed by this function's contract; read, not retained.
        match unsafe { CStr::from_ptr(config_json) }.to_str() {
            Ok(text) => reload_text(text),
            Err(error) => {
                set_last_error(format!("config_json is not valid UTF-8: {error}"));
                ZRAY_ERR_INVALID_ARGUMENT
            }
        }
    })
}

/// Reload from a configuration already known to be UTF-8.
fn reload_text(text: &str) -> c_int {
    clear_last_error();
    let mut slot = INSTANCE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(running) = slot.as_mut() else {
        set_last_error("the runtime is not started");
        return ZRAY_ERR_STATE;
    };
    let generation = match compile_document(text, next_generation()) {
        Ok(generation) => generation,
        Err((code, message)) => {
            set_last_error(message);
            return code;
        }
    };
    match running
        .server
        .reload(Arc::clone(&generation.config), generation.id)
    {
        Ok(()) => {
            running.config = Arc::clone(&generation.config);
            ZRAY_OK
        }
        Err(reason) => {
            set_last_error(format!("reload rejected: {reason}"));
            ZRAY_ERR_CONFIG
        }
    }
}

/// Tell the runtime the underlying network changed (Wi-Fi to cellular, a new
/// cell, a captive portal cleared).
///
/// Re-installs the current configuration as a new generation. That replaces
/// the resolver, which drops the DNS cache — answers learned on the old
/// network, often from its own resolver — and the resolver's pooled DoH/DoT
/// connections, which are bound to an interface that no longer exists.
/// Sessions in flight are left alone: the ones that still work keep working,
/// and the dead ones fail on their own and are re-dialled by the application.
///
/// A no-op returning [`ZRAY_OK`] when nothing is running.
#[no_mangle]
pub extern "C" fn zray_network_changed() -> c_int {
    guard("zray_network_changed", network_changed_inner)
}

fn network_changed_inner() -> c_int {
    clear_last_error();
    // A start in progress is building a fresh resolver anyway.
    let Some(mut slot) = try_instance() else {
        return ZRAY_OK;
    };
    let Some(running) = slot.as_mut() else {
        return ZRAY_OK;
    };
    match running
        .server
        .reload(Arc::clone(&running.config), next_generation())
    {
        Ok(()) => {
            tracing::info!("network changed: resolver state reset");
            ZRAY_OK
        }
        Err(reason) => {
            set_last_error(format!("could not reset for the new network: {reason}"));
            ZRAY_ERR_CONFIG
        }
    }
}

/// Stop the proxy and release its runtime.
///
/// Returns [`ZRAY_ERR_STATE`] if nothing was running. Safe to call from the
/// platform's teardown callback; it blocks only as long as shutting the
/// runtime down takes.
#[no_mangle]
pub extern "C" fn zray_stop() -> c_int {
    guard("zray_stop", stop_inner)
}

fn stop_inner() -> c_int {
    clear_last_error();
    let taken = INSTANCE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    let Some(running) = taken else {
        set_last_error("the runtime is not started");
        return ZRAY_ERR_STATE;
    };
    drop(running.server);
    // Dropping the runtime from inside one of its own threads would deadlock,
    // and the host may well be calling from a callback we do not control the
    // provenance of. Shutting down in the background is both safe and what the
    // platform wants: teardown callbacks are time-limited.
    running.runtime.shutdown_background();
    ZRAY_OK
}

/// A snapshot of traffic counters, as JSON. Null if nothing is running.
///
/// # Safety
///
/// The result must be released with [`zray_string_free`].
#[no_mangle]
pub extern "C" fn zray_stats_json() -> *mut c_char {
    guard_string(|| {
        let slot = INSTANCE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(running) = slot.as_ref() else {
            return std::ptr::null_mut();
        };
        let snapshot = running.server.stats.snapshot();
        match serde_json::to_string(&snapshot)
            .ok()
            .and_then(|text| CString::new(text).ok())
        {
            Some(text) => text.into_raw(),
            None => std::ptr::null_mut(),
        }
    })
}

/// The mobile host's view of the counters: totals across every session the
/// runtime carried (proxied and direct alike), live sessions, and per-tag
/// byte counts keyed by inbound or outbound tag. `None` if nothing is running.
#[cfg_attr(not(feature = "jni"), allow(dead_code))]
fn stats_value() -> Option<serde_json::Value> {
    let slot = try_instance()?;
    let running = slot.as_ref()?;
    let stats = &running.server.stats;
    let mut tags = serde_json::Map::new();
    for (name, value) in stats.traffic_counters(false) {
        // `inbound>>>{tag}>>>traffic>>>uplink` and the outbound equivalent.
        let mut parts = name.split(">>>");
        let (Some(_kind), Some(tag), Some(_), Some(direction)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let key = match direction {
            "uplink" => "up",
            "downlink" => "down",
            _ => continue,
        };
        let entry = tags
            .entry(tag.to_string())
            .or_insert_with(|| serde_json::json!({"up": 0u64, "down": 0u64}));
        let current = entry[key].as_u64().unwrap_or(0);
        entry[key] = serde_json::json!(current.saturating_add(value));
    }
    Some(serde_json::json!({
        "up": stats.uploaded.load(Ordering::Relaxed),
        "down": stats.downloaded.load(Ordering::Relaxed),
        "sessions": running.server.active_sessions(),
        "tags": tags,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Serialises the tests that touch process-wide state.
    ///
    /// `LAST_ERROR` and `INSTANCE` are one slot each for the whole process —
    /// they have to be, because a C caller has no handle to scope them to —
    /// so tests that write or read them cannot run concurrently. Without this
    /// they pass alone and fail together, which is the worst way to find out.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn c(text: &str) -> CString {
        CString::new(text).unwrap()
    }

    fn take_last_error() -> Option<String> {
        let pointer = zray_last_error();
        if pointer.is_null() {
            return None;
        }
        // SAFETY: the pointer came from `zray_last_error` and is freed here.
        let message = unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned();
        unsafe { zray_string_free(pointer) };
        Some(message)
    }

    #[test]
    fn a_null_configuration_is_rejected_rather_than_dereferenced() {
        let _serial = serial();
        // SAFETY: passing null is exactly what this checks.
        let code = unsafe { zray_start(std::ptr::null()) };
        assert_eq!(code, ZRAY_ERR_INVALID_ARGUMENT);
        assert!(take_last_error().is_some_and(|text| text.contains("null")));
    }

    #[test]
    fn invalid_json_is_a_configuration_error_with_a_reason() {
        let _serial = serial();
        let text = c("{not json");
        // SAFETY: a valid NUL-terminated string for the duration of the call.
        let code = unsafe { zray_start(text.as_ptr()) };
        assert_eq!(code, ZRAY_ERR_CONFIG);
        let message = take_last_error().expect("a reason is recorded");
        assert!(
            message.contains("JSON"),
            "the host should learn what was wrong, got: {message}"
        );
    }

    #[test]
    fn a_rejected_configuration_reports_the_compilers_own_message() {
        let _serial = serial();
        // REALITY over WebSocket is impossible, and the compiler says so. The
        // point is that the host sees that sentence rather than a code.
        let text = c(r#"{
            "inbounds": [{"tag":"s","listen":"127.0.0.1","port":1080,"protocol":"socks"}],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{"address":"198.51.100.4","port":443,
                    "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
                "streamSettings": {"network":"ws","security":"reality",
                    "realitySettings":{"serverName":"a.example",
                        "publicKey":"hK8vN2pQ4rS6tU8wY0aB2cD4eF6gH8iJ0kL2mN4oP6Q",
                        "shortId":"0123456789abcdef"}}
            }]
        }"#);
        // SAFETY: a valid NUL-terminated string for the duration of the call.
        let code = unsafe { zray_start(text.as_ptr()) };
        assert_eq!(code, ZRAY_ERR_CONFIG);
        let message = take_last_error().expect("a reason is recorded");
        assert!(
            message.contains("REALITY"),
            "the host should see the compiler's own explanation, got: {message}"
        );
    }

    #[test]
    fn reloading_or_resetting_when_nothing_runs_is_handled() {
        let _serial = serial();
        let text = c(r#"{"outbounds":[{"protocol":"freedom"}]}"#);
        // SAFETY: a valid NUL-terminated string for the duration of the call.
        assert_eq!(unsafe { zray_reload(text.as_ptr()) }, ZRAY_ERR_STATE);
        // SAFETY: passing null is exactly what this checks.
        assert_eq!(
            unsafe { zray_reload(std::ptr::null()) },
            ZRAY_ERR_INVALID_ARGUMENT
        );
        // A network change with nothing running has nothing to reset.
        assert_eq!(zray_network_changed(), ZRAY_OK);
        assert!(stats_value().is_none());
    }

    #[test]
    fn stopping_when_nothing_runs_is_an_error_not_a_crash() {
        let _serial = serial();
        assert_eq!(zray_is_running(), 0);
        assert_eq!(zray_stop(), ZRAY_ERR_STATE);
    }

    #[test]
    fn a_tun_descriptor_must_be_plausible() {
        let _serial = serial();
        assert_eq!(
            zray_set_tun_descriptor(-1, 0, 1500),
            ZRAY_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            zray_set_tun_descriptor(9, 0, 0),
            ZRAY_ERR_INVALID_ARGUMENT,
            "an MTU of zero would make every packet invalid"
        );
        assert_eq!(
            zray_set_tun_descriptor(9, -1, 1500),
            ZRAY_ERR_INVALID_ARGUMENT
        );
    }

    #[test]
    fn freeing_a_null_string_is_harmless() {
        // Hosts written against a C header will do this; the alternative is a
        // crash in someone else's process.
        // SAFETY: null is explicitly allowed.
        unsafe { zray_string_free(std::ptr::null_mut()) };
    }

    #[test]
    fn declining_protection_is_allowed_and_is_not_an_error() {
        // iOS packet-tunnel providers need no protection, and a simulator has
        // nothing to protect against.
        // SAFETY: passing no callback is explicitly supported.
        let code = unsafe { zray_set_protect_callback(None, std::ptr::null_mut()) };
        assert_eq!(code, ZRAY_OK);
    }
}
