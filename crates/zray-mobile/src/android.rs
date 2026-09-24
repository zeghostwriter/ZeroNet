//! The JNI surface: `com.zeronet.mobile.core.ZrayNative`.
//!
//! This is the Rust half of `ZeroNet-Mobile/docs/native-contract.md`, and the
//! contract is the specification: function names, JSON shapes and event
//! shapes are defined there. The rules that shape this file:
//!
//! * **Strings in, strings out.** Every argument and result is a UTF-8 JSON
//!   string (or a plain int/long/boolean). No Java object graph is built or
//!   walked here, so the Kotlin side can evolve its models freely.
//! * **No unwinding into the JVM.** Every export runs inside
//!   [`std::panic::catch_unwind`] and turns a panic into the contract's error
//!   value. (This only works in a build with `panic = "unwind"`; the
//!   `release-mobile` profile used by `build-android.sh` is exactly that.)
//! * **Nothing slow on the caller's thread.** `start`, `reload` and `stop`
//!   block for as long as the runtime needs (the service calls them off the
//!   main thread); everything else returns within milliseconds. Discovery,
//!   delay tests and scans run on a dedicated two-thread job runtime,
//!   separate from the proxy's, and report through a listener.
//! * **Batched callbacks.** Job events reach Kotlin as newline-separated JSON
//!   batches, at most ten calls a second (`zero_discovery::events`), from Rust
//!   threads permanently attached to the VM as daemons.
//!
//! Socket protection is the one place Java is called *synchronously* from the
//! data path: every outbound socket the runtime opens goes through
//! `ZrayNative.protect(int)` before it connects. The class and method id are
//! resolved once, in `init`, on a thread whose class loader can see the app's
//! classes — a native thread's `FindClass` only sees the system loader.

use std::ffi::c_int;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use jni::objects::{GlobalRef, JClass, JMethodID, JObject, JStaticMethodID, JString};
use jni::signature::{Primitive, ReturnType};
use jni::sys::{jboolean, jint, jlong, jstring, jvalue, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use serde_json::json;
use zero_discovery::{CancellationToken, EndReason, EventCallback, EventSink};

use crate::ZRAY_OK;

/// The Kotlin class holding the natives and the static `protect` callback.
const NATIVE_CLASS: &str = "com/zeronet/mobile/core/ZrayNative";

/// The VM, cached by `init` so Rust threads can attach to it.
static VM: OnceLock<JavaVM> = OnceLock::new();
/// `filesDir`, as given to the first `init`.
static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

// ------------------------------------------------------------------ helpers

/// Run an export's body with panics contained. `fallback` produces the
/// contract's error value for the entry point.
fn contained<T>(name: &'static str, fallback: impl FnOnce() -> T, body: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) => {
            tracing::error!(
                entry = name,
                "a native call panicked; the app was not aborted"
            );
            fallback()
        }
    }
}

fn read_string(env: &mut JNIEnv, value: &JString) -> Result<String, String> {
    if value.is_null() {
        return Err("argument is null".into());
    }
    env.get_string(value)
        .map(String::from)
        .map_err(|error| format!("argument is not a readable string: {error}"))
}

/// A Java string, or null if even that cannot be made (out of memory, or a
/// pending exception).
fn java_string(env: &mut JNIEnv, text: &str) -> jstring {
    env.new_string(text)
        .map(JString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// The contract's `String?`: null for success, the message otherwise.
fn outcome(env: &mut JNIEnv, result: Result<(), String>) -> jstring {
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(message) => java_string(env, &message),
    }
}

/// Map a C-ABI status code to the contract's `String?`.
fn status(code: c_int) -> Result<(), String> {
    if code == ZRAY_OK {
        Ok(())
    } else {
        Err(crate::last_error_message().unwrap_or_else(|| format!("failed with status {code}")))
    }
}

/// Attach the current thread to the VM for good, as a daemon so it never
/// holds the VM open at exit. A thread that already is attached is left as
/// it is.
fn attached_env() -> Option<JNIEnv<'static>> {
    VM.get()?.attach_current_thread_as_daemon().ok()
}

// ------------------------------------------------------------------ logging

mod logging {
    //! `tracing` to a size-capped file in `dataDir` and, on Android, to
    //! logcat under the tag `zray`.

    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::{reload, Registry};

    /// Rotate `zray.log` to `zray.log.1` past this size, so the two never
    /// hold more than twice it.
    pub const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

    static LEVEL: OnceLock<reload::Handle<LevelFilter, Registry>> = OnceLock::new();

    pub fn parse_level(text: &str) -> Result<LevelFilter, String> {
        Ok(match text.trim().to_ascii_lowercase().as_str() {
            "off" | "none" => LevelFilter::OFF,
            "error" => LevelFilter::ERROR,
            "warn" | "warning" => LevelFilter::WARN,
            "info" => LevelFilter::INFO,
            "debug" => LevelFilter::DEBUG,
            "trace" => LevelFilter::TRACE,
            other => return Err(format!("unknown log level {other:?}")),
        })
    }

    /// A log file that rotates itself once it passes [`MAX_LOG_BYTES`].
    pub struct CappedFile {
        path: PathBuf,
        file: Option<File>,
        written: u64,
        cap: u64,
    }

    impl CappedFile {
        pub fn open(path: &Path, cap: u64) -> io::Result<Self> {
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);
            Ok(Self {
                path: path.to_path_buf(),
                file: Some(file),
                written,
                cap,
            })
        }

        fn rotate(&mut self) -> io::Result<()> {
            self.file = None;
            let mut rotated = self.path.clone().into_os_string();
            rotated.push(".1");
            let _ = std::fs::rename(&self.path, PathBuf::from(rotated));
            self.file = Some(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&self.path)?,
            );
            self.written = 0;
            Ok(())
        }
    }

    impl Write for CappedFile {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.written + buf.len() as u64 > self.cap {
                self.rotate()?;
            }
            let file = self
                .file
                .as_mut()
                .ok_or_else(|| io::Error::other("log file is closed"))?;
            file.write_all(buf)?;
            self.written += buf.len() as u64;
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            match self.file.as_mut() {
                Some(file) => file.flush(),
                None => Ok(()),
            }
        }
    }

    #[cfg(target_os = "android")]
    mod logcat {
        use std::ffi::{c_char, c_int, CString};
        use std::fmt::Write as _;

        use tracing::field::{Field, Visit};
        use tracing::{Event, Level, Subscriber};
        use tracing_subscriber::layer::{Context, Layer};

        #[link(name = "log")]
        extern "C" {
            fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
        }

        const TAG: &[u8] = b"zray\0";

        /// Forwards each event to `__android_log_write`.
        pub struct Logcat;

        struct Line(String);

        impl Visit for Line {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    let _ = write!(self.0, "{value:?}");
                } else {
                    let _ = write!(self.0, " {}={value:?}", field.name());
                }
            }

            fn record_str(&mut self, field: &Field, value: &str) {
                if field.name() == "message" {
                    self.0.push_str(value);
                } else {
                    let _ = write!(self.0, " {}={value}", field.name());
                }
            }
        }

        impl<S: Subscriber> Layer<S> for Logcat {
            fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
                let metadata = event.metadata();
                let priority = match *metadata.level() {
                    Level::ERROR => 6,
                    Level::WARN => 5,
                    Level::INFO => 4,
                    Level::DEBUG => 3,
                    Level::TRACE => 2,
                };
                let mut line = Line(format!("{}: ", metadata.target()));
                event.record(&mut line);
                let text = CString::new(line.0.replace('\0', "")).unwrap_or_default();
                // SAFETY: both strings are NUL-terminated and live across
                // the call; liblog copies them.
                unsafe {
                    __android_log_write(priority, TAG.as_ptr().cast(), text.as_ptr());
                }
            }
        }
    }

    /// Install the subscriber once per process; later calls only change the
    /// level.
    pub fn init(data_dir: &Path, level: LevelFilter) -> Result<(), String> {
        if let Some(handle) = LEVEL.get() {
            return handle
                .modify(|filter| *filter = level)
                .map_err(|error| format!("could not change the log level: {error}"));
        }
        let file = CappedFile::open(&data_dir.join("zray.log"), MAX_LOG_BYTES)
            .map_err(|error| format!("could not open the log file: {error}"))?;
        let (filter, handle) = reload::Layer::new(level);
        let file_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_thread_names(true)
            .with_writer(Mutex::new(file));
        let subscriber = Registry::default().with(filter).with(file_layer);
        #[cfg(target_os = "android")]
        let subscriber = subscriber.with(logcat::Logcat);
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|error| format!("a logger is already installed: {error}"))?;
        let _ = LEVEL.set(handle);
        Ok(())
    }
}

// --------------------------------------------------------------- protection

/// Calls `ZrayNative.protect(fd)` for every socket the runtime opens.
struct JavaProtector {
    class: GlobalRef,
    method: JStaticMethodID,
}

impl zero_core::SocketProtector for JavaProtector {
    fn protect(&self, fd: i32) -> std::io::Result<()> {
        let mut env = attached_env()
            .ok_or_else(|| std::io::Error::other("cannot attach this thread to the JVM"))?;
        let class: &JClass = self.class.as_obj().into();
        let result = env.with_local_frame(4, |env| -> jni::errors::Result<bool> {
            // SAFETY: the method id was resolved for this class with the
            // signature (I)Z, and the argument is an int.
            let value = unsafe {
                env.call_static_method_unchecked(
                    class,
                    self.method,
                    ReturnType::Primitive(Primitive::Boolean),
                    &[jvalue { i: fd as jint }],
                )
            }?;
            value.z()
        });
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
            return Err(std::io::Error::other(
                "ZrayNative.protect threw; the socket was not protected",
            ));
        }
        match result {
            Ok(true) => Ok(()),
            Ok(false) => Err(std::io::Error::other(
                "the VPN service refused to protect a socket; it would have looped \
                 back into the tunnel",
            )),
            Err(error) => Err(std::io::Error::other(format!(
                "calling ZrayNative.protect failed: {error}"
            ))),
        }
    }
}

fn install_protector(env: &mut JNIEnv) -> Result<(), String> {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    if INSTALLED.get().is_some() {
        return Ok(());
    }
    let class = env.find_class(NATIVE_CLASS).map_err(|error| {
        let _ = env.exception_clear();
        format!("cannot find {NATIVE_CLASS}: {error}")
    })?;
    let method = env
        .get_static_method_id(&class, "protect", "(I)Z")
        .map_err(|error| {
            let _ = env.exception_clear();
            format!("{NATIVE_CLASS} has no static protect(int): boolean: {error}")
        })?;
    let class = env
        .new_global_ref(&class)
        .map_err(|error| format!("cannot keep a reference to {NATIVE_CLASS}: {error}"))?;
    match zero_core::set_socket_protector(Arc::new(JavaProtector { class, method })) {
        Ok(()) => {}
        // Installed through the C ABI already; that one wins.
        Err(reason) => tracing::warn!(%reason, "socket protector not replaced"),
    }
    let _ = INSTALLED.set(());
    Ok(())
}

// --------------------------------------------------------------------- jobs

/// The runtime discovery, delay tests and scans run on. Separate from the
/// proxy's so a sweep of hundreds of sockets cannot starve the tunnel of
/// scheduler time, and small: the jobs are I/O bound.
fn job_runtime() -> Option<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                // Name lookups (`lookup_host`) and listener calls use the
                // blocking pool; a TCP sweep resolves many names at once.
                .max_blocking_threads(64)
                .thread_name("zray-jobs")
                // Attach up front, so neither listener calls nor dropping a
                // listener's global reference has to attach mid-flight.
                .on_thread_start(|| {
                    let _ = attached_env();
                })
                .enable_all()
                .build()
                .map_err(|error| tracing::error!(%error, "job runtime failed to start"))
                .ok()
        })
        .as_ref()
}

static JOBS: Mutex<Option<std::collections::HashMap<u64, CancellationToken>>> = Mutex::new(None);
static NEXT_JOB: AtomicU64 = AtomicU64::new(1);

fn jobs(
) -> std::sync::MutexGuard<'static, Option<std::collections::HashMap<u64, CancellationToken>>> {
    JOBS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A Kotlin `NativeListener`, callable from any Rust thread.
struct JavaListener {
    listener: GlobalRef,
    method: JMethodID,
}

impl JavaListener {
    fn new(env: &mut JNIEnv, listener: &JObject) -> Result<Self, String> {
        if listener.is_null() {
            return Err("listener is null".into());
        }
        let class = env
            .get_object_class(listener)
            .map_err(|error| format!("listener has no class: {error}"))?;
        let method = env
            .get_method_id(&class, "onEvents", "(Ljava/lang/String;)V")
            .map_err(|error| {
                let _ = env.exception_clear();
                format!("listener has no onEvents(String): {error}")
            })?;
        let listener = env
            .new_global_ref(listener)
            .map_err(|error| format!("cannot keep the listener: {error}"))?;
        Ok(Self { listener, method })
    }

    /// Hand one batch to Kotlin. Exceptions thrown by the listener are
    /// described and cleared: a buggy listener loses its own events, it does
    /// not poison the thread for the next call.
    fn deliver(&self, batch: &str) {
        let Some(mut env) = attached_env() else {
            return;
        };
        let _ = env.with_local_frame(4, |env| -> jni::errors::Result<()> {
            let text = env.new_string(batch)?;
            // SAFETY: the method id was resolved on the listener's class with
            // the signature (Ljava/lang/String;)V; the argument is a String.
            unsafe {
                env.call_method_unchecked(
                    self.listener.as_obj(),
                    self.method,
                    ReturnType::Primitive(Primitive::Void),
                    &[jvalue { l: text.as_raw() }],
                )
            }?;
            Ok(())
        });
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
        }
    }
}

/// Start one job: parse the request, register a cancellation handle and run
/// it on the job runtime. Returns the handle, or 0 after delivering a single
/// error event when the job could not start.
fn start_job<R, F, Fut>(
    env: &mut JNIEnv,
    request: &JString,
    listener: &JObject,
    name: &'static str,
    run: F,
) -> jlong
where
    R: serde::de::DeserializeOwned + Send + 'static,
    F: FnOnce(R, EventSink, CancellationToken) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = EndReason> + Send + 'static,
{
    let listener = match JavaListener::new(env, listener) {
        Ok(listener) => Arc::new(listener),
        Err(message) => {
            tracing::error!(job = name, %message, "job not started");
            return 0;
        }
    };
    let Some(runtime) = job_runtime() else {
        listener.deliver(
            &json!({"t": "error", "message": "the job runtime is unavailable"}).to_string(),
        );
        return 0;
    };
    let parsed = read_string(env, request).and_then(|text| {
        serde_json::from_str::<R>(&text).map_err(|error| format!("invalid {name} request: {error}"))
    });
    let request = match parsed {
        Ok(request) => request,
        Err(message) => {
            let event = json!({"t": "error", "message": message}).to_string();
            runtime.spawn_blocking(move || listener.deliver(&event));
            return 0;
        }
    };

    let id = NEXT_JOB.fetch_add(1, Ordering::Relaxed);
    let token = CancellationToken::new();
    jobs()
        .get_or_insert_with(Default::default)
        .insert(id, token.clone());

    runtime.spawn(async move {
        let callback: EventCallback = {
            let listener = Arc::clone(&listener);
            Arc::new(move |batch: String| listener.deliver(&batch))
        };
        let (sink, flusher) = zero_discovery::batching_sink(callback);
        let guard_sink = sink.clone();
        let outcome = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(run(
            request, sink, token,
        )))
        .await;
        match outcome {
            Ok(reason) => tracing::debug!(job = name, id, reason = reason.as_str(), "job ended"),
            Err(_) => {
                tracing::error!(job = name, id, "job panicked");
                guard_sink
                    .emit(json!({"t": "error", "message": format!("{name} failed internally")}));
                guard_sink.emit(json!({"t": "done", "reason": "cancelled", "error": true}));
            }
        }
        drop(guard_sink);
        let _ = flusher.await;
        if let Some(jobs) = jobs().as_mut() {
            jobs.remove(&id);
        }
    });
    id as jlong
}

// ------------------------------------------------------------------ exports

/// `init(dataDir, logLevel): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_init<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    data_dir: JString<'local>,
    log_level: JString<'local>,
) -> jstring {
    contained("init", std::ptr::null_mut, || {
        let result = (|| -> Result<(), String> {
            let data_dir = PathBuf::from(read_string(&mut env, &data_dir)?);
            let level = logging::parse_level(&read_string(&mut env, &log_level)?)?;
            std::fs::create_dir_all(&data_dir)
                .map_err(|error| format!("cannot create {}: {error}", data_dir.display()))?;
            let _ = DATA_DIR.set(data_dir.clone());
            let data_dir = DATA_DIR.get().cloned().unwrap_or(data_dir);
            // Logging is best effort: a failure is reported, but must not stop
            // the protector from being installed, without which no socket
            // would work once the tunnel is up.
            let logged = logging::init(&data_dir, level);
            if VM.get().is_none() {
                let vm = env
                    .get_java_vm()
                    .map_err(|error| format!("cannot reach the JVM: {error}"))?;
                let _ = VM.set(vm);
            }
            install_protector(&mut env)?;
            tracing::info!(data_dir = %data_dir.display(), "zray initialised");
            logged
        })();
        outcome(&mut env, result)
    })
}

/// `setTun(fd, mtu): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_setTun<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    fd: jint,
    mtu: jint,
) -> jstring {
    let result = contained(
        "setTun",
        || Err("setTun panicked".to_string()),
        || status(crate::zray_set_tun_descriptor(fd, 0, mtu)),
    );
    outcome(&mut env, result)
}

/// `start(configJson): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_start<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
) -> jstring {
    let result = contained(
        "start",
        || Err("start panicked".to_string()),
        || {
            let text = read_string(&mut env, &config_json)?;
            status(crate::start_text(&text))
        },
    );
    outcome(&mut env, result)
}

/// `reload(configJson): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_reload<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
) -> jstring {
    let result = contained(
        "reload",
        || Err("reload panicked".to_string()),
        || {
            let text = read_string(&mut env, &config_json)?;
            status(crate::reload_text(&text))
        },
    );
    outcome(&mut env, result)
}

/// `stop(): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_stop<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let result = contained(
        "stop",
        || Err("stop panicked".to_string()),
        || status(crate::stop_inner()),
    );
    outcome(&mut env, result)
}

/// `isRunning(): Boolean`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_isRunning<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jboolean {
    contained(
        "isRunning",
        || JNI_FALSE,
        || {
            if crate::zray_is_running() == 1 {
                JNI_TRUE
            } else {
                JNI_FALSE
            }
        },
    )
}

/// `stats(): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_stats<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let text = contained(
        "stats",
        || None,
        || crate::stats_value().map(|value| value.to_string()),
    );
    match text {
        Some(text) => java_string(&mut env, &text),
        None => std::ptr::null_mut(),
    }
}

/// `networkChanged(): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_networkChanged<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let result = contained(
        "networkChanged",
        || Err("networkChanged panicked".to_string()),
        || status(crate::network_changed_inner()),
    );
    outcome(&mut env, result)
}

/// `buildConfig(requestJson): String` — `{"config": …}` or `{"error": …}`.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_buildConfig<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
) -> jstring {
    let answer = contained(
        "buildConfig",
        || json!({"error": "buildConfig failed internally"}),
        || {
            let built = read_string(&mut env, &request_json)
                .and_then(|text| {
                    serde_json::from_str::<serde_json::Value>(&text)
                        .map_err(|error| format!("request is not valid JSON: {error}"))
                })
                .and_then(|request| {
                    let assets = DATA_DIR.get().map(|dir| dir.join("assets"));
                    zero_discovery::build_config_with_assets(&request, assets.as_deref())
                });
            match built {
                Ok(config) => json!({"config": config}),
                Err(error) => json!({"error": error}),
            }
        },
    );
    java_string(&mut env, &answer.to_string())
}

/// `parseLinks(text): String` — `{"items": […], "rejected": n, "reasons": {…}}`.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_parseLinks<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    text: JString<'local>,
) -> jstring {
    let answer = contained(
        "parseLinks",
        || json!({"items": [], "rejected": 0, "reasons": {}, "error": "parseLinks failed internally"}),
        || {
            match read_string(&mut env, &text) {
            Ok(text) => serde_json::to_value(zero_discovery::parse_links(&text))
                .unwrap_or_else(|error| json!({"items": [], "rejected": 0, "reasons": {}, "error": error.to_string()})),
            Err(error) => json!({"items": [], "rejected": 0, "reasons": {}, "error": error}),
        }
        },
    );
    java_string(&mut env, &answer.to_string())
}

/// `discover(requestJson, listener): Long`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_discover<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
    listener: JObject<'local>,
) -> jlong {
    contained(
        "discover",
        || 0,
        || {
            start_job(
                &mut env,
                &request_json,
                &listener,
                "discover",
                zero_discovery::discover,
            )
        },
    )
}

/// `testLinks(requestJson, listener): Long`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_testLinks<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
    listener: JObject<'local>,
) -> jlong {
    contained(
        "testLinks",
        || 0,
        || {
            start_job(
                &mut env,
                &request_json,
                &listener,
                "testLinks",
                zero_discovery::test_links,
            )
        },
    )
}

/// `scan(requestJson, listener): Long`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_scan<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
    listener: JObject<'local>,
) -> jlong {
    contained(
        "scan",
        || 0,
        || {
            start_job(
                &mut env,
                &request_json,
                &listener,
                "scan",
                zero_discovery::scan,
            )
        },
    )
}

/// `cancel(handle)`. Unknown or finished handles are ignored.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_cancel<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    contained(
        "cancel",
        || (),
        || {
            let Ok(id) = u64::try_from(handle) else {
                return;
            };
            if let Some(token) = jobs().as_ref().and_then(|jobs| jobs.get(&id)) {
                token.cancel();
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::logging::*;
    use std::io::Write;

    #[test]
    fn levels_parse_and_unknown_ones_are_rejected() {
        assert_eq!(
            parse_level("warn").unwrap(),
            tracing_subscriber::filter::LevelFilter::WARN
        );
        assert_eq!(
            parse_level("OFF").unwrap(),
            tracing_subscriber::filter::LevelFilter::OFF
        );
        assert!(parse_level("loud").is_err());
    }

    #[test]
    fn the_log_file_rotates_at_its_cap() {
        let dir = std::env::temp_dir().join(format!("zray-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("zray.log");
        let mut file = CappedFile::open(&path, 100).unwrap();
        for _ in 0..30 {
            file.write_all(b"0123456789\n").unwrap();
        }
        file.flush().unwrap();
        let current = std::fs::metadata(&path).unwrap().len();
        let rotated = std::fs::metadata(dir.join("zray.log.1")).unwrap().len();
        assert!(current <= 100, "{current}");
        assert!(rotated <= 100 && rotated > 0, "{rotated}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
