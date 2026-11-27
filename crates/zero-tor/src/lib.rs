//! An embedded Tor client, for use as a last-resort outbound.
//!
//! Tor is slow (three hops) and heavy for a phone, so this crate is built to
//! cost nothing until it is needed and little after:
//!
//! * **Lazy.** No client exists until the first connection asks for one, and
//!   the directory download starts then, not at startup.
//! * **Dormant when idle.** Two minutes with no open stream puts Arti's
//!   background work (directory refresh, preemptive circuits, padding timers)
//!   to sleep. The next connection wakes it.
//! * **Capped.** A memory ceiling replaces Arti's "a fraction of system RAM"
//!   default, padding is reduced, and only port 443 circuits are built ahead.
//!
//! One [`Instance`] is shared by every connection that uses the same
//! [`TorConfig`]: Arti locks its state directory, so two clients over one
//! directory cannot coexist, and one client multiplexes streams over a few
//! circuits far more cheaply than two would.
//!
//! Names are never resolved here. A domain goes to Tor as a name and the exit
//! resolves it, so a lookup never leaves the circuit.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{BootstrapBehavior, DataStream, DormantMode, TorClient, TorClientConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;
use tor_rtcompat::{CompoundRuntime, NetStreamProvider, PreferredRuntime, RuntimeSubstExt};
use zero_config::{TorConfig, TOR_MIN_MEMORY_MIB};
use zero_core::Address;

/// How long one connection waits for Tor to finish starting. Longer than the
/// other outbounds' setup deadline because a cold start downloads the network
/// directory first; the download continues after a caller gives up.
const START_WAIT: Duration = Duration::from_secs(150);
/// A start that Arti itself reports as blocked is given this long to recover
/// before a caller is told it is not going to work (a slow network gets
/// through the first resets; a filtered one never does).
const BLOCKED_GRACE: Duration = Duration::from_secs(45);
/// Bound on building one circuit and opening one stream.
const STREAM_WAIT: Duration = Duration::from_secs(75);
/// After a failed start, further connections fail at once for this long instead
/// of each restarting the download.
const RETRY_AFTER: Duration = Duration::from_secs(20);
/// No open stream for this long puts the client to sleep.
const IDLE_AFTER: Duration = Duration::from_secs(120);
const IDLE_CHECK: Duration = Duration::from_secs(30);
const DEFAULT_MEMORY_MIB: u32 = 64;

static DEFAULT_DIR: OnceLock<PathBuf> = OnceLock::new();
static INSTANCES: Mutex<Option<HashMap<TorConfig, Arc<Instance>>>> = Mutex::new(None);

/// Where Tor keeps its cache when a config names no directory. A host that has
/// an app-private folder (Android) calls this once at startup; the others fall
/// back to the per-user state folder.
pub fn set_default_data_dir(dir: impl Into<PathBuf>) {
    let _ = DEFAULT_DIR.set(dir.into());
}

fn default_data_dir() -> PathBuf {
    if let Some(dir) = DEFAULT_DIR.get() {
        return dir.clone();
    }
    let var = |name| std::env::var_os(name).map(PathBuf::from);
    if let Some(state) = var("XDG_STATE_HOME") {
        return state.join("zray").join("tor");
    }
    if let Some(home) = var("HOME") {
        return home.join(".local/state/zray/tor");
    }
    if let Some(local) = var("LOCALAPPDATA") {
        return local.join("zray").join("tor");
    }
    std::env::temp_dir().join("zray-tor")
}

/// Arti's own TCP provider, except that every outbound connection first gives
/// the host its chance to exempt the socket from the VPN (`zero_core::platform`).
///
/// Without this, Tor's connections to its guards would be routed into the very
/// tunnel Tor is serving, and nothing would ever be carried. Listening is not
/// used by a client and is passed through.
#[derive(Clone)]
struct ProtectedTcp(PreferredRuntime);

#[async_trait::async_trait]
impl NetStreamProvider for ProtectedTcp {
    type Stream = <PreferredRuntime as NetStreamProvider>::Stream;
    type Listener = <PreferredRuntime as NetStreamProvider>::Listener;
    type ConnectOptions = <PreferredRuntime as NetStreamProvider>::ConnectOptions;
    type ListenOptions = <PreferredRuntime as NetStreamProvider>::ListenOptions;

    async fn connect(
        &self,
        addr: &std::net::SocketAddr,
        _options: &Self::ConnectOptions,
    ) -> io::Result<Self::Stream> {
        Ok(zero_core::connect_protected(*addr).await?.into())
    }

    async fn listen(
        &self,
        addr: &std::net::SocketAddr,
        options: &Self::ListenOptions,
    ) -> io::Result<Self::Listener> {
        self.0.listen(addr, options).await
    }
}

/// The runtime Arti runs on: the ordinary tokio one with [`ProtectedTcp`].
type Runtime = CompoundRuntime<
    PreferredRuntime,
    PreferredRuntime,
    PreferredRuntime,
    ProtectedTcp,
    PreferredRuntime,
    PreferredRuntime,
    PreferredRuntime,
>;

/// Where a start attempt stands. `Failed` remembers when, for [`RETRY_AFTER`].
#[derive(Clone)]
enum Boot {
    Idle,
    Starting,
    Ready,
    Failed(String, Instant),
}

/// One running Tor client and the bookkeeping that lets it sleep.
struct Instance {
    client: Arc<TorClient<Runtime>>,
    boot: watch::Sender<Boot>,
    /// Streams currently open.
    open: AtomicUsize,
    /// When the last stream closed (or the client started).
    last_active: Mutex<Instant>,
    bridges: usize,
}

/// Held by a [`TorStream`]; counts it as open until dropped.
struct Lease(Arc<Instance>);

impl Lease {
    fn new(instance: &Arc<Instance>) -> Self {
        instance.open.fetch_add(1, Ordering::Relaxed);
        Lease(Arc::clone(instance))
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Stamp before decrementing so the idle check never sees "0 open" with
        // a stale time.
        *lock(&self.0.last_active) = Instant::now();
        self.0.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A stream through Tor. Reads and writes go straight to Arti's stream.
pub struct TorStream {
    inner: DataStream,
    _lease: Lease,
}

impl AsyncRead for TorStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TorStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Open a stream to `host:port` through Tor, starting Tor first if needed.
///
/// The error is one sentence a person can act on (rule: say what to do next),
/// not an Arti debug dump.
pub async fn connect(config: &TorConfig, host: &Address, port: u16) -> Result<TorStream, String> {
    let instance = instance_for(config)?;
    ensure_started(&instance).await?;
    let opened = match host {
        Address::Domain(name) => {
            tokio::time::timeout(STREAM_WAIT, instance.client.connect((name.as_ref(), port))).await
        }
        Address::Ip(ip) => {
            tokio::time::timeout(STREAM_WAIT, instance.client.connect((ip.to_string(), port))).await
        }
    };
    match opened {
        Ok(Ok(inner)) => Ok(TorStream {
            inner,
            _lease: Lease::new(&instance),
        }),
        Ok(Err(error)) => Err(stream_failure(&instance, &error)),
        Err(_) => Err(circuit_failure(&instance, "it took too long")),
    }
}

/// Pick `ring` as rustls's process-wide default, before any Arti runtime exists.
///
/// This workspace's rustls has both `ring` and `aws-lc-rs` compiled in, so
/// rustls cannot choose a default itself, and Arti, which does not name one,
/// panics when its runtime builds its first TLS config. Every other user here
/// passes a provider explicitly, so installing `ring` changes nothing for them.
/// An `Err` only means one is already installed.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// The shared instance for `config`, created on first use.
fn instance_for(config: &TorConfig) -> Result<Arc<Instance>, String> {
    let mut guard = lock(&INSTANCES);
    let map = guard.get_or_insert_with(HashMap::new);
    if let Some(existing) = map.get(config) {
        return Ok(Arc::clone(existing));
    }
    let built = build_config(config)?;
    install_crypto_provider();
    let base = PreferredRuntime::current()
        .map_err(|error| format!("Tor needs a tokio runtime: {error}"))?;
    let runtime = base.with_tcp_provider(ProtectedTcp(base.clone()));
    let client = TorClient::with_runtime(runtime)
        .config(built)
        // Bootstrap is started by `ensure_started`, so the wait and the retry
        // policy are ours rather than Arti's.
        .bootstrap_behavior(BootstrapBehavior::Manual)
        .create_unbootstrapped()
        .map_err(|error| describe(&error))?;
    let instance = Arc::new(Instance {
        client,
        boot: watch::channel(Boot::Idle).0,
        open: AtomicUsize::new(0),
        last_active: Mutex::new(Instant::now()),
        bridges: config.bridges.len(),
    });
    tokio::spawn(sleep_when_idle(Arc::downgrade(&instance)));
    map.insert(config.clone(), Arc::clone(&instance));
    Ok(instance)
}

/// Wait until Tor has enough directory to build circuits, starting the download
/// if nobody has. Only one start runs at a time; the rest wait on it.
async fn ensure_started(instance: &Arc<Instance>) -> Result<(), String> {
    // Claim the start under the channel's own lock so two callers cannot both
    // begin one.
    let mut claimed = false;
    let mut early = None;
    instance.boot.send_if_modified(|state| match state {
        Boot::Ready => false,
        Boot::Starting => false,
        Boot::Failed(message, at) if at.elapsed() < RETRY_AFTER => {
            early = Some(message.clone());
            false
        }
        _ => {
            *state = Boot::Starting;
            claimed = true;
            true
        }
    });
    if let Some(message) = early {
        return Err(message);
    }
    if claimed {
        let task = Arc::clone(instance);
        tokio::spawn(async move {
            let outcome = task.client.bootstrap().await;
            let next = match outcome {
                Ok(()) => Boot::Ready,
                Err(error) => Boot::Failed(start_failure(&task, &error), Instant::now()),
            };
            task.boot.send_replace(next);
        });
    }

    let mut watcher = instance.boot.subscribe();
    let began = Instant::now();
    let mut poll = tokio::time::interval(Duration::from_secs(5));
    let wait = async {
        loop {
            match &*watcher.borrow_and_update() {
                Boot::Ready => return Ok(()),
                Boot::Failed(message, _) => return Err(message.clone()),
                Boot::Idle | Boot::Starting => {}
            }
            tokio::select! {
                changed = watcher.changed() => {
                    if changed.is_err() {
                        return Err("Tor stopped while starting".to_string());
                    }
                }
                _ = poll.tick() => {
                    let status = instance.client.bootstrap_status();
                    if status.blocked().is_some() && began.elapsed() >= BLOCKED_GRACE {
                        tracing::warn!(%status, "tor start is blocked");
                        return Err(blocked_message(instance));
                    }
                }
            }
        }
    };
    match tokio::time::timeout(START_WAIT, wait).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "Tor is still starting ({}); it keeps going in the background, try again soon",
            instance.client.bootstrap_status()
        )),
    }
}

/// Said when Arti reports it cannot make progress. The download goes on in the
/// background, so a bridge added later or a network that recovers still works.
fn blocked_message(instance: &Instance) -> String {
    let remedy = if instance.bridges == 0 {
        "add a bridge in the Tor settings"
    } else {
        "check the Tor bridges or try different ones"
    };
    format!(
        "Tor cannot reach the Tor network from here ({}); {remedy}",
        instance.client.bootstrap_status()
    )
}

/// A failed start said in terms of what the user can change.
fn start_failure(instance: &Instance, error: &arti_client::Error) -> String {
    tracing::warn!(%error, "tor start failed");
    blocked_message(instance)
}

fn describe(error: &arti_client::Error) -> String {
    format!("Tor: {error}")
}

/// A stream that could not be opened. Arti's own wording is kept, but the
/// useful part is the next step: when circuits cannot be built the relays are
/// almost always being filtered, and a bridge is the remedy.
fn stream_failure(instance: &Instance, error: &arti_client::Error) -> String {
    tracing::debug!(%error, "tor stream failed");
    circuit_failure(instance, &error.to_string())
}

fn circuit_failure(instance: &Instance, why: &str) -> String {
    let remedy = if instance.bridges == 0 {
        "Tor is probably blocked on this network: add a bridge in the Tor settings"
    } else {
        "check the Tor bridges or try different ones"
    };
    format!(
        "Tor could not open a circuit ({}); {remedy}",
        why.trim_start_matches("tor: ")
    )
}

/// Background task: once nothing has been open for [`IDLE_AFTER`], tell Arti to
/// stop its periodic work. Holds only a weak reference, so it ends with the
/// instance.
async fn sleep_when_idle(instance: Weak<Instance>) {
    let mut ticker = tokio::time::interval(IDLE_CHECK);
    loop {
        ticker.tick().await;
        let Some(instance) = instance.upgrade() else {
            return;
        };
        let idle = instance.open.load(Ordering::Relaxed) == 0
            && lock(&instance.last_active).elapsed() >= IDLE_AFTER;
        if idle && matches!(*instance.boot.borrow(), Boot::Ready) {
            // Using the client again wakes it; no explicit wake is needed.
            instance.client.set_dormant(DormantMode::Soft);
        }
    }
}

/// The memory ceiling handed to Arti, in bytes: the configured value, never
/// below [`TOR_MIN_MEMORY_MIB`], or [`DEFAULT_MEMORY_MIB`] when unset. Arti's
/// own default scales with system RAM, which on a big machine is no cap at all.
fn memory_cap_bytes(config: &TorConfig) -> usize {
    let mib = match config.memory_mib {
        0 => DEFAULT_MEMORY_MIB,
        mib => mib.max(TOR_MIN_MEMORY_MIB),
    };
    mib as usize * 1024 * 1024
}

/// Translate our settings into Arti's configuration.
fn build_config(config: &TorConfig) -> Result<TorClientConfig, String> {
    let base = match &config.data_dir {
        Some(dir) => PathBuf::from(&**dir),
        None => default_data_dir(),
    };
    let bad = |what: &str, error: &dyn std::fmt::Display| format!("Tor {what}: {error}");
    let mut builder =
        TorClientConfigBuilder::from_directories(base.join("state"), base.join("cache"));

    builder.system().memory().max(memory_cap_bytes(config));
    // Padding exists to hide traffic shape from a network observer; the reduced
    // level keeps most of that and cuts the timers that wake a phone's radio.
    builder.channel().padding(tor_config::PaddingLevel::Reduced);
    // Build circuits ahead for HTTPS only, not the default 80 and 443.
    builder
        .preemptive_circuits()
        .initial_predicted_ports()
        .push(443);

    for line in &config.bridges {
        let line = line.trim();
        let line = line.strip_prefix("Bridge ").unwrap_or(line);
        let bridge: BridgeConfigBuilder = line.parse().map_err(|e| bad("bridge line", &e))?;
        builder.bridges().bridges().push(bridge);
    }
    for (name, program) in &config.transports {
        let mut transport = TransportConfigBuilder::default();
        transport
            .protocols(vec![name.parse().map_err(|e| bad("transport name", &e))?])
            .path(CfgPath::new(program.to_string()))
            // Started when a bridge needs it, not at boot.
            .run_on_startup(false);
        builder.bridges().transports().push(transport);
    }
    builder.build().map_err(|e| bad("settings", &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BRIDGE: &str = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0";

    fn with_dir(name: &str) -> TorConfig {
        TorConfig {
            data_dir: Some(std::env::temp_dir().join(name).to_string_lossy().into()),
            ..TorConfig::default()
        }
    }

    #[test]
    fn the_memory_cap_has_a_default_and_a_floor() {
        let mut config = with_dir("zero-tor-test-default");
        assert_eq!(memory_cap_bytes(&config), 64 << 20);
        config.memory_mib = 48;
        assert_eq!(memory_cap_bytes(&config), 48 << 20);
        config.memory_mib = 1;
        assert_eq!(
            memory_cap_bytes(&config),
            (TOR_MIN_MEMORY_MIB as usize) << 20
        );
        build_config(&config).unwrap();
    }

    #[test]
    fn bridges_and_a_transport_program_build() {
        let mut config = with_dir("zero-tor-test-bridge");
        config.bridges = vec![BRIDGE.into(), format!("Bridge {BRIDGE}").into()];
        config.transports = vec![("obfs4".into(), "/usr/bin/lyrebird".into())];
        build_config(&config).unwrap();
    }

    #[test]
    fn a_garbled_bridge_line_is_named_not_swallowed() {
        let mut config = with_dir("zero-tor-test-garbled");
        config.bridges = vec!["this is not a bridge".into()];
        let error = build_config(&config).err().unwrap();
        assert!(error.contains("bridge line"), "{error}");
    }

    /// The reason `ProtectedTcp` exists: Tor's sockets must reach the host's
    /// exemption hook before they connect, or on a VPN they loop.
    #[tokio::test]
    async fn tors_sockets_are_offered_to_the_vpn_exemption_hook() {
        struct Counting(AtomicUsize);
        impl zero_core::SocketProtector for Counting {
            fn protect(&self, _fd: i32) -> io::Result<()> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
        let counter = Arc::new(Counting(AtomicUsize::new(0)));
        zero_core::set_socket_protector(counter.clone()).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        install_crypto_provider();
        let provider = ProtectedTcp(PreferredRuntime::current().unwrap());
        let _stream = provider
            .connect(&target, &Default::default())
            .await
            .unwrap();
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn the_default_folder_is_per_user_and_overridable() {
        assert!(default_data_dir().to_string_lossy().contains("tor"));
        set_default_data_dir("/data/app/tor");
        assert_eq!(default_data_dir(), PathBuf::from("/data/app/tor"));
    }
}
