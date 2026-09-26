//! One authenticated QUIC connection per server, shared by every proxied
//! stream and datagram — the way the Hysteria2 and TUIC reference clients
//! work.
//!
//! Before this, each proxied TCP connection and each UDP datagram opened a
//! QUIC connection of its own: a full handshake plus authentication (two to
//! three round trips on the long, lossy paths these carriers exist for)
//! before the first byte of every web request, a new UDP port per request
//! for a DPI box to count, and no way for a connection to outlive a network
//! change. Now:
//!
//! * [`get`] returns the live connection for a server, dialling (and
//!   authenticating) one only when there is none. Concurrent callers wait
//!   for the one dial instead of racing their own.
//! * Datagrams are shared too: one reader task per connection hands each
//!   response to the exchange waiting for its session ([`Pooled::register`]).
//! * [`rebind_all`] moves every pooled connection onto a fresh socket after
//!   the network changed (Wi-Fi ↔ mobile). QUIC connection migration keeps
//!   the connection — and the streams on it — alive where a TCP-based
//!   carrier would have to start over.
//! * A connection nobody has used for [`IDLE_CLOSE`] and that carries no
//!   stream is closed, so an idle client does not keep NAT state and a
//!   keep-alive going forever.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h3_quinn::quinn::{Connection, Endpoint};
use tokio::sync::mpsc;

/// A pooled connection unused this long, with no stream open, is closed.
pub const IDLE_CLOSE: Duration = Duration::from_secs(5 * 60);
/// How often the reaper looks at a connection.
const REAP_INTERVAL: Duration = Duration::from_secs(30);

type Slot = Arc<tokio::sync::Mutex<Option<Arc<Pooled>>>>;

static POOL: LazyLock<StdMutex<HashMap<String, Slot>>> = LazyLock::new(Default::default);
/// Time base for `last_used`.
static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

fn now_ms() -> u64 {
    EPOCH.elapsed().as_millis() as u64
}

fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Extracts the session a response datagram belongs to (`None`: not a
/// response, dropped).
pub type SessionOf = fn(&[u8]) -> Option<u32>;

/// A live, authenticated connection and the endpoint that owns its socket.
pub struct Pooled {
    pub endpoint: Endpoint,
    pub connection: Connection,
    /// The runtime the endpoint's socket lives in. A rebind must register
    /// the new socket there: done from another runtime (or from a thread
    /// with none, like the platform's network callback) the socket would
    /// belong to that one and die with it.
    runtime: tokio::runtime::Handle,
    v6: bool,
    last_used: AtomicU64,
    /// Streams currently open on the connection.
    active: AtomicUsize,
    waiters: StdMutex<HashMap<u32, mpsc::UnboundedSender<Bytes>>>,
    reader: std::sync::Once,
}

impl Pooled {
    fn new(endpoint: Endpoint, connection: Connection) -> Self {
        let v6 = connection.remote_address().is_ipv6();
        Self {
            endpoint,
            connection,
            runtime: tokio::runtime::Handle::current(),
            v6,
            last_used: AtomicU64::new(now_ms()),
            active: AtomicUsize::new(0),
            waiters: StdMutex::new(HashMap::new()),
            reader: std::sync::Once::new(),
        }
    }

    fn alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    fn touch(&self) {
        self.last_used.store(now_ms(), Ordering::Relaxed);
    }

    /// Count a stream as open until the returned guard is dropped, so the
    /// reaper never closes a connection under a long download.
    pub fn stream_guard(self: &Arc<Self>) -> StreamGuard {
        self.active.fetch_add(1, Ordering::Relaxed);
        self.touch();
        StreamGuard(Arc::clone(self))
    }

    /// Receive the datagrams of `session` until the returned registration is
    /// dropped. The first registration starts the connection's reader.
    pub fn register(self: &Arc<Self>, session: u32, session_of: SessionOf) -> Registration {
        let (sender, receiver) = mpsc::unbounded_channel();
        lock(&self.waiters).insert(session, sender);
        self.touch();
        self.reader.call_once(|| {
            let weak = Arc::downgrade(self);
            let connection = self.connection.clone();
            tokio::spawn(read_datagrams(connection, weak, session_of));
        });
        Registration {
            pooled: Arc::clone(self),
            session,
            receiver,
        }
    }
}

/// See [`Pooled::stream_guard`].
pub struct StreamGuard(Arc<Pooled>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
        self.0.touch();
    }
}

/// See [`Pooled::register`].
pub struct Registration {
    pooled: Arc<Pooled>,
    session: u32,
    pub receiver: mpsc::UnboundedReceiver<Bytes>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        lock(&self.pooled.waiters).remove(&self.session);
    }
}

async fn read_datagrams(connection: Connection, pooled: Weak<Pooled>, session_of: SessionOf) {
    while let Ok(datagram) = connection.read_datagram().await {
        let Some(pooled) = pooled.upgrade() else { return };
        let Some(session) = session_of(&datagram) else { continue };
        let waiter = lock(&pooled.waiters).get(&session).cloned();
        if let Some(waiter) = waiter {
            let _ = waiter.send(datagram);
        }
    }
}

/// The pool key: protocol, server addresses, TLS parameters and a hash of
/// the credentials. Two outbounds that differ in any of them never share.
pub fn key(protocol: &str, addrs: &[SocketAddr], tls: &impl std::fmt::Debug, secret: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    format!("{tls:?}").hash(&mut hasher);
    secret.hash(&mut hasher);
    let mut sorted: Vec<_> = addrs.iter().map(ToString::to_string).collect();
    sorted.sort();
    format!("{protocol}|{}|{:016x}", sorted.join(","), hasher.finish())
}

/// The live connection for `key`, or a new one from `connect` (which must
/// return it authenticated). Callers asking at the same time share one dial.
pub async fn get<F, Fut>(key: &str, connect: F) -> Result<Arc<Pooled>, String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(Endpoint, Connection), String>>,
{
    let slot = lock(&POOL).entry(key.to_string()).or_default().clone();
    let mut held = slot.lock().await;
    if let Some(pooled) = held.as_ref() {
        if pooled.alive() {
            pooled.touch();
            return Ok(Arc::clone(pooled));
        }
    }
    let (endpoint, connection) = connect().await?;
    let pooled = Arc::new(Pooled::new(endpoint, connection));
    *held = Some(Arc::clone(&pooled));
    tokio::spawn(reap(key.to_string(), Arc::downgrade(&pooled)));
    Ok(pooled)
}

/// Drop `pooled` from the pool (it failed); the next [`get`] dials anew.
pub fn evict(key: &str, pooled: &Arc<Pooled>) {
    let slot = lock(&POOL).get(key).cloned();
    if let Some(slot) = slot {
        if let Ok(mut held) = slot.try_lock() {
            if held.as_ref().is_some_and(|current| Arc::ptr_eq(current, pooled)) {
                *held = None;
            }
        }
    }
    pooled.connection.close(0u32.into(), b"evicted");
}

async fn reap(key: String, pooled: Weak<Pooled>) {
    loop {
        tokio::time::sleep(REAP_INTERVAL).await;
        let Some(current) = pooled.upgrade() else { return };
        if !current.alive() {
            evict(&key, &current);
            return;
        }
        let idle = now_ms().saturating_sub(current.last_used.load(Ordering::Relaxed));
        let busy = current.active.load(Ordering::Relaxed) > 0 || !lock(&current.waiters).is_empty();
        if !busy && idle >= IDLE_CLOSE.as_millis() as u64 {
            evict(&key, &current);
            return;
        }
    }
}

/// After a network change: move every pooled connection onto a fresh socket
/// on the new network (QUIC connection migration). Returns how many moved.
/// A connection the server will not migrate simply fails and is re-dialled
/// on next use. Callable from any thread, inside a runtime or not.
pub fn rebind_all() -> usize {
    let slots: Vec<Slot> = lock(&POOL).values().cloned().collect();
    let mut moved = 0;
    for slot in slots {
        // A dial in progress is on the new network already.
        let Ok(held) = slot.try_lock() else { continue };
        let Some(pooled) = held.as_ref() else { continue };
        if !pooled.alive() {
            continue;
        }
        let bind: SocketAddr = if pooled.v6 {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let _runtime = pooled.runtime.enter();
        match zero_core::platform::bind_protected_udp(bind).and_then(|socket| pooled.endpoint.rebind(socket)) {
            Ok(()) => moved += 1,
            Err(error) => {
                tracing::debug!(%error, "QUIC migration: could not rebind; the connection will be re-dialled");
                pooled.connection.close(0u32.into(), b"network changed");
            }
        }
    }
    if moved > 0 {
        tracing::info!(moved, "QUIC connections migrated to the new network");
    }
    moved
}

/// Connections in the pool that are still open (for tests and diagnostics).
pub fn live_connections() -> usize {
    let slots: Vec<Slot> = lock(&POOL).values().cloned().collect();
    slots
        .iter()
        .filter(|slot| slot.try_lock().ok().is_some_and(|held| held.as_ref().is_some_and(|p| p.alive())))
        .count()
}

/// Open pooled connections to `server` (for tests and diagnostics).
pub fn live_connections_to(server: SocketAddr) -> usize {
    let needle = server.to_string();
    let slots: Vec<Slot> = lock(&POOL)
        .iter()
        .filter(|(key, _)| key.split('|').nth(1).is_some_and(|addrs| addrs.split(',').any(|a| a == needle)))
        .map(|(_, slot)| slot.clone())
        .collect();
    slots
        .iter()
        .filter(|slot| slot.try_lock().ok().is_some_and(|held| held.as_ref().is_some_and(|p| p.alive())))
        .count()
}

/// Close every pooled connection to `server`, so the next use dials anew.
pub fn close_all_to(server: SocketAddr) {
    let needle = server.to_string();
    let slots: Vec<(String, Slot)> = lock(&POOL)
        .iter()
        .filter(|(key, _)| key.split('|').nth(1).is_some_and(|addrs| addrs.split(',').any(|a| a == needle)))
        .map(|(key, slot)| (key.clone(), slot.clone()))
        .collect();
    for (key, slot) in slots {
        let current = slot.try_lock().ok().and_then(|held| held.clone());
        if let Some(pooled) = current {
            evict(&key, &pooled);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_separate_servers_credentials_and_tls() {
        let a: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let b: SocketAddr = "192.0.2.2:443".parse().unwrap();
        let base = key("hysteria2", &[a, b], &"sni=x", b"pw");
        assert_eq!(base, key("hysteria2", &[b, a], &"sni=x", b"pw"), "address order does not matter");
        assert_ne!(base, key("tuic", &[a, b], &"sni=x", b"pw"));
        assert_ne!(base, key("hysteria2", &[a], &"sni=x", b"pw"));
        assert_ne!(base, key("hysteria2", &[a, b], &"sni=y", b"pw"));
        assert_ne!(base, key("hysteria2", &[a, b], &"sni=x", b"other"));
        assert!(!base.contains("pw"), "the credential itself is never part of the key");
    }
}
