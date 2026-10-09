//! XMUX: XHTTP's HTTP/2 connections, reused across proxied requests.
//!
//! Without it every proxied connection costs a TCP and TLS handshake to the
//! server, which from Iran is most of the time to the first byte. With it a
//! new proxied connection is one more HTTP/2 stream on a connection that is
//! already open. The rules are Xray's (`zero_config::XmuxConfig`), so a
//! server built for Xray clients sees the same pattern of connections:
//!
//! * a connection is retired after `hMaxRequestTimes` HTTP requests, after
//!   `hMaxReusableSecs`, or after being handed out `cMaxReuseTimes` more
//!   times, each drawn per connection from its range, so connections from one
//!   client do not roll over in step;
//! * while fewer than `maxConnections` are open, a request opens another one;
//!   otherwise a request goes on a random open one that carries fewer than
//!   `maxConcurrency` requests, or opens a new one when none does.
//!
//! A retired connection is only no longer handed out: the requests already
//! on it run to their end, and h2 closes it once the last one is gone. A
//! connection nothing has used for [`IDLE_AFTER`] is retired too, by a small
//! sweeper task, so a server the balancer moved away from (or one a delay
//! test touched once) does not keep a connection and its keepalive PINGs open
//! for as long as the process lives. The sweeper ends once no pool is left.
//!
//! One pool per server, keyed by a digest of the compiled outbound and its
//! addresses (the same key VLESS Mux pools use), so a reload that changes
//! the outbound starts a fresh pool, and credentials never sit in a key.
//!
//! ```text
//! request 1 -> no connection yet           -> dial, open, use
//! request 2 -> 1 open, maxConnections 3    -> dial another
//! request 4 -> 3 open                      -> a random open one
//! ```
//!
//! Two requests that both find the pool needing a connection both dial, up
//! to `maxConnections`; one that finds every connection full while a dial is
//! already on its way waits for that dial instead of starting its own.
//!
//! Reuse watches itself, so it is safe without anyone testing it first. Some
//! networks let a fresh connection through and stall one that has been open
//! a while. So each request on a *reused* connection is judged: it is fine
//! once the server sends anything back, and a strike when it could not be
//! opened, or when it wrote and then heard nothing for [`SILENT_AFTER`] before
//! it ended. [`STRIKES`] in a row and that server gets a connection per
//! request for [`BYPASS_FOR`], after which reuse is tried again. A request on
//! a fresh connection says nothing about reuse and is not judged.
//!
//! ```text
//! reused -> answered            -> strikes back to 0
//! reused -> silent, then closed -> 1 strike
//! reused -> silent, then closed -> 2 strikes: a connection per request, 10 min
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zero_config::xhttp::XmuxConfig;
use zero_core::{BoxStream, Failure, FailureKind, Stage};
use zero_transport::xhttp::H2Carrier;

/// Most servers with a pool at once. A pool with nothing open in it is
/// dropped first when a new server needs room.
const MAX_POOLS: usize = 64;
/// How long a connection may sit with no request on it before it is closed.
/// Go's HTTP/2 transport, which Xray uses, closes idle ones too.
const IDLE_AFTER: Duration = Duration::from_secs(120);
/// How often the sweeper looks for idle connections.
const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// How long a request on a reused connection may go unanswered after it
/// wrote, before it counts against reuse. Well above a slow line's round
/// trip, well below how long a person waits.
const SILENT_AFTER: Duration = Duration::from_secs(5);
/// Failed requests on reused connections in a row that stop reuse for a
/// server. One is not enough: a page closed early looks the same.
const STRIKES: u8 = 2;
/// How long a server that failed reuse gets a connection per request.
const BYPASS_FOR: Duration = Duration::from_secs(10 * 60);

/// How reuse has been going for one server, shared by its pool and every
/// connection and request in it.
#[derive(Default)]
struct Health {
    /// Failed requests on reused connections since the last answered one.
    strikes: std::sync::atomic::AtomicU8,
    /// Until when this server gets no reuse.
    bypass_until: Mutex<Option<Instant>>,
}

impl Health {
    fn answered(&self) {
        self.strikes.store(0, Ordering::Relaxed);
    }

    fn failed(&self) {
        if self.strikes.fetch_add(1, Ordering::Relaxed) + 1 >= STRIKES {
            self.strikes.store(0, Ordering::Relaxed);
            *self.bypass_until.lock().unwrap_or_else(|p| p.into_inner()) =
                Some(Instant::now() + BYPASS_FOR);
            tracing::info!(
                minutes = BYPASS_FOR.as_secs() / 60,
                "XHTTP connection reuse failed twice for a server; a connection per request for now"
            );
        }
    }

    fn bypassing(&self, now: Instant) -> bool {
        self.bypass_until
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some_and(|until| now < until)
    }
}

/// One open connection and what is left of its allowance.
struct Entry {
    carrier: H2Carrier,
    /// Proxied requests on it right now, for `maxConcurrency`.
    open: AtomicU32,
    /// Times it may still be handed out again; negative is unlimited.
    uses_left: AtomicI64,
    /// HTTP requests it may serve before it is retired; zero is unlimited.
    max_requests: u32,
    /// When it stops being handed out, if ever.
    until: Option<Instant>,
    /// When it last had a request start or end on it, for [`IDLE_AFTER`].
    used: Mutex<Instant>,
    /// Its server's record of how reuse is going.
    health: Arc<Health>,
}

impl Entry {
    fn new(carrier: H2Carrier, config: &XmuxConfig, now: Instant, health: Arc<Health>) -> Self {
        let uses = draw(config.c_max_reuse_times);
        let secs = draw(config.h_max_reusable_secs);
        Self {
            carrier,
            open: AtomicU32::new(0),
            uses_left: AtomicI64::new(if uses == 0 { -1 } else { i64::from(uses) }),
            max_requests: draw(config.h_max_request_times),
            until: (secs > 0).then(|| now + Duration::from_secs(u64::from(secs))),
            used: Mutex::new(now),
            health,
        }
    }

    /// Note a request starting or ending on this connection.
    fn touch(&self) {
        *self.used.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
    }

    /// Whether nothing is on this connection and nothing has been for
    /// [`IDLE_AFTER`].
    fn idle(&self, now: Instant) -> bool {
        self.open.load(Ordering::Relaxed) == 0
            && now.duration_since(*self.used.lock().unwrap_or_else(|p| p.into_inner()))
                >= IDLE_AFTER
    }

    /// Whether this connection may take another proxied request.
    fn reusable(&self, now: Instant) -> bool {
        self.uses_left.load(Ordering::Relaxed) != 0
            && (self.max_requests == 0 || self.carrier.requests() < self.max_requests)
            && self.until.is_none_or(|until| now < until)
            && self.carrier.is_usable()
    }

    /// Hand this connection out: one more request on it. `reused` says it
    /// already carried one, which is what makes the request worth judging.
    fn lease(self: &Arc<Self>, reused: bool) -> Lease {
        self.open.fetch_add(1, Ordering::Relaxed);
        self.touch();
        Lease {
            entry: Arc::clone(self),
            reused,
        }
    }
}

/// A number from an Xray range, `(0, 0)` giving zero ("no limit").
fn draw((from, to): (u32, u32)) -> u32 {
    let (low, high) = (from.min(to), from.max(to));
    if low == high {
        low
    } else {
        rand::thread_rng().gen_range(low..=high)
    }
}

/// One server's connections.
struct Pool {
    entries: Vec<Arc<Entry>>,
    /// Dials on their way, counted as connections so two requests do not
    /// both open the last one `maxConnections` allows.
    dialing: u32,
    /// Drawn once per pool, as Xray does.
    max_connections: u32,
    max_concurrency: u32,
    /// Bumped whenever a dial ends, for the requests waiting on one.
    dialed: tokio::sync::watch::Sender<u64>,
    health: Arc<Health>,
}

/// What a request does next.
enum Next {
    Use(Lease),
    Dial,
    /// A connection of its own, kept out of the pool: reuse is off for this
    /// server for now.
    DialAlone(Arc<Health>),
    Wait(tokio::sync::watch::Receiver<u64>),
}

impl Pool {
    fn new(config: &XmuxConfig) -> Self {
        Self {
            entries: Vec::new(),
            dialing: 0,
            max_connections: draw(config.max_connections),
            max_concurrency: draw(config.max_concurrency),
            dialed: tokio::sync::watch::channel(0).0,
            health: Arc::default(),
        }
    }

    /// Xray's choice: drop what may not be reused, open another connection
    /// while below `maxConnections`, else a random one with room.
    fn next(&mut self, now: Instant) -> Next {
        self.prune(now);
        if self.health.bypassing(now) {
            return Next::DialAlone(Arc::clone(&self.health));
        }
        let total = self.entries.len() as u32 + self.dialing;
        if total == 0 || (self.max_connections > 0 && total < self.max_connections) {
            self.dialing += 1;
            return Next::Dial;
        }
        let room: Vec<&Arc<Entry>> = self
            .entries
            .iter()
            .filter(|entry| {
                self.max_concurrency == 0
                    || entry.open.load(Ordering::Relaxed) < self.max_concurrency
            })
            .collect();
        if room.is_empty() {
            if self.dialing > 0 {
                return Next::Wait(self.dialed.subscribe());
            }
            self.dialing += 1;
            return Next::Dial;
        }
        let entry = room[rand::thread_rng().gen_range(0..room.len())];
        // Only a positive allowance counts down; negative is unlimited.
        let _ = entry
            .uses_left
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                (left > 0).then(|| left - 1)
            });
        Next::Use(entry.lease(true))
    }

    /// Whether this pool still holds anything worth keeping: connections, a
    /// dial on its way, or a server's "no reuse for now" that must not be
    /// forgotten when its last connection goes.
    fn keep(&self, now: Instant) -> bool {
        self.dialing > 0 || !self.entries.is_empty() || self.health.bypassing(now)
    }
}

impl Pool {
    /// Drop the connections that may not be handed out again, or that have
    /// sat idle too long. Dropping one here only drops the pool's handle.
    fn prune(&mut self, now: Instant) {
        self.entries
            .retain(|entry| entry.reusable(now) && !entry.idle(now));
    }
}

static POOLS: OnceLock<Mutex<HashMap<String, Pool>>> = OnceLock::new();

fn pools() -> std::sync::MutexGuard<'static, HashMap<String, Pool>> {
    POOLS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn with_pool<T>(key: &str, config: &XmuxConfig, f: impl FnOnce(&mut Pool) -> T) -> T {
    let mut pools = pools();
    if !pools.contains_key(key) {
        if pools.len() >= MAX_POOLS {
            let now = Instant::now();
            pools.retain(|_, pool| pool.keep(now));
        }
        start_sweeper();
    }
    f(pools
        .entry(key.to_owned())
        .or_insert_with(|| Pool::new(config)))
}

/// Prune every pool as of `now`, forget the pools left with nothing in them,
/// and say how many remain.
fn sweep(now: Instant) -> usize {
    sweep_where(now, |_| true)
}

/// [`sweep`], limited to the pools whose key passes `which`.
fn sweep_where(now: Instant, which: impl Fn(&str) -> bool) -> usize {
    let mut pools = pools();
    pools.retain(|key, pool| {
        if which(key) {
            pool.prune(now);
        }
        pool.keep(now)
    });
    pools.len()
}

/// Whether a sweeper task is running.
static SWEEPING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Start the sweeper on the current runtime unless one is running. It ends
/// by itself once no pool is left, and if its runtime shuts down; either way
/// the flag is cleared, so the next pool starts a new one.
fn start_sweeper() {
    if SWEEPING.swap(true, Ordering::AcqRel) {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        SWEEPING.store(false, Ordering::Release);
        return;
    };
    struct Done;
    impl Drop for Done {
        fn drop(&mut self) {
            SWEEPING.store(false, Ordering::Release);
        }
    }
    runtime.spawn(async {
        let _done = Done;
        loop {
            tokio::time::sleep(SWEEP_EVERY).await;
            if sweep(Instant::now()) == 0 {
                return;
            }
        }
    });
}

/// A connection handed to one proxied request. Dropping it gives the slot
/// back; keep it as long as the request runs ([`hold`]).
pub(crate) struct Lease {
    entry: Arc<Entry>,
    /// The connection had carried a request before this one.
    reused: bool,
}

impl Lease {
    pub(crate) fn carrier(&self) -> &H2Carrier {
        &self.entry.carrier
    }

    /// Keep this connection from being handed out again, after a request on
    /// it failed: it is broken or about to be, and the next request should
    /// not find out the same way. On a reused connection it is also a strike
    /// against reuse for this server.
    pub(crate) fn retire(&self) {
        self.entry.uses_left.store(0, Ordering::Relaxed);
        if self.reused {
            self.entry.health.failed();
        }
    }

    /// The server answered a request on this connection.
    fn answered(&self) {
        if self.reused {
            self.entry.health.answered();
        }
    }

    /// The request wrote and heard nothing back for [`SILENT_AFTER`].
    fn went_silent(&self) {
        if self.reused {
            self.entry.health.failed();
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.entry.touch();
        self.entry.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connection from the pool under `key`, or a new one made with `dial`
/// (TCP plus TLS or REALITY to the server) and added to it.
pub(crate) async fn lease<F, Fut>(key: &str, config: &XmuxConfig, dial: F) -> Result<Lease, Failure>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<BoxStream, Failure>>,
{
    loop {
        match with_pool(key, config, |pool| pool.next(Instant::now())) {
            Next::Use(lease) => return Ok(lease),
            Next::DialAlone(health) => {
                let carrier = open(config, dial).await?;
                let entry = Arc::new(Entry::new(carrier, config, Instant::now(), health));
                // Handed out once and never pooled.
                entry.uses_left.store(0, Ordering::Relaxed);
                return Ok(entry.lease(false));
            }
            Next::Wait(mut dialed) => {
                // The dial in flight ends either way; then choose again.
                let _ = dialed.changed().await;
            }
            Next::Dial => {
                let opened = open(config, dial).await;
                return with_pool(key, config, |pool| {
                    pool.dialing = pool.dialing.saturating_sub(1);
                    pool.dialed.send_modify(|count| *count += 1);
                    let health = Arc::clone(&pool.health);
                    let entry = Arc::new(Entry::new(opened?, config, Instant::now(), health));
                    let lease = entry.lease(false);
                    pool.entries.push(entry);
                    Ok(lease)
                });
            }
        }
    }
}

/// Dial and open one HTTP/2 connection with this pool's keepalive.
async fn open<F, Fut>(config: &XmuxConfig, dial: F) -> Result<H2Carrier, Failure>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<BoxStream, Failure>>,
{
    let stream = dial().await?;
    H2Carrier::open_with_keepalive(stream, config.h_keep_alive_period)
        .await
        .map_err(|error| {
            Failure::new(FailureKind::HttpMalformed, Stage::RequestSent).with_detail(error)
        })
}

/// `stream` with the leases it runs on, so each connection's slot is given
/// back when the proxied request ends, not before.
pub(crate) fn hold(stream: BoxStream, leases: Vec<Lease>) -> BoxStream {
    if leases.is_empty() {
        return stream;
    }
    zero_core::boxed(Held {
        inner: stream,
        leases,
        wrote: None,
        answered: false,
    })
}

/// A proxied request and the connections it runs on, judged for reuse
/// (see the module text): answered at its first byte back, silent when it
/// ends having written and heard nothing for [`SILENT_AFTER`].
struct Held {
    inner: BoxStream,
    leases: Vec<Lease>,
    /// When it first wrote.
    wrote: Option<Instant>,
    /// Whether anything came back yet.
    answered: bool,
}

impl AsyncRead for Held {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = self.inner.as_mut().poll_read(cx, buf);
        if !self.answered && buf.filled().len() > before {
            self.answered = true;
            self.leases.iter().for_each(Lease::answered);
        }
        poll
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let silent = !self.answered
            && self
                .wrote
                .is_some_and(|wrote| wrote.elapsed() >= SILENT_AFTER);
        if silent {
            self.leases.iter().for_each(Lease::went_silent);
        }
    }
}

impl AsyncWrite for Held {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.wrote.is_none() && !buf.is_empty() {
            self.wrote = Some(Instant::now());
        }
        self.inner.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An HTTP/2 server that answers every request with 200 and echoes the
    /// body, and counts the connections it accepted.
    fn server() -> (tokio::net::TcpListener, Arc<AtomicU32>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        (
            tokio::net::TcpListener::from_std(listener).unwrap(),
            Arc::new(AtomicU32::new(0)),
        )
    }

    async fn serve(listener: tokio::net::TcpListener, accepted: Arc<AtomicU32>) {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            accepted.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(tcp).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    tokio::spawn(async move {
                        let mut body = request.into_body();
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        let mut send = respond.send_response(response, false).unwrap();
                        while let Some(Ok(chunk)) = body.data().await {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            if send.send_data(chunk, false).is_err() {
                                return;
                            }
                        }
                        let _ = send.send_data(bytes::Bytes::new(), true);
                    });
                }
            });
        }
    }

    async fn dial(address: std::net::SocketAddr) -> Result<BoxStream, Failure> {
        let tcp = tokio::net::TcpStream::connect(address)
            .await
            .map_err(|error| Failure::from_io(&error, Stage::SocketConnected))?;
        Ok(zero_core::boxed(tcp))
    }

    async fn round_trip(lease: &Lease, word: &[u8]) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let config = zero_transport::ws::WsConfig::new("/x", "example.com");
        let mut stream = lease.carrier().stream_one(&config).await.unwrap();
        stream.write_all(word).await.unwrap();
        stream.flush().await.unwrap();
        let mut echo = vec![0u8; word.len()];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(echo, word);
    }

    /// Xray's defaults: up to three connections, then reuse.
    #[tokio::test]
    async fn requests_spread_over_max_connections_then_reuse_them() {
        let (listener, accepted) = server();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&accepted)));
        let key = format!("spread-{address}");
        let config = XmuxConfig::DEFAULTS;
        let mut leases = Vec::new();
        for n in 0..8u8 {
            let lease = lease(&key, &config, || dial(address)).await.unwrap();
            round_trip(&lease, &[n; 3]).await;
            leases.push(lease);
        }
        assert_eq!(accepted.load(Ordering::Relaxed), 3);
        drop(leases);
        // Slots given back: the next requests still find the same three.
        let again = lease(&key, &config, || dial(address)).await.unwrap();
        round_trip(&again, b"again").await;
        assert_eq!(accepted.load(Ordering::Relaxed), 3);
    }

    /// `maxConcurrency`: a full connection makes the next request open
    /// another, and a freed slot is used again.
    #[tokio::test]
    async fn a_full_connection_opens_another() {
        let (listener, accepted) = server();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&accepted)));
        let key = format!("concurrency-{address}");
        let config = XmuxConfig {
            max_concurrency: (2, 2),
            ..XmuxConfig::NONE
        };
        // A round trip on each, so the server has accepted what was opened
        // before the count is read.
        let first = lease(&key, &config, || dial(address)).await.unwrap();
        round_trip(&first, b"first").await;
        let second = lease(&key, &config, || dial(address)).await.unwrap();
        round_trip(&second, b"second").await;
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
        let third = lease(&key, &config, || dial(address)).await.unwrap();
        round_trip(&third, b"third").await;
        assert_eq!(accepted.load(Ordering::Relaxed), 2);
        drop(first);
        let fourth = lease(&key, &config, || dial(address)).await.unwrap();
        round_trip(&fourth, b"fourth").await;
        assert_eq!(accepted.load(Ordering::Relaxed), 2);
        drop((second, third, fourth));
    }

    /// A connection is retired after its request allowance, and one that
    /// was retired by hand is never handed out again.
    #[tokio::test]
    async fn spent_and_retired_connections_are_not_reused() {
        let (listener, accepted) = server();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&accepted)));
        let key = format!("retire-{address}");
        let config = XmuxConfig {
            h_max_request_times: (2, 2),
            ..XmuxConfig::NONE
        };
        for n in 0..4u8 {
            let lease = lease(&key, &config, || dial(address)).await.unwrap();
            round_trip(&lease, &[n; 2]).await;
        }
        // Two requests per connection: four requests, two connections.
        assert_eq!(accepted.load(Ordering::Relaxed), 2);
        let broken = lease(&key, &config, || dial(address)).await.unwrap();
        broken.retire();
        drop(broken);
        let fresh = lease(&key, &config, || dial(address)).await.unwrap();
        round_trip(&fresh, b"fresh").await;
        assert_eq!(accepted.load(Ordering::Relaxed), 4);
    }

    /// Many requests at once with one connection allowed: one dial, the
    /// rest wait for it rather than opening their own.
    #[tokio::test]
    async fn simultaneous_requests_share_one_dial() {
        let (listener, accepted) = server();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&accepted)));
        let key = Arc::new(format!("burst-{address}"));
        let config = XmuxConfig {
            max_connections: (1, 1),
            ..XmuxConfig::NONE
        };
        let tasks: Vec<_> = (0..16u8)
            .map(|n| {
                let key = Arc::clone(&key);
                tokio::spawn(async move {
                    let lease = lease(&key, &config, || dial(address)).await.unwrap();
                    round_trip(&lease, &[n; 4]).await;
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
    }

    /// A connection left idle past [`IDLE_AFTER`] is swept out of its pool,
    /// and with no handle and no stream left on it, h2 closes it: the server
    /// sees the connection end.
    #[tokio::test]
    async fn an_idle_connection_is_swept_and_closed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let address = listener.local_addr().unwrap();
        let (closed_tx, closed) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(tcp).await.unwrap();
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                let mut body = request.into_body();
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                tokio::spawn(async move {
                    while let Some(Ok(chunk)) = body.data().await {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        let _ = send.send_data(chunk, false);
                    }
                    let _ = send.send_data(bytes::Bytes::new(), true);
                });
            }
            let _ = closed_tx.send(());
        });
        let key = format!("idle-{address}");
        let lease = lease(&key, &XmuxConfig::DEFAULTS, || dial(address))
            .await
            .unwrap();
        {
            // The stream ends with this scope, and so does the lease.
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let config = zero_transport::ws::WsConfig::new("/x", "example.com");
            let mut stream = lease.carrier().stream_one(&config).await.unwrap();
            stream.write_all(b"once").await.unwrap();
            let mut echo = [0u8; 4];
            stream.read_exact(&mut echo).await.unwrap();
            stream.shutdown().await.unwrap();
        }
        drop(lease);
        // Not yet idle long enough: kept.
        // Only this test's pool: the others run alongside and are theirs.
        let mine = |k: &str| k == key;
        sweep_where(Instant::now(), mine);
        assert!(pools()
            .get(&key)
            .is_some_and(|pool| pool.entries.len() == 1));
        // As if the idle time had passed.
        sweep_where(Instant::now() + IDLE_AFTER + Duration::from_secs(1), mine);
        assert!(pools().get(&key).is_none(), "an empty pool is forgotten");
        tokio::time::timeout(Duration::from_secs(10), closed)
            .await
            .expect("the idle connection is closed")
            .unwrap();
    }

    /// A request on a reused connection, as [`hold`] makes it, that wrote
    /// [`SILENT_AFTER`] ago and then ends: answered or not.
    fn judged(lease: Lease, answered: bool) {
        // What the first byte back does in `Held::poll_read`.
        if answered {
            lease.answered();
        }
        drop(Held {
            inner: zero_core::boxed(tokio::io::duplex(16).0),
            leases: vec![lease],
            wrote: Some(Instant::now() - SILENT_AFTER - Duration::from_millis(1)),
            answered,
        });
    }

    /// Two silent requests in a row on reused connections switch reuse off
    /// for that server: every request then gets a connection of its own,
    /// outside the pool. An answer in between wipes the first strike.
    #[tokio::test]
    async fn reuse_that_goes_silent_twice_is_switched_off_for_that_server() {
        let (listener, accepted) = server();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&accepted)));
        let key = format!("silent-{address}");
        let config = XmuxConfig {
            max_connections: (1, 1),
            ..XmuxConfig::NONE
        };
        let first = lease(&key, &config, || dial(address)).await.unwrap();
        assert!(!first.reused, "a fresh connection is not judged");
        round_trip(&first, b"first").await;
        drop(first);

        // Strike, answer, strike: not two in a row, so reuse stays.
        for answered in [false, true, false] {
            let lease = lease(&key, &config, || dial(address)).await.unwrap();
            assert!(lease.reused);
            judged(lease, answered);
        }
        let still = lease(&key, &config, || dial(address)).await.unwrap();
        assert!(still.reused, "one strike alone does not stop reuse");
        round_trip(&still, b"still").await;
        assert_eq!(accepted.load(Ordering::Relaxed), 1);

        // That request was answered; two silent ones in a row now.
        judged(still, true);
        for _ in 0..2 {
            let lease = lease(&key, &config, || dial(address)).await.unwrap();
            assert!(lease.reused);
            judged(lease, false);
        }
        for n in 0..2u8 {
            let alone = lease(&key, &config, || dial(address)).await.unwrap();
            assert!(!alone.reused, "a connection of its own");
            round_trip(&alone, &[n; 5]).await;
        }
        assert_eq!(
            accepted.load(Ordering::Relaxed),
            3,
            "one new connection per request"
        );
        // The "no reuse for now" outlives a sweep of the empty pool.
        sweep_where(Instant::now() + IDLE_AFTER + Duration::from_secs(1), |k| {
            k == key
        });
        let after = lease(&key, &config, || dial(address)).await.unwrap();
        assert!(!after.reused);
        drop(after);
    }

    /// End to end, through [`hold`] and real time: a server that answers
    /// the first request on a connection and stalls every later one, which is
    /// what a path that cuts reused connections looks like. Two stalls and
    /// the next request gets a connection of its own, and gets through.
    #[tokio::test]
    async fn a_path_that_stalls_reused_connections_gets_fresh_ones() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut connection = h2::server::handshake(tcp).await.unwrap();
                    let mut first = true;
                    let mut stalled = Vec::new();
                    while let Some(Ok((request, mut respond))) = connection.accept().await {
                        if !std::mem::take(&mut first) {
                            stalled.push((request, respond));
                            continue;
                        }
                        let mut body = request.into_body();
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        let mut send = respond.send_response(response, false).unwrap();
                        tokio::spawn(async move {
                            while let Some(Ok(chunk)) = body.data().await {
                                let _ = body.flow_control().release_capacity(chunk.len());
                                let _ = send.send_data(chunk, false);
                            }
                        });
                    }
                });
            }
        });
        let key = format!("stall-{address}");
        let config = XmuxConfig {
            max_connections: (1, 1),
            ..XmuxConfig::NONE
        };
        let http = zero_transport::ws::WsConfig::new("/x", "example.com");
        let open = || async {
            let lease = lease(&key, &config, || dial(address)).await.unwrap();
            let reused = lease.reused;
            let stream = lease.carrier().stream_one(&http).await.unwrap();
            (hold(stream, vec![lease]), reused)
        };
        let (mut first, reused) = open().await;
        assert!(!reused);
        first.write_all(b"hello").await.unwrap();
        let mut echo = [0u8; 5];
        first.read_exact(&mut echo).await.unwrap();
        for _ in 0..2 {
            let (mut stalled, reused) = open().await;
            assert!(reused);
            stalled.write_all(b"anyone").await.unwrap();
            stalled.flush().await.unwrap();
            tokio::time::sleep(SILENT_AFTER + Duration::from_millis(200)).await;
            drop(stalled);
        }
        let (mut fresh, reused) = open().await;
        assert!(!reused, "reuse is off for this server now");
        fresh.write_all(b"again").await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), fresh.read_exact(&mut echo))
            .await
            .expect("a fresh connection gets through")
            .unwrap();
        assert_eq!(&echo, b"again");
        drop(first);
    }

    /// A request that failed to open on a reused connection counts too, and
    /// one on a fresh connection never does.
    #[tokio::test]
    async fn only_requests_on_reused_connections_are_judged() {
        let (listener, accepted) = server();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&accepted)));
        let key = format!("judged-{address}");
        let config = XmuxConfig {
            max_connections: (1, 1),
            ..XmuxConfig::NONE
        };
        let fresh = lease(&key, &config, || dial(address)).await.unwrap();
        round_trip(&fresh, b"fresh").await;
        let health = Arc::clone(&fresh.entry.health);
        judged(fresh, false);
        assert_eq!(health.strikes.load(Ordering::Relaxed), 0);
        let reused = lease(&key, &config, || dial(address)).await.unwrap();
        reused.retire();
        assert_eq!(health.strikes.load(Ordering::Relaxed), 1);
    }

    /// A failed dial is reported, and does not leave the pool thinking one
    /// is still on its way.
    #[tokio::test]
    async fn a_failed_dial_is_reported_and_forgotten() {
        let (listener, accepted) = server();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&accepted)));
        let key = format!("fail-{address}");
        let config = XmuxConfig::DEFAULTS;
        let failed = lease(&key, &config, || async {
            Err(Failure::new(
                FailureKind::TcpTimeout,
                Stage::SocketConnected,
            ))
        })
        .await;
        assert!(failed.is_err());
        let lease = lease(&key, &config, || dial(address)).await.unwrap();
        round_trip(&lease, b"after").await;
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
    }
}
