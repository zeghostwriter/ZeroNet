//! Reverse proxy: a server behind a NAT that clients can still reach.
//!
//! Two roles, both Xray's (`reverse.bridges` and `reverse.portals`), so either
//! can talk to the other implementation.
//!
//! * The **bridge** runs where the service is (home, an office), which cannot
//!   be reached from outside. It dials *out* to the portal, as an ordinary
//!   routed connection to the name `domain`, and on that one connection acts
//!   as a Mux.cool **server**: whatever the portal sends down it is a request
//!   to open a connection from here.
//! * The **portal** runs on a public host. The bridge's dial-in reaches it as a
//!   connection routed to the portal's outbound tag; recognising the name
//!   `domain`, it does not forward the connection but runs a Mux.cool
//!   **client** on it. From then on, traffic that rules send to the portal tag
//!   is opened as sessions on one of the bridges' carriers.
//!
//! Besides the sessions, the portal keeps a UDP session to the name `reverse`
//! on every carrier and writes a heartbeat there ([`zero_protocol::reverse`]).
//! It lets the bridge tell a carrier that is alive from one a NAT has
//! silently dropped (no heartbeat for [`SILENCE`]), and lets the portal say
//! "this carrier is full, dial another" (`DRAIN`).
//!
//! Rule it must keep: nothing here decides where a bridge's sessions go. They
//! are routed like any connection that arrived on an inbound named after the
//! bridge, so the operator's `routing` (`inboundTag: ["<bridge>"]`) says
//! which local service each one reaches.
//!
//! Limits: TCP only (a UDP session on a carrier is refused), and one portal
//! carrier carries at most [`PER_CARRIER`] sessions.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use zero_core::{boxed, Address, BoxStream, Destination};
use zero_protocol::mux::{ClientPool, ControlSession};
use zero_protocol::reverse::{self as control, State, CONTROL_HOST};

/// Sessions one carrier takes before a portal sends the next one elsewhere.
const PER_CARRIER: usize = 256;
/// Sessions opened on a carrier, over its life, before the portal asks the
/// bridge to dial a fresh one (`DRAIN`).
const DRAIN_AFTER: u32 = 256;
/// How often a portal speaks on a carrier, and how often a bridge looks at its
/// carriers.
const BEAT: Duration = Duration::from_secs(10);
const WATCH: Duration = Duration::from_secs(2);
/// A bridge carrier that has heard nothing for this long is taken as dead.
const SILENCE: Duration = Duration::from_secs(60);
/// Average sessions per carrier above which a bridge opens another.
const BUSY: u32 = 16;
/// Carriers a bridge keeps at most, however busy.
const MAX_CARRIERS: usize = 16;

// ---------------------------------------------------------------- portal

/// The public end. One per portal tag; the carriers bridges have dialled in.
pub struct Portal {
    domain: Arc<str>,
    carriers: Mutex<Vec<Arc<Carrier>>>,
}

struct Carrier {
    pool: Arc<ClientPool>,
    opened: AtomicU32,
    draining: AtomicBool,
}

impl Portal {
    pub fn new(domain: Arc<str>) -> Arc<Self> {
        Arc::new(Self {
            domain,
            carriers: Mutex::new(Vec::new()),
        })
    }

    /// The name a bridge addresses its dial-in to.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Whether `destination` is a bridge announcing itself.
    pub fn is_bridge(&self, destination: &Destination) -> bool {
        matches!(&destination.address, Address::Domain(host) if **host == *self.domain)
    }

    /// Take the connection a bridge dialled in as a carrier: run the mux
    /// client on it and start the heartbeat.
    pub fn adopt(&self, carrier: BoxStream) -> io::Result<()> {
        let pool = ClientPool::raw(carrier, PER_CARRIER as u16);
        let control = pool.open(Destination::udp(Address::domain(CONTROL_HOST), 0))?;
        let carrier = Arc::new(Carrier {
            pool,
            opened: AtomicU32::new(0),
            draining: AtomicBool::new(false),
        });
        {
            let mut carriers = self.lock();
            carriers.retain(|carrier| !carrier.pool.is_closed());
            carriers.push(Arc::clone(&carrier));
        }
        tokio::spawn(heartbeat(carrier, control));
        Ok(())
    }

    /// Open a session to `destination` on the least loaded carrier that is
    /// not draining, or on a draining one when that is all there is.
    pub fn open(&self, destination: &Destination) -> io::Result<BoxStream> {
        let mut candidates: Vec<_> = {
            let mut carriers = self.lock();
            carriers.retain(|carrier| !carrier.pool.is_closed());
            carriers.clone()
        };
        candidates.sort_by_key(|carrier| {
            (
                carrier.draining.load(Ordering::Relaxed),
                carrier.pool.active(),
            )
        });
        for carrier in candidates {
            match carrier.pool.open(destination.clone()) {
                Ok(stream) => {
                    carrier.opened.fetch_add(1, Ordering::Relaxed);
                    return Ok(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no bridge is connected to this portal",
        ))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Arc<Carrier>>> {
        self.carriers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Speak on a carrier's control session until it ends: at once, then every
/// [`BEAT`], with padding of a different length each time. After
/// [`DRAIN_AFTER`] sessions it says `DRAIN` once and falls silent, so the
/// bridge opens another carrier and this one empties out.
async fn heartbeat(carrier: Arc<Carrier>, mut control: BoxStream) {
    let mut ticker = tokio::time::interval(BEAT);
    loop {
        ticker.tick().await;
        if carrier.pool.is_closed() {
            return;
        }
        let drain = carrier.opened.load(Ordering::Relaxed) > DRAIN_AFTER;
        let padding: Vec<u8> = (0..rand::random::<u8>() % 64)
            .map(|_| rand::random())
            .collect();
        let state = if drain { State::Drain } else { State::Active };
        if control
            .write_all(&control::encode(state, &padding))
            .await
            .is_err()
        {
            return;
        }
        if drain {
            carrier.draining.store(true, Ordering::Relaxed);
            let _ = control.shutdown().await;
            return;
        }
    }
}

// ---------------------------------------------------------------- bridge

/// A stream that counts itself while it lives, so a bridge knows how busy a
/// carrier is.
struct Counted {
    inner: BoxStream,
    live: Arc<AtomicU32>,
}

impl Counted {
    fn new(inner: BoxStream, live: &Arc<AtomicU32>) -> Self {
        live.fetch_add(1, Ordering::Relaxed);
        Self {
            inner,
            live: Arc::clone(live),
        }
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::Relaxed);
    }
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_shutdown(cx)
    }
}

struct BridgeCarrier {
    /// False once the portal has said `DRAIN`.
    active: Arc<AtomicBool>,
    /// Sessions being served on it now.
    live: Arc<AtomicU32>,
    /// When the portal last spoke, as milliseconds since `born`.
    heard: Arc<AtomicU64>,
    born: Instant,
    task: tokio::task::JoinHandle<()>,
}

impl BridgeCarrier {
    fn silent_for(&self) -> Duration {
        let now = self.born.elapsed().as_millis() as u64;
        Duration::from_millis(now.saturating_sub(self.heard.load(Ordering::Relaxed)))
    }
}

/// Keep a bridge's carriers up, for as long as this future is polled.
///
/// `dial` opens one connection to the portal (the dial-in); `route` opens
/// the connection one of the portal's sessions asks for. A carrier is added
/// when none is active or the active ones average more than [`BUSY`]
/// sessions; one that goes silent or ends is dropped and, if need be,
/// replaced two seconds later. Trade-off: a bridge whose portal is down
/// retries every two seconds, which is cheap and recovers quickly.
pub async fn run_bridge<D, DF, R, RF>(dial: D, route: R)
where
    D: Fn() -> DF,
    DF: Future<Output = io::Result<BoxStream>>,
    R: Fn(Destination) -> RF + Clone + Send + Sync + 'static,
    RF: Future<Output = io::Result<BoxStream>> + Send + 'static,
{
    let mut carriers: Vec<Arc<BridgeCarrier>> = Vec::new();
    let mut ticker = tokio::time::interval(WATCH);
    loop {
        ticker.tick().await;
        carriers.retain(|carrier| {
            let dead = carrier.task.is_finished() || carrier.silent_for() > SILENCE;
            if dead {
                carrier.task.abort();
            }
            !dead
        });
        let active: Vec<_> = carriers
            .iter()
            .filter(|carrier| carrier.active.load(Ordering::Relaxed))
            .collect();
        let live: u32 = active
            .iter()
            .map(|carrier| carrier.live.load(Ordering::Relaxed))
            .sum();
        let busy = active.is_empty() || live / active.len() as u32 > BUSY;
        if !busy || carriers.len() >= MAX_CARRIERS {
            continue;
        }
        let stream = match dial().await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(%error, "reverse bridge could not reach its portal");
                continue;
            }
        };
        carriers.push(spawn_carrier(stream, route.clone()));
    }
}

fn spawn_carrier<R, RF>(stream: BoxStream, route: R) -> Arc<BridgeCarrier>
where
    R: Fn(Destination) -> RF + Clone + Send + Sync + 'static,
    RF: Future<Output = io::Result<BoxStream>> + Send + 'static,
{
    let born = Instant::now();
    let active = Arc::new(AtomicBool::new(true));
    let live = Arc::new(AtomicU32::new(0));
    let heard = Arc::new(AtomicU64::new(0));
    let control = ControlSession {
        host: CONTROL_HOST,
        on_message: {
            let (active, heard) = (Arc::clone(&active), Arc::clone(&heard));
            Box::new(move |message| {
                heard.store(born.elapsed().as_millis() as u64, Ordering::Relaxed);
                tracing::debug!(bytes = message.len(), state = ?control::decode(message), "reverse control message");
                if control::decode(message) == Some(State::Drain) {
                    active.store(false, Ordering::Relaxed);
                }
            })
        },
    };
    let counted = {
        let live = Arc::clone(&live);
        move |destination| {
            let route = route.clone();
            let live = Arc::clone(&live);
            async move {
                let stream = route(destination).await?;
                Ok(boxed(Counted::new(stream, &live)))
            }
        }
    };
    let task = tokio::spawn(async move {
        match zero_protocol::mux::serve_carrier(stream, control, counted).await {
            Ok(()) => tracing::debug!("a reverse-proxy carrier was closed by the portal"),
            Err(error) => tracing::debug!(%error, "a reverse-proxy carrier ended"),
        }
    });
    Arc::new(BridgeCarrier {
        active,
        live,
        heard,
        born,
        task,
    })
}
