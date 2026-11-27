//! Tide over HTTP/2: sessions carried in ordinary request and response bodies.
//!
//! How this works: a Tide session (`zero_protocol::tide`) only needs pipes,
//! things that move bytes one way and may die. Here a pipe is an HTTP body.
//!
//! ```text
//!   POST <path>/<session>/open         body: handshake     reply: handshake
//!   POST <path>/<session>/u/<n>?t=..   body: chunks going up
//!   GET  <path>/<session>/d/<n>?t=..   reply: chunks coming down
//! ```
//!
//! Upload and download are separate requests, and can be separate
//! connections. To anyone watching, one connection is a client posting data
//! and getting short answers, and the other is a client downloading one long
//! response. Neither shows a request followed by its reply, which is the
//! shape that gives a proxied TLS handshake away.
//!
//! Every connection first asks for the site's front page, as a visitor
//! would. That makes the opening packets ordinary web traffic, and the reply
//! carries the server's clock (`Date`), which the handshake's timestamp is
//! taken from, so a phone with the wrong time still connects.
//!
//! The server side answers anything that is not a valid Tide request with
//! its decoy page: a wrong path, an unknown session, a handshake that does
//! not decrypt or was seen before all look the same from outside.
//!
//! The rules it keeps:
//!  * a pipe that fails reports it ([`Session::pipe_closed`]), so what it
//!    carried is sent again elsewhere; a session outlives its connections;
//!  * a connection that is working is still replaced now and then (age and
//!    volume limits, see [`Rotation`]): the new one is made first, new
//!    requests move to it, and the old one closes when its last request is
//!    done, so no connection grows old enough to be remembered;
//!  * a body is written only as fast as HTTP/2 grants room, so nothing piles
//!    up in memory behind a slow link;
//!  * nothing is read from a request before its path proves it belongs to a
//!    session, apart from the small handshake body.
//!
//! The surprise: pipes are numbered by the client and each number is used
//! once. A proof derived from the session's keys rides in the query string,
//! so someone who learned a session's name (a CDN log, say) cannot attach a
//! pipe to it.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use h2::client::SendRequest;
use http::{Method, Request, Response, StatusCode};
use rand::{Rng, RngCore};
use zero_core::{BoxStream, Destination};
use zero_protocol::tide::session::{pipe_tag, CHUNK_PLAIN_MAX};
use zero_protocol::tide::{self, ChunkParser, ReplayGuard, Session, TideStream, UserId};

/// HTTP/2 windows large enough that the transport, not HTTP/2, sets the pace.
pub(crate) const H2_WINDOW: u32 = 4 * 1024 * 1024;
/// The most a handshake body may be; real ones are well under 100 bytes.
const HANDSHAKE_MAX: usize = 1024;
/// A download pipe with nothing to carry for this long is ended by the
/// server. Shorter than the idle limits of the proxies it may sit behind.
const DOWN_IDLE: Duration = Duration::from_secs(45);
/// A session with no streams for this long is closed, and its connections
/// with it: an idle phone should not hold a connection open.
const SESSION_IDLE: Duration = Duration::from_secs(90);
/// Sessions the server has not heard from for this long are forgotten.
const SESSION_FORGET: Duration = Duration::from_secs(300);
/// Failed attempts in a row before a client gives a session up.
const MAX_FAILURES: u32 = 6;
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36";

/// What the client's requests look like to anything reading them: the
/// browser it says it is, the language it asks for, and any headers a site
/// would send that the user wants added. Every request carries it, so a
/// middlebox sees one consistent visitor.
///
/// The rule: `headers` never holds a name Tide itself sets (`content-type`,
/// `host`, `content-length`), which the link parser refuses; if one got in,
/// it would break the protocol, not just change the look.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Look {
    pub user_agent: String,
    pub language: String,
    pub headers: Vec<(String, String)>,
}

impl Default for Look {
    fn default() -> Self {
        Self {
            user_agent: USER_AGENT.into(),
            language: "en-US,en;q=0.9".into(),
            headers: Vec::new(),
        }
    }
}

/// How many connections a session keeps busy and how often it checks on
/// them. The defaults are what Tide was tuned with; each is a link setting
/// for a path where something else works better (a proxy that allows one
/// open request per client, a mobile network that kills quiet connections
/// early, a server that wants a bigger spread).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tuning {
    pub look: Look,
    /// Download requests open at once.
    pub down_pipes: usize,
    /// Upload requests that may wait for their answer at once.
    pub up_pipes: usize,
    /// How often each HTTP/2 connection is pinged.
    pub ping: Duration,
    /// A session with no streams for this long is closed.
    pub idle: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            look: Look::default(),
            down_pipes: DOWNLOAD_PIPES,
            up_pipes: UPLOADS_IN_FLIGHT,
            ping: PING_EVERY,
            idle: SESSION_IDLE,
        }
    }
}

pub(crate) fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Write `data` to a body, waiting for HTTP/2 to grant room for each part.
pub(crate) async fn send_all(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let granted = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?
            .map_err(other)?;
        let part = data.split_to(granted.min(data.len()));
        send.send_data(part, false).map_err(other)?;
    }
    Ok(())
}

// ---------------------------------------------------------------- HTTP dates

const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Seconds since 1970 as an HTTP `Date` value, e.g.
/// `Wed, 07 Oct 2026 14:05:09 GMT`.
pub fn http_date(time: u64) -> String {
    let days = time / 86_400;
    let (hour, minute, second) = (time % 86_400 / 3600, time % 3600 / 60, time % 60);
    // Days to a calendar date, by Howard Hinnant's civil-from-days method.
    let shifted = days as i64 + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        day,
        MONTHS[(month - 1) as usize],
        year,
        hour,
        minute,
        second
    )
}

/// The reverse of [`http_date`]; `None` for anything else.
pub fn parse_http_date(text: &str) -> Option<u64> {
    let mut parts = text.split_ascii_whitespace();
    parts.next()?; // weekday
    let day: i64 = parts.next()?.parse().ok()?;
    let month_name = parts.next()?;
    let month = MONTHS.iter().position(|name| *name == month_name)? as i64 + 1;
    let year: i64 = parts.next()?.parse().ok()?;
    let mut clock = parts.next()?.split(':');
    let hour: u64 = clock.next()?.parse().ok()?;
    let minute: u64 = clock.next()?.parse().ok()?;
    let second: u64 = clock.next()?.parse().ok()?;
    if !(1..=31).contains(&day) || year < 1970 || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    // Days from a calendar date, the same method run backwards.
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days as u64 * 86_400 + hour * 3600 + minute * 60 + second)
}

// -------------------------------------------------------------------- client

/// Connects to the server and returns a stream ready for HTTP/2 (TLS already
/// done, with `h2` negotiated, when the server expects TLS).
pub type Dialer =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send>> + Send + Sync>;

/// When a connection is replaced by a fresh one while it still works.
///
/// A connection that lives for hours and moves gigabytes is what a censor's
/// per-flow budget catches, and what no browser's connection looks like. So
/// each connection is given its own age and volume limit, drawn at random
/// from the upper half of the allowance here (so rotations keep no rhythm),
/// and is replaced when it passes either. `min_age` is the floor under both
/// draws: a connection is never churned faster than this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rotation {
    pub min_age: Duration,
    pub max_age: Duration,
    pub max_bytes: u64,
}

impl Default for Rotation {
    fn default() -> Self {
        Self {
            min_age: Duration::from_secs(120),
            max_age: Duration::from_secs(600),
            max_bytes: 2 << 30,
        }
    }
}

impl Rotation {
    /// One connection's own limits: `(age, bytes)`, with the allowance
    /// multiplied by `scale` (1.0 unless connections have been dying young).
    /// The age never goes below `min_age` and the volume never below
    /// [`MIN_BYTES`], so a hostile network can make rotation faster but not
    /// frantic.
    fn draw(&self, scale: f64) -> (Duration, u64) {
        let mut rng = rand::thread_rng();
        let age = self.max_age.mul_f64(rng.gen_range(0.5..=1.0) * scale);
        let bytes = (self.max_bytes as f64 * rng.gen_range(0.5..=1.0) * scale) as u64;
        (
            age.max(self.min_age),
            bytes.max(MIN_BYTES.min(self.max_bytes)),
        )
    }
}

#[derive(Clone)]
pub struct ClientConfig {
    /// The site's name, for the `:authority` of every request.
    pub host: String,
    /// The path prefix Tide requests live under, e.g. `/assets/v2`.
    pub path: String,
    pub server_public: [u8; 32],
    pub user: UserId,
    /// Use a second connection for uploads, so the two directions never
    /// share one.
    pub split: bool,
    /// How long an upload request stays open waiting for more to send. Zero
    /// ends it as soon as nothing is waiting, which is what a server that
    /// collects a whole request before passing it on needs.
    pub linger: Duration,
    /// Ask the server to carry UDP too (the datagram lane). A server that
    /// does not know it simply does not grant it, and UDP is then refused.
    pub lane: bool,
    /// When to replace a working connection; `None` keeps one until it breaks.
    pub rotation: Option<Rotation>,
    pub tuning: Tuning,
}

/// The smallest volume limit a connection is given, however hard the network
/// has been on earlier ones.
const MIN_BYTES: u64 = 64 << 20;
/// A connection that fails before its limits multiplies the allowance by
/// `SHRINK` for the connections after it, down to `FLOOR`; one that reaches
/// its limit and is replaced on schedule multiplies it by `GROW`, up to 1.
/// The reasoning: a censor's cut looks like a dead connection, not a labelled
/// ban, so the only honest response to an early death is to be more careful
/// with both limits, and to relax slowly while things go well.
const SHRINK: f64 = 0.7;
const GROW: f64 = 1.15;
const FLOOR: f64 = 0.25;

/// How long after a failed replacement the old connection is left alone
/// before another replacement is tried. A broken network must not turn into
/// a dial every request.
const ROTATION_RETRY: Duration = Duration::from_secs(30);
/// How often an open download looks at whether its connection is due, and
/// how recently the session must have moved data for that to matter: an
/// idle session is left alone (a rotation then costs battery and shows a
/// connection opening with nothing to say).
const ROTATION_CHECK: Duration = Duration::from_secs(1);
const ROTATION_ACTIVE: Duration = Duration::from_secs(10);

/// One HTTP/2 connection, with the limits it was given.
struct Live {
    sender: SendRequest<Bytes>,
    born: Instant,
    /// Bytes the pipes on this connection have moved, both ways.
    moved: Arc<AtomicU64>,
    /// `(age, bytes)` after which it is due for replacing.
    limits: Option<(Duration, u64)>,
}

impl Live {
    fn due(&self) -> bool {
        self.limits.is_some_and(|(age, bytes)| {
            self.born.elapsed() >= age || self.moved.load(Ordering::Relaxed) >= bytes
        })
    }

    fn lease(&self, epoch: u64, time: Option<u64>) -> Lease {
        Lease {
            sender: self.sender.clone(),
            time,
            moved: self.moved.clone(),
            epoch,
        }
    }
}

/// A connection lent to one request: send on it, and count what it carried
/// against its volume limit.
pub(crate) struct Lease {
    pub(crate) sender: SendRequest<Bytes>,
    /// The server's clock, from the front page; only a new connection has it.
    time: Option<u64>,
    moved: Arc<AtomicU64>,
    /// Which connection of the carrier this is; see [`Carrier::changes`].
    pub(crate) epoch: u64,
}

impl Lease {
    fn count(&self, bytes: usize) {
        self.moved.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

struct State {
    live: Option<Live>,
    /// A replacement is being dialled; everyone else keeps using the old one.
    rotating: bool,
    hold_until: Option<Instant>,
    /// Counts connections put in `live`, so a replacement that lost a race
    /// with another one is dropped, not stacked.
    epoch: u64,
    /// What the next connection's limits are multiplied by; see [`SHRINK`].
    scale: f64,
}

impl Default for State {
    fn default() -> Self {
        Self {
            live: None,
            rotating: false,
            hold_until: None,
            epoch: 0,
            scale: 1.0,
        }
    }
}

/// One HTTP/2 connection that is redialled when it breaks, and replaced
/// before it gets old (see [`Rotation`]).
///
/// The rule: a replacement is dialled *before* the old connection is let go
/// (make before break). Requests keep using the old one until the new one
/// has fetched the front page; requests already running on the old one
/// finish there, and the connection closes by itself when the last ends. The
/// session does not notice: the server knows it by name, not by connection.
pub(crate) struct Carrier {
    dial: Dialer,
    host: String,
    rotation: Option<Rotation>,
    look: Look,
    ping: Duration,
    state: tokio::sync::Mutex<State>,
    /// The epoch of the current connection, for requests that outlive their
    /// connection's turn (a download) to see they should move.
    epoch: tokio::sync::watch::Sender<u64>,
}

impl Carrier {
    pub(crate) fn new(
        dial: Dialer,
        host: String,
        rotation: Option<Rotation>,
        tuning: &Tuning,
    ) -> Arc<Self> {
        Arc::new(Self {
            dial,
            host,
            rotation,
            look: tuning.look.clone(),
            ping: tuning.ping,
            state: tokio::sync::Mutex::new(State::default()),
            epoch: tokio::sync::watch::channel(0).0,
        })
    }

    /// Changes whenever the carrier switches to a different connection.
    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.epoch.subscribe()
    }

    /// A new connection, with the front page fetched.
    async fn connect(&self, scale: f64) -> io::Result<(Live, Option<u64>)> {
        let (io, uncork) = Cork::new((self.dial)().await?);
        let (sender, mut connection) = h2::client::Builder::new()
            .initial_window_size(H2_WINDOW)
            .initial_connection_window_size(H2_WINDOW)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(other)?;
        // The page request is queued while the connection's first bytes are
        // still held back, so the HTTP/2 preface, the settings and the
        // request leave together in one write, as a browser's do, and not as
        // a 46-byte packet followed by the request.
        let page = front_page_request(sender.clone(), &self.host, &self.look);
        uncork.store(true, Ordering::Release);
        let pings = connection.ping_pong();
        tokio::spawn(drive(connection, pings, self.ping, PING_DEADLINE));
        let time = front_page(page).await;
        let live = Live {
            sender,
            born: Instant::now(),
            moved: Arc::default(),
            limits: self.rotation.map(|rotation| rotation.draw(scale)),
        };
        Ok((live, time))
    }

    /// A connection for one request, dialling first if there is none. When
    /// the current one is due, a replacement is dialled in the background
    /// and this request still goes on the current one, so rotating never
    /// delays anything; the replacement takes over once it is ready, and if
    /// it cannot be made the current one stays. Idle sessions never get
    /// here, so they are never rotated: only a connection about to be used
    /// is replaced.
    pub(crate) async fn get(self: &Arc<Self>) -> io::Result<Lease> {
        let mut state = self.state.lock().await;
        let Some(live) = &state.live else {
            let (live, time) = self.connect(state.scale).await?;
            state.epoch += 1;
            let lease = live.lease(state.epoch, time);
            state.live = Some(live);
            self.epoch.send_replace(state.epoch);
            return Ok(lease);
        };
        let lease = live.lease(state.epoch, None);
        let held = state.hold_until.is_some_and(|until| Instant::now() < until);
        if live.due() && !state.rotating && !held {
            state.rotating = true;
            let (carrier, epoch, scale) = (Arc::clone(self), state.epoch, state.scale);
            tokio::spawn(async move {
                let fresh = carrier.connect(scale).await;
                let mut state = carrier.state.lock().await;
                state.rotating = false;
                match fresh {
                    // Only if nothing else replaced the connection meanwhile.
                    Ok((live, _)) if state.epoch == epoch => {
                        tracing::debug!("tide connection replaced");
                        state.live = Some(live);
                        state.epoch += 1;
                        state.hold_until = None;
                        state.scale = (state.scale * GROW).min(1.0);
                        carrier.epoch.send_replace(state.epoch);
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::debug!(%error, "tide connection replacement failed");
                        state.hold_until = Some(Instant::now() + ROTATION_RETRY);
                    }
                }
            });
        }
        Ok(lease)
    }

    /// Forget connection `epoch` after a failure, so the next use redials. A
    /// connection that fails before either of its limits shrinks the
    /// allowance of the next ones (see [`SHRINK`]).
    ///
    /// Several requests share a connection, so the later ones to fail must
    /// not throw away the fresh connection an earlier failure already made:
    /// when the carrier is on a newer epoch than the one that failed, nothing
    /// happens. A replacement being dialled in the background when this
    /// happens is dropped too (the epoch moves on): it was started before the
    /// failure, so by the time it is used again it may be as dead as the
    /// connection that failed, and installing it would turn one failure into
    /// several.
    pub(crate) async fn invalidate(&self, epoch: u64) {
        let mut state = self.state.lock().await;
        if state.epoch != epoch {
            return;
        }
        if let Some(live) = state.live.take() {
            if live.limits.is_some() && !live.due() {
                state.scale = (state.scale * SHRINK).max(FLOOR);
            }
        }
        state.epoch += 1;
        self.epoch.send_replace(state.epoch);
    }

    /// Let go of the connection once the session is over. Not a failure, so
    /// it does not shrink the allowance of later connections.
    async fn close(&self) {
        let mut state = self.state.lock().await;
        state.live = None;
        state.epoch += 1;
        self.epoch.send_replace(state.epoch);
    }
}

/// How often a carrier's HTTP/2 connection is pinged, and how long a PING may
/// go unanswered before the connection counts as frozen.
const PING_EVERY: Duration = Duration::from_secs(12);
const PING_DEADLINE: Duration = Duration::from_secs(8);

/// Runs an HTTP/2 connection until it ends, pinging it every `period`.
///
/// A TCP connection can freeze without closing (a middlebox stops forwarding
/// it, or loss stretches TCP's retransmit timer to minutes); every pipe on it
/// then hangs with no error. A PING not answered within `deadline` ends the
/// connection here: its requests fail at once, the pipes redial, and the
/// session carries on over a fresh connection. An idle session is closed
/// long before this matters, so the PINGs only run while it is in use.
async fn drive(
    connection: h2::client::Connection<Cork, Bytes>,
    pings: Option<h2::PingPong>,
    period: Duration,
    deadline: Duration,
) {
    let keep = async {
        let Some(mut pings) = pings else {
            return std::future::pending::<()>().await;
        };
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        loop {
            tick.tick().await;
            match tokio::time::timeout(deadline, pings.ping(h2::Ping::opaque())).await {
                Ok(Ok(_)) => {}
                // The connection is going; `connection` reports how.
                Ok(Err(_)) => return std::future::pending::<()>().await,
                Err(_) => return,
            }
        }
    };
    tokio::select! {
        result = connection => {
            if let Err(error) = result {
                tracing::debug!(%error, "tide connection ended");
            }
        }
        () = keep => tracing::debug!("tide connection stopped answering PINGs"),
    }
}

/// Holds back everything written to a new connection until released, then
/// sends it in one write with whatever is written next.
///
/// HTTP/2 libraries write the connection preface as soon as they can and the
/// first request when it comes, which on the wire is two small packets where
/// a browser sends one. Holding the preface for the moment it takes to queue
/// the first request removes that difference. Once released this passes
/// writes straight through.
struct Cork {
    inner: BoxStream,
    released: Arc<std::sync::atomic::AtomicBool>,
    held: Vec<u8>,
    written: usize,
}

impl Cork {
    fn new(inner: BoxStream) -> (Self, Arc<std::sync::atomic::AtomicBool>) {
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cork = Self {
            inner,
            released: released.clone(),
            held: Vec::new(),
            written: 0,
        };
        (cork, released)
    }

    fn is_released(&self) -> bool {
        self.released.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Write out what was held. Only called once released.
    fn poll_drain(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        use tokio::io::AsyncWrite;
        while self.written < self.held.len() {
            let n = std::task::ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.held[self.written..])
            )?;
            if n == 0 {
                return std::task::Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        if !self.held.is_empty() {
            self.held = Vec::new();
            self.written = 0;
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncRead for Cork {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Cork {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.held.is_empty() && this.is_released() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if this.written == 0 {
            // Still held, or just released: these bytes join the held ones
            // so that both leave in the same write.
            this.held.extend_from_slice(buf);
            if this.is_released() {
                if let std::task::Poll::Ready(Err(error)) = this.poll_drain(cx) {
                    return std::task::Poll::Ready(Err(error));
                }
            }
            return std::task::Poll::Ready(Ok(buf.len()));
        }
        // Part of the held bytes is already out: finish them first.
        std::task::ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.is_released() {
            return std::task::Poll::Ready(Ok(()));
        }
        std::task::ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = &mut *self;
        this.released
            .store(true, std::sync::atomic::Ordering::Release);
        std::task::ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

pub(crate) fn request(method: Method, host: &str, path: &str) -> Request<()> {
    request_as(method, host, path, &Look::default())
}

/// A request as `look` makes it. The extra headers replace any header of the
/// same name, so a link can swap `accept` as well as add `referer`.
pub(crate) fn request_as(method: Method, host: &str, path: &str, look: &Look) -> Request<()> {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"))
        .header("user-agent", look.user_agent.as_str())
        .header("accept", "*/*")
        .header("accept-language", look.language.as_str())
        .body(())
        .expect("a request built from checked parts");
    for (name, value) in &look.headers {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            request.headers_mut().insert(name, value);
        }
    }
    request
}

/// Queue a request for the site's front page, as a browser makes on a new
/// connection. Nothing is awaited: the request is only placed in the
/// connection's outgoing buffer.
fn front_page_request(
    mut sender: SendRequest<Bytes>,
    host: &str,
    look: &Look,
) -> Option<h2::client::ResponseFuture> {
    let mut page = request_as(Method::GET, host, "/", look);
    page.headers_mut().insert(
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            .parse()
            .expect("a fixed header value"),
    );
    sender
        .send_request(page, true)
        .ok()
        .map(|(response, _)| response)
}

/// Read the server's clock from the front page reply. The body is read and
/// dropped in the background.
async fn front_page(response: Option<h2::client::ResponseFuture>) -> Option<u64> {
    let response = tokio::time::timeout(Duration::from_secs(10), response?)
        .await
        .ok()?
        .ok()?;
    let time = response
        .headers()
        .get("date")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date);
    let mut body = response.into_body();
    tokio::spawn(async move {
        let mut read = 0usize;
        while let Some(Ok(data)) = body.data().await {
            let _ = body.flow_control().release_capacity(data.len());
            read += data.len();
            if read > 512 * 1024 {
                break;
            }
        }
    });
    time
}

/// A Tide client for one server: opens streams, keeping a session and its
/// connections alive underneath for as long as they are used.
pub struct Client {
    config: ClientConfig,
    down: Arc<Carrier>,
    up: Arc<Carrier>,
    live: tokio::sync::Mutex<Option<Arc<Session>>>,
}

/// Why a pipe request did not carry anything.
enum PipeError {
    /// The server does not know the session any more.
    Gone,
    /// The connection or the request failed; worth another try.
    Failed(io::Error),
}

impl From<io::Error> for PipeError {
    fn from(error: io::Error) -> Self {
        Self::Failed(error)
    }
}

impl Client {
    pub fn new(config: ClientConfig, dial: Dialer) -> Arc<Self> {
        let (host, rotation, tuning) = (&config.host, config.rotation, &config.tuning);
        let down = Carrier::new(dial.clone(), host.clone(), rotation, tuning);
        let up = if config.split {
            Carrier::new(dial, host.clone(), rotation, tuning)
        } else {
            down.clone()
        };
        Arc::new(Self {
            config,
            down,
            up,
            live: tokio::sync::Mutex::new(None),
        })
    }

    /// Open a stream to `destination` through the server.
    pub async fn open(self: &Arc<Self>, destination: Destination) -> io::Result<TideStream> {
        let mut live = self.live.lock().await;
        if let Some(session) = live.as_ref().filter(|session| !session.is_closed()) {
            if let Ok(stream) = session.open(destination.clone()) {
                return Ok(stream);
            }
        }
        let session = self.establish().await?;
        *live = Some(session.clone());
        session.open(destination)
    }

    /// Open a UDP flow through the server. Its first datagram's destination
    /// names the flow for routing; later datagrams may go anywhere.
    pub async fn open_udp(self: &Arc<Self>, first: Destination) -> io::Result<tide::UdpFlow> {
        self.open(first).await.map(tide::UdpFlow::new)
    }

    /// Start connecting now if nothing is up, without opening a stream: for a
    /// caller that knows a stream is about to be wanted.
    pub fn prewarm(self: &Arc<Self>) {
        let client = Arc::clone(self);
        tokio::spawn(async move {
            let mut live = client.live.lock().await;
            if live.as_ref().is_none_or(|session| session.is_closed()) {
                if let Ok(session) = client.establish().await {
                    *live = Some(session);
                }
            }
        });
    }

    async fn establish(self: &Arc<Self>) -> io::Result<Arc<Session>> {
        let (sender, server_time, epoch) = match self.down.get().await {
            Ok(lease) => (lease.sender, lease.time, lease.epoch),
            Err(error) => return Err(error),
        };
        let mut name = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut name);
        let base = format!("{}/{}", self.config.path, hex_name(&name));
        let (hello, handshake) = tide::client_hello_with(
            &self.config.server_public,
            &self.config.user,
            server_time.unwrap_or_else(now),
            if self.config.lane { tide::FLAG_LANE } else { 0 },
        )?;

        let opened = async {
            let mut sender = sender.ready().await.map_err(other)?;
            let open = request_as(
                Method::POST,
                &self.config.host,
                &format!("{base}/open"),
                &self.config.tuning.look,
            );
            let (response, mut body) = sender.send_request(open, false).map_err(other)?;
            // A server or proxy that answers before it has read the whole
            // request ends the stream under the writer; what it said is more
            // useful than the broken pipe, so the answer is read either way.
            let written = async {
                send_all(&mut body, Bytes::from(hello)).await?;
                body.send_data(Bytes::new(), true).map_err(other)
            }
            .await;
            let response = match response.await {
                Ok(response) => response,
                Err(error) => return Err(written.err().unwrap_or_else(|| other(error))),
            };
            if response.status().is_server_error() {
                // A proxy in front has no backend right now; not a refusal.
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "the server is not available right now",
                ));
            }
            if response.status() != StatusCode::OK {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the server did not accept the tide handshake",
                ));
            }
            let mut reply = Vec::new();
            let mut body = response.into_body();
            while let Some(data) = body.data().await {
                let data = data.map_err(other)?;
                let _ = body.flow_control().release_capacity(data.len());
                reply.extend_from_slice(&data);
                if reply.len() > HANDSHAKE_MAX {
                    return Err(other("tide handshake reply is too large"));
                }
            }
            handshake.finish(&reply)
        };
        let session = match tokio::time::timeout(Duration::from_secs(15), opened).await {
            Ok(Ok(session)) => session,
            Ok(Err(error)) => {
                self.down.invalidate(epoch).await;
                return Err(error);
            }
            Err(_) => {
                self.down.invalidate(epoch).await;
                return Err(io::ErrorKind::TimedOut.into());
            }
        };

        tokio::spawn(session.clone().run_timers());
        tokio::spawn(download(
            session.clone(),
            self.down.clone(),
            self.config.host.clone(),
            base.clone(),
            self.config.tuning.down_pipes,
        ));
        tokio::spawn(upload(
            session.clone(),
            self.up.clone(),
            self.config.clone(),
            base,
        ));
        tokio::spawn(close_when_idle(
            session.clone(),
            self.down.clone(),
            self.up.clone(),
            self.config.tuning.idle,
        ));
        Ok(session)
    }
}

fn hex_name(name: &[u8; 16]) -> String {
    name.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn close_when_idle(
    session: Arc<Session>,
    down: Arc<Carrier>,
    up: Arc<Carrier>,
    idle: Duration,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        if session.is_closed() {
            break;
        }
        if session.streams() == 0 && session.idle_for() > idle {
            session.close();
            break;
        }
    }
    // Dropping the handles lets the HTTP/2 connections close.
    down.close().await;
    up.close().await;
}

/// Wait a little longer after each failure in a row.
async fn back_off(failures: u32) {
    let wait = 200u64.saturating_mul(1 << failures.min(4));
    tokio::time::sleep(Duration::from_millis(wait)).await;
}

/// Download requests kept open at once. The server ends each after 8 to 16
/// MB, and a request opened only then leaves the session with no way to send
/// to the client for a round trip. With two open, the one that is left
/// carries on while its replacement is made. They also share the load: the
/// server hands each chunk to whichever pipe is ready, and the receiver puts
/// the chunks back in order.
const DOWNLOAD_PIPES: usize = 2;

/// Keep download requests open for as long as the session lives.
async fn download(
    session: Arc<Session>,
    carrier: Arc<Carrier>,
    host: String,
    base: String,
    pipes: usize,
) {
    let numbers = Arc::new(AtomicU64::new(0));
    let failures = Arc::new(AtomicU32::new(0));
    let mut slots = Vec::new();
    for index in 0..pipes {
        let (session, carrier, host, base) =
            (session.clone(), carrier.clone(), host.clone(), base.clone());
        let (numbers, failures) = (numbers.clone(), failures.clone());
        slots.push(tokio::spawn(async move {
            if index > 0 {
                // Staggered, so the pipes do not all reach their end together.
                let wait = rand::thread_rng().gen_range(300..1500);
                tokio::time::sleep(Duration::from_millis(wait)).await;
            }
            download_slot(session, carrier, host, base, numbers, failures, pipes).await;
        }));
    }
    for slot in slots {
        let _ = slot.await;
    }
    session.close();
}

/// One of the download requests: opens a request, reads it to its end, and
/// opens the next.
async fn download_slot(
    session: Arc<Session>,
    carrier: Arc<Carrier>,
    host: String,
    base: String,
    numbers: Arc<AtomicU64>,
    failures: Arc<AtomicU32>,
    pipes: usize,
) {
    use Ordering::Relaxed;
    while !session.is_closed() {
        let mut epoch = 0;
        match download_once(
            &session, &carrier, &host, &base, &numbers, &failures, &mut epoch,
        )
        .await
        {
            Ok(()) => failures.store(0, Relaxed),
            Err(PipeError::Gone) => {
                tracing::debug!("tide download: the server no longer knows the session");
                break;
            }
            Err(PipeError::Failed(error)) => {
                tracing::debug!(%error, "tide download pipe failed");
                carrier.invalidate(epoch).await;
                let total = failures.fetch_add(1, Relaxed) + 1;
                if total > MAX_FAILURES * pipes as u32 {
                    break;
                }
                back_off(total.div_ceil(pipes as u32)).await;
            }
        }
    }
    session.close();
}

/// A download request that is open.
struct Down {
    body: h2::RecvStream,
    parser: ChunkParser,
    lease: Lease,
}

/// Start the next download request, numbered from `numbers`, which every
/// download slot of the session draws from. `epoch` is set to the connection
/// it was made on, so a failure can name the connection it blames.
async fn open_download(
    session: &Session,
    carrier: &Arc<Carrier>,
    host: &str,
    base: &str,
    numbers: &AtomicU64,
    epoch: &mut u64,
) -> Result<Down, PipeError> {
    let number = numbers.fetch_add(1, Ordering::Relaxed) + 1;
    let path = format!(
        "{base}/d/{number}?t={}",
        pipe_tag(session.binding(), b'd', number)
    );
    let lease = carrier.get().await?;
    *epoch = lease.epoch;
    let mut sender = lease.sender.clone().ready().await.map_err(other)?;
    let (response, _) = sender
        .send_request(request_as(Method::GET, host, &path, &carrier.look), true)
        .map_err(other)?;
    let response = response.await.map_err(other)?;
    match response.status() {
        StatusCode::OK => {}
        // The server does not know the session (or answers as the decoy
        // does): it is gone. Any other status is a proxy in the way having
        // a bad moment (a relay whose egress is down says 502), which a
        // retry may get past.
        StatusCode::NOT_FOUND => return Err(PipeError::Gone),
        status => {
            return Err(PipeError::Failed(other(format!(
                "download answered {status}"
            ))))
        }
    }
    Ok(Down {
        body: response.into_body(),
        parser: ChunkParser::default(),
        lease,
    })
}

/// Read one download request to its end.
///
/// The rule: when the carrier moves to a new connection, the next request
/// is opened on it *before* this one is dropped. Dropping resets the old
/// request, so what it was carrying and the peer had not yet acknowledged
/// goes out again on the new one; the session never sees a gap. Without
/// this, a download would sit on its old connection until the server ended
/// it (up to 16 MiB or 45 quiet seconds later) and the rotation would not
/// reach the direction that carries the bytes.
async fn download_once(
    session: &Session,
    carrier: &Arc<Carrier>,
    host: &str,
    base: &str,
    numbers: &AtomicU64,
    failures: &AtomicU32,
    epoch: &mut u64,
) -> Result<(), PipeError> {
    let mut pipe = open_download(session, carrier, host, base, numbers, epoch).await?;
    // The server answered for this session, so it is alive: only failures to
    // get an answer count towards giving up. A download is cut and reopened
    // many times in a long session, and without this every cut, however
    // well recovered, would add up until the session was dropped.
    failures.store(0, Ordering::Relaxed);
    let mut changes = carrier.changes();
    let mut seen = pipe.lease.epoch;
    let mut check = tokio::time::interval(ROTATION_CHECK);
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            // Only a request being made starts a rotation, and this one is
            // the longest-lived, so it asks.
            _ = check.tick(), if carrier.rotation.is_some() && session.idle_for() < ROTATION_ACTIVE => {
                carrier.get().await?;
            }
            data = pipe.body.data() => {
                let Some(data) = data else { return Ok(()) };
                let data = data.map_err(other)?;
                session.receive(&mut pipe.parser, &data)?;
                pipe.lease.count(data.len());
                let _ = pipe.body.flow_control().release_capacity(data.len());
            }
            Ok(latest) = async { changes.wait_for(|epoch| *epoch != seen).await.map(|e| *e) } => {
                seen = latest;
                let mut next_epoch = 0;
                if let Ok(next) = open_download(session, carrier, host, base, numbers, &mut next_epoch).await {
                    seen = next_epoch;
                    *epoch = next_epoch;
                    pipe = next;
                    failures.store(0, Ordering::Relaxed);
                }
            }
        }
    }
}

/// Upload requests that may wait for their answer at once. HTTP/2 lets the
/// next request go out while the last one's reply is still on its way; waiting
/// for it left the link idle for a round trip after every request.
const UPLOADS_IN_FLIGHT: usize = 3;

/// Send what the session has to send, in upload requests that overlap: the
/// next starts as soon as the previous body is closed, and the answers are
/// collected in the background. An answer that says the chunks did not get
/// there (or never comes) hands them back to the session to send again.
async fn upload(session: Arc<Session>, carrier: Arc<Carrier>, config: ClientConfig, base: String) {
    let mut number = 0u64;
    let failures = Arc::new(AtomicU32::new(0));
    let up_pipes = config.tuning.up_pipes;
    let slots = Arc::new(tokio::sync::Semaphore::new(up_pipes));
    loop {
        // Wait for room, then for something to send, before making a request.
        let Ok(slot) = slots.clone().acquire_owned().await else {
            break;
        };
        let Ok(first) = session.next_chunk(number + 1, CHUNK_PLAIN_MAX).await else {
            break;
        };
        number += 1;
        session.pipe_opened(number);
        let path = format!(
            "{base}/u/{number}?t={}",
            pipe_tag(session.binding(), b'u', number)
        );
        let mut epoch = 0;
        match upload_send(
            &session, &carrier, &config, &path, number, first, &mut epoch,
        )
        .await
        {
            Ok(pending) => {
                let (session, carrier, failures) =
                    (session.clone(), carrier.clone(), failures.clone());
                tokio::spawn(async move {
                    let _slot = slot;
                    match upload_answer(pending).await {
                        Ok(()) => {
                            session.pipe_closed(number, true);
                            failures.store(0, Ordering::Relaxed);
                        }
                        Err(PipeError::Gone) => {
                            tracing::debug!("tide upload: the server no longer knows the session");
                            session.pipe_closed(number, false);
                            session.close();
                        }
                        Err(PipeError::Failed(error)) => {
                            tracing::debug!(%error, "tide upload pipe failed");
                            session.pipe_closed(number, false);
                            carrier.invalidate(epoch).await;
                            let total = failures.fetch_add(1, Ordering::Relaxed) + 1;
                            if total > MAX_FAILURES * up_pipes as u32 {
                                session.close();
                            }
                        }
                    }
                });
            }
            Err(PipeError::Gone) => {
                tracing::debug!("tide upload: the server no longer knows the session");
                session.pipe_closed(number, false);
                break;
            }
            Err(PipeError::Failed(error)) => {
                tracing::debug!(%error, "tide upload pipe failed");
                session.pipe_closed(number, false);
                carrier.invalidate(epoch).await;
                let total = failures.fetch_add(1, Ordering::Relaxed) + 1;
                if total > MAX_FAILURES {
                    break;
                }
                back_off(total).await;
            }
        }
    }
    session.close();
}

/// Open one upload request and write chunks into it until it has carried
/// enough (a different amount each time, so no size repeats), or nothing more
/// is waiting. Returns the pending answer without waiting for it.
async fn upload_send(
    session: &Session,
    carrier: &Arc<Carrier>,
    config: &ClientConfig,
    path: &str,
    number: u64,
    first: Bytes,
    epoch: &mut u64,
) -> Result<Pending, PipeError> {
    let lease = carrier.get().await?;
    *epoch = lease.epoch;
    let mut sender = lease.sender.clone().ready().await.map_err(other)?;
    let mut post = request_as(Method::POST, &config.host, path, &config.tuning.look);
    post.headers_mut().insert(
        "content-type",
        "application/octet-stream"
            .parse()
            .expect("a fixed header value"),
    );
    let (response, mut body) = sender.send_request(post, false).map_err(other)?;
    let limit = rand::thread_rng().gen_range(256 * 1024..1024 * 1024);
    let mut sent = first.len();
    lease.count(sent);
    // As in the handshake: if the far end answers before the body is done
    // (a 404 for a session it has forgotten), that answer decides what
    // happens next, not the broken pipe it caused.
    let written = async {
        send_all(&mut body, first).await?;
        while sent < limit {
            let next = if config.linger.is_zero() {
                session.try_next_chunk(number, CHUNK_PLAIN_MAX)
            } else {
                match tokio::time::timeout(
                    config.linger,
                    session.next_chunk(number, CHUNK_PLAIN_MAX),
                )
                .await
                {
                    Ok(Ok(chunk)) => Some(chunk),
                    Ok(Err(_)) | Err(_) => None,
                }
            };
            let Some(chunk) = next else { break };
            sent += chunk.len();
            lease.count(chunk.len());
            send_all(&mut body, chunk).await?;
        }
        body.send_data(Bytes::new(), true).map_err(other)
    }
    .await;
    Ok(Pending { response, written })
}

/// An upload request whose body is closed and whose answer is still to come.
struct Pending {
    response: h2::client::ResponseFuture,
    /// How writing the body went. The answer is read first, because a 404
    /// for a session the server has forgotten matters more than the broken
    /// pipe it caused.
    written: Result<(), io::Error>,
}

/// The server's answer to an upload request.
async fn upload_answer(pending: Pending) -> Result<(), PipeError> {
    let Pending { response, written } = pending;
    let response = match response.await {
        Ok(response) => response,
        Err(error) => return Err(written.err().unwrap_or_else(|| other(error)).into()),
    };
    if response.status() == StatusCode::NOT_FOUND {
        return Err(PipeError::Gone);
    }
    written?;
    match response.status() {
        StatusCode::OK => Ok(()),
        StatusCode::NOT_FOUND => Err(PipeError::Gone),
        status => Err(PipeError::Failed(other(format!(
            "upload answered {status}"
        )))),
    }
}

// -------------------------------------------------------------------- server

/// What a visitor who is not a Tide client is shown.
#[derive(Clone)]
pub struct Decoy {
    pub page: Bytes,
}

impl Default for Decoy {
    fn default() -> Self {
        Self {
            page: Bytes::from_static(
                b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Welcome</title></head><body><h1>It works</h1><p>This site is being set up. Please check back later.</p></body></html>\n",
            ),
        }
    }
}

/// What a control panel answers a request with.
pub struct AdminReply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// Where to send the browser instead, for a redirect.
    pub location: Option<String>,
}

impl AdminReply {
    pub fn html(page: String) -> Self {
        Self {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: page.into_bytes(),
            location: None,
        }
    }

    pub fn see_other(location: &str) -> Self {
        Self {
            status: 303,
            content_type: "text/plain",
            body: Vec::new(),
            location: Some(location.to_string()),
        }
    }

    pub fn not_found() -> Self {
        Self {
            status: 404,
            content_type: "text/plain",
            body: b"not found\n".to_vec(),
            location: None,
        }
    }
}

/// Answers a panel request: method, what follows the panel's path, body.
pub type AdminHandler = dyn Fn(&str, &str, &[u8]) -> AdminReply + Send + Sync;

/// A control panel served under a secret path of the same server. The
/// handler gets the method, what follows the path, and the request body.
#[derive(Clone)]
pub struct Admin {
    pub path: String,
    pub handler: Arc<AdminHandler>,
}

/// The most a panel request body may be.
const ADMIN_BODY_MAX: usize = 64 * 1024;

pub struct ServerConfig {
    /// The path prefix Tide requests live under.
    pub path: String,
    /// A control panel, if the operator wants one.
    pub admin: Option<Admin>,
    pub secret: [u8; 32],
    /// Who may connect, by id, with a name for the operator's eyes. Shared so
    /// a control panel can change it while the server runs.
    pub users: Arc<RwLock<HashMap<UserId, String>>>,
    pub decoy: Decoy,
    /// How far the server pads its answers to an upload (see
    /// [`tide::ShapeLevel`]).
    pub shape: tide::ShapeLevel,
}

/// A stream a client opened: who it is, where it wants to go, and the stream.
pub type Incoming = (UserId, Destination, TideStream);

struct Known {
    session: Arc<Session>,
    user: UserId,
}

/// The server side of Tide. Feed it connections; it hands back streams.
pub struct Server {
    config: ServerConfig,
    sessions: Mutex<HashMap<String, Known>>,
    replay: ReplayGuard,
    incoming: tokio::sync::mpsc::Sender<Incoming>,
    /// What each request looked like on arrival, so a test can check what the
    /// client put on the wire.
    #[cfg(test)]
    seen: Mutex<Vec<(String, String, http::HeaderMap)>>,
}

impl Server {
    pub fn new(config: ServerConfig) -> (Arc<Self>, tokio::sync::mpsc::Receiver<Incoming>) {
        let (incoming, streams) = tokio::sync::mpsc::channel(256);
        (
            Arc::new(Self {
                config,
                sessions: Mutex::new(HashMap::new()),
                replay: ReplayGuard::default(),
                incoming,
                #[cfg(test)]
                seen: Mutex::default(),
            }),
            streams,
        )
    }

    /// Sessions alive now, per user, for an operator's view.
    pub fn sessions_by_user(&self) -> HashMap<UserId, usize> {
        let sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        let mut counts = HashMap::new();
        for known in sessions.values() {
            *counts.entry(known.user).or_insert(0) += 1;
        }
        counts
    }

    /// Serve one connection (TLS already done, if any) until it closes. A
    /// connection starting with the HTTP/2 preface is served as HTTP/2;
    /// anything else as HTTP/1.1, for a proxy that cannot speak HTTP/2 to
    /// its origin (see [`crate::tide_http1`]).
    pub async fn serve_connection(self: &Arc<Self>, mut io: BoxStream) -> io::Result<()> {
        let mut first = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut io, &mut first).await?;
        let io = crate::tide_http1::Prefixed::new(&first, io);
        if &first == b"PRI " {
            self.serve_h2(zero_core::boxed(io)).await
        } else {
            crate::tide_http1::serve(self, io).await
        }
    }

    pub(crate) async fn serve_h2(self: &Arc<Self>, io: BoxStream) -> io::Result<()> {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(H2_WINDOW)
            .initial_connection_window_size(H2_WINDOW)
            .max_concurrent_streams(256)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(other)?;
        while let Some(accepted) = connection.accept().await {
            let (request, respond) = accepted.map_err(other)?;
            #[cfg(test)]
            self.seen.lock().unwrap().push((
                request
                    .uri()
                    .authority()
                    .map_or_else(String::new, |a| a.to_string()),
                request.uri().path().to_string(),
                request.headers().clone(),
            ));
            let server = Arc::clone(self);
            tokio::spawn(async move {
                if let Err(error) = server.handle(request, respond).await {
                    tracing::debug!(%error, "tide request ended with an error");
                }
            });
        }
        Ok(())
    }

    fn session(&self, name: &str) -> Option<Arc<Session>> {
        let sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        sessions
            .get(name)
            .filter(|known| !known.session.is_closed())
            .map(|known| Arc::clone(&known.session))
    }

    async fn handle(
        self: &Arc<Self>,
        request: Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
    ) -> io::Result<()> {
        let path = request.uri().path().to_string();
        let query = request.uri().query().unwrap_or("").to_string();
        let method = request.method().clone();
        if let Some(admin) = &self.config.admin {
            let inside = path
                .strip_prefix(admin.path.as_str())
                .filter(|rest| rest.is_empty() || rest.starts_with('/'));
            if let Some(rest) = inside {
                return self.panel(admin, &method, rest, request, respond).await;
            }
        }
        let route = path
            .strip_prefix(self.config.path.as_str())
            .and_then(|rest| rest.strip_prefix('/'))
            .and_then(|rest| rest.split_once('/'))
            .filter(|(name, _)| name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit()));
        let Some((name, action)) = route else {
            return self.decoy(&method, &path, respond).await;
        };
        let tag = query.strip_prefix("t=").unwrap_or("");
        let pipe = |direction: u8, text: &str| -> Option<(Arc<Session>, u64)> {
            let number: u64 = text.parse().ok()?;
            let session = self.session(name)?;
            // Compared in full; the tag is not a secret worth timing attacks.
            (pipe_tag(session.binding(), direction, number) == tag).then_some((session, number))
        };

        if method == Method::POST && action == "open" {
            let mut body = request.into_body();
            let mut hello = Vec::new();
            while let Some(data) = body.data().await {
                let data = data.map_err(other)?;
                let _ = body.flow_control().release_capacity(data.len());
                hello.extend_from_slice(&data);
                if hello.len() > HANDSHAKE_MAX {
                    return self.decoy(&method, &path, respond).await;
                }
            }
            let Some((reply, session, user)) = self.admit(&hello) else {
                return self.decoy(&method, &path, respond).await;
            };
            self.remember(name, session, user);
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("date", http_date(now()))
                .header("content-type", "application/octet-stream")
                .header("cache-control", "no-store")
                .body(())
                .expect("a fixed response");
            let mut body = respond.send_response(response, false).map_err(other)?;
            send_all(&mut body, Bytes::from(reply)).await?;
            body.send_data(Bytes::new(), true).map_err(other)?;
            return Ok(());
        }

        if let Some(number) = action.strip_prefix("u/").filter(|_| method == Method::POST) {
            let Some((session, _)) = pipe(b'u', number) else {
                return self.decoy(&method, &path, respond).await;
            };
            let mut body = request.into_body();
            let mut parser = ChunkParser::default();
            let mut failed = false;
            while let Some(data) = body.data().await {
                let Ok(data) = data else {
                    failed = true;
                    break;
                };
                if session.receive(&mut parser, &data).is_err() {
                    failed = true;
                    break;
                }
                let _ = body.flow_control().release_capacity(data.len());
            }
            let status = if failed {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::OK
            };
            let response = Response::builder()
                .status(status)
                .header("date", http_date(now()))
                .header("content-length", "0")
                .body(())
                .expect("a fixed response");
            respond.send_response(response, true).map_err(other)?;
            return Ok(());
        }

        if let Some(number) = action.strip_prefix("d/").filter(|_| method == Method::GET) {
            let Some((session, number)) = pipe(b'd', number) else {
                return self.decoy(&method, &path, respond).await;
            };
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("date", http_date(now()))
                .header("content-type", "application/octet-stream")
                .header("cache-control", "no-store")
                // Asks a proxy in front not to collect the reply before
                // passing it on.
                .header("x-accel-buffering", "no")
                .body(())
                .expect("a fixed response");
            let mut body = respond.send_response(response, false).map_err(other)?;
            // Download pipes are numbered apart from upload ones on the wire,
            // but the session needs one number space for the pipes it sends
            // on, and here the server only ever sends on download pipes.
            session.pipe_opened(number);
            let limit = rand::thread_rng().gen_range(8 * 1024 * 1024..16 * 1024 * 1024);
            let mut sent = 0usize;
            let delivered = loop {
                if sent >= limit {
                    break true;
                }
                let chunk =
                    tokio::time::timeout(DOWN_IDLE, session.next_chunk(number, CHUNK_PLAIN_MAX))
                        .await;
                let Ok(Ok(chunk)) = chunk else { break true };
                sent += chunk.len();
                if send_all(&mut body, chunk).await.is_err() {
                    break false;
                }
            };
            session.pipe_closed(number, delivered);
            let _ = body.send_data(Bytes::new(), true);
            return Ok(());
        }

        self.decoy(&method, &path, respond).await
    }

    /// Answer a request for the control panel.
    async fn panel(
        &self,
        admin: &Admin,
        method: &Method,
        rest: &str,
        request: Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
    ) -> io::Result<()> {
        // The bare path redirects to the one with a slash, so the page's
        // relative form targets resolve under it.
        let reply = if rest.is_empty() {
            AdminReply::see_other(&format!("{}/", admin.path))
        } else {
            let mut body = request.into_body();
            let mut read = Vec::new();
            while let Some(data) = body.data().await {
                let data = data.map_err(other)?;
                let _ = body.flow_control().release_capacity(data.len());
                read.extend_from_slice(&data);
                if read.len() > ADMIN_BODY_MAX {
                    break;
                }
            }
            (admin.handler)(method.as_str(), &rest[1..], &read)
        };
        let mut response = Response::builder()
            .status(reply.status)
            .header("date", http_date(now()))
            .header("content-type", reply.content_type)
            .header("content-length", reply.body.len().to_string())
            .header("cache-control", "no-store")
            // The address is the secret: never pass it on, never index it.
            .header("referrer-policy", "no-referrer")
            .header("x-robots-tag", "noindex")
            .header("x-frame-options", "DENY");
        if let Some(location) = &reply.location {
            response = response.header("location", location);
        }
        let response = response.body(()).map_err(other)?;
        let mut body = respond.send_response(response, false).map_err(other)?;
        send_all(&mut body, Bytes::from(reply.body)).await?;
        body.send_data(Bytes::new(), true).map_err(other)?;
        Ok(())
    }

    /// Check a handshake and, if it is good, start a session for it.
    fn admit(self: &Arc<Self>, hello: &[u8]) -> Option<(Vec<u8>, Arc<Session>, UserId)> {
        let offer = tide::server_read(&self.config.secret, hello).ok()?;
        let user = offer.user;
        let known = self
            .config
            .users
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&user);
        if !known || !self.replay.admit(&offer, now()) {
            return None;
        }
        let (reply, session) = offer.accept().ok()?;
        session.shape(self.config.shape);
        tokio::spawn(session.clone().run_timers());
        let accept = {
            let (session, incoming) = (session.clone(), self.incoming.clone());
            async move {
                while let Ok((destination, stream)) = session.accept().await {
                    if incoming.send((user, destination, stream)).await.is_err() {
                        break;
                    }
                }
                session.close();
            }
        };
        tokio::spawn(accept);
        Some((reply, session, user))
    }

    fn remember(&self, name: &str, session: Arc<Session>, user: UserId) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        sessions.retain(|_, known| {
            let dead = known.session.is_closed()
                || (known.session.streams() == 0 && known.session.idle_for() > SESSION_FORGET);
            if dead {
                known.session.close();
            }
            !dead
        });
        sessions.insert(name.to_string(), Known { session, user });
    }

    /// Answer as the site would: the page for `/`, not found for the rest.
    async fn decoy(
        &self,
        method: &Method,
        path: &str,
        respond: h2::server::SendResponse<Bytes>,
    ) -> io::Result<()> {
        answer_decoy(&self.config.decoy.page, method, path, respond).await
    }
}

/// Answer as the site would: `page` for `/`, not found for the rest. Shared
/// by the server and the relay, so both look the same from outside.
/// What an ordinary reverse proxy shows when its backend is down: a 502 with
/// the usual short page. Tide clients retry on it; they give a session up
/// only on the 404 an egress gives for a session it does not know.
pub(crate) async fn answer_bad_gateway(
    mut respond: h2::server::SendResponse<Bytes>,
) -> io::Result<()> {
    let page = Bytes::from_static(b"<html><head><title>502 Bad Gateway</title></head><body><center><h1>502 Bad Gateway</h1></center></body></html>\n");
    let response = Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("date", http_date(now()))
        .header("content-type", "text/html; charset=utf-8")
        .header("content-length", page.len().to_string())
        .body(())
        .expect("a fixed response");
    let mut body = respond.send_response(response, false).map_err(other)?;
    send_all(&mut body, page).await?;
    body.send_data(Bytes::new(), true).map_err(other)?;
    Ok(())
}

pub(crate) async fn answer_decoy(
    page: &Bytes,
    method: &Method,
    path: &str,
    mut respond: h2::server::SendResponse<Bytes>,
) -> io::Result<()> {
    let front =
        matches!(path, "/" | "/index.html") && (method == Method::GET || method == Method::HEAD);
    let page = if front {
        page.clone()
    } else {
        Bytes::from_static(b"<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center></body></html>\n")
    };
    let response = Response::builder()
        .status(if front {
            StatusCode::OK
        } else {
            StatusCode::NOT_FOUND
        })
        .header("date", http_date(now()))
        .header("content-type", "text/html; charset=utf-8")
        .header("content-length", page.len().to_string())
        .body(())
        .expect("a fixed response");
    if method == Method::HEAD {
        respond.send_response(response, true).map_err(other)?;
        return Ok(());
    }
    let mut body = respond.send_response(response, false).map_err(other)?;
    send_all(&mut body, page).await?;
    body.send_data(Bytes::new(), true).map_err(other)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zero_core::{boxed, Address};

    #[test]
    fn http_dates_round_trip_and_match_a_known_one() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_791_381_909), "Wed, 07 Oct 2026 14:05:09 GMT");
        // A leap day, checked against `date -u`.
        assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
        for time in [0, 951_782_400, 1_709_251_199, 1_791_381_909, 4_102_444_800] {
            assert_eq!(parse_http_date(&http_date(time)), Some(time), "{time}");
        }
        assert_eq!(parse_http_date("yesterday"), None);
    }

    /// A connection that freezes without closing is found by its unanswered
    /// PING and ended, so the requests on it fail now instead of hanging.
    #[tokio::test]
    async fn a_connection_that_stops_answering_pings_is_ended() {
        use std::sync::atomic::AtomicBool;
        let (client, relay_near) = tokio::io::duplex(64 * 1024);
        let (relay_far, server) = tokio::io::duplex(64 * 1024);
        let frozen = Arc::new(AtomicBool::new(false));
        // A relay between the two that can stop forwarding while staying open.
        let pipe = |mut from: tokio::io::ReadHalf<tokio::io::DuplexStream>,
                    mut to: tokio::io::WriteHalf<tokio::io::DuplexStream>,
                    frozen: Arc<AtomicBool>| async move {
            let mut buffer = vec![0u8; 16 * 1024];
            while let Ok(n @ 1..) = from.read(&mut buffer).await {
                if frozen.load(Ordering::SeqCst) {
                    std::future::pending::<()>().await;
                }
                if to.write_all(&buffer[..n]).await.is_err() {
                    break;
                }
            }
        };
        let (near_read, near_write) = tokio::io::split(relay_near);
        let (far_read, far_write) = tokio::io::split(relay_far);
        tokio::spawn(pipe(near_read, far_write, Arc::clone(&frozen)));
        tokio::spawn(pipe(far_read, near_write, Arc::clone(&frozen)));
        tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            while connection.accept().await.is_some() {}
        });
        let (io, uncork) = Cork::new(boxed(client));
        uncork.store(true, Ordering::Release);
        let (_sender, mut connection) = h2::client::Builder::new()
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let pings = connection.ping_pong();
        let driver = tokio::spawn(drive(
            connection,
            pings,
            Duration::from_millis(100),
            Duration::from_millis(300),
        ));

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!driver.is_finished(), "answered PINGs keep it open");
        frozen.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(3), driver)
            .await
            .expect("a frozen connection was never ended")
            .unwrap();
    }

    struct Bench {
        client: Arc<Client>,
        dials: Arc<AtomicUsize>,
        /// Cut every connection made so far.
        cut: Arc<tokio::sync::Notify>,
        /// While set, new dials wait; while `refuse` is set they fail.
        hold: Arc<std::sync::atomic::AtomicBool>,
        refuse: Arc<std::sync::atomic::AtomicBool>,
        /// Connections the server has seen end.
        ended: Arc<AtomicUsize>,
        /// The server, for the requests it has seen.
        server: Arc<Server>,
    }

    /// A server answering every stream as an echo, and a client wired to it
    /// through in-memory connections.
    fn bench(split: bool, linger: Duration, known_user: bool) -> Bench {
        bench_full(split, linger, known_user, Duration::ZERO, None)
    }

    /// Two connected ends with `one_way` of delay each way and no limit on
    /// bandwidth, like a long fat path: a copy task per direction stamps each
    /// read with the time it may be written, so delays overlap instead of
    /// adding up.
    fn delayed_pair(one_way: Duration) -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        // No delay: no relay either, so that dropping one end is seen at once
        // by the other, which the connection-cut tests rely on.
        if one_way.is_zero() {
            return tokio::io::duplex(256 * 1024);
        }
        let (client, relay_near) = tokio::io::duplex(1024 * 1024);
        let (relay_far, server) = tokio::io::duplex(1024 * 1024);
        fn carry(
            mut from: tokio::io::ReadHalf<tokio::io::DuplexStream>,
            mut to: tokio::io::WriteHalf<tokio::io::DuplexStream>,
            one_way: Duration,
        ) {
            let (send, mut receive) =
                tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 64 * 1024];
                while let Ok(n @ 1..) = from.read(&mut buffer).await {
                    let due = tokio::time::Instant::now() + one_way;
                    if send.send((due, buffer[..n].to_vec())).is_err() {
                        break;
                    }
                }
            });
            tokio::spawn(async move {
                while let Some((due, data)) = receive.recv().await {
                    tokio::time::sleep_until(due).await;
                    if to.write_all(&data).await.is_err() {
                        break;
                    }
                }
            });
        }
        let (near_read, near_write) = tokio::io::split(relay_near);
        let (far_read, far_write) = tokio::io::split(relay_far);
        carry(near_read, far_write, one_way);
        carry(far_read, near_write, one_way);
        (client, server)
    }

    fn bench_with_delay(
        split: bool,
        linger: Duration,
        known_user: bool,
        one_way: Duration,
    ) -> Bench {
        bench_full(split, linger, known_user, one_way, None)
    }

    fn bench_rotating(
        split: bool,
        linger: Duration,
        known_user: bool,
        rotation: Option<Rotation>,
    ) -> Bench {
        bench_full(split, linger, known_user, Duration::ZERO, rotation)
    }

    fn bench_full(
        split: bool,
        linger: Duration,
        known_user: bool,
        one_way: Duration,
        rotation: Option<Rotation>,
    ) -> Bench {
        bench_core(
            split,
            linger,
            known_user,
            one_way,
            rotation,
            "example.test",
            Tuning::default(),
        )
    }

    fn bench_core(
        split: bool,
        linger: Duration,
        known_user: bool,
        one_way: Duration,
        rotation: Option<Rotation>,
        host: &str,
        tuning: Tuning,
    ) -> Bench {
        let (secret, public) = tide::generate_keypair();
        let user = [9u8; 16];
        let users = Arc::new(RwLock::new(HashMap::new()));
        if known_user {
            users.write().unwrap().insert(user, "test".to_string());
        }
        let (server, mut streams) = Server::new(ServerConfig {
            path: "/static/app".into(),
            admin: None,
            secret,
            users,
            decoy: Decoy::default(),
            shape: tide::ShapeLevel::default(),
        });
        let observed = server.clone();
        tokio::spawn(async move {
            while let Some((_, destination, mut stream)) = streams.recv().await {
                if destination.network == zero_core::Network::Udp {
                    tokio::spawn(async move {
                        let flow = tide::UdpFlow::new(stream);
                        while let Ok((from, payload)) = flow.recv().await {
                            if flow.send(&from, &payload).is_err() {
                                break;
                            }
                        }
                    });
                    continue;
                }
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 16 * 1024];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&buffer[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        let dials = Arc::new(AtomicUsize::new(0));
        let cut = Arc::new(tokio::sync::Notify::new());
        let hold = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let refuse = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ended = Arc::new(AtomicUsize::new(0));
        let dial: Dialer = {
            let (dials, cut, ended) = (dials.clone(), cut.clone(), ended.clone());
            let (hold, refuse) = (hold.clone(), refuse.clone());
            Arc::new(move || {
                let (server, dials, cut) = (server.clone(), dials.clone(), cut.clone());
                let (hold, refuse, ended) = (hold.clone(), refuse.clone(), ended.clone());
                Box::pin(async move {
                    dials.fetch_add(1, Ordering::SeqCst);
                    while hold.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    if refuse.load(Ordering::SeqCst) {
                        return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                    }
                    let (near, far) = delayed_pair(one_way);
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = server.serve_connection(boxed(far)) => {}
                            () = cut.notified() => {}
                        }
                        ended.fetch_add(1, Ordering::SeqCst);
                    });
                    Ok(boxed(near))
                })
            })
        };
        let client = Client::new(
            ClientConfig {
                host: host.into(),
                path: "/static/app".into(),
                server_public: public,
                user,
                split,
                linger,
                lane: true,
                rotation,
                tuning,
            },
            dial,
        );
        Bench {
            client,
            dials,
            cut,
            hold,
            refuse,
            ended,
            server: observed,
        }
    }

    fn target() -> Destination {
        Destination::tcp(Address::domain("example.com"), 443)
    }

    fn pattern(length: usize) -> Vec<u8> {
        (0..length).map(|i| (i % 251) as u8).collect()
    }

    async fn round_trip(stream: &mut TideStream, payload: &[u8]) {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let send = async {
            writer.write_all(payload).await.unwrap();
            writer.flush().await.unwrap();
        };
        let receive = async {
            let mut got = vec![0u8; payload.len()];
            reader.read_exact(&mut got).await.unwrap();
            got
        };
        let ((), got) = tokio::join!(send, receive);
        assert!(got == payload, "payload came back altered");
    }

    #[tokio::test]
    async fn streams_round_trip_over_split_connections() {
        let bench = bench(true, Duration::from_millis(200), true);
        let mut first = bench.client.open(target()).await.unwrap();
        round_trip(&mut first, b"hello").await;
        round_trip(&mut first, &pattern(700_000)).await;
        let mut second = bench.client.open(target()).await.unwrap();
        round_trip(&mut second, &pattern(50_000)).await;
        // One connection each way, and the second stream reused both.
        assert_eq!(bench.dials.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn one_connection_carries_both_directions_when_not_split() {
        let bench = bench(false, Duration::ZERO, true);
        let mut stream = bench.client.open(target()).await.unwrap();
        round_trip(&mut stream, &pattern(200_000)).await;
        assert_eq!(bench.dials.load(Ordering::SeqCst), 1);
    }

    /// Both connections are cut in the middle of a transfer. The session
    /// reconnects and the stream carries on with nothing lost.
    #[tokio::test]
    async fn a_stream_survives_its_connections_being_cut() {
        let bench = bench(true, Duration::from_millis(200), true);
        let mut stream = bench.client.open(target()).await.unwrap();
        round_trip(&mut stream, &pattern(100_000)).await;
        let before = bench.dials.load(Ordering::SeqCst);
        bench.cut.notify_waiters();
        round_trip(&mut stream, &pattern(300_000)).await;
        bench.cut.notify_waiters();
        round_trip(&mut stream, &pattern(300_000)).await;
        assert!(bench.dials.load(Ordering::SeqCst) > before, "it redialled");
    }

    /// UDP over the same HTTP/2 pipes as the streams: datagrams come back
    /// from the server, a flow keeps working after both connections are cut
    /// (what was in flight is lost, as UDP allows), and TCP streams carry on
    /// beside it.
    #[tokio::test]
    async fn udp_flows_share_the_connections_and_survive_a_cut() {
        let bench = bench(true, Duration::from_millis(200), true);
        let peer = Destination::udp(Address::domain("stun.example.org"), 3478);
        let flow = bench.client.open_udp(peer.clone()).await.unwrap();
        let mut tcp = bench.client.open(target()).await.unwrap();
        for round in 0..30u8 {
            flow.send(&peer, &[round; 200]).unwrap();
            let (from, got) = tokio::time::timeout(Duration::from_secs(5), flow.recv())
                .await
                .expect("an echo")
                .unwrap();
            assert_eq!(from, peer);
            assert_eq!(got[..], [round; 200]);
        }
        round_trip(&mut tcp, &pattern(100_000)).await;
        bench.cut.notify_waiters();
        // Keep sending until one gets through the redialled connections.
        let mut recovered = false;
        for round in 0..40u8 {
            flow.send(&peer, &[round; 64]).unwrap();
            if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(500), flow.recv()).await {
                recovered = true;
                break;
            }
        }
        assert!(recovered, "the flow never came back after the cut");
        round_trip(&mut tcp, &pattern(100_000)).await;
    }

    /// On a path with a long round trip, an upload keeps the pipe full and a
    /// datagram sent during it is not stuck behind it. Prints what it saw;
    /// the bounds are loose so a loaded machine does not fail it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn uploads_and_datagrams_on_a_long_path() {
        let one_way = Duration::from_millis(80);
        let bench = bench_with_delay(true, Duration::from_millis(200), true, one_way);
        let peer = Destination::udp(Address::domain("stun.example.org"), 3478);
        let flow = bench.client.open_udp(peer.clone()).await.unwrap();
        // Warm the session.
        flow.send(&peer, b"warm").unwrap();
        tokio::time::timeout(Duration::from_secs(5), flow.recv())
            .await
            .unwrap()
            .unwrap();
        let tcp = bench.client.open(target()).await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(tcp);
        let total = 6 * 1024 * 1024;
        let started = std::time::Instant::now();
        let upload = tokio::spawn(async move {
            let block = pattern(64 * 1024);
            for _ in 0..total / block.len() {
                writer.write_all(&block).await.unwrap();
            }
            writer
        });
        let drain = tokio::spawn(async move {
            let mut buffer = vec![0u8; 64 * 1024];
            let mut got = 0;
            while got < total {
                got += reader.read(&mut buffer).await.unwrap();
            }
            started.elapsed()
        });
        let mut latencies = Vec::new();
        for round in 0..40u8 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let at = std::time::Instant::now();
            flow.send(&peer, &[round; 100]).unwrap();
            if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(2), flow.recv()).await {
                latencies.push(at.elapsed());
            }
        }
        let elapsed = drain.await.unwrap();
        let _ = upload.await;
        latencies.sort();
        let median = latencies.get(latencies.len() / 2).copied();
        eprintln!(
            "6 MiB echoed in {elapsed:?} ({:.1} Mbit/s each way); {} of 40 datagrams came back, median {median:?}, worst {:?}",
            total as f64 * 8.0 / elapsed.as_secs_f64() / 1e6,
            latencies.len(),
            latencies.last()
        );
        assert!(
            latencies.len() >= 20,
            "datagrams were lost during an upload"
        );
    }

    #[tokio::test]
    async fn a_client_that_does_not_ask_for_the_lane_gets_no_udp() {
        let mut bench = bench(true, Duration::from_millis(200), true);
        let config = ClientConfig {
            lane: false,
            ..bench.client.config.clone()
        };
        let dial = bench.client.down.dial.clone();
        bench.client = Client::new(config, dial);
        let error = bench
            .client
            .open_udp(Destination::udp(Address::domain("a.b"), 1))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let mut tcp = bench.client.open(target()).await.unwrap();
        round_trip(&mut tcp, b"still fine").await;
    }

    async fn stop_by(limit: Duration, done: impl Fn() -> bool) {
        let end = std::time::Instant::now() + limit;
        while !done() {
            assert!(std::time::Instant::now() < end, "it did not happen in time");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A rotation that fires after about this long and moves this many bytes.
    fn quick_rotation(age: Duration, bytes: u64) -> Option<Rotation> {
        Some(Rotation {
            min_age: age,
            max_age: age,
            max_bytes: bytes,
        })
    }

    /// Connections are replaced on their own as they age, in the middle of
    /// a live stream, and nothing the stream carries is lost or reordered.
    #[tokio::test]
    async fn connections_are_replaced_by_age_without_disturbing_a_stream() {
        let bench = bench_rotating(
            true,
            Duration::from_millis(100),
            true,
            quick_rotation(Duration::from_millis(400), u64::MAX),
        );
        let mut stream = bench.client.open(target()).await.unwrap();
        let started = bench.dials.load(Ordering::SeqCst);
        for round in 0..24u8 {
            let payload: Vec<u8> = pattern(30_000).iter().map(|b| b ^ round).collect();
            round_trip(&mut stream, &payload).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let dialled = bench.dials.load(Ordering::SeqCst) - started;
        assert!(dialled >= 2, "only {dialled} replacements in 2.4 s");
        // The replaced connections close by themselves once drained.
        stop_by(Duration::from_secs(5), || {
            bench.ended.load(Ordering::SeqCst) >= dialled
        })
        .await;
    }

    /// The volume limit alone is enough to replace a connection.
    #[tokio::test]
    async fn connections_are_replaced_by_volume() {
        let bench = bench_rotating(
            true,
            Duration::from_millis(100),
            true,
            quick_rotation(Duration::from_secs(3600), 100_000),
        );
        let mut stream = bench.client.open(target()).await.unwrap();
        let started = bench.dials.load(Ordering::SeqCst);
        for _ in 0..8 {
            round_trip(&mut stream, &pattern(120_000)).await;
        }
        assert!(bench.dials.load(Ordering::SeqCst) > started);
        // One long transfer crossing many replacements arrives whole.
        let before = bench.dials.load(Ordering::SeqCst);
        round_trip(&mut stream, &pattern(3_000_000)).await;
        assert!(bench.dials.load(Ordering::SeqCst) > before);
    }

    /// While the replacement is still being dialled the old connection keeps
    /// carrying the stream: rotating costs no stall.
    #[tokio::test]
    async fn the_old_connection_carries_on_while_its_replacement_is_dialled() {
        let bench = bench_rotating(
            true,
            Duration::from_millis(100),
            true,
            quick_rotation(Duration::from_millis(300), u64::MAX),
        );
        let mut stream = bench.client.open(target()).await.unwrap();
        round_trip(&mut stream, &pattern(10_000)).await;
        bench.hold.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let started = std::time::Instant::now();
        for _ in 0..3 {
            round_trip(&mut stream, &pattern(40_000)).await;
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "traffic waited for the dial: {:?}",
            started.elapsed()
        );
        bench.hold.store(false, Ordering::SeqCst);
    }

    /// A replacement that cannot be made leaves the old connection in use,
    /// and is not retried on every request.
    #[tokio::test]
    async fn a_failed_replacement_keeps_the_old_connection_and_backs_off() {
        let bench = bench_rotating(
            true,
            Duration::from_millis(100),
            true,
            quick_rotation(Duration::from_millis(200), u64::MAX),
        );
        let mut stream = bench.client.open(target()).await.unwrap();
        round_trip(&mut stream, &pattern(10_000)).await;
        bench.refuse.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let before = bench.dials.load(Ordering::SeqCst);
        for _ in 0..10 {
            round_trip(&mut stream, &pattern(20_000)).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let tried = bench.dials.load(Ordering::SeqCst) - before;
        assert!(
            tried <= 2,
            "{tried} replacement dials while the network was refusing"
        );
    }

    /// A connection that dies young makes the next ones shorter-lived, down
    /// to a floor; ones that reach their limits on schedule win it back.
    #[tokio::test]
    async fn connections_dying_young_shorten_the_next_ones() {
        let bench = bench_rotating(
            true,
            Duration::from_millis(100),
            true,
            Some(Rotation::default()),
        );
        let mut stream = bench.client.open(target()).await.unwrap();
        round_trip(&mut stream, &pattern(10_000)).await;
        let scale = || async { bench.client.down.state.lock().await.scale };
        assert_eq!(scale().await, 1.0);
        for _ in 0..3 {
            bench.cut.notify_waiters();
            tokio::time::sleep(Duration::from_millis(300)).await;
            round_trip(&mut stream, &pattern(50_000)).await;
        }
        let shrunk = scale().await;
        assert!((FLOOR..0.8).contains(&shrunk), "scale is {shrunk}");
    }

    #[test]
    fn limits_follow_the_scale_but_keep_their_floors() {
        let rotation = Rotation::default();
        for _ in 0..100 {
            let (age, bytes) = rotation.draw(FLOOR);
            assert!(age >= rotation.min_age);
            assert!(bytes >= MIN_BYTES);
            assert!(bytes <= rotation.max_bytes / 3);
        }
    }

    #[test]
    fn rotation_limits_stay_inside_the_allowance_and_vary() {
        let rotation = Rotation::default();
        let draws: Vec<_> = (0..200).map(|_| rotation.draw(1.0)).collect();
        for (age, bytes) in &draws {
            assert!(*age >= rotation.min_age && *age <= rotation.max_age);
            assert!(*bytes >= rotation.max_bytes / 2 && *bytes <= rotation.max_bytes);
        }
        let first = draws[0];
        assert!(draws.iter().any(|draw| *draw != first), "no two differ");
    }

    /// Constant trouble: connections are cut at random while six streams move
    /// data of every size, rotation is replacing connections on its own, and
    /// the server pads uploads. Every byte of every stream must still arrive,
    /// in order, and the session must still be the one it started as.
    #[tokio::test]
    async fn a_busy_session_survives_constant_trouble() {
        let bench = bench_rotating(
            true,
            Duration::from_millis(50),
            true,
            quick_rotation(Duration::from_millis(400), 400_000),
        );
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let chaos = tokio::spawn({
            let (cut, stop) = (bench.cut.clone(), stop.clone());
            async move {
                while !stop.load(Ordering::SeqCst) {
                    let wait = rand::thread_rng().gen_range(300..900);
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    cut.notify_waiters();
                }
            }
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        let mut flows = Vec::new();
        for flow in 0..6u8 {
            let client = bench.client.clone();
            flows.push(tokio::spawn(async move {
                let mut stream = client.open(target()).await.unwrap();
                let mut rounds = 0u32;
                while std::time::Instant::now() < deadline {
                    let size = rand::thread_rng().gen_range(1_000..250_000);
                    let payload: Vec<u8> = (0..size)
                        .map(|i| ((i as u32).wrapping_mul(31) as u8) ^ flow ^ rounds as u8)
                        .collect();
                    tokio::time::timeout(
                        Duration::from_secs(30),
                        round_trip(&mut stream, &payload),
                    )
                    .await
                    .expect("a round trip stalled for 30 s");
                    rounds += 1;
                }
                rounds
            }));
        }
        let mut total = 0;
        for flow in flows {
            total += flow.await.unwrap();
        }
        stop.store(true, Ordering::SeqCst);
        chaos.await.unwrap();
        assert!(total >= 12, "only {total} round trips in 8 s of trouble");
        assert!(
            bench.dials.load(Ordering::SeqCst) > 6,
            "no reconnects happened, so nothing was tested"
        );
    }

    #[tokio::test]
    async fn an_unknown_user_is_shown_the_site_not_an_error_of_its_own() {
        let bench = bench(true, Duration::ZERO, false);
        let error = bench.client.open(target()).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    /// What a prober sees: the front page, and the same "not found" for a
    /// random path, a Tide-shaped path, and a handshake full of garbage.
    #[tokio::test]
    async fn a_visitor_without_the_key_only_ever_sees_the_site() {
        let (secret, _) = tide::generate_keypair();
        let (server, _streams) = Server::new(ServerConfig {
            path: "/static/app".into(),
            admin: None,
            secret,
            users: Arc::default(),
            decoy: Decoy::default(),
            shape: tide::ShapeLevel::default(),
        });
        let (near, far) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move { server.serve_connection(boxed(far)).await });
        let (sender, connection) = h2::client::handshake(near).await.unwrap();
        tokio::spawn(connection);

        async fn fetch(
            sender: &SendRequest<Bytes>,
            method: Method,
            path: &str,
            body: &[u8],
        ) -> (StatusCode, Vec<u8>, bool) {
            let mut sender = sender.clone().ready().await.unwrap();
            let (response, mut send) = sender
                .send_request(request(method, "example.test", path), false)
                .unwrap();
            send.send_data(Bytes::copy_from_slice(body), true).unwrap();
            let response = response.await.unwrap();
            let status = response.status();
            let dated = response.headers().contains_key("date");
            let mut body = response.into_body();
            let mut got = Vec::new();
            while let Some(data) = body.data().await {
                got.extend_from_slice(&data.unwrap());
            }
            (status, got, dated)
        }

        let (status, page, dated) = fetch(&sender, Method::GET, "/", b"").await;
        assert_eq!(status, StatusCode::OK);
        assert!(dated && page.starts_with(b"<!doctype html>"));

        let name = "0123456789abcdef0123456789abcdef";
        let (plain_status, plain_body, _) = fetch(&sender, Method::GET, "/nothing", b"").await;
        assert_eq!(plain_status, StatusCode::NOT_FOUND);
        for (method, path, body) in [
            (
                Method::POST,
                format!("/static/app/{name}/open"),
                vec![0u8; 73],
            ),
            (
                Method::POST,
                format!("/static/app/{name}/open"),
                vec![0u8; 4000],
            ),
            (
                Method::GET,
                format!("/static/app/{name}/d/1?t=0000000000000000"),
                vec![],
            ),
            (
                Method::POST,
                format!("/static/app/{name}/u/1?t=0000000000000000"),
                vec![1, 2, 3],
            ),
            (Method::GET, "/static/app/short/open".to_string(), vec![]),
        ] {
            let (status, got, _) = fetch(&sender, method, &path, &body).await;
            assert_eq!(status, plain_status, "{path}");
            assert_eq!(got, plain_body, "{path}");
        }
    }

    /// What a link says about the look of the requests reaches the server on
    /// every request: the opening handshake, the pipes, the front page.
    #[tokio::test]
    async fn the_look_a_link_asks_for_is_on_every_request() {
        let tuning = Tuning {
            look: Look {
                user_agent:
                    "Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0".into(),
                language: "fa-IR,fa;q=0.9".into(),
                headers: vec![
                    ("referer".into(), "https://front.test/".into()),
                    ("x-visit".into(), "7".into()),
                ],
            },
            ..Tuning::default()
        };
        let bench = bench_core(
            true,
            Duration::from_millis(100),
            true,
            Duration::ZERO,
            None,
            "front.test",
            tuning.clone(),
        );
        let mut stream = bench.client.open(target()).await.unwrap();
        round_trip(&mut stream, &pattern(20_000)).await;
        let seen = bench.server.seen.lock().unwrap();
        // The front page of each connection, the open, a download, an upload.
        let paths: Vec<&str> = seen.iter().map(|(_, path, _)| path.as_str()).collect();
        for expected in ["/", "/open", "/d/1", "/u/1"] {
            assert!(
                paths.iter().any(|path| path.ends_with(expected)),
                "no request for {expected}: {paths:?}"
            );
        }
        for (authority, path, headers) in seen.iter() {
            assert_eq!(authority, "front.test", "{path}");
            assert_eq!(
                headers["user-agent"],
                tuning.look.user_agent.as_str(),
                "{path}"
            );
            assert_eq!(headers["accept-language"], "fa-IR,fa;q=0.9", "{path}");
            assert_eq!(headers["referer"], "https://front.test/", "{path}");
            assert_eq!(headers["x-visit"], "7", "{path}");
        }
    }

    /// Pipes are the number of download requests held open: with one, the
    /// session never opens a second beside it.
    #[tokio::test]
    async fn the_download_pipe_count_is_honoured() {
        for pipes in [1usize, 3] {
            let bench = bench_core(
                true,
                Duration::from_millis(100),
                true,
                Duration::ZERO,
                None,
                "example.test",
                Tuning {
                    down_pipes: pipes,
                    ..Tuning::default()
                },
            );
            let mut stream = bench.client.open(target()).await.unwrap();
            round_trip(&mut stream, &pattern(5_000)).await;
            // The extra pipes are staggered by up to a second and a half.
            tokio::time::sleep(Duration::from_millis(2_200)).await;
            let downloads = bench
                .server
                .seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, path, _)| path.contains("/d/"))
                .count();
            assert_eq!(downloads, pipes, "pipes={pipes}");
        }
    }

    /// A short idle limit closes a session with nothing open on it, and its
    /// connections with it. The check runs every ten seconds, so this waits
    /// for one; with the default limit a session this young stays open.
    #[tokio::test]
    async fn the_idle_setting_closes_a_quiet_session() {
        let bench = bench_core(
            true,
            Duration::from_millis(100),
            true,
            Duration::ZERO,
            None,
            "example.test",
            Tuning {
                idle: Duration::from_millis(50),
                ..Tuning::default()
            },
        );
        let stream = bench.client.open(target()).await.unwrap();
        drop(stream);
        for _ in 0..140 {
            let closed = bench
                .client
                .live
                .lock()
                .await
                .as_ref()
                .is_some_and(|session| session.is_closed());
            if closed {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the quiet session was not closed");
    }
}
