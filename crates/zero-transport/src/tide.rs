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
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use h2::client::SendRequest;
use http::{Method, Request, Response, StatusCode};
use rand::{Rng, RngCore};
use zero_core::{BoxStream, Destination};
use zero_protocol::tide::session::{pipe_tag, CHUNK_PLAIN_MAX};
use zero_protocol::tide::{self, ChunkParser, ReplayGuard, Session, TideStream, UserId};

/// HTTP/2 windows large enough that the transport, not HTTP/2, sets the pace.
const H2_WINDOW: u32 = 4 * 1024 * 1024;
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

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Write `data` to a body, waiting for HTTP/2 to grant room for each part.
async fn send_all(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
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
}

/// One HTTP/2 connection that is redialled when it breaks.
struct Carrier {
    dial: Dialer,
    host: String,
    current: tokio::sync::Mutex<Option<SendRequest<Bytes>>>,
}

impl Carrier {
    fn new(dial: Dialer, host: String) -> Arc<Self> {
        Arc::new(Self {
            dial,
            host,
            current: tokio::sync::Mutex::new(None),
        })
    }

    /// A handle for sending requests, connecting first if there is none. A
    /// new connection fetches the front page before anything else; the
    /// server's clock from that reply is returned with it.
    async fn get(&self) -> io::Result<(SendRequest<Bytes>, Option<u64>)> {
        let mut current = self.current.lock().await;
        if let Some(sender) = current.as_ref() {
            return Ok((sender.clone(), None));
        }
        let (io, uncork) = Cork::new((self.dial)().await?);
        let (sender, connection) = h2::client::Builder::new()
            .initial_window_size(H2_WINDOW)
            .initial_connection_window_size(H2_WINDOW)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(other)?;
        // The page request is queued while the connection's first bytes are
        // still held back, so the HTTP/2 preface, the settings and the
        // request leave together in one write, as a browser's do, and not as
        // a 46-byte packet followed by the request.
        let page = front_page_request(sender.clone(), &self.host);
        uncork.store(true, std::sync::atomic::Ordering::Release);
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "tide connection ended");
            }
        });
        let time = front_page(page).await;
        *current = Some(sender.clone());
        Ok((sender, time))
    }

    /// Forget the connection after a failure, so the next use redials.
    async fn invalidate(&self) {
        *self.current.lock().await = None;
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

fn request(method: Method, host: &str, path: &str) -> Request<()> {
    Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"))
        .header("user-agent", USER_AGENT)
        .header("accept", "*/*")
        .header("accept-language", "en-US,en;q=0.9")
        .body(())
        .expect("a request built from checked parts")
}

/// Queue a request for the site's front page, as a browser makes on a new
/// connection. Nothing is awaited: the request is only placed in the
/// connection's outgoing buffer.
fn front_page_request(
    mut sender: SendRequest<Bytes>,
    host: &str,
) -> Option<h2::client::ResponseFuture> {
    let mut page = request(Method::GET, host, "/");
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
        let down = Carrier::new(dial.clone(), config.host.clone());
        let up = if config.split {
            Carrier::new(dial, config.host.clone())
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
        let (sender, server_time) = match self.down.get().await {
            Ok(connected) => connected,
            Err(error) => {
                self.down.invalidate().await;
                return Err(error);
            }
        };
        let mut name = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut name);
        let base = format!("{}/{}", self.config.path, hex_name(&name));
        let (hello, handshake) = tide::client_hello(
            &self.config.server_public,
            &self.config.user,
            server_time.unwrap_or_else(now),
        )?;

        let opened = async {
            let mut sender = sender.ready().await.map_err(other)?;
            let open = request(Method::POST, &self.config.host, &format!("{base}/open"));
            let (response, mut body) = sender.send_request(open, false).map_err(other)?;
            send_all(&mut body, Bytes::from(hello)).await?;
            body.send_data(Bytes::new(), true).map_err(other)?;
            let response = response.await.map_err(other)?;
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
                self.down.invalidate().await;
                return Err(error);
            }
            Err(_) => {
                self.down.invalidate().await;
                return Err(io::ErrorKind::TimedOut.into());
            }
        };

        tokio::spawn(session.clone().run_timers());
        tokio::spawn(download(
            session.clone(),
            self.down.clone(),
            self.config.host.clone(),
            base.clone(),
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
        ));
        Ok(session)
    }
}

fn hex_name(name: &[u8; 16]) -> String {
    name.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn close_when_idle(session: Arc<Session>, down: Arc<Carrier>, up: Arc<Carrier>) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        if session.is_closed() {
            break;
        }
        if session.streams() == 0 && session.idle_for() > SESSION_IDLE {
            session.close();
            break;
        }
    }
    // Dropping the handles lets the HTTP/2 connections close.
    down.invalidate().await;
    up.invalidate().await;
}

/// Wait a little longer after each failure in a row.
async fn back_off(failures: u32) {
    let wait = 200u64.saturating_mul(1 << failures.min(4));
    tokio::time::sleep(Duration::from_millis(wait)).await;
}

/// Keep one download request open for as long as the session lives.
async fn download(session: Arc<Session>, carrier: Arc<Carrier>, host: String, base: String) {
    let mut number = 0u64;
    let mut failures = 0;
    while !session.is_closed() {
        number += 1;
        let path = format!(
            "{base}/d/{number}?t={}",
            pipe_tag(session.binding(), b'd', number)
        );
        match download_once(&session, &carrier, &host, &path).await {
            Ok(()) => failures = 0,
            Err(PipeError::Gone) => break,
            Err(PipeError::Failed(error)) => {
                tracing::debug!(%error, "tide download pipe failed");
                carrier.invalidate().await;
                failures += 1;
                if failures > MAX_FAILURES {
                    break;
                }
                back_off(failures).await;
            }
        }
    }
    session.close();
}

async fn download_once(
    session: &Session,
    carrier: &Carrier,
    host: &str,
    path: &str,
) -> Result<(), PipeError> {
    let (sender, _) = carrier.get().await?;
    let mut sender = sender.ready().await.map_err(other)?;
    let (response, _) = sender
        .send_request(request(Method::GET, host, path), true)
        .map_err(other)?;
    let response = response.await.map_err(other)?;
    if response.status() != StatusCode::OK {
        return Err(PipeError::Gone);
    }
    let mut body = response.into_body();
    let mut parser = ChunkParser::default();
    while let Some(data) = body.data().await {
        let data = data.map_err(other)?;
        session.receive(&mut parser, &data)?;
        let _ = body.flow_control().release_capacity(data.len());
    }
    Ok(())
}

/// Send what the session has to send, one upload request after another.
async fn upload(session: Arc<Session>, carrier: Arc<Carrier>, config: ClientConfig, base: String) {
    let mut number = 0u64;
    let mut failures = 0;
    loop {
        // Wait for something to send before making a request for it.
        let Ok(first) = session.next_chunk(number + 1, CHUNK_PLAIN_MAX).await else {
            break;
        };
        number += 1;
        session.pipe_opened(number);
        let path = format!(
            "{base}/u/{number}?t={}",
            pipe_tag(session.binding(), b'u', number)
        );
        match upload_once(&session, &carrier, &config, &path, number, first).await {
            Ok(()) => {
                session.pipe_closed(number, true);
                failures = 0;
            }
            Err(PipeError::Gone) => {
                session.pipe_closed(number, false);
                break;
            }
            Err(PipeError::Failed(error)) => {
                tracing::debug!(%error, "tide upload pipe failed");
                session.pipe_closed(number, false);
                carrier.invalidate().await;
                failures += 1;
                if failures > MAX_FAILURES {
                    break;
                }
                back_off(failures).await;
            }
        }
    }
    session.close();
}

async fn upload_once(
    session: &Session,
    carrier: &Carrier,
    config: &ClientConfig,
    path: &str,
    number: u64,
    first: Bytes,
) -> Result<(), PipeError> {
    let (sender, _) = carrier.get().await?;
    let mut sender = sender.ready().await.map_err(other)?;
    let mut post = request(Method::POST, &config.host, path);
    post.headers_mut().insert(
        "content-type",
        "application/octet-stream"
            .parse()
            .expect("a fixed header value"),
    );
    let (response, mut body) = sender.send_request(post, false).map_err(other)?;
    // Each request carries a different amount, so no size repeats.
    let limit = rand::thread_rng().gen_range(256 * 1024..1024 * 1024);
    let mut sent = first.len();
    send_all(&mut body, first).await?;
    while sent < limit {
        let next = if config.linger.is_zero() {
            session.try_next_chunk(number, CHUNK_PLAIN_MAX)
        } else {
            match tokio::time::timeout(config.linger, session.next_chunk(number, CHUNK_PLAIN_MAX))
                .await
            {
                Ok(Ok(chunk)) => Some(chunk),
                Ok(Err(_)) | Err(_) => None,
            }
        };
        let Some(chunk) = next else { break };
        sent += chunk.len();
        send_all(&mut body, chunk).await?;
    }
    body.send_data(Bytes::new(), true).map_err(other)?;
    let response = response.await.map_err(other)?;
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

    /// Serve one connection (TLS already done, if any) until it closes.
    pub async fn serve_connection(self: &Arc<Self>, io: BoxStream) -> io::Result<()> {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(H2_WINDOW)
            .initial_connection_window_size(H2_WINDOW)
            .max_concurrent_streams(256)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(other)?;
        while let Some(accepted) = connection.accept().await {
            let (request, respond) = accepted.map_err(other)?;
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
        mut respond: h2::server::SendResponse<Bytes>,
    ) -> io::Result<()> {
        let front = matches!(path, "/" | "/index.html")
            && (method == Method::GET || method == Method::HEAD);
        let page = if front {
            self.config.decoy.page.clone()
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

    struct Bench {
        client: Arc<Client>,
        dials: Arc<AtomicUsize>,
        /// Cut every connection made so far.
        cut: Arc<tokio::sync::Notify>,
    }

    /// A server answering every stream as an echo, and a client wired to it
    /// through in-memory connections.
    fn bench(split: bool, linger: Duration, known_user: bool) -> Bench {
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
        });
        tokio::spawn(async move {
            while let Some((_, _, mut stream)) = streams.recv().await {
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
        let dial: Dialer = {
            let (dials, cut) = (dials.clone(), cut.clone());
            Arc::new(move || {
                let (server, dials, cut) = (server.clone(), dials.clone(), cut.clone());
                Box::pin(async move {
                    dials.fetch_add(1, Ordering::SeqCst);
                    let (near, far) = tokio::io::duplex(256 * 1024);
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = server.serve_connection(boxed(far)) => {}
                            () = cut.notified() => {}
                        }
                    });
                    Ok(boxed(near))
                })
            })
        };
        let client = Client::new(
            ClientConfig {
                host: "example.test".into(),
                path: "/static/app".into(),
                server_public: public,
                user,
                split,
                linger,
            },
            dial,
        );
        Bench { client, dials, cut }
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
}
