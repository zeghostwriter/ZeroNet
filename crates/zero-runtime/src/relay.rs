//! Bidirectional relay with staged progress accounting.
//!
//! The byte counts and the stage reached are not statistics — they are the
//! evidence the planner needs. A path that completes TLS and then transfers
//! nothing is a *different* failure from one that transfers 40 KB and stops,
//! and only the relay can tell them apart (RESEARCH-01 §27, PLAN-02 §5.2).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;
use zero_core::{FailureKind, Stage};

// Every direction starts on a small buffer and is promoted to a large one only
// once a read fills the small one completely, i.e. once the flow has shown it
// is a bulk transfer. Interactive and idle sessions -- the overwhelming
// majority on a proxy -- then cost 32 KiB, and bulk transfers run on 64 KiB
// chunks: eight times Xray's 8 KiB, so a gigabit flow is a few thousand
// read/write rounds a second, not tens of thousands. 128 KiB chunks bought
// no measurable throughput and made every busy connection cost 256 KiB,
// which in TUN mode, where a browser keeps hundreds of connections, was a
// large share of the client's memory.
const RELAY_SMALL_BUFFER_SIZE: usize = 16 * 1024;
const RELAY_BUFFER_SIZE: usize = 64 * 1024;
// What the pools keep for reuse after connections close: 4 MiB + 2 MiB.
const RELAY_SMALL_POOL_LIMIT: usize = 256;
const RELAY_BUFFER_POOL_LIMIT: usize = 32;

/// Close a flow that has moved no byte in either direction for this long.
/// Matches Xray's default `connIdle` policy. Without it a peer that vanished
/// without a FIN or RST (a NAT rebinding, a mobile handover, a middlebox that
/// silently drops the flow) pins a task, two sockets and two buffers forever.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Once one direction has finished, how long the other may stay silent
/// before the flow is closed. Xray's `uplinkOnly`/`downlinkOnly` default.
/// The timer restarts on every byte, so a direction that is still moving
/// data runs to completion; what it ends is a peer that answered a FIN with
/// nothing, which otherwise held both sockets and their buffers for the full
/// five-minute idle period (and, in TUN mode, the stack's buffers with them).
pub const HALF_CLOSE_IDLE: Duration = Duration::from_secs(1);

type BufferPool = Mutex<Vec<Box<[u8]>>>;

fn pool_for(size: usize) -> Option<(&'static BufferPool, usize)> {
    static SMALL: OnceLock<BufferPool> = OnceLock::new();
    static LARGE: OnceLock<BufferPool> = OnceLock::new();
    match size {
        RELAY_SMALL_BUFFER_SIZE => Some((
            SMALL.get_or_init(|| Mutex::new(Vec::with_capacity(RELAY_SMALL_POOL_LIMIT))),
            RELAY_SMALL_POOL_LIMIT,
        )),
        RELAY_BUFFER_SIZE => Some((
            LARGE.get_or_init(|| Mutex::new(Vec::with_capacity(RELAY_BUFFER_POOL_LIMIT))),
            RELAY_BUFFER_POOL_LIMIT,
        )),
        _ => None,
    }
}

fn take_buffer(size: usize) -> Box<[u8]> {
    pool_for(size)
        .and_then(|(pool, _)| {
            pool.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop()
        })
        .unwrap_or_else(|| vec![0u8; size].into_boxed_slice())
}

fn recycle_buffer(buf: Box<[u8]>) {
    let Some((pool, limit)) = pool_for(buf.len()) else {
        return;
    };
    let mut pool = pool.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if pool.len() < limit {
        pool.push(buf);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transferred {
    pub uploaded: u64,
    pub downloaded: u64,
}

#[derive(Debug, Clone)]
pub struct RelayOutcome {
    pub transferred: Transferred,
    /// The furthest stage this flow reached.
    pub stage: Stage,
    pub elapsed: std::time::Duration,
    pub error: Option<String>,
}

/// Preserve useful failure taxonomy when a lower layer returns only an I/O
/// string. Transport wrappers intentionally expose human-readable errors, so
/// this small last-mile classifier keeps the planner from recording every
/// failed flow as `UNKNOWN`.
pub fn classify_error(error: &str, stage: Stage) -> FailureKind {
    let error = error.to_ascii_lowercase();
    if error.contains("timed out") || error.contains("timeout") {
        return match stage {
            Stage::Resolving => FailureKind::DnsTimeout,
            Stage::TlsStarted | Stage::TlsCompleted => FailureKind::TlsTimeout,
            _ => FailureKind::TcpTimeout,
        };
    }
    if error.contains("network is down") || error.contains("network changed") {
        return FailureKind::NetworkChanged;
    }
    if error.contains("network unreachable")
        || error.contains("host unreachable")
        || error.contains("no route to host")
    {
        return FailureKind::TcpUnreachable;
    }
    if error.contains("connection reset") || error.contains("broken pipe") {
        return FailureKind::TcpReset;
    }
    if error.contains("connection refused") {
        return FailureKind::TcpRefused;
    }
    if error.contains("websocket") {
        return FailureKind::WebsocketMalformed;
    }
    if error.contains("http/2") || error.contains("h2") {
        return FailureKind::H2ProtocolError;
    }
    FailureKind::Unknown
}

impl RelayOutcome {
    /// Whether the flow moved enough data to count as a working path.
    pub fn is_useful(&self) -> bool {
        self.stage.is_useful_progress()
    }
}

struct CopyBuffer {
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
    /// The last read filled the whole (small) buffer: swap in a large one
    /// before the next read.
    grow: bool,
    read_done: bool,
    need_flush: bool,
    total: u64,
    /// Bumped on every successful read or write, so the idle timer can tell a
    /// quiet flow from a busy one without touching the clock per chunk.
    activity: u64,
    shut_down: bool,
    done: bool,
    error: Option<String>,
}

impl CopyBuffer {
    fn new() -> Self {
        Self {
            buf: take_buffer(RELAY_SMALL_BUFFER_SIZE),
            pos: 0,
            cap: 0,
            grow: false,
            read_done: false,
            need_flush: false,
            total: 0,
            activity: 0,
            shut_down: false,
            done: false,
            error: None,
        }
    }

    fn fail(&mut self, error: io::Error) -> Poll<io::Result<()>> {
        self.error = Some(error.to_string());
        self.done = true;
        Poll::Ready(Err(error))
    }

    fn poll_copy_step<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        if self.done {
            return Poll::Ready(Ok(()));
        }

        loop {
            // 1. If buffer has data, write it out.
            while self.pos < self.cap {
                match writer
                    .as_mut()
                    .poll_write(cx, &self.buf[self.pos..self.cap])
                {
                    Poll::Ready(Ok(0)) => {
                        return self.fail(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero byte into writer",
                        ));
                    }
                    Poll::Ready(Ok(n)) => {
                        self.pos += n;
                        self.total += n as u64;
                        self.activity = self.activity.wrapping_add(1);
                        self.need_flush = true;
                    }
                    Poll::Ready(Err(e)) => return self.fail(e),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // The buffer is completely drained here.
            self.pos = 0;
            self.cap = 0;

            // 2. If read is not done, try to read into buffer.
            if !self.read_done {
                if self.grow {
                    self.grow = false;
                    let small = std::mem::replace(&mut self.buf, take_buffer(RELAY_BUFFER_SIZE));
                    recycle_buffer(small);
                }
                let mut read_buf = ReadBuf::new(&mut self.buf);
                match reader.as_mut().poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.cap = n;
                            self.activity = self.activity.wrapping_add(1);
                            self.grow = n == self.buf.len() && n < RELAY_BUFFER_SIZE;
                            // Loop around to write immediately without yielding.
                            continue;
                        }
                    }
                    Poll::Ready(Err(e)) => return self.fail(e),
                    Poll::Pending => {
                        // Reader has no data ready right now. If we wrote data earlier,
                        // flush the writer so the peer receives it without waiting for a second write.
                        if self.need_flush {
                            match writer.as_mut().poll_flush(cx) {
                                Poll::Ready(Ok(())) => self.need_flush = false,
                                Poll::Ready(Err(e)) => return self.fail(e),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        return Poll::Pending;
                    }
                }
            }

            // 3. Read is done and the buffer is empty: flush, then half-close
            //    the writer so the peer sees EOF while the other direction
            //    keeps running.
            if self.need_flush {
                match writer.as_mut().poll_flush(cx) {
                    Poll::Ready(Ok(())) => self.need_flush = false,
                    Poll::Ready(Err(e)) => return self.fail(e),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if !self.shut_down {
                match writer.as_mut().poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => {
                        if !matches!(
                            e.kind(),
                            io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe
                        ) {
                            self.error = Some(e.to_string());
                        }
                    }
                    Poll::Pending => return Poll::Pending,
                }
                self.shut_down = true;
            }

            self.done = true;
            // Nothing more moves this way: hand the buffer back now rather
            // than when the other direction finishes too.
            recycle_buffer(std::mem::take(&mut self.buf));
            return Poll::Ready(Ok(()));
        }
    }
}

impl Drop for CopyBuffer {
    fn drop(&mut self) {
        recycle_buffer(std::mem::take(&mut self.buf));
    }
}

/// Idle detection that does not re-arm a timer per chunk: the timer is armed
/// once per period, and when it fires the activity counters decide whether the
/// flow was quiet for the whole period or merely needs the timer pushed out.
/// A flow is therefore closed between one and two periods after its last byte.
struct IdleTimer {
    period: Duration,
    sleep: Pin<Box<Sleep>>,
    seen: u64,
}

impl IdleTimer {
    fn new(period: Duration) -> Self {
        Self {
            period,
            sleep: Box::pin(tokio::time::sleep(period)),
            seen: 0,
        }
    }

    /// `true` once the flow has been idle for a full period.
    fn poll_expired(&mut self, cx: &mut Context<'_>, activity: u64) -> bool {
        loop {
            if self.sleep.as_mut().poll(cx).is_pending() {
                return false;
            }
            if activity == self.seen {
                return true;
            }
            self.seen = activity;
            let next = tokio::time::Instant::now() + self.period;
            self.sleep.as_mut().reset(next);
        }
    }
}

/// Unified bidirectional copy future without `tokio::io::split` or `tokio::sync::Mutex`.
struct CopyBidirectional<'a, A, B> {
    client: &'a mut A,
    remote: &'a mut B,
    a_to_b: CopyBuffer,
    b_to_a: CopyBuffer,
    idle: Option<IdleTimer>,
    /// Armed when exactly one direction has finished; see [`HALF_CLOSE_IDLE`].
    half_closed: Option<IdleTimer>,
    half_close_limit: Option<Duration>,
}

struct CopyResult {
    uploaded: u64,
    downloaded: u64,
    error: Option<String>,
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    type Output = CopyResult;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        // Drive upload: client -> remote
        let _ = this.a_to_b.poll_copy_step(
            cx,
            Pin::new(&mut *this.client),
            Pin::new(&mut *this.remote),
        );

        // Drive download: remote -> client
        let _ = this.b_to_a.poll_copy_step(
            cx,
            Pin::new(&mut *this.remote),
            Pin::new(&mut *this.client),
        );

        // If either encountered an error, finish early: a reset on one side
        // makes the other direction meaningless, and both sockets are closed
        // when the relay returns.
        let error = this
            .a_to_b
            .error
            .take()
            .or_else(|| this.b_to_a.error.take());
        if error.is_some() || (this.a_to_b.done && this.b_to_a.done) {
            return Poll::Ready(CopyResult {
                uploaded: this.a_to_b.total,
                downloaded: this.b_to_a.total,
                error,
            });
        }

        let activity = this.a_to_b.activity.wrapping_add(this.b_to_a.activity);
        if this.a_to_b.done != this.b_to_a.done {
            if let Some(limit) = this.half_close_limit {
                let timer = this
                    .half_closed
                    .get_or_insert_with(|| IdleTimer::new(limit));
                if timer.poll_expired(cx, activity) {
                    // The remaining side had its chance to finish; this is an
                    // ordinary end of the flow, not a failure.
                    return Poll::Ready(CopyResult {
                        uploaded: this.a_to_b.total,
                        downloaded: this.b_to_a.total,
                        error: None,
                    });
                }
            }
        }
        if let Some(idle) = this.idle.as_mut() {
            if idle.poll_expired(cx, activity) {
                let (uploaded, downloaded) = (this.a_to_b.total, this.b_to_a.total);
                // A flow on which nothing ever moved tells the planner nothing
                // about the path -- the client simply never used it -- so it
                // closes exactly like a client that hung up. A flow that sent
                // and then heard nothing for a whole period is a real timeout.
                let error = (uploaded > 0 || downloaded > 0)
                    .then(|| format!("relay idle timeout after {}s", idle.period.as_secs()));
                return Poll::Ready(CopyResult {
                    uploaded,
                    downloaded,
                    error,
                });
            }
        }

        Poll::Pending
    }
}

/// Copy in both directions until both sides close, either side errors, or the
/// flow stays idle for [`DEFAULT_IDLE_TIMEOUT`].
pub async fn relay<A, B>(client: A, remote: B) -> RelayOutcome
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    relay_with_idle_timeout(client, remote, Some(DEFAULT_IDLE_TIMEOUT)).await
}

/// [`relay`] with an explicit idle limit; `None` never times out.
pub async fn relay_with_idle_timeout<A, B>(
    mut client: A,
    mut remote: B,
    idle_timeout: Option<Duration>,
) -> RelayOutcome
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let started = Instant::now();

    let copy = CopyBidirectional {
        client: &mut client,
        remote: &mut remote,
        a_to_b: CopyBuffer::new(),
        b_to_a: CopyBuffer::new(),
        idle: idle_timeout
            .filter(|period| !period.is_zero())
            .map(IdleTimer::new),
        half_closed: None,
        // A caller that asked for no idle limit gets no half-close limit
        // either.
        half_close_limit: idle_timeout.map(|_| HALF_CLOSE_IDLE),
    };
    let CopyResult {
        uploaded,
        downloaded,
        error,
    } = copy.await;

    // Stage is driven by what actually moved, not by what succeeded to open.
    let stage = if uploaded > 0 && downloaded > 0 {
        Stage::BidirectionalConfirmed
    } else if downloaded > 0 {
        Stage::PayloadTransferred
    } else if uploaded > 0 {
        Stage::UploadConfirmed
    } else {
        Stage::RequestSent
    };

    RelayOutcome {
        transferred: Transferred {
            uploaded,
            downloaded,
        },
        stage,
        elapsed: started.elapsed(),
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn relays_both_directions_and_counts_bytes() {
        let (client, client_peer) = duplex(8192);
        let (remote, remote_peer) = duplex(8192);

        tokio::spawn(async move {
            let mut p = client_peer;
            p.write_all(b"request").await.unwrap();
            p.shutdown().await.unwrap();
            let mut got = Vec::new();
            p.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"response!!");
        });

        tokio::spawn(async move {
            let mut p = remote_peer;
            let mut got = vec![0u8; 7];
            p.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"request");
            p.write_all(b"response!!").await.unwrap();
            p.shutdown().await.unwrap();
        });

        let out = relay(client, remote).await;
        assert_eq!(out.transferred.uploaded, 7);
        assert_eq!(out.transferred.downloaded, 10);
        assert_eq!(out.stage, Stage::BidirectionalConfirmed);
        assert!(out.is_useful());
    }

    #[tokio::test]
    async fn upload_only_flow_is_not_useful_progress() {
        let (client, client_peer) = duplex(8192);
        let (remote, remote_peer) = duplex(8192);

        tokio::spawn(async move {
            let mut p = client_peer;
            p.write_all(b"data").await.unwrap();
            p.shutdown().await.unwrap();
        });
        tokio::spawn(async move {
            // Read but never answer: the classic "ghost connectivity" shape.
            let mut p = remote_peer;
            let mut sink = Vec::new();
            let _ = p.read_to_end(&mut sink).await;
            p.shutdown().await.unwrap();
        });

        let out = relay(client, remote).await;
        assert_eq!(out.transferred.uploaded, 4);
        assert_eq!(out.transferred.downloaded, 0);
        assert_eq!(out.stage, Stage::UploadConfirmed);
        assert!(!out.is_useful(), "upload alone must not count as working");
    }

    #[tokio::test]
    async fn immediate_close_records_no_progress() {
        let (client, client_peer) = duplex(64);
        let (remote, remote_peer) = duplex(64);
        drop(client_peer);
        drop(remote_peer);

        let out = relay(client, remote).await;
        assert_eq!(out.transferred.uploaded, 0);
        assert_eq!(out.transferred.downloaded, 0);
        assert_eq!(out.stage, Stage::RequestSent);
        assert!(!out.is_useful());
    }

    #[tokio::test]
    async fn request_reaches_the_peer_without_a_second_write() {
        // A buffering writer must be flushed, or a lone request never
        // arrives and the exchange stalls.
        struct BufferingWriter {
            inner: tokio::io::DuplexStream,
            pending: Vec<u8>,
        }

        impl tokio::io::AsyncWrite for BufferingWriter {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                // Accept everything but hold it until flushed.
                self.pending.extend_from_slice(buf);
                std::task::Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                while !self.pending.is_empty() {
                    let this = &mut *self;
                    match std::pin::Pin::new(&mut this.inner).poll_write(cx, &this.pending) {
                        std::task::Poll::Ready(Ok(n)) => {
                            this.pending.drain(..n);
                        }
                        std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                    }
                }
                std::pin::Pin::new(&mut self.inner).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }

        impl tokio::io::AsyncRead for BufferingWriter {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
            }
        }

        let (client, mut client_peer) = duplex(8192);
        let (remote_inner, mut remote_peer) = duplex(8192);
        let remote = BufferingWriter {
            inner: remote_inner,
            pending: Vec::new(),
        };

        tokio::spawn(async move {
            client_peer.write_all(b"PING").await.unwrap();
            // Deliberately send nothing further: the relay must not need a
            // second write to get the first one out.
            let mut got = vec![0u8; 4];
            client_peer.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"PONG");
            client_peer.shutdown().await.unwrap();
        });

        tokio::spawn(async move {
            let mut got = vec![0u8; 4];
            remote_peer.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"PING");
            remote_peer.write_all(b"PONG").await.unwrap();
            remote_peer.shutdown().await.unwrap();
        });

        let out = tokio::time::timeout(std::time::Duration::from_secs(5), relay(client, remote))
            .await
            .expect("relay must not stall waiting for a flush");

        assert_eq!(out.transferred.uploaded, 4);
        assert_eq!(out.transferred.downloaded, 4);
    }

    #[tokio::test]
    async fn large_transfer_is_counted_exactly() {
        let (client, client_peer) = duplex(64 * 1024);
        let (remote, remote_peer) = duplex(64 * 1024);

        let payload = vec![0x42u8; 500_000];
        let p2 = payload.clone();
        tokio::spawn(async move {
            let mut p = client_peer;
            p.write_all(&p2).await.unwrap();
            // Half-close the request direction, then stay alive to receive
            // the response. A client that drops its socket here cannot be
            // delivered to, which would be a fault in the test, not the relay.
            p.shutdown().await.unwrap();
            let mut back = Vec::new();
            p.read_to_end(&mut back).await.unwrap();
            assert_eq!(back, b"ok");
        });
        tokio::spawn(async move {
            let mut p = remote_peer;
            let mut sink = Vec::new();
            p.read_to_end(&mut sink).await.unwrap();
            assert_eq!(sink.len(), 500_000);
            p.write_all(b"ok").await.unwrap();
            p.shutdown().await.unwrap();
        });

        let out = relay(client, remote).await;
        assert_eq!(out.transferred.uploaded, 500_000);
        assert_eq!(out.transferred.downloaded, 2);
        assert_eq!(out.error, None, "clean transfer should report no error");
    }

    #[test]
    fn classifies_common_relay_failures_for_the_planner() {
        assert_eq!(
            classify_error("connection reset by peer", Stage::PayloadTransferred),
            FailureKind::TcpReset
        );
        assert_eq!(
            classify_error("operation timed out", Stage::TlsStarted),
            FailureKind::TlsTimeout
        );
        assert_eq!(
            classify_error("operation timed out", Stage::Resolving),
            FailureKind::DnsTimeout
        );
        assert_eq!(
            classify_error("Network is down (os error 100)", Stage::PayloadTransferred),
            FailureKind::NetworkChanged
        );
        assert_eq!(
            classify_error("no route to host", Stage::SocketConnected),
            FailureKind::TcpUnreachable
        );
        assert_eq!(
            classify_error("h2 protocol error", Stage::RequestSent),
            FailureKind::H2ProtocolError
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_flow_is_closed_after_the_idle_period() {
        // A peer that vanished without FIN/RST must not pin the session.
        let (client, _client_peer) = duplex(1024);
        let (remote, _remote_peer) = duplex(1024);
        let started = tokio::time::Instant::now();
        let out = relay_with_idle_timeout(client, remote, Some(Duration::from_secs(10))).await;
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_secs(10),
            "closed early: {waited:?}"
        );
        assert!(waited < Duration::from_secs(21), "closed late: {waited:?}");
        assert_eq!(out.transferred.uploaded, 0);
        // Nothing ever moved, so there is nothing to blame on the path.
        assert_eq!(out.error, None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_half_closed_flow_ends_soon_when_the_other_side_stays_silent() {
        // The server finished and closed; the client never answers the FIN.
        // Before, this held both sockets for the whole five-minute idle
        // period, and in TUN mode the netstack buffers with them.
        let (client, _client_peer) = duplex(1024);
        let (remote, mut remote_peer) = duplex(1024);
        let relay = tokio::spawn(relay(client, remote));
        remote_peer.write_all(b"response").await.unwrap();
        remote_peer.shutdown().await.unwrap();
        let started = tokio::time::Instant::now();
        let out = relay.await.unwrap();
        let waited = started.elapsed();
        assert!(waited <= HALF_CLOSE_IDLE * 3, "held for {waited:?}");
        assert_eq!(out.transferred.downloaded, 8);
        assert_eq!(out.error, None, "a finished flow is not a failure");
    }

    #[tokio::test(start_paused = true)]
    async fn a_half_closed_flow_keeps_going_while_the_other_side_sends() {
        let (client, mut client_peer) = duplex(1024);
        let (remote, mut remote_peer) = duplex(1024);
        let relay = tokio::spawn(relay(client, remote));
        remote_peer.shutdown().await.unwrap();
        // An upload trickling in after the response: well past the half-close
        // limit in total, but never silent for that long.
        for _ in 0..10 {
            tokio::time::sleep(HALF_CLOSE_IDLE / 2).await;
            client_peer.write_all(b"x").await.unwrap();
            let mut byte = [0u8; 1];
            remote_peer.read_exact(&mut byte).await.unwrap();
        }
        assert!(
            !relay.is_finished(),
            "cut off a direction still moving data"
        );
        drop(client_peer);
        let out = relay.await.unwrap();
        assert_eq!(out.transferred.uploaded, 10);
    }

    #[tokio::test(start_paused = true)]
    async fn a_flow_that_keeps_moving_is_not_idle() {
        let (client, mut client_peer) = duplex(1024);
        let (remote, mut remote_peer) = duplex(1024);
        let relay = tokio::spawn(relay_with_idle_timeout(
            client,
            remote,
            Some(Duration::from_secs(10)),
        ));
        // Six seconds between bytes, for well over two idle periods.
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_secs(6)).await;
            client_peer.write_all(b"x").await.unwrap();
            let mut byte = [0u8; 1];
            remote_peer.read_exact(&mut byte).await.unwrap();
        }
        assert!(!relay.is_finished(), "an active flow was closed as idle");
        client_peer.shutdown().await.unwrap();
        remote_peer.shutdown().await.unwrap();
        let out = relay.await.unwrap();
        assert_eq!(out.transferred.uploaded, 6);
        assert_eq!(out.error, None);
    }

    #[tokio::test(start_paused = true)]
    async fn upload_then_silence_times_out_with_an_error() {
        let (client, mut client_peer) = duplex(1024);
        let (remote, mut remote_peer) = duplex(1024);
        tokio::spawn(async move {
            client_peer.write_all(b"hello").await.unwrap();
            // Keep both peers open and silent.
            let mut sink = [0u8; 16];
            let _ = client_peer.read(&mut sink).await;
        });
        tokio::spawn(async move {
            let mut got = [0u8; 5];
            remote_peer.read_exact(&mut got).await.unwrap();
            let mut sink = [0u8; 16];
            let _ = remote_peer.read(&mut sink).await;
        });
        let out = relay_with_idle_timeout(client, remote, Some(Duration::from_secs(10))).await;
        assert_eq!(out.transferred.uploaded, 5);
        assert!(
            out.error
                .as_deref()
                .is_some_and(|e| e.contains("idle timeout")),
            "{:?}",
            out.error
        );
    }

    #[tokio::test]
    async fn half_close_keeps_the_other_direction_flowing() {
        // The client finishes its request, then the server streams a large
        // response. The request-side EOF must be forwarded as a half-close,
        // not tear down the response direction.
        let (client, mut client_peer) = duplex(4096);
        let (remote, mut remote_peer) = duplex(4096);
        let response = vec![7u8; 1_000_000];
        let expected = response.clone();
        let server = tokio::spawn(async move {
            let mut request = Vec::new();
            remote_peer.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"GET");
            remote_peer.write_all(&response).await.unwrap();
            remote_peer.shutdown().await.unwrap();
        });
        let client_task = tokio::spawn(async move {
            client_peer.write_all(b"GET").await.unwrap();
            client_peer.shutdown().await.unwrap();
            let mut body = Vec::new();
            client_peer.read_to_end(&mut body).await.unwrap();
            body
        });
        let out = relay(client, remote).await;
        server.await.unwrap();
        assert_eq!(client_task.await.unwrap(), expected);
        assert_eq!(out.transferred.downloaded, 1_000_000);
        assert_eq!(out.error, None);
    }

    #[test]
    fn buffers_return_to_the_pool_of_their_own_size() {
        let small = take_buffer(RELAY_SMALL_BUFFER_SIZE);
        let large = take_buffer(RELAY_BUFFER_SIZE);
        assert_eq!(small.len(), RELAY_SMALL_BUFFER_SIZE);
        assert_eq!(large.len(), RELAY_BUFFER_SIZE);
        recycle_buffer(small);
        recycle_buffer(large);
        // A foreign size is dropped, never pooled.
        recycle_buffer(vec![0u8; 3].into_boxed_slice());
        assert_eq!(
            take_buffer(RELAY_SMALL_BUFFER_SIZE).len(),
            RELAY_SMALL_BUFFER_SIZE
        );
        assert_eq!(take_buffer(RELAY_BUFFER_SIZE).len(), RELAY_BUFFER_SIZE);
    }
}
