//! The running tunnel: a pool of workers, each sending one packet and reading
//! the one that answers it, and the stream handles the caller holds.
//!
//! How it works: [`Client::connect`] probes the resolvers and runs the
//! handshake (see `bringup`), then starts `workers` tasks. A worker asks the
//! shared [`Core`] for the next packet, sends it as a DNS question to a usable
//! resolver (round robin), and hands whatever the answer carries back to the
//! core. When nothing is queued the core supplies a keep-alive `PING`, so the
//! workers also *poll* the server, which is the only way downstream data
//! arrives.
//!
//! A stream is a plain [`Stream`] (one end of an in-memory pipe): the caller
//! reads and writes it like a socket. Two small tasks per stream move bytes
//! between the other end of the pipe and the core.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf};
use tokio::sync::{mpsc, oneshot, Notify, OwnedSemaphorePermit, Semaphore};
use zero_protocol::masterdns::enums::PACKET_SESSION_CLOSE;
use zero_protocol::masterdns::packet::BuildOptions;
use zero_protocol::masterdns::socks::{
    build_target_payload, Target, ADDRESS_TYPE_DOMAIN, ADDRESS_TYPE_IPV4, ADDRESS_TYPE_IPV6,
};

use super::bringup::bring_up;
use super::core::{Core, StreamPorts};
use super::wire::{Wire, QUERY_TIMEOUT};
use super::{Config, Error};
use crate::carrier::is_dns_response;

/// One tunnelled connection: read and write it like a socket.
pub type Stream = DuplexStream;

/// How long a stream may wait for the server to say it is connected.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
/// Buffered bytes between a stream's owner and the tunnel, each way.
const PIPE_BYTES: usize = 128 * 1024;

struct Shared {
    core: Mutex<Core>,
    wake: Notify,
    stop: AtomicBool,
    stop_signal: Notify,
    wire: Arc<Wire>,
    resolvers: Vec<SocketAddr>,
    next_resolver: AtomicUsize,
    session_id: u8,
    cookie: u8,
}

impl Shared {
    fn core(&self) -> MutexGuard<'_, Core> {
        self.core
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.stop_signal.notify_waiters();
        self.wake.notify_waiters();
    }

    /// The next packet for a free worker, waiting for one if the queue is empty.
    async fn next_work(&self) -> Option<super::core::Out> {
        loop {
            let wait = {
                let mut core = self.core();
                let now = Instant::now();
                core.tick(now);
                if let Some(out) = core.next_out(now) {
                    return Some(out);
                }
                core.next_check(now)
            };
            if self.stopped() {
                return None;
            }
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(wait) => {}
                _ = self.stop_signal.notified() => return None,
            }
        }
    }
}

/// A live MasterDNS tunnel. Dropping it ends the session.
pub struct Client {
    shared: Arc<Shared>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}

impl Client {
    /// Probe the resolvers, agree a session with the server and start the
    /// workers. Fails with [`Error::NoResolver`] when no resolver passes a
    /// probe, and with [`Error::NoSession`] when the server never accepts.
    pub async fn connect(cfg: Config) -> Result<Client, Error> {
        let up = bring_up(&cfg).await?;
        let shared = Arc::new(Shared {
            core: Mutex::new(Core::new(up.tuning, cfg.mode, Instant::now())),
            wake: Notify::new(),
            stop: AtomicBool::new(false),
            stop_signal: Notify::new(),
            wire: up.wire,
            resolvers: up.resolvers,
            next_resolver: AtomicUsize::new(0),
            session_id: up.session_id,
            cookie: up.cookie,
        });
        for _ in 0..cfg.workers.max(1) {
            tokio::spawn(worker(shared.clone()));
        }
        Ok(Client { shared })
    }

    /// Whether the tunnel is still usable (the server still knows the session).
    pub fn is_alive(&self) -> bool {
        !self.shared.stopped() && self.shared.core().dead.is_none()
    }

    /// How many streams are open.
    pub fn streams(&self) -> usize {
        self.shared.core().stream_count()
    }

    /// Open a connection to `host:port` through the server.
    pub async fn open(&self, host: &str, port: u16) -> Result<Stream, Error> {
        let (address_type, host) = match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => (ADDRESS_TYPE_IPV4, ip.to_string()),
            Ok(IpAddr::V6(ip)) => (ADDRESS_TYPE_IPV6, ip.to_string()),
            Err(_) => (ADDRESS_TYPE_DOMAIN, host.to_string()),
        };
        let target = build_target_payload(&Target {
            address_type,
            host,
            port,
        });
        let (user_end, inner) = tokio::io::duplex(PIPE_BYTES);
        let (inner_read, inner_write) = tokio::io::split(inner);
        let (to_user, from_core) = mpsc::unbounded_channel();
        let (connect_tx, connect_rx) = oneshot::channel();
        let waker = Arc::new(Notify::new());

        let id = self.shared.core().open(
            &target,
            StreamPorts {
                to_user,
                connect: connect_tx,
                waker: waker.clone(),
            },
            Instant::now(),
        )?;
        self.shared.wake.notify_one();
        tokio::spawn(downlink(from_core, inner_write));

        match tokio::time::timeout(CONNECT_TIMEOUT, connect_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => return Err(error),
            Ok(Err(_)) => return Err(Error::Closed),
            Err(_) => {
                self.shared
                    .core()
                    .abort(id, "connect timed out", Instant::now());
                self.shared.wake.notify_one();
                return Err(Error::Timeout);
            }
        }
        tokio::spawn(uplink(inner_read, self.shared.clone(), id, waker));
        Ok(user_end)
    }

    /// End the session: stop the workers and tell the server, best effort.
    pub fn close(&self) {
        if self.shared.stop.swap(true, Ordering::AcqRel) {
            return;
        }
        self.shared.stop_signal.notify_waiters();
        self.shared.wake.notify_waiters();
        let shared = &self.shared;
        let Some(&resolver) = shared.resolvers.first() else {
            return;
        };
        let Ok(question) = shared.wire.question(&BuildOptions {
            session_id: shared.session_id,
            session_cookie: shared.cookie,
            packet_type: PACKET_SESSION_CLOSE,
            ..BuildOptions::default()
        }) else {
            return;
        };
        if let Ok(socket) = zero_core::bind_protected_udp(SocketAddr::from(([0, 0, 0, 0], 0))) {
            for _ in 0..3 {
                let _ = socket.send_to(&question, resolver);
            }
        }
    }
}

/// Bytes the core delivers go to the stream's owner; the end of the channel is
/// the end of the stream.
async fn downlink(
    mut from_core: mpsc::UnboundedReceiver<Vec<u8>>,
    mut sink: tokio::io::WriteHalf<DuplexStream>,
) {
    while let Some(bytes) = from_core.recv().await {
        if sink.write_all(&bytes).await.is_err() {
            return;
        }
    }
    let _ = sink.shutdown().await;
}

/// The owner's bytes go into the core, a chunk at a time, waiting whenever the
/// stream's send window is full.
async fn uplink(
    mut source: ReadHalf<DuplexStream>,
    shared: Arc<Shared>,
    id: u16,
    waker: Arc<Notify>,
) {
    let chunk = shared.core().chunk();
    let mut buffer = vec![0u8; chunk];
    'outer: loop {
        // Wait for room before reading, so the pipe applies the back-pressure.
        loop {
            let room = shared.core().can_send(id);
            match room {
                None => break 'outer,
                Some(true) => break,
                Some(false) => {
                    let _ =
                        tokio::time::timeout(Duration::from_millis(200), waker.notified()).await;
                }
            }
        }
        let n = match source.read(&mut buffer).await {
            Ok(0) => {
                shared.core().finish(id, Instant::now());
                shared.wake.notify_one();
                return;
            }
            Ok(n) => n,
            Err(_) => break,
        };
        loop {
            let sent = shared.core().send(id, &buffer[..n], Instant::now());
            match sent {
                Ok(true) => break,
                Ok(false) => {
                    let _ =
                        tokio::time::timeout(Duration::from_millis(200), waker.notified()).await;
                }
                // The stream is gone, or the server stopped reading: nothing
                // more can be sent, and the close machine owns what follows.
                Err(_) => return,
            }
        }
        shared.wake.notify_one();
    }
    // The owner's end broke without a clean close: reset the stream.
    shared
        .core()
        .abort(id, "local connection failed", Instant::now());
    shared.wake.notify_one();
}

/// Queries one worker may have outstanding at once. A lost query or answer
/// holds its slot until it expires, so this is also how much loss one worker
/// can absorb before it idles.
const IN_FLIGHT_PER_WORKER: usize = 6;

/// A query that has been sent and not yet answered. The permit is returned to
/// the worker when any answer arrives or the query expires.
type Pending = Arc<Mutex<VecDeque<(Instant, OwnedSemaphorePermit)>>>;

/// One worker: a socket with a sender loop and a receiver task. They are
/// separate on purpose: if one loop both sent and waited, a single lost
/// datagram would hold the worker for the whole timeout and loss would
/// collapse throughput; this way a lost query only costs its own slot.
async fn worker(shared: Arc<Shared>) {
    let Ok(std_socket) = zero_core::bind_protected_udp(SocketAddr::from(([0, 0, 0, 0], 0))) else {
        return;
    };
    if std_socket.set_nonblocking(true).is_err() {
        return;
    }
    let Ok(socket) = tokio::net::UdpSocket::from_std(std_socket) else {
        return;
    };
    let socket = Arc::new(socket);
    let slots = Arc::new(Semaphore::new(IN_FLIGHT_PER_WORKER));
    let pending: Pending = Arc::default();
    tokio::spawn(receiver(shared.clone(), socket.clone(), pending.clone()));

    loop {
        // Free the slots of queries that will never be answered.
        {
            let mut queue = pending.lock().unwrap_or_else(|p| p.into_inner());
            while queue
                .front()
                .is_some_and(|(sent, _)| sent.elapsed() > QUERY_TIMEOUT)
            {
                queue.pop_front();
            }
        }
        if shared.stopped() {
            return;
        }
        let permit =
            match tokio::time::timeout(Duration::from_millis(100), slots.clone().acquire_owned())
                .await
            {
                Ok(Ok(permit)) => permit,
                _ => continue,
            };
        let Some(out) = shared.next_work().await else {
            return;
        };
        let Ok(question) = shared
            .wire
            .question(&out.options(shared.session_id, shared.cookie))
        else {
            continue;
        };
        let at = shared.next_resolver.fetch_add(1, Ordering::Relaxed) % shared.resolvers.len();
        if socket
            .send_to(&question, shared.resolvers[at])
            .await
            .is_ok()
        {
            pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push_back((Instant::now(), permit));
        }
    }
}

/// Read answers for one worker's socket and hand them to the core.
async fn receiver(shared: Arc<Shared>, socket: Arc<tokio::net::UdpSocket>, pending: Pending) {
    let mut buffer = vec![0u8; 65535];
    loop {
        let received = tokio::select! {
            r = socket.recv_from(&mut buffer) => r,
            _ = shared.stop_signal.notified() => return,
        };
        let Ok((len, _)) = received else {
            if shared.stopped() {
                return;
            }
            continue;
        };
        if !is_dns_response(&buffer[..len]) {
            continue;
        }
        // Whatever answered, one slot is free again.
        pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front();
        let replies = shared.wire.replies(&buffer[..len]);
        let mut core = shared.core();
        let now = Instant::now();
        for reply in replies {
            core.handle_reply(reply, now);
        }
        let (dead, queued) = (core.dead.is_some(), core.has_queued());
        drop(core);
        if dead {
            shared.stop();
            return;
        }
        if queued {
            shared.wake.notify_one();
        }
    }
}
