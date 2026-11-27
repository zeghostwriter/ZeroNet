//! Port hopping for a QUIC endpoint's UDP socket.
//!
//! How this works. QUIC above this socket believes it talks to one server
//! address, `ip:nominal`. This socket sends every datagram to `ip:port` where
//! `port` is one of a set of server ports, and every few seconds it moves: it
//! opens a *new* local socket and sends to a new server port from then on.
//! What it receives has its source port turned back into `nominal`, so the
//! connection above never notices. To a filter that blocks or throttles a UDP
//! flow by its address pair, the flow keeps ending and a new one starting.
//!
//! Why a new local socket each time and not only a new destination port: the
//! server cooperates the way Hysteria's does, with a firewall rule that sends
//! the whole port range to the one port it listens on. That rule is NAT, and
//! NAT tells flows apart by their addresses. Two flows from the same local
//! port to two ports that map to the same listening port would have the same
//! reply path and the second would be dropped. A fresh local port makes each
//! hop a distinct flow, and the server sees the client's address change, which
//! QUIC handles as connection migration.
//!
//! The rule it keeps: only datagrams for the server's own `ip:nominal` are
//! moved. Anything else the endpoint sends passes untouched, through the
//! current socket.
//!
//! The surprise: the old socket is not closed at once. Datagrams already on
//! their way back to it still arrive and are mapped like the rest, so a hop
//! loses nothing; it is let go after [`LINGER`].

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::Rng;

/// How long a socket is still read from after the flow has moved on.
const LINGER: Duration = Duration::from_secs(10);

/// Where and how often to move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    /// The server ports to move between.
    pub ports: Vec<u16>,
    /// Each stay lasts a time drawn from this range.
    pub interval: (Duration, Duration),
}

/// Opens a fresh local socket for the next stay.
pub type SocketFactory = Box<dyn Fn() -> io::Result<Arc<dyn AsyncUdpSocket>> + Send + Sync>;

struct State {
    /// Which stay this is; a poller notices a change and starts over.
    generation: u64,
    current: Arc<dyn AsyncUdpSocket>,
    port: u16,
    until: Instant,
    /// The socket before this one, read from until the time given.
    previous: Option<(Arc<dyn AsyncUdpSocket>, Instant)>,
}

/// A UDP socket that moves the server port of the datagrams it carries.
pub struct HoppingSocket {
    open: SocketFactory,
    hop: Hop,
    server: SocketAddr,
    state: Mutex<State>,
}

impl fmt::Debug for HoppingSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HoppingSocket")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl HoppingSocket {
    /// `server` is the address the connection above was made to; its port is
    /// the nominal one. `open` makes the local socket for each stay.
    pub fn open(
        open: SocketFactory,
        hop: Hop,
        server: SocketAddr,
    ) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let current = open()?;
        let port = pick(&hop.ports, server.port());
        let until = Instant::now() + stay(&hop);
        Ok(Arc::new(Self {
            open,
            hop,
            server,
            state: Mutex::new(State {
                generation: 0,
                current,
                port,
                until,
                previous: None,
            }),
        }))
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The socket and port to send with now, moving on first if the stay is
    /// over. A socket that cannot be opened keeps the old one for another
    /// stay rather than losing the flow.
    fn current(&self) -> (Arc<dyn AsyncUdpSocket>, u16) {
        let mut state = self.state();
        let now = Instant::now();
        if now >= state.until {
            match (self.open)() {
                Ok(fresh) => {
                    let old = std::mem::replace(&mut state.current, fresh);
                    state.previous = Some((old, now + LINGER));
                    state.generation += 1;
                }
                Err(error) => tracing::debug!(%error, "port hop: no new socket; staying put"),
            }
            state.port = pick(&self.hop.ports, state.port);
            state.until = now + stay(&self.hop);
        }
        (Arc::clone(&state.current), state.port)
    }

    fn is_server_port(&self, port: u16) -> bool {
        port == self.server.port() || self.hop.ports.contains(&port)
    }

    fn map_source(&self, meta: &mut [RecvMeta], count: usize) {
        for received in meta.iter_mut().take(count) {
            if received.addr.ip() == self.server.ip() && self.is_server_port(received.addr.port()) {
                received.addr.set_port(self.server.port());
            }
        }
    }
}

/// A port from `ports` other than `avoid`, when there is another to take.
fn pick(ports: &[u16], avoid: u16) -> u16 {
    let candidates = ports.iter().filter(|port| **port != avoid).count();
    if candidates == 0 {
        return ports.first().copied().unwrap_or(avoid);
    }
    let mut index = rand::thread_rng().gen_range(0..candidates);
    for port in ports.iter().filter(|port| **port != avoid) {
        if index == 0 {
            return *port;
        }
        index -= 1;
    }
    avoid
}

fn stay(hop: &Hop) -> Duration {
    let (low, high) = hop.interval;
    if high <= low {
        return low;
    }
    rand::thread_rng().gen_range(low..=high)
}

/// Waits for the *current* socket to be writable, whichever it is.
struct HopPoller {
    socket: Arc<HoppingSocket>,
    seen: Option<(u64, Pin<Box<dyn UdpPoller>>)>,
}

impl fmt::Debug for HopPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HopPoller")
    }
}

impl UdpPoller for HopPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let (generation, current) = {
            let state = self.socket.state();
            (state.generation, Arc::clone(&state.current))
        };
        if self
            .seen
            .as_ref()
            .is_none_or(|(seen, _)| *seen != generation)
        {
            self.seen = Some((generation, current.create_io_poller()));
        }
        match self.seen.as_mut() {
            Some((_, poller)) => poller.as_mut().poll_writable(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncUdpSocket for HoppingSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(HopPoller {
            socket: self,
            seen: None,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let (socket, port) = self.current();
        if transmit.destination != self.server {
            return socket.try_send(transmit);
        }
        let mut destination = transmit.destination;
        destination.set_port(port);
        socket.try_send(&Transmit {
            destination,
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (current, previous) = {
            let mut state = self.state();
            if state
                .previous
                .as_ref()
                .is_some_and(|(_, gone)| Instant::now() >= *gone)
            {
                state.previous = None;
            }
            (
                Arc::clone(&state.current),
                state
                    .previous
                    .as_ref()
                    .map(|(socket, _)| Arc::clone(socket)),
            )
        };
        // Both are polled so both wake this task; the old socket first, as
        // what it still holds was sent earlier.
        if let Some(previous) = previous {
            if let Poll::Ready(Ok(count)) = previous.poll_recv(cx, bufs, meta) {
                self.map_source(meta, count);
                return Poll::Ready(Ok(count));
            }
        }
        match current.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => {
                self.map_source(meta, count);
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        let current = Arc::clone(&self.state().current);
        current.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        Arc::clone(&self.state().current).max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        Arc::clone(&self.state().current).max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        Arc::clone(&self.state().current).may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::Runtime;

    #[test]
    fn a_pick_is_in_the_set_and_never_the_port_just_left() {
        let ports = [1000u16, 1001, 1002, 1003];
        for _ in 0..200 {
            let next = pick(&ports, 1001);
            assert!(ports.contains(&next) && next != 1001);
        }
        // A single port has nowhere else to go.
        assert_eq!(pick(&[443], 443), 443);
    }

    #[test]
    fn a_stay_is_drawn_inside_its_range() {
        let hop = Hop {
            ports: vec![1, 2],
            interval: (Duration::from_secs(5), Duration::from_secs(10)),
        };
        for _ in 0..100 {
            let stay = stay(&hop);
            assert!(stay >= Duration::from_secs(5) && stay <= Duration::from_secs(10));
        }
    }

    fn factory() -> SocketFactory {
        Box::new(|| {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
            quinn::TokioRuntime.wrap_udp_socket(socket)
        })
    }

    async fn send(socket: &Arc<dyn AsyncUdpSocket>, to: SocketAddr, body: &'static [u8]) {
        loop {
            let sent = socket.try_send(&Transmit {
                destination: to,
                ecn: None,
                contents: body,
                segment_size: None,
                src_ip: None,
            });
            match sent {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await
                }
                other => break other.unwrap(),
            }
        }
    }

    /// Two plain UDP sockets stand in for the server's listening port and a
    /// hopped one: the client sends to the nominal address, and the server
    /// sees both the port and the source address move while the client
    /// always sees one server.
    #[tokio::test]
    async fn the_server_sees_the_flow_move_and_the_client_sees_one_server() {
        let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (port_a, port_b) = (
            a.local_addr().unwrap().port(),
            b.local_addr().unwrap().port(),
        );
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        // Nominal port: one nobody listens on, as with a real range.
        let nominal = SocketAddr::from(([127, 0, 0, 1], 9));
        let socket = HoppingSocket::open(
            factory(),
            Hop {
                ports: vec![port_a, port_b],
                interval: (Duration::from_millis(60), Duration::from_millis(60)),
            },
            nominal,
        )
        .unwrap();
        let mut reached = std::collections::HashSet::new();
        let mut sources = std::collections::HashSet::new();
        for _ in 0..60 {
            send(&socket, nominal, b"ping").await;
            tokio::time::sleep(Duration::from_millis(15)).await;
            let mut buf = [0u8; 16];
            for (socket, port) in [(&a, port_a), (&b, port_b)] {
                if let Ok((n, from)) = socket.recv_from(&mut buf) {
                    assert_eq!(&buf[..n], b"ping");
                    reached.insert(port);
                    sources.insert(from);
                }
            }
        }
        assert_eq!(
            reached.len(),
            2,
            "the flow never moved between server ports"
        );
        assert!(
            sources.len() >= 2,
            "the local port stayed the same, so NAT would see one flow"
        );
    }

    /// A reply from a hopped server port, to the client's current socket,
    /// reads as coming from the nominal address.
    #[tokio::test]
    async fn a_reply_from_a_hopped_port_reads_as_the_nominal_server() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let hopped = server.local_addr().unwrap().port();
        let nominal = SocketAddr::from(([127, 0, 0, 1], 9));
        let socket = HoppingSocket::open(
            factory(),
            Hop {
                ports: vec![hopped],
                interval: (Duration::from_secs(60), Duration::from_secs(60)),
            },
            nominal,
        )
        .unwrap();
        send(&socket, nominal, b"hello").await;
        let mut buf = [0u8; 16];
        let from = loop {
            match server.recv_from(&mut buf) {
                Ok((_, from)) => break from,
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        };
        server.send_to(b"pong", from).unwrap();
        let mut storage = [0u8; 16];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];
        let received = tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .expect("the reply never arrived")
        .unwrap();
        assert_eq!(received, 1);
        assert_eq!(meta[0].addr, nominal);
    }

    #[tokio::test]
    async fn the_poller_follows_the_socket_the_flow_moved_to() {
        let nominal = SocketAddr::from(([127, 0, 0, 1], 9));
        let socket = HoppingSocket::open(
            factory(),
            Hop {
                ports: vec![5000, 5001],
                interval: (Duration::from_millis(20), Duration::from_millis(20)),
            },
            nominal,
        )
        .unwrap();
        let mut poller = Arc::clone(&socket).create_io_poller();
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(30)).await;
            send(&socket, nominal, b"x").await;
            std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                .await
                .unwrap();
        }
    }
}
