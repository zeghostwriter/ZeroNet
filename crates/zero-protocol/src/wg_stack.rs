//! TCP, UDP and DNS through a WireGuard (or AmneziaWG) tunnel, in user space.
//!
//! WireGuard carries IP packets, not streams. To proxy a TCP connection
//! through it — which is what makes a WireGuard exit such as Cloudflare WARP
//! useful as a fallback — the client needs a TCP/IP stack of its own. This
//! module runs one: a [`WgStack`] is a single driver task that owns
//!
//! * the WireGuard state (boringtun) and its one UDP socket,
//! * a smoltcp interface holding the tunnel address(es),
//! * every TCP and UDP socket opened through the tunnel.
//!
//! Everything shares that one WireGuard session. That is not only cheaper, it
//! is required: a WireGuard peer keeps one session per key, so a second
//! session with the same key (say, one for UDP and one for TCP) would keep
//! replacing the first.
//!
//! Costs are kept flat on purpose, for phones:
//!
//! * one task per tunnel, woken by the network, by a stream with data, or by
//!   the stack's own timers — never a polling loop;
//! * packet buffers of a few KiB, reused (the tunnel MTU is 1280), instead of
//!   64 KiB scratch buffers;
//! * per-stream TCP buffers bounded ([`TCP_RX_BUFFER`], [`TCP_TX_BUFFER`]),
//!   with backpressure through bounded channels: a slow reader closes the TCP
//!   window rather than growing a queue;
//! * an idle tunnel ([`IDLE_SHUTDOWN`] with nothing open) shuts itself down.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use bytes::Bytes;
use rand::SeedableRng;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};

use crate::amnezia::{self, AmneziaParams};

/// The tunnel MTU. WARP (and most WireGuard setups) use 1280, the IPv6
/// minimum, which survives every path.
pub const TUNNEL_MTU: usize = 1280;
/// Receive window of one TCP connection through the tunnel. Large enough for
/// a few Mbit/s at the round trips of a WARP path, small enough that fifty
/// open connections stay under ten megabytes.
pub const TCP_RX_BUFFER: usize = 128 * 1024;
/// Send buffer of one TCP connection.
pub const TCP_TX_BUFFER: usize = 64 * 1024;
/// A tunnel with nothing open for this long shuts down.
pub const IDLE_SHUTDOWN: Duration = Duration::from_secs(5 * 60);
/// How long a TCP connect through the tunnel may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
/// How long a UDP exchange waits for its answer.
const UDP_TIMEOUT: Duration = Duration::from_secs(6);
/// WireGuard's own timers (handshake retries, keepalives) are driven this often.
const WG_TIMER_TICK: Duration = Duration::from_millis(250);
/// Largest UDP datagram read from the network: an MTU-sized packet plus
/// WireGuard overhead and the largest AmneziaWG padding.
const NETWORK_BUFFER: usize = 4096;
/// Chunks queued between a stream and the driver, each way.
const STREAM_QUEUE: usize = 8;
/// Largest chunk handed to a stream at once.
const DOWN_CHUNK: usize = 16 * 1024;
/// A resolved name is reused at most this long, whatever its TTL says.
const DNS_CACHE_MAX_TTL: Duration = Duration::from_secs(300);
const DNS_CACHE_ENTRIES: usize = 256;

/// What a tunnel needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgStackParams {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// The tunnel's own addresses (WARP hands out one of each family).
    pub addresses: Vec<IpAddr>,
    pub persistent_keepalive: Option<u16>,
    pub obfuscation: AmneziaParams,
    /// The three "reserved" bytes of every WireGuard message, which
    /// Cloudflare WARP uses as a client id. Zero for ordinary WireGuard.
    pub reserved: [u8; 3],
    /// Resolver reached through the tunnel for names (WARP: 1.1.1.1).
    pub dns: SocketAddr,
}

enum Command {
    Connect {
        destination: SocketAddr,
        reply: oneshot::Sender<Result<StreamIo, String>>,
    },
    Udp {
        destination: SocketAddr,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(SocketAddr, Vec<u8>), String>>,
    },
    /// Move to a fresh UDP socket (the device changed networks). WireGuard
    /// roams: the peer follows the first authenticated packet from the new
    /// address.
    Rebind,
}

/// The two ends a stream task and the driver exchange data through.
pub struct StreamIo {
    up: mpsc::Sender<Bytes>,
    down: mpsc::Receiver<Bytes>,
    wake: Arc<Notify>,
}

/// A running tunnel. Cheap to clone; the driver stops when every clone is
/// gone or after [`IDLE_SHUTDOWN`] with nothing open.
#[derive(Clone)]
pub struct WgStack {
    commands: mpsc::UnboundedSender<Command>,
    wake: Arc<Notify>,
    alive: Arc<AtomicBool>,
    dns: SocketAddr,
    family_v4: bool,
    family_v6: bool,
    cache: Arc<StdMutex<HashMap<String, (Vec<IpAddr>, Instant)>>>,
}

impl WgStack {
    /// Start a tunnel to `peer`. The WireGuard handshake happens with the
    /// first packet; this only binds the socket and spawns the driver.
    pub fn start(peer: SocketAddr, params: WgStackParams) -> Result<Self, String> {
        params.obfuscation.validate()?;
        if params.addresses.is_empty() {
            return Err("WireGuard tunnel has no address".into());
        }
        let socket = bind_for(peer)?;
        let (commands, receiver) = mpsc::unbounded_channel();
        let wake = Arc::new(Notify::new());
        let alive = Arc::new(AtomicBool::new(true));
        let stack = Self {
            commands,
            wake: Arc::clone(&wake),
            alive: Arc::clone(&alive),
            dns: params.dns,
            family_v4: params.addresses.iter().any(IpAddr::is_ipv4),
            family_v6: params.addresses.iter().any(IpAddr::is_ipv6),
            cache: Arc::default(),
        };
        let driver = Driver::new(socket, peer, params, receiver, wake);
        tokio::spawn(async move {
            driver.run().await;
            alive.store(false, Ordering::Release);
        });
        Ok(stack)
    }

    /// Whether the driver is still running.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire) && !self.commands.is_closed()
    }

    /// Move to a new UDP socket after a network change.
    pub fn rebind(&self) {
        let _ = self.commands.send(Command::Rebind);
    }

    /// Open a TCP connection through the tunnel.
    pub async fn connect(&self, destination: SocketAddr) -> Result<zero_core::BoxStream, String> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Connect { destination, reply })
            .map_err(|_| "WireGuard tunnel is closed".to_string())?;
        self.wake.notify_one();
        let io = answer.await.map_err(|_| "WireGuard tunnel is closed".to_string())??;
        Ok(stream_from(io))
    }

    /// Send one UDP datagram through the tunnel and wait for the answer.
    pub async fn exchange_udp(&self, destination: SocketAddr, payload: &[u8]) -> Result<(SocketAddr, Vec<u8>), String> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Udp {
                destination,
                payload: payload.to_vec(),
                reply,
            })
            .map_err(|_| "WireGuard tunnel is closed".to_string())?;
        self.wake.notify_one();
        answer.await.map_err(|_| "WireGuard tunnel is closed".to_string())?
    }

    /// Resolve `name` with the resolver inside the tunnel, so the lookup is
    /// neither visible to nor poisoned by the local network.
    pub async fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, String> {
        let key = name.trim_end_matches('.').to_ascii_lowercase();
        if let Some((addresses, until)) = lock(&self.cache).get(&key) {
            if *until > Instant::now() {
                return Ok(addresses.clone());
            }
        }
        let mut addresses = Vec::new();
        let mut ttl = DNS_CACHE_MAX_TTL;
        let mut last_error = String::from("no address family in the tunnel");
        for (wanted, qtype) in [(self.family_v4, 1u16), (self.family_v6, 28u16)] {
            if !wanted {
                continue;
            }
            let id: u16 = rand::random();
            let query = dns_query(id, &key, qtype)?;
            match self.exchange_udp(self.dns, &query).await {
                Ok((_, answer)) => match dns_answer(&answer, id, qtype) {
                    Ok((found, answer_ttl)) => {
                        ttl = ttl.min(answer_ttl);
                        addresses.extend(found);
                    }
                    Err(error) => last_error = error,
                },
                Err(error) => last_error = error,
            }
            // An IPv4 answer is enough to connect; skip the second round trip.
            if !addresses.is_empty() {
                break;
            }
        }
        if addresses.is_empty() {
            return Err(format!("resolving {key} through the tunnel: {last_error}"));
        }
        let mut cache = lock(&self.cache);
        if cache.len() >= DNS_CACHE_ENTRIES {
            let now = Instant::now();
            cache.retain(|_, (_, until)| *until > now);
            if cache.len() >= DNS_CACHE_ENTRIES {
                cache.clear();
            }
        }
        cache.insert(key, (addresses.clone(), Instant::now() + ttl.max(Duration::from_secs(10))));
        Ok(addresses)
    }

    /// Connect to a host (name or address) and port through the tunnel.
    pub async fn connect_host(&self, host: &zero_core::Address, port: u16) -> Result<zero_core::BoxStream, String> {
        let addresses = match host {
            zero_core::Address::Ip(ip) => vec![*ip],
            zero_core::Address::Domain(name) => self.resolve(name).await?,
        };
        let mut last = String::from("no usable address");
        for ip in addresses.into_iter().filter(|ip| self.carries(*ip)).take(2) {
            match self.connect(SocketAddr::new(ip, port)).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Whether the tunnel has an address of `ip`'s family.
    pub fn carries(&self, ip: IpAddr) -> bool {
        if ip.is_ipv4() {
            self.family_v4
        } else {
            self.family_v6
        }
    }
}

/// Running tunnels, one per peer and parameter set, shared by every stream
/// and datagram of an outbound.
static SHARED: std::sync::LazyLock<StdMutex<Vec<(SocketAddr, WgStackParams, WgStack)>>> =
    std::sync::LazyLock::new(Default::default);

/// The running tunnel to `peer` with `params`, started if there is none (or
/// the last one shut down).
pub fn shared(peer: SocketAddr, params: WgStackParams) -> Result<WgStack, String> {
    let mut tunnels = lock(&SHARED);
    tunnels.retain(|(_, _, stack)| stack.is_alive());
    if let Some((_, _, stack)) = tunnels.iter().find(|(p, q, _)| *p == peer && *q == params) {
        return Ok(stack.clone());
    }
    let stack = WgStack::start(peer, params.clone())?;
    tunnels.push((peer, params, stack.clone()));
    Ok(stack)
}

/// After a network change: move every running tunnel to a fresh socket.
/// Returns how many were asked to move.
pub fn rebind_all() -> usize {
    let tunnels = lock(&SHARED);
    let mut moved = 0;
    for (_, _, stack) in tunnels.iter().filter(|(_, _, s)| s.is_alive()) {
        stack.rebind();
        moved += 1;
    }
    moved
}

fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn bind_for(peer: SocketAddr) -> Result<UdpSocket, String> {
    let bind: SocketAddr = if peer.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    // Protected: the tunnel's own packets must reach the real network, not
    // the VPN they may be standing in for.
    let socket = zero_core::platform::bind_protected_udp(bind).map_err(|error| format!("WireGuard UDP bind: {error}"))?;
    socket.set_nonblocking(true).map_err(|error| format!("WireGuard UDP bind: {error}"))?;
    UdpSocket::from_std(socket).map_err(|error| format!("WireGuard UDP bind: {error}"))
}

/// The application end of a tunnelled TCP connection: a duplex pipe whose
/// other end one small task pumps to and from the driver.
fn stream_from(io: StreamIo) -> zero_core::BoxStream {
    let (app, worker) = tokio::io::duplex(32 * 1024);
    let StreamIo { up, mut down, wake } = io;
    let (mut reader, mut writer) = tokio::io::split(worker);
    let up_wake = Arc::clone(&wake);
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up.send(Bytes::copy_from_slice(&buffer[..n])).await.is_err() {
                        break;
                    }
                    up_wake.notify_one();
                }
            }
        }
        // Dropping `up` tells the driver the application finished sending.
        drop(up);
        up_wake.notify_one();
    });
    tokio::spawn(async move {
        while let Some(chunk) = down.recv().await {
            // Space freed in the queue: the driver may read more.
            wake.notify_one();
            if writer.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });
    zero_core::boxed(app)
}

// ------------------------------------------------------------------ device

/// A smoltcp device over two packet queues: packets decrypted from the
/// tunnel go in, packets for the tunnel come out. Buffers are recycled.
struct QueueDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    spare: Vec<Vec<u8>>,
}

impl QueueDevice {
    fn new() -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            spare: Vec::new(),
        }
    }

    fn buffer(&mut self) -> Vec<u8> {
        let mut buffer = self.spare.pop().unwrap_or_else(|| Vec::with_capacity(TUNNEL_MTU));
        buffer.clear();
        buffer
    }

    fn recycle(&mut self, buffer: Vec<u8>) {
        if self.spare.len() < 64 && buffer.capacity() <= 2 * TUNNEL_MTU {
            self.spare.push(buffer);
        }
    }
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut QueueDevice);

impl RxToken for Rx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = self.0.buffer();
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        self.0.outbound.push_back(buffer);
        result
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = Rx where Self: 'a;
    type TxToken<'a> = Tx<'a> where Self: 'a;

    fn receive(&mut self, _now: smoltcp::time::Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((Rx(packet), Tx(self)))
    }

    fn transmit(&mut self, _now: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(Tx(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = TUNNEL_MTU;
        caps
    }
}

// ------------------------------------------------------------------ driver

struct TcpSlot {
    handle: SocketHandle,
    /// Chunks the application sent, not yet in the socket.
    up: Option<mpsc::Receiver<Bytes>>,
    pending: Option<(Bytes, usize)>,
    down: Option<mpsc::Sender<Bytes>>,
    /// Waiting for the handshake: the connect's answer and its deadline.
    reply: Option<(oneshot::Sender<Result<StreamIo, String>>, Instant, StreamIo)>,
}

struct UdpSlot {
    handle: SocketHandle,
    reply: Option<oneshot::Sender<Result<(SocketAddr, Vec<u8>), String>>>,
    deadline: Instant,
}

struct Driver {
    socket: UdpSocket,
    peer: SocketAddr,
    tunnel: Tunn,
    params: WgStackParams,
    /// Standard WireGuard framing (no AmneziaWG padding or headers): packets
    /// go out without re-encoding, and the reserved bytes apply.
    plain: bool,
    device: QueueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: Vec<TcpSlot>,
    udp: Vec<UdpSlot>,
    commands: mpsc::UnboundedReceiver<Command>,
    wake: Arc<Notify>,
    rng: rand::rngs::StdRng,
    next_port: u16,
    started: Instant,
    last_activity: Instant,
    /// Reused buffers: WireGuard output, decrypted input, network input.
    out: Vec<u8>,
    clear: Vec<u8>,
    network: Vec<u8>,
}

impl Driver {
    fn new(
        socket: UdpSocket,
        peer: SocketAddr,
        params: WgStackParams,
        commands: mpsc::UnboundedReceiver<Command>,
        wake: Arc<Notify>,
    ) -> Self {
        let tunnel = Tunn::new(
            boringtun::x25519::StaticSecret::from(params.private_key),
            boringtun::x25519::PublicKey::from(params.peer_public_key),
            params.preshared_key,
            params.persistent_keepalive,
            rand::random(),
            None,
        );
        let mut device = QueueDevice::new();
        let started = Instant::now();
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, smoltcp::time::Instant::from_millis(0));
        iface.update_ip_addrs(|addresses| {
            for address in &params.addresses {
                let prefix = if address.is_ipv4() { 32 } else { 128 };
                let _ = addresses.push(IpCidr::new(IpAddress::from(*address), prefix));
            }
        });
        // A point-to-point link: everything goes to the peer. On an IP
        // medium the gateway is never resolved, so any address serves.
        if params.addresses.iter().any(IpAddr::is_ipv4) {
            let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Addr::new(169, 254, 0, 1));
        }
        if params.addresses.iter().any(IpAddr::is_ipv6) {
            let _ = iface
                .routes_mut()
                .add_default_ipv6_route(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        }
        let standard = AmneziaParams::default();
        let o = params.obfuscation;
        let plain = o.init_padding == standard.init_padding
            && o.response_padding == standard.response_padding
            && o.cookie_padding == standard.cookie_padding
            && o.transport_padding == standard.transport_padding
            && o.init_header == standard.init_header
            && o.response_header == standard.response_header
            && o.cookie_header == standard.cookie_header
            && o.transport_header == standard.transport_header;
        Self {
            socket,
            peer,
            tunnel,
            params,
            plain,
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            tcp: Vec::new(),
            udp: Vec::new(),
            commands,
            wake,
            rng: rand::rngs::StdRng::from_entropy(),
            next_port: 40000 + rand::random::<u16>() % 20000,
            started,
            last_activity: started,
            out: vec![0u8; NETWORK_BUFFER],
            clear: vec![0u8; NETWORK_BUFFER],
            network: vec![0u8; NETWORK_BUFFER],
        }
    }

    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_millis(self.started.elapsed().as_millis() as i64)
    }

    async fn run(mut self) {
        let mut next_timer = Instant::now();
        loop {
            // Timers first: a handshake that must be (re)sent goes out now.
            if Instant::now() >= next_timer {
                self.wireguard_timers().await;
                next_timer = Instant::now() + WG_TIMER_TICK;
            }
            self.pump().await;

            let idle = self.tcp.is_empty() && self.udp.is_empty();
            if idle && self.last_activity.elapsed() >= IDLE_SHUTDOWN {
                return;
            }
            let stack_delay = self
                .iface
                .poll_delay(self.now(), &self.sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(Duration::from_secs(1));
            let timer_delay = next_timer.saturating_duration_since(Instant::now());
            let delay = stack_delay.min(timer_delay).max(Duration::from_millis(1));

            let mut network = std::mem::take(&mut self.network);
            let wake = Arc::clone(&self.wake);
            tokio::select! {
                received = self.socket.recv_from(&mut network) => {
                    if let Ok((length, source)) = received {
                        self.from_network(&mut network[..length], source).await;
                    }
                }
                command = self.commands.recv() => match command {
                    Some(command) => self.command(command),
                    // Every handle is gone.
                    None => {
                        self.network = network;
                        return;
                    }
                },
                _ = wake.notified() => {}
                _ = tokio::time::sleep(delay) => {}
            }
            self.network = network;
        }
    }

    /// Move data between the stack, the sockets and the network until nothing
    /// is left to do right now.
    async fn pump(&mut self) {
        for _ in 0..8 {
            let now = self.now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            let moved = self.service();
            let now = self.now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            let sent = self.flush().await;
            if !moved && !sent && self.device.inbound.is_empty() {
                break;
            }
        }
    }

    async fn wireguard_timers(&mut self) {
        loop {
            match self.tunnel.update_timers(&mut self.out) {
                TunnResult::WriteToNetwork(packet) => {
                    let packet = packet.to_vec();
                    self.send(&packet).await;
                }
                TunnResult::Err(boringtun::noise::errors::WireGuardError::ConnectionExpired) => {
                    // No session for a long while; the next packet starts one.
                    break;
                }
                _ => break,
            }
        }
    }

    fn command(&mut self, command: Command) {
        self.last_activity = Instant::now();
        match command {
            Command::Connect { destination, reply } => {
                if !self.params.addresses.iter().any(|a| a.is_ipv4() == destination.is_ipv4()) {
                    let _ = reply.send(Err(format!("the tunnel has no address for {destination}")));
                    return;
                }
                let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]),
                    tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]),
                );
                socket.set_nagle_enabled(false);
                socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
                let port = self.port();
                let remote = IpEndpoint::new(IpAddress::from(destination.ip()), destination.port());
                if let Err(error) = socket.connect(self.iface.context(), remote, port) {
                    let _ = reply.send(Err(format!("TCP connect through the tunnel: {error}")));
                    return;
                }
                let handle = self.sockets.add(socket);
                let (up_tx, up_rx) = mpsc::channel(STREAM_QUEUE);
                let (down_tx, down_rx) = mpsc::channel(STREAM_QUEUE);
                let io = StreamIo {
                    up: up_tx,
                    down: down_rx,
                    wake: Arc::clone(&self.wake),
                };
                self.tcp.push(TcpSlot {
                    handle,
                    up: Some(up_rx),
                    pending: None,
                    down: Some(down_tx),
                    reply: Some((reply, Instant::now() + CONNECT_TIMEOUT, io)),
                });
            }
            Command::Udp {
                destination,
                payload,
                reply,
            } => {
                let local = self.params.addresses.iter().find(|a| a.is_ipv4() == destination.is_ipv4()).copied();
                let Some(_) = local else {
                    let _ = reply.send(Err(format!("the tunnel has no address for {destination}")));
                    return;
                };
                let mut socket = udp::Socket::new(
                    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; 8 * 1024]),
                    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 2], vec![0u8; payload.len().max(512)]),
                );
                let port = self.port();
                if let Err(error) = socket.bind(port) {
                    let _ = reply.send(Err(format!("UDP bind in the tunnel: {error}")));
                    return;
                }
                let remote = IpEndpoint::new(IpAddress::from(destination.ip()), destination.port());
                if let Err(error) = socket.send_slice(&payload, remote) {
                    let _ = reply.send(Err(format!("UDP send in the tunnel: {error}")));
                    return;
                }
                let handle = self.sockets.add(socket);
                self.udp.push(UdpSlot {
                    handle,
                    reply: Some(reply),
                    deadline: Instant::now() + UDP_TIMEOUT,
                });
            }
            Command::Rebind => match bind_for(self.peer) {
                Ok(socket) => self.socket = socket,
                Err(error) => tracing::debug!(%error, "WireGuard rebind failed; keeping the old socket"),
            },
        }
    }

    /// A local port not in use by another socket of this tunnel.
    fn port(&mut self) -> u16 {
        self.next_port = if self.next_port >= 65000 { 40000 } else { self.next_port + 1 };
        self.next_port
    }

    /// Move data between sockets and streams. Returns whether anything moved.
    fn service(&mut self) -> bool {
        let mut moved = false;
        let now = Instant::now();
        let mut index = 0;
        while index < self.tcp.len() {
            let slot = &mut self.tcp[index];
            let socket = self.sockets.get_mut::<tcp::Socket>(slot.handle);

            // Connecting: answer once established, or give up.
            if let Some((reply, deadline, io)) = slot.reply.take() {
                match socket.state() {
                    tcp::State::Established | tcp::State::CloseWait => {
                        let _ = reply.send(Ok(io));
                        moved = true;
                    }
                    tcp::State::Closed | tcp::State::TimeWait => {
                        let _ = reply.send(Err("connection refused through the tunnel".into()));
                        slot.up = None;
                        slot.down = None;
                    }
                    _ if now >= deadline => {
                        socket.abort();
                        let _ = reply.send(Err("TCP connect through the tunnel timed out".into()));
                        slot.up = None;
                        slot.down = None;
                    }
                    _ => slot.reply = Some((reply, deadline, io)),
                }
            }

            if slot.reply.is_none() {
                // Application → socket.
                while socket.can_send() {
                    if slot.pending.is_none() {
                        match slot.up.as_mut().map(mpsc::Receiver::try_recv) {
                            Some(Ok(chunk)) => slot.pending = Some((chunk, 0)),
                            Some(Err(mpsc::error::TryRecvError::Empty)) | None => break,
                            Some(Err(mpsc::error::TryRecvError::Disconnected)) => {
                                slot.up = None;
                                socket.close();
                                break;
                            }
                        }
                    }
                    let Some((chunk, offset)) = slot.pending.as_mut() else { break };
                    match socket.send_slice(&chunk[*offset..]) {
                        Ok(sent) => {
                            *offset += sent;
                            moved |= sent > 0;
                            if *offset >= chunk.len() {
                                slot.pending = None;
                            } else {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Socket → application, only as fast as it reads.
                while socket.can_recv() {
                    let Some(down) = slot.down.as_ref() else {
                        // Nobody reads any more: discard.
                        let _ = socket.recv(|data| (data.len(), ()));
                        continue;
                    };
                    let Ok(permit) = down.try_reserve() else { break };
                    let _ = socket.recv(|data| {
                        let n = data.len().min(DOWN_CHUNK);
                        permit.send(Bytes::copy_from_slice(&data[..n]));
                        (n, ())
                    });
                    moved = true;
                }
                // The peer finished sending: end of stream for the application.
                if !socket.may_recv() && !socket.can_recv() && slot.down.is_some() && socket.state() != tcp::State::SynSent {
                    slot.down = None;
                }
                // The application went away entirely.
                if slot.down.as_ref().is_some_and(mpsc::Sender::is_closed) {
                    slot.down = None;
                    if slot.up.is_some() {
                        slot.up = None;
                        socket.close();
                    }
                }
            }

            let finished = slot.reply.is_none()
                && slot.down.is_none()
                && slot.up.is_none()
                && slot.pending.is_none()
                && matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait | tcp::State::Closing | tcp::State::LastAck | tcp::State::FinWait2 | tcp::State::FinWait1)
                && socket.send_queue() == 0;
            if finished {
                // Let a clean close finish on its own; a socket that no one
                // needs any more is released right away.
                if socket.state() == tcp::State::Closed || socket.state() == tcp::State::TimeWait || socket.state() == tcp::State::FinWait2 {
                    let handle = slot.handle;
                    self.sockets.remove(handle);
                    self.tcp.swap_remove(index);
                    self.last_activity = now;
                    continue;
                }
            }
            index += 1;
        }

        let mut index = 0;
        while index < self.udp.len() {
            let slot = &mut self.udp[index];
            let socket = self.sockets.get_mut::<udp::Socket>(slot.handle);
            let mut done = false;
            if let Ok((data, meta)) = socket.recv() {
                if let Some(reply) = slot.reply.take() {
                    let from = SocketAddr::new(IpAddr::from(meta.endpoint.addr), meta.endpoint.port);
                    let _ = reply.send(Ok((from, data.to_vec())));
                }
                done = true;
                moved = true;
            } else if now >= slot.deadline {
                if let Some(reply) = slot.reply.take() {
                    let _ = reply.send(Err("UDP answer through the tunnel timed out".into()));
                }
                done = true;
            }
            if done {
                let handle = slot.handle;
                self.sockets.remove(handle);
                self.udp.swap_remove(index);
                self.last_activity = now;
            } else {
                index += 1;
            }
        }
        moved
    }

    /// Encrypt and send every packet the stack produced. Returns whether any went.
    async fn flush(&mut self) -> bool {
        let mut sent = false;
        while let Some(packet) = self.device.outbound.pop_front() {
            match self.tunnel.encapsulate(&packet, &mut self.out) {
                TunnResult::WriteToNetwork(encrypted) => {
                    let encrypted = encrypted.to_vec();
                    self.send(&encrypted).await;
                    sent = true;
                }
                // Queued inside boringtun until the handshake completes.
                TunnResult::Done => {}
                TunnResult::Err(error) => tracing::debug!(?error, "WireGuard encapsulate"),
                _ => {}
            }
            self.device.recycle(packet);
        }
        sent
    }

    async fn from_network(&mut self, datagram: &mut [u8], source: SocketAddr) {
        if source != self.peer {
            return;
        }
        let decoded;
        let packet: &[u8] = if self.plain {
            // WARP echoes its reserved bytes; boringtun expects zeros.
            if datagram.len() >= 4 {
                datagram[1..4].fill(0);
            }
            datagram
        } else {
            match amnezia::decode_packet(self.params.obfuscation, datagram) {
                Ok(Some(normal)) => {
                    decoded = normal;
                    &decoded
                }
                _ => return,
            }
        };
        let mut clear = std::mem::take(&mut self.clear);
        let mut state = self.tunnel.decapsulate(Some(source.ip()), packet, &mut clear);
        loop {
            match state {
                TunnResult::WriteToNetwork(reply) => {
                    let reply = reply.to_vec();
                    self.send(&reply).await;
                    // Flush packets queued during the handshake.
                    state = self.tunnel.decapsulate(None, &[], &mut clear);
                }
                TunnResult::WriteToTunnelV4(inner, _) | TunnResult::WriteToTunnelV6(inner, _) => {
                    let mut buffer = self.device.buffer();
                    buffer.extend_from_slice(inner);
                    self.device.inbound.push_back(buffer);
                    break;
                }
                TunnResult::Done | TunnResult::Err(_) => break,
            }
        }
        self.clear = clear;
    }

    async fn send(&mut self, packet: &[u8]) {
        let result = if self.plain {
            if amnezia::packet_kind(packet) == Some(amnezia::PacketKind::HandshakeInit) {
                if let Ok(junk) = amnezia::junk_packets(self.params.obfuscation, &mut self.rng) {
                    for junk in junk {
                        let _ = self.socket.send_to(&junk, self.peer).await;
                    }
                }
            }
            if self.params.reserved != [0; 3] && packet.len() >= 4 {
                let mut stamped = packet.to_vec();
                stamped[1..4].copy_from_slice(&self.params.reserved);
                self.socket.send_to(&stamped, self.peer).await
            } else {
                self.socket.send_to(packet, self.peer).await
            }
        } else {
            match amnezia::encode_packet(self.params.obfuscation, packet, &mut self.rng) {
                Ok(encoded) => {
                    if amnezia::packet_kind(packet) == Some(amnezia::PacketKind::HandshakeInit) {
                        if let Ok(junk) = amnezia::junk_packets(self.params.obfuscation, &mut self.rng) {
                            for junk in junk {
                                let _ = self.socket.send_to(&junk, self.peer).await;
                            }
                        }
                    }
                    self.socket.send_to(&encoded, self.peer).await
                }
                Err(error) => {
                    tracing::debug!(%error, "AmneziaWG encode");
                    return;
                }
            }
        };
        if let Err(error) = result {
            tracing::debug!(%error, "WireGuard send");
        }
    }
}

// --------------------------------------------------------------------- DNS

fn dns_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    if name.is_empty() || name.len() > 253 {
        return Err("invalid name".into());
    }
    let mut query = Vec::with_capacity(18 + name.len());
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("invalid name".into());
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    Ok(query)
}

/// Addresses of `qtype` in an answer, and the smallest TTL among them.
fn dns_answer(message: &[u8], id: u16, qtype: u16) -> Result<(Vec<IpAddr>, Duration), String> {
    if message.len() < 12 || u16::from_be_bytes([message[0], message[1]]) != id {
        return Err("mismatched DNS answer".into());
    }
    if message[3] & 0x0f != 0 {
        return Err(format!("DNS error code {}", message[3] & 0x0f));
    }
    let questions = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answers = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut at = 12;
    let skip_name = |mut at: usize| -> Result<usize, String> {
        loop {
            let length = *message.get(at).ok_or("truncated DNS name")? as usize;
            if length == 0 {
                return Ok(at + 1);
            }
            if length & 0xc0 == 0xc0 {
                return Ok(at + 2);
            }
            at += length + 1;
        }
    };
    for _ in 0..questions {
        at = skip_name(at)? + 4;
    }
    let mut out = Vec::new();
    let mut ttl = DNS_CACHE_MAX_TTL;
    for _ in 0..answers {
        at = skip_name(at)?;
        let header = message.get(at..at + 10).ok_or("truncated DNS record")?;
        let rtype = u16::from_be_bytes([header[0], header[1]]);
        let record_ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let length = u16::from_be_bytes([header[8], header[9]]) as usize;
        let data = message.get(at + 10..at + 10 + length).ok_or("truncated DNS data")?;
        if rtype == qtype {
            match (qtype, length) {
                (1, 4) => out.push(IpAddr::from(<[u8; 4]>::try_from(data).unwrap())),
                (28, 16) => out.push(IpAddr::from(<[u8; 16]>::try_from(data).unwrap())),
                _ => {}
            }
            ttl = ttl.min(Duration::from_secs(u64::from(record_ttl)));
        }
        at += 10 + length;
    }
    if out.is_empty() {
        return Err("no address in the DNS answer".into());
    }
    Ok((out, ttl))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-process WireGuard peer: boringtun plus its own smoltcp stack at
    /// 10.9.0.1, serving TCP echo on port 7 (several at once), UDP echo on 7
    /// and DNS on 53 (`echo.test` → 10.9.0.1). Returns its UDP address and
    /// public key.
    async fn peer(client_public: [u8; 32], reserved: [u8; 3]) -> (SocketAddr, [u8; 32]) {
        let secret = boringtun::x25519::StaticSecret::from([7u8; 32]);
        let public = boringtun::x25519::PublicKey::from(&secret).to_bytes();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut tunnel = Tunn::new(secret, boringtun::x25519::PublicKey::from(client_public), None, None, 1, None);
            let mut device = QueueDevice::new();
            let started = Instant::now();
            let now = || smoltcp::time::Instant::from_millis(started.elapsed().as_millis() as i64);
            let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, now());
            iface.update_ip_addrs(|a| {
                let _ = a.push(IpCidr::new(IpAddress::from(Ipv4Addr::new(10, 9, 0, 1)), 24));
            });
            let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Addr::new(10, 9, 0, 254));
            let mut sockets = SocketSet::new(Vec::new());
            let mut listeners = Vec::new();
            for _ in 0..6 {
                let mut tcp = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 256 * 1024]), tcp::SocketBuffer::new(vec![0; 256 * 1024]));
                tcp.listen(7).unwrap();
                listeners.push(sockets.add(tcp));
            }
            let mut udp_echo = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 16384]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 16384]),
            );
            udp_echo.bind(7).unwrap();
            let udp_echo = sockets.add(udp_echo);
            let mut dns = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 4096]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 4096]),
            );
            dns.bind(53).unwrap();
            let dns = sockets.add(dns);
            let mut client: Option<SocketAddr> = None;
            let (mut network, mut out, mut clear) = (vec![0u8; 4096], vec![0u8; 4096], vec![0u8; 4096]);
            loop {
                let received = tokio::time::timeout(Duration::from_millis(5), socket.recv_from(&mut network)).await;
                if let Ok(Ok((length, from))) = received {
                    // The client stamps WARP's reserved bytes on every
                    // WireGuard message; anything else (the junk sent before
                    // a handshake) is dropped, as Cloudflare drops it.
                    if length < 4 || network[1..4] != reserved {
                        continue;
                    }
                    network[1..4].fill(0);
                    client = Some(from);
                    let mut state = tunnel.decapsulate(Some(from.ip()), &network[..length], &mut clear);
                    loop {
                        match state {
                            TunnResult::WriteToNetwork(p) => {
                                socket.send_to(p, from).await.unwrap();
                                state = tunnel.decapsulate(None, &[], &mut clear);
                            }
                            TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                                device.inbound.push_back(p.to_vec());
                                break;
                            }
                            _ => break,
                        }
                    }
                }
                iface.poll(now(), &mut device, &mut sockets);
                for handle in &listeners {
                    let tcp = sockets.get_mut::<tcp::Socket>(*handle);
                    if tcp.can_recv() && tcp.can_send() {
                        let room = tcp.send_capacity() - tcp.send_queue();
                        let data = tcp.recv(|d| { let n = d.len().min(room); (n, d[..n].to_vec()) }).unwrap();
                        tcp.send_slice(&data).unwrap();
                    }
                    if !tcp.may_recv() && tcp.state() == tcp::State::CloseWait && tcp.send_queue() == 0 {
                        tcp.close();
                    }
                    if tcp.state() == tcp::State::Closed {
                        tcp.listen(7).unwrap();
                    }
                }
                {
                    let echo = sockets.get_mut::<udp::Socket>(udp_echo);
                    if let Ok((data, meta)) = echo.recv() {
                        let data = data.to_vec();
                        echo.send_slice(&data, meta.endpoint).unwrap();
                    }
                }
                {
                    let dns = sockets.get_mut::<udp::Socket>(dns);
                    if let Ok((query, meta)) = dns.recv() {
                        let mut answer = query.to_vec();
                        answer[2] = 0x81;
                        answer[3] = 0x80;
                        answer[7] = 1;
                        answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 9, 0, 1]);
                        dns.send_slice(&answer, meta.endpoint).unwrap();
                    }
                }
                iface.poll(now(), &mut device, &mut sockets);
                while let Some(packet) = device.outbound.pop_front() {
                    if let (TunnResult::WriteToNetwork(p), Some(to)) = (tunnel.encapsulate(&packet, &mut out), client) {
                        socket.send_to(p, to).await.unwrap();
                    }
                }
                if let TunnResult::WriteToNetwork(p) = tunnel.update_timers(&mut out) {
                    if let Some(to) = client {
                        socket.send_to(p, to).await.unwrap();
                    }
                }
            }
        });
        (address, public)
    }

    fn client_params(peer_public: [u8; 32], reserved: [u8; 3]) -> WgStackParams {
        WgStackParams {
            private_key: [9u8; 32],
            peer_public_key: peer_public,
            preshared_key: None,
            addresses: vec![IpAddr::from([10, 9, 0, 2])],
            persistent_keepalive: None,
            obfuscation: AmneziaParams { junk_count: 3, junk_size: amnezia::RangeU16 { min: 40, max: 70 }, ..AmneziaParams::default() },
            reserved,
            dns: "10.9.0.1:53".parse().unwrap(),
        }
    }

    async fn echo(stream: &mut zero_core::BoxStream, body: &[u8]) {
        stream.write_all(body).await.unwrap();
        let mut back = vec![0u8; body.len()];
        tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut back)).await.expect("echo timed out").unwrap();
        assert_eq!(back, body);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tcp_udp_and_dns_ride_one_wireguard_session() {
        let client_public = boringtun::x25519::PublicKey::from(&boringtun::x25519::StaticSecret::from([9u8; 32])).to_bytes();
        let reserved = [0x12, 0x34, 0x56];
        let (server, server_public) = peer(client_public, reserved).await;
        let stack = WgStack::start(server, client_params(server_public, reserved)).unwrap();

        // DNS through the tunnel, then TCP to the name.
        let addresses = stack.resolve("echo.test").await.unwrap();
        assert_eq!(addresses, vec![IpAddr::from([10, 9, 0, 1])]);
        let mut stream = stack.connect_host(&zero_core::Address::domain("echo.test"), 7).await.unwrap();
        echo(&mut stream, b"hello through wireguard").await;
        // A larger transfer: windows, segmentation and backpressure.
        let big: Vec<u8> = (0..600_000u32).map(|i| (i * 31 % 251) as u8).collect();
        echo(&mut stream, &big).await;

        // Several streams at once over the same session.
        let tasks: Vec<_> = (0..4u8)
            .map(|n| {
                let stack = stack.clone();
                tokio::spawn(async move {
                    let mut s = stack.connect("10.9.0.1:7".parse().unwrap()).await.unwrap();
                    echo(&mut s, &vec![n; 50_000]).await;
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }

        // UDP.
        let (from, answer) = stack.exchange_udp("10.9.0.1:7".parse().unwrap(), b"ping").await.unwrap();
        assert_eq!(answer, b"ping");
        assert_eq!(from, "10.9.0.1:7".parse::<SocketAddr>().unwrap());

        // A closed port fails fast rather than hanging.
        let refused = tokio::time::timeout(Duration::from_secs(15), stack.connect("10.9.0.1:9".parse().unwrap())).await.unwrap();
        assert!(refused.is_err());

        // A network change: a new socket, same session, still working.
        stack.rebind();
        let mut after = stack.connect("10.9.0.1:7".parse().unwrap()).await.unwrap();
        echo(&mut after, b"after the move").await;
        assert!(stack.is_alive());
    }

    #[test]
    fn dns_round_trips_an_a_record() {
        let query = dns_query(0x1234, "example.com", 1).unwrap();
        // Answer = query with the answer count set and one A record appended.
        let mut answer = query.clone();
        answer[2] = 0x81;
        answer[3] = 0x80;
        answer[7] = 1;
        answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let (addresses, ttl) = dns_answer(&answer, 0x1234, 1).unwrap();
        assert_eq!(addresses, vec![IpAddr::from([93, 184, 216, 34])]);
        assert_eq!(ttl, Duration::from_secs(60));
        assert!(dns_answer(&answer, 0x9999, 1).is_err());
        assert!(dns_query(1, "bad..name", 1).is_err());
    }
}
