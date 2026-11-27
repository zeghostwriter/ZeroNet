//! Upload throughput from a simulated app, through the userspace netstack,
//! at several TUN MTUs. Measures only the in-device leg the TUN MTU governs.
//!
//! `cargo run --release -p zero-tun --example mtu_bench`

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::io::AsyncReadExt;

struct Queue {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    mtu: usize,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.0.push(buffer);
        result
    }
}

impl Device for Queue {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: SmolInstant) -> Option<(Rx, Tx<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((Rx(packet), Tx(&mut self.tx)))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

async fn run(mtu: usize, total: usize) -> Duration {
    let parts = zero_tun::build_netstack(zero_tun::NetstackConfig {
        mtu,
        enable_tcp: true,
        enable_udp: false,
        enable_icmp: false,
    })
    .unwrap();
    if let Some(runner) = parts.runner {
        tokio::spawn(runner);
    }
    let mut listener = parts.tcp.unwrap();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _, _) = listener.next().await.unwrap();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut received = 0;
        while received < total {
            let n = stream.read(&mut buffer).await.unwrap();
            if n == 0 {
                break;
            }
            received += n;
        }
        let _ = done_tx.send(Instant::now());
    });
    let (mut sink, mut stream) = parts.stack.split();

    let mut device = Queue {
        rx: VecDeque::new(),
        tx: Vec::new(),
        mtu,
    };
    let start = std::time::Instant::now();
    let now = || SmolInstant::from_micros(start.elapsed().as_micros() as i64);
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, now());
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
            .unwrap();
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1))
        .unwrap();
    let mut sockets = SocketSet::new(vec![]);
    let socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 256 * 1024]),
        tcp::SocketBuffer::new(vec![0; 256 * 1024]),
    );
    let handle = sockets.add(socket);
    sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(iface.context(), (IpAddress::v4(1, 2, 3, 4), 80), 40000)
        .unwrap();

    let chunk = vec![7u8; 64 * 1024];
    let mut sent = 0;
    let began = Instant::now();
    let mut done_rx = done_rx;
    loop {
        iface.poll(now(), &mut device, &mut sockets);
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        while sent < total && socket.can_send() {
            let n = socket
                .send_slice(&chunk[..chunk.len().min(total - sent)])
                .unwrap();
            if n == 0 {
                break;
            }
            sent += n;
        }
        iface.poll(now(), &mut device, &mut sockets);
        for packet in device.tx.drain(..) {
            sink.feed(packet).await.unwrap();
        }
        sink.flush().await.unwrap();
        // Take whatever the stack has ready, waiting briefly if nothing.
        match tokio::time::timeout(Duration::from_micros(200), stream.next()).await {
            Ok(Some(Ok(packet))) => {
                device.rx.push_back(packet);
                while let Some(Some(Ok(packet))) = futures::FutureExt::now_or_never(stream.next()) {
                    device.rx.push_back(packet);
                }
            }
            Ok(_) => break,
            Err(_) => {}
        }
        if let Ok(end) = done_rx.try_recv() {
            return end - began;
        }
    }
    panic!("stack closed");
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let total = 256 * 1024 * 1024;
    for mtu in [1280, 1500, 4000, 9000, 16000, 65000] {
        let mut best = Duration::MAX;
        for _ in 0..3 {
            best = best.min(run(mtu, total).await);
        }
        let mbps = total as f64 * 8.0 / best.as_secs_f64() / 1e6;
        println!("mtu {mtu:>5}: {mbps:>8.0} Mbit/s");
    }
}
