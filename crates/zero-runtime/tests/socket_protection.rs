//! Every socket that leaves the machine is offered to the host's protector.
//!
//! On Android the proxy process sits *behind* the VPN it is providing, so a
//! socket that is not exempted routes back into the TUN device: the proxy's
//! own traffic to its server arrives at the proxy. The tunnel does not perform
//! badly, it carries nothing. One missed call site is enough to cause it.
//!
//! Counting call sites by reading the code is exactly the check that fails
//! silently when a new transport is added, so this drives real traffic through
//! the runtime and watches what the protector is handed.
//!
//! The protector is process-wide and write-once, so everything here is one
//! test — two tests installing protectors would race for the registry.

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Records what it was asked to protect.
///
/// The bound port is read back from the descriptor, which is what makes the
/// negative half of this test possible: a UDP socket is bound before it is
/// protected, so its port identifies it.
#[derive(Default)]
struct Recorder {
    calls: AtomicUsize,
    bound_ports: Mutex<HashSet<u16>>,
}

impl zero_core::SocketProtector for Recorder {
    fn protect(&self, fd: i32) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if let Some(port) = local_port(fd) {
            if port != 0 {
                self.bound_ports
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(port);
            }
        }
        Ok(())
    }
}

impl Recorder {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    fn protected_port(&self, port: u16) -> bool {
        self.bound_ports
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&port)
    }
}

/// The port a descriptor is bound to, or `None` if it is not bound yet.
///
/// A TCP socket is protected *before* connect and so is unbound at that point,
/// which is the correct ordering and the reason this returns `None` for them.
fn local_port(fd: i32) -> Option<u16> {
    // SAFETY: `storage` is large enough for any sockaddr, `length` describes
    // it, and the descriptor is one the runtime just created and still owns.
    unsafe {
        let mut storage: libc::sockaddr_storage = std::mem::zeroed();
        let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getsockname(
            fd,
            &mut storage as *mut _ as *mut libc::sockaddr,
            &mut length,
        ) != 0
        {
            return None;
        }
        match storage.ss_family as libc::c_int {
            libc::AF_INET => {
                let addr = &*(&storage as *const _ as *const libc::sockaddr_in);
                Some(u16::from_be(addr.sin_port))
            }
            libc::AF_INET6 => {
                let addr = &*(&storage as *const _ as *const libc::sockaddr_in6);
                Some(u16::from_be(addr.sin6_port))
            }
            _ => None,
        }
    }
}

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                while let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 || stream.write_all(&buffer[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    address
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 2048];
        while let Ok((n, peer)) = socket.recv_from(&mut buffer).await {
            if socket.send_to(&buffer[..n], peer).await.is_err() {
                return;
            }
        }
    });
    address
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_outbound_socket_is_offered_to_the_host_protector() {
    let recorder = Arc::new(Recorder::default());
    zero_core::set_socket_protector(recorder.clone()).expect("first install in this process");

    let tcp_target = tcp_echo().await;
    let udp_target = udp_echo().await;
    let socks_port = free_port();

    let config = json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": true},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    });
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1)).unwrap();
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = running.run().await;
    });
    tokio::time::timeout(Duration::from_secs(10), server.wait_until_listening())
        .await
        .expect("server listening");

    let socks = SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port);

    // --- TCP: the dialer's socket must be protected before it connects ---
    let before = recorder.calls();
    let mut stream = TcpStream::connect(socks).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    let std::net::IpAddr::V4(ip) = tcp_target.ip() else {
        panic!("IPv4 only");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&tcp_target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS CONNECT failed");
    stream.write_all(b"protected?").await.unwrap();
    let mut echoed = [0u8; 10];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"protected?");
    assert!(
        recorder.calls() > before,
        "the outbound TCP socket reached the peer without being offered to \
         the protector; on Android that connection would have looped back \
         into the tunnel"
    );

    // --- UDP: the relay's outbound socket must be protected too ---
    let before = recorder.calls();
    let mut control = TcpStream::connect(socks).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    control.read_exact(&mut greeting).await.unwrap();
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "UDP ASSOCIATE refused");
    let association_port = u16::from_be_bytes([reply[8], reply[9]]);
    let relay = SocketAddr::new("127.0.0.1".parse().unwrap(), association_port);

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let std::net::IpAddr::V4(target_ip) = udp_target.ip() else {
        panic!("IPv4 only");
    };
    let mut datagram = vec![0x00, 0x00, 0x00, 0x01];
    datagram.extend_from_slice(&target_ip.octets());
    datagram.extend_from_slice(&udp_target.port().to_be_bytes());
    datagram.extend_from_slice(b"datagram");
    client.send_to(&datagram, relay).await.unwrap();
    let mut received = vec![0u8; 2048];
    let (read, _) = tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut received))
        .await
        .expect("UDP echo timed out")
        .unwrap();
    assert_eq!(&received[10..read], b"datagram");
    assert!(
        recorder.calls() > before,
        "the outbound UDP socket was never offered to the protector"
    );

    // --- and the local association socket must *not* be protected ---
    //
    // It listens for datagrams from applications on this device. Exempting it
    // from the tunnel would move it off the interface those applications send
    // to, breaking the half of the path that is supposed to stay local.
    assert!(
        !recorder.protected_port(association_port),
        "the SOCKS5 UDP association socket on port {association_port} was \
         protected; it faces the local applications, not the network"
    );
}
