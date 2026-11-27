//! Juicity end to end: the real client runtime against a Juicity server written
//! here from the wire contract (daeuniverse/outbound `protocol/juicity` and the
//! juicity `docs/spec.md`), not from the client under test.
//!
//! The server is deliberately independent of `zero_transport::juicity`: it reads
//! the five facts a Juicity server checks and nothing else, so a mistake in the
//! client's framing shows up as a hung or refused stream rather than being
//! echoed back by a mirror-image implementation.
//!
//! * Authentication: one unidirectional stream `[0][0][uuid(16)][token(32)]`,
//!   `token = ExportKeyingMaterial(label = uuid bytes, context = password)`.
//! * A TCP stream opens `[1][type][host][port]` and then carries bytes.
//! * A UDP stream opens `[3]` and then frames every datagram as
//!   `[type][host][port][len(16-bit BE)][payload]`, in both directions.
//! * Address types are the trojan ones: IPv4 = 1, domain = 3 (one length
//!   byte), IPv6 = 4.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const UUID_BYTES: [u8; 16] = [
    0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
];
const PASSWORD: &str = "a-juicity-shared-password";
const SERVER_NAME: &str = "zray.test";

const CERTIFICATE: &str = include_str!("fixtures/loopback-cert.pem");
const PRIVATE_KEY: &str = include_str!("fixtures/loopback-key.pem");
const CA_CERTIFICATE: &str = include_str!("fixtures/loopback-ca.pem");

/// What the server reports about the connections it served, so a test can tell
/// "the client authenticated once and multiplexed" from "it redialled".
#[derive(Default)]
struct Stats {
    connections: std::sync::atomic::AtomicUsize,
    authenticated: std::sync::atomic::AtomicUsize,
    streams: std::sync::atomic::AtomicUsize,
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Read one trojan address `[type][host][port]` from `recv`.
async fn read_address(recv: &mut quinn::RecvStream) -> Option<(String, u16)> {
    let mut kind = [0u8; 1];
    recv.read_exact(&mut kind).await.ok()?;
    let host = match kind[0] {
        1 => {
            let mut b = [0u8; 4];
            recv.read_exact(&mut b).await.ok()?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        4 => {
            let mut b = [0u8; 16];
            recv.read_exact(&mut b).await.ok()?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            recv.read_exact(&mut len).await.ok()?;
            let mut b = vec![0u8; len[0] as usize];
            recv.read_exact(&mut b).await.ok()?;
            String::from_utf8(b).ok()?
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    recv.read_exact(&mut port).await.ok()?;
    Some((host, u16::from_be_bytes(port)))
}

/// Write an IPv4 trojan address, the only kind a reply from the loopback echo
/// can carry.
fn encode_v4(addr: SocketAddr) -> Vec<u8> {
    let std::net::IpAddr::V4(ip) = addr.ip() else {
        panic!("IPv4 only");
    };
    let mut out = vec![1];
    out.extend_from_slice(&ip.octets());
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

async fn serve_tcp(mut send: quinn::SendStream, mut recv: quinn::RecvStream, target: String) {
    let Ok(mut upstream) = TcpStream::connect(&target).await else {
        let _ = send.reset(1u32.into());
        return;
    };
    let (mut up_read, mut up_write) = upstream.split();
    let to_target = async {
        let mut buf = vec![0u8; 32 * 1024];
        while let Ok(Some(n)) = recv.read(&mut buf).await {
            if up_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = up_write.shutdown().await;
    };
    let from_target = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match up_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = send.finish();
    };
    tokio::join!(to_target, from_target);
}

/// The server end of a UDP stream. The stream header named one address (the
/// reference server reads it and moves on); after it, every datagram repeats
/// its address and carries a two-byte length.
async fn serve_udp(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    let Ok(socket) = UdpSocket::bind("127.0.0.1:0").await else {
        return;
    };
    loop {
        let Some((host, port)) = read_address(&mut recv).await else {
            return;
        };
        let mut length = [0u8; 2];
        if recv.read_exact(&mut length).await.is_err() {
            return;
        }
        let mut payload = vec![0u8; u16::from_be_bytes(length) as usize];
        if recv.read_exact(&mut payload).await.is_err() {
            return;
        }
        let Some(target) = tokio::net::lookup_host((host.as_str(), port))
            .await
            .ok()
            .and_then(|mut found| found.next())
        else {
            return;
        };
        if socket.send_to(&payload, target).await.is_err() {
            return;
        }
        let mut answer = vec![0u8; 64 * 1024];
        let Ok(Ok((n, from))) =
            tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut answer)).await
        else {
            return;
        };
        let mut reply = encode_v4(from);
        reply.extend_from_slice(&(n as u16).to_be_bytes());
        reply.extend_from_slice(&answer[..n]);
        if send.write_all(&reply).await.is_err() {
            return;
        }
    }
}

/// A Juicity server on `port`. A connection whose token is wrong is closed, as
/// the reference does, so a stream opened on it never completes.
fn juicity_server(port: u16, stats: Arc<Stats>) {
    use std::sync::atomic::Ordering::Relaxed;
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = {
        let mut reader = std::io::BufReader::new(CERTIFICATE.as_bytes());
        rustls_pki_types::pem::PemObject::pem_reader_iter(&mut reader)
            .filter_map(Result::ok)
            .collect()
    };
    let key: rustls_pki_types::PrivateKeyDer<'static> = {
        let mut reader = std::io::BufReader::new(PRIVATE_KEY.as_bytes());
        rustls_pki_types::pem::PemObject::from_pem_reader(&mut reader).expect("test key")
    };
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("a usable test certificate");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("QUIC TLS");
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    // The spec asks a server for at least 30 incoming streams.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(64u32.into());
    config.transport_config(Arc::new(transport));
    let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let endpoint = quinn::Endpoint::server(config, address).expect("Juicity endpoint");

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let stats = Arc::clone(&stats);
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                stats.connections.fetch_add(1, Relaxed);
                let (authed_tx, authed_rx) = tokio::sync::watch::channel(false);

                // Authentication, concurrently with the first proxy streams:
                // the client sends both without waiting for the other.
                let auth_connection = connection.clone();
                tokio::spawn(async move {
                    let Ok(mut uni) = auth_connection.accept_uni().await else {
                        return;
                    };
                    let mut command = [0u8; 50];
                    if uni.read_exact(&mut command).await.is_err() {
                        auth_connection.close(1u32.into(), b"bad auth");
                        return;
                    }
                    let mut expected = [0u8; 32];
                    auth_connection
                        .export_keying_material(&mut expected, &UUID_BYTES, PASSWORD.as_bytes())
                        .expect("export keying material");
                    if command[0] != 0
                        || command[1] != 0
                        || command[2..18] != UUID_BYTES
                        || command[18..] != expected
                    {
                        auth_connection.close(1u32.into(), b"bad auth");
                        return;
                    }
                    let _ = authed_tx.send(true);
                });

                loop {
                    let Ok((send, mut recv)) = connection.accept_bi().await else {
                        return;
                    };
                    let mut authed = authed_rx.clone();
                    let stats = Arc::clone(&stats);
                    tokio::spawn(async move {
                        // Only an authenticated connection is served.
                        if tokio::time::timeout(Duration::from_secs(3), authed.wait_for(|ok| *ok))
                            .await
                            .is_err()
                        {
                            return;
                        }
                        stats.authenticated.fetch_max(1, Relaxed);
                        let mut network = [0u8; 1];
                        if recv.read_exact(&mut network).await.is_err() {
                            return;
                        }
                        let Some((host, port)) = read_address(&mut recv).await else {
                            return;
                        };
                        stats.streams.fetch_add(1, Relaxed);
                        match network[0] {
                            1 => serve_tcp(send, recv, format!("{host}:{port}")).await,
                            3 => serve_udp(send, recv).await,
                            _ => {}
                        }
                    });
                }
            });
        }
    });
}

async fn echo_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    address
}

async fn udp_echo_service() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 64 * 1024];
        while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..read], from).await;
        }
    });
    address
}

struct Tunnel {
    socks: SocketAddr,
    echo: SocketAddr,
    udp_echo: SocketAddr,
    relay: SocketAddr,
    stats: Arc<Stats>,
}

fn spawn_client(config: Value) -> Arc<zero_runtime::Server> {
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
        .unwrap_or_else(|error| panic!("configuration rejected: {error}\n{config:#}"));
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        if let Err(error) = running.run().await {
            panic!("client failed to start: {error}");
        }
    });
    server
}

async fn tunnel(password: &str) -> Tunnel {
    let echo = echo_service().await;
    let udp_echo = udp_echo_service().await;
    let relay_port = free_udp_port();
    let socks_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let stats = Arc::new(Stats::default());
    juicity_server(relay_port, Arc::clone(&stats));

    let client = spawn_client(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks", "settings": {"udp": true},
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "juicity",
            "settings": {"address": SERVER_NAME, "port": relay_port, "uuid": UUID, "password": password},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": SERVER_NAME,
                    "certificates": [{"usage": "verify", "certificate": [CA_CERTIFICATE]}],
                },
            },
        }],
        "dns": {"hosts": {SERVER_NAME: ["127.0.0.1"]}},
    }));
    tokio::time::timeout(Duration::from_secs(30), client.wait_until_listening())
        .await
        .expect("client never listened");

    Tunnel {
        socks: SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port),
        echo,
        udp_echo,
        relay: SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port),
        stats,
    }
}

/// SOCKS5 CONNECT by IPv4, or by name when `name` is given.
async fn socks_connect(
    socks: SocketAddr,
    target: SocketAddr,
    name: Option<&str>,
) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let mut request = vec![0x05, 0x01, 0x00];
    match name {
        Some(name) => {
            request.push(0x03);
            request.push(name.len() as u8);
            request.extend_from_slice(name.as_bytes());
        }
        None => {
            let std::net::IpAddr::V4(ip) = target.ip() else {
                panic!("IPv4 only");
            };
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("SOCKS reply {}", reply[1])));
    }
    let skip = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        _ => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            l[0] as usize
        }
    };
    let mut discard = vec![0u8; skip + 2];
    stream.read_exact(&mut discard).await?;
    Ok(stream)
}

fn payload(seed: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(seed))
        .collect()
}

async fn round_trip(stream: &mut TcpStream, body: &[u8]) {
    stream.write_all(body).await.unwrap();
    let mut echoed = vec![0u8; body.len()];
    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut echoed))
        .await
        .expect("echo timed out")
        .expect("echo failed");
    assert_eq!(echoed, body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn juicity_carries_tcp_payload_intact() {
    let tunnel = tunnel(PASSWORD).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo, None)
        .await
        .unwrap();
    round_trip(&mut stream, &payload(1, 64)).await;
    round_trip(&mut stream, &payload(2, 512 * 1024)).await;
}

/// A destination given as a name crosses as a name (trojan type 3) and the
/// server resolves it, so the client never does a lookup of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn juicity_sends_a_domain_destination_as_a_name() {
    let tunnel = tunnel(PASSWORD).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo, Some("localhost"))
        .await
        .unwrap();
    round_trip(&mut stream, &payload(3, 4096)).await;
}

/// Many streams, one authenticated QUIC connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn juicity_multiplexes_streams_over_one_connection() {
    let tunnel = Arc::new(tunnel(PASSWORD).await);
    let tasks = (0..12u8).map(|seed| {
        let tunnel = Arc::clone(&tunnel);
        tokio::spawn(async move {
            let mut stream = socks_connect(tunnel.socks, tunnel.echo, None)
                .await
                .unwrap();
            round_trip(&mut stream, &payload(seed, 64 * 1024)).await;
        })
    });
    for task in futures::future::join_all(tasks).await {
        task.unwrap();
    }
    assert_eq!(
        zero_transport::quic_pool::live_connections_to(tunnel.relay),
        1
    );
    assert_eq!(
        tunnel
            .stats
            .connections
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the client redialled instead of multiplexing"
    );
    assert_eq!(
        tunnel
            .stats
            .streams
            .load(std::sync::atomic::Ordering::Relaxed),
        12
    );
}

/// UDP rides a stream, one request and one framed response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn juicity_carries_udp_over_a_stream() {
    let tunnel = tunnel(PASSWORD).await;
    let mut control = TcpStream::connect(tunnel.socks).await.unwrap();
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
    let relay = SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        u16::from_be_bytes([reply[8], reply[9]]),
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let std::net::IpAddr::V4(ip) = tunnel.udp_echo.ip() else {
        panic!("IPv4 only");
    };
    let body = b"a datagram over a juicity stream";
    let mut datagram = vec![0, 0, 0, 1];
    datagram.extend_from_slice(&ip.octets());
    datagram.extend_from_slice(&tunnel.udp_echo.port().to_be_bytes());
    datagram.extend_from_slice(body);
    socket.send_to(&datagram, relay).await.unwrap();

    let mut received = vec![0u8; 64 * 1024];
    let (read, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut received))
        .await
        .expect("UDP response timed out")
        .unwrap();
    assert!(read > 10);
    assert_eq!(&received[10..read], body);
    drop(control);
}

/// A wrong password never gets a stream served: the server closes the
/// connection and the SOCKS request fails instead of hanging for ever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn juicity_with_the_wrong_password_is_refused() {
    let tunnel = tunnel("not-the-password").await;
    let attempt = tokio::time::timeout(Duration::from_secs(20), async {
        let mut stream = socks_connect(tunnel.socks, tunnel.echo, None).await?;
        stream.write_all(b"ping").await?;
        let mut got = [0u8; 4];
        stream.read_exact(&mut got).await?;
        Ok::<_, std::io::Error>(got)
    })
    .await
    .expect("a refused client must fail, not hang");
    assert!(attempt.is_err(), "the server echoed for a wrong password");
}
