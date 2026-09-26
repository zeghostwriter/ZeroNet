//! Interoperability for the TLS- and QUIC-based protocols.
//!
//! Separate from `loopback_interop` because everything here needs a server
//! certificate, and because the QUIC protocols bind UDP sockets rather than
//! reusing the TCP listener path. The certificate is a committed test fixture
//! and the clients set `allowInsecure`, so nothing outside the test process
//! ever trusts it.
//!
//! These are the protocols PLAN-01 lists but that no automated test had
//! exercised end to end: AnyTLS, Hysteria2 and TUIC each carry their own
//! handshake *inside* TLS or QUIC, which is precisely the arrangement where a
//! unit test over the codec proves the least.

use std::net::{SocketAddr, TcpListener as StdListener, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "an-example-shared-password";
const SERVER_NAME: &str = "zray.test";

const CERTIFICATE: &str = include_str!("fixtures/loopback-cert.pem");
const PRIVATE_KEY: &str = include_str!("fixtures/loopback-key.pem");
const CA_CERTIFICATE: &str = include_str!("fixtures/loopback-ca.pem");

/// Hand out a port no other test in this process has been given.
///
/// Binding `:0` and releasing is the usual trick, but two tests running
/// concurrently can be handed the *same* ephemeral port, and the second server
/// to bind it then fails or steals the first one's traffic. That produced a
/// failure that looked exactly like a protocol race, so the allocator keeps a
/// process-wide record instead.
fn reserve_port(udp: bool) -> u16 {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);

    for _ in 0..500 {
        let port = if udp {
            StdUdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        } else {
            StdListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        };
        let mut taken = TAKEN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if taken.get_or_insert_with(HashSet::new).insert(port) {
            return port;
        }
    }
    panic!("could not reserve a free port");
}

fn free_tcp_port() -> u16 {
    reserve_port(false)
}

fn free_udp_port() -> u16 {
    reserve_port(true)
}

fn init_logging() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("ZRAY_TEST_LOG").is_some() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_env("ZRAY_TEST_LOG")
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
                )
                .with_test_writer()
                .try_init();
        }
    });
}

fn spawn(config: Value) -> Arc<zero_runtime::Server> {
    init_logging();
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
        .unwrap_or_else(|error| panic!("configuration rejected: {error}\n{config:#}"));
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        if let Err(error) = running.run().await {
            panic!("server failed to start: {error}");
        }
    });
    server
}

/// Wait for a spawned server to report every listener bound.
///
/// This asks the server rather than probing its ports. Probing was not just
/// imprecise, it was harmful: a UDP readiness probe has to *bind* the port to
/// learn whether it is free, which races the listener for that same port and
/// can make the startup it was checking on fail.
async fn wait_until_listening(server: &Arc<zero_runtime::Server>) {
    tokio::time::timeout(Duration::from_secs(30), server.wait_until_listening())
        .await
        .expect("server never reported its listeners bound");
}

fn inbound_tls() -> Value {
    json!({
        "security": "tls",
        "tlsSettings": {
            "certificates": [{
                "certificate": [CERTIFICATE],
                "key": [PRIVATE_KEY],
            }],
        },
    })
}

/// Trust the fixture CA explicitly rather than switching verification off.
/// `allowInsecure` is refused by the config validator, and rightly so — this is
/// the supported way to reach a privately-issued certificate.
fn client_tls() -> Value {
    json!({
        "security": "tls",
        "tlsSettings": {
            "serverName": SERVER_NAME,
            "certificates": [{"usage": "verify", "certificate": [CA_CERTIFICATE]}],
        },
    })
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

/// A UDP echo, for the datagram paths.
async fn udp_echo_service() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((read, peer)) => {
                    let _ = socket.send_to(&buffer[..read], peer).await;
                }
                Err(_) => return,
            }
        }
    });
    address
}

async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.set_nodelay(true)?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    let std::net::IpAddr::V4(ip) = target.ip() else {
        panic!("IPv4 only");
    };
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    assert_eq!(
        reply[1], 0x00,
        "SOCKS5 CONNECT failed with code {}",
        reply[1]
    );
    let skip = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        other => panic!("unexpected address type {other}"),
    };
    let mut discard = vec![0u8; skip + 2];
    stream.read_exact(&mut discard).await?;
    Ok(stream)
}

async fn round_trip(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("echo timed out")
        .expect("echo failed");
    assert_eq!(echoed, payload);
}

fn payload(seed: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(17).wrapping_add(seed))
        .collect()
}

struct Tunnel {
    socks: SocketAddr,
    echo: SocketAddr,
    udp_echo: SocketAddr,
    /// The relay's listener, which the client's QUIC pool keys on.
    relay: SocketAddr,
}

/// Build a client/server pair for a TLS- or QUIC-terminated protocol.
async fn tunnel(protocol: &str, quic: bool, transport: Value) -> Tunnel {
    let echo = echo_service().await;
    let udp_echo = udp_echo_service().await;
    let relay_port = if quic {
        free_udp_port()
    } else {
        free_tcp_port()
    };
    let socks_port = free_tcp_port();

    let (server_settings, client_settings) = match protocol {
        "anytls" => (
            json!({"users": [{"password": PASSWORD}]}),
            json!({"servers": [{"address": SERVER_NAME, "port": relay_port, "password": PASSWORD}]}),
        ),
        "hysteria2" => (
            json!({"users": [{"password": PASSWORD}]}),
            json!({"servers": [{"address": SERVER_NAME, "port": relay_port, "password": PASSWORD}]}),
        ),
        "tuic" => (
            json!({"uuid": UUID, "password": PASSWORD}),
            json!({"servers": [{
                "address": SERVER_NAME,
                "port": relay_port,
                "uuid": UUID,
                "password": PASSWORD
            }]}),
        ),
        "vless" => (
            json!({"clients": [{"id": UUID}]}),
            json!({"vnext": [{
                "address": SERVER_NAME,
                "port": relay_port,
                "users": [{"id": UUID, "encryption": "none"}]
            }]}),
        ),
        other => panic!("unsupported protocol {other}"),
    };

    let mut inbound_stream = inbound_tls();
    let mut outbound_stream = client_tls();
    merge(&mut inbound_stream, &transport);
    merge(&mut outbound_stream, &transport);

    let relay = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "relay-in",
            "listen": "127.0.0.1",
            "port": relay_port,
            "protocol": protocol,
            "settings": server_settings,
            "streamSettings": inbound_stream,
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }));

    let client = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": true},
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": protocol,
            "settings": client_settings,
            "streamSettings": outbound_stream,
        }],
        // The server name resolves to the loopback listener; nothing leaves
        // the machine.
        "dns": {"hosts": {SERVER_NAME: ["127.0.0.1"]}},
    }));

    wait_until_listening(&relay).await;
    wait_until_listening(&client).await;

    Tunnel {
        socks: SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port),
        echo,
        udp_echo,
        relay: SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port),
    }
}

fn merge(target: &mut Value, extra: &Value) {
    let (Some(target), Some(extra)) = (target.as_object_mut(), extra.as_object()) else {
        return;
    };
    for (key, value) in extra {
        target.insert(key.clone(), value.clone());
    }
}

fn raw() -> Value {
    json!({"network": "tcp"})
}

fn xhttp(mode: &str, version: &str) -> Value {
    // `httpVersion` belongs inside `xhttpSettings`. Placed at the top level of
    // `streamSettings` — where it was — the parser never sees it and falls
    // back to guessing from ALPN, so the HTTP/3 case below silently ran over
    // HTTP/2 and the QUIC carrier was never exercised at all.
    json!({
        "network": "xhttp",
        "xhttpSettings": {"path": "/tunnel", "mode": mode, "httpVersion": version},
    })
}

// ------------------------------------------------------------------- TCP/TLS

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anytls_carries_payload_intact() {
    let tunnel = tunnel("anytls", false, raw()).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(1, 64)).await;
    round_trip(&mut stream, &payload(2, 128 * 1024)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xhttp_over_http2_carries_payload_intact() {
    let tunnel = tunnel("vless", false, xhttp("stream-one", "h2")).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(3, 64)).await;
    round_trip(&mut stream, &payload(4, 128 * 1024)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn xhttp_over_http2_keeps_concurrent_flows_separate() {
    // HTTP/2 multiplexes every flow onto one connection, so a stream-id
    // mistake here delivers one session's bytes to another rather than failing.
    let tunnel = tunnel("vless", false, xhttp("stream-one", "h2")).await;
    let mut tasks = Vec::new();
    for index in 0..16 {
        let socks = tunnel.socks;
        let echo = tunnel.echo;
        tasks.push(tokio::spawn(async move {
            let mut stream = socks_connect(socks, echo).await.unwrap();
            round_trip(&mut stream, &payload(index as u8, 16 * 1024)).await;
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

// ---------------------------------------------------------------- QUIC

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hysteria2_carries_payload_intact() {
    let tunnel = tunnel("hysteria2", true, raw()).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(5, 64)).await;
    round_trip(&mut stream, &payload(6, 128 * 1024)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tuic_carries_payload_intact() {
    let tunnel = tunnel("tuic", true, raw()).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(7, 64)).await;
    round_trip(&mut stream, &payload(8, 128 * 1024)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xhttp_over_http3_carries_payload_intact() {
    let tunnel = tunnel("vless", true, xhttp("stream-one", "h3")).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(9, 64)).await;
    round_trip(&mut stream, &payload(10, 128 * 1024)).await;
}

// ----------------------------------------------------------------- UDP

/// SOCKS5 UDP ASSOCIATE through a QUIC protocol that supports datagrams.
async fn udp_round_trip(tunnel: &Tunnel, body: &[u8]) {
    let mut control = TcpStream::connect(tunnel.socks).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    control.read_exact(&mut greeting).await.unwrap();

    // UDP ASSOCIATE with an unspecified client address: the relay learns it
    // from the first datagram.
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "UDP ASSOCIATE refused with {}", reply[1]);
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    let relay = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let std::net::IpAddr::V4(target_ip) = tunnel.udp_echo.ip() else {
        panic!("IPv4 only");
    };
    let mut datagram = vec![0x00, 0x00, 0x00, 0x01];
    datagram.extend_from_slice(&target_ip.octets());
    datagram.extend_from_slice(&tunnel.udp_echo.port().to_be_bytes());
    datagram.extend_from_slice(body);
    socket.send_to(&datagram, relay).await.unwrap();

    let mut received = vec![0u8; 64 * 1024];
    let (read, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut received))
        .await
        .expect("UDP echo timed out")
        .unwrap();
    // Strip the SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) ADDR(4) PORT(2).
    assert!(read > 10, "reply is too short to contain a payload");
    assert_eq!(&received[10..read], body);

    drop(control);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hysteria2_carries_udp_datagrams() {
    let tunnel = tunnel("hysteria2", true, raw()).await;
    udp_round_trip(&tunnel, b"datagram over hysteria2").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tuic_carries_udp_datagrams() {
    let tunnel = tunnel("tuic", true, raw()).await;
    udp_round_trip(&tunnel, b"datagram over tuic").await;
}

// ---------------------------------------------------------- QUIC pooling

/// Hysteria2 and TUIC multiplex every proxied stream over one authenticated
/// QUIC connection per server, as their reference clients do, instead of a
/// handshake and authentication per stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn quic_carriers_reuse_one_connection_for_many_streams() {
    for protocol in ["hysteria2", "tuic"] {
        let tunnel = tunnel(protocol, true, raw()).await;
        for seed in 0..5u8 {
            let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
            round_trip(&mut stream, &payload(seed, 4096)).await;
        }
        let concurrent = (0..6u8).map(|seed| {
            let socks = tunnel.socks;
            let echo = tunnel.echo;
            tokio::spawn(async move {
                let mut stream = socks_connect(socks, echo).await.unwrap();
                round_trip(&mut stream, &payload(100 + seed, 64 * 1024)).await;
            })
        });
        for task in futures::future::join_all(concurrent).await {
            task.unwrap();
        }
        assert_eq!(
            zero_transport::quic_pool::live_connections_to(tunnel.relay),
            1,
            "{protocol}: eleven streams should share one QUIC connection"
        );
    }
}

/// Concurrent UDP sessions share the pooled connection, and each gets its
/// own answer back: one reader hands every response to its session.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn quic_udp_sessions_share_a_connection_without_crossing() {
    for protocol in ["hysteria2", "tuic"] {
        let tunnel = std::sync::Arc::new(tunnel(protocol, true, raw()).await);
        let sessions = (0..8u8).map(|n| {
            let tunnel = std::sync::Arc::clone(&tunnel);
            tokio::spawn(async move {
                let body = format!("{protocol} datagram {n} {}", "x".repeat(n as usize * 50));
                udp_round_trip(&tunnel, body.as_bytes()).await;
            })
        });
        for task in futures::future::join_all(sessions).await {
            task.unwrap();
        }
        assert_eq!(zero_transport::quic_pool::live_connections_to(tunnel.relay), 1, "{protocol}");
    }
}

/// After a network change the pooled connections move to a new socket
/// (QUIC connection migration): a stream opened before keeps working, and
/// new streams still share the migrated connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_quic_connection_survives_moving_to_a_new_socket() {
    for protocol in ["hysteria2", "tuic"] {
        let tunnel = tunnel(protocol, true, raw()).await;
        let mut before = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
        round_trip(&mut before, &payload(1, 2048)).await;

        assert!(zero_transport::quic_pool::rebind_all() >= 1, "{protocol}: nothing was migrated");

        round_trip(&mut before, &payload(2, 256 * 1024)).await;
        let mut after = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
        round_trip(&mut after, &payload(3, 2048)).await;
        assert_eq!(zero_transport::quic_pool::live_connections_to(tunnel.relay), 1, "{protocol}");
    }
}

/// Migration in the middle of transfers: streams in flight when the socket
/// changes must finish intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn transfers_in_flight_survive_a_migration() {
    for protocol in ["hysteria2", "tuic"] {
        let tunnel = tunnel(protocol, true, raw()).await;
        let transfers: Vec<_> = (0..6u8)
            .map(|seed| {
                let (socks, echo) = (tunnel.socks, tunnel.echo);
                tokio::spawn(async move {
                    let mut stream = socks_connect(socks, echo).await.unwrap();
                    for round in 0..4u8 {
                        round_trip(&mut stream, &payload(seed.wrapping_mul(7).wrapping_add(round), 256 * 1024)).await;
                    }
                })
            })
            .collect();
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(15)).await;
            zero_transport::quic_pool::rebind_all();
        }
        for task in futures::future::join_all(transfers).await {
            task.unwrap_or_else(|error| panic!("{protocol}: {error}"));
        }
    }
}

// ------------------------------------------------------------------- 0-RTT

/// A Hysteria2 server that takes early data (quinn with a TLS server that
/// issues tickets allowing 0-RTT), echoing every proxied stream.
async fn zero_rtt_hysteria2_server(echo: SocketAddr) -> SocketAddr {
    use rustls_pki_types::pem::PemObject;
    let certs = rustls_pki_types::CertificateDer::pem_slice_iter(CERTIFICATE.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(PRIVATE_KEY.as_bytes()).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = u32::MAX;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    server.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let mut acceptor = zero_transport::hysteria2::Acceptor::new(endpoint);
    tokio::spawn(async move {
        let passwords: Vec<Box<str>> = vec![PASSWORD.into()];
        while let Ok(Some(accepted)) = acceptor.accept(&passwords).await {
            if let zero_transport::hysteria2::Accepted::Tcp { mut stream, .. } = accepted {
                tokio::spawn(async move {
                    let mut upstream = TcpStream::connect(echo).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                });
            }
        }
    });
    address
}

/// The second connection to a Hysteria2 server that allows early data
/// resumes in 0-RTT: the handshake and the authentication share the first
/// flight. (A server that does not allow it gets an ordinary handshake.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hysteria2_reconnects_in_zero_rtt_when_the_server_allows_it() {
    let echo = echo_service().await;
    let server = zero_rtt_hysteria2_server(echo).await;
    let mut tls = zero_security::TlsParams::new(SERVER_NAME);
    tls.extra_roots = vec![CA_CERTIFICATE.as_bytes().to_vec()];
    let destination = zero_core::Destination::tcp(
        zero_core::Address::Ip(echo.ip()),
        echo.port(),
    );

    async fn echo_once(mut stream: zero_core::BoxStream, body: &[u8]) {
        stream.write_all(body).await.unwrap();
        let mut back = vec![0u8; body.len()];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut back))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(back, body);
    }

    let before = zero_transport::hysteria2::zero_rtt_accepted();
    let first = zero_transport::hysteria2::connect(&[server], &tls, PASSWORD, &destination)
        .await
        .expect("first connection");
    echo_once(first, b"first, in 1-RTT").await;
    // Give the server's session ticket time to arrive, then drop the pooled
    // connection so the next stream has to dial.
    tokio::time::sleep(Duration::from_millis(200)).await;
    zero_transport::quic_pool::close_all_to(server);

    let second = zero_transport::hysteria2::connect(&[server], &tls, PASSWORD, &destination)
        .await
        .expect("resumed connection");
    echo_once(second, b"second, resumed").await;
    assert!(
        zero_transport::hysteria2::zero_rtt_accepted() > before,
        "the reconnection did not use 0-RTT"
    );
}
