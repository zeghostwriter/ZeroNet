//! Protocol and transport interoperability, Zray client against Zray server.
//!
//! Every one of these runs two complete runtime instances over the loopback
//! interface: a client with a SOCKS inbound and a proxy outbound, and a server
//! with the matching proxy inbound and a freedom outbound. Traffic is driven
//! through the client's SOCKS port and must arrive intact at an ordinary TCP
//! service on the other side.
//!
//! This is the level at which framing bugs actually show up. A unit test over a
//! codec proves the codec round-trips its own output; it cannot catch a header
//! written once per connection instead of once per request, a flush that never
//! happens, or a length prefix that is correct in isolation and wrong when two
//! requests share a carrier. Those only appear when the whole stack is
//! assembled and made to carry concurrent, sized, bidirectional traffic — which
//! is what these do.

use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const SS_PASSWORD: &str = "an-example-shadowsocks-password";
const TROJAN_PASSWORD: &str = "an-example-trojan-password";

/// Hand out a port no other test in this process has been given.
///
/// Binding `:0` and releasing is the usual trick, but two tests running
/// concurrently can be handed the *same* ephemeral port, and the second server
/// to bind it then fails or steals the first one's traffic — a failure that
/// looks exactly like a protocol race. The allocator keeps a process-wide
/// record so that cannot happen.
fn free_port() -> u16 {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);

    for _ in 0..500 {
        let port = StdListener::bind("127.0.0.1:0")
            .expect("bind ephemeral")
            .local_addr()
            .expect("local addr")
            .port();
        let mut taken = TAKEN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if taken.get_or_insert_with(HashSet::new).insert(port) {
            return port;
        }
    }
    panic!("could not reserve a free port");
}

/// Enable runtime logs when `ZRAY_TEST_LOG` is set, so a failing interop test
/// can be diagnosed without editing it.
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
        .unwrap_or_else(|error| {
            panic!("configuration rejected: {error}\n{config:#}");
        });
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

/// Wait for a spawned server to report every listener bound, rather than
/// inferring it from the outside.
async fn wait_until_listening(server: &Arc<zero_runtime::Server>) {
    tokio::time::timeout(Duration::from_secs(30), server.wait_until_listening())
        .await
        .expect("server never reported its listeners bound");
}

/// A length-prefixed echo service: the client sends `len` then `len` bytes and
/// reads them back. Sizing the exchange explicitly is what makes a truncated or
/// duplicated frame a test failure rather than a timing artefact.
async fn echo_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                loop {
                    let mut header = [0u8; 4];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let length = u32::from_be_bytes(header) as usize;
                    if length == 0 || length > 4 * 1024 * 1024 {
                        return;
                    }
                    let mut body = vec![0u8; length];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    if stream.write_all(&header).await.is_err()
                        || stream.write_all(&body).await.is_err()
                        || stream.flush().await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    address
}

/// Open a SOCKS5 CONNECT tunnel to `target` through `socks`.
async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.set_nodelay(true)?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [0x05, 0x00], "SOCKS5 no-auth was refused");

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    match target.ip() {
        std::net::IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(_) => panic!("test targets are IPv4"),
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT failed with {}", reply[1]);
    let skip = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        other => panic!("unexpected SOCKS5 address type {other}"),
    };
    let mut discard = vec![0u8; skip + 2];
    stream.read_exact(&mut discard).await?;
    Ok(stream)
}

/// Send `payload` through an established tunnel and require it back verbatim.
async fn round_trip(stream: &mut TcpStream, payload: &[u8]) {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut header = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
        .await
        .expect("echo header timed out")
        .expect("echo header failed");
    assert_eq!(u32::from_be_bytes(header) as usize, payload.len());
    let mut body = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .expect("echo body timed out")
        .expect("echo body failed");
    assert_eq!(body, payload, "payload came back altered");
}

fn payload(seed: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

struct Tunnel {
    socks: SocketAddr,
    echo: SocketAddr,
}

/// Stand up a client/server pair carrying `protocol` over `transport`.
async fn tunnel(protocol: &str, transport: Value) -> Tunnel {
    let echo = echo_service().await;
    let relay_port = free_port();
    let socks_port = free_port();

    let (server_settings, client_settings) = match protocol {
        "vless" => (
            json!({"clients": [{"id": UUID}]}),
            json!({"vnext": [{
                "address": "127.0.0.1",
                "port": relay_port,
                "users": [{"id": UUID, "encryption": "none"}]
            }]}),
        ),
        "trojan" => (
            json!({"clients": [{"password": TROJAN_PASSWORD}]}),
            json!({"servers": [{
                "address": "127.0.0.1",
                "port": relay_port,
                "password": TROJAN_PASSWORD
            }]}),
        ),
        "vmess" => (
            json!({"clients": [{"id": UUID}]}),
            json!({"vnext": [{
                "address": "127.0.0.1",
                "port": relay_port,
                "users": [{"id": UUID, "security": "auto"}]
            }]}),
        ),
        // Zray implements the legacy AEAD ciphers; the 2022-blake3 family is
        // not present, so the harness exercises what exists.
        "shadowsocks" => (
            json!({"method": "aes-256-gcm", "password": SS_PASSWORD}),
            json!({"servers": [{
                "address": "127.0.0.1",
                "port": relay_port,
                "method": "aes-256-gcm",
                "password": SS_PASSWORD
            }]}),
        ),
        other => panic!("unsupported protocol {other} in the harness"),
    };

    let relay = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "relay-in",
            "listen": "127.0.0.1",
            "port": relay_port,
            "protocol": protocol,
            "settings": server_settings,
            "streamSettings": transport,
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
            "streamSettings": transport,
        }],
    }));

    wait_until_listening(&relay).await;
    wait_until_listening(&client).await;
    Tunnel {
        socks: SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port),
        echo,
    }
}

fn raw() -> Value {
    json!({"network": "tcp"})
}

fn websocket() -> Value {
    json!({"network": "ws", "wsSettings": {"path": "/tunnel"}})
}

fn http_upgrade() -> Value {
    json!({"network": "httpupgrade", "httpupgradeSettings": {"path": "/tunnel"}})
}

fn grpc() -> Value {
    json!({"network": "grpc", "grpcSettings": {"serviceName": "TunnelService"}})
}

fn xhttp(mode: &str, version: &str) -> Value {
    // `httpVersion` belongs inside `xhttpSettings`; at the top level of
    // `streamSettings` it is silently ignored and the version falls back to an
    // ALPN heuristic — which is how the HTTP/3 case in the TLS suite spent its
    // life running HTTP/2.
    json!({
        "network": "xhttp",
        "xhttpSettings": {
            "path": "/tunnel",
            "mode": mode,
            "httpVersion": version,
            "extra": {"xmux": {}},
        },
    })
}

// ---------------------------------------------------------------- protocols

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_over_raw_tcp_carries_payload_intact() {
    let tunnel = tunnel("vless", raw()).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(1, 64)).await;
    // A second exchange on the same tunnel: the header is written once, and a
    // codec that re-emits it would corrupt this one.
    round_trip(&mut stream, &payload(2, 96 * 1024)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trojan_over_raw_tcp_carries_payload_intact() {
    let tunnel = tunnel("trojan", raw()).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(3, 64)).await;
    round_trip(&mut stream, &payload(4, 128 * 1024)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vmess_over_raw_tcp_carries_payload_intact() {
    let tunnel = tunnel("vmess", raw()).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(5, 64)).await;
    // VMess chunks its payload; a size that straddles several chunks is the
    // case where an off-by-one in the length prefix becomes visible.
    round_trip(&mut stream, &payload(6, 200 * 1024)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shadowsocks_aead_over_raw_tcp_carries_payload_intact() {
    let tunnel = tunnel("shadowsocks", raw()).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(7, 64)).await;
    round_trip(&mut stream, &payload(8, 150 * 1024)).await;
}

// --------------------------------------------------------------- transports

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_over_websocket_carries_payload_intact() {
    let tunnel = tunnel("vless", websocket()).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(9, 64)).await;
    // Larger than one WebSocket frame, so frame reassembly is exercised.
    round_trip(&mut stream, &payload(10, 256 * 1024)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_over_http_upgrade_carries_payload_intact() {
    let tunnel = tunnel("vless", http_upgrade()).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(11, 64)).await;
    round_trip(&mut stream, &payload(12, 128 * 1024)).await;
}

/// Locks a defect this suite found: the HTTPUpgrade carrier never wrote the
/// protocol header, so the server waited forever for a request that was never
/// sent. Trojan exercises the same code path with a different header, which is
/// what makes it a check on the carrier rather than on VLESS.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trojan_over_http_upgrade_sends_its_request_header() {
    let tunnel = tunnel("trojan", http_upgrade()).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(21, 64)).await;
    round_trip(&mut stream, &payload(22, 64 * 1024)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_upgrade_keeps_concurrent_flows_separate() {
    let tunnel = tunnel("vless", http_upgrade()).await;
    concurrent_flows(&tunnel, 32, 16 * 1024).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_over_grpc_carries_payload_intact() {
    let tunnel = tunnel("vless", grpc()).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(13, 64)).await;
    round_trip(&mut stream, &payload(14, 128 * 1024)).await;
}

// ------------------------------------------------------------ concurrency

/// Many simultaneous tunnels over one carrier.
///
/// Concurrency is where multiplexed transports fail, and they fail silently:
/// a stream-id mix-up delivers the wrong bytes to the wrong session rather than
/// erroring, so every flow here carries a distinct payload and checks it back.
async fn concurrent_flows(tunnel: &Tunnel, flows: usize, size: usize) {
    let mut tasks = Vec::with_capacity(flows);
    for index in 0..flows {
        let socks = tunnel.socks;
        let echo = tunnel.echo;
        tasks.push(tokio::spawn(async move {
            let mut stream = socks_connect(socks, echo).await.unwrap();
            let body = payload(index as u8, size);
            round_trip(&mut stream, &body).await;
            round_trip(&mut stream, &body).await;
        }));
    }
    for (index, task) in tasks.into_iter().enumerate() {
        task.await
            .unwrap_or_else(|error| panic!("flow {index}: {error}"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn websocket_keeps_concurrent_flows_separate() {
    let tunnel = tunnel("vless", websocket()).await;
    concurrent_flows(&tunnel, 32, 16 * 1024).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn grpc_keeps_concurrent_flows_separate() {
    let tunnel = tunnel("vless", grpc()).await;
    concurrent_flows(&tunnel, 32, 16 * 1024).await;
}

// --------------------------------------------------------------------- XHTTP

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xhttp_stream_one_over_http1_carries_payload_intact() {
    let tunnel = tunnel("vless", xhttp("stream-one", "h1")).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(30, 64)).await;
    round_trip(&mut stream, &payload(31, 128 * 1024)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xhttp_packet_up_over_http1_carries_payload_intact() {
    // packet-up splits the upload into discrete POSTs, so this is the mode
    // where sequence numbering and reassembly can go wrong.
    let tunnel = tunnel("vless", xhttp("packet-up", "h1")).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(32, 64)).await;
    round_trip(&mut stream, &payload(33, 128 * 1024)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xhttp_stream_up_over_http1_carries_payload_intact() {
    let tunnel = tunnel("vless", xhttp("stream-up", "h1")).await;
    let mut stream = socks_connect(tunnel.socks, tunnel.echo).await.unwrap();
    round_trip(&mut stream, &payload(34, 64)).await;
    round_trip(&mut stream, &payload(35, 128 * 1024)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn xhttp_stream_one_keeps_concurrent_flows_separate() {
    let tunnel = tunnel("vless", xhttp("stream-one", "h1")).await;
    concurrent_flows(&tunnel, 24, 16 * 1024).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn xhttp_packet_up_keeps_concurrent_flows_separate() {
    let tunnel = tunnel("vless", xhttp("packet-up", "h1")).await;
    concurrent_flows(&tunnel, 24, 16 * 1024).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn raw_tcp_keeps_concurrent_flows_separate() {
    let tunnel = tunnel("vless", raw()).await;
    concurrent_flows(&tunnel, 64, 8 * 1024).await;
}
