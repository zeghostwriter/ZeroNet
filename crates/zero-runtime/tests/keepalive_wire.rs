//! Keepalive shaping, observed on the wire (PLAN-01 §5.2).
//!
//! The planner's decision to shape a flow's lifetime is tested in the
//! observatory; that the rung lands on an outbound as concrete numbers is
//! tested in `zero-runtime`'s own unit tests; that the timing logic is right is
//! tested in `zero-evasion`. None of that proves a single byte leaves the host.
//!
//! A flow-timeout policy is answered by what a middlebox *sees*, so the only
//! test that settles it is one that watches the socket. This one stands a
//! WebSocket relay in front of the outbound and counts the frames that arrive
//! while the session is deliberately idle.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// WebSocket opcodes, from RFC 6455 §5.2.
const OP_BINARY: u8 = 0x2;
const OP_PING: u8 = 0x9;

#[derive(Default)]
struct FrameTally {
    pings: AtomicUsize,
    binary: AtomicUsize,
}

/// A relay that completes the WebSocket upgrade and then only counts frames.
///
/// It deliberately never answers: a Pong would be the *peer's* traffic, and
/// what is being measured is whether Zray keeps the flow alive on its own.
async fn counting_ws_relay(tally: Arc<FrameTally>) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let tally = Arc::clone(&tally);
            tokio::spawn(async move {
                // Read the upgrade request and answer it, so the carrier comes
                // up and the session settles into its idle state.
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => head.push(byte[0]),
                    }
                }
                let key = String::from_utf8_lossy(&head)
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("sec-websocket-key")
                            .then(|| value.trim().to_owned())
                    })
                    .unwrap_or_default();
                let accept = websocket_accept(&key);
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                if stream.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
                let _ = stream.flush().await;

                // Count frames until the peer goes away.
                loop {
                    let Some(opcode) = read_frame(&mut stream).await else {
                        return;
                    };
                    match opcode {
                        OP_PING => {
                            tally.pings.fetch_add(1, Ordering::Relaxed);
                        }
                        OP_BINARY => {
                            tally.binary.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    Ok(address)
}

/// `Sec-WebSocket-Accept`, per RFC 6455 §4.2.2.
fn websocket_accept(key: &str) -> String {
    use base64::Engine;
    use sha1::{Digest, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Read one WebSocket frame and return its opcode, discarding the payload.
async fn read_frame(stream: &mut TcpStream) -> Option<u8> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.ok()?;
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let length = match header[1] & 0x7f {
        126 => {
            let mut extended = [0u8; 2];
            stream.read_exact(&mut extended).await.ok()?;
            u16::from_be_bytes(extended) as usize
        }
        127 => {
            let mut extended = [0u8; 8];
            stream.read_exact(&mut extended).await.ok()?;
            u64::from_be_bytes(extended) as usize
        }
        short => short as usize,
    };
    if masked {
        let mut mask = [0u8; 4];
        stream.read_exact(&mut mask).await.ok()?;
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).await.ok()?;
    Some(opcode)
}

fn spawn(config: Value) -> Arc<zero_runtime::Server> {
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Build a client whose WebSocket outbound carries the given keepalive shape.
fn client_config(relay: SocketAddr, socks_port: u16, keepalive: Option<Value>) -> Value {
    let mut stream = json!({
        "network": "ws",
        "wsSettings": {"path": "/tunnel"},
    });
    if let Some(keepalive) = keepalive {
        stream["finalmask"] = json!({
            "tcp": [{"type": "keepalive", "settings": keepalive}],
        });
    }
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "127.0.0.1",
                "port": relay.port(),
                "users": [{"id": UUID, "encryption": "none"}],
            }]},
            "streamSettings": stream,
        }],
    })
}

/// Open a SOCKS session and leave it idle for `hold`.
async fn idle_session(socks: SocketAddr, hold: Duration) {
    let mut stream = TcpStream::connect(socks).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    // CONNECT to an arbitrary address; the relay never completes the tunnel,
    // which is the idle state being measured.
    stream
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb])
        .await
        .unwrap();
    tokio::time::sleep(hold).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shaped_websocket_carrier_keeps_an_idle_flow_alive() {
    let tally = Arc::new(FrameTally::default());
    let relay = counting_ws_relay(Arc::clone(&tally)).await.unwrap();
    let socks_port = free_port();
    let server = spawn(client_config(
        relay,
        socks_port,
        Some(json!({"idle": "150ms", "lifetime": "60s"})),
    ));
    tokio::time::timeout(Duration::from_secs(10), server.wait_until_listening())
        .await
        .expect("server listening");

    let socks = SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port);
    idle_session(socks, Duration::from_secs(2)).await;

    let pings = tally.pings.load(Ordering::Relaxed);
    assert!(
        pings >= 3,
        "an idle shaped carrier should have emitted several WebSocket pings \
         over two seconds at a 150ms threshold, saw {pings}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unshaped_carrier_stays_silent() {
    // The cost of shaping is real traffic, so it must not happen until the
    // planner has evidence that it should. Without this, the test above would
    // pass just as well on a carrier that pings unconditionally.
    let tally = Arc::new(FrameTally::default());
    let relay = counting_ws_relay(Arc::clone(&tally)).await.unwrap();
    let socks_port = free_port();
    let server = spawn(client_config(relay, socks_port, None));
    tokio::time::timeout(Duration::from_secs(10), server.wait_until_listening())
        .await
        .expect("server listening");

    let socks = SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port);
    idle_session(socks, Duration::from_secs(2)).await;

    assert_eq!(
        tally.pings.load(Ordering::Relaxed),
        0,
        "an unshaped carrier must not put keepalive traffic on the wire"
    );
}
