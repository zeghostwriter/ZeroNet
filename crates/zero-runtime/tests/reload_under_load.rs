//! Whole-generation reload under live traffic (PLAN-01 §4 / §8).
//!
//! A reload is only useful if it changes the graph for *new* sessions without
//! terminating sessions that were already relaying.  This test drives that
//! distinction through the public management endpoint rather than calling the
//! internal swap directly:
//!
//! 1. establish 32 SOCKS TCP sessions through generation 1 (Freedom);
//! 2. put every session in the middle of a delayed echo exchange;
//! 3. POST generation 2 (Blackhole is now the default) to `/reload`;
//! 4. require every established session to complete further exchanges; and
//! 5. require a fresh SOCKS request to receive `REP_NOT_ALLOWED`.
//!
//! This makes a state-lifetime regression visible.  Rebuilding an immutable
//! graph incorrectly, or making an established relay look up the replaced
//! graph again, would drop one or more of the active streams.  Conversely, if
//! the swap did not take effect, the fresh request would reach the echo service.

use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Barrier};

const FLOWS: usize = 32;
const ECHO_DELAY: Duration = Duration::from_millis(40);

/// Hand out a port no other test in this process has already selected.
///
/// Releasing an ephemeral port before the runtime binds it is still necessary
/// for a configuration-driven listener, but retaining the process-local record
/// prevents two test cases from selecting the same port and impersonating a
/// reload race.
fn free_port() -> u16 {
    use std::collections::HashSet;

    static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);
    for _ in 0..500 {
        let port = StdListener::bind("127.0.0.1:0")
            .expect("bind ephemeral")
            .local_addr()
            .expect("read ephemeral address")
            .port();
        let mut taken = TAKEN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if taken.get_or_insert_with(HashSet::new).insert(port) {
            return port;
        }
    }
    panic!("could not reserve a free test port");
}

fn config(socks_port: u16, block_by_default: bool) -> Value {
    let direct = json!({"tag": "direct", "protocol": "freedom"});
    let blackhole = json!({"tag": "blocked", "protocol": "blackhole"});
    let outbounds = if block_by_default {
        vec![blackhole, direct]
    } else {
        vec![direct, blackhole]
    };

    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
        }],
        "outbounds": outbounds,
    })
}

fn spawn(config: &Value) -> Arc<zero_runtime::Server> {
    let (generation, _) = zero_config::compile_config(config, zero_core::GenerationId(1))
        .unwrap_or_else(|error| panic!("configuration rejected: {error}\n{config:#}"));
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = running.run().await;
    });
    server
}

async fn wait_for_listener(address: SocketAddr) {
    for _ in 0..200 {
        if TcpStream::connect(address).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{address} never started listening");
}

/// A framing-aware echo service.  Its short reply delay creates a known window
/// in which all test flows have live data outstanding while reload runs.
async fn delayed_echo_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo listener");
    let address = listener.local_addr().expect("read echo address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                loop {
                    let mut header = [0u8; 4];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let length = u32::from_be_bytes(header) as usize;
                    if length == 0 || length > 1024 * 1024 {
                        return;
                    }
                    let mut body = vec![0u8; length];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(ECHO_DELAY).await;
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

async fn socks_connect_reply(socks: SocketAddr, target: SocketAddr) -> (u8, TcpStream) {
    let mut stream = TcpStream::connect(socks).await.expect("connect SOCKS");
    stream.set_nodelay(true).expect("enable TCP_NODELAY");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write SOCKS greeting");
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .expect("read SOCKS greeting");
    assert_eq!(greeting, [0x05, 0x00], "SOCKS no-auth was refused");

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    match target.ip() {
        std::net::IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(_) => panic!("the loopback test targets IPv4"),
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&request)
        .await
        .expect("write SOCKS request");

    let mut reply = [0u8; 4];
    stream
        .read_exact(&mut reply)
        .await
        .expect("read SOCKS reply");
    assert_eq!(reply[0], 0x05, "invalid SOCKS reply version");
    let address_length = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .expect("read SOCKS domain reply length");
            length[0] as usize
        }
        other => panic!("unexpected SOCKS reply address type {other}"),
    };
    let mut discard = vec![0u8; address_length + 2];
    stream
        .read_exact(&mut discard)
        .await
        .expect("read SOCKS reply address");
    (reply[1], stream)
}

async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> TcpStream {
    let (code, stream) = socks_connect_reply(socks, target).await;
    assert_eq!(code, 0x00, "SOCKS CONNECT failed with reply {code}");
    stream
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8]) {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .expect("write echo frame length");
    stream
        .write_all(payload)
        .await
        .expect("write echo frame body");
    stream.flush().await.expect("flush echo frame");
}

async fn read_frame(stream: &mut TcpStream, expected: &[u8]) {
    let mut header = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .expect("echo header timed out")
        .expect("echo header failed");
    assert_eq!(u32::from_be_bytes(header) as usize, expected.len());
    let mut body = vec![0u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut body))
        .await
        .expect("echo body timed out")
        .expect("echo body failed");
    assert_eq!(body, expected, "echo payload was altered");
}

async fn round_trip(stream: &mut TcpStream, payload: &[u8]) {
    write_frame(stream, payload).await;
    read_frame(stream, payload).await;
}

fn payload(flow: usize, exchange: usize) -> Vec<u8> {
    let length = 1024 + ((flow * 113 + exchange * 307) % 4096);
    (0..length)
        .map(|index| {
            (flow as u8)
                .wrapping_add(exchange as u8)
                .wrapping_add(index as u8)
        })
        .collect()
}

async fn post_reload(api: SocketAddr, next_config: &Value) -> Value {
    let body = serde_json::to_vec(next_config).expect("encode reload configuration");
    let mut stream = TcpStream::connect(api)
        .await
        .expect("connect management API");
    let request = format!(
        "POST /reload HTTP/1.1\r\nHost: {api}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write reload headers");
    stream.write_all(&body).await.expect("write reload body");
    stream.flush().await.expect("flush reload request");

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("reload response timed out")
        .expect("read reload response");
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("reload response has no HTTP header")
        + 4;
    assert!(
        response[..head_end].starts_with(b"HTTP/1.1 200"),
        "reload endpoint refused config: {}",
        String::from_utf8_lossy(&response),
    );
    serde_json::from_slice(&response[head_end..]).expect("decode reload response")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn reload_preserves_active_flows_and_applies_the_new_graph_to_new_sessions() {
    let socks = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let management = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let generation_one = config(socks.port(), false);
    let generation_two = config(socks.port(), true);
    let server = spawn(&generation_one);
    let api = zero_runtime::api::ManagementServer::new(zero_runtime::api::ManagementConfig {
        listen: management,
        bearer_token: None,
    })
    .expect("construct loopback management API");
    let api_server = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = api.run(api_server).await;
    });
    wait_for_listener(socks).await;
    wait_for_listener(management).await;

    let echo = delayed_echo_service().await;
    let start_traffic = Arc::new(Barrier::new(FLOWS + 1));
    let (ready_tx, mut ready_rx) = mpsc::channel(FLOWS);
    let (active_tx, mut active_rx) = mpsc::channel(FLOWS);
    let mut flows = Vec::with_capacity(FLOWS);

    for flow in 0..FLOWS {
        let start_traffic = Arc::clone(&start_traffic);
        let ready_tx = ready_tx.clone();
        let active_tx = active_tx.clone();
        flows.push(tokio::spawn(async move {
            let mut stream = socks_connect(socks, echo).await;
            round_trip(&mut stream, &payload(flow, 0)).await;
            ready_tx.send(()).await.expect("report ready flow");

            // All streams begin an exchange together.  The marker is emitted
            // only after the frame has been flushed, while the echo's reply is
            // deliberately delayed, so reload is performed with every stream
            // in flight rather than merely connected and idle.
            start_traffic.wait().await;
            let first_live_payload = payload(flow, 1);
            write_frame(&mut stream, &first_live_payload).await;
            active_tx.send(()).await.expect("report active flow");
            read_frame(&mut stream, &first_live_payload).await;

            // These reads and writes happen after generation 2 is installed.
            // They must continue to use the already-open relay rather than
            // being re-routed through its new Blackhole default.
            for exchange in 2..8 {
                round_trip(&mut stream, &payload(flow, exchange)).await;
            }
        }));
    }
    drop(ready_tx);
    drop(active_tx);

    for flow in 0..FLOWS {
        tokio::time::timeout(Duration::from_secs(5), ready_rx.recv())
            .await
            .expect("flow did not establish before reload")
            .unwrap_or_else(|| panic!("flow {flow} setup channel closed"));
    }
    start_traffic.wait().await;
    for flow in 0..FLOWS {
        tokio::time::timeout(Duration::from_secs(5), active_rx.recv())
            .await
            .expect("flow did not become active before reload")
            .unwrap_or_else(|| panic!("flow {flow} active channel closed"));
    }

    let response = post_reload(management, &generation_two).await;
    assert_eq!(
        response["generation"], 2,
        "reload returned wrong generation"
    );
    assert_eq!(server.current_generation(), zero_core::GenerationId(2));

    for (flow, task) in flows.into_iter().enumerate() {
        task.await
            .unwrap_or_else(|error| panic!("active flow {flow} was dropped: {error}"));
    }

    // A connection born after the swap must see the replacement graph.  The
    // explicit SOCKS refusal proves this is a routing change, not merely a
    // generation counter update.
    let (reply, _) = socks_connect_reply(socks, echo).await;
    assert_eq!(reply, 0x02, "new session did not use Blackhole generation");
    assert!(
        server.stats.snapshot().blocked >= 1,
        "the replacement Blackhole route was not recorded",
    );
}
