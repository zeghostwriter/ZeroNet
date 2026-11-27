//! A balancer member that cannot be reached, or that never answers, costs a
//! slow session, not a failed one: the connection goes through the next
//! member.
//!
//! The pool holds a SOCKS outbound pointed at a port that refuses (or one
//! that accepts and stays silent) and a direct one. Round-robin makes the
//! bad one the first pick for every other session; every session must still
//! reach the echo service.

use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

fn config(socks_port: u16, dead_port: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
        }],
        "outbounds": [
            {"tag": "pool-dead", "protocol": "socks", "settings": {
                "servers": [{"address": "127.0.0.1", "port": dead_port}]}},
            {"tag": "pool-live", "protocol": "freedom"},
        ],
        "routing": {
            "balancers": [{"tag": "pool", "selector": ["pool-"],
                           "strategy": {"type": "roundRobin"}}],
            "rules": [{"type": "field", "network": "tcp", "balancerTag": "pool"}],
        },
    })
}

fn spawn(config: &Value) -> Arc<zero_runtime::Server> {
    let (generation, _) = zero_config::compile_config(config, zero_core::GenerationId(1))
        .unwrap_or_else(|error| panic!("configuration rejected: {error}"));
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

async fn echo_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let address = listener.local_addr().expect("echo address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            });
        }
    });
    address
}

async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(socks).await.expect("connect SOCKS");
    stream.set_nodelay(true).unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    match target.ip() {
        std::net::IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(_) => panic!("test targets IPv4"),
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    let addr_len = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        other => panic!("unexpected reply atyp {other}"),
    };
    let mut discard = vec![0u8; addr_len + 2];
    stream.read_exact(&mut discard).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS CONNECT failed");
    stream
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_member_is_skipped_for_the_next_one() {
    let socks = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let closed = free_port();
    let _server = spawn(&config(socks.port(), closed));
    wait_for_listener(socks).await;
    let echo = echo_service().await;
    for round in 0..4 {
        let mut client = socks_connect(socks, echo).await;
        client.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut back))
            .await
            .unwrap_or_else(|_| panic!("session {round} got no answer"))
            .unwrap();
        assert_eq!(&back, b"ping", "session {round}");
    }
}

/// A member that accepts the connection and then says nothing is not waited
/// for: after a few seconds the next member is tried beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_member_is_raced_by_the_next_one() {
    let silent = TcpListener::bind("127.0.0.1:0").await.expect("bind silent");
    let silent_port = silent.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = silent.accept().await {
            held.push(stream);
        }
    });
    let socks = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let _server = spawn(&config(socks.port(), silent_port));
    wait_for_listener(socks).await;
    let echo = echo_service().await;
    let started = std::time::Instant::now();
    let mut client = socks_connect(socks, echo).await;
    client.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(8), client.read_exact(&mut back))
        .await
        .expect("the silent member held the session")
        .unwrap();
    assert_eq!(&back, b"ping");
    assert!(started.elapsed() < Duration::from_secs(7));
}

/// A transparent session (the path a VPN's TUN device uses) fails over too:
/// it used to take whichever member the balancer picked and give up when that
/// one could not be reached, again and again, since nothing learned from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transparent_session_goes_through_the_next_member_when_one_is_dead() {
    let echo = echo_service().await;
    let (forward_port, dead_port) = (free_port(), free_port());
    let mut config = config(free_port(), dead_port);
    config["inbounds"] = json!([{
        "tag": "forward-in",
        "listen": "127.0.0.1",
        "port": forward_port,
        "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1", "port": echo.port(), "network": "tcp"},
    }]);
    let _server = spawn(&config);
    let forward = SocketAddr::from(([127, 0, 0, 1], forward_port));
    wait_for_listener(forward).await;
    for round in 0..4 {
        let mut client = TcpStream::connect(forward).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut back))
            .await
            .unwrap_or_else(|_| panic!("session {round} got no answer"))
            .unwrap_or_else(|error| panic!("session {round} was closed: {error}"));
        assert_eq!(&back, b"ping", "session {round}");
    }
}
