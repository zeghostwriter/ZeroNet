//! Graceful drain: active-session accounting and bounded shutdown wait.
//!
//! The drain contract is that `Server::drain` returns 0 only once every live
//! TCP session has finished, and returns the still-active count when its
//! timeout elapses first. This drives that through a real SOCKS session held
//! open against a delayed echo service, so the gauge is exercised by an actual
//! relay rather than a hand-incremented counter.

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

fn config(socks_port: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
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

/// Echo service that holds a reply until told, so a session stays live.
async fn gated_echo_service() -> (SocketAddr, Arc<tokio::sync::Notify>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let address = listener.local_addr().expect("echo address");
    let release = Arc::new(tokio::sync::Notify::new());
    let service_release = Arc::clone(&release);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let release = Arc::clone(&service_release);
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                let n = match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                // Hold the session open until the test releases it.
                release.notified().await;
                let _ = stream.write_all(&buf[..n]).await;
                let _ = stream.flush().await;
            });
        }
    });
    (address, release)
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
async fn drain_waits_for_the_live_session_then_reports_clean() {
    let socks = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let server = spawn(&config(socks.port()));
    wait_for_listener(socks).await;
    let (echo, release) = gated_echo_service().await;

    let mut client = socks_connect(socks, echo).await;
    client.write_all(b"hold-open").await.unwrap();
    client.flush().await.unwrap();

    // The relay is now live end-to-end; the gauge must see exactly one session.
    let mut seen = 0;
    for _ in 0..200 {
        if server.active_sessions() >= 1 {
            seen = server.active_sessions();
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(seen, 1, "the live session was not counted");

    // A short drain cannot succeed while the echo reply is still gated.
    let remaining = server.drain(Duration::from_millis(150)).await;
    assert_eq!(remaining, 1, "drain should time out with the session live");

    // Release the echo, read the reply, and close the client. The session
    // ends, and a subsequent drain returns cleanly.
    release.notify_waiters();
    let mut buf = [0u8; 9];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hold-open");
    drop(client);

    let remaining = server.drain(Duration::from_secs(5)).await;
    assert_eq!(remaining, 0, "drain never observed the session finish");
    assert_eq!(server.active_sessions(), 0);
}
