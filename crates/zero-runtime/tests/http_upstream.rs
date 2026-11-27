//! An `http` outbound reaches its destination through an HTTP proxy with
//! `CONNECT`, logging in when it has to. The upstream here is Zray's own HTTP
//! inbound in the same process, so the two ends are checked against each
//! other, with accounts on one and credentials on the other.

use std::net::TcpListener as StdListener;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn echo_sink() -> u16 {
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = sink.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = sink.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 || socket.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

async fn start(config: Value) {
    let (generation, _) =
        zero_config::compile_config(&config, zero_core::GenerationId(1)).expect("config");
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move { running.run().await });
    server.wait_until_listening().await;
}

/// Through the SOCKS5 inbound to the sink; true when "ping" comes back.
async fn echoes(socks_port: u16, sink_port: u16) -> bool {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&sink_port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    let answered =
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut reply)).await;
    if !matches!(answered, Ok(Ok(_))) || reply[1] != 0 {
        return false;
    }
    stream.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut echo))
        .await
        .is_ok_and(|read| read.is_ok())
        && &echo == b"ping"
}

fn rig_config(socks_port: u16, upstream_port: u16, pass: &str) -> Value {
    json!({
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks"},
            {
                "tag": "proxy-in", "listen": "127.0.0.1", "port": upstream_port,
                "protocol": "http",
                "settings": {"accounts": [{"user": "alice", "pass": "wonderland"}]},
            },
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {
                "tag": "via-http", "protocol": "http",
                "settings": {"servers": [{
                    "address": "127.0.0.1", "port": upstream_port,
                    "users": [{"user": "alice", "pass": pass}],
                }]},
            },
        ],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["socks"], "outboundTag": "via-http"},
            {"type": "field", "inboundTag": ["proxy-in"], "outboundTag": "direct"},
        ]},
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_http_outbound_tunnels_through_a_proxy_that_wants_a_login() {
    let sink = echo_sink().await;
    let (socks, upstream) = (free_port(), free_port());
    start(rig_config(socks, upstream, "wonderland")).await;
    assert!(echoes(socks, sink).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_password_is_a_refused_connection_not_a_hang() {
    let sink = echo_sink().await;
    let (socks, upstream) = (free_port(), free_port());
    start(rig_config(socks, upstream, "not-the-password")).await;
    assert!(!echoes(socks, sink).await);
}
