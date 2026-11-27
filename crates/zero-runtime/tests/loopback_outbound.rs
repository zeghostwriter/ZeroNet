//! A `loopback` outbound routes a connection a second time, as if it had
//! arrived on another inbound, so that inbound's rules apply.

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
}

fn config(socks_port: u16, second_rule_target: &str) -> Value {
    json!({
        "inbounds": [
            {"tag": "first", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks"},
            {"tag": "second", "listen": "127.0.0.1", "port": free_port(), "protocol": "socks"},
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
            {"tag": "again", "protocol": "loopback", "settings": {"inboundTag": "second"}},
        ],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["first"], "outboundTag": "again"},
            {"type": "field", "inboundTag": ["second"], "outboundTag": second_rule_target},
        ]},
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_second_routing_decides_where_the_connection_goes() {
    let sink = echo_sink().await;
    let (open, shut) = (free_port(), free_port());
    start(config(open, "direct")).await;
    start(config(shut, "block")).await;
    assert!(echoes(open, sink).await);
    assert!(
        !echoes(shut, sink).await,
        "the second inbound's rule was not applied"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_loop_of_loopbacks_ends_in_a_refusal() {
    let sink = echo_sink().await;
    let port = free_port();
    start(config(port, "again")).await;
    assert!(!echoes(port, sink).await);
}

#[test]
fn a_loopback_must_name_the_inbound() {
    let bad = json!({
        "inbounds": [],
        "outbounds": [{"tag": "x", "protocol": "loopback", "settings": {}}],
    });
    assert!(zero_config::parse_config(&bad).is_err());
}
