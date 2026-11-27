//! What a SOCKS client is told when the proxy server cannot be reached.
//!
//! The desktop app checks a profile by sending a SOCKS CONNECT and reading
//! the answer. A server that refuses the connection must come back as a
//! "host unreachable" answer the app can show, not as a connection that is
//! closed without a word (which reads as a bare "EOF").

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn a_refused_server_is_answered_with_host_unreachable() {
    let (socks_port, dead_port) = (free_port(), free_port());
    let config = json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks"}],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1", "port": dead_port,
                "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "encryption": "none"}]}]},
            "streamSettings": {"network": "tcp", "security": "none"},
        }],
    });
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1)).unwrap();
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    let socks: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    for _ in 0..200 {
        if TcpStream::connect(socks).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut stream = TcpStream::connect(socks).await.unwrap();
    let host = b"example.com";
    let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&443u16.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    let mut reply = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut reply))
        .await
        .expect("the proxy must answer")
        .expect("the proxy closed the connection without an answer");
    assert_eq!(reply[1], 0x04, "expected SOCKS host unreachable");
}
