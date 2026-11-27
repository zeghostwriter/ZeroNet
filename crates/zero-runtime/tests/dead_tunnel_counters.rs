//! What the byte counters show for a tunnel that is up but dead.
//!
//! The desktop watchdog and the Android stall check both decide "is this
//! connection carrying traffic?" from the engine's counters. This pins the
//! fact they rely on: against a server that accepts and never answers, the
//! applications' retries still count as *uploaded* bytes, while nothing is
//! ever *downloaded*. Upload alone is therefore no proof of a working tunnel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Accept and then say nothing at all: a blackholed or dead server.
async fn silent_peer() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut stream, _)) = listener.accept().await {
            // Read (so the client's writes complete) but never reply.
            tokio::spawn(async move {
                let mut sink = [0u8; 4096];
                while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
            });
            held.push(());
        }
    });
    address
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn socks_connect(socks: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(socks).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    // CONNECT example.com:443 by name.
    let host = b"example.com";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&443u16.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS CONNECT refused");
    stream
}

#[tokio::test]
async fn a_dead_tunnel_counts_retries_as_upload_and_nothing_as_download() {
    let dead = silent_peer().await;
    let socks_port = free_port();
    let config = json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks"}],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1", "port": dead.port(),
                "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "encryption": "none"}]}]},
            "streamSettings": {"network": "tcp", "security": "none"},
        }],
    });
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1)).unwrap();
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = running.run().await;
    });
    let socks: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    for _ in 0..200 {
        if TcpStream::connect(socks).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // An application retrying a request three times; each attempt writes a
    // ClientHello-sized payload, waits, gets nothing and gives up.
    for _ in 0..3 {
        let mut stream = socks_connect(socks).await;
        stream.write_all(&[0x16; 600]).await.unwrap();
        let mut buf = [0u8; 1];
        let answered =
            tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await;
        assert!(
            !matches!(answered, Ok(Ok(n)) if n > 0),
            "the dead server must not answer"
        );
        drop(stream);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let stats = server.stats.snapshot();
    assert!(
        stats.uploaded > 0,
        "retries into a dead tunnel are counted as upload: {stats:?}"
    );
    assert_eq!(stats.downloaded, 0, "nothing came back: {stats:?}");
}
