//! Local stand-ins for the network, shared by the job tests.
//!
//! Every real-stage test needs a working proxy and a probe endpoint. Both run
//! on the loopback interface: a complete Zray runtime with a Shadowsocks
//! inbound and a `freedom` outbound plays the proxy server, and a few lines of
//! tokio play `cp.cloudflare.com/generate_204`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub const SS_METHOD: &str = "aes-256-gcm";
pub const SS_PASSWORD: &str = "zero-discovery-test-password";

/// A plain-HTTP server that answers every request with `204 No Content`.
pub async fn http_204_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

/// A Zray runtime serving Shadowsocks on loopback and forwarding to
/// wherever the client asks.
pub async fn shadowsocks_relay() -> SocketAddr {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "relay-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "shadowsocks",
            "settings": {"method": SS_METHOD, "password": SS_PASSWORD},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    });
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
        .expect("relay configuration compiles");
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = running.run().await;
    });
    tokio::time::timeout(Duration::from_secs(10), server.wait_until_listening())
        .await
        .expect("relay listens");
    // Keep the server alive for the rest of the test process.
    std::mem::forget(server);
    SocketAddr::from(([127, 0, 0, 1], port))
}

pub const VLESS_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// A Zray runtime serving plain VLESS on loopback. Unlike Shadowsocks, VLESS
/// answers with a response header before the first payload byte, which a
/// client has to strip.
pub async fn vless_relay() -> SocketAddr {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "relay-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": VLESS_UUID}], "decryption": "none"},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    });
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
        .expect("relay configuration compiles");
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = running.run().await;
    });
    tokio::time::timeout(Duration::from_secs(10), server.wait_until_listening())
        .await
        .expect("relay listens");
    std::mem::forget(server);
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// A plain VLESS share link to `address`.
pub fn vless_link(address: SocketAddr, remark: &str) -> String {
    format!("vless://{VLESS_UUID}@{address}?security=none&type=tcp&encryption=none#{remark}")
}

/// A Shadowsocks share link to `address`.
pub fn ss_link(address: SocketAddr, remark: &str) -> String {
    use base64::Engine as _;
    let credential =
        base64::engine::general_purpose::STANDARD.encode(format!("{SS_METHOD}:{SS_PASSWORD}"));
    format!("ss://{credential}@{address}#{remark}")
}
