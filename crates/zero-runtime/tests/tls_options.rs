//! `verifyPeerCertByName` and `masterKeyLog`, on a Zray client talking to a
//! Zray TLS server with the loopback test certificate (valid for `zray.test`).

use std::net::TcpListener as StdListener;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";
const CERTIFICATE: &str = include_str!("fixtures/loopback-cert.pem");
const PRIVATE_KEY: &str = include_str!("fixtures/loopback-key.pem");
const CA: &str = include_str!("fixtures/loopback-ca.pem");

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

/// A SOCKS5 inbound whose route is a VLESS-over-TLS outbound with
/// `tls_settings`, to a VLESS-over-TLS inbound in the same process.
async fn rig(tls_settings: Value) -> (u16, u16) {
    let sink = echo_sink().await;
    let (socks, server) = (free_port(), free_port());
    let mut tls = json!({"certificates": [{"usage": "verify", "certificate": [CA]}]});
    for (key, value) in tls_settings.as_object().unwrap() {
        tls[key] = value.clone();
    }
    let config = json!({
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": socks, "protocol": "socks"},
            {
                "tag": "server", "listen": "127.0.0.1", "port": server, "protocol": "vless",
                "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                "streamSettings": {
                    "network": "raw", "security": "tls",
                    "tlsSettings": {"certificates": [{
                        "certificate": [CERTIFICATE], "key": [PRIVATE_KEY],
                    }]},
                },
            },
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {
                "tag": "to-server", "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1", "port": server,
                    "users": [{"id": UUID, "encryption": "none"}],
                }]},
                "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": tls},
            },
        ],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["socks"], "outboundTag": "to-server"},
        ]},
    });
    let (generation, _) =
        zero_config::compile_config(&config, zero_core::GenerationId(1)).expect("config");
    let running = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let runner = Arc::clone(&running);
    tokio::spawn(async move { runner.run().await });
    running.wait_until_listening().await;
    (socks, sink)
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
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut reply)).await;
    if !matches!(answered, Ok(Ok(_))) || reply[1] != 0 {
        return false;
    }
    stream.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut echo))
        .await
        .is_ok_and(|read| read.is_ok())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_certificate_can_be_checked_for_another_name_than_the_one_sent() {
    // A hello that names a front, a certificate that is for the real name.
    let (socks, sink) = rig(json!({
        "serverName": "front.example.com",
        "verifyPeerCertByName": "zray.test",
    }))
    .await;
    assert!(echoes(socks, sink).await);
    // Without it the certificate does not carry the name sent.
    let (socks, sink) = rig(json!({"serverName": "front.example.com"})).await;
    assert!(!echoes(socks, sink).await);
    // A list: any one of the names will do.
    let (socks, sink) = rig(json!({
        "serverName": "front.example.com",
        "verifyPeerCertByName": ["other.example", "zray.test"],
    }))
    .await;
    assert!(echoes(socks, sink).await);
    // A name the certificate is not for is still refused.
    let (socks, sink) = rig(json!({
        "serverName": "zray.test",
        "verifyPeerCertByName": "other.example",
    }))
    .await;
    assert!(!echoes(socks, sink).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_secrets_are_written_for_wireshark_when_asked() {
    let path = std::env::temp_dir().join(format!("zray-keylog-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (socks, sink) = rig(json!({
        "serverName": "zray.test",
        "masterKeyLog": path.to_str().unwrap(),
    }))
    .await;
    assert!(echoes(socks, sink).await);
    let log = std::fs::read_to_string(&path).expect("the key log was never written");
    let _ = std::fs::remove_file(&path);
    assert!(
        log.lines()
            .any(|line| line.starts_with("CLIENT_TRAFFIC_SECRET_0 ")),
        "{log}"
    );
    for line in log.lines() {
        let parts: Vec<&str> = line.split(' ').collect();
        assert_eq!(parts.len(), 3, "{line}");
        assert_eq!(parts[1].len(), 64, "the client random is 32 bytes: {line}");
    }
}
