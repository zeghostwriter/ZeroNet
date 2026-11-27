//! A SOCKS5 client that names its target by IP sends nothing until the proxy
//! has answered, so sniffing must not wait for bytes ahead of the reply.
//! Routing by the sniffed name is what keeps domain rules working for such
//! clients (TUN-fed apps, browsers with DNS-over-HTTPS).

use std::net::TcpListener as StdListener;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn client_hello(name: &str) -> Vec<u8> {
    let mut sni = Vec::new();
    sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name.as_bytes());
    let mut extensions = vec![0, 0];
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);
    let mut hello = vec![3, 3];
    hello.extend_from_slice(&[0; 32]);
    hello.push(0);
    hello.extend_from_slice(&[0, 2, 0x13, 0x01]);
    hello.extend_from_slice(&[1, 0]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);
    let mut record = vec![0x16, 3, 1];
    record.extend_from_slice(&(hello.len() as u16 + 4).to_be_bytes());
    record.extend_from_slice(&[
        1,
        (hello.len() >> 16) as u8,
        (hello.len() >> 8) as u8,
        hello.len() as u8,
    ]);
    record.extend_from_slice(&hello);
    record
}

/// Connect through SOCKS5 by IP, wait for the reply, then send `hello`.
/// True when the sink's echo came back.
async fn reaches_sink(socks_port: u16, sink_port: u16, hello: &[u8]) -> bool {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&sink_port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    let answered =
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut reply)).await;
    if !matches!(answered, Ok(Ok(_))) {
        return false;
    }
    stream.write_all(hello).await.unwrap();
    let mut echo = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echo))
        .await
        .is_ok_and(|read| read.is_ok())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_ip_clients_are_routed_by_their_sniffed_name() {
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_port = sink.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = sink.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                if let Ok(read) = socket.read(&mut buffer).await {
                    let _ = socket.write_all(&buffer[..read.min(4)]).await;
                }
            });
        }
    });

    let socks_port = free_port();
    let config = json!({
        "inbounds": [{
            "tag": "socks", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
            "sniffing": {"enabled": true, "destOverride": ["http", "tls"]},
        }],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"rules": [
            {"type": "field", "domain": ["full:blocked.example"], "outboundTag": "block"},
        ]},
        "dns": {"hosts": {"allowed.example": "127.0.0.1"}},
    });
    let (generation, _) =
        zero_config::compile_config(&config, zero_core::GenerationId(1)).expect("config");
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move { running.run().await });
    server.wait_until_listening().await;

    assert!(
        !reaches_sink(socks_port, sink_port, &client_hello("blocked.example")).await,
        "a domain rule was skipped because the sniff ran before the SOCKS reply"
    );
    assert!(
        reaches_sink(socks_port, sink_port, &client_hello("allowed.example")).await,
        "an allowed name no longer reaches its destination"
    );
}
