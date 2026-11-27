//! Reverse proxy, both ends in this process: a service that only the
//! "bridge" side can reach, used through the "portal" side.
//!
//! The bridge dials the portal (a VLESS inbound), the portal runs a mux
//! client on that connection, and a SOCKS client of the portal reaches the
//! service through it. The wire form is Xray's, checked against the real
//! Xray binary by hand; this test pins that the two Zray roles keep working
//! together, and what happens when no bridge is there.

use std::net::TcpListener as StdListener;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const USER: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A service that answers "service:" and what it was sent, then closes.
async fn service() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                let mut reply = b"service:".to_vec();
                reply.extend_from_slice(&buffer[..read]);
                let _ = stream.write_all(&reply).await;
            });
        }
    });
    port
}

async fn start(config: Value) -> Arc<zero_runtime::Server> {
    let (generation, _) =
        zero_config::compile_config(&config, zero_core::GenerationId(1)).expect("config");
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move { running.run().await });
    server.wait_until_listening().await;
    server
}

fn portal_config(link: u16, socks: u16) -> Value {
    json!({
        "reverse": {"portals": [{"tag": "portal", "domain": "reverse.test"}]},
        "inbounds": [
            {"tag": "interconn", "protocol": "vless", "listen": "127.0.0.1", "port": link,
             "settings": {"clients": [{"id": USER}], "decryption": "none"}},
            {"tag": "external", "protocol": "socks", "listen": "127.0.0.1", "port": socks,
             "settings": {"auth": "noauth"}}
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["interconn"], "outboundTag": "portal"},
            {"type": "field", "inboundTag": ["external"], "outboundTag": "portal"}
        ]}
    })
}

fn bridge_config(link: u16) -> Value {
    json!({
        "reverse": {"bridges": [{"tag": "bridge", "domain": "reverse.test"}]},
        "inbounds": [],
        "outbounds": [
            {"tag": "interconn", "protocol": "vless",
             "settings": {"vnext": [{"address": "127.0.0.1", "port": link,
                "users": [{"id": USER, "encryption": "none"}]}]}},
            {"tag": "out", "protocol": "freedom"}
        ],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["bridge"], "domain": ["full:reverse.test"],
             "outboundTag": "interconn"},
            {"type": "field", "inboundTag": ["bridge"], "outboundTag": "out"}
        ]}
    })
}

/// Ask the portal's SOCKS5 inbound for `127.0.0.1:port`, send `hello`, and
/// read what comes back until the far side closes.
async fn through_portal(socks: u16, port: u16) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("SOCKS reply {}", reply[1])));
    }
    stream.write_all(b"hello").await?;
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer))
        .await
        .map_err(|_| std::io::Error::other("timed out"))??;
    Ok(answer)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bridge_makes_its_network_reachable_through_the_portal() {
    let (link, socks) = (free_port(), free_port());
    let service = service().await;
    let _portal = start(portal_config(link, socks)).await;

    // Before any bridge has dialled in there is nothing to carry the session.
    let early = through_portal(socks, service).await;
    assert!(
        early.as_ref().map_or(true, |bytes| bytes.is_empty()),
        "nothing should be answering yet: {early:?}"
    );

    let bridge = Arc::new(zero_runtime::Server::new({
        let (generation, _) =
            zero_config::compile_config(&bridge_config(link), zero_core::GenerationId(1)).unwrap();
        zero_runtime::ServerConfig {
            config: Arc::clone(&generation.config),
            generation: generation.id,
        }
    }));
    let running = Arc::clone(&bridge);
    let bridge_task = tokio::spawn(async move { running.run().await });

    // The bridge looks for work every two seconds; give it a few.
    let mut answer = Vec::new();
    for _ in 0..12 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(bytes) = through_portal(socks, service).await {
            if !bytes.is_empty() {
                answer = bytes;
                break;
            }
        }
    }
    assert_eq!(answer, b"service:hello");

    // Several at once share the carrier.
    let many = futures::future::join_all((0..8).map(|_| through_portal(socks, service))).await;
    for one in many {
        assert_eq!(one.unwrap(), b"service:hello");
    }
    bridge_task.abort();
}

/// VLESS's own reverse proxy: the portal is an inbound account with
/// `reverse.tag`, the bridge an outbound account with it, and the dial-in is
/// the reverse command rather than a routed connection to a name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_vless_account_can_be_a_reverse_bridge() {
    let (link, socks) = (free_port(), free_port());
    let service = service().await;
    let _portal = start(json!({
        "inbounds": [
            {"tag": "link", "protocol": "vless", "listen": "127.0.0.1", "port": link,
             "settings": {"decryption": "none",
                "clients": [{"id": USER, "reverse": {"tag": "r"}}]}},
            {"tag": "external", "protocol": "socks", "listen": "127.0.0.1", "port": socks,
             "settings": {"auth": "noauth"}}
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["external"], "outboundTag": "r"}]},
    }))
    .await;
    // The simplified outbound form, as a current Xray writes it.
    let bridge = Arc::new(zero_runtime::Server::new({
        let (generation, _) = zero_config::compile_config(
            &json!({
                "inbounds": [],
                "outbounds": [
                    {"tag": "link", "protocol": "vless",
                     "settings": {"address": "127.0.0.1", "port": link, "id": USER,
                                  "encryption": "none", "reverse": {"tag": "r"}}},
                    {"tag": "out", "protocol": "freedom"}
                ],
                "routing": {"rules": [{"type": "field", "inboundTag": ["r"], "outboundTag": "out"}]},
            }),
            zero_core::GenerationId(1),
        )
        .unwrap();
        zero_runtime::ServerConfig {
            config: Arc::clone(&generation.config),
            generation: generation.id,
        }
    }));
    let running = Arc::clone(&bridge);
    let bridge_task = tokio::spawn(async move { running.run().await });
    let mut answer = Vec::new();
    for _ in 0..12 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(bytes) = through_portal(socks, service).await {
            if !bytes.is_empty() {
                answer = bytes;
                break;
            }
        }
    }
    assert_eq!(answer, b"service:hello");
    bridge_task.abort();
}
