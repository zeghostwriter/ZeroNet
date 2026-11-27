//! A proxy *server* must sniff what its clients send, not only a local proxy
//! must: a server's rules (block BitTorrent, route by a TLS name when the
//! client dialled a bare address) have nothing else to go on.
//!
//! The rig is one process with two halves: a SOCKS5 inbound whose only route
//! is a VLESS outbound, and a VLESS inbound (the "server") that applies the
//! rules under test and then dials a local echo sink.

use std::net::TcpListener as StdListener;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";

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

fn bittorrent_handshake() -> Vec<u8> {
    let mut hello = vec![19];
    hello.extend_from_slice(b"BitTorrent protocol");
    hello.extend_from_slice(&[0; 48]);
    hello
}

struct Rig {
    socks_port: u16,
    sink_port: u16,
}

/// Start the rig with `server_sniffing` on the VLESS inbound and `rules`
/// applied to what arrives there.
async fn rig(server_sniffing: Value, rules: Value) -> Rig {
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
    let (socks_port, vless_port) = (free_port(), free_port());
    let mut all_rules = vec![json!({
        "type": "field", "inboundTag": ["socks"], "outboundTag": "to-server"
    })];
    all_rules.splice(0..0, rules.as_array().unwrap().iter().cloned());
    // Rules for the server half name its inbound; the client half's catch-all
    // comes last so it cannot shadow them.
    let config = json!({
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks"},
            {
                "tag": "server", "listen": "127.0.0.1", "port": vless_port,
                "protocol": "vless",
                "settings": {"clients": [{"id": UUID, "email": "alice@example"}], "decryption": "none"},
                "sniffing": server_sniffing,
            },
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
            {
                "tag": "to-server", "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1", "port": vless_port,
                    "users": [{"id": UUID, "encryption": "none"}],
                }]},
            },
        ],
        "routing": {"rules": all_rules},
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
    Rig {
        socks_port,
        sink_port,
    }
}

impl Rig {
    /// Connect to the sink by address through the SOCKS5 inbound, send
    /// `first`, and say whether the sink's echo came back.
    async fn echoes(&self, first: &[u8]) -> bool {
        let mut stream = TcpStream::connect(("127.0.0.1", self.socks_port))
            .await
            .unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await.unwrap();
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&self.sink_port.to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        let answered =
            tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut reply)).await;
        if !matches!(answered, Ok(Ok(_))) {
            return false;
        }
        stream.write_all(first).await.unwrap();
        let mut echo = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut echo))
            .await
            .is_ok_and(|read| read.is_ok())
    }
}

fn server_rules(rules: Value) -> Value {
    let mut out = Vec::new();
    for rule in rules.as_array().unwrap() {
        let mut rule = rule.clone();
        rule["inboundTag"] = json!(["server"]);
        out.push(rule);
    }
    Value::Array(out)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_blocks_bittorrent_it_can_recognise() {
    let rig = rig(
        json!({"enabled": true, "destOverride": ["http", "tls"]}),
        server_rules(json!([
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
        ])),
    )
    .await;
    assert!(
        !rig.echoes(&bittorrent_handshake()).await,
        "a BitTorrent handshake got through a server that blocks the protocol"
    );
    assert!(
        rig.echoes(b"hello, sink").await,
        "ordinary traffic no longer reaches its destination"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_routes_a_client_that_dialled_an_address_by_its_tls_name() {
    let rig = rig(
        json!({"enabled": true, "destOverride": ["http", "tls"], "routeOnly": true}),
        server_rules(json!([
            {"type": "field", "domain": ["full:blocked.example"], "outboundTag": "block"},
        ])),
    )
    .await;
    assert!(!rig.echoes(&client_hello("blocked.example")).await);
    assert!(rig.echoes(&client_hello("allowed.example")).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_excluded_name_does_not_steer_the_connection() {
    let rig = rig(
        json!({
            "enabled": true, "destOverride": ["http", "tls"], "routeOnly": true,
            "domainsExcluded": ["full:blocked.example"],
        }),
        server_rules(json!([
            {"type": "field", "domain": ["full:blocked.example"], "outboundTag": "block"},
        ])),
    )
    .await;
    assert!(
        rig.echoes(&client_hello("blocked.example")).await,
        "an excluded name was still used to route the connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_that_does_not_sniff_cannot_see_the_protocol() {
    let rig = rig(
        json!({"enabled": false}),
        server_rules(json!([
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
        ])),
    )
    .await;
    assert!(rig.echoes(&bittorrent_handshake()).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rule_can_name_the_account_that_connected() {
    let blocked = rig(
        json!({"enabled": false}),
        server_rules(json!([
            {"type": "field", "user": ["alice@example"], "outboundTag": "block"},
        ])),
    )
    .await;
    assert!(!blocked.echoes(b"hello, sink").await);
    let other = rig(
        json!({"enabled": false}),
        server_rules(json!([
            {"type": "field", "user": ["bob@example"], "outboundTag": "block"},
        ])),
    )
    .await;
    assert!(other.echoes(b"hello, sink").await);
}

/// The route number is bytes 6 and 7 of the user id: `51cd` in the test id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rule_can_name_the_vless_route_in_the_user_id() {
    let blocked = rig(
        json!({"enabled": false}),
        server_rules(json!([
            {"type": "field", "vlessRoute": "20941", "outboundTag": "block"},
        ])),
    )
    .await;
    assert!(!blocked.echoes(b"hello, sink").await);
    let other = rig(
        json!({"enabled": false}),
        server_rules(json!([
            {"type": "field", "vlessRoute": "1-100", "outboundTag": "block"},
        ])),
    )
    .await;
    assert!(other.echoes(b"hello, sink").await);
}
