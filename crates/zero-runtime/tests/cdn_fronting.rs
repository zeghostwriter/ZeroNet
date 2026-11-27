//! Cloudflare-style CDN fronting (PLAN-02 §3.6, class B).
//!
//! Fronting works because two names are in play at once and they are *not* the
//! same name:
//!
//! * the **SNI** is the front — the name the TLS session is opened to, and the
//!   only name a passive observer sees;
//! * the **`Host` header** is the real destination — encrypted inside that
//!   session, and the thing the CDN actually routes on.
//!
//! If the client ever sends the real destination as the SNI, the arrangement is
//! pointless: the name it was meant to hide is on the wire in plaintext. If it
//! sends the front as the `Host`, the CDN routes to the wrong worker and the
//! tunnel simply does not work. Both mistakes are invisible in a test that only
//! checks that bytes flow, which is why these two properties are asserted
//! directly against the wire.

use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
/// The name the TLS session is opened to: a large, ordinary CDN hostname.
const FRONT_NAME: &str = "zray.test";
/// The name the CDN routes on, carried inside the encrypted session.
const WORKER_NAME: &str = "worker.zray.test";

const CERTIFICATE: &str = include_str!("fixtures/loopback-cert.pem");
const PRIVATE_KEY: &str = include_str!("fixtures/loopback-key.pem");
const CA_CERTIFICATE: &str = include_str!("fixtures/loopback-ca.pem");

fn free_port() -> u16 {
    use std::collections::HashSet;
    static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);
    for _ in 0..500 {
        let port = StdListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut taken = TAKEN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if taken.get_or_insert_with(HashSet::new).insert(port) {
            return port;
        }
    }
    panic!("could not reserve a free port");
}

fn spawn(config: Value) -> Arc<zero_runtime::Server> {
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
        .unwrap_or_else(|error| panic!("configuration rejected: {error}\n{config:#}"));
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

/// A client whose outbound fronts `WORKER_NAME` behind `FRONT_NAME`.
fn fronting_client(socks_port: u16, edge_port: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{
                // The edge address is reached directly; only the names differ.
                "address": FRONT_NAME,
                "port": edge_port,
                "users": [{"id": UUID, "encryption": "none"}],
            }]},
            "streamSettings": {
                "network": "ws",
                "wsSettings": {"path": "/tunnel", "host": WORKER_NAME},
                "security": "tls",
                "tlsSettings": {
                    "serverName": FRONT_NAME,
                    "certificates": [{"usage": "verify", "certificate": [CA_CERTIFICATE]}],
                },
            },
        }],
        "dns": {"hosts": {FRONT_NAME: ["127.0.0.1"], WORKER_NAME: ["127.0.0.1"]}},
    })
}

async fn drive_one_connection(socks: SocketAddr) {
    // The handshake is expected to fail: these listeners observe and then hang
    // up. Reaching them at all is what the test is about.
    let Ok(mut stream) = TcpStream::connect(socks).await else {
        return;
    };
    let _ = stream.write_all(&[0x05, 0x01, 0x00]).await;
    let mut greeting = [0u8; 2];
    if stream.read_exact(&mut greeting).await.is_err() {
        return;
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&[203, 0, 113, 1]);
    request.extend_from_slice(&443u16.to_be_bytes());
    let _ = stream.write_all(&request).await;
    let mut reply = [0u8; 4];
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut reply)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sni_on_the_wire_is_the_front_and_never_the_destination() {
    let edge_port = free_port();
    let socks_port = free_port();
    let observed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    // A listener that reads just far enough to parse the ClientHello. This is
    // exactly what a passive censor on the path can see.
    let listener = TcpListener::bind(SocketAddr::new("127.0.0.1".parse().unwrap(), edge_port))
        .await
        .unwrap();
    let recorder = Arc::clone(&observed);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let recorder = Arc::clone(&recorder);
            tokio::spawn(async move {
                let mut hello = vec![0u8; 8192];
                let Ok(read) = stream.read(&mut hello).await else {
                    return;
                };
                let sniffed = zero_core::sniff::inspect(&hello[..read], false, true);
                *recorder
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    sniffed.domain.map(|name| name.to_string());
            });
        }
    });

    spawn(fronting_client(socks_port, edge_port));
    tokio::time::sleep(Duration::from_millis(200)).await;
    drive_one_connection(SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port)).await;

    let sni = observed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(
        sni.as_deref(),
        Some(FRONT_NAME),
        "the ClientHello must carry the front name"
    );
    assert_ne!(
        sni.as_deref(),
        Some(WORKER_NAME),
        "the destination name must never appear in plaintext"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_header_inside_tls_is_the_destination_not_the_front() {
    let edge_port = free_port();
    let socks_port = free_port();
    let observed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    // Terminate TLS with the fixture certificate and read the HTTP request the
    // client sends inside it — the CDN's view rather than the censor's.
    let acceptor =
        zero_security::server::server_config(CERTIFICATE.as_bytes(), PRIVATE_KEY.as_bytes(), &[])
            .expect("test certificate must load");

    let listener = TcpListener::bind(SocketAddr::new("127.0.0.1".parse().unwrap(), edge_port))
        .await
        .unwrap();
    let recorder = Arc::clone(&observed);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = Arc::clone(&acceptor);
            let recorder = Arc::clone(&recorder);
            tokio::spawn(async move {
                let Ok(mut tls) = zero_security::server::accept(stream, acceptor).await else {
                    return;
                };
                let mut request = vec![0u8; 8192];
                let Ok(read) = tls.read(&mut request).await else {
                    return;
                };
                let text = String::from_utf8_lossy(&request[..read]).into_owned();
                let host = text.lines().find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("host")
                            .then(|| value.trim().to_string())
                    })
                });
                *recorder
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = host;
            });
        }
    });

    spawn(fronting_client(socks_port, edge_port));
    tokio::time::sleep(Duration::from_millis(200)).await;
    drive_one_connection(SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let host = observed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(
        host.as_deref(),
        Some(WORKER_NAME),
        "the CDN must be told the real destination"
    );
}
