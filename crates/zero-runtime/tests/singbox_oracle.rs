//! ShadowTLS v3 against the sing-box oracle.
//!
//! `zero_transport::shadowtls` is a simplified client: it never finishes a TLS
//! handshake with the decoy, so nothing about it can be checked against a mirror
//! image of itself. These tests run it against a real sing-box ShadowTLS v3
//! server, which is the only judge of whether the relay really switches to the
//! backend on the first authenticated frame.
//!
//! They are opt-in because they need a `sing-box` binary. Set `ZRAY_SINGBOX_BINARY`
//! to a path, or have `sing-box` on `PATH`, then:
//!
//! ```bash
//! cargo test -p zero-runtime --test singbox_oracle -- --ignored --test-threads=1
//! ```
//!
//! A missing binary panics with the reason rather than passing, for the same
//! reason as `xray_oracle`: a comparison that quietly does nothing reports
//! success for a check it never made.

use std::io::Write;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DECOY_CERTIFICATE: &str = include_str!("fixtures/loopback-cert.pem");
const DECOY_PRIVATE_KEY: &str = include_str!("fixtures/loopback-key.pem");
const SHADOWTLS_PASSWORD: &str = "a-shadowtls-password";
/// The inner Shadowsocks key: 16 bytes, base64, as `2022-blake3-aes-128-gcm`
/// wants.
const SHADOWSOCKS_KEY: &str = "AAECAwQFBgcICQoLDA0ODw==";

fn oracle_binary() -> Result<String, String> {
    if let Some(path) = std::env::var_os("ZRAY_SINGBOX_BINARY") {
        let path = path.to_string_lossy().into_owned();
        return if std::path::Path::new(&path).exists() {
            Ok(path)
        } else {
            Err(format!(
                "ZRAY_SINGBOX_BINARY points at {path}, which does not exist"
            ))
        };
    }
    match Command::new("sing-box").arg("version").output() {
        Ok(output) if output.status.success() => Ok("sing-box".into()),
        _ => Err("no `sing-box` on PATH and ZRAY_SINGBOX_BINARY is unset".into()),
    }
}

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A sing-box process killed when the test ends, however it ends.
struct Oracle {
    child: Child,
    directory: std::path::PathBuf,
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn spawn_oracle(binary: &str, config: Value) -> Oracle {
    let directory = std::env::temp_dir().join(format!(
        "zray-singbox-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("config.json");
    std::fs::File::create(&path)
        .unwrap()
        .write_all(serde_json::to_string_pretty(&config).unwrap().as_bytes())
        .unwrap();
    let show_logs = std::env::var_os("ZRAY_ORACLE_LOG").is_some();
    let quiet = || {
        if show_logs {
            Stdio::inherit()
        } else {
            Stdio::null()
        }
    };
    let child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&path)
        .stdout(quiet())
        .stderr(quiet())
        .spawn()
        .unwrap_or_else(|error| panic!("could not start the oracle: {error}"));
    Oracle { child, directory }
}

async fn wait_for(address: SocketAddr) -> bool {
    for _ in 0..100 {
        if TcpStream::connect(address).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// A TLS 1.3 server that sits behind the ShadowTLS relay as the decoy. The relay
/// forwards the client's ClientHello to it and checks it negotiated TLS 1.3; what
/// it serves afterwards does not matter, so it just reads until the peer goes.
async fn decoy_server(port: u16) {
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = {
        let mut reader = std::io::BufReader::new(DECOY_CERTIFICATE.as_bytes());
        rustls_pki_types::pem::PemObject::pem_reader_iter(&mut reader)
            .filter_map(Result::ok)
            .collect()
    };
    let key: rustls_pki_types::PrivateKeyDer<'static> = {
        let mut reader = std::io::BufReader::new(DECOY_PRIVATE_KEY.as_bytes());
        rustls_pki_types::pem::PemObject::from_pem_reader(&mut reader).expect("test key")
    };
    let config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("a usable test certificate");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut sink = [0u8; 1024];
                    while matches!(tls.read(&mut sink).await, Ok(n) if n > 0) {}
                }
            });
        }
    });
}

async fn echo_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 64 * 1024];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    address
}

fn spawn_client(config: Value) -> Arc<zero_runtime::Server> {
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))
        .unwrap_or_else(|error| panic!("configuration rejected: {error}\n{config:#}"));
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        if let Err(error) = running.run().await {
            panic!("client failed to start: {error}");
        }
    });
    server
}

async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let std::net::IpAddr::V4(ip) = target.ip() else {
        panic!("IPv4 only");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("SOCKS reply {}", reply[1])));
    }
    Ok(stream)
}

fn payload(seed: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// A Zray client reaching `relay_port` as a Shadowsocks outbound under ShadowTLS
/// v3 with `password`, behind a SOCKS inbound on the returned address.
async fn zray_client(relay_port: u16, password: &str) -> SocketAddr {
    let socks_port = free_port();
    let client = spawn_client(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks", "settings": {"udp": false},
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": "127.0.0.1", "port": relay_port,
                "method": "2022-blake3-aes-128-gcm", "password": SHADOWSOCKS_KEY,
            }]},
            "streamSettings": {
                "network": "raw",
                "security": "shadowtls",
                "shadowtlsSettings": {
                    "version": 3,
                    "password": password,
                    "tls": {"serverName": "localhost"},
                },
            },
        }],
    }));
    tokio::time::timeout(Duration::from_secs(30), client.wait_until_listening())
        .await
        .expect("client never listened");
    SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port)
}

fn shadowtls_server(relay_port: u16, decoy_port: u16) -> Value {
    json!({
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "shadowtls", "tag": "stls-in",
                "listen": "127.0.0.1", "listen_port": relay_port,
                "version": 3,
                "users": [{"name": "zray", "password": SHADOWTLS_PASSWORD}],
                "handshake": {"server": "127.0.0.1", "server_port": decoy_port},
                "strict_mode": false,
                "detour": "ss-in",
            },
            {
                "type": "shadowsocks", "tag": "ss-in",
                "listen": "127.0.0.1", "network": "tcp",
                "method": "2022-blake3-aes-128-gcm", "password": SHADOWSOCKS_KEY,
            },
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a sing-box binary; see the module documentation"]
async fn shadowtls_v3_carries_payload_through_a_real_sing_box_relay() {
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the oracle comparison cannot run: {reason}");
    });
    let (relay_port, decoy_port) = (free_port(), free_port());
    decoy_server(decoy_port).await;
    let _oracle = spawn_oracle(&binary, shadowtls_server(relay_port, decoy_port));
    let relay = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port);
    assert!(wait_for(relay).await, "sing-box never listened");

    let echo = echo_service().await;
    let socks = zray_client(relay_port, SHADOWTLS_PASSWORD).await;

    // Small, then larger than one data frame (16 KiB), then a few at once.
    for (seed, length) in [(1u8, 64usize), (2, 100_000), (3, 1_000_000)] {
        let mut stream = socks_connect(socks, echo).await.unwrap();
        let body = payload(seed, length);
        let write = async {
            // Write and read concurrently: a megabyte does not fit in the
            // pipes between the two, so a write-then-read would deadlock.
            let (mut read_half, mut write_half) = stream.split();
            let writer = async {
                write_half.write_all(&body).await.unwrap();
            };
            let reader = async {
                let mut echoed = vec![0u8; body.len()];
                read_half.read_exact(&mut echoed).await.unwrap();
                echoed
            };
            let (_, echoed) = tokio::join!(writer, reader);
            echoed
        };
        let echoed = tokio::time::timeout(Duration::from_secs(30), write)
            .await
            .expect("echo timed out");
        assert_eq!(echoed, body, "payload of {length} bytes came back altered");
    }

    let tasks = (0..6u8).map(|seed| {
        tokio::spawn(async move {
            let mut stream = socks_connect(socks, echo).await.unwrap();
            let body = payload(seed, 32 * 1024);
            stream.write_all(&body).await.unwrap();
            let mut echoed = vec![0u8; body.len()];
            tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut echoed))
                .await
                .expect("echo timed out")
                .unwrap();
            assert_eq!(echoed, body);
        })
    });
    for task in futures::future::join_all(tasks).await {
        task.unwrap();
    }
}

/// A wrong ShadowTLS password never gets a byte through: the relay treats the
/// client as any other visitor of the decoy, and the client fails closed rather
/// than falling back to talking to the decoy as if it were the backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a sing-box binary; see the module documentation"]
async fn shadowtls_v3_with_the_wrong_password_fails_closed() {
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the oracle comparison cannot run: {reason}");
    });
    let (relay_port, decoy_port) = (free_port(), free_port());
    decoy_server(decoy_port).await;
    let _oracle = spawn_oracle(&binary, shadowtls_server(relay_port, decoy_port));
    let relay = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port);
    assert!(wait_for(relay).await, "sing-box never listened");

    let echo = echo_service().await;
    let socks = zray_client(relay_port, "not-the-password").await;

    let attempt = tokio::time::timeout(Duration::from_secs(30), async {
        let mut stream = socks_connect(socks, echo).await?;
        stream.write_all(b"ping").await?;
        let mut got = [0u8; 4];
        stream.read_exact(&mut got).await?;
        Ok::<_, std::io::Error>(got)
    })
    .await
    .expect("a refused client must fail, not hang");
    assert!(
        attempt.is_err(),
        "the relay served a client with the wrong password"
    );
}
