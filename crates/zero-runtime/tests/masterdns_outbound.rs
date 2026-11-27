//! The MasterDNS outbound inside the engine, against the real Go server.
//!
//! A client runtime (SOCKS inbound, one `masterdns://` outbound) is pointed at
//! the upstream `masterking32/MasterDnsVPN` server's UDP port. What is asserted
//! is what the engine adds on top of `zero_masterdns::client`: the first
//! connection starts a tunnel and later ones share it (one session on the
//! server, however many connections), payload survives, and a wrong key is a
//! clean refusal rather than a hang.
//!
//! Opt-in, because it needs the server binary built from the pinned release:
//!
//! ```bash
//! ZRAY_MASTERDNS_SERVER=/path/to/masterdns-server \
//!   cargo test -p zero-runtime --test masterdns_outbound -- --ignored --test-threads=1
//! ```
//!
//! The server runs in `TCP` mode against a local echo origin (its `SOCKS5` mode
//! refuses private destinations by design).

use std::net::{SocketAddr, TcpListener as StdListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DOMAIN: &str = "t.example.test";
const KEY: &str = "0123456789abcdef0123456789abcdef";

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
        if let Err(error) = running.run().await {
            panic!("server failed to start: {error}");
        }
    });
    server
}

async fn echo_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 || stream.write_all(&buffer[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    address
}

/// The Go server in `TCP` mode, with its log in a file the test can read.
struct GoServer {
    child: Child,
    directory: PathBuf,
    resolver: SocketAddr,
}

impl GoServer {
    fn log(&self) -> String {
        std::fs::read_to_string(self.directory.join("server.log")).unwrap_or_default()
    }
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn go_server(origin: u16) -> GoServer {
    let binary = std::env::var_os("ZRAY_MASTERDNS_SERVER")
        .expect("ZRAY_MASTERDNS_SERVER is unset (path to the Go server binary)");
    let directory = std::env::temp_dir().join(format!(
        "zray-masterdns-outbound-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("encrypt_key.txt"), KEY).unwrap();
    let port = free_udp_port();
    std::fs::write(
        directory.join("server_config.toml"),
        format!(
            "DOMAIN = [\"{DOMAIN}\"]\nPROTOCOL_TYPE = \"TCP\"\nFORWARD_IP = \"127.0.0.1\"\n\
             FORWARD_PORT = {origin}\nUDP_HOST = \"127.0.0.1\"\nUDP_PORT = {port}\n\
             DATA_ENCRYPTION_METHOD = 5\nENCRYPTION_KEY_FILE = \"encrypt_key.txt\"\nLOG_LEVEL = \"INFO\"\n"
        ),
    )
    .unwrap();
    let log = std::fs::File::create(directory.join("server.log")).unwrap();
    let child = Command::new(binary)
        .current_dir(&directory)
        .args(["-config", "server_config.toml", "-nowait"])
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("could not start the server");
    GoServer {
        child,
        directory,
        resolver: format!("127.0.0.1:{port}").parse().unwrap(),
    }
}

/// A client runtime whose only outbound is the MasterDNS server.
async fn client(server: &GoServer, key: &str) -> SocketAddr {
    let socks_port = free_port();
    let link = format!(
        "masterdns://{key}@{DOMAIN}?server={}&mode=tcp#test",
        server.resolver
    );
    let runtime = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks", "settings": {"udp": false},
        }],
        "outbounds": [{"tag": "proxy", "link": link}],
    }));
    tokio::time::timeout(Duration::from_secs(30), runtime.wait_until_listening())
        .await
        .expect("client never bound its listeners");
    SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port)
}

/// SOCKS5 CONNECT to a domain; returns the reply code and the stream.
async fn connect_domain(
    socks: SocketAddr,
    name: &str,
    port: u16,
) -> std::io::Result<(u8, TcpStream)> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let mut request = vec![5, 1, 0, 3, name.len() as u8];
    request.extend_from_slice(name.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] == 0 {
        let skip = match reply[3] {
            1 => 4,
            4 => 16,
            _ => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                len[0] as usize
            }
        };
        let mut discard = vec![0u8; skip + 2];
        stream.read_exact(&mut discard).await?;
    }
    Ok((reply[1], stream))
}

async fn echoes(stream: &mut TcpStream, message: &[u8]) {
    stream.write_all(message).await.unwrap();
    let mut back = vec![0u8; message.len()];
    tokio::time::timeout(Duration::from_secs(60), stream.read_exact(&mut back))
        .await
        .expect("echo timed out")
        .expect("echo failed");
    assert_eq!(back, message);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn connections_share_one_session_and_payload_survives() {
    let origin = echo_service().await;
    let server = go_server(origin.port());
    let socks = client(&server, KEY).await;

    // Three connections, two of them at once.
    let (code, mut first) = connect_domain(socks, "anything.example", 80).await.unwrap();
    assert_eq!(code, 0, "the first connection failed");
    echoes(&mut first, b"first").await;
    let (code_b, mut second) = connect_domain(socks, "anything.example", 80).await.unwrap();
    let (code_c, mut third) = connect_domain(socks, "anything.example", 80).await.unwrap();
    assert_eq!((code_b, code_c), (0, 0));
    echoes(&mut second, b"second").await;
    echoes(&mut third, b"third").await;
    let big: Vec<u8> = (0..60_000u32).map(|i| (i % 251) as u8).collect();
    let (mut read, mut write) = first.into_split();
    let writer = {
        let big = big.clone();
        tokio::spawn(async move { write.write_all(&big).await.unwrap() })
    };
    let mut back = vec![0u8; big.len()];
    tokio::time::timeout(Duration::from_secs(120), read.read_exact(&mut back))
        .await
        .expect("the large echo timed out")
        .unwrap();
    writer.await.unwrap();
    assert!(back == big, "the large echo differs");

    let sessions = server.log().matches("Session Created").count();
    assert_eq!(
        sessions,
        1,
        "every connection must share one session:\n{}",
        server.log()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn a_wrong_key_is_refused_cleanly() {
    let origin = echo_service().await;
    let server = go_server(origin.port());
    let socks = client(&server, "ffffffffffffffffffffffffffffffff").await;
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        connect_domain(socks, "anything.example", 80),
    )
    .await
    .expect("a wrong key must fail, not hang");
    let refused = match result {
        Ok((code, _)) => code != 0,
        Err(_) => true,
    };
    assert!(refused, "a wrong key must not connect");
    eprintln!("refused after {:?}", started.elapsed());
}
