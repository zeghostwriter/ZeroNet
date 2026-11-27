//! The whole client against the real Go server.
//!
//! `live_go_server.rs` drives the building blocks by hand; these tests run the
//! finished [`zero_masterdns::client::Client`]: it probes the resolver, runs the
//! handshake, opens streams and moves real bytes through the upstream
//! `masterking32/MasterDnsVPN` server (the pinned release). Opt-in, because they
//! need that server binary:
//!
//! ```bash
//! ZRAY_MASTERDNS_SERVER=/path/to/masterdns-server \
//!   cargo test -p zero-masterdns --test live_client -- --ignored --test-threads=1
//! ```
//!
//! `TCP` mode forwards every stream to a fixed local origin. `SOCKS5` mode (what
//! the installer sets up) dials the destination the stream names, and refuses
//! private ones by design, so its success test goes to a real website.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zero_masterdns::client::{Client, Config, Mode};

const DOMAIN: &str = "t.example.test";
const KEY: &str = "0123456789abcdef0123456789abcdef";

fn server_binary() -> PathBuf {
    let path = std::env::var_os("ZRAY_MASTERDNS_SERVER")
        .expect("ZRAY_MASTERDNS_SERVER is unset (path to the Go server binary)");
    let path = PathBuf::from(path);
    assert!(path.exists(), "{} does not exist", path.display());
    path
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Server {
    child: Child,
    directory: PathBuf,
    resolver: SocketAddr,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// `forward` is `Some(port)` for TCP mode, `None` for SOCKS5 mode.
fn spawn_server(forward: Option<u16>) -> Server {
    let directory = std::env::temp_dir().join(format!(
        "zray-masterdns-client-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("encrypt_key.txt"), KEY).unwrap();
    let port = free_udp_port();
    let mode = match forward {
        Some(origin) => format!(
            "PROTOCOL_TYPE = \"TCP\"\nFORWARD_IP = \"127.0.0.1\"\nFORWARD_PORT = {origin}\n"
        ),
        None => "PROTOCOL_TYPE = \"SOCKS5\"\n".to_string(),
    };
    std::fs::write(
        directory.join("server_config.toml"),
        format!(
            "DOMAIN = [\"{DOMAIN}\"]\n{mode}UDP_HOST = \"127.0.0.1\"\nUDP_PORT = {port}\n\
             DATA_ENCRYPTION_METHOD = 5\nENCRYPTION_KEY_FILE = \"encrypt_key.txt\"\nLOG_LEVEL = \"INFO\"\n"
        ),
    )
    .unwrap();
    let show = std::env::var_os("ZRAY_ORACLE_LOG").is_some();
    let sink = || {
        if show {
            Stdio::inherit()
        } else {
            Stdio::null()
        }
    };
    let child = Command::new(server_binary())
        .current_dir(&directory)
        .args(["-config", "server_config.toml", "-nowait"])
        .stdout(sink())
        .stderr(sink())
        .spawn()
        .expect("could not start the server");
    Server {
        child,
        directory,
        resolver: format!("127.0.0.1:{port}").parse().unwrap(),
    }
}

/// An origin that echoes everything back until the peer closes.
async fn echo_origin(bind: IpAddr) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind((bind, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16 * 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buffer[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// A UDP relay between the client and the server that drops and delays
/// datagrams in both directions, the way a bad DNS path does. Delay is random,
/// so datagrams also arrive out of order. Returns the address to use as the
/// resolver.
async fn lossy_relay(server: SocketAddr, loss_percent: u32, max_delay_ms: u64) -> SocketAddr {
    use rand::Rng;
    use std::collections::HashMap;
    use std::sync::Arc;

    let front = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = front.local_addr().unwrap();
    let lossy = move || {
        let mut rng = rand::thread_rng();
        (
            rng.gen_range(0..100) < loss_percent,
            Duration::from_millis(rng.gen_range(0..=max_delay_ms)),
        )
    };
    tokio::spawn(async move {
        let mut backs: HashMap<SocketAddr, Arc<tokio::net::UdpSocket>> = HashMap::new();
        let mut buffer = vec![0u8; 65535];
        loop {
            let Ok((n, client)) = front.recv_from(&mut buffer).await else {
                return;
            };
            let back = match backs.get(&client) {
                Some(back) => back.clone(),
                None => {
                    let back = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    back.connect(server).await.unwrap();
                    backs.insert(client, back.clone());
                    // Answers travel back through the same weather.
                    let (answers_out, answers_in) = (front.clone(), back.clone());
                    tokio::spawn(async move {
                        let mut buffer = vec![0u8; 65535];
                        while let Ok(n) = answers_in.recv(&mut buffer).await {
                            let (drop, delay) = lossy();
                            if drop {
                                continue;
                            }
                            let (front, packet) = (answers_out.clone(), buffer[..n].to_vec());
                            tokio::spawn(async move {
                                tokio::time::sleep(delay).await;
                                let _ = front.send_to(&packet, client).await;
                            });
                        }
                    });
                    back
                }
            };
            let (drop, delay) = lossy();
            if drop {
                continue;
            }
            let packet = buffer[..n].to_vec();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = back.send(&packet).await;
            });
        }
    });
    addr
}

/// A pattern that shows any reordering, loss or duplication.
fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2654435761).to_be_bytes()[1] ^ salt)
        .collect()
}

async fn connect(server: &Server, mode: Mode) -> Client {
    let mut config = Config::new(DOMAIN, KEY, vec![server.resolver]);
    config.mode = mode;
    tokio::time::timeout(Duration::from_secs(60), Client::connect(config))
        .await
        .expect("the handshake took over a minute")
        .expect("the handshake failed")
}

/// Send `payload` through a fresh stream to the echo origin and read it back.
async fn round_trip(client: &Client, host: &str, port: u16, payload: Vec<u8>) -> Vec<u8> {
    let stream = tokio::time::timeout(Duration::from_secs(60), client.open(host, port))
        .await
        .expect("opening the stream timed out")
        .expect("the stream did not open");
    let expected = payload.len();
    let (mut read, mut write) = tokio::io::split(stream);
    let writer = tokio::spawn(async move {
        write.write_all(&payload).await.unwrap();
        write.flush().await.unwrap();
        // Keep the write half open until the echo is complete: closing it early
        // would only test half-close, which has its own test.
        write
    });
    let mut got = Vec::with_capacity(expected);
    let mut buffer = vec![0u8; 8192];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(240);
    while got.len() < expected {
        let n = tokio::time::timeout_at(deadline, read.read(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("timed out with {} of {expected} bytes", got.len()))
            .unwrap();
        assert!(
            n > 0,
            "the stream ended after {} of {expected} bytes",
            got.len()
        );
        got.extend_from_slice(&buffer[..n]);
    }
    let _write = writer.await.unwrap();
    got
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn tcp_mode_echoes_a_small_message() {
    let origin = echo_origin(Ipv4Addr::LOCALHOST.into()).await;
    let server = spawn_server(Some(origin.port()));
    let client = connect(&server, Mode::Tcp).await;
    let payload = b"hello through the dns tunnel".to_vec();
    let got = round_trip(&client, "ignored.example", 80, payload.clone()).await;
    assert_eq!(got, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn tcp_mode_carries_a_large_transfer_intact() {
    let origin = echo_origin(Ipv4Addr::LOCALHOST.into()).await;
    let server = spawn_server(Some(origin.port()));
    let client = connect(&server, Mode::Tcp).await;
    let payload = pattern(256 * 1024, 7);
    let started = std::time::Instant::now();
    let got = round_trip(&client, "ignored.example", 80, payload.clone()).await;
    assert!(got == payload, "the echo differs from what was sent");
    eprintln!("256 KiB there and back in {:?}", started.elapsed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn tcp_mode_survives_loss_and_reordering() {
    let origin = echo_origin(Ipv4Addr::LOCALHOST.into()).await;
    let server = spawn_server(Some(origin.port()));
    // One datagram in ten is lost each way, and the rest arrive up to 40 ms
    // apart and out of order.
    let relay = lossy_relay(server.resolver, 10, 40).await;
    let mut config = Config::new(DOMAIN, KEY, vec![relay]);
    config.mode = Mode::Tcp;
    config.probe_retries = 4;
    let client = std::sync::Arc::new(
        tokio::time::timeout(Duration::from_secs(120), Client::connect(config))
            .await
            .expect("the handshake took too long")
            .expect("the handshake failed"),
    );
    let mut tasks = Vec::new();
    for salt in 0..std::env::var("ZRAY_LOSS_STREAMS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3u8)
    {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let payload = pattern(
                std::env::var("ZRAY_LOSS_BYTES")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(60_000),
                salt,
            );
            let got = round_trip(&client, "ignored.example", 80, payload.clone()).await;
            assert!(got == payload, "stream {salt} came back different");
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

/// A resolver that is up but answers nothing, like a filtered one: the probe
/// finds out only by waiting for its timeout, and must not hold up the connect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn a_silent_resolver_does_not_delay_the_first_connect() {
    let origin = echo_origin(Ipv4Addr::LOCALHOST.into()).await;
    let server = spawn_server(Some(origin.port()));
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut config = Config::new(
        DOMAIN,
        KEY,
        vec![silent.local_addr().unwrap(), server.resolver],
    );
    config.mode = Mode::Tcp;
    let started = std::time::Instant::now();
    let client = Client::connect(config).await.expect("the handshake failed");
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(5),
        "the silent resolver held the connect for {took:?}"
    );
    let got = round_trip(&client, "ignored.example", 80, b"still works".to_vec()).await;
    assert_eq!(got, b"still works");
    drop(silent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn tcp_mode_keeps_concurrent_streams_apart() {
    let origin = echo_origin(Ipv4Addr::LOCALHOST.into()).await;
    let server = spawn_server(Some(origin.port()));
    let client = std::sync::Arc::new(connect(&server, Mode::Tcp).await);
    let mut tasks = Vec::new();
    for salt in 0..6u8 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let payload = pattern(20_000 + usize::from(salt) * 1000, salt);
            let got = round_trip(&client, "ignored.example", 80, payload.clone()).await;
            assert!(got == payload, "stream {salt} came back different");
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

/// An address the server's rules refuse: it denies private destinations, so the
/// machine's own LAN address stands for "somewhere the server will not go".
fn lan_ip() -> Ipv4Addr {
    if let Some(text) = std::env::var_os("ZRAY_TEST_LAN_IP") {
        return text
            .to_string_lossy()
            .parse()
            .expect("ZRAY_TEST_LAN_IP is an IPv4 address");
    }
    // The address the machine would use to reach the internet; nothing is sent.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("192.0.2.1:9").unwrap();
    match socket.local_addr().unwrap().ip() {
        IpAddr::V4(ip) if !ip.is_loopback() => ip,
        other => panic!("no non-loopback IPv4 address found ({other}); set ZRAY_TEST_LAN_IP"),
    }
}

/// A real public website, through the server. Needs the internet from the
/// machine the server runs on; this checks dialling a *named* destination, an
/// ordinary request and the answer ending cleanly when the website closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the MasterDnsVPN Go server and the internet; see the module documentation"]
async fn socks5_mode_reaches_a_named_public_website() {
    let server = spawn_server(None);
    let client = connect(&server, Mode::Socks5).await;
    let mut stream = tokio::time::timeout(Duration::from_secs(60), client.open("example.com", 80))
        .await
        .expect("opening the stream timed out")
        .expect("the stream did not open");
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(90), stream.read_to_end(&mut answer))
        .await
        .expect("the page never finished")
        .unwrap();
    let text = String::from_utf8_lossy(&answer);
    assert!(
        text.starts_with("HTTP/1."),
        "not an HTTP answer: {:?}",
        &text[..text.len().min(80)]
    );
    assert!(text.contains("Example Domain"), "the page body is missing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn socks5_mode_reports_a_destination_the_server_refuses() {
    let server = spawn_server(None);
    let client = connect(&server, Mode::Socks5).await;
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        client.open(&lan_ip().to_string(), 80),
    )
    .await
    .expect("the refusal never arrived");
    let error = result.expect_err("a private destination must be refused");
    assert!(
        error.to_string().contains("rules deny"),
        "unexpected error: {error}"
    );
}
