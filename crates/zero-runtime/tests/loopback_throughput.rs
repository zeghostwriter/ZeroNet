//! Release-mode SOCKS/Freedom throughput gate (PLAN-01 phase 2).
//!
//! The comparison deliberately keeps both implementations in the same shape:
//! a loopback SOCKS inbound, a Freedom/direct outbound, and a local framed echo
//! origin. It excludes process startup and SOCKS negotiation, but includes the
//! full proxy data path in both directions. Samples alternate which proxy runs
//! first so temporary CPU frequency or cache effects cannot consistently favour
//! one implementation.
//!
//! Run it explicitly, because its repeated large transfers are not appropriate
//! for every ordinary unit-test run:
//!
//!     cargo test --release -p zero-runtime --test loopback_throughput \
//!       -- --ignored --test-threads=1

use std::io::Write;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
// Seven alternating samples make the median insensitive to up to three noisy
// host-scheduling outliers while preserving a strict relative threshold.
const SAMPLES: usize = 7;
const MAX_SLOWDOWN: f64 = 1.10;

fn free_port() -> u16 {
    use std::collections::HashSet;

    static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);
    for _ in 0..500 {
        let port = StdListener::bind("127.0.0.1:0")
            .expect("bind ephemeral")
            .local_addr()
            .expect("read ephemeral address")
            .port();
        let mut taken = TAKEN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if taken.get_or_insert_with(HashSet::new).insert(port) {
            return port;
        }
    }
    panic!("could not reserve a free test port");
}

fn zray_config(socks_port: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    })
}

fn xray_config(socks_port: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": false},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    })
}

fn spawn_zray(config: &Value) -> Arc<zero_runtime::Server> {
    let (generation, _) = zero_config::compile_config(config, zero_core::GenerationId(1))
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

fn xray_binary() -> String {
    if let Some(path) = std::env::var_os("ZRAY_XRAY_BINARY") {
        let path = path.to_string_lossy().into_owned();
        assert!(
            std::path::Path::new(&path).exists(),
            "ZRAY_XRAY_BINARY points at {path}, which does not exist"
        );
        return path;
    }
    let available = Command::new("xray")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success());
    assert!(
        available,
        "loopback throughput gate needs xray on PATH or ZRAY_XRAY_BINARY"
    );
    "xray".into()
}

/// An Xray process plus the unique temporary config directory it owns.
struct Xray {
    child: Child,
    directory: std::path::PathBuf,
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn spawn_xray(binary: &str, config: &Value) -> Xray {
    let directory = std::env::temp_dir().join(format!(
        "zray-throughput-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).expect("create Xray config directory");
    let config_path = directory.join("config.json");
    let mut config_file = std::fs::File::create(&config_path).expect("create Xray config");
    config_file
        .write_all(
            serde_json::to_string_pretty(config)
                .expect("serialize Xray config")
                .as_bytes(),
        )
        .expect("write Xray config");
    config_file.sync_all().expect("sync Xray config");
    let child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("start Xray: {error}"));
    Xray { child, directory }
}

async fn wait_for_listener(address: SocketAddr) {
    for _ in 0..200 {
        if TcpStream::connect(address).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{address} never started listening");
}

/// A frame-aware echo target. Framing keeps the payload transfer attributable
/// to this exact request rather than an arbitrary amount of stream buffering.
async fn echo_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo listener");
    let address = listener.local_addr().expect("read echo address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                loop {
                    let mut header = [0u8; 4];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let length = u32::from_be_bytes(header) as usize;
                    if length == 0 || length > PAYLOAD_BYTES {
                        return;
                    }
                    let mut body = vec![0u8; length];
                    if stream.read_exact(&mut body).await.is_err()
                        || stream.write_all(&header).await.is_err()
                        || stream.write_all(&body).await.is_err()
                        || stream.flush().await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    address
}

async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(socks).await.expect("connect SOCKS");
    stream.set_nodelay(true).expect("enable TCP_NODELAY");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write SOCKS greeting");
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .expect("read SOCKS greeting");
    assert_eq!(greeting, [0x05, 0x00], "SOCKS no-auth was refused");

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    match target.ip() {
        std::net::IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(_) => panic!("the loopback target must be IPv4"),
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&request)
        .await
        .expect("write SOCKS request");
    let mut reply = [0u8; 4];
    stream
        .read_exact(&mut reply)
        .await
        .expect("read SOCKS reply");
    assert_eq!(reply[0], 0x05, "invalid SOCKS reply version");
    assert_eq!(reply[1], 0x00, "SOCKS CONNECT failed with {}", reply[1]);
    let address_length = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .expect("read SOCKS domain reply length");
            length[0] as usize
        }
        other => panic!("unexpected SOCKS reply address type {other}"),
    };
    let mut discard = vec![0u8; address_length + 2];
    stream
        .read_exact(&mut discard)
        .await
        .expect("read SOCKS reply address");
    stream
}

async fn transfer(socks: SocketAddr, target: SocketAddr, payload: &[u8]) -> Duration {
    let mut stream = socks_connect(socks, target).await;
    let started = Instant::now();
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .expect("write frame length");
    stream.write_all(payload).await.expect("write frame body");
    stream.flush().await.expect("flush frame");

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .expect("read echo frame length");
    assert_eq!(u32::from_be_bytes(header) as usize, payload.len());
    let mut echoed = vec![0u8; payload.len()];
    stream
        .read_exact(&mut echoed)
        .await
        .expect("read echo frame body");
    assert_eq!(
        echoed, payload,
        "payload was altered during throughput sample"
    );
    started.elapsed()
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs release-mode loopback comparison against an installed Xray binary"]
async fn socks_freedom_loopback_is_within_ten_percent_of_xray() {
    let xray_socks = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let zray_socks = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let echo = echo_service().await;
    let _zray = spawn_zray(&zray_config(zray_socks.port()));
    let _xray = spawn_xray(&xray_binary(), &xray_config(xray_socks.port()));
    wait_for_listener(zray_socks).await;
    wait_for_listener(xray_socks).await;

    // First allocation, CPU-frequency ramp, and proxy connection are all
    // deliberately warmed before samples. The measured payload has a stable
    // deterministic pattern so a misrouted or truncated flow cannot score.
    let warmup = vec![0xA5; 1024 * 1024];
    let _ = transfer(xray_socks, echo, &warmup).await;
    let _ = transfer(zray_socks, echo, &warmup).await;
    let payload = (0..PAYLOAD_BYTES)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(17))
        .collect::<Vec<_>>();

    let mut xray_samples = Vec::with_capacity(SAMPLES);
    let mut zray_samples = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        if sample % 2 == 0 {
            xray_samples.push(transfer(xray_socks, echo, &payload).await);
            zray_samples.push(transfer(zray_socks, echo, &payload).await);
        } else {
            zray_samples.push(transfer(zray_socks, echo, &payload).await);
            xray_samples.push(transfer(xray_socks, echo, &payload).await);
        }
    }
    let xray_median = median(xray_samples);
    let zray_median = median(zray_samples);
    let xray_seconds = xray_median.as_secs_f64();
    let zray_seconds = zray_median.as_secs_f64();
    let ratio = zray_seconds / xray_seconds;
    let payload_mib = PAYLOAD_BYTES as f64 / (1024.0 * 1024.0);
    eprintln!(
        "Xray median: {xray_seconds:.3}s ({:.1} MiB/s); Zray median: {zray_seconds:.3}s ({:.1} MiB/s); ratio: {ratio:.3}",
        payload_mib * 2.0 / xray_seconds,
        payload_mib * 2.0 / zray_seconds,
    );
    assert!(
        ratio <= MAX_SLOWDOWN,
        "Zray loopback path is {:.1}% slower than Xray (limit: {:.1}%)",
        (ratio - 1.0) * 100.0,
        (MAX_SLOWDOWN - 1.0) * 100.0,
    );
}
