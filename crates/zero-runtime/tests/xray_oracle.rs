//! Differential testing against the Xray oracle (PLAN-01 §7).
//!
//! `Zray ↔ Zray` proves only that Zray agrees with itself. A framing mistake
//! that both ends make consistently is invisible to it, and consistency with
//! itself is worth nothing to a user whose server runs Xray. So these tests run
//! the two mixed directions:
//!
//! ```text
//! Zray client → Xray server        Xray client → Zray server
//! ```
//!
//! They are opt-in because they need an `xray` binary. Set `ZRAY_XRAY_BINARY`
//! to a path, or have `xray` on `PATH`, then:
//!
//! ```bash
//! cargo test -p zero-runtime --test xray_oracle -- --ignored --test-threads=1
//! ```
//!
//! Skipping loudly rather than silently passing matters here: a differential
//! suite that quietly does nothing is worse than no suite, because it reports
//! success for a comparison it never made.

use std::io::Write;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const DECOY_CERTIFICATE: &str = include_str!("fixtures/loopback-cert.pem");
const DECOY_PRIVATE_KEY: &str = include_str!("fixtures/loopback-key.pem");
const PASSWORD: &str = "an-example-shared-password";

/// Locate the oracle, or explain why the comparison cannot be made.
fn oracle_binary() -> Result<String, String> {
    if let Some(path) = std::env::var_os("ZRAY_XRAY_BINARY") {
        let path = path.to_string_lossy().into_owned();
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
        return Err(format!(
            "ZRAY_XRAY_BINARY points at {path}, which does not exist"
        ));
    }
    let probe = Command::new("xray").arg("version").output();
    match probe {
        Ok(output) if output.status.success() => Ok("xray".into()),
        _ => Err("no `xray` on PATH and ZRAY_XRAY_BINARY is unset".into()),
    }
}

fn oracle_version(binary: &str) -> String {
    Command::new(binary)
        .arg("version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| text.lines().next().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

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

/// An Xray process that is killed when the test ends, however it ends.
struct Oracle {
    child: Child,
    _directory: std::path::PathBuf,
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self._directory);
    }
}

fn spawn_oracle(binary: &str, config: Value) -> Oracle {
    let directory = std::env::temp_dir().join(format!(
        "zray-oracle-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("config.json");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(serde_json::to_string_pretty(&config).unwrap().as_bytes())
        .unwrap();
    file.sync_all().unwrap();

    // The oracle's own log is the fastest way to tell a Zray defect from a
    // malformed oracle configuration, so it can be turned on per run.
    let show_logs = std::env::var_os("ZRAY_ORACLE_LOG").is_some();
    let child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&path)
        .stdout(if show_logs {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stderr(if show_logs {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .spawn()
        .unwrap_or_else(|error| panic!("could not start the oracle: {error}"));
    Oracle {
        child,
        _directory: directory,
    }
}

fn init_logging() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("ZRAY_TEST_LOG").is_some() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_env("ZRAY_TEST_LOG")
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
                )
                .with_test_writer()
                .try_init();
        }
    });
}

fn spawn_zray(config: Value) -> Arc<zero_runtime::Server> {
    init_logging();
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

async fn echo_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    address
}

/// A local UDP echo service for the SOCKS5 UDP/XUDP differential path.
async fn udp_echo_service() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        while let Ok((read, peer)) = socket.recv_from(&mut buffer).await {
            if socket.send_to(&buffer[..read], peer).await.is_err() {
                return;
            }
        }
    });
    address
}

async fn wait_for(address: SocketAddr) -> bool {
    for _ in 0..200 {
        if TcpStream::connect(address).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.set_nodelay(true)?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [0x05, 0x00]);

    let std::net::IpAddr::V4(ip) = target.ip() else {
        panic!("IPv4 only");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT failed with {}", reply[1]);
    let skip = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        other => panic!("unexpected address type {other}"),
    };
    let mut discard = vec![0u8; skip + 2];
    stream.read_exact(&mut discard).await?;
    Ok(stream)
}

/// Exercise a complete SOCKS5 UDP ASSOCIATE. This is intentionally shared by
/// both mixed directions: the socket-level response proves the full chain
/// (SOCKS framing, VLESS Mux/XUDP, remote UDP, and the return packet) rather
/// than only one codec's byte layout.
async fn socks_udp_round_trip(socks: SocketAddr, target: SocketAddr, body: &[u8]) {
    let mut control = TcpStream::connect(socks).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    control.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    // An unspecified address tells the proxy to learn the UDP association
    // from our first datagram, as RFC 1928 permits.
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut head = [0u8; 4];
    control.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x05, "SOCKS server sent an invalid version");
    assert_eq!(head[1], 0x00, "SOCKS UDP ASSOCIATE failed with {}", head[1]);
    assert_eq!(head[2], 0x00, "SOCKS server set reserved reply bits");

    let relay = match head[3] {
        0x01 => {
            let mut tail = [0u8; 6];
            control.read_exact(&mut tail).await.unwrap();
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(tail[0], tail[1], tail[2], tail[3])),
                u16::from_be_bytes([tail[4], tail[5]]),
            )
        }
        0x04 => {
            let mut tail = [0u8; 18];
            control.read_exact(&mut tail).await.unwrap();
            let mut address = [0u8; 16];
            address.copy_from_slice(&tail[..16]);
            SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(address)),
                u16::from_be_bytes([tail[16], tail[17]]),
            )
        }
        0x03 => {
            let mut length = [0u8; 1];
            control.read_exact(&mut length).await.unwrap();
            let mut ignored = vec![0u8; length[0] as usize + 2];
            control.read_exact(&mut ignored).await.unwrap();
            panic!("SOCKS UDP relay returned a domain instead of an IP address")
        }
        other => panic!("SOCKS UDP relay returned address type {other}"),
    };
    // Both implementations may reply with 0.0.0.0 to mean the same address
    // as the TCP control listener.
    let relay = SocketAddr::new(
        if relay.ip().is_unspecified() {
            socks.ip()
        } else {
            relay.ip()
        },
        relay.port(),
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let std::net::IpAddr::V4(target_ip) = target.ip() else {
        panic!("the UDP oracle fixture is IPv4-only")
    };
    let mut request = vec![0x00, 0x00, 0x00, 0x01];
    request.extend_from_slice(&target_ip.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    request.extend_from_slice(body);
    socket.send_to(&request, relay).await.unwrap();

    let mut received = vec![0u8; 65_535];
    let (read, _) = tokio::time::timeout(Duration::from_secs(15), socket.recv_from(&mut received))
        .await
        .expect("UDP echo timed out")
        .expect("UDP echo failed");
    let response = zero_protocol::socks::parse_udp_datagram(&received[..read])
        .expect("proxy response is not a SOCKS5 UDP datagram");
    assert_eq!(response.destination.port, target.port());
    assert_eq!(response.payload, body, "UDP payload came back altered");
}

async fn round_trip(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut echoed))
        .await
        .expect("echo timed out")
        .expect("echo failed");
    assert_eq!(echoed, payload, "payload came back altered");
}

fn payload(seed: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(29).wrapping_add(seed))
        .collect()
}

/// Settings pairs for a protocol: (Xray-side server, client-side outbound).
fn protocol_settings(protocol: &str, port: u16) -> (Value, Value) {
    match protocol {
        "vless" => (
            json!({"clients": [{"id": UUID}], "decryption": "none"}),
            json!({"vnext": [{
                "address": "127.0.0.1",
                "port": port,
                "users": [{"id": UUID, "encryption": "none"}]
            }]}),
        ),
        "trojan" => (
            json!({"clients": [{"password": PASSWORD}]}),
            json!({"servers": [{"address": "127.0.0.1", "port": port, "password": PASSWORD}]}),
        ),
        "vmess" => (
            json!({"clients": [{"id": UUID}]}),
            json!({"vnext": [{
                "address": "127.0.0.1",
                "port": port,
                "users": [{"id": UUID, "security": "auto"}]
            }]}),
        ),
        "shadowsocks" => (
            json!({"method": "aes-256-gcm", "password": PASSWORD, "network": "tcp"}),
            json!({"servers": [{
                "address": "127.0.0.1",
                "port": port,
                "method": "aes-256-gcm",
                "password": PASSWORD
            }]}),
        ),
        other => panic!("unsupported protocol {other}"),
    }
}

fn transport(name: &str) -> Value {
    match name {
        "tcp" => json!({"network": "tcp"}),
        "ws" => json!({"network": "ws", "wsSettings": {"path": "/tunnel"}}),
        "httpupgrade" => json!({
            "network": "httpupgrade",
            "httpupgradeSettings": {"path": "/tunnel", "host": "oracle.example"}
        }),
        "grpc" => json!({"network": "grpc", "grpcSettings": {"serviceName": "TunnelService"}}),
        other => panic!("unsupported transport {other}"),
    }
}

/// Xray v26.7.28 protects proxy inbounds from SSRF by default and blackholes
/// private destinations reached through Freedom.  Every target in this local
/// differential harness is a loopback echo server, so opt out *inside the
/// disposable oracle configuration* just as Xray's own integration scenarios
/// do.  This does not weaken Zray's runtime policy or any user configuration.
fn oracle_loopback_freedom() -> Value {
    json!({
        "protocol": "freedom",
        "settings": {"finalRules": [{"action": "allow"}]},
    })
}

/// The decoy SNI both ends agree on. A collateral-damage domain is the right
/// choice in production (PLAN-02 §2); here it only has to be a name both
/// implementations treat identically.
const REALITY_SNI: &str = "www.googletagmanager.com";
/// Eight bytes, the maximum a REALITY shortId can carry.
const REALITY_SHORT_ID: &str = "0123456789abcdef";

/// An X25519 keypair in the exact encoding Xray expects.
///
/// Generated by the pinned oracle itself rather than by Zray. That is the
/// point of an oracle: if the two disagreed about base64 variant, key clamping
/// or byte order, a pair Zray produced would hide the disagreement by being
/// self-consistent.
fn oracle_x25519_keypair(binary: &str) -> (String, String) {
    let output = Command::new(binary)
        .arg("x25519")
        .output()
        .expect("the oracle binary should be able to generate an X25519 keypair");
    assert!(
        output.status.success(),
        "`{binary} x25519` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut private = None;
    let mut public = None;
    for line in text.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let label = label.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        // The wording has changed across releases ("Private key" vs
        // "PrivateKey"), so match on the distinguishing word rather than on an
        // exact label that would silently stop matching.
        if label.contains("private") {
            private = Some(value);
        } else if label.contains("public") || label.contains("password") {
            public = Some(value);
        }
    }
    match (private, public) {
        (Some(private), Some(public)) => (private, public),
        _ => panic!("could not parse an X25519 keypair from `{binary} x25519`:\n{text}"),
    }
}

/// A loopback TLS 1.3 server to act as the REALITY decoy.
///
/// The decoy is not optional scenery and it is not only used on failure: the
/// REALITY server mirrors the client's bytes to it on *every* connection and
/// reads its handshake back, validating that it really is a TLS 1.3 server
/// (proper ServerHello, a TLS 1.3 supported_version, a known suite, an X25519
/// or X25519MLKEM768 share) and copying its record lengths so the real session
/// is shaped like the decoy's. Point `dest` at anything else — a plain echo
/// listener, say — and the server abandons the handshake and forwards the
/// decoy's bytes verbatim, which reaches the client as "that was not a
/// ServerHello".
///
/// Another Xray instance is the honest choice here: using Go's own TLS server
/// means this fixture cannot accidentally pass by being shaped the way Zray
/// happens to expect.
fn spawn_decoy(binary: &str, port: u16) -> Oracle {
    spawn_oracle(
        binary,
        json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": "decoy-in",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vless",
                "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": REALITY_SNI,
                        "certificates": [{
                            "certificate": [DECOY_CERTIFICATE],
                            "key": [DECOY_PRIVATE_KEY],
                        }],
                    },
                },
            }],
            "outbounds": [oracle_loopback_freedom()],
        }),
    )
}

/// The REALITY server half, for an Xray inbound.
fn reality_server_settings(private_key: &str, fallback: SocketAddr) -> Value {
    json!({
        "show": false,
        "dest": fallback.to_string(),
        "xver": 0,
        "serverNames": [REALITY_SNI],
        "privateKey": private_key,
        "shortIds": [REALITY_SHORT_ID],
    })
}

/// The REALITY client half.
fn reality_client_settings(public_key: &str) -> Value {
    json!({
        "serverName": REALITY_SNI,
        "publicKey": public_key,
        "shortId": REALITY_SHORT_ID,
        "fingerprint": "chrome",
    })
}

/// Put `flow` on both ends of a VLESS pair.
///
/// Vision has to be named identically by client and server: Xray refuses a
/// user whose flow it does not recognise, and — worse for a test — a client
/// that omits it against a Vision server still completes the handshake and
/// then desynchronises on the first padded record.
fn apply_flow(server_settings: &mut Value, client_settings: &mut Value, flow: Option<&str>) {
    let Some(flow) = flow else {
        return;
    };
    for client in server_settings["clients"]
        .as_array_mut()
        .expect("VLESS inbound settings carry a clients array")
    {
        client["flow"] = json!(flow);
    }
    for entry in client_settings["vnext"]
        .as_array_mut()
        .expect("VLESS outbound settings carry a vnext array")
    {
        for user in entry["users"]
            .as_array_mut()
            .expect("each vnext entry carries a users array")
        {
            user["flow"] = json!(flow);
        }
    }
}

/// Zray client → Xray REALITY server./// Zray client → Xray REALITY server.
///
/// This is the column `xray-rust` cannot run and the one that matters most for
/// REALITY: the handshake hides its authentication tag inside a ClientHello
/// that has to be byte-acceptable to Go's implementation. A tag in the wrong
/// place does not produce an error — the server silently relays the connection
/// to the decoy site — so the assertion has to be that payload came *back*,
/// not that the socket opened.
async fn zray_client_to_xray_reality_server(binary: &str, carrier: &str, flow: Option<&str>) {
    let echo = echo_service().await;
    let relay_port = free_port();
    let socks_port = free_port();
    let (private_key, public_key) = oracle_x25519_keypair(binary);
    let (mut server_settings, mut client_settings) = protocol_settings("vless", relay_port);
    apply_flow(&mut server_settings, &mut client_settings, flow);
    let decoy_port = free_port();
    let _decoy = spawn_decoy(binary, decoy_port);
    let decoy = SocketAddr::new("127.0.0.1".parse().unwrap(), decoy_port);
    assert!(wait_for(decoy).await, "the REALITY decoy never listened");

    let mut oracle_stream = transport(carrier);
    oracle_stream["security"] = json!("reality");
    oracle_stream["realitySettings"] = reality_server_settings(&private_key, decoy);

    let mut zray_stream = transport(carrier);
    zray_stream["security"] = json!("reality");
    zray_stream["realitySettings"] = reality_client_settings(&public_key);

    let _oracle = spawn_oracle(
        binary,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "tag": "in",
                "listen": "127.0.0.1",
                "port": relay_port,
                "protocol": "vless",
                "settings": server_settings,
                "streamSettings": oracle_stream,
            }],
            "outbounds": [oracle_loopback_freedom()],
        }),
    );

    spawn_zray(json!({
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
            "settings": client_settings,
            "streamSettings": zray_stream,
        }],
    }));

    let relay = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port);
    assert!(
        wait_for(relay).await,
        "the oracle never listened on {relay} for REALITY/{carrier}"
    );
    assert!(wait_for(SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port)).await);

    let mut stream = socks_connect(
        SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port),
        echo,
    )
    .await
    .unwrap();
    round_trip(&mut stream, &payload(11, 64)).await;
    round_trip(&mut stream, &payload(12, 96 * 1024)).await;
}

/// Xray client → Zray REALITY server.
async fn xray_client_to_zray_reality_server(binary: &str, carrier: &str, flow: Option<&str>) {
    let echo = echo_service().await;
    let relay_port = free_port();
    let socks_port = free_port();
    let (private_key, public_key) = oracle_x25519_keypair(binary);
    let (mut server_settings, mut client_settings) = protocol_settings("vless", relay_port);
    apply_flow(&mut server_settings, &mut client_settings, flow);
    let decoy_port = free_port();
    let _decoy = spawn_decoy(binary, decoy_port);
    let decoy = SocketAddr::new("127.0.0.1".parse().unwrap(), decoy_port);
    assert!(wait_for(decoy).await, "the REALITY decoy never listened");

    let mut zray_stream = transport(carrier);
    zray_stream["security"] = json!("reality");
    zray_stream["realitySettings"] = reality_server_settings(&private_key, decoy);

    let mut oracle_stream = transport(carrier);
    oracle_stream["security"] = json!("reality");
    oracle_stream["realitySettings"] = reality_client_settings(&public_key);

    spawn_zray(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "relay-in",
            "listen": "127.0.0.1",
            "port": relay_port,
            "protocol": "vless",
            "settings": server_settings,
            "streamSettings": zray_stream,
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }));

    let _oracle = spawn_oracle(
        binary,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": false},
            }],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": client_settings,
                "streamSettings": oracle_stream,
            }],
        }),
    );

    assert!(wait_for(SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port)).await);
    assert!(wait_for(SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port)).await);

    let mut stream = socks_connect(
        SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port),
        echo,
    )
    .await
    .unwrap();
    round_trip(&mut stream, &payload(13, 64)).await;
    round_trip(&mut stream, &payload(14, 96 * 1024)).await;
}

/// Zray client → Xray server.
async fn zray_client_to_xray_server(binary: &str, protocol: &str, carrier: &str) {
    let echo = echo_service().await;
    let relay_port = free_port();
    let socks_port = free_port();
    let (server_settings, client_settings) = protocol_settings(protocol, relay_port);
    let stream = transport(carrier);

    let _oracle = spawn_oracle(
        binary,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "tag": "in",
                "listen": "127.0.0.1",
                "port": relay_port,
                "protocol": protocol,
                "settings": server_settings,
                "streamSettings": stream,
            }],
            "outbounds": [oracle_loopback_freedom()],
        }),
    );

    spawn_zray(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": protocol,
            "settings": client_settings,
            "streamSettings": stream,
        }],
    }));

    let relay = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port);
    assert!(
        wait_for(relay).await,
        "the oracle never listened on {relay}; is {protocol}/{carrier} supported by this build?"
    );
    assert!(wait_for(SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port)).await);

    let mut stream = socks_connect(
        SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port),
        echo,
    )
    .await
    .unwrap();
    round_trip(&mut stream, &payload(1, 64)).await;
    round_trip(&mut stream, &payload(2, 96 * 1024)).await;
}

/// Xray client → Zray server.
async fn xray_client_to_zray_server(binary: &str, protocol: &str, carrier: &str) {
    let echo = echo_service().await;
    let relay_port = free_port();
    let socks_port = free_port();
    let (server_settings, client_settings) = protocol_settings(protocol, relay_port);
    let stream = transport(carrier);

    spawn_zray(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "relay-in",
            "listen": "127.0.0.1",
            "port": relay_port,
            "protocol": protocol,
            "settings": server_settings,
            "streamSettings": stream,
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }));

    let _oracle = spawn_oracle(
        binary,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": false},
            }],
            "outbounds": [{
                "tag": "proxy",
                "protocol": protocol,
                "settings": client_settings,
                "streamSettings": stream,
            }],
        }),
    );

    assert!(wait_for(SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port)).await);
    let socks = SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port);
    assert!(
        wait_for(socks).await,
        "the oracle never listened on {socks}"
    );

    let mut stream = socks_connect(socks, echo).await.unwrap();
    round_trip(&mut stream, &payload(3, 64)).await;
    round_trip(&mut stream, &payload(4, 96 * 1024)).await;
}

/// Zray client → Xray server over VLESS Mux's UDP packet path.
async fn zray_xudp_to_xray(binary: &str) {
    let target = udp_echo_service().await;
    let relay_port = free_port();
    let socks_port = free_port();
    let (server_settings, client_settings) = protocol_settings("vless", relay_port);

    let _oracle = spawn_oracle(
        binary,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "tag": "vless-in",
                "listen": "127.0.0.1",
                "port": relay_port,
                "protocol": "vless",
                "settings": server_settings,
                "streamSettings": {"network": "tcp"},
            }],
            "outbounds": [oracle_loopback_freedom()],
        }),
    );

    spawn_zray(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": true},
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": client_settings,
            "streamSettings": {"network": "tcp"},
            "mux": {"enabled": true, "concurrency": 1},
        }],
    }));

    let relay = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port);
    assert!(
        wait_for(relay).await,
        "the Xray VLESS listener never started"
    );
    let socks = SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port);
    assert!(
        wait_for(socks).await,
        "the Zray SOCKS listener never started"
    );
    socks_udp_round_trip(socks, target, &payload(5, 1200)).await;
}

/// Xray client → Zray server through Xray's dedicated XUDP worker pool.
async fn xray_xudp_to_zray(binary: &str) {
    let target = udp_echo_service().await;
    let relay_port = free_port();
    let socks_port = free_port();
    let (server_settings, client_settings) = protocol_settings("vless", relay_port);

    spawn_zray(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "port": relay_port,
            "protocol": "vless",
            "settings": server_settings,
            "streamSettings": {"network": "tcp"},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }));

    let _oracle = spawn_oracle(
        binary,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": true},
            }],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": client_settings,
                "streamSettings": {"network": "tcp"},
                "mux": {
                    "enabled": true,
                    "concurrency": 1,
                    "xudpConcurrency": 1,
                    "xudpProxyUDP443": "allow",
                },
            }],
        }),
    );

    let relay = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port);
    assert!(
        wait_for(relay).await,
        "the Zray VLESS listener never started"
    );
    let socks = SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port);
    assert!(
        wait_for(socks).await,
        "the Xray SOCKS listener never started"
    );
    socks_udp_round_trip(socks, target, &payload(6, 1200)).await;
}

macro_rules! differential {
    ($name:ident, $protocol:literal, $carrier:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        #[ignore = "needs an Xray binary; see the module documentation"]
        async fn $name() {
            let binary = match oracle_binary() {
                Ok(binary) => binary,
                Err(reason) => panic!("the oracle comparison cannot run: {reason}"),
            };
            eprintln!(
                "oracle: {} ({} over {})",
                oracle_version(&binary),
                $protocol,
                $carrier
            );
            zray_client_to_xray_server(&binary, $protocol, $carrier).await;
            xray_client_to_zray_server(&binary, $protocol, $carrier).await;
        }
    };
}

differential!(vless_over_raw_tcp_matches_the_oracle, "vless", "tcp");
differential!(vless_over_websocket_matches_the_oracle, "vless", "ws");
differential!(
    vless_over_http_upgrade_matches_the_oracle,
    "vless",
    "httpupgrade"
);
differential!(vless_over_grpc_matches_the_oracle, "vless", "grpc");
differential!(trojan_over_raw_tcp_matches_the_oracle, "trojan", "tcp");
differential!(trojan_over_websocket_matches_the_oracle, "trojan", "ws");
differential!(vmess_over_raw_tcp_matches_the_oracle, "vmess", "tcp");
differential!(vmess_over_websocket_matches_the_oracle, "vmess", "ws");
differential!(
    shadowsocks_over_raw_tcp_matches_the_oracle,
    "shadowsocks",
    "tcp"
);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray binary; see the module documentation"]
async fn vless_over_reality_raw_tcp_matches_the_oracle() {
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the oracle comparison cannot run: {reason}");
    });
    eprintln!(
        "oracle: {} (VLESS/REALITY over raw TCP)",
        oracle_version(&binary)
    );
    zray_client_to_xray_reality_server(&binary, "tcp", None).await;
    xray_client_to_zray_reality_server(&binary, "tcp", None).await;
}

/// The combination the working Iranian configuration actually uses.
///
/// PLAN-02 §2 identifies `sni` choice, REALITY and Vision as the load-bearing
/// parts of that config, and Vision is the one with no self-consistent
/// fallback: it splices inner TLS records directly after the outer handshake
/// to erase the TLS-in-TLS signature, so client and server have to agree
/// byte-for-byte on where padding stops and payload begins. Two Zray ends can
/// agree on a wrong answer indefinitely; Xray cannot be talked into it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray binary; see the module documentation"]
async fn vless_vision_over_reality_matches_the_oracle() {
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the oracle comparison cannot run: {reason}");
    });
    eprintln!(
        "oracle: {} (VLESS/Vision over REALITY)",
        oracle_version(&binary)
    );
    let flow = Some("xtls-rprx-vision");
    zray_client_to_xray_reality_server(&binary, "tcp", flow).await;
    xray_client_to_zray_reality_server(&binary, "tcp", flow).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray binary; see the module documentation"]
async fn a_wrong_reality_public_key_is_refused_rather_than_silently_relayed() {
    // The failure mode REALITY is built around: a client that does not
    // authenticate is handed to the decoy site instead of being rejected. If
    // Zray treated that as success it would send tunnel traffic into a
    // connection the censor controls, so it has to be a *failure* here.
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the oracle comparison cannot run: {reason}");
    });
    let echo = echo_service().await;
    let relay_port = free_port();
    let socks_port = free_port();
    let (private_key, _) = oracle_x25519_keypair(&binary);
    // A second, unrelated keypair: the client believes a public key the server
    // has never held.
    let (_, wrong_public_key) = oracle_x25519_keypair(&binary);
    let (server_settings, client_settings) = protocol_settings("vless", relay_port);
    let decoy_port = free_port();
    let _decoy = spawn_decoy(&binary, decoy_port);
    let decoy = SocketAddr::new("127.0.0.1".parse().unwrap(), decoy_port);
    assert!(wait_for(decoy).await, "the REALITY decoy never listened");

    let mut oracle_stream = transport("tcp");
    oracle_stream["security"] = json!("reality");
    oracle_stream["realitySettings"] = reality_server_settings(&private_key, decoy);

    let mut zray_stream = transport("tcp");
    zray_stream["security"] = json!("reality");
    zray_stream["realitySettings"] = reality_client_settings(&wrong_public_key);

    let _oracle = spawn_oracle(
        &binary,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "tag": "in",
                "listen": "127.0.0.1",
                "port": relay_port,
                "protocol": "vless",
                "settings": server_settings,
                "streamSettings": oracle_stream,
            }],
            "outbounds": [oracle_loopback_freedom()],
        }),
    );

    spawn_zray(json!({
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
            "settings": client_settings,
            "streamSettings": zray_stream,
        }],
    }));

    assert!(wait_for(SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port)).await);
    assert!(wait_for(SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port)).await);

    let socks = SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port);
    let outcome = async {
        let mut stream = socks_connect(socks, echo).await?;
        stream.write_all(&4u32.to_be_bytes()).await?;
        stream.write_all(b"ping").await?;
        stream.flush().await?;
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        Ok::<[u8; 4], std::io::Error>(header)
    }
    .await;
    // Either the CONNECT is refused or the tunnel never carries the echo. What
    // must not happen is an intact round trip, which would mean Zray accepted
    // a server it never authenticated.
    match outcome {
        Err(_) => {}
        Ok(header) => panic!(
            "an unauthenticated REALITY server answered a full round trip \
             (echo header {header:?}); the fallback was treated as success"
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray binary; see the module documentation"]
async fn vless_xudp_matches_the_oracle() {
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the oracle comparison cannot run: {reason}");
    });
    eprintln!("oracle: {} (VLESS XUDP)", oracle_version(&binary));
    zray_xudp_to_xray(&binary).await;
    xray_xudp_to_zray(&binary).await;
}

/// Zray client → Xray server with arbitrary inbound and outbound settings,
/// over `connections` sequential tunnels (0-RTT tickets and XHTTP sessions
/// only show their bugs from the second connection on).
async fn zray_client_to_xray_with(
    binary: &str,
    protocol: &str,
    server_settings: Value,
    client_settings: Value,
    stream: Value,
    connections: u8,
) {
    let echo = echo_service().await;
    let relay_port = free_port();
    let socks_port = free_port();
    let mut client_settings = client_settings;
    client_settings["vnext"][0]["port"] = json!(relay_port);
    let _oracle = spawn_oracle(
        binary,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "tag": "in",
                "listen": "127.0.0.1",
                "port": relay_port,
                "protocol": protocol,
                "settings": server_settings,
                "streamSettings": stream,
            }],
            "outbounds": [oracle_loopback_freedom()],
        }),
    );
    spawn_zray(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": protocol,
            "settings": client_settings,
            "streamSettings": stream,
        }],
    }));
    let relay = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_port);
    assert!(
        wait_for(relay).await,
        "the oracle never listened on {relay}"
    );
    let socks = SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port);
    assert!(wait_for(socks).await);
    for connection in 0..connections {
        let mut tunnel = socks_connect(socks, echo).await.unwrap();
        round_trip(&mut tunnel, &payload(connection, 64)).await;
        round_trip(&mut tunnel, &payload(connection + 7, 96 * 1024)).await;
    }
}

/// `xray vlessenc`'s key pairs: (decryption, encryption) suffixes for X25519
/// and for ML-KEM-768, generated by the oracle so an encoding disagreement
/// cannot hide behind keys Zray made itself.
fn oracle_vlessenc_keys(binary: &str) -> Vec<(String, String)> {
    let output = Command::new(binary).arg("vlessenc").output().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    let values = |field: &str| -> Vec<String> {
        text.lines()
            .filter_map(|line| line.trim().strip_prefix(&format!("\"{field}\": \"")))
            .map(|rest| {
                rest.trim_end_matches('"')
                    .rsplit('.')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect()
    };
    let pairs: Vec<_> = values("decryption")
        .into_iter()
        .zip(values("encryption"))
        .collect();
    assert_eq!(pairs.len(), 2, "unexpected `xray vlessenc` output:\n{text}");
    pairs
}

/// Xray's post-quantum VLESS Encryption, in every mode, both round-trip
/// settings and both key types, plus Vision on top of it over a non-raw
/// carrier (which Xray allows only with encryption).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray binary; see the module documentation"]
async fn vless_encryption_matches_the_oracle() {
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the oracle comparison cannot run: {reason}");
    });
    eprintln!("oracle: {} (VLESS Encryption)", oracle_version(&binary));
    let keys = oracle_vlessenc_keys(&binary);
    let chained = (
        format!("{}.{}", keys[1].0, keys[0].0),
        format!("{}.{}", keys[1].1, keys[0].1),
    );
    for mode in ["native", "xorpub", "random"] {
        for rtt in ["1rtt", "0rtt"] {
            for (decryption, encryption) in [&keys[0], &keys[1], &chained] {
                eprintln!("  {mode} {rtt} key={}B", encryption.len());
                zray_client_to_xray_with(
                    &binary,
                    "vless",
                    json!({"clients": [{"id": UUID}],
                           "decryption": format!("mlkem768x25519plus.{mode}.600s.{decryption}")}),
                    json!({"vnext": [{"address": "127.0.0.1", "port": 0, "users": [{
                        "id": UUID,
                        "encryption": format!("mlkem768x25519plus.{mode}.{rtt}.{encryption}"),
                    }]}]}),
                    transport("tcp"),
                    3,
                )
                .await;
            }
        }
    }
    for (mode, carrier) in [("native", "tcp"), ("random", "tcp"), ("random", "ws")] {
        eprintln!("  Vision over {carrier}, {mode}");
        let (decryption, encryption) = &keys[0];
        zray_client_to_xray_with(
            &binary,
            "vless",
            json!({"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}],
                   "decryption": format!("mlkem768x25519plus.{mode}.600s.{decryption}")}),
            json!({"vnext": [{"address": "127.0.0.1", "port": 0, "users": [{
                "id": UUID,
                "flow": "xtls-rprx-vision",
                "encryption": format!("mlkem768x25519plus.{mode}.0rtt.{encryption}"),
            }]}]}),
            transport(carrier),
            2,
        )
        .await;
    }
}

/// XHTTP as Xray 26 shapes it: path normalisation and `x_padding`, which the
/// server enforces, and the obfuscation settings share links carry in
/// `extra`, in each upload mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray binary; see the module documentation"]
async fn xhttp_requests_match_the_oracle() {
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the oracle comparison cannot run: {reason}");
    });
    eprintln!("oracle: {} (XHTTP)", oracle_version(&binary));
    let header_obfs = json!({
        "xPaddingBytes": "1-1", "xPaddingObfsMode": true, "xPaddingKey": "ctx",
        "xPaddingHeader": "x-grpc-context", "xPaddingMethod": "tokenish",
        "sessionIDPlacement": "header", "sessionIDKey": "Idempotency-Key",
        "seqPlacement": "header", "seqKey": "Upload-Offset",
    });
    let cookie_obfs = json!({
        "xPaddingObfsMode": true, "xPaddingPlacement": "cookie",
        "sessionIDPlacement": "cookie", "seqPlacement": "query",
        "uplinkDataPlacement": "cookie",
    });
    let query_obfs = json!({
        "xPaddingObfsMode": true, "xPaddingPlacement": "query", "xPaddingMethod": "tokenish",
        "sessionIDPlacement": "query", "seqPlacement": "header",
        "uplinkDataPlacement": "header", "sessionIDTable": "Base62", "sessionIDLength": "8-12",
    });
    let mut cases = Vec::new();
    for mode in ["stream-one", "stream-up", "packet-up"] {
        cases.push((mode, None));
        cases.push((mode, Some(header_obfs.clone())));
    }
    cases.push(("packet-up", Some(cookie_obfs)));
    cases.push(("packet-up", Some(query_obfs)));
    for (mode, extra) in cases {
        eprintln!("  {mode} extra={}", extra.is_some());
        let mut settings = json!({"path": "/tunnel", "mode": mode});
        if let Some(extra) = extra {
            settings["extra"] = extra;
        }
        let (server_settings, client_settings) = protocol_settings("vless", 0);
        zray_client_to_xray_with(
            &binary,
            "vless",
            server_settings,
            client_settings,
            json!({"network": "xhttp", "xhttpSettings": settings}),
            2,
        )
        .await;
    }
}
