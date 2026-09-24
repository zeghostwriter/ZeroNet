//! DNS-over-QUIC and plain UDP DNS, compared against the pinned oracle.
//!
//! The protocol oracle proves Zray and Xray agree about *proxy* wire formats.
//! DNS is the other half of what a client does on the network, and it is the
//! half that decides where everything else goes — a resolver that disagrees
//! with Xray about framing does not fail loudly, it fails on one transport, at
//! one resolver, for one user.
//!
//! DoQ (RFC 9250) is the interesting case. It is young enough that
//! implementations still differ on two details that are invisible until they
//! are not:
//!
//! * **The message ID must be zero.** §4.2.1 requires it, because QUIC streams
//!   already correlate request and response. A client that sends a random ID
//!   interoperates with servers that ignore it and fails against servers that
//!   enforce it.
//! * **Each query gets its own bidirectional stream**, length-prefixed like
//!   DNS-over-TCP, and the client closes its send side afterwards.
//!
//! So the oracle here is the *server*: one DoQ server, both clients, and the
//! recorded queries compared. A disagreement shows up as two different
//! recordings rather than as a resolver that mysteriously stops working.
//!
//! ```bash
//! cargo test -p zero-runtime --test dns_oracle -- --ignored --test-threads=1
//! ```

use std::io::Write;
use std::net::{SocketAddr, TcpListener as StdListener, UdpSocket as StdUdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const CERTIFICATE: &str = include_str!("fixtures/loopback-cert.pem");
const PRIVATE_KEY: &str = include_str!("fixtures/loopback-key.pem");
const CA_CERTIFICATE: &str = include_str!("fixtures/loopback-ca.pem");

/// The name both resolvers are asked about, and the answer the server gives.
const QUERY_NAME: &str = "oracle.zray.test";
const ANSWER: [u8; 4] = [127, 0, 0, 1];

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
    match Command::new("xray").arg("version").output() {
        Ok(output) if output.status.success() => Ok("xray".into()),
        _ => Err("no `xray` on PATH and ZRAY_XRAY_BINARY is unset".into()),
    }
}

fn free_tcp_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp_port() -> u16 {
    StdUdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Oracle {
    child: Child,
    _directory: std::path::PathBuf,
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start Xray, trusting the test CA for this process only.
///
/// Xray's DoQ nameserver builds its TLS config with no way to name a trust
/// anchor, so the anchor has to reach Go's root pool another way. `SSL_CERT_FILE`
/// is read by `crypto/x509` on Linux and applies to this child alone — it
/// changes nothing on the machine and nothing for any other process.
fn spawn_oracle(binary: &str, config: Value, ca_path: &std::path::Path) -> Oracle {
    let directory = std::env::temp_dir().join(format!(
        "zray-dns-oracle-{}-{}",
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

    let show_logs = std::env::var_os("ZRAY_ORACLE_LOG").is_some();
    let child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&path)
        .env("SSL_CERT_FILE", ca_path)
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

// ------------------------------------------------------------- DNS messages

/// What a resolver actually put on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedQuery {
    /// The DNS message ID. RFC 9250 §4.2.1 requires zero over DoQ.
    id: u16,
    /// The question name, lower-cased and without a trailing dot.
    name: String,
    /// The question type. 1 is A.
    kind: u16,
    /// Whether a length prefix framed the message, as DoQ and DoT require.
    length_prefixed: bool,
}

/// Parse a DNS query far enough to record what distinguishes implementations.
fn parse_query(message: &[u8], length_prefixed: bool) -> Option<RecordedQuery> {
    if message.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    let questions = u16::from_be_bytes([message[4], message[5]]);
    if questions != 1 {
        return None;
    }
    let mut at = 12usize;
    let mut labels = Vec::new();
    loop {
        let length = *message.get(at)? as usize;
        at += 1;
        if length == 0 {
            break;
        }
        // Compression pointers are not legal in a question section.
        if length & 0xc0 != 0 {
            return None;
        }
        labels.push(String::from_utf8_lossy(message.get(at..at + length)?).into_owned());
        at += length;
    }
    let kind = u16::from_be_bytes([*message.get(at)?, *message.get(at + 1)?]);
    Some(RecordedQuery {
        id,
        name: labels.join(".").to_ascii_lowercase(),
        kind,
        length_prefixed,
    })
}

/// Build a minimal response: the question echoed back, plus one A record.
fn build_response(query: &[u8]) -> Vec<u8> {
    let mut response = query.to_vec();
    // QR=1, RD copied, RA=1.
    response[2] = 0x81;
    response[3] = 0x80;
    // One answer.
    response[6] = 0x00;
    response[7] = 0x01;
    // Name compression pointer back to the question at offset 12.
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&1u16.to_be_bytes()); // A
    response.extend_from_slice(&1u16.to_be_bytes()); // IN
    response.extend_from_slice(&60u32.to_be_bytes()); // TTL
    response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    response.extend_from_slice(&ANSWER);
    response
}

// ------------------------------------------------------------- DoQ server

#[derive(Default)]
struct Recorder {
    queries: Mutex<Vec<RecordedQuery>>,
}

impl Recorder {
    fn record(&self, query: RecordedQuery) {
        self.queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(query);
    }

    fn take(&self) -> Vec<RecordedQuery> {
        std::mem::take(
            &mut *self
                .queries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }
}

/// A DoQ server that answers every query identically and records what it saw.
///
/// Being the same server for both clients is the whole point: any difference
/// in the recordings is a difference between the clients.
async fn doq_server(port: u16, recorder: Arc<Recorder>) -> SocketAddr {
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = {
        let mut reader = std::io::BufReader::new(CERTIFICATE.as_bytes());
        rustls_pki_types::pem::PemObject::pem_reader_iter(&mut reader)
            .filter_map(Result::ok)
            .collect()
    };
    let key: rustls_pki_types::PrivateKeyDer<'static> = {
        let mut reader = std::io::BufReader::new(PRIVATE_KEY.as_bytes());
        rustls_pki_types::pem::PemObject::from_pem_reader(&mut reader).expect("test key")
    };

    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("ring supports the default versions")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("a usable test certificate");
    // Xray offers three protocols and expects the server to pick `doq`.
    tls.alpn_protocols = vec![b"doq".to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("QUIC TLS");
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let endpoint = quinn::Endpoint::server(server_config, address).expect("DoQ endpoint");
    let bound = endpoint.local_addr().unwrap();

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let recorder = Arc::clone(&recorder);
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                loop {
                    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                        return;
                    };
                    let recorder = Arc::clone(&recorder);
                    tokio::spawn(async move {
                        // DoQ frames each message with a two-byte length, the
                        // same as DNS over TCP.
                        let Ok(length) = recv.read_u16().await else {
                            return;
                        };
                        let mut message = vec![0u8; length as usize];
                        if recv.read_exact(&mut message).await.is_err() {
                            return;
                        }
                        if let Some(query) = parse_query(&message, true) {
                            recorder.record(query);
                        }
                        let response = build_response(&message);
                        let _ = send.write_u16(response.len() as u16).await;
                        let _ = send.write_all(&response).await;
                        let _ = send.finish();
                    });
                }
            });
        }
    });
    bound
}

/// A plain UDP DNS server, recording the same way.
async fn udp_dns_server(port: u16, recorder: Arc<Recorder>) -> SocketAddr {
    let socket = UdpSocket::bind(("127.0.0.1", port)).await.expect("UDP DNS");
    let bound = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 1500];
        while let Ok((read, peer)) = socket.recv_from(&mut buffer).await {
            let message = &buffer[..read];
            if let Some(query) = parse_query(message, false) {
                recorder.record(query);
            }
            let response = build_response(message);
            let _ = socket.send_to(&response, peer).await;
        }
    });
    bound
}

// ------------------------------------------------------------------ fixture

async fn echo_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buffer[..n]).await.is_err() {
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

fn ca_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("zray-dns-oracle-ca-{}.pem", std::process::id()));
    std::fs::write(&path, CA_CERTIFICATE).expect("writing the test CA");
    path
}

/// Drive Xray into resolving `QUERY_NAME` through the configured resolver.
///
/// Xray does not expose a resolver API, so the observation is behavioural: a
/// SOCKS request for a hostname, a freedom outbound told to resolve it, and an
/// echo server at the address the DNS server hands back. Traffic completing is
/// proof the answer was used.
async fn xray_resolves_through(binary: &str, dns: Value, echo: SocketAddr, ca: &std::path::Path) {
    let socks_port = free_tcp_port();
    let _oracle = spawn_oracle(
        binary,
        json!({
            "log": {"loglevel": "debug"},
            "dns": dns,
            "inbounds": [{
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": false},
            }],
            "outbounds": [{
                "protocol": "freedom",
                // Force the name through the resolver rather than passing it
                // to the operating system at connect time.
                "settings": {
                    "domainStrategy": "UseIP",
                    "finalRules": [{"action": "allow"}],
                },
            }],
        }),
        ca,
    );

    let socks = SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port);
    assert!(
        wait_for(socks).await,
        "the oracle never listened on {socks}"
    );

    let mut stream = socks_connect_domain(socks, QUERY_NAME, echo.port())
        .await
        .expect("SOCKS CONNECT through the oracle");
    stream.write_all(b"resolved").await.unwrap();
    let mut echoed = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("the oracle's resolved connection timed out")
        .expect("reading the echo");
    assert_eq!(&echoed, b"resolved");
}

async fn wait_for(address: SocketAddr) -> bool {
    for _ in 0..100 {
        if TcpStream::connect(address).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn socks_connect_domain(
    socks: SocketAddr,
    host: &str,
    port: u16,
) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.set_nodelay(true)?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;

    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!(
            "SOCKS CONNECT failed with code {}",
            reply[1]
        )));
    }
    let skip = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        other => panic!("unexpected SOCKS5 address type {other}"),
    };
    let mut discard = vec![0u8; skip + 2];
    stream.read_exact(&mut discard).await?;
    Ok(stream)
}

/// Zray's resolver, asked the same question directly.
async fn zray_resolves_through(server: &str) -> Vec<std::net::IpAddr> {
    use zero_config::dns::{DnsServer, DnsSettings, LeakPolicy, ResolverEndpoint};

    let settings = DnsSettings {
        servers: vec![DnsServer {
            endpoint: ResolverEndpoint::parse(server)
                .unwrap_or_else(|| panic!("{server} should parse as a resolver endpoint")),
            domains: Vec::new(),
            expect_ips: Vec::new(),
            skip_fallback: false,
            tag: None,
        }]
        .into_boxed_slice(),
        hosts: Default::default(),
        query_strategy: Default::default(),
        leak_policy: LeakPolicy::Strict,
        disable_cache: true,
        tag: None,
        // The private CA the test DoQ server presents. Without this the
        // resolver correctly refuses it — which is the behaviour the new
        // `dns.certificates` surface exists to make configurable.
        trusted_roots: vec![CA_CERTIFICATE.as_bytes().to_vec().into_boxed_slice()],
    };
    let resolver = zero_dns::Resolver::new(settings);
    resolver
        .lookup(QUERY_NAME, Default::default())
        .await
        .expect("Zray should resolve through the test resolver")
}

// -------------------------------------------------------------------- cases

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray binary; see the module documentation"]
async fn doq_queries_match_the_oracle() {
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the DNS oracle comparison cannot run: {reason}");
    });
    let ca = ca_file();
    let recorder = Arc::new(Recorder::default());
    let port = free_udp_port();
    let server = doq_server(port, Arc::clone(&recorder)).await;
    let echo = echo_service().await;

    // Zray first, so its recording is isolated.
    let resolved = zray_resolves_through(&format!("doq://127.0.0.1:{}", server.port())).await;
    assert!(
        resolved.contains(&std::net::IpAddr::from(ANSWER)),
        "Zray did not use the DoQ answer: {resolved:?}"
    );
    let zray_queries = recorder.take();
    assert!(
        !zray_queries.is_empty(),
        "the DoQ server saw no query from Zray"
    );

    // Then Xray, against the same server.
    xray_resolves_through(
        &binary,
        json!({"servers": [format!("quic+local://127.0.0.1:{}", server.port())]}),
        echo,
        &ca,
    )
    .await;
    let xray_queries = recorder.take();
    assert!(
        !xray_queries.is_empty(),
        "the DoQ server saw no query from the oracle"
    );

    let zray = &zray_queries[0];
    let xray = xray_queries
        .iter()
        .find(|query| query.name == QUERY_NAME && query.kind == 1)
        .unwrap_or_else(|| panic!("the oracle asked about something else: {xray_queries:?}"));

    assert!(
        zray.length_prefixed && xray.length_prefixed,
        "DoQ frames each message with a two-byte length (RFC 9250 §4.2)"
    );
    assert_eq!(
        zray.kind, xray.kind,
        "the two clients asked for different record types"
    );
    // The detail that actually differs between implementations.
    assert_eq!(
        xray.id, 0,
        "the oracle sent a non-zero DoQ message id, which RFC 9250 §4.2.1 \
         forbids; the expectation encoded here needs revisiting"
    );
    assert_eq!(
        zray.id, xray.id,
        "Zray sent DoQ message id {} where the oracle sent {}. RFC 9250 \
         §4.2.1 requires zero, and a server that enforces it drops the other \
         one without an error",
        zray.id, xray.id
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray binary; see the module documentation"]
async fn plain_udp_dns_queries_match_the_oracle() {
    // The control for the case above: the same comparison on the transport
    // both implementations have spoken for years. If this disagrees, the DoQ
    // result says nothing about DoQ.
    let binary = oracle_binary().unwrap_or_else(|reason| {
        panic!("the DNS oracle comparison cannot run: {reason}");
    });
    let ca = ca_file();
    let recorder = Arc::new(Recorder::default());
    let port = free_udp_port();
    let server = udp_dns_server(port, Arc::clone(&recorder)).await;
    let echo = echo_service().await;

    let resolved = zray_resolves_through(&format!("{}:{}", server.ip(), server.port())).await;
    assert!(
        resolved.contains(&std::net::IpAddr::from(ANSWER)),
        "Zray did not use the UDP answer: {resolved:?}"
    );
    let zray_queries = recorder.take();
    assert!(!zray_queries.is_empty(), "no query from Zray");

    // Xray only parses a URL when the address is a domain; a plain IP with a
    // non-standard port has to be given in the object form.
    xray_resolves_through(
        &binary,
        json!({"servers": [{"address": server.ip().to_string(), "port": server.port()}]}),
        echo,
        &ca,
    )
    .await;
    let xray_queries = recorder.take();
    assert!(!xray_queries.is_empty(), "no query from the oracle");

    let zray = &zray_queries[0];
    let xray = xray_queries
        .iter()
        .find(|query| query.name == QUERY_NAME && query.kind == 1)
        .unwrap_or_else(|| panic!("the oracle asked about something else: {xray_queries:?}"));

    assert_eq!(zray.name, xray.name);
    assert_eq!(zray.kind, xray.kind);
    assert!(
        !zray.length_prefixed && !xray.length_prefixed,
        "plain UDP DNS carries no length prefix"
    );
    // Over UDP the id is the *only* correlator, so unlike DoQ it must not be
    // zero — the opposite requirement, on the same message.
    assert_ne!(
        zray.id, 0,
        "a zero message id over UDP leaves nothing to match a response against"
    );
}
