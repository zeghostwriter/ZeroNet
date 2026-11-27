//! The MasterDNS building blocks against the real Go server.
//!
//! `zero-masterdns` is a set of parts (codec, packet framing, session
//! handshake, MTU probes, ping, the data ARQ), not yet a whole client. These
//! tests put those parts on a real UDP socket and talk to the upstream
//! `masterking32/MasterDnsVPN` server, built from the pinned release
//! `v2026.06.13.234407-7de2476`, so a disagreement over one byte of the wire
//! shows up as a failed handshake instead of a passing round trip against
//! ourselves.
//!
//! What is driven end to end, per encryption method: the MTU probes (upload and
//! download), `SESSION_INIT` → `SESSION_ACCEPT` through [`SessionHandshake`],
//! `PING` → `PONG`, a stream open (`STREAM_SYN` → `STREAM_CONNECTED`), and an
//! HTTP request carried through [`DataArq`] to a local origin and its answer
//! read back, acknowledged packet by packet.
//!
//! Opt-in, because they need the server binary. Build it from the pinned source
//! (`go build -o masterdns-server ./cmd/server`) and:
//!
//! ```bash
//! ZRAY_MASTERDNS_SERVER=/path/to/masterdns-server \
//!   cargo test -p zero-masterdns --test live_go_server -- --ignored --test-threads=1
//! ```
//!
//! A missing binary panics with the reason rather than passing. The server runs
//! in `TCP` mode against a fixed local origin: its `SOCKS5` mode refuses
//! loopback targets by design, which is the right behaviour and no use here.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zero_masterdns::arq::data::{Config as ArqConfig, DataArq};
use zero_masterdns::carrier::{exchange, DnsRequestIds, Exchange, TunnelSocket};
use zero_masterdns::mtu::{
    build_download_probe_payload, build_upload_probe_payload, effective_download_mtu_probe_size,
    validate_download_response, validate_upload_response, PROBE_FRAGMENT_ID,
    PROBE_SENTINEL_SESSION_ID, PROBE_SEQUENCE_NUM, PROBE_STREAM_ID, PROBE_TOTAL_FRAGMENTS,
};
use zero_masterdns::ping::ping_payload;
use zero_masterdns::session::{
    SessionAcceptClientSettings, SessionConfig, SessionHandshake, SessionReplyOutcome,
};
use zero_protocol::masterdns::codec::Codec;
use zero_protocol::masterdns::dns::{build_tunnel_txt_question, extract_vpn_frame};
use zero_protocol::masterdns::enums::*;
use zero_protocol::masterdns::packet::{
    build_raw, iter_packed_control_blocks, parse, BuildOptions,
};

const DOMAIN: &str = "t.example.test";
const KEY: &str = "0123456789abcdef0123456789abcdef";
const REQUEST: &[u8] = b"GET /index.html HTTP/1.0\r\nHost: origin\r\n\r\n";
const BODY: &str = "hello from the origin behind the go server";

/// The key the server accepts for `method`: it insists on exactly 16 characters
/// for AES-128, 24 for AES-192 and 32 for everything else, and quietly
/// generates its own when the file says otherwise.
fn key_for(method: u8) -> &'static str {
    match method {
        METHOD_AES_128_GCM => &KEY[..16],
        METHOD_AES_192_GCM => &KEY[..24],
        _ => KEY,
    }
}

fn server_binary() -> Result<PathBuf, String> {
    let path = std::env::var_os("ZRAY_MASTERDNS_SERVER")
        .ok_or("ZRAY_MASTERDNS_SERVER is unset (path to the Go server binary)")?;
    let path = PathBuf::from(path);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!("{} does not exist", path.display()))
    }
}

fn free_port(udp: bool) -> u16 {
    if udp {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    } else {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}

/// The Go server in a scratch directory, killed when the test ends.
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

fn spawn_server(binary: &PathBuf, method: u8, origin_port: u16) -> Server {
    let directory = std::env::temp_dir().join(format!(
        "zray-masterdns-{}-{}-{}",
        std::process::id(),
        method,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("encrypt_key.txt"), key_for(method)).unwrap();
    let port = free_port(true);
    std::fs::write(
        directory.join("server_config.toml"),
        format!(
            "DOMAIN = [\"{DOMAIN}\"]\n\
             PROTOCOL_TYPE = \"TCP\"\n\
             FORWARD_IP = \"127.0.0.1\"\n\
             FORWARD_PORT = {origin_port}\n\
             UDP_HOST = \"127.0.0.1\"\n\
             UDP_PORT = {port}\n\
             DATA_ENCRYPTION_METHOD = {method}\n\
             ENCRYPTION_KEY_FILE = \"encrypt_key.txt\"\n\
             LOG_LEVEL = \"DEBUG\"\n"
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
    let child = Command::new(binary)
        .current_dir(&directory)
        .args(["-config", "server_config.toml", "-nowait"])
        .stdout(sink())
        .stderr(sink())
        .spawn()
        .unwrap_or_else(|error| panic!("could not start the server: {error}"));
    Server {
        child,
        directory,
        resolver: format!("127.0.0.1:{port}").parse().unwrap(),
    }
}

/// A plain HTTP origin standing in for the service behind the tunnel.
async fn origin() -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer).await;
                let response = format!(
                    "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{BODY}",
                    BODY.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

/// One reply packet, copied out of the datagram.
#[derive(Debug, Clone)]
struct Reply {
    packet_type: u8,
    stream_id: u16,
    sequence: u16,
    payload: Vec<u8>,
}

/// The client half of the wire: build, seal, put in a DNS question, send, read
/// the TXT answer back into packets.
struct Wire {
    socket: TunnelSocket,
    resolver: SocketAddr,
    codec: Codec,
    ids: DnsRequestIds,
}

impl Wire {
    async fn new(resolver: SocketAddr, method: u8) -> Self {
        Wire {
            socket: TunnelSocket::bind().await.unwrap(),
            resolver,
            codec: Codec::new(method, key_for(method)).expect("the method is supported"),
            ids: DnsRequestIds::random(),
        }
    }

    /// Send one packet and return what came back, if anything did. A
    /// `PACKED_CONTROL_BLOCKS` answer is expanded into its blocks.
    async fn call(&self, opts: &BuildOptions<'_>) -> Vec<Reply> {
        let raw = build_raw(opts).expect("a well-formed packet");
        let labels = self.codec.encrypt_and_encode(&raw);
        let question =
            build_tunnel_txt_question(DOMAIN, labels.as_bytes(), self.ids.next(), 16, 4096)
                .expect("the name fits");
        let mut buffer = vec![0u8; 65535];
        let Ok(Exchange::Response { len, .. }) = exchange(
            &self.socket,
            &question,
            self.resolver,
            Duration::from_secs(2),
            &mut buffer,
        )
        .await
        else {
            return Vec::new();
        };
        let Ok(frame) = extract_vpn_frame(&buffer[..len], false) else {
            return Vec::new();
        };
        let Ok(packet) = parse(&frame) else {
            return Vec::new();
        };
        if packet.packet_type == PACKET_PACKED_CONTROL_BLOCKS {
            return iter_packed_control_blocks(packet.payload)
                .map(|block| Reply {
                    packet_type: block.packet_type,
                    stream_id: block.stream_id,
                    sequence: block.sequence_num,
                    payload: Vec::new(),
                })
                .collect();
        }
        vec![Reply {
            packet_type: packet.packet_type,
            stream_id: packet.stream_id.unwrap_or(0),
            sequence: packet.sequence_num.unwrap_or(0),
            payload: packet.payload.to_vec(),
        }]
    }
}

async fn wait_ready(wire: &Wire) {
    // The server is ready when it answers a probe at all.
    for _ in 0..50 {
        let payload = build_upload_probe_payload(40, false, 7).unwrap();
        let replies = wire.call(&probe(PACKET_MTU_UP_REQ, &payload)).await;
        if !replies.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the Go server never answered");
}

fn probe<'a>(packet_type: u8, payload: &'a [u8]) -> BuildOptions<'a> {
    BuildOptions {
        session_id: PROBE_SENTINEL_SESSION_ID,
        packet_type,
        stream_id: PROBE_STREAM_ID,
        sequence_num: PROBE_SEQUENCE_NUM,
        fragment_id: PROBE_FRAGMENT_ID,
        total_fragments: PROBE_TOTAL_FRAGMENTS,
        payload,
        ..Default::default()
    }
}

async fn run_method(method: u8) {
    let binary = server_binary().unwrap_or_else(|reason| {
        panic!("the live comparison cannot run: {reason}");
    });
    let origin_port = origin().await;
    let server = spawn_server(&binary, method, origin_port);
    let wire = Wire::new(server.resolver, method).await;
    wait_ready(&wire).await;

    // Upload MTU: the server echoes the code and the size it saw, so a question
    // of that size really crossed.
    for size in [40, 60, 80] {
        let payload = build_upload_probe_payload(size, false, 0xA1B2_C3D4).unwrap();
        let replies = wire.call(&probe(PACKET_MTU_UP_REQ, &payload)).await;
        let reply = replies
            .first()
            .unwrap_or_else(|| panic!("no answer to a {size}-byte probe"));
        assert!(
            validate_upload_response(reply.packet_type, &reply.payload, 0xA1B2_C3D4, size),
            "upload probe {size}: type {:#x}, payload {:?}",
            reply.packet_type,
            reply.payload
        );
    }

    // Download MTU: the answer's own length is the proof.
    let download = 400;
    let effective = effective_download_mtu_probe_size(download);
    let probe_down =
        build_download_probe_payload(download, 80, false, 0x0102_0304).expect("a probe that fits");
    let replies = wire
        .call(&probe(PACKET_MTU_DOWN_REQ, &probe_down.payload))
        .await;
    let reply = replies.first().expect("no answer to the download probe");
    assert!(
        validate_download_response(reply.packet_type, &reply.payload, 0x0102_0304, effective),
        "download probe {download}: type {:#x}, {} bytes",
        reply.packet_type,
        reply.payload.len()
    );

    // Session handshake through the real state machine.
    let mut handshake = SessionHandshake::new(SessionConfig {
        upload_mtu: 80,
        download_mtu: 400,
        ..SessionConfig::client_defaults()
    });
    let attempt = handshake
        .begin_attempt(&[true], [9, 8, 7, 6])
        .expect("one usable resolver");
    let replies = wire
        .call(&BuildOptions {
            packet_type: attempt.packet_type,
            payload: &attempt.payload,
            ..Default::default()
        })
        .await;
    let reply = replies.first().expect("no answer to SESSION_INIT");
    let outcome = handshake.apply_reply(
        reply.packet_type,
        &reply.payload,
        SessionAcceptClientSettings {
            packet_duplication_count: 2,
            setup_packet_duplication_count: 2,
            max_upload_mtu: 150,
            max_download_mtu: 4000,
            rx_tx_workers: 4,
            ping_aggressive_interval: 0.1,
            max_packets_per_batch: 8,
            arq_window_size: 600,
            arq_data_nack_max_gap: 16,
            compression_min_size: 120,
            arq_initial_rto_seconds: 1.0,
            arq_control_initial_rto_seconds: 1.0,
            arq_max_rto_seconds: 5.0,
            arq_control_max_rto_seconds: 5.0,
        },
        Instant::now(),
    );
    let SessionReplyOutcome::Accepted {
        session_id,
        session_cookie,
        ..
    } = outcome
    else {
        panic!("the server did not accept the session: {outcome:?} (reply {reply:?})");
    };
    assert_ne!(session_id, 0);

    // PING → PONG on stream 0.
    let ping = ping_payload([1, 2, 3, 4]);
    let replies = wire
        .call(&BuildOptions {
            session_id,
            session_cookie,
            packet_type: PACKET_PING,
            stream_id: 0,
            sequence_num: 1,
            payload: &ping,
            ..Default::default()
        })
        .await;
    assert!(
        replies.iter().any(|r| r.packet_type == PACKET_PONG),
        "no PONG for the PING: {replies:?}"
    );

    // Open a stream and wait for the server to connect to the origin.
    let stream_id = 1u16;
    let mut sequence = 100u16;
    let mut connected = false;
    let mut replies = wire
        .call(&BuildOptions {
            session_id,
            session_cookie,
            packet_type: PACKET_STREAM_SYN,
            stream_id,
            sequence_num: 0,
            ..Default::default()
        })
        .await;
    for _ in 0..40 {
        if replies
            .iter()
            .any(|r| r.packet_type == PACKET_STREAM_CONNECTED)
        {
            connected = true;
            break;
        }
        assert!(
            !replies
                .iter()
                .any(|r| r.packet_type == PACKET_STREAM_CONNECT_FAIL),
            "the server could not reach the origin"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        sequence += 1;
        replies = wire
            .call(&ping_for(session_id, session_cookie, sequence))
            .await;
    }
    assert!(connected, "STREAM_CONNECTED never arrived");
    // Acknowledge it so the server stops repeating it.
    wire.call(&BuildOptions {
        session_id,
        session_cookie,
        packet_type: PACKET_STREAM_CONNECTED_ACK,
        stream_id,
        sequence_num: 0,
        ..Default::default()
    })
    .await;

    // Carry a request through the data ARQ and read the answer back.
    let mut arq = DataArq::new(ArqConfig::client_defaults());
    arq.set_io_ready(true);
    let sent = arq.push_data(REQUEST.to_vec(), Instant::now());
    arq.on_dispatched(sent.seq, Instant::now());
    let mut inbox = wire
        .call(&BuildOptions {
            session_id,
            session_cookie,
            packet_type: PACKET_STREAM_DATA,
            stream_id,
            sequence_num: sent.seq,
            compression_type: 0,
            payload: &sent.data,
            ..Default::default()
        })
        .await;

    let mut body = Vec::new();
    let mut acked = false;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let mut outgoing: Vec<(u8, u16)> = Vec::new();
        for reply in inbox.drain(..) {
            match reply.packet_type {
                PACKET_STREAM_DATA_ACK if reply.stream_id == stream_id => {
                    acked |= arq.receive_ack(reply.sequence, Instant::now()).freed;
                }
                PACKET_STREAM_DATA | PACKET_STREAM_RESEND if reply.stream_id == stream_id => {
                    let outcome =
                        arq.receive_data(reply.sequence, reply.payload.clone(), Instant::now());
                    body.extend_from_slice(&outcome.delivered);
                    for packet in outcome.packets {
                        outgoing.push((packet.packet_type, packet.seq));
                    }
                }
                _ => {}
            }
        }
        if body.ends_with(BODY.as_bytes()) {
            break;
        }
        // Acknowledge what arrived, then poll again.
        if outgoing.is_empty() {
            sequence += 1;
            inbox = wire
                .call(&ping_for(session_id, session_cookie, sequence))
                .await;
        }
        for (packet_type, seq) in outgoing {
            inbox.extend(
                wire.call(&BuildOptions {
                    session_id,
                    session_cookie,
                    packet_type,
                    stream_id,
                    sequence_num: seq,
                    ..Default::default()
                })
                .await,
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.starts_with("HTTP/1.0 200 OK") && text.ends_with(BODY),
        "method {method}: the answer through the tunnel was {text:?}"
    );
    assert!(acked, "the server never acknowledged our request");
}

fn ping_for(session_id: u8, session_cookie: u8, sequence: u16) -> BuildOptions<'static> {
    static PAYLOAD: [u8; 7] = [b'P', b'O', b':', 1, 2, 3, 4];
    BuildOptions {
        session_id,
        session_cookie,
        packet_type: PACKET_PING,
        stream_id: 0,
        sequence_num: sequence,
        payload: &PAYLOAD,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn xor_session_carries_a_request_through_the_go_server() {
    run_method(METHOD_XOR).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn aes_256_gcm_session_carries_a_request_through_the_go_server() {
    run_method(METHOD_AES_256_GCM).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn aes_128_gcm_session_carries_a_request_through_the_go_server() {
    run_method(METHOD_AES_128_GCM).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn aes_192_gcm_session_carries_a_request_through_the_go_server() {
    run_method(METHOD_AES_192_GCM).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the MasterDnsVPN Go server; see the module documentation"]
async fn unencrypted_session_carries_a_request_through_the_go_server() {
    run_method(METHOD_NONE).await;
}
