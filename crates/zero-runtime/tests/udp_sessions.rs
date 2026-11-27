//! UDP sessions behave like UDP, not like request/response RPC.
//!
//! A proxied UDP flow must deliver every datagram the remote sends, including
//! several answers to one request, and a datagram that is never answered (an
//! ACK, a lost query) must neither stall the flow nor end it. These run the
//! real runtime over loopback against a scripted UDP peer.

use std::net::{SocketAddr, TcpListener as StdListener, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn free_port() -> u16 {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);
    for _ in 0..500 {
        let port = StdListener::bind("127.0.0.1:0")
            .expect("bind ephemeral")
            .local_addr()
            .expect("local addr")
            .port();
        // The UDP half of the port must be free too for UDP-facing inbounds.
        if StdUdpSocket::bind(("127.0.0.1", port)).is_err() {
            continue;
        }
        let mut taken = TAKEN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if taken.get_or_insert_with(HashSet::new).insert(port) {
            return port;
        }
    }
    panic!("could not reserve a free port");
}

async fn spawn(config: Value) -> Arc<zero_runtime::Server> {
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
    tokio::time::timeout(Duration::from_secs(30), server.wait_until_listening())
        .await
        .expect("server never reported its listeners bound");
    server
}

/// A UDP peer that ignores `quiet`, answers `twice` with two datagrams, and
/// echoes anything else once.
async fn scripted_peer() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let Ok((length, from)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            match &buffer[..length] {
                b"quiet" => {}
                b"twice" => {
                    let _ = socket.send_to(b"first", from).await;
                    let _ = socket.send_to(b"second", from).await;
                }
                other => {
                    let _ = socket.send_to(other, from).await;
                }
            }
        }
    });
    address
}

async fn read_vless_udp_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await.unwrap();
    let mut payload = vec![0u8; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut payload).await.unwrap();
    payload
}

fn vless_udp_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = (payload.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(payload);
    frame
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_udp_delivers_every_answer_and_survives_unanswered_datagrams() {
    let peer = scripted_peer().await;
    let port = free_port();
    let _server = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": UUID}]},
            "streamSettings": {"network": "tcp"},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }))
    .await;

    let uuid = zero_config::share_link::parse_uuid(UUID).unwrap();
    let destination = zero_core::Destination::udp(zero_core::Address::Ip(peer.ip()), peer.port());
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut request = zero_protocol::vless::encode_request(&uuid, "", &destination).to_vec();
    // The first datagram gets no answer at all.
    request.extend_from_slice(&vless_udp_frame(b"quiet"));
    request.extend_from_slice(&vless_udp_frame(b"twice"));
    stream.write_all(&request).await.unwrap();

    let exchange = async {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [0, 0], "VLESS response header");
        // Both answers to one request arrive, promptly: the unanswered
        // datagram before them must not be waited on.
        assert_eq!(read_vless_udp_frame(&mut stream).await, b"first");
        assert_eq!(read_vless_udp_frame(&mut stream).await, b"second");
        // And the session is still alive afterwards.
        stream
            .write_all(&vless_udp_frame(b"still-here"))
            .await
            .unwrap();
        assert_eq!(read_vless_udp_frame(&mut stream).await, b"still-here");
    };
    tokio::time::timeout(Duration::from_secs(3), exchange)
        .await
        .expect("UDP answers were delayed or lost");
}

fn socks_udp_datagram(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut datagram = vec![0, 0, 0, 0x01];
    match target.ip() {
        std::net::IpAddr::V4(ip) => datagram.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(_) => panic!("test targets are IPv4"),
    }
    datagram.extend_from_slice(&target.port().to_be_bytes());
    datagram.extend_from_slice(payload);
    datagram
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_udp_association_delivers_every_answer() {
    let peer = scripted_peer().await;
    let port = free_port();
    let _server = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"udp": true},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }))
    .await;

    let mut control = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    control.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "UDP ASSOCIATE was refused");
    let relay = SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([reply[8], reply[9]])));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&socks_udp_datagram(peer, b"quiet"), relay)
        .await
        .unwrap();
    client
        .send_to(&socks_udp_datagram(peer, b"twice"), relay)
        .await
        .unwrap();

    let exchange = async {
        let mut answers = Vec::new();
        let mut buffer = vec![0u8; 65_535];
        while answers.len() < 2 {
            let (length, _) = client.recv_from(&mut buffer).await.unwrap();
            // RSV(2) FRAG(1) ATYP(1) IPv4(4) PORT(2), then the payload.
            answers.push(buffer[10..length].to_vec());
        }
        answers
    };
    let answers = tokio::time::timeout(Duration::from_secs(3), exchange)
        .await
        .expect("UDP answers were delayed or lost");
    assert_eq!(answers, vec![b"first".to_vec(), b"second".to_vec()]);
    drop(control);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_client_does_not_hold_up_the_listener() {
    // A client that connects and never speaks sits in its own task under the
    // handshake deadline; an honest client on the same listener proceeds.
    let port = free_port();
    let server = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }))
    .await;
    let _silent = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut honest = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    honest.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), honest.read_exact(&mut greeting))
        .await
        .expect("an honest client was held up behind a silent one")
        .unwrap();
    assert_eq!(greeting, [0x05, 0x00]);
    assert!(server.active_sessions() >= 1);
}
