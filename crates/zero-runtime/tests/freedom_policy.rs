//! What Freedom's `redirect`, `finalRules` and `proxyProtocol` do to a
//! connection, seen from a SOCKS5 client and a local sink.

use std::net::TcpListener as StdListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A sink that notes what a connection sent up to "ping", then answers "pong".
async fn sink() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                // Everything that arrives until the client has said "ping":
                // a PROXY header and the data behind it may come separately.
                let mut received = Vec::new();
                let mut buffer = [0u8; 4096];
                while !received.ends_with(b"ping") {
                    match tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buffer))
                        .await
                    {
                        Ok(Ok(read)) if read > 0 => received.extend_from_slice(&buffer[..read]),
                        _ => break,
                    }
                }
                log.lock().unwrap().push(received);
                let _ = socket.write_all(b"pong").await;
            });
        }
    });
    (port, seen)
}

async fn start(config: Value) {
    let (generation, _) =
        zero_config::compile_config(&config, zero_core::GenerationId(1)).expect("config");
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move { running.run().await });
    server.wait_until_listening().await;
}

/// Ask the SOCKS5 inbound for `ip:port`, send "ping", and say whether "pong"
/// came back.
async fn answers(socks_port: u16, ip: [u8; 4], port: u16) -> bool {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&ip);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    let answered =
        tokio::time::timeout(Duration::from_secs(4), stream.read_exact(&mut reply)).await;
    if !matches!(answered, Ok(Ok(_))) || reply[1] != 0 {
        return false;
    }
    stream.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut echo))
        .await
        .is_ok_and(|read| read.is_ok())
        && &echo == b"pong"
}

fn config(socks_port: u16, freedom_settings: Value) -> Value {
    json!({
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks"}],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": freedom_settings}],
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redirect_sends_the_connection_somewhere_else() {
    let (sink_port, _) = sink().await;
    let socks = free_port();
    start(config(
        socks,
        json!({"redirect": format!("127.0.0.1:{sink_port}")}),
    ))
    .await;
    // The client asks for an address nothing listens on.
    assert!(answers(socks, [127, 0, 0, 1], 9).await);

    // Only the port can be redirected too.
    let socks = free_port();
    start(config(socks, json!({"redirect": format!(":{sink_port}")}))).await;
    assert!(answers(socks, [127, 0, 0, 1], 9).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_final_rule_can_block_a_range_and_the_rest_goes_through() {
    let (sink_port, _) = sink().await;
    let blocked = free_port();
    start(config(
        blocked,
        json!({"finalRules": [{"action": "block", "ip": ["127.0.0.0/8"], "blockDelay": "0-0"}]}),
    ))
    .await;
    assert!(!answers(blocked, [127, 0, 0, 1], sink_port).await);

    let elsewhere = free_port();
    start(config(
        elsewhere,
        json!({"finalRules": [{"action": "block", "ip": ["10.0.0.0/8"], "blockDelay": "0-0"}]}),
    ))
    .await;
    assert!(answers(elsewhere, [127, 0, 0, 1], sink_port).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rules_are_tried_in_order_and_may_name_networks_and_ports() {
    let (sink_port, _) = sink().await;
    // An allow for the sink's port comes first, so the block behind it
    // never applies to this connection.
    let socks = free_port();
    start(config(
        socks,
        json!({"finalRules": [
            {"action": "allow", "network": "tcp", "port": sink_port.to_string()},
            {"action": "block", "ip": ["geoip:private"], "blockDelay": "0-0"},
        ]}),
    ))
    .await;
    assert!(answers(socks, [127, 0, 0, 1], sink_port).await);

    // Without it, geoip:private covers loopback.
    let socks = free_port();
    start(config(
        socks,
        json!({"finalRules": [{"action": "block", "ip": ["geoip:private"], "blockDelay": "0-0"}]}),
    ))
    .await;
    assert!(!answers(socks, [127, 0, 0, 1], sink_port).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blocked_connection_is_held_for_its_delay_before_it_is_refused() {
    let (sink_port, _) = sink().await;
    let socks = free_port();
    start(config(
        socks,
        json!({"finalRules": [{"action": "block", "ip": ["127.0.0.0/8"], "blockDelay": "1-1"}]}),
    ))
    .await;
    let started = std::time::Instant::now();
    assert!(!answers(socks, [127, 0, 0, 1], sink_port).await);
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "the refusal came at once: {:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_proxy_protocol_header_comes_first_in_either_version() {
    for version in [1u8, 2] {
        let (sink_port, seen) = sink().await;
        let socks = free_port();
        start(config(socks, json!({"proxyProtocol": version}))).await;
        assert!(answers(socks, [127, 0, 0, 1], sink_port).await);
        let first = seen.lock().unwrap()[0].clone();
        match zero_protocol::proxy_protocol::parse(&first) {
            zero_protocol::proxy_protocol::Parsed::Header(header, consumed) => {
                let source = header.source.expect("a source");
                assert!(source.ip().is_loopback());
                assert_eq!(header.destination.unwrap().port(), sink_port);
                // What follows is the client's own data.
                assert_eq!(&first[consumed..], b"ping", "version {version}");
            }
            other => panic!("version {version}: {other:?} from {first:?}"),
        }
    }
}

#[test]
fn what_cannot_be_enforced_is_refused_at_load() {
    for bad in [
        json!({"finalRules": [{"action": "block", "ip": ["geoip:cn"]}]}),
        json!({"finalRules": [{"action": "maybe"}]}),
        json!({"finalRules": [{"action": "block", "network": "icmp"}]}),
        json!({"proxyProtocol": 3}),
        json!({"redirect": ":notaport"}),
    ] {
        let config = config(1080, bad.clone());
        assert!(zero_config::parse_config(&config).is_err(), "{bad}");
    }
}

/// Through the SOCKS5 inbound with `header` sent first on the connection.
async fn answers_with_header(socks_port: u16, header: &[u8], sink_port: u16) -> bool {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    stream.write_all(header).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    if !matches!(
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut method)).await,
        Ok(Ok(_))
    ) {
        return false;
    }
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&sink_port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    if !matches!(
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut reply)).await,
        Ok(Ok(_))
    ) || reply[1] != 0
    {
        return false;
    }
    stream.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut echo))
        .await
        .is_ok_and(|read| read.is_ok())
}

/// A balancer in front puts the client's address in a PROXY header; the rules
/// then see that address, not the balancer's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inbound_that_accepts_the_proxy_protocol_routes_by_the_address_in_it() {
    let (sink_port, _) = sink().await;
    let socks = free_port();
    start(json!({
        "inbounds": [{
            "tag": "in", "listen": "127.0.0.1", "port": socks, "protocol": "socks",
            "streamSettings": {"sockopt": {"acceptProxyProtocol": true}},
        }],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"rules": [
            {"type": "field", "source": ["198.51.100.9/32"], "outboundTag": "block"},
        ]},
    }))
    .await;
    let from = |text: &str| {
        zero_protocol::proxy_protocol::encode(
            2,
            Some(text.parse().unwrap()),
            Some("192.0.2.1:1080".parse().unwrap()),
        )
    };
    assert!(!answers_with_header(socks, &from("198.51.100.9:4000"), sink_port).await);
    assert!(answers_with_header(socks, &from("198.51.100.10:4000"), sink_port).await);
    let v1 = zero_protocol::proxy_protocol::encode(
        1,
        Some("203.0.113.5:4000".parse().unwrap()),
        Some("192.0.2.1:1080".parse().unwrap()),
    );
    assert!(answers_with_header(socks, &v1, sink_port).await);
    // A connection with no header is refused, not trusted.
    assert!(!answers_with_header(socks, b"", sink_port).await);
}

/// `customSockopt` on a Freedom outbound reaches the sockets it dials: a valid
/// option leaves connections working, one the kernel refuses stops them (as
/// Xray's does), so a typo in an option number is found at once.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custom_sockopt_applies_to_dialled_sockets() {
    let (sink_port, _) = sink().await;
    let outbound = |opt: u32| {
        json!({
            "inbounds": [],
            "outbounds": [{"tag": "direct", "protocol": "freedom",
                "streamSettings": {"sockopt": {"customSockopt": [
                    {"level": "1", "opt": opt.to_string(), "value": "65536", "type": "int",
                     "network": "tcp"}]}}}],
        })
    };
    let with = |socks: u16, opt: u32| {
        let mut config = outbound(opt);
        config["inbounds"] = json!([{"tag": "in", "listen": "127.0.0.1", "port": socks,
            "protocol": "socks"}]);
        config
    };
    // Level 1, option 8 is SO_RCVBUF: fine.
    let socks = free_port();
    start(with(socks, 8)).await;
    assert!(answers(socks, [127, 0, 0, 1], sink_port).await);
    // An option number the kernel has never heard of stops the connection.
    let socks = free_port();
    start(with(socks, 9999)).await;
    assert!(!answers(socks, [127, 0, 0, 1], sink_port).await);
}
