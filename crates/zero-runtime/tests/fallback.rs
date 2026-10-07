//! A VLESS or Trojan inbound with `fallbacks` hands anyone who does not
//! authenticate to a web server, with every byte they sent.
//!
//! Without this a prober that connects and sends an HTTP request, or a wrong
//! credential, is simply cut off, which no real website does. With it the
//! prober gets the web server's own answer, and a real client is unaffected.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A stand-in web server: answers anything with [`REPLY`] and remembers what
/// each visitor sent first.
async fn web_server() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                log.lock().unwrap().push(buffer[..read].to_vec());
                let _ = stream.write_all(REPLY).await;
            });
        }
    });
    (port, seen)
}

async fn echo_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
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

async fn inbound(protocol: &str, fallbacks: Value) -> u16 {
    let port = free_port();
    let clients = match protocol {
        "vless" => json!([{"id": UUID}]),
        _ => json!([{"password": "the-right-password"}]),
    };
    let config = json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "in", "listen": "127.0.0.1", "port": port, "protocol": protocol,
            "settings": {"clients": clients, "decryption": "none", "fallbacks": fallbacks},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    });
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1)).unwrap();
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move { running.run().await.unwrap() });
    tokio::time::timeout(Duration::from_secs(30), server.wait_until_listening())
        .await
        .unwrap();
    // Keep the server alive for the length of the test.
    std::mem::forget(server);
    port
}

/// Send `request` to the inbound and read the whole reply.
async fn visit(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut reply = vec![0u8; REPLY.len()];
    match tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut reply)).await {
        Ok(Ok(_)) => reply,
        _ => Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_browser_reaching_a_vless_port_is_answered_by_the_web_server() {
    let (web, seen) = web_server().await;
    let port = inbound("vless", json!([{"dest": web}])).await;
    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert_eq!(visit(port, request).await, REPLY);
    assert_eq!(seen.lock().unwrap()[0], request, "every byte was passed on");
    // Something far too short to be a request header goes the same way.
    assert_eq!(visit(port, b"hi\r\n").await, REPLY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_vless_user_is_answered_by_the_web_server() {
    let (web, seen) = web_server().await;
    let port = inbound("vless", json!([{"dest": format!("127.0.0.1:{web}")}])).await;
    let destination = zero_core::Destination::tcp(zero_core::Address::domain("example.com"), 443);
    let mut request = zero_protocol::vless::encode_request(&[0x11; 16], "", &destination).to_vec();
    request.extend_from_slice(b"payload");
    assert_eq!(visit(port, &request).await, REPLY);
    assert_eq!(seen.lock().unwrap()[0], request);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_trojan_password_is_answered_by_the_web_server() {
    let (web, seen) = web_server().await;
    let port = inbound("trojan", json!([{"dest": web}])).await;
    // Shaped exactly like a Trojan request, with a password nobody has.
    let mut request = vec![b'a'; 56];
    request.extend_from_slice(b"\r\n\x01\x01\x7f\x00\x00\x01\x00\x50\r\nGET / HTTP/1.1\r\n\r\n");
    assert_eq!(visit(port, &request).await, REPLY);
    assert_eq!(seen.lock().unwrap()[0], request);
    assert_eq!(visit(port, b"GET / HTTP/1.1\r\n\r\n").await, REPLY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_client_still_gets_through_when_a_fallback_is_set() {
    let (web, seen) = web_server().await;
    let echo = echo_service().await;
    let port = inbound("vless", json!([{"dest": web}])).await;
    let uuid = zero_config::share_link::parse_uuid(UUID).unwrap();
    let destination = zero_core::Destination::tcp(zero_core::Address::Ip(echo.ip()), echo.port());
    let mut request = zero_protocol::vless::encode_request(&uuid, "", &destination).to_vec();
    request.extend_from_slice(b"ping");
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(&request).await.unwrap();
    // The VLESS response header, then the echo.
    let mut reply = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"\x00\x00ping");
    assert!(
        seen.lock().unwrap().is_empty(),
        "the web server never saw it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_fallback_a_stranger_is_still_just_cut_off() {
    let port = inbound("vless", json!([])).await;
    assert!(visit(port, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fallback_chosen_by_path_or_name_is_not_used_for_everyone() {
    let (web, seen) = web_server().await;
    let port = inbound("vless", json!([{"path": "/ws", "dest": web}])).await;
    assert!(visit(port, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .is_empty());
    assert!(seen.lock().unwrap().is_empty());
}
