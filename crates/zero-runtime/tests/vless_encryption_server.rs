//! VLESS Encryption on a server, from the outside: a Zray VLESS outbound with
//! `encryption` talks to a Zray VLESS inbound with `decryption`, through the
//! whole runtime, in every mode and with Vision.
//!
//! The same server is checked against Xray's own client by hand (see the
//! notes in the commit); this test keeps the two Zray ends honest, and
//! checks the failure cases: a client without the setting, with the wrong
//! key, and a server given a setting it cannot use.

use std::net::TcpListener as StdListener;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const USER: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                let mut reply = b"echo:".to_vec();
                reply.extend_from_slice(&buffer[..read]);
                let _ = stream.write_all(&reply).await;
            });
        }
    });
    port
}

async fn start(config: Value) -> Result<Arc<zero_runtime::Server>, String> {
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1))?;
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    let task = tokio::spawn(async move { running.run().await });
    tokio::select! {
        () = server.wait_until_listening() => Ok(server),
        ended = task => Err(format!("{:?}", ended.unwrap())),
    }
}

fn server_config(port: u16, decryption: &str, flow: &str) -> Value {
    json!({
        "inbounds": [{"tag": "in", "protocol": "vless", "listen": "127.0.0.1", "port": port,
            "settings": {"decryption": decryption, "clients": [{"id": USER, "flow": flow}]}}],
        "outbounds": [{"protocol": "freedom"}],
    })
}

fn client_config(link: u16, socks: u16, encryption: &str, flow: &str) -> Value {
    json!({
        "inbounds": [{"tag": "s", "protocol": "socks", "listen": "127.0.0.1", "port": socks,
            "settings": {"auth": "noauth"}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1",
            "port": link, "users": [{"id": USER, "encryption": encryption, "flow": flow}]}]}}],
    })
}

async fn through(socks: u16, target: u16) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other("SOCKS refused"));
    }
    stream.write_all(b"hello").await?;
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(8), stream.read_to_end(&mut answer))
        .await
        .map_err(|_| std::io::Error::other("timed out"))??;
    Ok(answer)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_mode_carries_a_session_through_both_zray_ends() {
    let target = echo().await;
    for (mlkem, mode, rtt, flow) in [
        (false, "native", "1rtt", ""),
        (true, "native", "0rtt", ""),
        (true, "xorpub", "1rtt", ""),
        (true, "random", "0rtt", ""),
        (true, "native", "1rtt", "xtls-rprx-vision"),
        (false, "random", "0rtt", "xtls-rprx-vision"),
    ] {
        let (encryption, decryption) =
            zero_protocol::vless_encryption::generate_pair(mlkem, mode, rtt, "600s");
        let (link, socks) = (free_port(), free_port());
        let _server = start(server_config(link, &decryption, flow)).await.unwrap();
        let _client = start(client_config(link, socks, &encryption, flow))
            .await
            .unwrap();
        // Twice: a 0-RTT client resumes on the second.
        for round in 0..2 {
            let answer = through(socks, target).await.unwrap_or_else(|error| {
                panic!("{mode} {rtt} {flow:?} mlkem={mlkem} round {round}: {error}")
            });
            assert_eq!(answer, b"echo:hello", "{mode} {rtt} {flow:?} round {round}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_without_the_setting_or_with_another_key_gets_nothing() {
    let target = echo().await;
    let (_, decryption) =
        zero_protocol::vless_encryption::generate_pair(true, "native", "1rtt", "600s");
    let (other_encryption, _) =
        zero_protocol::vless_encryption::generate_pair(true, "native", "1rtt", "600s");
    let link = free_port();
    let _server = start(server_config(link, &decryption, "")).await.unwrap();
    for encryption in ["none", other_encryption.as_str()] {
        let socks = free_port();
        let _client = start(client_config(link, socks, encryption, ""))
            .await
            .unwrap();
        let answer = through(socks, target).await;
        assert!(
            answer.map_or(true, |bytes| bytes.is_empty()),
            "{encryption:?} must not get through"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_setting_that_cannot_be_used_stops_the_server_at_start() {
    let error = start(server_config(
        free_port(),
        "mlkem768x25519plus.native.600s.not-a-key-but-long-enough-to-pass-the-length-rule",
        "",
    ))
    .await
    .err()
    .expect("the server must not start");
    assert!(error.contains("decryption"), "{error}");
    // Fallbacks and decryption are exclusive, as in Xray.
    let mut config = server_config(free_port(), "none", "");
    config["inbounds"][0]["settings"]["fallbacks"] = json!([{"dest": 80}]);
    config["inbounds"][0]["settings"]["decryption"] =
        json!("mlkem768x25519plus.native.600s.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert!(zero_config::compile_config(&config, zero_core::GenerationId(1)).is_err());
}
