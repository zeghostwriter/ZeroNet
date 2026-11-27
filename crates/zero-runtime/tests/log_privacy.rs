//! A server's log must never hold what its users authenticate with.
//!
//! Operators send logs to journald, to bug reports and to strangers asking for
//! help; a user id or password printed once at startup ends up in all of them.
//! This starts a server whose inbounds carry known secrets and checks that none
//! of them, in any form a `Debug` print would give, reaches the log.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
    type Writer = Sink;
    fn make_writer(&'a self) -> Sink {
        self.clone()
    }
}

const USER_ID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "correct-horse-battery-staple-9f3a";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_logs_name_the_protocol_and_not_its_secrets() {
    let sink = Sink::default();
    // Global, not per-thread: the server logs from its own worker tasks. This
    // file holds one test, so nothing else shares the subscriber.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(sink.clone())
        .init();

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let trojan = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = json!({
        "inbounds": [
            {"tag": "vless-in", "listen": "127.0.0.1", "port": port, "protocol": "vless",
             "settings": {"clients": [{"id": USER_ID}], "decryption": "none"}},
            {"tag": "trojan-in", "listen": "127.0.0.1", "port": trojan, "protocol": "trojan",
             "settings": {"clients": [{"password": PASSWORD}]}},
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    });
    let (generation, _) = zero_config::compile_config(&config, zero_core::GenerationId(1)).unwrap();
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = running.run().await;
    });
    tokio::time::timeout(Duration::from_secs(10), server.wait_until_listening())
        .await
        .expect("the server never listened");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let log = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    assert!(
        log.contains("listening"),
        "the server logged nothing:\n{log}"
    );
    assert!(log.contains("vless") && log.contains("trojan"));
    assert!(!log.contains(USER_ID), "a user id reached the log:\n{log}");
    assert!(
        !log.contains(PASSWORD),
        "a password reached the log:\n{log}"
    );
    // `Debug` prints a uuid as its bytes: 0xb8 0x31 0x38 0x1d is 184, 49, 56, 29.
    assert!(
        !log.contains("184, 49, 56, 29"),
        "a user id's bytes reached the log:\n{log}"
    );
    assert!(
        !log.contains("users: ["),
        "an inbound's user list reached the log:\n{log}"
    );
}
