//! `policy.levels."0".connIdle` ends a connection that has gone quiet. The
//! limit is process-wide, so this is the only test in its binary.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_goes_quiet_is_closed_after_the_configured_idle_time() {
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_port = sink.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = sink.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 || socket.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    let socks_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = json!({
        "policy": {"levels": {"0": {"connIdle": 2}}},
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks"}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    });
    let (generation, _) =
        zero_config::compile_config(&config, zero_core::GenerationId(1)).expect("config");
    assert_eq!(generation.config.policy.conn_idle, Duration::from_secs(2));
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move { running.run().await });
    server.wait_until_listening().await;

    let mut stream = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&sink_port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");

    // Now say nothing. The connection must end well before the default five
    // minutes: within a few seconds of the two the policy names.
    let quiet = Instant::now();
    let mut byte = [0u8; 1];
    let ended = tokio::time::timeout(Duration::from_secs(8), stream.read(&mut byte)).await;
    assert!(
        matches!(ended, Ok(Ok(0)) | Ok(Err(_))),
        "the quiet connection was still open after {:?}",
        quiet.elapsed()
    );
    assert!(
        quiet.elapsed() >= Duration::from_millis(1500),
        "{:?}",
        quiet.elapsed()
    );
}
