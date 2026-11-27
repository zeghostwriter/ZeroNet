//! How fast Tide moves bulk data in one process (no network): a stream
//! echoed through a server, uploads and downloads at once. Run on its own,
//! in release, to compare two builds:
//! `cargo test -p zero-transport --release --test tide_throughput -- --ignored --nocapture`
//!
//! It measures the protocol and the HTTP/2 framing, not any line: the numbers
//! only mean something next to the same test on another build.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zero_core::{boxed, Address, Destination};
use zero_protocol::tide;
use zero_transport::tide::{Client, ClientConfig, Decoy, Dialer, Server, ServerConfig};

fn rig() -> Arc<Client> {
    let (secret, public) = tide::generate_keypair();
    let user = [9u8; 16];
    let users = Arc::new(RwLock::new(HashMap::from([(user, "t".to_string())])));
    let (server, mut streams) = Server::new(ServerConfig {
        path: "/static/app".into(),
        admin: None,
        secret,
        users,
        decoy: Decoy::default(),
        shape: zero_protocol::tide::ShapeLevel::Off,
    });
    tokio::spawn(async move {
        while let Some((_, _, mut stream)) = streams.recv().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 64 * 1024];
                while let Ok(n @ 1..) = stream.read(&mut buffer).await {
                    if stream.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let dial: Dialer = Arc::new(move || {
        let server = server.clone();
        Box::pin(async move {
            let (near, far) = tokio::io::duplex(1024 * 1024);
            tokio::spawn(async move { server.serve_connection(boxed(far)).await });
            Ok(boxed(near))
        })
    });
    Client::new(
        ClientConfig {
            host: "example.test".into(),
            path: "/static/app".into(),
            server_public: public,
            user,
            split: true,
            linger: Duration::from_millis(50),
            lane: false,
            rotation: None,
            tuning: Default::default(),
        },
        dial,
    )
}

async fn run(streams: usize, megabytes: usize) -> f64 {
    let client = rig();
    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..streams {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let stream = client
                .open(Destination::tcp(Address::domain("example.com"), 443))
                .await
                .unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);
            let chunk = vec![0x5au8; 64 * 1024];
            let total = megabytes * 1024 * 1024;
            let send = async {
                let mut sent = 0;
                while sent < total {
                    writer.write_all(&chunk).await.unwrap();
                    sent += chunk.len();
                }
                writer.flush().await.unwrap();
            };
            let receive = async {
                let mut buffer = vec![0u8; 64 * 1024];
                let mut got = 0;
                while got < total {
                    got += reader.read(&mut buffer).await.unwrap();
                }
            };
            tokio::join!(send, receive);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    (streams * megabytes * 2) as f64 / started.elapsed().as_secs_f64()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, not a check"]
async fn bulk_throughput() {
    // Warm up, then three runs of each shape; the best of three is reported.
    let _ = run(1, 8).await;
    for (streams, megabytes) in [(1, 128), (8, 32)] {
        let best = {
            let mut best = 0.0f64;
            for _ in 0..3 {
                best = best.max(run(streams, megabytes).await);
            }
            best
        };
        println!("THROUGHPUT {streams} stream(s): {best:.0} MiB/s (up + down counted)");
    }
}
