//! Transparent dokodemo-door inbounds, end to end on a private network.
//!
//! A gateway steers traffic into the inbound without the client knowing: with
//! REDIRECT (the kernel remembers the old destination) or TPROXY (the packet
//! keeps it). The inbound has to learn where the client was really going and
//! carry the flow there; for UDP it also has to answer *from* that address.
//!
//! This needs a network, nft rules and a second host, so the test builds them
//! in a user, network and mount namespace of its own (`unshare -Urnm`): a far
//! host reached over a veth pair runs two echo servers (this same binary, run
//! with another role), and the gateway side runs the inbound in this process.
//! Every flow is marked by Freedom's `sockopt.mark`, and a counter on that mark
//! is the proof that the traffic really went through the inbound and did not
//! just arrive.
//!
//! Where namespaces, `nft` or `nsenter` are not available the test says so and
//! passes, so a plain `cargo test` cannot fail on a locked-down machine.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const ROLE: &str = "ZRAY_TRANSPARENT_ROLE";
const FAR: &str = "10.1.0.2";

/// Outer test: build the namespaces and run the other two roles in them.
#[test]
fn redirect_and_tproxy_inbounds_follow_the_real_destination() {
    if std::env::var_os(ROLE).is_some() {
        return;
    }
    let usable = Command::new("unshare")
        .args(["-Urnm", "sh", "-c", "ip link set lo up && nft list ruleset"])
        .output()
        .is_ok_and(|output| output.status.success());
    if !usable {
        eprintln!("skipped: no private network namespace with nft here");
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let exe = exe.display();
    let name = "inbound_role";
    let script = format!(
        r#"set -e
ip link set lo up
unshare -n sleep 90 & FAR=$!
sleep 0.3
ip link add v0 type veth peer name v1
ip link set v1 netns $FAR
ip addr add 10.1.0.1/24 dev v0
ip link set v0 up
nsenter -t $FAR -n sh -c 'ip link set lo up; ip addr add 10.1.0.2/24 dev v1; ip link set v1 up'
ZRAY_TRANSPARENT_ROLE=far nsenter -t $FAR -n {exe} --exact {name} --nocapture &
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
nft -f - <<'NFT'
table ip mangle {{
  chain out {{
    type route hook output priority mangle; policy accept;
    meta mark != 255 ip daddr 10.1.0.2 tcp dport 7000 meta mark set 1
    meta mark != 255 ip daddr 10.1.0.2 udp dport 7001 meta mark set 1
    meta mark 255 meta l4proto tcp counter comment "zray-tcp"
    meta mark 255 meta l4proto udp counter comment "zray-udp"
  }}
  chain pre {{
    type filter hook prerouting priority mangle; policy accept;
    meta mark 1 meta l4proto tcp tproxy to :12346
    meta mark 1 meta l4proto udp tproxy to :12346
  }}
}}
table ip nat {{
  chain out {{
    type nat hook output priority -100; policy accept;
    meta mark != 255 ip daddr 10.1.0.2 tcp dport 7002 redirect to :12345
  }}
}}
NFT
sleep 0.5
set +e
ZRAY_TRANSPARENT_ROLE=near {exe} --exact {name} --nocapture
status=$?
kill $(jobs -p) 2>/dev/null
exit $status
"#
    );
    match Command::new("unshare")
        .args(["-Urnm", "sh", "-c", &script])
        .status()
    {
        Ok(status) => assert!(status.success(), "the test failed inside the namespace"),
        Err(error) => eprintln!("skipped: cannot run unshare ({error})"),
    }
}

/// Both inner roles are this one test function, told apart by the environment.
#[test]
fn inbound_role() {
    match std::env::var(ROLE).as_deref() {
        Ok("far") => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(far_host()),
        Ok("near") => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(gateway()),
        _ => {}
    }
}

/// The far host: "tcp-echo:" and "udp-echo:" in front of what it is sent, on
/// the three ports the gateway side talks to.
async fn far_host() {
    for port in [7000, 7002] {
        let listener = TcpListener::bind((FAR, port)).await.unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 100];
                    let read = stream.read(&mut buffer).await.unwrap_or(0);
                    let mut reply = format!("tcp-echo:{port}:").into_bytes();
                    reply.extend_from_slice(&buffer[..read]);
                    let _ = stream.write_all(&reply).await;
                });
            }
        });
    }
    let socket = UdpSocket::bind((FAR, 7001)).await.unwrap();
    let mut buffer = [0u8; 100];
    // Lives as long as the gateway side needs it; the shell kills it after.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while let Ok(Ok((read, from))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
    {
        let mut reply = b"udp-echo:".to_vec();
        reply.extend_from_slice(&buffer[..read]);
        let _ = socket.send_to(&reply, from).await;
    }
}

fn counter(name: &str) -> u64 {
    let listing = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&listing.stdout);
    text.lines()
        .find(|line| line.contains(name))
        .and_then(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            let at = words.iter().position(|word| *word == "packets")?;
            words.get(at + 1)?.parse().ok()
        })
        .unwrap_or(0)
}

async fn gateway() {
    let config = json!({
        "inbounds": [
            {"tag": "redirected", "protocol": "dokodemo-door", "listen": "127.0.0.1", "port": 12345,
             "settings": {"network": "tcp", "followRedirect": true},
             "streamSettings": {"sockopt": {"tproxy": "redirect"}}},
            {"tag": "tproxied", "protocol": "dokodemo-door", "listen": "0.0.0.0", "port": 12346,
             "settings": {"network": "tcp,udp", "followRedirect": true},
             "streamSettings": {"sockopt": {"tproxy": "tproxy"}}}
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom",
                       "streamSettings": {"sockopt": {"mark": 255}}}]
    });
    let (generation, _) =
        zero_config::compile_config(&config, zero_core::GenerationId(1)).expect("config");
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move { running.run().await });
    server.wait_until_listening().await;
    // The far host may still be binding.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // TCP by TPROXY.
    let tcp_answer = |port: u16| async move {
        let target: SocketAddr = format!("{FAR}:{port}").parse().unwrap();
        let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(target))
            .await
            .expect("connect timed out")
            .expect("connect");
        stream.write_all(b"hello").await.unwrap();
        let mut buffer = [0u8; 100];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .expect("read timed out")
            .expect("read");
        buffer[..read].to_vec()
    };
    assert_eq!(tcp_answer(7000).await, b"tcp-echo:7000:hello", "TPROXY TCP");
    // TCP by REDIRECT.
    assert_eq!(
        tcp_answer(7002).await,
        b"tcp-echo:7002:hello",
        "REDIRECT TCP"
    );
    // UDP by TPROXY: the answer must come back from the far host's address.
    let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    client.send_to(b"ping", (FAR, 7001)).await.unwrap();
    let mut buffer = [0u8; 100];
    let (read, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
        .await
        .expect("no UDP answer")
        .unwrap();
    assert_eq!(&buffer[..read], b"udp-echo:ping");
    assert_eq!(from, format!("{FAR}:7001").parse::<SocketAddr>().unwrap());

    // The flows went through the inbound: its own connections carry the mark.
    assert!(counter("zray-tcp") >= 2, "no marked TCP left the gateway");
    assert!(counter("zray-udp") >= 1, "no marked UDP left the gateway");
}
