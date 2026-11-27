//! A SOCKS5 outbound, end to end: a client runtime sends traffic through a
//! SOCKS5 upstream, which is how a local Tor, Orbot or Psiphon client is used.
//!
//! The upstream here is a small hand-written SOCKS5 server, not Zray's own
//! inbound, so the outbound is checked against an independent reading of RFC
//! 1928. Two things matter most and are asserted directly:
//!
//! * a domain name reaches the upstream as a *name*. The test name used below
//!   resolves nowhere, so the only way the payload can come back is if the
//!   client left the lookup to the upstream (for Tor, a local lookup would
//!   leak the name outside the circuit);
//! * a refusal from the upstream closes the tunnel instead of hanging it.

use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

fn spawn(config: Value) -> Arc<zero_runtime::Server> {
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
    server
}

/// A plain echo service: whatever arrives goes straight back.
async fn echo_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 || stream.write_all(&buffer[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    address
}

/// What the upstream saw in the CONNECT request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Name(String, u16),
    Ip(std::net::IpAddr, u16),
}

/// Behaviour switch for the fake upstream.
#[derive(Clone)]
struct Upstream {
    /// `Some((user, pass))` demands RFC 1929 login.
    login: Option<(&'static str, &'static str)>,
    /// A fixed reply code instead of connecting (for refusal tests).
    refuse_with: Option<u8>,
    /// Where `echo.invalid` is really found.
    echo: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

async fn upstream(behaviour: Upstream) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let behaviour = behaviour.clone();
            tokio::spawn(async move {
                let _ = serve(&mut stream, behaviour).await;
            });
        }
    });
    address
}

async fn serve(stream: &mut TcpStream, b: Upstream) -> std::io::Result<()> {
    let mut hello = [0u8; 2];
    stream.read_exact(&mut hello).await?;
    let mut methods = vec![0u8; hello[1] as usize];
    stream.read_exact(&mut methods).await?;
    if let Some((user, pass)) = b.login {
        if !methods.contains(&0x02) {
            return stream.write_all(&[5, 0xFF]).await;
        }
        stream.write_all(&[5, 0x02]).await?;
        let mut ver_len = [0u8; 2];
        stream.read_exact(&mut ver_len).await?;
        let mut got_user = vec![0u8; ver_len[1] as usize];
        stream.read_exact(&mut got_user).await?;
        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen).await?;
        let mut got_pass = vec![0u8; plen[0] as usize];
        stream.read_exact(&mut got_pass).await?;
        let ok = got_user == user.as_bytes() && got_pass == pass.as_bytes();
        stream.write_all(&[1, u8::from(!ok)]).await?;
        if !ok {
            return Ok(());
        }
    } else {
        stream.write_all(&[5, 0x00]).await?;
    }

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    assert_eq!(&head[..3], &[5, 1, 0], "expected a CONNECT");
    let seen = match head[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Seen::Ip(ip.into(), u16::from_be_bytes(port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Seen::Name(String::from_utf8(name).unwrap(), u16::from_be_bytes(port))
        }
        other => panic!("unexpected address type {other}"),
    };
    b.seen.lock().unwrap().push(seen.clone());

    if let Some(code) = b.refuse_with {
        return stream.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    }
    let target = match &seen {
        Seen::Name(name, _) if name == "echo.invalid" => b.echo,
        Seen::Name(name, _) => panic!("unknown test name {name}"),
        Seen::Ip(ip, port) => SocketAddr::new(*ip, *port),
    };
    let mut onward = TcpStream::connect(target).await?;
    // A domain-form bound address, to prove the client drains every form.
    stream
        .write_all(&[5, 0, 0, 3, 4, b't', b'e', b's', b't', 0, 80])
        .await?;
    tokio::io::copy_bidirectional(stream, &mut onward).await?;
    Ok(())
}

/// A client runtime: SOCKS inbound, one SOCKS5 outbound toward `upstream`.
async fn client(upstream: SocketAddr, auth: Option<(&str, &str)>) -> SocketAddr {
    let socks_port = free_port();
    let mut server = json!({"address": "127.0.0.1", "port": upstream.port()});
    if let Some((user, pass)) = auth {
        server["users"] = json!([{"user": user, "pass": pass}]);
    }
    let runtime = spawn(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks", "settings": {"udp": false},
        }],
        "outbounds": [{
            "tag": "tor", "protocol": "socks", "settings": {"servers": [server]},
        }],
    }));
    tokio::time::timeout(Duration::from_secs(30), runtime.wait_until_listening())
        .await
        .expect("client never bound its listeners");
    SocketAddr::new("127.0.0.1".parse().unwrap(), socks_port)
}

/// SOCKS5 CONNECT to a domain through the client; returns the reply code and
/// the stream.
async fn connect_domain(
    socks: SocketAddr,
    name: &str,
    port: u16,
) -> std::io::Result<(u8, TcpStream)> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let mut request = vec![5, 1, 0, 3, name.len() as u8];
    request.extend_from_slice(name.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] == 0 {
        let skip = match reply[3] {
            1 => 4,
            4 => 16,
            _ => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                len[0] as usize
            }
        };
        let mut discard = vec![0u8; skip + 2];
        stream.read_exact(&mut discard).await?;
    }
    Ok((reply[1], stream))
}

fn behaviour(echo: SocketAddr) -> Upstream {
    Upstream {
        login: None,
        refuse_with: None,
        echo,
        seen: Arc::new(Mutex::new(Vec::new())),
    }
}

async fn echoes(stream: &mut TcpStream, message: &[u8]) {
    stream.write_all(message).await.unwrap();
    let mut back = vec![0u8; message.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut back))
        .await
        .expect("echo timed out")
        .expect("echo failed");
    assert_eq!(back, message);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_domain_reaches_the_upstream_as_a_name_and_payload_survives() {
    let echo = echo_service().await;
    let b = behaviour(echo);
    let seen = Arc::clone(&b.seen);
    let socks = client(upstream(b).await, None).await;

    let (code, mut stream) = connect_domain(socks, "echo.invalid", 4433).await.unwrap();
    assert_eq!(code, 0, "CONNECT through the SOCKS5 upstream failed");
    echoes(&mut stream, b"through the upstream").await;
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    // Write and read at once: 200 KB overruns every socket buffer on the path.
    let (mut read, mut write) = stream.into_split();
    let writer = {
        let big = big.clone();
        tokio::spawn(async move { write.write_all(&big).await.unwrap() })
    };
    let mut back = vec![0u8; big.len()];
    read.read_exact(&mut back).await.unwrap();
    writer.await.unwrap();
    assert_eq!(back, big);

    assert_eq!(
        seen.lock().unwrap().as_slice(),
        [Seen::Name("echo.invalid".into(), 4433)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ip_destination_is_sent_as_an_address() {
    let echo = echo_service().await;
    let b = behaviour(echo);
    let seen = Arc::clone(&b.seen);
    let socks = client(upstream(b).await, None).await;

    // Plain IPv4 CONNECT through the client's inbound.
    let mut stream = TcpStream::connect(socks).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap_or_else(|_| {
        panic!("short reply");
    });
    assert_eq!(reply[1], 0);
    echoes(&mut stream, b"ip form").await;
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        [Seen::Ip("127.0.0.1".parse().unwrap(), echo.port())]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_and_password_are_sent_when_configured() {
    let echo = echo_service().await;
    let mut b = behaviour(echo);
    b.login = Some(("alice", "s3cret"));
    let addr = upstream(b).await;

    let socks = client(addr, Some(("alice", "s3cret"))).await;
    let (code, mut stream) = connect_domain(socks, "echo.invalid", 1).await.unwrap();
    assert_eq!(code, 0);
    echoes(&mut stream, b"logged in").await;

    // The wrong password must surface as a failed CONNECT, not a hang.
    let socks = client(addr, Some(("alice", "nope"))).await;
    let outcome = tokio::time::timeout(
        Duration::from_secs(15),
        connect_domain(socks, "echo.invalid", 1),
    )
    .await
    .expect("a rejected login left the client hanging");
    // A dropped connection is also a failure; only a success is wrong.
    if let Ok((code, _)) = outcome {
        assert_ne!(code, 0, "wrong password was accepted");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_from_the_upstream_fails_the_connection() {
    let echo = echo_service().await;
    let mut b = behaviour(echo);
    b.refuse_with = Some(0x05);
    let socks = client(upstream(b).await, None).await;
    let outcome = tokio::time::timeout(
        Duration::from_secs(15),
        connect_domain(socks, "echo.invalid", 1),
    )
    .await
    .expect("a refusal left the client hanging");
    if let Ok((code, _)) = outcome {
        assert_ne!(code, 0, "a refused CONNECT was reported as success");
    }
}
