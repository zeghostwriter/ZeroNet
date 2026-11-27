//! TCP Fast Open end to end, on a private network.
//!
//! Fast Open needs a server that does it, and a kernel setting that is off on
//! most machines and needs root to change. A user and network namespace gives
//! this test both without privilege: the test runs itself again under
//! `unshare -rn`, where loopback is its own, turns the setting on there, and
//! checks two things the unit tests cannot:
//!
//! * the first connection to a server is a throwaway that fetches the cookie
//!   and the dial that follows is deferred (the SYN is held for the hello);
//! * the hello then arrives *in the SYN*: the server's `TCPFastOpenPassive`
//!   counter moves, and it reads the bytes.
//!
//! Where `unshare` or user namespaces are not available the test says so and
//! passes, so a plain `cargo test` cannot fail on a locked-down machine.

#![cfg(target_os = "linux")]

use std::os::fd::AsRawFd;
use std::process::Command;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zero_net::{dial_tcp, fastopen, RacePolicy, SocketOptions};

const INSIDE: &str = "ZRAY_FASTOPEN_NETNS";

fn netstat(field: &str) -> u64 {
    let text = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
    let mut lines = text.lines();
    while let Some(names) = lines.next() {
        let Some(values) = lines.next() else { break };
        if !names.starts_with("TcpExt:") {
            continue;
        }
        let index = names.split_whitespace().position(|name| name == field);
        return index
            .and_then(|i| values.split_whitespace().nth(i))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
    }
    0
}

#[test]
fn the_hello_rides_in_the_syn_once_the_cookie_is_held() {
    if std::env::var_os(INSIDE).is_none() {
        let exe = std::env::current_exe().unwrap();
        let setup = "ip link set lo up && sysctl -qw net.ipv4.tcp_fastopen=3";
        // Some hosts refuse unprivileged user namespaces (or lack `ip` or
        // `sysctl`): the setup is tried on its own first, and a failure there
        // is a skip, not a failed test.
        let usable = Command::new("unshare")
            .args(["-rn", "sh", "-c", setup])
            .status()
            .is_ok_and(|status| status.success());
        if !usable {
            eprintln!("skipped: no private network namespace here");
            return;
        }
        let script = format!(
            "{setup} && exec {} --exact \
             the_hello_rides_in_the_syn_once_the_cookie_is_held --nocapture",
            exe.display()
        );
        match Command::new("unshare")
            .args(["-rn", "sh", "-c", &script])
            .env(INSIDE, "1")
            .status()
        {
            Ok(status) => assert!(status.success(), "the test failed inside the namespace"),
            Err(error) => eprintln!("skipped: cannot run unshare ({error})"),
        }
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(inside());
}

async fn inside() {
    if !fastopen::supported() {
        eprintln!("skipped: this kernel has no client Fast Open");
        return;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let queue: libc::c_int = 16;
    // SAFETY: a live listening socket and an int option that outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            listener.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            std::ptr::from_ref(&queue).cast(),
            std::mem::size_of_val(&queue) as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "the server could not turn Fast Open on");
    let server = tokio::spawn(async move {
        let mut heard = Vec::new();
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 32];
            let n = socket.read(&mut buf).await.unwrap();
            heard.push(buf[..n].to_vec());
        }
        heard
    });

    let opts = SocketOptions {
        fast_open_if: Some(|_| true),
        ..Default::default()
    };
    let passive = netstat("TCPFastOpenPassive");
    let dialed = dial_tcp(&[addr], &RacePolicy::default(), &opts)
        .await
        .unwrap();
    assert!(
        fastopen::deferred(&dialed.stream),
        "the dial after the cookie fetch should be held for the hello"
    );
    assert!(dialed.stream.peer_addr().is_err());
    assert_eq!(fastopen::peer_addr(&dialed.stream), Some(addr));
    let mut stream = dialed.stream;
    stream.write_all(b"hello in the syn").await.unwrap();
    stream.flush().await.unwrap();
    // The cookie fetch sent nothing, the held connection sent the hello.
    let heard = server.await.unwrap();
    assert_eq!(heard[0], b"");
    assert_eq!(heard[1], b"hello in the syn");
    assert_eq!(
        netstat("TCPFastOpenPassive"),
        passive + 1,
        "the server did not take the hello from the SYN"
    );
}
