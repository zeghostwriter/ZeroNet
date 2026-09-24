//! TCP handshake latency probes for the node list.
//!
//! The list used to show `---` for every node because nothing ever measured
//! them. This probes each node's advertised `address:port` with a plain TCP
//! connect and reports the handshake round-trip, which is the latency that
//! actually matters for a proxy endpoint — it includes the path to the server
//! but none of the proxy negotiation, so it is comparable across protocols.
//!
//! Probes run concurrently and report results as they arrive, so the list
//! fills in progressively rather than all at once at the end.

use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedSender;

/// Per-probe timeout. Anything slower than this is not a usable endpoint.
pub const PING_TIMEOUT: Duration = Duration::from_millis(2500);

/// How long the post-connect traffic check may take.
pub const REAL_DELAY_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the traffic check goes: a tiny plain-HTTP endpoint that answers
/// 204, the same probe v2rayN and most Android clients use.
const PROBE_HOST: &str = "cp.cloudflare.com";

/// Send one real request through the local SOCKS port and time it end to
/// end: SOCKS handshake, the proxy's dial to its server, the server's dial
/// to the probe, and the response.
///
/// A connected engine proves only that the local listeners are up. This is
/// what proves a profile actually carries traffic, which is the question the
/// user is asking when a browser set to the system proxy cannot load a page.
pub async fn real_delay(socks_port: u16) -> Result<Duration, String> {
    tokio::time::timeout(REAL_DELAY_TIMEOUT, real_delay_inner(socks_port))
        .await
        .map_err(|_| format!("no answer within {}s", REAL_DELAY_TIMEOUT.as_secs()))?
}

async fn real_delay_inner(socks_port: u16) -> Result<Duration, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let started = Instant::now();
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .map_err(|e| format!("the local proxy port {socks_port} is not answering: {e}"))?;
    let _ = stream.set_nodelay(true);

    // Greeting (no authentication), then CONNECT by name so the probe is
    // resolved at the far end, as a browser's would be.
    let mut request = vec![
        0x05,
        0x01,
        0x00,
        0x05,
        0x01,
        0x00,
        0x03,
        PROBE_HOST.len() as u8,
    ];
    request.extend_from_slice(PROBE_HOST.as_bytes());
    request.extend_from_slice(&80u16.to_be_bytes());
    request.extend_from_slice(
        format!("GET /generate_204 HTTP/1.1\r\nHost: {PROBE_HOST}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    );
    // Everything goes in one write. The local proxy answers the greeting and
    // the CONNECT without waiting on the server, so pipelining is safe and
    // saves two local round trips that would only blur the measurement.
    stream
        .write_all(&request)
        .await
        .map_err(|e| format!("writing to the local proxy: {e}"))?;

    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(|e| format!("the local proxy closed the connection: {e}"))?;
    if greeting != [0x05, 0x00] {
        return Err("the local proxy refused the SOCKS greeting".into());
    }
    let mut reply = [0u8; 4];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|e| format!("the local proxy closed the connection: {e}"))?;
    if reply[1] != 0x00 {
        return Err(format!(
            "the proxy could not open a connection (SOCKS code {})",
            reply[1]
        ));
    }
    let skip = match reply[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|e| e.to_string())?;
            len[0] as usize + 2
        }
        other => return Err(format!("the local proxy sent address type {other}")),
    };
    let mut bound = vec![0u8; skip];
    stream
        .read_exact(&mut bound)
        .await
        .map_err(|e| e.to_string())?;

    let mut head = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    while !head.windows(2).any(|w| w == b"\r\n") {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("the server dropped the connection: {e}"))?;
        if n == 0 {
            return Err("the server closed the connection without answering".into());
        }
        head.extend_from_slice(&chunk[..n]);
        if head.len() > 4096 {
            break;
        }
    }
    let line = String::from_utf8_lossy(&head);
    let status = line.split_whitespace().nth(1).unwrap_or("");
    if status.starts_with('2') || status.starts_with('3') {
        Ok(started.elapsed())
    } else {
        Err(format!("the probe answered with HTTP {status}, not 204"))
    }
}
/// How many probes may be in flight at once.
const MAX_CONCURRENT_PROBES: usize = 16;

/// Result of probing one config row.
#[derive(Debug, Clone, Copy)]
pub struct PingResult {
    pub config_id: i64,
    /// Handshake round-trip, or `None` if the endpoint did not answer.
    pub latency_ms: Option<f64>,
}

/// A node to probe.
#[derive(Debug, Clone)]
pub struct PingTarget {
    pub config_id: i64,
    pub host: String,
    pub port: u16,
}

/// Measure the TCP handshake time to `host:port`.
///
/// Returns `None` on timeout, DNS failure, or refusal — the caller renders
/// those identically (a dash), and distinguishing them would only add noise
/// to a latency column.
///
/// Name resolution happens first and is *not* part of the reading: timing
/// `connect((host, port))` as one step folded a cold DNS lookup — often the
/// slowest part on a censored network, and cached a moment later — into the
/// number shown as the node's latency. Both steps share the one `timeout`.
pub async fn tcp_ping(host: &str, port: u16, timeout: Duration) -> Option<f64> {
    // A placeholder address from a config that was imported without a real
    // endpoint would otherwise spend the whole timeout failing to resolve.
    if host.is_empty() || host == "proxy" || host == "localhost" && port == 0 {
        return None;
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let addr = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => std::net::SocketAddr::new(ip, port),
        Err(_) => {
            let mut resolved =
                tokio::time::timeout_at(deadline, tokio::net::lookup_host((host, port)))
                    .await
                    .ok()?
                    .ok()?;
            resolved.next()?
        }
    };

    let started = Instant::now();
    match tokio::time::timeout_at(deadline, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            let elapsed = started.elapsed();
            // Drop the socket immediately; we only wanted the handshake.
            drop(stream);
            Some(elapsed.as_secs_f64() * 1000.0)
        }
        Ok(Err(_)) | Err(_) => None,
    }
}

/// Probe every target, emitting each result as it lands.
///
/// Concurrency is capped so that a subscription with hundreds of nodes does
/// not open hundreds of sockets at once — which on a censored network is
/// itself a conspicuous traffic pattern, quite apart from the file-descriptor
/// cost.
///
/// Targets sharing an endpoint are probed once and the reading fanned out:
/// feeds commonly list one server many times under different paths or
/// names, and connecting to it once per row multiplied exactly the traffic
/// the cap above exists to limit.
pub async fn ping_all(targets: Vec<PingTarget>, tx: UnboundedSender<PingResult>) {
    use futures::stream::{self, StreamExt};

    let mut groups: Vec<((String, u16), Vec<i64>)> = Vec::new();
    let mut index: std::collections::HashMap<(String, u16), usize> =
        std::collections::HashMap::new();
    for target in targets {
        let key = (target.host.to_ascii_lowercase(), target.port);
        match index.get(&key) {
            Some(&i) => groups[i].1.push(target.config_id),
            None => {
                index.insert(key.clone(), groups.len());
                groups.push((key, vec![target.config_id]));
            }
        }
    }

    stream::iter(groups)
        .for_each_concurrent(MAX_CONCURRENT_PROBES, |((host, port), ids)| {
            let tx = tx.clone();
            async move {
                let latency_ms = tcp_ping(&host, port, PING_TIMEOUT).await;
                for config_id in ids {
                    let _ = tx.send(PingResult {
                        config_id,
                        latency_ms,
                    });
                }
            }
        })
        .await;
}

/// A short bar visualising a latency reading, for the node table's ping cell.
///
/// The scale is fixed rather than relative to the fastest node on the list:
/// a relative scale would make the best of a bad set look excellent.
pub fn latency_bar(latency_ms: Option<f64>, width: usize) -> String {
    let Some(ms) = latency_ms else {
        return " ".repeat(width);
    };
    // 0 ms fills the bar, 400 ms and beyond leaves it empty.
    let ratio = (1.0 - (ms / 400.0)).clamp(0.0, 1.0);
    let filled = ((ratio * width as f64).round() as usize).min(width);
    let mut bar = "▇".repeat(filled);
    bar.push_str(&"·".repeat(width - filled));
    bar
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for the engine's SOCKS port: answers the greeting and the
    /// CONNECT, then plays the far end of the probe with `status`.
    async fn fake_socks(status: &'static str) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(&[5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            s.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .await
                .unwrap();
        });
        port
    }

    #[tokio::test]
    async fn real_delay_measures_a_204_through_the_socks_port() {
        let port = fake_socks("204 No Content").await;
        let delay = real_delay(port).await.expect("a 204 is a working path");
        assert!(delay < REAL_DELAY_TIMEOUT);
    }

    #[tokio::test]
    async fn real_delay_reports_a_broken_path_in_words() {
        let port = fake_socks("502 Bad Gateway").await;
        let error = real_delay(port).await.unwrap_err();
        assert!(error.contains("502"), "{error}");
        // Nothing listening at all.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        assert!(real_delay(port)
            .await
            .unwrap_err()
            .contains("not answering"));
    }

    #[tokio::test]
    async fn ping_measures_a_live_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Accept a couple of connections so the probe completes.
            for _ in 0..2 {
                let _ = listener.accept().await;
            }
        });

        let ms = tcp_ping("127.0.0.1", addr.port(), PING_TIMEOUT).await;
        assert!(ms.is_some(), "loopback listener should answer");
        assert!(ms.unwrap() < 2500.0);
    }

    #[tokio::test]
    async fn ping_returns_none_for_a_closed_port() {
        // Bind and immediately drop, so the port is almost certainly free.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let ms = tcp_ping("127.0.0.1", port, Duration::from_millis(300)).await;
        assert!(ms.is_none());
    }

    #[tokio::test]
    async fn placeholder_hosts_short_circuit() {
        let started = Instant::now();
        assert!(tcp_ping("proxy", 443, PING_TIMEOUT).await.is_none());
        assert!(tcp_ping("", 443, PING_TIMEOUT).await.is_none());
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "placeholder hosts must not wait for the timeout"
        );
    }

    #[tokio::test]
    async fn ping_all_reports_one_result_per_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let targets = vec![
            PingTarget {
                config_id: 1,
                host: "127.0.0.1".into(),
                port,
            },
            PingTarget {
                config_id: 2,
                host: "proxy".into(),
                port: 443,
            },
        ];
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ping_all(targets, tx).await;

        let mut seen = Vec::new();
        while let Ok(r) = rx.try_recv() {
            seen.push(r);
        }
        assert_eq!(seen.len(), 2);
        assert!(seen
            .iter()
            .any(|r| r.config_id == 1 && r.latency_ms.is_some()));
        assert!(seen
            .iter()
            .any(|r| r.config_id == 2 && r.latency_ms.is_none()));
    }

    #[tokio::test]
    async fn rows_sharing_an_endpoint_are_probed_once() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let targets = (1..=5)
            .map(|id| PingTarget {
                config_id: id,
                host: "127.0.0.1".into(),
                port,
            })
            .collect();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ping_all(targets, tx).await;

        let mut ids = Vec::new();
        while let Ok(r) = rx.try_recv() {
            assert!(r.latency_ms.is_some());
            ids.push(r.config_id);
        }
        ids.sort();
        assert_eq!(ids, vec![1, 2, 3, 4, 5], "every row still gets its reading");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn latency_bar_scales_with_the_reading() {
        assert_eq!(latency_bar(Some(0.0), 6), "▇▇▇▇▇▇");
        assert_eq!(latency_bar(Some(500.0), 6), "······");
        assert_eq!(latency_bar(None, 6), "      ");
        // Mid-range readings land in between.
        let mid = latency_bar(Some(200.0), 6);
        assert!(mid.contains('▇') && mid.contains('·'), "got {mid:?}");
    }

    #[test]
    fn latency_bar_always_has_the_requested_width() {
        for ms in [0.0, 50.0, 133.0, 399.0, 400.0, 10_000.0] {
            assert_eq!(latency_bar(Some(ms), 8).chars().count(), 8, "ms={ms}");
        }
    }
}
