//! Candidate CDN-edge probing.
//!
//! A TCP connect is not a useful CDN signal: an edge may accept sockets and
//! then blackhole the first application request. This probe sends a bounded
//! HTTP request with the intended Host header and ranks candidates by actual
//! response progress.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout_at;

const MAX_HEAD: usize = 16 * 1024;

/// Probes in flight at once. Unbounded, a large candidate list opened every
/// socket simultaneously: descriptor exhaustion on a phone's 1024-fd limit,
/// a SYN burst that looks like a scan to the network being measured, and
/// timings skewed by the probes congesting each other.
const MAX_CONCURRENT_PROBES: usize = 64;

/// Cloudflare's cleartext ports. Every other CDN port carries TLS, and probing
/// one of those with a plaintext request measures nothing — the edge simply
/// never answers, so a perfectly good address ranks as dead.
pub const CDN_CLEARTEXT_PORTS: [u16; 7] = [80, 8080, 2052, 2082, 2086, 2095, 8880];

/// Cloudflare's HTTPS ports, in the order worth trying: 443 first, then the
/// alternates that often survive when 443 is throttled.
pub const CDN_TLS_PORTS: [u16; 6] = [443, 8443, 2053, 2083, 2087, 2096];

/// Published Cloudflare IPv4 prefixes that carry proxied traffic. Candidates
/// are sampled from these rather than hard-coded, because any single address
/// is as likely to be blocked as any other and a fixed list ages badly.
pub const CLOUDFLARE_PREFIXES: [(Ipv4Addr, u8); 15] = [
    (Ipv4Addr::new(173, 245, 48, 0), 20),
    (Ipv4Addr::new(103, 21, 244, 0), 22),
    (Ipv4Addr::new(103, 22, 200, 0), 22),
    (Ipv4Addr::new(103, 31, 4, 0), 22),
    (Ipv4Addr::new(141, 101, 64, 0), 18),
    (Ipv4Addr::new(108, 162, 192, 0), 18),
    (Ipv4Addr::new(190, 93, 240, 0), 20),
    (Ipv4Addr::new(188, 114, 96, 0), 20),
    (Ipv4Addr::new(197, 234, 240, 0), 22),
    (Ipv4Addr::new(198, 41, 128, 0), 17),
    (Ipv4Addr::new(162, 158, 0, 0), 15),
    (Ipv4Addr::new(104, 16, 0, 0), 13),
    (Ipv4Addr::new(104, 24, 0, 0), 14),
    (Ipv4Addr::new(172, 64, 0, 0), 13),
    (Ipv4Addr::new(131, 0, 72, 0), 22),
];

#[derive(Debug, Clone)]
pub struct CleanIpCandidate {
    pub address: SocketAddr,
    pub host: String,
    /// Whether the probe must complete a TLS handshake first. A CDN edge on
    /// 443 answers nothing at all to a plaintext request.
    pub tls: bool,
}

impl CleanIpCandidate {
    /// Build a candidate, choosing the probe scheme from the port. Explicit
    /// construction remains available for a non-standard deployment.
    pub fn new(address: SocketAddr, host: impl Into<String>) -> Self {
        let tls = !CDN_CLEARTEXT_PORTS.contains(&address.port());
        Self {
            address,
            host: host.into(),
            tls,
        }
    }
}

/// Deterministically sample `per_prefix` addresses from each Cloudflare prefix,
/// paired with each requested port.
///
/// Deterministic because the point is a *bounded, repeatable* candidate set: a
/// client that re-rolls its candidates on every start can never accumulate
/// evidence about any of them, and an unbounded set turns edge measurement into
/// a port scan.
pub fn cloudflare_candidates(
    host: &str,
    ports: &[u16],
    per_prefix: u8,
    seed: u64,
) -> Vec<CleanIpCandidate> {
    let mut candidates = Vec::new();
    for (index, (network, prefix)) in CLOUDFLARE_PREFIXES.iter().enumerate() {
        let host_bits = 32u32.saturating_sub(*prefix as u32);
        if host_bits < 2 {
            continue;
        }
        let size = 1u32 << host_bits;
        let base = u32::from(*network);
        for nth in 0..per_prefix {
            // A cheap, stable mix: the same seed and index always yield the
            // same address, and different prefixes do not collide.
            let mixed = seed
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add((index as u64) << 32)
                .wrapping_add(nth as u64 + 1);
            let offset = 1 + (mixed % u64::from(size.saturating_sub(2)).max(1)) as u32;
            let address = Ipv4Addr::from(base.wrapping_add(offset));
            for port in ports {
                candidates.push(CleanIpCandidate::new(
                    SocketAddr::new(IpAddr::V4(address), *port),
                    host,
                ));
            }
        }
    }
    candidates
}

#[derive(Debug, Clone)]
pub struct CleanIpResult {
    pub address: SocketAddr,
    pub elapsed: Duration,
    pub status: Option<u16>,
    pub response_bytes: usize,
    pub success: bool,
}

impl CleanIpResult {
    fn failed(address: SocketAddr, elapsed: Duration) -> Self {
        Self {
            address,
            elapsed,
            status: None,
            response_bytes: 0,
            success: false,
        }
    }
}

/// Probe candidates concurrently (at most [`MAX_CONCURRENT_PROBES`] at a
/// time), returning fastest useful responses first. `timeout_duration` bounds
/// each probe as a whole — connect, TLS, request and response together. The
/// request never performs DNS resolution; callers provide literal edge
/// addresses and the intended fronted Host name explicitly.
pub async fn probe_http(
    candidates: &[CleanIpCandidate],
    path: &str,
    timeout_duration: Duration,
) -> Vec<CleanIpResult> {
    use futures::stream::{FuturesUnordered, StreamExt};
    // A hand-rolled window rather than `stream::iter(..).buffer_unordered`:
    // the closure-based combinator trips rustc's higher-ranked `Send`
    // inference when this future is spawned (rust-lang/rust#102211).
    let mut pending = FuturesUnordered::new();
    let mut queue = candidates.iter();
    let mut results = Vec::with_capacity(candidates.len());
    loop {
        while pending.len() < MAX_CONCURRENT_PROBES {
            let Some(candidate) = queue.next() else { break };
            pending.push(probe_one(candidate, path, timeout_duration));
        }
        match pending.next().await {
            Some(result) => results.push(result),
            None => break,
        }
    }
    results.sort_by(|a, b| {
        b.success
            .cmp(&a.success)
            .then_with(|| b.response_bytes.cmp(&a.response_bytes))
            .then_with(|| a.elapsed.cmp(&b.elapsed))
    });
    results
}

async fn probe_one(
    candidate: &CleanIpCandidate,
    path: &str,
    timeout_duration: Duration,
) -> CleanIpResult {
    let started = Instant::now();
    // One deadline for the whole probe. Per-step timeouts let a slow edge
    // take four times the budget and still be measured as a success.
    let deadline = tokio::time::Instant::now() + timeout_duration;
    let stream = match timeout_at(
        deadline,
        zero_core::platform::connect_protected(candidate.address),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => return CleanIpResult::failed(candidate.address, started.elapsed()),
    };
    let _ = stream.set_nodelay(true);
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: zray-clean-ip-probe/1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        if path.is_empty() { "/" } else { path },
        candidate.host
    );

    let response = if candidate.tls {
        let connector = tokio_rustls::TlsConnector::from(probe_tls_config());
        let Ok(server_name) = rustls_pki_types::ServerName::try_from(candidate.host.clone()) else {
            return CleanIpResult::failed(candidate.address, started.elapsed());
        };
        // The handshake itself is the measurement that matters for a fronted
        // path: an edge that completes TLS for this SNI is reachable for the
        // traffic that will actually be sent through it.
        let Ok(Ok(stream)) = timeout_at(deadline, connector.connect(server_name, stream)).await
        else {
            return CleanIpResult::failed(candidate.address, started.elapsed());
        };
        exchange(stream, request.as_bytes(), deadline).await
    } else {
        exchange(stream, request.as_bytes(), deadline).await
    };

    let Some(response) = response else {
        return CleanIpResult::failed(candidate.address, started.elapsed());
    };
    let status = response
        .split(|byte| *byte == b' ')
        .nth(1)
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse::<u16>().ok());
    CleanIpResult {
        address: candidate.address,
        elapsed: started.elapsed(),
        status,
        response_bytes: response.len(),
        success: status.is_some_and(|code| (200..500).contains(&code)) && !response.is_empty(),
    }
}

async fn exchange<S>(
    mut stream: S,
    request: &[u8],
    deadline: tokio::time::Instant,
) -> Option<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    timeout_at(deadline, async {
        stream.write_all(request).await?;
        stream.flush().await
    })
    .await
    .ok()?
    .ok()?;
    let mut response = vec![0u8; MAX_HEAD];
    let count = timeout_at(deadline, stream.read(&mut response))
        .await
        .ok()?
        .ok()?;
    response.truncate(count);
    Some(response)
}

/// A probe-only TLS client. Certificate verification stays on: an edge that
/// cannot present a valid certificate for the fronted name is not an edge this
/// client could use, so accepting one would rank an unusable address highly.
fn probe_tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn ranks_application_progress_above_socket_only_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 512];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let results = probe_http(
            &[
                CleanIpCandidate {
                    address: "127.0.0.1:1".parse().unwrap(),
                    host: "edge.example".into(),
                    tls: false,
                },
                CleanIpCandidate {
                    address: live,
                    host: "edge.example".into(),
                    tls: false,
                },
            ],
            "/health",
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(results.first().unwrap().address, live);
        assert!(results.first().unwrap().success);
        task.await.unwrap();
    }

    #[test]
    fn the_probe_scheme_follows_the_cdn_port_convention() {
        // 443 and the alternate HTTPS ports must not be probed in cleartext:
        // the edge would never answer and a good address would rank as dead.
        for port in CDN_TLS_PORTS {
            let candidate = CleanIpCandidate::new(
                format!("104.16.0.1:{port}").parse().unwrap(),
                "edge.example",
            );
            assert!(candidate.tls, "port {port} should use TLS");
        }
        for port in CDN_CLEARTEXT_PORTS {
            let candidate = CleanIpCandidate::new(
                format!("104.16.0.1:{port}").parse().unwrap(),
                "edge.example",
            );
            assert!(!candidate.tls, "port {port} should be cleartext");
        }
    }

    #[test]
    fn generated_candidates_are_inside_the_published_prefixes_and_bounded() {
        let candidates = cloudflare_candidates("edge.example", &[443, 2053], 2, 7);
        assert_eq!(candidates.len(), CLOUDFLARE_PREFIXES.len() * 2 * 2);
        for candidate in &candidates {
            let IpAddr::V4(ip) = candidate.address.ip() else {
                panic!("expected IPv4");
            };
            let value = u32::from(ip);
            let inside = CLOUDFLARE_PREFIXES.iter().any(|(network, prefix)| {
                let mask = u32::MAX.checked_shl(32 - u32::from(*prefix)).unwrap_or(0);
                value & mask == u32::from(*network) & mask
            });
            assert!(inside, "{ip} is outside every published prefix");
            // Never the network or broadcast address of its block.
            assert_ne!(ip.octets()[3] | ip.octets()[2] | ip.octets()[1], 0);
        }
    }

    /// Opt-in: reaches real Cloudflare edges. Run with
    /// `cargo test -p zero-net -- --ignored live_cloudflare`.
    #[tokio::test]
    #[ignore = "requires outbound network access to Cloudflare"]
    async fn live_cloudflare_edges_rank_by_measured_tls_progress() {
        let candidates = cloudflare_candidates("www.cloudflare.com", &[443], 1, 11);
        let results = probe_http(&candidates, "/cdn-cgi/trace", Duration::from_secs(8)).await;
        let reachable = results.iter().filter(|result| result.success).count();
        for result in results.iter().take(5) {
            println!(
                "{} success={} status={:?} bytes={} elapsed={:?}",
                result.address,
                result.success,
                result.status,
                result.response_bytes,
                result.elapsed
            );
        }
        assert!(
            reachable > 0,
            "no Cloudflare edge completed TLS and answered; the probe would rank every edge dead"
        );
    }

    #[test]
    fn candidate_generation_is_repeatable_so_evidence_can_accumulate() {
        let first = cloudflare_candidates("edge.example", &[443], 3, 42);
        let second = cloudflare_candidates("edge.example", &[443], 3, 42);
        let different_seed = cloudflare_candidates("edge.example", &[443], 3, 43);
        let addresses =
            |set: &[CleanIpCandidate]| set.iter().map(|c| c.address).collect::<Vec<_>>();
        assert_eq!(addresses(&first), addresses(&second));
        assert_ne!(addresses(&first), addresses(&different_seed));
    }
}
