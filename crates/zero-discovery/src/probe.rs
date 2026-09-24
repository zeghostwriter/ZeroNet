//! The two liveness tests: a cheap TCP connect and a real request through the
//! proxy.
//!
//! **TCP** answers "is anything listening at the server's address". It is
//! nearly free and eliminates the majority of a public feed — dead servers,
//! blocked addresses — in one round trip each. It proves nothing about the
//! protocol: a filtered server often still completes the handshake.
//!
//! **Real** builds the outbound exactly as the runtime would
//! (`zero_runtime::outbound::connect`), opens a proxied stream to the probe
//! URL's host and sends a plain `GET`. Only an HTTP status line coming back
//! through the tunnel counts: that is the same evidence the user's browser
//! needs. The delay is measured from the start of the connect to the status
//! line, so it includes the proxy handshake — the latency a user actually
//! feels on a new connection.
//!
//! Both open their sockets through the host's socket protector, so inside a
//! running VPN they measure the physical network rather than the tunnel.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zero_core::{Address, Destination};

/// Default probe: plain HTTP, answered with an empty 204 by a CDN edge close
/// to every exit.
pub const DEFAULT_PROBE_URL: &str = "http://cp.cloudflare.com/generate_204";

/// A parsed probe URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    pub destination: Destination,
    pub host_header: String,
    pub path: String,
}

impl ProbeTarget {
    /// Parse an `http://` URL. HTTPS is refused: a TLS layer inside the
    /// tunnel would double the handshake cost of every test and prove nothing
    /// more about the proxy.
    pub fn parse(url: &str) -> Result<Self, String> {
        let parsed = url::Url::parse(url.trim()).map_err(|error| format!("probe_url: {error}"))?;
        if parsed.scheme() != "http" {
            return Err("probe_url must be a plain http:// URL".into());
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| "probe_url has no host".to_string())?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = parsed.port().unwrap_or(80);
        let mut path = parsed.path().to_string();
        if path.is_empty() {
            path.push('/');
        }
        if let Some(query) = parsed.query() {
            path.push('?');
            path.push_str(query);
        }
        let host_header = match parsed.port() {
            Some(port) => format!("{}:{port}", parsed.host_str().unwrap_or(&host)),
            None => parsed.host_str().unwrap_or(&host).to_string(),
        };
        Ok(Self {
            destination: Destination::tcp(Address::parse_host(&host), port),
            host_header,
            path,
        })
    }
}

/// Resolve `host:port`, preferring IPv4 (mobile networks in the target region
/// rarely carry IPv6 end to end).
pub async fn resolve(host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let resolved = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| "dns: timed out".to_string())?
        .map_err(|error| format!("dns: {error}"))?;
    let mut addresses: Vec<SocketAddr> = resolved.collect();
    addresses.sort_by_key(|address| address.is_ipv6());
    addresses.dedup();
    if addresses.is_empty() {
        return Err("dns: no addresses".into());
    }
    Ok(addresses)
}

/// Time a TCP handshake to `host:port`. Name resolution is excluded from the
/// measurement but included in the timeout.
pub async fn tcp_ping(host: &str, port: u16, timeout: Duration) -> Result<Duration, String> {
    let deadline = Instant::now() + timeout;
    let addresses = resolve(host, port, timeout).await?;
    let mut last_error = String::from("no address answered");
    // At most two addresses: a feed server with a dozen A records is not
    // worth a dozen connects in a sweep of thousands.
    for address in addresses.into_iter().take(2) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("tcp: timed out".into());
        }
        let started = Instant::now();
        match tokio::time::timeout(remaining, zero_core::platform::connect_protected(address)).await
        {
            Ok(Ok(_stream)) => return Ok(started.elapsed()),
            Ok(Err(error)) => last_error = format!("tcp: {error}"),
            Err(_) => return Err("tcp: timed out".into()),
        }
    }
    Err(last_error)
}

/// One request through `outbound` to `target`, timed to the status line.
pub async fn real_delay(
    outbound: &zero_config::Outbound,
    target: &ProbeTarget,
    timeout: Duration,
) -> Result<Duration, String> {
    let started = Instant::now();
    let attempt = async {
        let mut stream = zero_runtime::outbound::connect(outbound, &target.destination)
            .await
            .map_err(|failure| format!("connect: {failure}"))?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            target.path, target.host_header
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| format!("write: {error}"))?;
        stream
            .flush()
            .await
            .map_err(|error| format!("write: {error}"))?;
        read_status(&mut stream).await?;
        let elapsed = started.elapsed();
        Ok(elapsed)
    };
    tokio::time::timeout(timeout, attempt)
        .await
        .map_err(|_| "timed out".to_string())?
}

/// Host of the TLS confirmation request.
pub const TLS_CONFIRM_HOST: &str = "www.gstatic.com";

/// A verified HTTPS request through `outbound` to
/// `https://www.gstatic.com/generate_204`, timed to the status line.
///
/// Why this exists: measured from inside Iran (2026-09-24), configs that
/// answered the plain-HTTP probe in discovery then failed every real request,
/// TLS handshakes included. A plain `GET` to a well-known host can be
/// answered by something other than the internet — a captive or broken
/// server, a CDN worker, a middlebox. A full TLS handshake with certificate
/// verification against the real host cannot be faked that way, and it is
/// what the user's browser needs anyway.
pub async fn tls_confirm(outbound: &zero_config::Outbound, timeout: Duration) -> Result<Duration, String> {
    let started = Instant::now();
    let attempt = async {
        let destination = Destination::tcp(Address::parse_host(TLS_CONFIRM_HOST), 443);
        let stream = zero_runtime::outbound::connect(outbound, &destination)
            .await
            .map_err(|failure| format!("connect: {failure}"))?;
        let server_name = rustls_pki_types::ServerName::try_from(TLS_CONFIRM_HOST.to_string())
            .map_err(|error| format!("tls: {error}"))?;
        let mut tls = tokio_rustls::TlsConnector::from(tls_config())
            .connect(server_name, stream)
            .await
            .map_err(|error| format!("tls: {error}"))?;
        let request = format!(
            "GET /generate_204 HTTP/1.1\r\nHost: {TLS_CONFIRM_HOST}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(request.as_bytes())
            .await
            .map_err(|error| format!("write: {error}"))?;
        tls.flush().await.map_err(|error| format!("write: {error}"))?;
        read_status(&mut tls).await?;
        Ok(started.elapsed())
    };
    tokio::time::timeout(timeout, attempt)
        .await
        .map_err(|_| "timed out".to_string())?
}

fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<std::sync::Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    std::sync::Arc::clone(CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        std::sync::Arc::new(
            rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }))
}

/// Read up to the end of an HTTP status line and accept 2xx/3xx.
async fn read_status<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<u16, String> {
    let mut head = Vec::with_capacity(64);
    let mut chunk = [0u8; 256];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("read: {error}"))?;
        if read == 0 {
            return Err(if head.is_empty() {
                "read: closed without a response".to_string()
            } else {
                "read: closed inside the status line".to_string()
            });
        }
        head.extend_from_slice(&chunk[..read]);
        if head.contains(&b'\n') || head.len() >= 512 {
            break;
        }
    }
    let line = String::from_utf8_lossy(&head);
    let line = line.lines().next().unwrap_or_default();
    let mut parts = line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .filter(|_| version.starts_with("HTTP/"))
        .ok_or_else(|| "http: malformed status line".to_string())?;
    if !(200..=399).contains(&status) {
        return Err(format!("http: status {status}"));
    }
    Ok(status)
}

/// The real test: a plain-HTTP request as a cheap filter, then a verified
/// HTTPS confirmation. Only a config that passes both is alive. The reported
/// delay is the plain request's, so it stays comparable across protocols and
/// excludes the extra TLS handshake the confirmation adds.
pub async fn real_test(
    outbound: &zero_config::Outbound,
    target: &ProbeTarget,
    timeout: Duration,
    confirm: Option<Duration>,
) -> Result<u64, String> {
    let first = real_delay(outbound, target, timeout).await?;
    if let Some(confirm_timeout) = confirm {
        tls_confirm(outbound, confirm_timeout)
            .await
            .map_err(|error| format!("tls confirm: {error}"))?;
    }
    Ok(first.as_millis().clamp(1, u128::from(u32::MAX)) as u64)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn probe_urls_are_parsed_and_https_is_refused() {
        let target = ProbeTarget::parse(DEFAULT_PROBE_URL).unwrap();
        assert_eq!(target.destination.port, 80);
        assert_eq!(target.host_header, "cp.cloudflare.com");
        assert_eq!(target.path, "/generate_204");

        let target = ProbeTarget::parse("http://127.0.0.1:8080/x?y=1").unwrap();
        assert_eq!(target.destination.port, 8080);
        assert_eq!(target.host_header, "127.0.0.1:8080");
        assert_eq!(target.path, "/x?y=1");

        assert!(ProbeTarget::parse("https://www.gstatic.com/generate_204").is_err());
        assert!(ProbeTarget::parse("not a url").is_err());
    }

    #[tokio::test]
    async fn tcp_ping_measures_an_open_port_and_reports_a_closed_one() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        let delay = tcp_ping("127.0.0.1", port, Duration::from_secs(2))
            .await
            .unwrap();
        assert!(delay < Duration::from_secs(2));

        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let error = tcp_ping("127.0.0.1", closed, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(error.starts_with("tcp:"), "{error}");

        // Hostnames are resolved.
        assert!(tcp_ping("localhost", port, Duration::from_secs(2))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn tcp_ping_times_out_on_a_blackhole() {
        // TEST-NET-1 is not routed; the connect either hangs until the
        // timeout or fails fast with "unreachable" — both are failures.
        let started = Instant::now();
        let result = tcp_ping("192.0.2.1", 443, Duration::from_millis(300)).await;
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
