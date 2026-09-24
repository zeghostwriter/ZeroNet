//! Small loopback management API.
//!
//! The API is intentionally separate from proxy listeners. It exposes only
//! bounded statistics and an authenticated whole-generation reload endpoint;
//! it never accepts arbitrary outbound destinations or executes config JSON
//! incrementally.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Server;

const MAX_REQUEST: usize = 2 * 1024 * 1024;
/// How long a client may take to deliver its request. Only reading is
/// bounded: handling (a forced asset refresh downloads rule sets) must not be
/// cancelled half-way by a deadline meant for slow senders.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct ManagementConfig {
    pub listen: SocketAddr,
    pub bearer_token: Option<Arc<str>>,
}

impl ManagementConfig {
    pub fn validate(&self) -> Result<(), String> {
        let loopback = self.listen.ip().is_loopback();
        if !loopback && self.bearer_token.as_deref().is_none_or(str::is_empty) {
            return Err("management API requires a bearer token off loopback".into());
        }
        Ok(())
    }
}

pub struct ManagementServer {
    config: ManagementConfig,
}

impl ManagementServer {
    pub fn new(config: ManagementConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self { config })
    }

    pub async fn run(self, server: Arc<Server>) -> std::io::Result<()> {
        let addr = self.config.listen;
        let listener = zero_net::prepare_listener(addr)?;
        let mut backoff_ms = 10u64;
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => {
                    backoff_ms = 10;
                    accepted
                }
                // Descriptor exhaustion and aborted handshakes are transient;
                // returning here would take the management API down for good.
                Err(error) => {
                    tracing::warn!(%error, backoff_ms, "management accept failed");
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(1000);
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);
            let config = self.config.clone();
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                if let Err(error) = handle_connection(stream, peer, config, server).await {
                    tracing::debug!(%peer, %error, "management request failed");
                }
            });
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: ManagementConfig,
    server: Arc<Server>,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + REQUEST_READ_TIMEOUT;
    let mut data = Vec::with_capacity(1024);
    let head_end;
    // Only the bytes that arrived since the last pass (plus three, for a
    // terminator split across reads) need scanning; rescanning the whole
    // buffer per read is quadratic in a trickled request.
    let mut scanned = 0usize;
    loop {
        let from = scanned.saturating_sub(3);
        if let Some(end) = data[from..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            head_end = from + end + 4;
            break;
        }
        scanned = data.len();
        if data.len() >= MAX_REQUEST {
            return write_response(&mut stream, 413, "request too large", b"").await;
        }
        let n = tokio::time::timeout_at(deadline, stream.read_buf(&mut data))
            .await
            .map_err(|_| "request head timed out".to_string())?
            .map_err(|error| format!("reading request: {error}"))?;
        if n == 0 {
            return Ok(());
        }
    }

    let mut headers = [httparse::EMPTY_HEADER; 48];
    let mut request = httparse::Request::new(&mut headers);
    request
        .parse(&data[..head_end])
        .map_err(|error| format!("malformed request: {error}"))?;
    let method = request.method.unwrap_or("").to_string();
    let path = request.path.unwrap_or("").to_string();
    let authorization = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("authorization"))
        .and_then(|header| std::str::from_utf8(header.value).ok())
        .map(str::to_owned);
    let content_length = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
        .and_then(|header| {
            std::str::from_utf8(header.value)
                .ok()
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    if content_length > MAX_REQUEST - head_end {
        return write_response(&mut stream, 413, "request too large", b"").await;
    }
    while data.len() < head_end + content_length {
        let n = tokio::time::timeout_at(deadline, stream.read_buf(&mut data))
            .await
            .map_err(|_| "request body timed out".to_string())?
            .map_err(|error| format!("reading request body: {error}"))?;
        if n == 0 {
            return write_response(&mut stream, 400, "truncated body", b"").await;
        }
    }

    if let Some(expected) = config.bearer_token.as_deref() {
        let actual = authorization
            .as_deref()
            .and_then(|value| value.strip_prefix("Bearer "));
        if actual != Some(expected) {
            return write_response(&mut stream, 401, "unauthorized", b"").await;
        }
    } else if !peer.ip().is_loopback() {
        return write_response(&mut stream, 403, "forbidden", b"").await;
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/stats") => {
            let body = serde_json::to_vec(&server.stats.snapshot())
                .map_err(|error| format!("encoding stats: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", path) if path == "/stats/traffic" || path.starts_with("/stats/traffic?") => {
            // Xray-compatible per-tag counters. `?reset=true` zeroes each
            // counter as it is read, matching Xray's QueryStats reset.
            let reset = path
                .split_once('?')
                .map(|(_, query)| {
                    query
                        .split('&')
                        .any(|pair| matches!(pair, "reset=true" | "reset=1" | "reset"))
                })
                .unwrap_or(false);
            let stat = server
                .stats
                .traffic_counters(reset)
                .into_iter()
                .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
                .collect::<Vec<_>>();
            let body = serde_json::to_vec(&serde_json::json!({ "stat": stat }))
                .map_err(|error| format!("encoding traffic stats: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/health") => {
            let body = serde_json::to_vec(&server.health_snapshot())
                .map_err(|error| format!("encoding health: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/clean-ip") => {
            let body = serde_json::to_vec(&server.clean_ip_snapshot())
                .map_err(|error| format!("encoding clean-ip results: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("GET", "/assets") => {
            let body = serde_json::to_vec(&server.asset_snapshot())
                .map_err(|error| format!("encoding asset status: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("POST", "/assets/refresh") => {
            // Forced because an operator asking for a refresh is doing so
            // precisely when the TTL says nothing needs doing.
            let report = server.refresh_assets_now().await;
            let body = serde_json::to_vec(&report)
                .map_err(|error| format!("encoding refresh report: {error}"))?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        ("POST", "/reload") => {
            let body = &data[head_end..head_end + content_length];
            let value: serde_json::Value = serde_json::from_slice(body)
                .map_err(|error| format!("reload body is not JSON: {error}"))?;
            let next = server.current_generation().0.saturating_add(1);
            let (generation, diagnostics) =
                zero_config::compile_config(&value, zero_core::GenerationId(next))
                    .map_err(|error| format!("reload config rejected: {error}"))?;
            server
                .reload(Arc::clone(&generation.config), generation.id)
                .map_err(|error| format!("reload rejected: {error}"))?;
            let body = serde_json::json!({
                "generation": next,
                "diagnostics": diagnostics.diagnostics.len()
            });
            let body = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
            write_response(&mut stream, 200, "ok", &body).await
        }
        _ => write_response(&mut stream, 404, "not found", b"").await,
    }
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<(), String> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| format!("writing response: {error}"))?;
    stream
        .write_all(body)
        .await
        .map_err(|error| format!("writing response body: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_management_listeners_require_authentication() {
        let config = ManagementConfig {
            listen: "0.0.0.0:8080".parse().unwrap(),
            bearer_token: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn loopback_management_listener_can_be_private() {
        let config = ManagementConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            bearer_token: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn traffic_counters_accumulate_per_tag_and_reset_on_demand() {
        use crate::relay::Transferred;
        use crate::server::Stats;

        let stats = Stats::default();
        stats.record_tag_traffic(
            "socks-in",
            Some("proxy"),
            &Transferred {
                uploaded: 100,
                downloaded: 250,
            },
        );
        stats.record_tag_traffic(
            "socks-in",
            Some("proxy"),
            &Transferred {
                uploaded: 5,
                downloaded: 7,
            },
        );

        let counters = stats.traffic_counters(false);
        let find = |name: &str| {
            counters
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, value)| *value)
        };
        assert_eq!(find("inbound>>>socks-in>>>traffic>>>uplink"), Some(105));
        assert_eq!(find("inbound>>>socks-in>>>traffic>>>downlink"), Some(257));
        assert_eq!(find("outbound>>>proxy>>>traffic>>>uplink"), Some(105));
        assert_eq!(find("outbound>>>proxy>>>traffic>>>downlink"), Some(257));

        // A read with reset returns the accumulated values, then zeroes them.
        let reset = stats.traffic_counters(true);
        assert_eq!(
            reset
                .iter()
                .find(|(n, _)| n == "inbound>>>socks-in>>>traffic>>>uplink")
                .map(|(_, v)| *v),
            Some(105)
        );
        let after = stats.traffic_counters(false);
        assert!(
            after.iter().all(|(_, value)| *value == 0),
            "reset should have zeroed every counter: {after:?}"
        );
    }

    #[test]
    fn a_zero_byte_session_records_no_counter() {
        use crate::relay::Transferred;
        use crate::server::Stats;

        let stats = Stats::default();
        stats.record_tag_traffic(
            "socks-in",
            None,
            &Transferred {
                uploaded: 0,
                downloaded: 0,
            },
        );
        assert!(stats.traffic_counters(false).is_empty());
    }
}
