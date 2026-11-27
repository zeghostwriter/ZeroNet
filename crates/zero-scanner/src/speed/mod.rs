use crate::probe::{
    connect_tcp, connect_tls, is_plain_http_port, probe_download_detailed, shared_tls_config,
    MAX_DOWNLOAD_SAMPLE_BYTES,
};
use crate::types::ProbeResult;
use rustls::ClientConfig;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

#[derive(Debug, Clone)]
pub struct SpeedTestResult {
    pub ip: IpAddr,
    pub port: u16,
    pub ttfb_ms: f64,
    pub download_mbps: f64,
    pub colo: Option<String>,
}

#[derive(Clone)]
pub struct SpeedTester {
    sni: String,
    sample_bytes: usize,
    timeout: Duration,
    tls_config: Arc<ClientConfig>,
}

impl SpeedTester {
    pub fn new(sni: Option<String>, sample_bytes: usize, timeout: Duration) -> Self {
        Self {
            sni: sni.unwrap_or_else(|| "speed.cloudflare.com".to_string()),
            sample_bytes: if sample_bytes == 0 {
                256 * 1024
            } else {
                sample_bytes.min(MAX_DOWNLOAD_SAMPLE_BYTES)
            },
            timeout,
            tls_config: shared_tls_config(),
        }
    }

    /// Measures download throughput and time-to-first-byte against one
    /// endpoint. The TCP and TLS handshakes happen before the clock starts.
    pub async fn test_endpoint(&self, ip: IpAddr, port: u16) -> Option<SpeedTestResult> {
        let dial_timeout = Duration::from_secs(3);

        let (tcp_stream, _) = connect_tcp(ip, port, dial_timeout).await.ok()?;
        let sample = if is_plain_http_port(port) {
            let mut tcp_stream = tcp_stream;
            probe_download_detailed(&mut tcp_stream, &self.sni, self.sample_bytes, self.timeout)
                .await?
        } else {
            let mut tls_stream = connect_tls(
                tcp_stream,
                &self.sni,
                self.tls_config.clone(),
                Duration::from_secs(4),
            )
            .await
            .ok()?;
            probe_download_detailed(&mut tls_stream, &self.sni, self.sample_bytes, self.timeout)
                .await?
        };

        Some(SpeedTestResult {
            ip,
            port,
            ttfb_ms: sample.ttfb.as_secs_f64() * 1000.0,
            download_mbps: sample.mbps,
            colo: None,
        })
    }

    pub async fn test_shortlist(
        &self,
        endpoints: &[ProbeResult],
        concurrency: usize,
    ) -> Vec<SpeedTestResult> {
        let sem = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
        let mut tasks = JoinSet::new();

        for ep in endpoints {
            let ip = ep.ip;
            let port = ep.port;
            let colo = ep.colo.clone();
            let Ok(permit) = sem.clone().acquire_owned().await else {
                break;
            };
            let tester = self.clone();

            tasks.spawn(async move {
                let _permit = permit;
                let mut res = tester.test_endpoint(ip, port).await;
                if let Some(ref mut r) = res {
                    r.colo = colo;
                }
                res
            });
        }

        let mut out = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            if let Ok(Some(res)) = joined {
                out.push(res);
            }
        }

        // Rank by download speed descending
        out.sort_by(|a, b| b.download_mbps.total_cmp(&a.download_mbps));
        out
    }
}
