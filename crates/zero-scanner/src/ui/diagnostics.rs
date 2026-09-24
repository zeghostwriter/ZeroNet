use crate::dns::FastResolver;
use crate::meta::lookup_iranian_isp;
use crate::probe::{connect_tcp, connect_tls, probe_download, probe_trace, shared_tls_config};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct DiagnosticReport {
    pub isp_name: String,
    pub client_ip: Option<String>,
    pub ping_ms: f64,
    pub tls_handshake_ms: f64,
    pub download_mbps: f64,
    pub packet_loss_pct: f64,
    pub network_quality: &'static str,
    pub recommended_workers: usize,
    pub recommended_timeout_secs: u64,
    pub recommended_count: usize,
    pub recommended_tries: usize,
}

pub async fn run_diagnostics(resolver: &FastResolver) -> DiagnosticReport {
    // Representative Anycast edges
    let test_targets = [
        Ipv4Addr::new(104, 16, 1, 1),
        Ipv4Addr::new(172, 66, 167, 79),
        Ipv4Addr::new(198, 202, 211, 142),
        Ipv4Addr::new(162, 159, 137, 85),
    ];

    let mut latencies = Vec::new();
    let mut successes = 0usize;
    let mut tls_latencies = Vec::new();
    let mut detected_client_ip = None;

    // Probe all edges concurrently: done one after another, four
    // unreachable targets cost ~20 s before the report could appear.
    let mut probes = tokio::task::JoinSet::new();
    for &ip in &test_targets {
        let tls_config = shared_tls_config();
        probes.spawn(async move {
            let ip_addr = IpAddr::V4(ip);
            let Ok((tcp_stream, lat)) =
                connect_tcp(ip_addr, 443, Duration::from_millis(1500)).await
            else {
                return None;
            };
            let tcp_ms = lat.as_secs_f64() * 1000.0;
            let tls_start = Instant::now();
            let Ok(mut tls_stream) = connect_tls(
                tcp_stream,
                "speed.cloudflare.com",
                tls_config,
                Duration::from_millis(2000),
            )
            .await
            else {
                return Some((tcp_ms, None, None));
            };
            let tls_ms = tls_start.elapsed().as_secs_f64() * 1000.0;
            // Query /cdn-cgi/trace to find real client IP
            let client_ip = probe_trace(
                &mut tls_stream,
                "speed.cloudflare.com",
                Duration::from_secs(2),
            )
            .await
            .ok()
            .and_then(|t| t.client_ip);
            Some((tcp_ms, Some(tls_ms), client_ip))
        });
    }
    while let Some(joined) = probes.join_next().await {
        if let Ok(Some((tcp_ms, tls_ms, client_ip))) = joined {
            latencies.push(tcp_ms);
            successes += 1;
            tls_latencies.extend(tls_ms);
            if detected_client_ip.is_none() {
                detected_client_ip = client_ip;
            }
        }
    }

    let avg_ping = if latencies.is_empty() {
        300.0
    } else {
        latencies.iter().sum::<f64>() / latencies.len() as f64
    };

    let avg_tls = if tls_latencies.is_empty() {
        500.0
    } else {
        tls_latencies.iter().sum::<f64>() / tls_latencies.len() as f64
    };

    let loss_pct = if test_targets.is_empty() {
        100.0
    } else {
        ((test_targets.len() - successes) as f64 / test_targets.len() as f64) * 100.0
    };

    // Bandwidth sample with fallback
    let mut dl_sample = 0.0;
    for &target in &test_targets {
        if let Ok((mut tcp, _)) =
            connect_tcp(IpAddr::V4(target), 80, Duration::from_millis(1200)).await
        {
            let speed = probe_download(
                &mut tcp,
                "speed.cloudflare.com",
                131072,
                Duration::from_secs(3),
            )
            .await;
            if speed > 0.0 {
                dl_sample = speed;
                break;
            }
        }
    }

    // Accurate ISP detection: First check user's actual WAN IP from trace, then DNS fallback
    let mut detected_isp = "Unknown ISP / Cloudflare Edge".to_string();
    if let Some(ref cip) = detected_client_ip {
        if let Ok(parsed_ip) = IpAddr::from_str(cip) {
            if let Some(isp) = lookup_iranian_isp(parsed_ip) {
                detected_isp = isp.to_string();
            }
        }
    }

    if detected_isp.starts_with("Unknown") {
        if let Ok(ips) = resolver.resolve_ips("speed.cloudflare.com").await {
            if let Some(first) = ips.first() {
                if let Some(isp) = lookup_iranian_isp(*first) {
                    detected_isp = isp.to_string();
                }
            }
        }
    }

    // Auto-tune parameters tailored to real network profile
    let is_irancell = detected_isp.to_lowercase().contains("irancell")
        || detected_isp.to_lowercase().contains("cell");
    let is_mci = detected_isp.to_lowercase().contains("mci")
        || detected_isp.to_lowercase().contains("mobile tele");
    let is_shatel = detected_isp.to_lowercase().contains("shatel");
    let is_mcci_or_mtn = is_irancell || is_mci;

    let (quality, workers, timeout, count, tries) =
        if avg_ping < 120.0 && loss_pct == 0.0 && dl_sample > 8.0 && !is_mcci_or_mtn {
            (
                "High-Speed Fiber / Fixed Broadband (Optimal)",
                128,
                2,
                5000,
                2,
            )
        } else if avg_ping < 200.0 && loss_pct < 25.0 && (!is_mcci_or_mtn || is_shatel) {
            ("Balanced / Moderate Connection", 64, 4, 1500, 2)
        } else if is_mcci_or_mtn {
            // Mobile networks in Iran (MCI/Irancell) suffer heavy rate-limiting and connection reset DPI
            (
                "Mobile DPI Network (Irancell/MCI Throttle Guard)",
                32,
                5,
                800,
                3,
            )
        } else {
            ("Restricted / High-Loss Link", 24, 6, 500, 3)
        };

    DiagnosticReport {
        isp_name: detected_isp,
        client_ip: detected_client_ip,
        ping_ms: avg_ping,
        tls_handshake_ms: avg_tls,
        download_mbps: dl_sample.max(0.2),
        packet_loss_pct: loss_pct,
        network_quality: quality,
        recommended_workers: workers,
        recommended_timeout_secs: timeout,
        recommended_count: count,
        recommended_tries: tries,
    }
}
