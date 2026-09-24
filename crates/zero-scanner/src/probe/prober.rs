use super::is_plain_http_port;
use super::socket::connect_tcp;
use super::speed::probe_download;
use super::stability::check_stability;
use super::tls::{connect_tls, shared_tls_config};
use super::trace::probe_trace;
use super::websocket::probe_websocket_upgrade;
use crate::types::{ProbeConfig, ProbeMode, ProbeResult, ResultFlags};
use rand::Rng;
use rustls::ClientConfig;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const DEFAULT_SNI_POOL: &[&str] = &[
    "speed.cloudflare.com",
    "www.cloudflare.com",
    "cloudflare.com",
    "1.1.1.1.cdn.cloudflare.net",
    "blog.cloudflare.com",
    "cf-ns.com",
    "developers.cloudflare.com",
    "radar.cloudflare.com",
];

pub struct Prober {
    tls_config: Arc<ClientConfig>,
}

impl Default for Prober {
    fn default() -> Self {
        Self::new()
    }
}

/// Which optional per-IP extras still need to run. They measure properties
/// of the IP rather than of one attempt, so once an attempt has produced them
/// the remaining tries skip them instead of paying for another connection
/// (and another multi-megabyte download) each time.
#[derive(Clone, Copy)]
struct Extras {
    ws: bool,
    speed: bool,
}

impl Prober {
    pub fn new() -> Self {
        Self {
            tls_config: shared_tls_config(),
        }
    }

    pub async fn probe(&self, ip: IpAddr, cfg: &ProbeConfig) -> ProbeResult {
        let tries = cfg.tries.max(1);
        let mut latencies_ms = Vec::with_capacity(tries);
        let mut flags = ResultFlags::empty();
        let mut http_status = 0u16;
        let mut colo = None;
        let mut throughput_mbps = 0.0f64;

        for try_idx in 0..tries {
            let extras = Extras {
                ws: (cfg.require_ws || cfg.ws_host.is_some())
                    && !flags.contains(ResultFlags::WS_OK),
                speed: cfg.speed_bytes > 0 && !flags.contains(ResultFlags::SPEED_OK),
            };
            let try_res = self.probe_once(ip, cfg, extras).await;

            latencies_ms.push(try_res.latency_ms.unwrap_or(0.0));

            flags |= try_res.flags;
            if try_res.http_status != 0 {
                http_status = try_res.http_status;
            }
            if try_res.colo.is_some() {
                colo = try_res.colo;
            }
            if try_res.throughput_mbps > 0.0 {
                throughput_mbps = try_res.throughput_mbps;
            }

            // Short-circuit: if the very first attempt cannot even connect,
            // don't waste further tries on an unreachable IP.
            if try_idx == 0 && !try_res.flags.contains(ResultFlags::TCP_OK) {
                latencies_ms.resize(tries, 0.0);
                break;
            }

            // Jitter between tries
            if try_idx + 1 < tries {
                let (min_j, max_j) = cfg.jitter_range_ms;
                let jitter_ms = rand::thread_rng().gen_range(min_j.min(max_j)..=max_j.max(min_j));
                tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
            }
        }

        ProbeResult {
            ip,
            port: cfg.port,
            mode: cfg.mode,
            latencies_ms,
            flags,
            http_status,
            colo,
            throughput_mbps,
            isp: None,
            asn: None,
        }
    }

    /// One probe attempt. The latency it reports depends on the mode:
    /// TCP handshake time for `Tcp`, TLS handshake time for `Tls`, and time
    /// to first byte of the `/cdn-cgi/trace` response for `Http`.
    async fn probe_once(
        &self,
        ip: IpAddr,
        cfg: &ProbeConfig,
        extras: Extras,
    ) -> SingleProbeOutcome {
        let mut outcome = SingleProbeOutcome::default();

        // 1. Budget splitting: 25% TCP connect
        let tcp_timeout =
            (cfg.timeout / 4).clamp(Duration::from_millis(500), Duration::from_secs(2));
        let (mut tcp_stream, tcp_latency) = match connect_tcp(ip, cfg.port, tcp_timeout).await {
            Ok(res) => res,
            Err(_) => return outcome,
        };

        outcome.flags.insert(ResultFlags::TCP_OK);
        outcome.latency_ms = Some(tcp_latency.as_secs_f64() * 1000.0);

        if cfg.mode == ProbeMode::Tcp {
            return outcome;
        }

        // Plain HTTP edge ports (80, 8080, ...) have no TLS layer.
        if is_plain_http_port(cfg.port) {
            let host = cfg.sni.as_deref().unwrap_or("speed.cloudflare.com");
            let http_timeout =
                (cfg.timeout / 2).clamp(Duration::from_millis(1000), Duration::from_secs(3));
            if let Ok(trace) = probe_trace(&mut tcp_stream, host, http_timeout).await {
                outcome.http_status = trace.status;
                outcome.colo = trace.colo;

                if (200..400).contains(&trace.status) {
                    outcome.latency_ms = Some(trace.latency.as_secs_f64() * 1000.0);
                    outcome.flags.insert(ResultFlags::HTTP_OK);
                    outcome.flags.insert(ResultFlags::STABLE_OK);
                }
            }
            return outcome;
        }

        // 2. TLS Handshake with Fallback SNI cascade
        let mut candidate_snis: Vec<&str> = Vec::with_capacity(DEFAULT_SNI_POOL.len() + 1);
        if let Some(ref custom_sni) = cfg.sni {
            candidate_snis.push(custom_sni.as_str());
        }
        for &s in DEFAULT_SNI_POOL {
            if !candidate_snis.contains(&s) {
                candidate_snis.push(s);
            }
        }
        candidate_snis.truncate(3);

        let tls_timeout =
            (cfg.timeout / 2).clamp(Duration::from_millis(1000), Duration::from_secs(3));
        let mut working = None;

        // Try primary SNI first, then fallback SNIs if needed
        for (i, &sni) in candidate_snis.iter().enumerate() {
            let hs_start = Instant::now();
            match connect_tls(tcp_stream, sni, self.tls_config.clone(), tls_timeout).await {
                Ok(s) => {
                    working = Some((s, sni, hs_start.elapsed()));
                    break;
                }
                Err(_) => {
                    if i + 1 == candidate_snis.len() {
                        break;
                    }
                    // The failed handshake consumed the socket; the next SNI
                    // needs a fresh connection.
                    match connect_tcp(ip, cfg.port, tcp_timeout).await {
                        Ok((new_tcp, _)) => tcp_stream = new_tcp,
                        Err(_) => break,
                    }
                }
            }
        }

        let Some((mut tls_stream, working_sni, handshake)) = working else {
            return outcome;
        };
        outcome.flags.insert(ResultFlags::TLS_OK);

        if cfg.mode == ProbeMode::Tls {
            outcome.latency_ms = Some(handshake.as_secs_f64() * 1000.0);
            return outcome;
        }

        // Optional DPI idle-hold: keep the fresh session idle for a moment
        // and see whether it survives. This has to happen before the request:
        // the trace asks for `Connection: close`, so after the response the
        // server's own close would read as an injected reset and every
        // healthy IP would fail the check.
        let stable = !cfg.check_dpi_hold
            || check_stability(&mut tls_stream, Duration::from_millis(350)).await;

        // 3. HTTP Mode: probe /cdn-cgi/trace
        let http_timeout =
            (cfg.timeout / 4).clamp(Duration::from_millis(1000), Duration::from_secs(3));
        if stable {
            if let Ok(trace) = probe_trace(&mut tls_stream, working_sni, http_timeout).await {
                outcome.http_status = trace.status;
                outcome.colo = trace.colo;

                if (200..400).contains(&trace.status) || trace.status == 403 {
                    outcome.latency_ms = Some(trace.latency.as_secs_f64() * 1000.0);
                    outcome.flags.insert(ResultFlags::HTTP_OK);
                    outcome.flags.insert(ResultFlags::STABLE_OK);
                }
            }
        }
        drop(tls_stream);

        // 4. Optional WebSocket Upgrade probe
        if extras.ws {
            let ws_host = cfg.ws_host.as_deref().unwrap_or(working_sni);
            let ws_path = cfg.ws_path.as_deref().unwrap_or("/");

            if let Ok((ws_tcp, _)) = connect_tcp(ip, cfg.port, tcp_timeout).await {
                if let Ok(mut ws_tls) =
                    connect_tls(ws_tcp, working_sni, self.tls_config.clone(), tls_timeout).await
                {
                    if probe_websocket_upgrade(&mut ws_tls, ws_host, ws_path, http_timeout).await {
                        outcome.flags.insert(ResultFlags::WS_OK);
                    }
                }
            }
        }

        // 5. Optional Download speed sample
        if extras.speed && outcome.flags.contains(ResultFlags::HTTP_OK) {
            if let Ok((speed_tcp, _)) = connect_tcp(ip, cfg.port, tcp_timeout).await {
                if let Ok(mut speed_tls) =
                    connect_tls(speed_tcp, working_sni, self.tls_config.clone(), tls_timeout).await
                {
                    let speed = probe_download(
                        &mut speed_tls,
                        working_sni,
                        cfg.speed_bytes,
                        Duration::from_secs(4),
                    )
                    .await;
                    if speed > 0.0 {
                        outcome.throughput_mbps = speed;
                        outcome.flags.insert(ResultFlags::SPEED_OK);
                    }
                }
            }
        }

        outcome
    }
}

#[derive(Default)]
struct SingleProbeOutcome {
    latency_ms: Option<f64>,
    flags: ResultFlags,
    http_status: u16,
    colo: Option<String>,
    throughput_mbps: f64,
}
