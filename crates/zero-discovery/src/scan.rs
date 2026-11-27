//! The `scan` job: find Cloudflare edge addresses that answer on this network.
//!
//! CDN-fronted configs (TLS over WebSocket, gRPC, HTTPUpgrade, XHTTP) work
//! through *any* Cloudflare edge, but filtering blocks edges unevenly, so the
//! address that matters is one that still completes a TLS handshake from
//! here. This drives `zero_scanner::ScanEngine` over the scanner's built-in
//! Cloudflare ranges in TLS mode (TCP connect plus a handshake carrying the
//! requested SNI) and reports each responsive `ip:port` with its round trip.
//!
//! One engine runs per requested port, sharing a single address source, so
//! the ports are probed over *different* addresses and the scan covers more
//! of the range for the same budget. Neighbours of a healthy address are
//! probed next: clean edges cluster.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use zero_scanner::{AtomicStats, IpSource, ProbeConfig, ProbeMode, ScanEngine, ScanEngineConfig};

use crate::discover::EndReason;
use crate::events::EventSink;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScanRequest {
    pub preset: String,
    pub ports: Vec<u16>,
    pub host: String,
    pub count: usize,
    pub concurrency: usize,
    pub timeout_ms: u64,
}

impl Default for ScanRequest {
    fn default() -> Self {
        Self {
            preset: "cloudflare".into(),
            ports: vec![443, 2053, 8443],
            host: "www.speedtest.net".into(),
            count: 2000,
            concurrency: 128,
            timeout_ms: 1500,
        }
    }
}

/// Run the job; the final `done` event is emitted before this returns.
pub async fn scan(request: ScanRequest, sink: EventSink, cancel: CancellationToken) -> EndReason {
    let started = Instant::now();
    if !request.preset.eq_ignore_ascii_case("cloudflare") {
        sink.emit(json!({
            "t": "error",
            "message": format!("unknown scan preset {:?}; only \"cloudflare\" is available", request.preset),
        }));
        sink.emit(json!({"t": "done", "scanned": 0, "responsive": 0, "reason": "exhausted", "elapsed_ms": 0}));
        return EndReason::Exhausted;
    }
    let mut ports = request.ports.clone();
    ports.retain(|port| *port != 0);
    ports.dedup();
    if ports.is_empty() {
        ports.push(443);
    }
    let total = request.count.clamp(1, 1_000_000);
    let concurrency = request.concurrency.clamp(1, 512);
    let per_port_count = total.div_ceil(ports.len());
    let per_port_concurrency = (concurrency / ports.len()).max(1);
    let timeout = Duration::from_millis(request.timeout_ms.clamp(200, 30_000));

    let source = Arc::new(IpSource::new(true, false, &[], true));
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut engines = Vec::with_capacity(ports.len());
    for port in &ports {
        let config = ScanEngineConfig {
            concurrency: per_port_concurrency,
            target_count: per_port_count,
            probe_config: ProbeConfig {
                port: *port,
                mode: ProbeMode::Tls,
                tries: 2,
                timeout,
                sni: Some(request.host.clone()),
                speed_bytes: 0,
                ws_host: None,
                ws_path: None,
                require_ws: false,
                check_dpi_hold: false,
                jitter_range_ms: (10, 40),
            },
            neighbor_scan: true,
            proxy_config: None,
        };
        engines.push(Arc::new(ScanEngine::new_with_state(
            config,
            Arc::clone(&source),
            Arc::new(AtomicStats::new()),
            Arc::clone(&cancelled),
        )));
    }
    let stats: Vec<Arc<AtomicStats>> = engines.iter().map(|engine| engine.stats()).collect();
    let snapshot = move || {
        stats
            .iter()
            .fold((0u64, 0u64), |(scanned, responsive), stats| {
                let (tested, healthy, ..) = stats.snapshot();
                (scanned + tested, responsive + healthy)
            })
    };

    let runs = engines.iter().map(|engine| {
        let engine = Arc::clone(engine);
        let sink = sink.clone();
        async move {
            engine
                .run(move |result| {
                    let rtt = result.min_latency_ms();
                    sink.emit(json!({
                        "t": "ip",
                        "ip": result.ip.to_string(),
                        "port": result.port,
                        "rtt_ms": rtt.round().max(1.0) as u64,
                    }));
                })
                .await
        }
    });
    let all = futures::future::join_all(runs);
    tokio::pin!(all);

    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last = (u64::MAX, u64::MAX);
    let reason = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                // The engines poll this flag between probes and abort the
                // ones in flight; waiting for them keeps "done" last.
                cancelled.store(true, Ordering::SeqCst);
                let _ = tokio::time::timeout(Duration::from_secs(2), &mut all).await;
                break EndReason::Cancelled;
            }
            _ = &mut all => break EndReason::Exhausted,
            _ = ticker.tick() => {
                let now = snapshot();
                if now != last {
                    sink.emit(json!({"t": "progress", "scanned": now.0, "responsive": now.1, "total": total}));
                    last = now;
                }
            }
        }
    };
    let (scanned, responsive) = snapshot();
    sink.emit(
        json!({"t": "progress", "scanned": scanned, "responsive": responsive, "total": total}),
    );
    sink.emit(json!({
        "t": "done",
        "scanned": scanned,
        "responsive": responsive,
        "reason": reason.as_str(),
        "elapsed_ms": started.elapsed().as_millis() as u64,
    }));
    reason
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{batching_sink_with_interval, Collected};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unknown_preset_is_an_error_event_then_done() {
        let collected = Collected::default();
        let (sink, flusher) =
            batching_sink_with_interval(collected.callback(), Duration::from_millis(10));
        let reason = scan(
            ScanRequest {
                preset: "akamai".into(),
                ..ScanRequest::default()
            },
            sink,
            CancellationToken::new(),
        )
        .await;
        flusher.await.unwrap();
        assert_eq!(reason, EndReason::Exhausted);
        assert_eq!(collected.of("error").len(), 1);
        assert_eq!(collected.of("done").len(), 1);
    }

    /// Runs against the real Cloudflare ranges, so it needs network access;
    /// what it checks offline is that cancel ends the scan promptly and the
    /// event sequence is well formed either way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_ends_a_scan_promptly_with_progress_and_done() {
        let collected = Collected::default();
        let (sink, flusher) =
            batching_sink_with_interval(collected.callback(), Duration::from_millis(10));
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1200)).await;
            trigger.cancel();
        });
        let started = Instant::now();
        let reason = scan(
            ScanRequest {
                count: 100_000,
                concurrency: 16,
                timeout_ms: 800,
                ..ScanRequest::default()
            },
            sink,
            cancel,
        )
        .await;
        flusher.await.unwrap();
        assert_eq!(reason, EndReason::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(5));
        let done = collected.of("done");
        assert_eq!(done.len(), 1);
        assert_eq!(done[0]["reason"], "cancelled");
        assert!(!collected.of("progress").is_empty());
        for ip in collected.of("ip") {
            assert!(ip["ip"]
                .as_str()
                .unwrap()
                .parse::<std::net::IpAddr>()
                .is_ok());
            assert!([443, 2053, 8443].contains(&ip["port"].as_u64().unwrap()));
        }
    }
}
