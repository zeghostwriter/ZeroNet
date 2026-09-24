//! The `testLinks` job: measure a given list of links, one result each.
//!
//! This is the "ping all" button. Unlike discovery it never stops early and
//! never skips a link; every link produces exactly one `result` event, a
//! failure included, so the app can update each row. With `tcp_only` it
//! measures the TCP handshake to the server instead of a request through it —
//! cheaper, and the right thing to show while the VPN is connected and a real
//! test through every server would cost the user data.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::discover::EndReason;
use crate::events::EventSink;
use crate::link::{link_key, parse_candidate};
use crate::probe::{real_test, tcp_ping, ProbeTarget, DEFAULT_PROBE_URL};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TestRequest {
    pub links: Vec<String>,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub probe_url: String,
    pub tcp_only: bool,
    /// See `DiscoverRequest::confirm_tls`.
    pub confirm_tls: bool,
    /// See `DiscoverRequest::confirm_timeout_ms`.
    pub confirm_timeout_ms: u64,
}

impl Default for TestRequest {
    fn default() -> Self {
        Self {
            links: Vec::new(),
            concurrency: 16,
            timeout_ms: 4000,
            probe_url: DEFAULT_PROBE_URL.into(),
            tcp_only: false,
            confirm_tls: true,
            confirm_timeout_ms: 6000,
        }
    }
}

fn failure(key: &str, error: &str) -> serde_json::Value {
    json!({"t": "result", "key": key, "delay_ms": -1, "error": error})
}

/// Run the job; the final `done` event is emitted before this returns.
pub async fn test_links(
    request: TestRequest,
    sink: EventSink,
    cancel: CancellationToken,
) -> EndReason {
    let started = Instant::now();
    let concurrency = request.concurrency.clamp(1, 128);
    let timeout = Duration::from_millis(request.timeout_ms.clamp(200, 60_000));
    let alive = Arc::new(AtomicUsize::new(0));
    let tested = Arc::new(AtomicUsize::new(0));
    let request_confirm = request
        .confirm_tls
        .then(|| Duration::from_millis(request.confirm_timeout_ms.clamp(200, 60_000)));

    let target = if request.tcp_only {
        None
    } else {
        match ProbeTarget::parse(&request.probe_url) {
            Ok(target) => Some(Arc::new(target)),
            Err(message) => {
                sink.emit(json!({"t": "error", "message": message}));
                sink.emit(json!({
                    "t": "done", "alive": 0, "tested": 0, "reason": "exhausted", "elapsed_ms": 0
                }));
                return EndReason::Exhausted;
            }
        }
    };

    let work = {
        let sink = sink.clone();
        let alive = Arc::clone(&alive);
        let tested = Arc::clone(&tested);
        async move {
            let semaphore = Arc::new(Semaphore::new(concurrency));
            let mut tasks = JoinSet::new();
            for link in request.links {
                let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                    break;
                };
                let sink = sink.clone();
                let alive = Arc::clone(&alive);
                let tested = Arc::clone(&tested);
                let target = target.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let event = match parse_candidate(&link) {
                        Err(error) => failure(&link_key(&link), &format!("parse: {error}")),
                        Ok(candidate) => {
                            let key = candidate.info.key.clone();
                            let outcome = match &target {
                                Some(target) => {
                                    real_test(&candidate.outbound, target, timeout, request_confirm)
                                        .await
                                }
                                None if candidate.is_udp_based() => {
                                    Err("tcp: not applicable to a UDP-based protocol".to_string())
                                }
                                None => {
                                    tcp_ping(&candidate.info.host, candidate.info.port, timeout)
                                        .await
                                        .map(|delay| delay.as_millis().max(1) as u64)
                                }
                            };
                            match outcome {
                                Ok(delay_ms) => {
                                    alive.fetch_add(1, Ordering::Relaxed);
                                    json!({"t": "result", "key": key, "delay_ms": delay_ms})
                                }
                                Err(error) => failure(&key, &error),
                            }
                        }
                    };
                    tested.fetch_add(1, Ordering::Relaxed);
                    sink.emit(event);
                });
                while tasks.try_join_next().is_some() {}
            }
            while tasks.join_next().await.is_some() {}
        }
    };

    let reason = tokio::select! {
        biased;
        _ = cancel.cancelled() => EndReason::Cancelled,
        () = work => EndReason::Exhausted,
    };
    sink.emit(json!({
        "t": "done",
        "alive": alive.load(Ordering::Relaxed),
        "tested": tested.load(Ordering::Relaxed),
        "reason": reason.as_str(),
        "elapsed_ms": started.elapsed().as_millis() as u64,
    }));
    reason
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{batching_sink_with_interval, Collected};
    use crate::testing::{http_204_server, shadowsocks_relay, ss_link};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_link_gets_exactly_one_result() {
        let probe = http_204_server().await;
        let relay = shadowsocks_relay().await;
        let unreachable = ss_link("127.0.0.1:1".parse().unwrap(), "nowhere");
        let live = ss_link(relay, "live");
        let collected = Collected::default();
        let (sink, flusher) =
            batching_sink_with_interval(collected.callback(), Duration::from_millis(10));
        let reason = test_links(
            TestRequest {
                links: vec![live.clone(), unreachable.clone(), "garbage".into()],
                timeout_ms: 3000,
                probe_url: format!("http://{probe}/generate_204"),
                confirm_tls: false,
                ..TestRequest::default()
            },
            sink,
            CancellationToken::new(),
        )
        .await;
        flusher.await.unwrap();
        assert_eq!(reason, EndReason::Exhausted);

        let results = collected.of("result");
        assert_eq!(results.len(), 3);
        let by_key = |link: &str| {
            results
                .iter()
                .find(|event| event["key"] == link_key(link))
                .cloned()
                .unwrap()
        };
        assert!(by_key(&live)["delay_ms"].as_i64().unwrap() >= 1);
        assert_eq!(by_key(&unreachable)["delay_ms"], -1);
        assert!(by_key("garbage")["error"]
            .as_str()
            .unwrap()
            .starts_with("parse:"));
        let done = &collected.of("done")[0];
        assert_eq!(done["alive"], 1);
        assert_eq!(done["tested"], 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tcp_only_measures_the_handshake() {
        let relay = shadowsocks_relay().await;
        let collected = Collected::default();
        let (sink, flusher) =
            batching_sink_with_interval(collected.callback(), Duration::from_millis(10));
        test_links(
            TestRequest {
                links: vec![ss_link(relay, "live")],
                tcp_only: true,
                ..TestRequest::default()
            },
            sink,
            CancellationToken::new(),
        )
        .await;
        flusher.await.unwrap();
        let results = collected.of("result");
        assert_eq!(results.len(), 1);
        assert!(results[0]["delay_ms"].as_i64().unwrap() >= 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancellation_stops_outstanding_tests() {
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = silent.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = silent.accept().await {
                held.push(stream);
            }
        });
        let collected = Collected::default();
        let (sink, flusher) =
            batching_sink_with_interval(collected.callback(), Duration::from_millis(10));
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            trigger.cancel();
        });
        let started = Instant::now();
        let reason = test_links(
            TestRequest {
                links: (0..8)
                    .map(|index| ss_link(address, &format!("s{index}")))
                    .collect(),
                timeout_ms: 30_000,
                probe_url: "http://127.0.0.1:9/".into(),
                confirm_tls: false,
                ..TestRequest::default()
            },
            sink,
            cancel,
        )
        .await;
        flusher.await.unwrap();
        assert_eq!(reason, EndReason::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(collected.of("done")[0]["reason"], "cancelled");
    }
}
