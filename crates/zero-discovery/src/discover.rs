//! The discovery job: find a handful of working servers as fast as possible.
//!
//! ```text
//! history ─ real-test the previous winners for this network (no TCP stage)
//!    │
//! tier 1 ─ fetch feeds (gzip, ETag cache) ─ parse ─ dedupe ─ order by class
//!    │        │
//!    │        └─ TCP stage ──(open)──► real stage ──(alive)──► event
//!    │            bounded, streaming: a server can be real-tested while
//!    │            thousands of others are still being connected to
//!    │
//! tier 2… only when tier 1 ended with fewer than `next_tier_if_alive_below`
//! ```
//!
//! The job ends at the first of: `want_alive` servers found, every tier
//! exhausted, `max_seconds` elapsed, or cancellation. Ending drops the job's
//! future, which aborts every probe still in flight — nothing keeps using the
//! network after `done` has been sent.
//!
//! Concurrency is bounded at every stage (`tcp_concurrency`,
//! `real_concurrency`), candidates are generated from an ordered list rather
//! than spawned all at once, and progress is reported on a half-second tick
//! only while something changed, so a sweep costs a predictable amount of
//! sockets, memory and wakeups.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::events::EventSink;
use crate::feed::{fetch_feed, FeedSource, FeedStatus};
use crate::link::{parse_candidate, parse_candidates, Candidate};
use crate::order::order_by_class;
use crate::probe::{real_test, tcp_ping, ProbeTarget, DEFAULT_PROBE_URL};

/// The `discover` request. Every field has a default, so `{}` is a valid
/// (if not very useful) request.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DiscoverRequest {
    pub sources: Vec<FeedSource>,
    pub cache_dir: Option<PathBuf>,
    pub priority_links: Vec<String>,
    pub extra_links: Vec<String>,
    pub exclude_keys: Vec<String>,
    pub want_alive: usize,
    pub max_seconds: u64,
    pub tcp_concurrency: usize,
    pub tcp_timeout_ms: u64,
    pub tcp_stop_after_open: usize,
    pub real_concurrency: usize,
    pub real_timeout_ms: u64,
    pub probe_url: String,
    /// Require a verified HTTPS request through the config before calling it
    /// alive (see `probe::tls_confirm`). On by default; tests against local
    /// servers turn it off.
    pub confirm_tls: bool,
    /// Deadline for the HTTPS confirmation, which adds a TLS handshake
    /// through the proxy on top of the plain request.
    pub confirm_timeout_ms: u64,
    pub next_tier_if_alive_below: usize,
    pub fetch: bool,
    /// Per-feed download deadline.
    pub fetch_timeout_ms: u64,
}

impl Default for DiscoverRequest {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            cache_dir: None,
            priority_links: Vec::new(),
            extra_links: Vec::new(),
            exclude_keys: Vec::new(),
            want_alive: 5,
            max_seconds: 60,
            tcp_concurrency: 256,
            tcp_timeout_ms: 1500,
            tcp_stop_after_open: 1500,
            real_concurrency: 64,
            real_timeout_ms: 3000,
            probe_url: DEFAULT_PROBE_URL.into(),
            confirm_tls: true,
            confirm_timeout_ms: 6000,
            next_tier_if_alive_below: 3,
            fetch: true,
            fetch_timeout_ms: 20_000,
        }
    }
}

impl DiscoverRequest {
    /// Clamp values a buggy caller could use to exhaust descriptors or spin.
    fn sanitized(mut self) -> Self {
        self.want_alive = self.want_alive.clamp(1, 1000);
        self.max_seconds = self.max_seconds.clamp(1, 3600);
        self.tcp_concurrency = self.tcp_concurrency.clamp(1, 1024);
        self.tcp_timeout_ms = self.tcp_timeout_ms.clamp(100, 30_000);
        self.tcp_stop_after_open = self.tcp_stop_after_open.max(1);
        self.real_concurrency = self.real_concurrency.clamp(1, 128);
        self.real_timeout_ms = self.real_timeout_ms.clamp(200, 60_000);
        self.confirm_timeout_ms = self.confirm_timeout_ms.clamp(200, 60_000);
        self.fetch_timeout_ms = self.fetch_timeout_ms.clamp(1000, 120_000);
        self
    }
}

/// Why a job ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    Enough,
    Exhausted,
    Timeout,
    Cancelled,
}

impl EndReason {
    pub fn as_str(self) -> &'static str {
        match self {
            EndReason::Enough => "enough",
            EndReason::Exhausted => "exhausted",
            EndReason::Timeout => "timeout",
            EndReason::Cancelled => "cancelled",
        }
    }
}

/// Counters behind the `progress` event.
#[derive(Default)]
struct Progress {
    candidates: AtomicUsize,
    tcp_done: AtomicUsize,
    tcp_open: AtomicUsize,
    real_done: AtomicUsize,
    alive: AtomicUsize,
}

impl Progress {
    fn snapshot(&self) -> [usize; 5] {
        [
            self.candidates.load(Ordering::Relaxed),
            self.tcp_done.load(Ordering::Relaxed),
            self.tcp_open.load(Ordering::Relaxed),
            self.real_done.load(Ordering::Relaxed),
            self.alive.load(Ordering::Relaxed),
        ]
    }

    fn event(snapshot: [usize; 5]) -> serde_json::Value {
        json!({
            "t": "progress",
            "candidates": snapshot[0],
            "tcp_done": snapshot[1],
            "tcp_open": snapshot[2],
            "real_done": snapshot[3],
            "alive": snapshot[4],
        })
    }
}

/// Everything the stages share.
struct Shared {
    request: DiscoverRequest,
    target: ProbeTarget,
    sink: EventSink,
    progress: Progress,
    /// Cancelled once `want_alive` servers have been found.
    enough: CancellationToken,
    /// Keys already reported alive, so a server listed by two feeds under
    /// different remarks is reported once.
    alive_keys: Mutex<HashSet<String>>,
}

impl Shared {
    fn record_alive(&self, candidate: &Candidate, delay_ms: u64) {
        let fresh = self
            .alive_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(candidate.info.key.clone());
        if !fresh {
            return;
        }
        self.sink.emit(json!({
            "t": "alive",
            "info": candidate.info,
            "delay_ms": delay_ms,
        }));
        let alive = self.progress.alive.fetch_add(1, Ordering::Relaxed) + 1;
        if alive >= self.request.want_alive {
            self.enough.cancel();
        }
    }

    fn stage(&self, stage: &str) {
        self.sink.emit(json!({"t": "stage", "stage": stage}));
    }
}

/// Run a discovery job to completion, emitting events into `sink`. The final
/// `done` event is emitted before this returns.
pub async fn discover(
    request: DiscoverRequest,
    sink: EventSink,
    cancel: CancellationToken,
) -> EndReason {
    let started = Instant::now();
    let request = request.sanitized();
    let target = match ProbeTarget::parse(&request.probe_url) {
        Ok(target) => target,
        Err(message) => {
            sink.emit(json!({"t": "error", "message": message}));
            sink.emit(json!({"t": "done", "alive": 0, "reason": "exhausted", "elapsed_ms": 0}));
            return EndReason::Exhausted;
        }
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(request.max_seconds);
    let shared = Arc::new(Shared {
        request,
        target,
        sink: sink.clone(),
        progress: Progress::default(),
        enough: CancellationToken::new(),
        alive_keys: Mutex::new(HashSet::new()),
    });

    // Progress on a tick, only when something moved.
    let ticker = {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let mut last = [usize::MAX; 5];
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let now = shared.progress.snapshot();
                if now != last {
                    shared.sink.emit(Progress::event(now));
                    last = now;
                }
            }
        })
    };

    let reason = tokio::select! {
        biased;
        _ = cancel.cancelled() => EndReason::Cancelled,
        _ = shared.enough.cancelled() => EndReason::Enough,
        _ = tokio::time::sleep_until(deadline) => EndReason::Timeout,
        () = run(Arc::clone(&shared)) => {
            // The last real test may have been the one that reached the goal.
            if shared.enough.is_cancelled() { EndReason::Enough } else { EndReason::Exhausted }
        }
    };
    ticker.abort();

    sink.emit(Progress::event(shared.progress.snapshot()));
    sink.emit(json!({
        "t": "done",
        "alive": shared.progress.alive.load(Ordering::Relaxed),
        "reason": reason.as_str(),
        "elapsed_ms": started.elapsed().as_millis() as u64,
    }));
    reason
}

async fn run(shared: Arc<Shared>) {
    let request = &shared.request;
    let mut seen: HashSet<String> = request.exclude_keys.iter().cloned().collect();

    // 1. History: the last winners on this network, straight to the real
    //    test. Usually one of them still works and discovery ends here.
    let mut history = Vec::new();
    for link in &request.priority_links {
        if let Ok(candidate) = parse_candidate(link) {
            if seen.insert(candidate.info.key.clone()) {
                history.push(candidate);
            }
        }
    }
    if !history.is_empty() {
        shared.stage("history");
        shared
            .progress
            .candidates
            .fetch_add(history.len(), Ordering::Relaxed);
        real_stage_all(&shared, history).await;
    }

    // The user's own configs join the first tier, ahead of the feeds.
    let mut own = Vec::new();
    for link in &request.extra_links {
        if let Ok(candidate) = parse_candidate(link) {
            if seen.insert(candidate.info.key.clone()) {
                own.push(candidate);
            }
        }
    }

    let mut tiers: Vec<u32> = if request.fetch {
        request.sources.iter().map(|source| source.tier).collect()
    } else {
        Vec::new()
    };
    tiers.sort_unstable();
    tiers.dedup();

    if tiers.is_empty() {
        if !own.is_empty() {
            shared
                .progress
                .candidates
                .fetch_add(own.len(), Ordering::Relaxed);
            pipeline(&shared, own).await;
        }
        return;
    }

    for (index, tier) in tiers.iter().enumerate() {
        let mut pool = if index == 0 {
            std::mem::take(&mut own)
        } else {
            Vec::new()
        };
        let own_count = pool.len();

        shared.stage("fetch");
        let sources: Vec<&FeedSource> = request
            .sources
            .iter()
            .filter(|source| source.tier == *tier)
            .collect();
        let cache_dir = request.cache_dir.clone();
        let timeout = Duration::from_millis(request.fetch_timeout_ms);
        let fetches = sources.iter().map(|source| {
            let cache_dir = cache_dir.clone();
            async move {
                let result = fetch_feed(source, cache_dir.as_deref(), timeout).await;
                (*source, result)
            }
        });
        let results = futures::future::join_all(fetches).await;

        shared.stage("parse");
        let mut fetched = Vec::new();
        for (source, result) in results {
            let mut count = 0usize;
            if let Some(body) = result.body.as_deref() {
                let (candidates, _report) = parse_candidates(body, &seen);
                for candidate in candidates {
                    if seen.insert(candidate.info.key.clone()) {
                        count += 1;
                        fetched.push(candidate);
                    }
                }
            }
            let mut event = json!({
                "t": "source",
                "id": source.id,
                "status": result.status.as_str(),
                "count": count,
                "bytes": result.bytes,
            });
            if let Some(error) = result.error {
                if result.status != FeedStatus::Ok {
                    event["error"] = json!(error);
                }
            }
            shared.sink.emit(event);
        }
        let ordered = order_by_class(
            fetched,
            |candidate| candidate.class,
            &mut rand::thread_rng(),
        );
        pool.extend(ordered);
        shared
            .progress
            .candidates
            .fetch_add(pool.len(), Ordering::Relaxed);
        tracing::debug!(
            tier,
            own = own_count,
            total = pool.len(),
            "discovery tier ready"
        );

        pipeline(&shared, pool).await;

        let alive = shared.progress.alive.load(Ordering::Relaxed);
        if alive >= request.next_tier_if_alive_below {
            return;
        }
    }
}

/// Real-test every candidate, `real_concurrency` at a time.
async fn real_stage_all(shared: &Arc<Shared>, candidates: Vec<Candidate>) {
    let semaphore = Arc::new(Semaphore::new(shared.request.real_concurrency));
    let mut tasks = JoinSet::new();
    for candidate in candidates {
        let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
            break;
        };
        let shared = Arc::clone(shared);
        tasks.spawn(async move {
            let _permit = permit;
            real_one(&shared, &candidate).await;
        });
        while tasks.try_join_next().is_some() {}
    }
    while tasks.join_next().await.is_some() {}
}

async fn real_one(shared: &Shared, candidate: &Candidate) {
    let timeout = Duration::from_millis(shared.request.real_timeout_ms);
    let result = real_test(
        &candidate.outbound,
        &shared.target,
        timeout,
        shared
            .request
            .confirm_tls
            .then(|| Duration::from_millis(shared.request.confirm_timeout_ms)),
    )
    .await;
    shared.progress.real_done.fetch_add(1, Ordering::Relaxed);
    match result {
        Ok(delay_ms) => shared.record_alive(candidate, delay_ms),
        Err(error) => {
            tracing::trace!(key = %candidate.info.key, %error, "real test failed");
        }
    }
}

/// The streaming TCP → real pipeline over one ordered pool.
async fn pipeline(shared: &Arc<Shared>, pool: Vec<Candidate>) {
    if pool.is_empty() {
        return;
    }
    shared.stage("tcp");
    let request = &shared.request;
    let (open_sender, mut open_receiver) =
        mpsc::channel::<Candidate>(request.real_concurrency.saturating_mul(4).max(8));

    // Real stage consumer: pulls opened candidates as they arrive.
    let consumer = {
        let shared = Arc::clone(shared);
        async move {
            let semaphore = Arc::new(Semaphore::new(shared.request.real_concurrency));
            let mut tasks = JoinSet::new();
            let mut announced = false;
            while let Some(candidate) = open_receiver.recv().await {
                if !announced {
                    shared.stage("real");
                    announced = true;
                }
                let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                    break;
                };
                let shared = Arc::clone(&shared);
                tasks.spawn(async move {
                    let _permit = permit;
                    real_one(&shared, &candidate).await;
                });
                while tasks.try_join_next().is_some() {}
            }
            while tasks.join_next().await.is_some() {}
        }
    };

    // TCP stage producer.
    let producer = {
        let shared = Arc::clone(shared);
        async move {
            let semaphore = Arc::new(Semaphore::new(shared.request.tcp_concurrency));
            let timeout = Duration::from_millis(shared.request.tcp_timeout_ms);
            // Feeds list many links per server (one per user id or path);
            // one connect answers for all of them.
            let verdicts: Arc<Mutex<HashMap<(String, u16), bool>>> =
                Arc::new(Mutex::new(HashMap::new()));
            let mut tasks = JoinSet::new();
            // The open-server budget is per tier: the progress counter is
            // cumulative for the whole job, and comparing it directly made
            // every tier after the first stop at its first candidate.
            let open_at_start = shared.progress.tcp_open.load(Ordering::Relaxed);
            for candidate in pool {
                if shared.progress.tcp_open.load(Ordering::Relaxed) - open_at_start
                    >= shared.request.tcp_stop_after_open
                {
                    break;
                }
                if candidate.is_udp_based() {
                    // Nothing to connect to over TCP; the real test decides.
                    if open_sender.send(candidate).await.is_err() {
                        break;
                    }
                    continue;
                }
                let endpoint = (candidate.info.host.clone(), candidate.info.port);
                let known = verdicts
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(&endpoint)
                    .copied();
                match known {
                    Some(false) => {
                        shared.progress.tcp_done.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Some(true) => {
                        shared.progress.tcp_done.fetch_add(1, Ordering::Relaxed);
                        shared.progress.tcp_open.fetch_add(1, Ordering::Relaxed);
                        if open_sender.send(candidate).await.is_err() {
                            break;
                        }
                        continue;
                    }
                    None => {}
                }
                let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                    break;
                };
                let shared = Arc::clone(&shared);
                let verdicts = Arc::clone(&verdicts);
                let sender = open_sender.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let open = tcp_ping(&endpoint.0, endpoint.1, timeout).await.is_ok();
                    verdicts
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(endpoint, open);
                    shared.progress.tcp_done.fetch_add(1, Ordering::Relaxed);
                    if open {
                        shared.progress.tcp_open.fetch_add(1, Ordering::Relaxed);
                        // Backpressure: when the real stage is saturated the
                        // TCP stage waits instead of piling up candidates.
                        let _ = sender.send(candidate).await;
                    }
                });
                while tasks.try_join_next().is_some() {}
            }
            drop(open_sender);
            while tasks.join_next().await.is_some() {}
        }
    };

    tokio::join!(producer, consumer);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{batching_sink_with_interval, Collected};
    use crate::testing::{http_204_server, shadowsocks_relay, ss_link};

    fn quick(request: DiscoverRequest) -> DiscoverRequest {
        DiscoverRequest {
            max_seconds: 20,
            tcp_timeout_ms: 500,
            real_timeout_ms: 3000,
            fetch: false,
            ..request
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn history_winner_is_found_and_the_job_ends_with_enough() {
        let probe = http_204_server().await;
        let relay = shadowsocks_relay().await;
        let collected = Collected::default();
        let (sink, flusher) =
            batching_sink_with_interval(collected.callback(), Duration::from_millis(10));
        let reason = discover(
            quick(DiscoverRequest {
                priority_links: vec![ss_link(relay, "winner")],
                want_alive: 1,
                probe_url: format!("http://{probe}/generate_204"),
                confirm_tls: false,
                ..DiscoverRequest::default()
            }),
            sink,
            CancellationToken::new(),
        )
        .await;
        flusher.await.unwrap();
        assert_eq!(reason, EndReason::Enough);
        let alive = collected.of("alive");
        assert_eq!(alive.len(), 1, "{:?}", collected.events());
        assert_eq!(alive[0]["info"]["name"], "winner");
        assert!(alive[0]["delay_ms"].as_u64().unwrap() >= 1);
        let done = collected.of("done");
        assert_eq!(done.len(), 1);
        assert_eq!(done[0]["reason"], "enough");
        assert_eq!(collected.of("stage")[0]["stage"], "history");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_pipeline_skips_dead_servers_and_reports_the_live_one() {
        let probe = http_204_server().await;
        let relay = shadowsocks_relay().await;
        let dead_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dead: std::net::SocketAddr = format!("127.0.0.1:{dead_port}").parse().unwrap();
        let collected = Collected::default();
        let (sink, flusher) =
            batching_sink_with_interval(collected.callback(), Duration::from_millis(10));
        let reason = discover(
            quick(DiscoverRequest {
                extra_links: vec![ss_link(dead, "dead"), ss_link(relay, "live")],
                want_alive: 5,
                probe_url: format!("http://{probe}/generate_204"),
                confirm_tls: false,
                ..DiscoverRequest::default()
            }),
            sink,
            CancellationToken::new(),
        )
        .await;
        flusher.await.unwrap();
        assert_eq!(reason, EndReason::Exhausted);
        let alive = collected.of("alive");
        assert_eq!(alive.len(), 1);
        assert_eq!(alive[0]["info"]["name"], "live");
        let progress = collected.of("progress");
        let last = progress.last().unwrap();
        assert_eq!(last["candidates"], 2);
        assert_eq!(last["tcp_done"], 2);
        assert_eq!(last["tcp_open"], 1);
        assert_eq!(last["real_done"], 1);
        let stages: Vec<String> = collected
            .of("stage")
            .iter()
            .map(|event| event["stage"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(stages, ["tcp", "real"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancellation_ends_the_job_promptly() {
        // A server that accepts and never answers: every real test would
        // run to its full timeout.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_address = silent.local_addr().unwrap();
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
            tokio::time::sleep(Duration::from_millis(300)).await;
            trigger.cancel();
        });
        let started = Instant::now();
        let reason = discover(
            DiscoverRequest {
                priority_links: vec![ss_link(silent_address, "silent")],
                real_timeout_ms: 30_000,
                max_seconds: 60,
                fetch: false,
                probe_url: "http://127.0.0.1:9/generate_204".into(),
                confirm_tls: false,
                ..DiscoverRequest::default()
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_time_budget_is_enforced() {
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_address = silent.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = silent.accept().await {
                held.push(stream);
            }
        });
        let collected = Collected::default();
        let (sink, flusher) =
            batching_sink_with_interval(collected.callback(), Duration::from_millis(10));
        let reason = discover(
            DiscoverRequest {
                priority_links: vec![ss_link(silent_address, "silent")],
                real_timeout_ms: 30_000,
                max_seconds: 1,
                fetch: false,
                probe_url: "http://127.0.0.1:9/generate_204".into(),
                confirm_tls: false,
                ..DiscoverRequest::default()
            },
            sink,
            CancellationToken::new(),
        )
        .await;
        flusher.await.unwrap();
        assert_eq!(reason, EndReason::Timeout);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn feeds_are_fetched_by_tier_and_the_next_tier_only_when_needed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let probe = http_204_server().await;
        let relay = shadowsocks_relay().await;
        let tier1_body: &'static str =
            Box::leak(format!("{}\n", ss_link(relay, "tier1")).into_boxed_str());
        let requests = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = listener.local_addr().unwrap();
        let counter = Arc::clone(&requests);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut request = [0u8; 2048];
                let n = stream.read(&mut request).await.unwrap_or(0);
                let text = String::from_utf8_lossy(&request[..n]).to_string();
                let body = if text.starts_with("GET /tier1") {
                    tier1_body
                } else {
                    ""
                };
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
            }
        });
        let collected = Collected::default();
        let (sink, flusher) =
            batching_sink_with_interval(collected.callback(), Duration::from_millis(10));
        discover(
            DiscoverRequest {
                sources: vec![
                    FeedSource {
                        id: "one".into(),
                        url: format!("http://{origin}/tier1"),
                        tier: 1,
                    },
                    FeedSource {
                        id: "two".into(),
                        url: format!("http://{origin}/tier2"),
                        tier: 2,
                    },
                ],
                want_alive: 3,
                next_tier_if_alive_below: 1,
                max_seconds: 20,
                tcp_timeout_ms: 500,
                probe_url: format!("http://{probe}/generate_204"),
                confirm_tls: false,
                ..DiscoverRequest::default()
            },
            sink,
            CancellationToken::new(),
        )
        .await;
        flusher.await.unwrap();
        // Tier 1 produced one alive, meeting the threshold of 1: tier 2 is
        // never fetched.
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        let sources = collected.of("source");
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0]["id"], "one");
        assert_eq!(sources[0]["status"], "ok");
        assert_eq!(sources[0]["count"], 1);
        assert_eq!(collected.of("alive").len(), 1);
        assert_eq!(collected.of("done")[0]["reason"], "exhausted");
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_later_tier_gets_its_own_tcp_budget() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let probe = http_204_server().await;
        let relay = shadowsocks_relay().await;
        // Tier 1: a server that accepts TCP and then never answers, using up
        // the whole budget of one open server. Tier 2: a working relay.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = silent.accept().await {
                held.push(stream);
            }
        });
        let tier1: &'static str =
            Box::leak(format!("{}\n", ss_link(silent_addr, "silent")).into_boxed_str());
        let tier2: &'static str =
            Box::leak(format!("{}\n", ss_link(relay, "live")).into_boxed_str());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0u8; 2048];
                let n = stream.read(&mut request).await.unwrap_or(0);
                let text = String::from_utf8_lossy(&request[..n]).to_string();
                let body = if text.starts_with("GET /tier1") {
                    tier1
                } else {
                    tier2
                };
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
            }
        });
        let collected = Collected::default();
        let (sink, flusher) =
            batching_sink_with_interval(collected.callback(), Duration::from_millis(10));
        discover(
            DiscoverRequest {
                sources: vec![
                    FeedSource {
                        id: "one".into(),
                        url: format!("http://{origin}/tier1"),
                        tier: 1,
                    },
                    FeedSource {
                        id: "two".into(),
                        url: format!("http://{origin}/tier2"),
                        tier: 2,
                    },
                ],
                want_alive: 1,
                next_tier_if_alive_below: 1,
                tcp_stop_after_open: 1,
                max_seconds: 20,
                tcp_timeout_ms: 500,
                real_timeout_ms: 800,
                probe_url: format!("http://{probe}/generate_204"),
                confirm_tls: false,
                ..DiscoverRequest::default()
            },
            sink,
            CancellationToken::new(),
        )
        .await;
        flusher.await.unwrap();
        let ids: Vec<String> = collected
            .of("source")
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids, vec!["one", "two"]);
        assert_eq!(
            collected.of("alive").len(),
            1,
            "tier 2's live relay must be tested"
        );
        assert_eq!(collected.of("done")[0]["reason"], "enough");
    }
}
