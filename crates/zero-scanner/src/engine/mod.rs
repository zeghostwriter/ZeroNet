use crate::dns::FastResolver;
use crate::ip::IpSource;
use crate::meta::{lookup_cymru_asn, lookup_iranian_isp};
use crate::probe::Prober;
use crate::proxy::{validate_proxy, ProxyConfig};
use crate::types::{AtomicStats, ProbeConfig, ProbeResult};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

/// How often a dispatcher that is blocked (all workers busy, paused, or
/// waiting for neighbours) re-checks the cancel and pause flags. They are
/// plain atomics shared with callers, so they cannot be awaited directly.
const CONTROL_POLL: Duration = Duration::from_millis(100);

/// Upper bound on the proxy-validation phase per IP.
const PROXY_VALIDATION_TIMEOUT: Duration = Duration::from_secs(6);

pub struct ScanEngineConfig {
    pub concurrency: usize,
    /// Number of candidate IPs to probe; 0 means until the pool is exhausted
    /// or the scan is cancelled.
    pub target_count: usize,
    pub probe_config: ProbeConfig,
    pub neighbor_scan: bool,
    pub proxy_config: Option<ProxyConfig>,
}

pub struct ScanEngine {
    config: ScanEngineConfig,
    ip_source: Arc<IpSource>,
    prober: Arc<Prober>,
    resolver: Arc<FastResolver>,
    stats: Arc<AtomicStats>,
    cancelled: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Ranking used for the final result list: lowest loss first, then lowest
/// average latency. Total and panic-free even with NaN latencies.
pub fn rank_results(a: &ProbeResult, b: &ProbeResult) -> std::cmp::Ordering {
    let loss_a = a.packet_loss_percent();
    let loss_b = b.packet_loss_percent();
    if (loss_a - loss_b).abs() > 0.01 {
        loss_a.total_cmp(&loss_b)
    } else {
        a.avg_latency_ms().total_cmp(&b.avg_latency_ms())
    }
}

/// Everything a worker needs, shared once per scan instead of cloning ten
/// `Arc`s per probed IP.
struct Shared<F> {
    prober: Arc<Prober>,
    resolver: Arc<FastResolver>,
    ip_source: Arc<IpSource>,
    stats: Arc<AtomicStats>,
    probe_cfg: ProbeConfig,
    proxy_cfg: Option<ProxyConfig>,
    neighbor_scan: bool,
    on_result: F,
    results: Mutex<Vec<ProbeResult>>,
    /// Neighbours of healthy hits, probed before fresh random candidates.
    neighbor_queue: Mutex<Vec<IpAddr>>,
    /// ASN per /24 (v4) or /48 (v6). Origin ASNs are announced per prefix, so
    /// one Team Cymru lookup answers for every neighbour in the block.
    asn_cache: Mutex<HashMap<(bool, u128), Option<u32>>>,
}

/// Keeps `in_flight` honest when a worker is aborted before it finishes.
struct InFlight<'a> {
    stats: &'a AtomicStats,
    done: bool,
}

impl InFlight<'_> {
    fn finish(mut self, healthy: bool) {
        self.done = true;
        self.stats.record_finish(healthy);
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.stats.record_abandoned();
        }
    }
}

fn asn_key(ip: IpAddr) -> (bool, u128) {
    match ip {
        IpAddr::V4(v4) => (false, u128::from(u32::from(v4) & 0xFFFF_FF00)),
        IpAddr::V6(v6) => (true, u128::from(v6) & !((1u128 << 80) - 1)),
    }
}

/// Largest number of probes the process can have open at once without
/// running out of file descriptors, or `None` if the limit is unknown.
/// A probe holds at most two sockets at a time (probe + WS/speed/proxy
/// follow-up), and some descriptors are reserved for the runtime and UI.
fn fd_concurrency_limit() -> Option<usize> {
    #[cfg(unix)]
    {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit only writes into the provided struct.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0
            || lim.rlim_cur == libc::RLIM_INFINITY
        {
            return None;
        }
        // rlim_t is u64 on Linux and macOS but not on every Unix.
        #[allow(clippy::unnecessary_cast)]
        let usable = (lim.rlim_cur as u64).saturating_sub(64) / 2;
        Some(usable.clamp(1, usize::MAX as u64) as usize)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

impl ScanEngine {
    pub fn new(config: ScanEngineConfig, ip_source: Arc<IpSource>) -> Self {
        Self::new_with_state(
            config,
            ip_source,
            Arc::new(AtomicStats::new()),
            Arc::new(AtomicBool::new(false)),
        )
    }

    pub fn new_with_state(
        config: ScanEngineConfig,
        ip_source: Arc<IpSource>,
        stats: Arc<AtomicStats>,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            config,
            ip_source,
            prober: Arc::new(Prober::new()),
            resolver: Arc::new(FastResolver::new()),
            stats,
            cancelled,
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Uses `paused` as the pause switch: while it is set no new IPs are
    /// dispatched (probes already running finish normally).
    pub fn with_pause_flag(mut self, paused: Arc<AtomicBool>) -> Self {
        self.paused = paused;
        self
    }

    pub fn stats(&self) -> Arc<AtomicStats> {
        self.stats.clone()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Runs the scan and returns the healthy results, best first.
    ///
    /// At most `concurrency` probes run at once (further capped by the
    /// process fd limit), candidates are generated lazily one at a time, and
    /// finished workers are reaped as the scan goes, so memory stays flat no
    /// matter how large the ranges or how long the scan. The scan ends when
    /// `target_count` IPs were probed, the candidate pool is exhausted, or
    /// the cancel flag is set; on cancel, in-flight probes are aborted and
    /// the results gathered so far are returned. Dropping the returned future
    /// also aborts every in-flight probe.
    pub async fn run<F>(&self, on_result: F) -> Vec<ProbeResult>
    where
        F: Fn(&ProbeResult) + Send + Sync + 'static,
    {
        let mut concurrency = self.config.concurrency.max(1);
        if let Some(limit) = fd_concurrency_limit() {
            concurrency = concurrency.min(limit);
        }
        let target = self.config.target_count;

        let shared = Arc::new(Shared {
            prober: self.prober.clone(),
            resolver: self.resolver.clone(),
            ip_source: self.ip_source.clone(),
            stats: self.stats.clone(),
            probe_cfg: self.config.probe_config.clone(),
            proxy_cfg: self.config.proxy_config.clone(),
            neighbor_scan: self.config.neighbor_scan,
            on_result,
            results: Mutex::new(Vec::new()),
            neighbor_queue: Mutex::new(Vec::new()),
            asn_cache: Mutex::new(HashMap::new()),
        });

        let sem = Arc::new(Semaphore::new(concurrency));
        let mut workers: JoinSet<()> = JoinSet::new();
        let mut dispatched = 0usize;

        loop {
            // Reap finished workers so the set only ever holds live ones.
            while workers.try_join_next().is_some() {}

            if self.is_cancelled() || (target > 0 && dispatched >= target) {
                break;
            }
            if self.paused.load(Ordering::Relaxed) {
                tokio::time::sleep(CONTROL_POLL).await;
                continue;
            }

            let permit = tokio::select! {
                p = sem.clone().acquire_owned() => match p {
                    Ok(p) => p,
                    Err(_) => break,
                },
                _ = tokio::time::sleep(CONTROL_POLL) => continue,
            };

            let next = lock(&shared.neighbor_queue).pop();
            let Some(ip) = next.or_else(|| shared.ip_source.random_candidate()) else {
                drop(permit);
                if workers.is_empty() {
                    // Pool exhausted and nothing running that could still
                    // queue neighbours: the scan is complete.
                    break;
                }
                // A running probe may yet enqueue neighbours; wait for one to
                // finish instead of spinning.
                tokio::select! {
                    _ = workers.join_next() => {}
                    _ = tokio::time::sleep(CONTROL_POLL) => {}
                }
                continue;
            };

            dispatched += 1;
            shared.stats.record_start();
            workers.spawn(probe_one(shared.clone(), ip, permit));
        }

        // Drain: let the last probes finish (their results count), but keep
        // watching the cancel flag so a cancel during the drain is prompt too.
        // Panicked probes are simply dropped; their IP produces no result.
        while !workers.is_empty() {
            if self.is_cancelled() {
                workers.abort_all();
            }
            tokio::select! {
                _ = workers.join_next() => {}
                _ = tokio::time::sleep(CONTROL_POLL) => {}
            }
        }

        let mut final_results = std::mem::take(&mut *lock(&shared.results));
        final_results.sort_by(rank_results);
        final_results
    }
}

async fn probe_one<F>(shared: Arc<Shared<F>>, ip: IpAddr, permit: OwnedSemaphorePermit)
where
    F: Fn(&ProbeResult) + Send + Sync + 'static,
{
    let in_flight = InFlight {
        stats: &shared.stats,
        done: false,
    };
    let cfg = &shared.probe_cfg;
    let mut res = shared.prober.probe(ip, cfg).await;

    // Phase 2: if a proxy is configured and Phase 1 passed, validate it.
    if res.is_healthy(cfg.require_ws) {
        if let Some(ref p_cfg) = shared.proxy_cfg {
            let proxy_val = validate_proxy(ip, p_cfg, PROXY_VALIDATION_TIMEOUT).await;
            if !proxy_val.success {
                res.latencies_ms.clear(); // Mark as failed
            } else {
                // The tunnelled trace reports the colo the *proxy server*
                // exits through, not the edge this IP lands on; only use it
                // when Phase 1 found none.
                if res.colo.is_none() {
                    res.colo = proxy_val.colo;
                }
                if proxy_val.ttfb_ms > 0.0 {
                    res.latencies_ms = vec![proxy_val.ttfb_ms];
                }
            }
        }
    }

    let healthy = res.is_healthy(cfg.require_ws);
    in_flight.finish(healthy);
    // The probe slot is free; metadata enrichment below must not hold up
    // the next probe.
    drop(permit);

    if !healthy {
        return;
    }

    res.isp = lookup_iranian_isp(res.ip).map(|s| s.to_string());
    if res.isp.is_none() {
        let key = asn_key(res.ip);
        let cached = lock(&shared.asn_cache).get(&key).copied();
        res.asn = match cached {
            Some(asn) => asn,
            None => {
                let asn = lookup_cymru_asn(&shared.resolver, res.ip)
                    .await
                    .map(|(asn, _)| asn);
                lock(&shared.asn_cache).insert(key, asn);
                asn
            }
        };
    }

    if shared.neighbor_scan {
        let neighbors = shared.ip_source.get_neighbors(res.ip);
        if !neighbors.is_empty() {
            lock(&shared.neighbor_queue).extend(neighbors);
        }
    }

    (shared.on_result)(&res);
    lock(&shared.results).push(res);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProbeMode, ResultFlags};
    use std::net::Ipv4Addr;
    use std::time::Instant;

    fn result(ip: [u8; 4], latencies: Vec<f64>) -> ProbeResult {
        ProbeResult {
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
            port: 443,
            mode: ProbeMode::Http,
            latencies_ms: latencies,
            flags: ResultFlags::HTTP_OK,
            http_status: 200,
            colo: Some("FRA".into()),
            throughput_mbps: 0.0,
            isp: None,
            asn: None,
        }
    }

    #[test]
    fn test_sorting_with_nan_and_zeros_never_panics() {
        let mut list = [
            result([1, 1, 1, 1], vec![]),
            result([1, 1, 1, 2], vec![50.0, 60.0]),
            result([1, 1, 1, 3], vec![f64::NAN, 10.0]),
        ];
        list.sort_by(rank_results);
        // NaN samples count neither as loss nor towards the average.
        assert_eq!(list[0].ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3)));
        assert_eq!(list[1].ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)));
        assert_eq!(list[2].ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    fn tcp_config(port: u16) -> ProbeConfig {
        ProbeConfig {
            port,
            mode: ProbeMode::Tcp,
            tries: 1,
            timeout: Duration::from_millis(500),
            jitter_range_ms: (0, 0),
            ..ProbeConfig::default()
        }
    }

    fn engine(cidrs: &[&str], port: u16, target: usize, concurrency: usize) -> ScanEngine {
        let list: Vec<String> = cidrs.iter().map(|s| s.to_string()).collect();
        let src = Arc::new(IpSource::new(true, false, &list, false));
        ScanEngine::new(
            ScanEngineConfig {
                concurrency,
                target_count: target,
                probe_config: tcp_config(port),
                neighbor_scan: false,
                proxy_config: None,
            },
            src,
        )
    }

    #[tokio::test]
    async fn finishes_when_a_small_pool_is_exhausted() {
        // Previously an unlimited scan over a short list spun forever once
        // every address had been handed out.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let eng = engine(&["127.0.0.1", "127.0.0.2", "127.0.0.3"], port, 0, 8);
        let results = tokio::time::timeout(Duration::from_secs(10), eng.run(|_| {}))
            .await
            .expect("scan must finish once the pool is exhausted");
        let (tested, _, _, in_flight, _) = eng.stats().snapshot();
        assert_eq!(tested, 3);
        assert_eq!(in_flight, 0);
        assert!(results
            .iter()
            .any(|r| r.ip == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[tokio::test]
    async fn target_count_is_exact() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let eng = engine(&["127.0.0.0/24"], port, 10, 4);
        let _ = tokio::time::timeout(Duration::from_secs(20), eng.run(|_| {}))
            .await
            .unwrap();
        assert_eq!(eng.stats().snapshot().0, 10);
    }

    #[tokio::test]
    async fn zero_concurrency_does_not_deadlock() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let eng = engine(&["127.0.0.1"], port, 0, 0);
        tokio::time::timeout(Duration::from_secs(10), eng.run(|_| {}))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cancel_stops_promptly_and_keeps_stats_consistent() {
        // 192.0.2.0/24 (TEST-NET-1) is unroutable, so probes hang until
        // their timeout; cancellation must not wait for them.
        let mut cfg = tcp_config(443);
        cfg.timeout = Duration::from_secs(30);
        let src = Arc::new(IpSource::new(
            true,
            false,
            &["192.0.2.0/24".to_string()],
            false,
        ));
        let eng = Arc::new(ScanEngine::new(
            ScanEngineConfig {
                concurrency: 16,
                target_count: 0,
                probe_config: cfg,
                neighbor_scan: false,
                proxy_config: None,
            },
            src,
        ));
        let runner = eng.clone();
        let handle = tokio::spawn(async move { runner.run(|_| {}).await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let t0 = Instant::now();
        eng.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("cancel must stop the scan promptly")
            .unwrap();
        assert!(t0.elapsed() < Duration::from_secs(2));
        assert_eq!(
            eng.stats().snapshot().3,
            0,
            "aborted probes must leave in_flight at 0"
        );
    }

    #[tokio::test]
    async fn pause_holds_dispatch() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let paused = Arc::new(AtomicBool::new(true));
        let eng = Arc::new(engine(&["127.0.0.0/24"], port, 5, 2).with_pause_flag(paused.clone()));
        let runner = eng.clone();
        let handle = tokio::spawn(async move { runner.run(|_| {}).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(eng.stats().snapshot().0, 0);
        paused.store(false, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(eng.stats().snapshot().0, 5);
    }
}
