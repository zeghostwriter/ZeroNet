//! The config finder: search the public feeds and the crowd rankings for a
//! server that works on this network right now, the way the Android app
//! does, and report back — anonymously — which public servers answered.
//!
//! ```text
//! known ─ real-test, all at once, the found servers that worked here
//!   │     before and the ones other users report working (crowd rankings)
//!   │
//! search ─ only when that was not enough: discovery over the public feeds
//!          (tiered, streaming TCP → real tests), skipping what was tested
//! ```
//!
//! Everything reaches the frame loop as a [`FinderEvent`]; the finder holds
//! no UI state and does no database work. The user's own profiles are never
//! part of a search and never part of a report: only servers from the public
//! feeds or the rankings are ([`Origin`]).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc::UnboundedSender;
use zero_discovery::crowd_client::{self, TestResult};
use zero_discovery::feed::FeedSource;
use zero_discovery::{CancellationToken, DiscoverRequest, LinkInfo, TestRequest};

/// Not Cloudflare: Worker-served configs cannot reach Cloudflare addresses.
pub const PROBE_URL: &str = "http://www.gstatic.com/generate_204";
/// Crowd picks tested before searching.
pub const CROWD_PICKS: usize = 12;
/// Found servers from earlier searches tested before searching.
pub const HISTORY_LINKS: usize = 12;

/// Where a found server came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// A public feed, found by a search (now or earlier).
    Found,
    /// The crowd rankings: other users got through with it.
    Crowd,
}

impl Origin {
    /// The value stored in the `configs.origin` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Found => "found",
            Origin::Crowd => "crowd",
        }
    }
}

/// What a search step reports.
#[derive(Debug, Clone, PartialEq)]
pub enum FinderEvent {
    /// `known`, then the discovery stages: `history`, `fetch`, `parse`, `tcp`, `real`.
    Stage(String),
    Progress(Progress),
    /// A server that carried a real request, with its delay.
    Alive {
        info: LinkInfo,
        delay_ms: u32,
        origin: Origin,
    },
    /// A known server that did not answer (successes come as [`FinderEvent::Alive`]).
    Failed { key: String },
    /// Something the user may want to know (a feed that failed, …).
    Note(String),
    /// The search is over.
    Done { alive: usize, reason: String },
}

/// Counters of the running search.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Progress {
    pub candidates: usize,
    pub tcp_done: usize,
    pub tcp_open: usize,
    pub real_done: usize,
    pub alive: usize,
}

/// One search.
#[derive(Debug, Clone)]
pub struct FinderRequest {
    /// Share links of found servers that worked before, best first.
    pub history: Vec<String>,
    pub sources: Vec<FeedSource>,
    /// Feed and rankings cache (`<data dir>/finder`).
    pub cache_dir: Option<PathBuf>,
    /// Stop after this many working servers.
    pub want_alive: usize,
    pub max_seconds: u64,
    /// The network name to read crowd picks for (`asn:…`), or `all`.
    pub crowd_net: String,
    /// Use the crowd rankings at all.
    pub use_crowd: bool,
}

impl Default for FinderRequest {
    fn default() -> Self {
        Self {
            history: Vec::new(),
            sources: zero_discovery::sources::enabled(&[], 2),
            cache_dir: None,
            want_alive: 3,
            max_seconds: 90,
            crowd_net: zero_discovery::crowd::ALL_NETS.into(),
            use_crowd: true,
        }
    }
}

type Tx = UnboundedSender<FinderEvent>;

/// Run one search to completion (or cancellation); ends with [`FinderEvent::Done`].
pub async fn run(request: FinderRequest, tx: Tx, cancel: CancellationToken) {
    let want = request.want_alive.max(1);
    let mut alive = 0usize;
    let mut tested: Vec<String> = Vec::new();

    // ---- 1. known servers: this machine's earlier finds and the crowd's picks
    let mut known: Vec<(String, Origin)> = request
        .history
        .iter()
        .take(HISTORY_LINKS)
        .map(|link| (link.clone(), Origin::Found))
        .collect();
    if request.use_crowd {
        let cache = request.cache_dir.as_ref().map(|dir| dir.join("rankings.json"));
        let rankings = tokio::select! {
            _ = cancel.cancelled() => None,
            r = crowd_client::fetch_rankings(cache.as_deref(), Duration::from_secs(4)) => r,
        };
        match rankings {
            Some(rankings) => {
                for pick in crowd_client::picks(&rankings, &request.crowd_net, CROWD_PICKS) {
                    known.push((pick.link, Origin::Crowd));
                }
            }
            None => {
                let _ = tx.send(FinderEvent::Note("crowd rankings unavailable".into()));
            }
        }
    }
    // One entry per server: a crowd pick this machine already found stays "found".
    let mut origins: HashMap<String, (String, Origin)> = HashMap::new();
    for (link, origin) in known {
        let key = zero_discovery::link_key(&link);
        origins.entry(key).or_insert((link, origin));
    }
    if !origins.is_empty() && !cancel.is_cancelled() {
        let _ = tx.send(FinderEvent::Stage("known".into()));
        let links: Vec<String> = origins.values().map(|(link, _)| link.clone()).collect();
        tested.extend(origins.keys().cloned());
        let test = TestRequest {
            concurrency: links.len().clamp(1, 32),
            timeout_ms: 4000,
            probe_url: PROBE_URL.into(),
            links,
            ..TestRequest::default()
        };
        let events = collect(|sink, cancel| zero_discovery::test_links(test, sink, cancel), &cancel).await;
        for event in events {
            if event["t"] != "result" {
                continue;
            }
            let key = event["key"].as_str().unwrap_or_default().to_string();
            let Some((link, origin)) = origins.get(&key) else { continue };
            let delay = event["delay_ms"].as_i64().unwrap_or(-1);
            if delay < 0 {
                let _ = tx.send(FinderEvent::Failed { key });
                continue;
            }
            let Ok(candidate) = zero_discovery::link::parse_candidate(link) else { continue };
            alive += 1;
            let _ = tx.send(FinderEvent::Alive {
                info: candidate.info,
                delay_ms: delay as u32,
                origin: *origin,
            });
        }
    }
    if cancel.is_cancelled() {
        let _ = tx.send(FinderEvent::Done { alive, reason: "cancelled".into() });
        return;
    }
    if alive >= want {
        let _ = tx.send(FinderEvent::Done { alive, reason: "enough".into() });
        return;
    }

    // ---- 2. search the public feeds
    let discover = DiscoverRequest {
        sources: request.sources.clone(),
        cache_dir: request.cache_dir.as_ref().map(|dir| dir.join("feeds")),
        exclude_keys: tested,
        want_alive: want - alive,
        max_seconds: request.max_seconds,
        tcp_concurrency: 256,
        tcp_timeout_ms: 1500,
        tcp_stop_after_open: 1500,
        real_concurrency: 48,
        real_timeout_ms: 3000,
        probe_url: PROBE_URL.into(),
        next_tier_if_alive_below: want.min(3),
        fetch: true,
        ..DiscoverRequest::default()
    };
    let forward = {
        let tx = tx.clone();
        let found = Arc::new(Mutex::new(0usize));
        let counter = Arc::clone(&found);
        let callback = move |event: Value| {
            match event["t"].as_str() {
                Some("stage") => {
                    let _ = tx.send(FinderEvent::Stage(event["stage"].as_str().unwrap_or_default().into()));
                }
                Some("progress") => {
                    let n = |k: &str| event[k].as_u64().unwrap_or(0) as usize;
                    let _ = tx.send(FinderEvent::Progress(Progress {
                        candidates: n("candidates"),
                        tcp_done: n("tcp_done"),
                        tcp_open: n("tcp_open"),
                        real_done: n("real_done"),
                        alive: n("alive"),
                    }));
                }
                Some("alive") => {
                    if let Ok(info) = serde_json::from_value::<LinkInfoWire>(event["info"].clone()) {
                        *counter.lock().unwrap_or_else(|p| p.into_inner()) += 1;
                        let _ = tx.send(FinderEvent::Alive {
                            info: info.into(),
                            delay_ms: event["delay_ms"].as_u64().unwrap_or(0) as u32,
                            origin: Origin::Found,
                        });
                    }
                }
                Some("error") => {
                    let _ = tx.send(FinderEvent::Note(event["message"].as_str().unwrap_or_default().into()));
                }
                _ => {}
            }
        };
        (found, callback)
    };
    let (found, callback) = forward;
    let reason = stream(
        move |sink, cancel| async move { zero_discovery::discover(discover, sink, cancel).await.as_str().to_string() },
        callback,
        &cancel,
    )
    .await;
    alive += *found.lock().unwrap_or_else(|p| p.into_inner());
    let _ = tx.send(FinderEvent::Done { alive, reason });
}

/// `LinkInfo` as it crosses the event stream (it is `Serialize` only).
#[derive(serde::Deserialize)]
struct LinkInfoWire {
    key: String,
    link: String,
    name: String,
    protocol: String,
    transport: String,
    security: String,
    host: String,
    port: u16,
    country: String,
    class: String,
}

impl From<LinkInfoWire> for LinkInfo {
    fn from(w: LinkInfoWire) -> Self {
        LinkInfo {
            key: w.key,
            link: w.link,
            name: w.name,
            protocol: w.protocol,
            transport: w.transport,
            security: w.security,
            host: w.host,
            port: w.port,
            country: w.country,
            class: w.class,
        }
    }
}

/// Run a job that writes to an event sink and collect every event.
async fn collect<F, Fut>(job: F, cancel: &CancellationToken) -> Vec<Value>
where
    F: FnOnce(zero_discovery::EventSink, CancellationToken) -> Fut,
    Fut: std::future::Future<Output = zero_discovery::EndReason>,
{
    let store: Arc<Mutex<Vec<Value>>> = Arc::default();
    let sink_store = Arc::clone(&store);
    stream(
        move |sink, cancel| async move {
            job(sink, cancel).await;
        },
        move |event| sink_store.lock().unwrap_or_else(|p| p.into_inner()).push(event),
        cancel,
    )
    .await;
    let events = std::mem::take(&mut *store.lock().unwrap_or_else(|p| p.into_inner()));
    events
}

/// Run a job that writes to an event sink, handing each event to `on_event`
/// as it arrives. Returns the job's own result once every event is delivered.
async fn stream<F, Fut, T, E>(job: F, on_event: E, cancel: &CancellationToken) -> T
where
    F: FnOnce(zero_discovery::EventSink, CancellationToken) -> Fut,
    Fut: std::future::Future<Output = T>,
    E: Fn(Value) + Send + Sync + 'static,
{
    let callback: zero_discovery::EventCallback = Arc::new(move |batch: String| {
        for line in batch.lines() {
            if let Ok(event) = serde_json::from_str::<Value>(line) {
                on_event(event);
            }
        }
    });
    let (sink, flusher) = zero_discovery::batching_sink(callback);
    let result = job(sink, cancel.child_token()).await;
    // The job's sink handles are gone; the flusher delivers the rest and ends.
    let _ = flusher.await;
    result
}

/// Results worth reporting from one search, public servers only.
#[derive(Debug, Default, Clone)]
pub struct Tally {
    results: HashMap<String, TestResult>,
}

impl Tally {
    pub fn ok(&mut self, key: &str, ms: u32) {
        self.results.insert(key.into(), TestResult { id: key.into(), ok: true, ms });
    }

    /// A failure never overwrites a success seen in the same search.
    pub fn failed(&mut self, key: &str) {
        self.results
            .entry(key.into())
            .or_insert(TestResult { id: key.into(), ok: false, ms: 0 });
    }

    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    pub fn len(&self) -> usize {
        self.results.len()
    }

    pub fn take(&mut self) -> Vec<TestResult> {
        std::mem::take(&mut self.results).into_values().collect()
    }
}

/// Send one search's results, anonymously. `through_tunnel` says the report
/// leaves through the running tunnel, where the relay would see the VPN
/// server rather than this network: then it is filed under `any`.
/// Returns the network the relay filed a direct report under (`asn:…`), to
/// read crowd picks for next time.
pub async fn report(
    cache_dir: Option<PathBuf>,
    nonce: String,
    through_tunnel: bool,
    results: Vec<TestResult>,
) -> Result<Option<String>, String> {
    if results.is_empty() {
        return Ok(None);
    }
    let cache = cache_dir.map(|dir| dir.join("rankings.json"));
    let rankings = crowd_client::fetch_rankings(cache.as_deref(), Duration::from_secs(6))
        .await
        .ok_or("crowd rankings unavailable, so no relay is known")?;
    let net = through_tunnel.then_some(zero_discovery::crowd::ANY_NET);
    let answered = crowd_client::report(&rankings.relays, &nonce, net, &results, &[]).await?;
    Ok(answered.filter(|net| !through_tunnel && net.starts_with("asn:")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_does_not_undo_a_success() {
        let mut tally = Tally::default();
        tally.ok("a", 120);
        tally.failed("a");
        tally.failed("b");
        let mut results = tally.take();
        results.sort_by(|x, y| x.id.cmp(&y.id));
        assert_eq!(results, vec![
            TestResult { id: "a".into(), ok: true, ms: 120 },
            TestResult { id: "b".into(), ok: false, ms: 0 },
        ]);
        assert!(tally.is_empty());
    }

    #[tokio::test]
    async fn a_search_with_nothing_to_search_ends_at_once() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let request = FinderRequest {
            sources: Vec::new(),
            use_crowd: false,
            max_seconds: 5,
            ..FinderRequest::default()
        };
        run(request, tx, CancellationToken::new()).await;
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        assert!(matches!(events.last(), Some(FinderEvent::Done { alive: 0, .. })), "{events:?}");
    }

    #[tokio::test]
    async fn a_cancelled_search_says_so() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let request = FinderRequest {
            history: vec!["vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=none#x".into()],
            use_crowd: false,
            ..FinderRequest::default()
        };
        run(request, tx, cancel).await;
        let mut last = None;
        while let Ok(event) = rx.try_recv() {
            last = Some(event);
        }
        assert_eq!(last, Some(FinderEvent::Done { alive: 0, reason: "cancelled".into() }));
    }
}
