//! `zeronet-harvest` — finds working public configs for the app to try
//! first.
//!
//! Run by the `harvest` GitHub Action:
//!
//! ```text
//! zeronet-harvest --sources deploy/crowd/sources.json \
//!                 --sources deploy/crowd/harvest-sources.json \
//!                 --telegram deploy/crowd/telegram-channels.json \
//!                 --telegram-state telegram-state.json \
//!                 --out verified.txt [--want 300] [--minutes 20]
//! ```
//!
//! Besides the feeds it reads Iranian Telegram channels that post configs
//! (see `zero_discovery::telegram`): the seed list, the channels an earlier
//! run found (`--telegram-state`, updated in place), every channel named in
//! a directory channel's lists (MahsaNet's monthly donor thank-yous), and
//! channels those mention whose names are about VPNs or configs. A channel
//! counts only if
//! its page is in Persian and it posts configs; one that has posted none
//! for two weeks is forgotten.
//!
//! Fetches every feed, then runs the same staged search the app runs (TCP,
//! then a real request through the server with TLS confirmed) until it has
//! `--want` working configs or runs out of time. Only configs whose traffic
//! is encrypted and looks like ordinary HTTPS are kept (REALITY, TLS, TLS
//! behind a CDN, and QUIC-based Hysteria2/TUIC); plain ones are what DPI
//! blocks first and carry the user's traffic in the clear. One config per
//! server address. The output is a plain list of share links, fastest first
//! within each family, families interleaved, so a client testing from the
//! top meets every kind of server early.
//!
//! These tests run from GitHub's machines, not from inside Iran: a config
//! on the list is alive and really relays traffic, which weeds out the
//! great majority of dead feed entries, but whether a given ISP lets it
//! through is what the crowd rankings and the app's own tests settle.
//!
//! Refuses to write a list shorter than `--min`: a bad run must not replace
//! a good list with an empty one.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use zero_discovery::feed::{fetch_feed, FeedSource};
use zero_discovery::telegram;
use zero_discovery::{batching_sink, discover, DiscoverRequest};

struct Args {
    sources: Vec<PathBuf>,
    telegram: Option<PathBuf>,
    telegram_state: Option<PathBuf>,
    telegram_max: usize,
    out: PathBuf,
    want: usize,
    min: usize,
    minutes: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        sources: Vec::new(),
        telegram: None,
        telegram_state: None,
        telegram_max: 150,
        out: PathBuf::new(),
        want: 300,
        min: 20,
        minutes: 20,
    };
    let mut out = None;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--sources" => args.sources.push(PathBuf::from(value()?)),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--telegram" => args.telegram = Some(PathBuf::from(value()?)),
            "--telegram-state" => args.telegram_state = Some(PathBuf::from(value()?)),
            "--telegram-max" => {
                args.telegram_max = value()?
                    .parse()
                    .map_err(|_| "--telegram-max takes a number")?
            }
            "--want" => args.want = value()?.parse().map_err(|_| "--want takes a number")?,
            "--min" => args.min = value()?.parse().map_err(|_| "--min takes a number")?,
            "--minutes" => {
                args.minutes = value()?.parse().map_err(|_| "--minutes takes a number")?
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if args.sources.is_empty() {
        return Err("at least one --sources file is required".into());
    }
    args.out = out.ok_or("--out is required")?;
    Ok(args)
}

/// Whether a config's traffic is encrypted and looks like ordinary HTTPS.
fn suits_iran(info: &serde_json::Value) -> bool {
    let security = info["security"].as_str().unwrap_or("");
    let protocol = info["protocol"].as_str().unwrap_or("");
    matches!(security, "tls" | "reality") || matches!(protocol, "hysteria2" | "tuic")
}

struct Found {
    link: String,
    class: String,
    delay: u64,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("zeronet-harvest: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut sources: Vec<FeedSource> = Vec::new();
    for path in &args.sources {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let list: Vec<FeedSource> = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not a source list: {e}", path.display()))?;
        sources.extend(list);
    }
    // Every feed at once: the search is not trying to stop early here.
    for source in &mut sources {
        source.tier = 1;
    }

    let found: Arc<Mutex<Vec<Found>>> = Arc::default();
    let seen: Arc<Mutex<HashSet<String>>> = Arc::default();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the runtime: {e}"))?;

    let telegram_links = match &args.telegram {
        Some(seeds) => runtime.block_on(crawl_telegram(
            seeds,
            args.telegram_state.as_deref(),
            args.telegram_max,
        ))?,
        None => Vec::new(),
    };

    runtime.block_on(async {
        let sink_found = Arc::clone(&found);
        let sink_seen = Arc::clone(&seen);
        let (sink, flusher) = batching_sink(Arc::new(move |batch: String| {
            for line in batch.lines() {
                let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                match event["t"].as_str() {
                    Some("alive") => {
                        let info = &event["info"];
                        if !suits_iran(info) {
                            continue;
                        }
                        // One config per server: feeds list the same
                        // server under many links.
                        let server = format!(
                            "{}:{}",
                            info["host"].as_str().unwrap_or(""),
                            info["port"].as_u64().unwrap_or(0)
                        );
                        if !sink_seen.lock().unwrap().insert(server) {
                            continue;
                        }
                        sink_found.lock().unwrap().push(Found {
                            link: info["link"].as_str().unwrap_or("").to_string(),
                            class: info["class"].as_str().unwrap_or("other").to_string(),
                            delay: event["delay_ms"].as_u64().unwrap_or(u64::MAX),
                        });
                    }
                    Some("source") | Some("stage") => eprintln!("{line}"),
                    Some("error") => eprintln!("error: {}", event["message"]),
                    Some("done") => eprintln!("{line}"),
                    _ => {}
                }
            }
        }));
        let request = DiscoverRequest {
            sources,
            extra_links: telegram_links,
            cache_dir: None,
            want_alive: args.want.saturating_mul(3),
            max_seconds: args.minutes * 60,
            tcp_concurrency: 512,
            tcp_timeout_ms: 3000,
            tcp_stop_after_open: usize::MAX,
            real_concurrency: 96,
            real_timeout_ms: 6000,
            confirm_timeout_ms: 8000,
            next_tier_if_alive_below: usize::MAX,
            fetch_timeout_ms: 60_000,
            ..DiscoverRequest::default()
        };
        let cancel = CancellationToken::new();
        let watchdog = {
            let cancel = cancel.clone();
            let limit = Duration::from_secs(args.minutes * 60 + 60);
            tokio::spawn(async move {
                tokio::time::sleep(limit).await;
                cancel.cancel();
            })
        };
        let reason = discover(request, sink, cancel).await;
        watchdog.abort();
        let _ = flusher.await;
        eprintln!("search ended: {reason:?}");
    });

    let mut found = std::mem::take(&mut *found.lock().unwrap());
    found.retain(|f| !f.link.is_empty());
    if found.len() < args.min {
        return Err(format!(
            "only {} working configs found (need {}); not publishing",
            found.len(),
            args.min
        ));
    }

    // Fastest first within each family, then the families interleaved.
    let mut by_class: BTreeMap<String, Vec<Found>> = BTreeMap::new();
    for f in found {
        by_class.entry(f.class.clone()).or_default().push(f);
    }
    for list in by_class.values_mut() {
        list.sort_by_key(|f| f.delay);
        list.reverse(); // pop() takes from the end
    }
    let mut ordered = Vec::new();
    while ordered.len() < args.want && by_class.values().any(|l| !l.is_empty()) {
        for list in by_class.values_mut() {
            if let Some(f) = list.pop() {
                ordered.push(f);
            }
        }
    }
    ordered.truncate(args.want);
    for (class, count) in ordered
        .iter()
        .fold(BTreeMap::<&str, usize>::new(), |mut m, f| {
            *m.entry(f.class.as_str()).or_default() += 1;
            m
        })
    {
        eprintln!("{class}: {count}");
    }

    let mut text = ordered
        .iter()
        .map(|f| f.link.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    text.push('\n');
    std::fs::write(&args.out, text)
        .map_err(|e| format!("cannot write {}: {e}", args.out.display()))?;
    eprintln!(
        "{} configs written to {}",
        ordered.len(),
        args.out.display()
    );
    Ok(())
}

/// What the harvest remembers about a channel between runs.
#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
struct ChannelState {
    /// Unix seconds of the last run that found configs there.
    seen: i64,
    /// Configs found on that run.
    configs: usize,
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
struct TelegramState {
    #[serde(default)]
    channels: BTreeMap<String, ChannelState>,
}

/// deploy/crowd/telegram-channels.json.
#[derive(Debug, Default, serde::Deserialize)]
struct Seeds {
    /// Channels known to post configs.
    #[serde(default)]
    channels: Vec<String>,
    /// Channels that list other channels (MahsaNet's monthly donor lists).
    #[serde(default)]
    directories: Vec<String>,
}

/// Pages read per channel (about 20 posts each).
const CHANNEL_PAGES: usize = 2;
/// Pages read per directory: enough to reach the last monthly list.
const DIRECTORY_PAGES: usize = 6;
/// A channel that has posted no configs for this long is forgotten.
const FORGET_AFTER_SECS: i64 = 14 * 24 * 3600;
/// Channels fetched at once: polite to Telegram, quick enough.
const TELEGRAM_CONCURRENCY: usize = 6;

/// Read the seed channels and those an earlier run found, follow mentions
/// to new ones, and return every share link the Persian ones posted.
/// Writes the updated channel list back to `state_path`.
async fn crawl_telegram(
    seeds_path: &std::path::Path,
    state_path: Option<&std::path::Path>,
    max: usize,
) -> Result<Vec<String>, String> {
    let seeds: Seeds = serde_json::from_str(
        &std::fs::read_to_string(seeds_path)
            .map_err(|e| format!("cannot read {}: {e}", seeds_path.display()))?,
    )
    .map_err(|e| format!("{} is not a channel list: {e}", seeds_path.display()))?;
    let previous: TelegramState = state_path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;

    let mut queue: VecDeque<String> = VecDeque::new();
    let mut queued: HashSet<String> = HashSet::new();
    let mut enqueue = |name: String, queue: &mut VecDeque<String>| {
        let name = name.to_ascii_lowercase();
        if telegram::valid_channel(&name) && queued.insert(name.clone()) {
            queue.push_back(name);
        }
    };
    // Directories first: channels such as mahsa_net that list other
    // channels (their monthly donors) rather than only posting configs.
    // Every name they list is worth one look, whatever it is called.
    for directory in &seeds.directories {
        let Some((text, _, mentioned)) = read_channel(directory, DIRECTORY_PAGES).await else {
            eprintln!("telegram directory {directory}: unreadable");
            continue;
        };
        let listed = telegram::listed_names(&text);
        eprintln!(
            "telegram directory {directory}: {} listed, {} mentioned",
            listed.len(),
            mentioned.len()
        );
        for name in listed.into_iter().chain(mentioned) {
            enqueue(name, &mut queue);
        }
    }
    for name in seeds.directories.iter().chain(&seeds.channels) {
        enqueue(name.clone(), &mut queue);
    }
    for (name, state) in &previous.channels {
        if now - state.seen < FORGET_AFTER_SECS {
            enqueue(name.clone(), &mut queue);
        }
    }

    let seed_set: HashSet<String> = seeds
        .directories
        .iter()
        .chain(&seeds.channels)
        .map(|s| s.to_ascii_lowercase())
        .collect();

    let mut state = TelegramState::default();
    let mut links: Vec<String> = Vec::new();
    let mut visited = 0usize;
    while !queue.is_empty() && visited < max {
        let batch: Vec<String> = (0..TELEGRAM_CONCURRENCY)
            .filter_map(|_| queue.pop_front())
            .take(max - visited)
            .collect();
        visited += batch.len();
        let pages =
            futures::future::join_all(batch.iter().map(|name| read_channel(name, CHANNEL_PAGES)))
                .await;
        for (name, page) in batch.iter().zip(pages) {
            let Some((text, found, mentioned)) = page else {
                continue;
            };
            let is_seed = seed_set.contains(name);
            let persian = telegram::persian_score(&text);
            if (!is_seed && persian < telegram::PERSIAN_MIN) || found.is_empty() {
                eprintln!(
                    "telegram {name}: skipped (persian {persian}, seed {is_seed}, {} links)",
                    found.len()
                );
                continue;
            }
            eprintln!("telegram {name}: {} links (persian {persian}, seed {is_seed})", found.len());
            state.channels.insert(
                name.clone(),
                ChannelState {
                    seen: now,
                    configs: found.len(),
                },
            );
            links.extend(found);
            for other in mentioned {
                if telegram::looks_like_config_channel(&other) {
                    enqueue(other, &mut queue);
                }
            }
        }
    }
    // Channels that had nothing this time are kept until they are stale.
    for (name, old) in previous.channels {
        if now - old.seen < FORGET_AFTER_SECS {
            state.channels.entry(name).or_insert(old);
        }
    }
    eprintln!(
        "telegram: {visited} channels read, {} kept, {} links",
        state.channels.len(),
        links.len()
    );
    if let Some(path) = state_path {
        let json = serde_json::to_string_pretty(&state).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    Ok(links)
}

/// A channel's latest `pages` pages: their text, the share links in them
/// and the channels they mention. `None` when the channel cannot be read.
async fn read_channel(name: &str, pages: usize) -> Option<(String, Vec<String>, Vec<String>)> {
    let mut html = String::new();
    let mut before = None;
    for _ in 0..pages {
        let source = FeedSource {
            id: format!("tg-{name}"),
            url: telegram::page_url(name, before),
            tier: 1,
            sig_url: None,
        };
        let page = fetch_feed(&source, None, Duration::from_secs(20))
            .await
            .body?;
        before = telegram::oldest_post(&page, name);
        html.push_str(&page);
        if before.is_none() {
            break;
        }
    }
    let text = telegram::page_text(&html);
    let links = zero_discovery::link::extract_links(&text);
    let mentioned = telegram::mentions(&html, name);
    Some((text, links, mentioned))
}

#[cfg(test)]
mod tests {
    use super::suits_iran;
    use serde_json::json;

    #[test]
    fn only_encrypted_configs_are_kept() {
        assert!(suits_iran(
            &json!({"security": "reality", "protocol": "vless"})
        ));
        assert!(suits_iran(
            &json!({"security": "tls", "protocol": "trojan"})
        ));
        assert!(suits_iran(
            &json!({"security": "", "protocol": "hysteria2"})
        ));
        assert!(!suits_iran(
            &json!({"security": "none", "protocol": "vless"})
        ));
        assert!(!suits_iran(
            &json!({"security": "", "protocol": "shadowsocks"})
        ));
    }
}
