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
//! for two weeks is forgotten. Each channel is read back to the newest post
//! the last run saw (at least its latest two pages), so every config posted
//! in between is tested.
//!
//! With `--github-state` it also looks on GitHub for repositories that
//! publish config lists and were pushed to in the last few days (see
//! `zero_discovery::github`): the files it picks are tested with everything
//! else, and the state file remembers, per file, how many of its servers
//! worked, so the useful ones are read first and the dead ones dropped. Set
//! `GITHUB_TOKEN` for the search: GitHub allows very few searches without one.
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
//!
//! The `fresh` workflow runs it every ten minutes on just the channels
//! listed under `priority` in telegram-channels.json:
//!
//! ```text
//! zeronet-harvest --channel radvpne --channel ciaconfig \
//!                 --telegram-state fresh-state.json --retest old-fresh.txt \
//!                 --out fresh.txt --want 300 --min 0 --minutes 5
//! ```
//!
//! which tests every config those channels posted since the last run (and
//! those already at the top, again), then puts what works at the top of the
//! published list:
//!
//! ```text
//! zeronet-harvest merge --top fresh.txt --drop old-fresh.txt \
//!                       --rest verified.txt --out verified.txt
//! ```

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
    /// Channels read directly, without the crawl. With `--telegram-state`
    /// they are read back to where the last run stopped.
    channels: Vec<String>,
    /// Lists whose configs are tested again (the fresh list's last top).
    retest: Vec<PathBuf>,
    /// Where the GitHub files found so far are remembered; GitHub is only
    /// searched when this is given.
    github_state: Option<PathBuf>,
    /// Most GitHub files read in one run.
    github_max: usize,
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
        channels: Vec::new(),
        retest: Vec::new(),
        github_state: None,
        github_max: 30,
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
            "--channel" => args.channels.push(value()?.to_ascii_lowercase()),
            "--retest" => args.retest.push(PathBuf::from(value()?)),
            "--github-state" => args.github_state = Some(PathBuf::from(value()?)),
            "--github-max" => {
                args.github_max = value()?
                    .parse()
                    .map_err(|_| "--github-max takes a number")?
            }
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
    if args.sources.is_empty()
        && args.telegram.is_none()
        && args.channels.is_empty()
        && args.github_state.is_none()
    {
        return Err(
            "at least one --sources, --telegram, --channel or --github-state is required".into(),
        );
    }
    if args.telegram.is_some() && !args.channels.is_empty() {
        // Both would keep their state in the one --telegram-state file.
        return Err("use --telegram or --channel, not both".into());
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
    let result = if std::env::args().nth(1).as_deref() == Some("merge") {
        merge(std::env::args().skip(2))
    } else {
        run()
    };
    if let Err(e) = result {
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

    let mut telegram_links = match &args.telegram {
        Some(seeds) => runtime.block_on(crawl_telegram(
            seeds,
            args.telegram_state.as_deref(),
            args.telegram_max,
        ))?,
        None => Vec::new(),
    };
    if !args.channels.is_empty() {
        telegram_links.extend(runtime.block_on(read_channels(
            &args.channels,
            args.telegram_state.as_deref(),
        ))?);
    }
    let mut github = match &args.github_state {
        Some(path) => {
            let known: HashSet<String> = sources.iter().map(|s| s.url.clone()).collect();
            let found = runtime.block_on(crawl_github(path, args.github_max, &known))?;
            for file in &found.files {
                telegram_links.extend(file.links.iter().cloned());
            }
            Some(found)
        }
        None => None,
    };
    for path in &args.retest {
        // Missing on the first run.
        if let Ok(text) = std::fs::read_to_string(path) {
            telegram_links.extend(zero_discovery::link::extract_links(&text));
        }
    }

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
    // Before the size check: what the GitHub files gave is worth keeping
    // even from a run that does not publish.
    if let (Some(github), Some(path)) = (github.as_mut(), &args.github_state) {
        github.settle(&found, path)?;
    }
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
    /// The newest post read. The next run reads back to it, however many
    /// pages that takes, so no config posted in between goes untested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_post: Option<u64>,
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
    /// Channels that post good configs often: the `fresh` workflow reads
    /// them every ten minutes and puts what works at the top of the list.
    /// The crawl treats them as seeds too.
    #[serde(default)]
    priority: Vec<String>,
    /// Channels that list other channels (MahsaNet's monthly donor lists).
    #[serde(default)]
    directories: Vec<String>,
}

/// Pages read per channel at least (about 20 posts each).
const CHANNEL_PAGES: usize = 2;
/// Pages read at most when catching up with a channel's posts since the
/// last run: a channel that posted more than that is read this far back.
const MAX_PAGES: usize = 50;
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
    // The seed list first, so the crawl's cap never crowds out a channel
    // someone picked by hand.
    for name in seeds
        .directories
        .iter()
        .chain(&seeds.channels)
        .chain(&seeds.priority)
    {
        enqueue(name.clone(), &mut queue);
    }
    // Then what the directories list: channels such as mahsa_net that list
    // other channels (their monthly donors) rather than only posting configs.
    // Every name they list is worth one look, whatever it is called.
    for directory in &seeds.directories {
        let Some(ChannelPage {
            text, mentioned, ..
        }) = read_channel(directory, None, DIRECTORY_PAGES).await
        else {
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
    for (name, state) in &previous.channels {
        if now - state.seen < FORGET_AFTER_SECS {
            enqueue(name.clone(), &mut queue);
        }
    }

    let seed_set: HashSet<String> = seeds
        .directories
        .iter()
        .chain(&seeds.channels)
        .chain(&seeds.priority)
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
        let pages = futures::future::join_all(batch.iter().map(|name| {
            let since = previous.channels.get(name).and_then(|c| c.last_post);
            read_channel(name, since, CHANNEL_PAGES)
        }))
        .await;
        for (name, page) in batch.iter().zip(pages) {
            let Some(ChannelPage {
                text,
                links: found,
                mentioned,
                newest,
            }) = page
            else {
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
            eprintln!(
                "telegram {name}: {} links (persian {persian}, seed {is_seed})",
                found.len()
            );
            state.channels.insert(
                name.clone(),
                ChannelState {
                    seen: now,
                    configs: found.len(),
                    last_post: newest,
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

/// Every share link `names` posted since the last run (their latest page
/// the first time), which `state_path` remembers. An error only when none
/// of them could be read: then Telegram, not the channels, is at fault,
/// and the list at the top should stay as it is.
async fn read_channels(
    names: &[String],
    state_path: Option<&std::path::Path>,
) -> Result<Vec<String>, String> {
    let mut state: TelegramState = state_path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;
    let pages = futures::future::join_all(names.iter().map(|name| {
        let since = state.channels.get(name).and_then(|c| c.last_post);
        read_channel(name, since, 1)
    }))
    .await;
    let mut links = Vec::new();
    let mut read = 0usize;
    for (name, page) in names.iter().zip(pages) {
        let Some(page) = page else {
            eprintln!("telegram {name}: unreadable");
            continue;
        };
        eprintln!(
            "telegram {name}: {} links, up to post {:?}",
            page.links.len(),
            page.newest
        );
        read += 1;
        // Left as it is when nothing new was posted, so a quiet run
        // changes nothing and publishes nothing.
        let known = state.channels.get(name).and_then(|c| c.last_post);
        if page.newest.is_some() && page.newest != known {
            state.channels.insert(
                name.clone(),
                ChannelState {
                    seen: now,
                    configs: page.links.len(),
                    last_post: page.newest,
                },
            );
        }
        links.extend(page.links);
    }
    if read == 0 {
        return Err("no channel could be read; not publishing".into());
    }
    if let Some(path) = state_path {
        let json = serde_json::to_string_pretty(&state).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    Ok(links)
}

/// Days back the GitHub search looks for pushes.
const GITHUB_SINCE_DAYS: i64 = 3;
/// Share links read from one GitHub file at most: a list of tens of
/// thousands is mostly old entries, and the test budget is shared.
const GITHUB_LINKS_PER_FILE: usize = 1500;
/// GitHub requests at once.
const GITHUB_CONCURRENCY: usize = 8;

/// One GitHub file read in this run.
struct GithubFile {
    url: String,
    links: Vec<String>,
    /// The servers (`host:port`) its links name, to credit it with the ones
    /// that work.
    servers: HashSet<String>,
}

/// The GitHub side of one run: the state as read, and the files read.
struct GithubRun {
    state: zero_discovery::github::GithubState,
    files: Vec<GithubFile>,
    now: i64,
}

impl GithubRun {
    /// Credit every file with the working servers it listed, forget what has
    /// gone quiet, and write the state to `path`.
    fn settle(&mut self, found: &[Found], path: &std::path::Path) -> Result<(), String> {
        let working: HashSet<String> = found.iter().filter_map(|f| server_of(&f.link)).collect();
        for file in &self.files {
            let alive = file.servers.intersection(&working).count();
            eprintln!("github {}: {alive} working servers", file.url);
            self.state.record(&file.url, alive, self.now);
        }
        self.state.keep(self.now);
        let json = serde_json::to_string_pretty(&self.state).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| format!("cannot write {}: {e}", path.display()))
    }
}

/// A GitHub API request, with the workflow's token when there is one.
async fn github_api(url: &str) -> Option<String> {
    let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
    let auth = token.map(|t| format!("Bearer {t}"));
    let mut headers = vec![("X-GitHub-Api-Version", "2022-11-28")];
    if let Some(auth) = auth.as_deref() {
        headers.push(("Authorization", auth));
    }
    let limits = zero_net::FetchLimits {
        max_bytes: 16 * 1024 * 1024,
        timeout: Duration::from_secs(30),
        max_redirects: 0,
    };
    match zero_net::send_with_headers("GET", url, "application/json", &headers, b"", &limits).await
    {
        Ok(body) => Some(String::from_utf8_lossy(&body).into_owned()),
        Err(error) => {
            eprintln!("github api {url}: {error}");
            None
        }
    }
}

/// `YYYY-MM-DD` for a Unix day number (days since 1970-01-01), in the
/// proleptic Gregorian calendar (Howard Hinnant's `civil_from_days`).
fn civil_date(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Search GitHub for config repositories pushed to lately, pick the lists in
/// the ones not looked into before, and read every remembered file (the
/// best `max` of them). Files already in `known` (the hand-kept source
/// lists) are left to those lists.
async fn crawl_github(
    state_path: &std::path::Path,
    max: usize,
    known: &HashSet<String>,
) -> Result<GithubRun, String> {
    use zero_discovery::github;
    let mut state: github::GithubState = std::fs::read_to_string(state_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;
    let since = civil_date(now / 86_400 - GITHUB_SINCE_DAYS);
    // This repository publishes the tested list itself; reading it back
    // would only test its own output again.
    let own = std::env::var("GITHUB_REPOSITORY")
        .unwrap_or_default()
        .to_ascii_lowercase();

    let mut repos: Vec<github::Repo> = Vec::new();
    for query in github::QUERIES {
        let Some(body) = github_api(&github::search_url(query, &since)).await else {
            continue;
        };
        let found = github::parse_search(&body);
        eprintln!("github search {query:?}: {} repositories", found.len());
        for repo in found {
            let new = !state.knows_repo(&repo.full_name, now)
                && repo.full_name.to_ascii_lowercase() != own
                && !repos.iter().any(|r| r.full_name == repo.full_name);
            if new {
                repos.push(repo);
            }
        }
    }
    eprintln!("github: {} repositories to look into", repos.len());
    for chunk in repos.chunks(GITHUB_CONCURRENCY) {
        let trees = futures::future::join_all(
            chunk
                .iter()
                .map(|repo| async move { github_api(&github::tree_url(repo)).await }),
        )
        .await;
        for (repo, tree) in chunk.iter().zip(trees) {
            // An unreadable tree is tried again next run.
            let Some(tree) = tree else { continue };
            let files: Vec<String> = github::pick_files(&tree, github::FILES_PER_REPO)
                .iter()
                .map(|path| github::raw_url(repo, path))
                .filter(|url| !known.contains(url))
                .collect();
            eprintln!("github {}: {} lists", repo.full_name, files.len());
            state.add_repo(&repo.full_name, &files, now);
        }
    }

    let urls = state.ranked(max);
    let mut files = Vec::new();
    for chunk in urls.chunks(GITHUB_CONCURRENCY) {
        let bodies = futures::future::join_all(chunk.iter().map(|url| {
            let source = FeedSource {
                id: format!("gh-{}", blake3::hash(url.as_bytes()).to_hex()),
                url: url.clone(),
                tier: 1,
                sig_url: None,
                mirrors: Vec::new(),
            };
            async move {
                fetch_feed(&source, None, Duration::from_secs(60))
                    .await
                    .body
            }
        }))
        .await;
        for (url, body) in chunk.iter().zip(bodies) {
            let Some(body) = body else {
                eprintln!("github {url}: unreadable");
                continue;
            };
            let mut links = zero_discovery::link::extract_links(&body);
            links.truncate(GITHUB_LINKS_PER_FILE);
            let servers = links.iter().filter_map(|l| server_of(l)).collect();
            files.push(GithubFile {
                url: url.clone(),
                links,
                servers,
            });
        }
    }
    eprintln!(
        "github: {} files read, {} links",
        files.len(),
        files.iter().map(|f| f.links.len()).sum::<usize>()
    );
    Ok(GithubRun { state, files, now })
}

/// `merge --top A --rest B [--drop C] --out D`: A's links, then B's, less
/// any of B's whose server is in A or C. C is the previous top: its servers
/// that are no longer in A stopped working or were no longer posted.
fn merge(args: impl Iterator<Item = String>) -> Result<(), String> {
    let (mut top, mut rest, mut drop, mut out) = (None, None, None, None);
    let mut it = args;
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--top" => top = Some(value),
            "--rest" => rest = Some(value),
            "--drop" => drop = Some(value),
            "--out" => out = Some(value),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let read = |path: Option<String>| -> Result<String, String> {
        match path {
            Some(p) => std::fs::read_to_string(&p).map_err(|e| format!("cannot read {p}: {e}")),
            None => Ok(String::new()),
        }
    };
    let top = read(Some(top.ok_or("--top is required")?))?;
    let rest = read(Some(rest.ok_or("--rest is required")?))?;
    let drop = read(drop)?;
    let out = out.ok_or("--out is required")?;
    let text = merged(&top, &rest, &drop);
    std::fs::write(&out, &text).map_err(|e| format!("cannot write {out}: {e}"))?;
    eprintln!("{} configs written to {out}", text.lines().count());
    Ok(())
}

/// The server a link names, or `None` for a line that is not a config.
fn server_of(link: &str) -> Option<String> {
    let info = zero_discovery::link::parse_candidate(link).ok()?.info;
    Some(format!("{}:{}", info.host, info.port))
}

fn merged(top: &str, rest: &str, drop: &str) -> String {
    let mut servers: HashSet<String> = drop.lines().filter_map(server_of).collect();
    let mut lines = Vec::new();
    for link in top.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some(server) = server_of(link) else {
            continue;
        };
        if !lines.contains(&link) {
            servers.insert(server);
            lines.push(link);
        }
    }
    for link in rest.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if server_of(link).is_some_and(|server| servers.insert(server)) {
            lines.push(link);
        }
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// Whether to read the page before one whose oldest post is `oldest`,
/// having read `pages` pages: until `min_pages` are read and the post
/// `since` is reached, and while there are older posts.
fn read_further(pages: usize, min_pages: usize, since: Option<u64>, oldest: Option<u64>) -> bool {
    let Some(oldest) = oldest else {
        return false;
    };
    pages < min_pages || since.is_some_and(|since| oldest > since)
}

/// What one read of a channel found.
struct ChannelPage {
    text: String,
    /// The share links in the posts read.
    links: Vec<String>,
    /// The channels the posts mention.
    mentioned: Vec<String>,
    /// The newest post read: where the next read can stop.
    newest: Option<u64>,
}

/// A channel's posts: at least its latest `min_pages` pages, and further
/// back until post `since` (the newest one an earlier run read) is reached,
/// up to [`MAX_PAGES`]. `None` when the channel cannot be read.
async fn read_channel(name: &str, since: Option<u64>, min_pages: usize) -> Option<ChannelPage> {
    let mut html = String::new();
    let mut before = None;
    let mut newest = None;
    let mut complete = true;
    for page_index in 0..MAX_PAGES {
        let source = FeedSource {
            id: format!("tg-{name}"),
            url: telegram::page_url(name, before),
            tier: 1,
            sig_url: None,
            mirrors: Vec::new(),
        };
        let Some(page) = fetch_feed(&source, None, Duration::from_secs(20))
            .await
            .body
        else {
            if page_index == 0 {
                return None;
            }
            // Posts between here and `since` were not read: do not move
            // past them, so the next run tries again.
            complete = false;
            break;
        };
        if page_index == 0 {
            newest = telegram::newest_post(&page, name);
        }
        before = telegram::oldest_post(&page, name);
        html.push_str(&page);
        if !read_further(page_index + 1, min_pages, since, before) {
            break;
        }
        if page_index + 1 == MAX_PAGES {
            eprintln!("telegram {name}: more than {MAX_PAGES} pages since the last run");
        }
    }
    let text = telegram::page_text(&html);
    let links = zero_discovery::link::extract_links(&text);
    let mentioned = telegram::mentions(&html, name);
    Some(ChannelPage {
        text,
        links,
        mentioned,
        newest: if complete { newest } else { since.or(newest) },
    })
}

#[cfg(test)]
mod tests {
    use super::{civil_date, merged, read_further, suits_iran};
    use serde_json::json;

    const A: &str = "trojan://pw@a.example.com:443?security=tls&sni=a.example.com#a";
    const A2: &str = "trojan://other@a.example.com:443?security=tls&sni=a.example.com#a2";
    const B: &str = "trojan://pw@b.example.com:443?security=tls&sni=b.example.com#b";
    const C: &str = "trojan://pw@c.example.com:443?security=tls&sni=c.example.com#c";

    #[test]
    fn unix_days_become_calendar_dates() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(59), "1970-03-01");
        assert_eq!(civil_date(11_016), "2000-02-29");
        assert_eq!(civil_date(20_734), "2026-10-08");
    }

    #[test]
    fn channels_are_read_back_to_the_last_post_seen() {
        // First time: just the minimum.
        assert!(read_further(1, 2, None, Some(900)));
        assert!(!read_further(2, 2, None, Some(880)));
        // Since post 850: on until a page reaches it.
        assert!(read_further(2, 2, Some(850), Some(880)));
        assert!(read_further(1, 1, Some(850), Some(880)));
        assert!(!read_further(1, 1, Some(850), Some(845)));
        assert!(!read_further(3, 2, Some(850), Some(850)));
        // The channel's first post.
        assert!(!read_further(1, 2, Some(850), None));
    }

    #[test]
    fn merge_puts_the_top_first_and_keeps_one_link_per_server() {
        let rest = format!("{B}\n{A2}\n{C}\n");
        assert_eq!(merged(A, &rest, ""), format!("{A}\n{B}\n{C}\n"));
    }

    #[test]
    fn merge_drops_the_previous_top() {
        // C was at the top last time and is not now: it stopped working.
        let rest = format!("{C}\n{B}\n");
        assert_eq!(merged(A, &rest, C), format!("{A}\n{B}\n"));
        // An empty top leaves the rest.
        assert_eq!(merged("\n", B, ""), format!("{B}\n"));
    }

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
