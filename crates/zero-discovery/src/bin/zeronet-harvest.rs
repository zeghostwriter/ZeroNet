//! `zeronet-harvest` — finds working public configs for the app to try
//! first.
//!
//! Run by the `harvest` GitHub Action:
//!
//! ```text
//! zeronet-harvest --sources deploy/crowd/sources.json \
//!                 --sources deploy/crowd/harvest-sources.json \
//!                 --out verified.txt [--want 300] [--minutes 20]
//! ```
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

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use zero_discovery::feed::FeedSource;
use zero_discovery::{batching_sink, discover, DiscoverRequest};

struct Args {
    sources: Vec<PathBuf>,
    out: PathBuf,
    want: usize,
    min: usize,
    minutes: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        sources: Vec::new(),
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
