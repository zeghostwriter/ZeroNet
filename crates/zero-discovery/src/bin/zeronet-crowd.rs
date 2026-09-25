//! `zeronet-crowd` — builds `rankings.json` from the relay's report export.
//!
//! Run by the `crowd` GitHub Action:
//!
//! ```text
//! zeronet-crowd --reports reports.json --sources sources.json \
//!               --out rankings.json [--relays https://a,https://b]
//! ```
//!
//! It fetches every public feed in `sources.json` itself, so it knows which
//! servers are public and what their links are (see `zero_discovery::crowd`),
//! then ranks the reports. It refuses to write a file when no feed could be
//! fetched: an empty ranking would tell every app that nothing works.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zero_discovery::crowd::{self, Report};
use zero_discovery::feed::{fetch_feed, FeedSource};

struct Args {
    reports: PathBuf,
    sources: PathBuf,
    out: PathBuf,
    relays: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut reports = None;
    let mut sources = None;
    let mut out = None;
    let mut relays = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--reports" => reports = Some(PathBuf::from(value()?)),
            "--sources" => sources = Some(PathBuf::from(value()?)),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--relays" => {
                relays = value()?
                    .split(',')
                    .map(str::trim)
                    .filter(|r| r.starts_with("https://"))
                    .map(str::to_string)
                    .collect()
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(Args {
        reports: reports.ok_or("--reports is required")?,
        sources: sources.ok_or("--sources is required")?,
        out: out.ok_or("--out is required")?,
        relays,
    })
}

fn main() {
    if let Err(e) = run() {
        eprintln!("zeronet-crowd: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let _ = rustls::crypto::ring::default_provider().install_default();

    let reports: Vec<Report> = {
        let text = std::fs::read_to_string(&args.reports)
            .map_err(|e| format!("cannot read {}: {e}", args.reports.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("reports are not valid JSON: {e}"))?
    };
    let sources: Vec<FeedSource> = {
        let text = std::fs::read_to_string(&args.sources)
            .map_err(|e| format!("cannot read {}: {e}", args.sources.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("sources are not valid JSON: {e}"))?
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the runtime: {e}"))?;
    let bodies: Vec<String> = runtime.block_on(async {
        let fetches = sources
            .iter()
            .map(|source| fetch_feed(source, None, Duration::from_secs(60)));
        futures::future::join_all(fetches)
            .await
            .into_iter()
            .zip(&sources)
            .filter_map(|(result, source)| {
                eprintln!("feed {}: {}", source.id, result.status.as_str());
                result.body
            })
            .collect()
    });
    if bodies.is_empty() {
        return Err("no feed could be fetched; not publishing".into());
    }
    let known = crowd::known_servers(bodies.iter().map(String::as_str));
    eprintln!("{} public servers, {} reports", known.len(), reports.len());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;
    let rankings = crowd::aggregate(&reports, &known, args.relays, now);
    for (net, ranking) in &rankings.nets {
        eprintln!(
            "{net}: {} servers, {} clean addresses",
            ranking.servers.len(),
            ranking.clean_ips.len()
        );
    }
    let json = serde_json::to_string(&rankings).map_err(|e| e.to_string())?;
    std::fs::write(&args.out, json).map_err(|e| format!("cannot write {}: {e}", args.out.display()))
}
