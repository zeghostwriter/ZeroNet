//! `zeronet-crowd` — builds `rankings.json` from the relay's report export.
//!
//! Run by the `crowd` GitHub Action:
//!
//! ```text
//! zeronet-crowd --reports reports.json --sources sources.json \
//!               [--sources more.json] --out rankings.json [--relays https://a,https://b]
//! ```
//!
//! It fetches every public feed in `sources.json` itself, so it knows which
//! servers are public and what their links are (see `zero_discovery::crowd`),
//! then ranks the reports. It refuses to write a file when no feed could be
//! fetched, and — given the currently published file with `--previous` — when
//! the new ranking is too thin or has shrunk sharply: an empty or gutted
//! ranking would tell every app that almost nothing works, and it replaces
//! the published one.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zero_discovery::crowd::{self, Report};
use zero_discovery::crowd_client;
use zero_discovery::feed::{fetch_feed, FeedSource};

struct Args {
    reports: PathBuf,
    sources: Vec<PathBuf>,
    out: PathBuf,
    relays: Vec<String>,
    /// The ranking currently published, to compare against before replacing
    /// it. Absent on a first run.
    previous: Option<PathBuf>,
    /// Below this many reports a run is refused when a list is already
    /// published. One by default, so a completely empty export never wipes
    /// the list; raise it on a relay that carries steady traffic.
    min_reports: usize,
    /// Publish even when the guards object.
    force: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut reports = None;
    let mut sources = Vec::new();
    let mut out = None;
    let mut relays = Vec::new();
    let mut previous = None;
    let mut min_reports = 1usize;
    let mut force = false;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--reports" => reports = Some(PathBuf::from(value()?)),
            "--sources" => sources.push(PathBuf::from(value()?)),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--previous" => previous = Some(PathBuf::from(value()?)),
            "--force" => force = true,
            "--min-reports" => {
                min_reports = value()?
                    .parse()
                    .map_err(|_| "--min-reports needs a number".to_string())?;
            }
            "--relays" => {
                for relay in value()?.split(',').map(str::trim) {
                    // The same relay can come from the Cloudflare lookup and
                    // from the CROWD_RELAYS variable.
                    if relay.starts_with("https://") && !relays.iter().any(|r| r == relay) {
                        relays.push(relay.to_string());
                    }
                }
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(Args {
        reports: reports.ok_or("--reports is required")?,
        sources: if sources.is_empty() {
            return Err("--sources is required".into());
        } else {
            sources
        },
        out: out.ok_or("--out is required")?,
        relays,
        previous,
        min_reports,
        force,
    })
}

/// Exit code of a run that chose to keep the published list (too few reports,
/// or a list that would shrink sharply). That is the guard doing its job, not
/// a broken run, so the workflow can tell it from a real failure (exit 1) and
/// skip publishing rankings without turning the job red.
const KEPT_PUBLISHED: i32 = 3;

/// Why a run stopped without writing a file.
enum Stop {
    /// Something is broken: bad input, no feed, a file that cannot be written.
    Failed(String),
    /// The new ranking is not good enough to replace the published one.
    Kept(String),
}

impl From<String> for Stop {
    fn from(why: String) -> Self {
        Stop::Failed(why)
    }
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(Stop::Failed(e)) => {
            eprintln!("zeronet-crowd: {e}");
            std::process::exit(1);
        }
        Err(Stop::Kept(e)) => {
            eprintln!("zeronet-crowd: {e}");
            std::process::exit(KEPT_PUBLISHED);
        }
    }
}

fn run() -> Result<(), Stop> {
    let args = parse_args()?;
    let _ = rustls::crypto::ring::default_provider().install_default();

    let reports: Vec<Report> = {
        let text = std::fs::read_to_string(&args.reports)
            .map_err(|e| format!("cannot read {}: {e}", args.reports.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("reports are not valid JSON: {e}"))?
    };
    let mut sources: Vec<FeedSource> = Vec::new();
    for path in &args.sources {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let list: Vec<FeedSource> = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
        sources.extend(list);
    }

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
        return Err("no feed could be fetched; not publishing"
            .to_string()
            .into());
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
    // Never replace a good published list with a thin or gutted one. The file
    // is optional: on a first run there is nothing to compare against.
    let previous = args.previous.as_ref().and_then(|path| {
        std::fs::read(path)
            .ok()
            .and_then(|body| crowd_client::parse_rankings(&body))
    });
    if !args.force {
        if let Some(reason) = crowd::refuse_publish(
            previous.as_ref(),
            &rankings,
            reports.len(),
            args.min_reports,
            now,
        ) {
            return Err(Stop::Kept(format!("refusing to publish: {reason}")));
        }
    }
    let json = serde_json::to_string(&rankings).map_err(|e| e.to_string())?;
    std::fs::write(&args.out, json)
        .map_err(|e| format!("cannot write {}: {e}", args.out.display()).into())
}
