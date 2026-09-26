//! The client side of the crowd rankings, for hosts written in Rust (the
//! desktop client). The Android app has the same logic in Kotlin
//! (`service/Crowd.kt`); both speak to the same files and relay.
//!
//! * Reading: `rankings.json` from the repository's `crowd-data` branch
//!   (GitHub raw, then two jsDelivr mirrors), verified against the
//!   compiled-in signing key ([`crate::sign`]) when one is set, cached on
//!   disk for [`RANKINGS_TTL`].
//! * Writing: after a search, which *public* servers answered and which did
//!   not, posted to a relay named in the rankings. Callers must never pass a
//!   config the user imported or subscribed to: only servers found in the
//!   public feeds (or picked from the rankings themselves) are reported, and
//!   the aggregator drops anything it cannot find in the feeds anyway.
//!
//! See `deploy/crowd-relay/README.md` for what is shared and what is not.

use std::path::Path;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::json;
use zero_net::{FetchLimits, FetchOptions, Fetched, Validators};

use crate::crowd::{RankedIp, RankedServer, Rankings, ALL_NETS, RANKINGS_VERSION};

/// Where the rankings are published, in the order they are tried.
pub const RANKING_URLS: [&str; 3] = [
    "https://raw.githubusercontent.com/zeghostwriter/ZeroNet/crowd-data/rankings.json",
    "https://cdn.jsdelivr.net/gh/zeghostwriter/ZeroNet@crowd-data/rankings.json",
    "https://fastly.jsdelivr.net/gh/zeghostwriter/ZeroNet@crowd-data/rankings.json",
];
/// A downloaded ranking is reused this long before it is fetched again.
pub const RANKINGS_TTL: Duration = Duration::from_secs(20 * 60);
/// At most this many results per report, as the relay accepts.
pub const MAX_RESULTS: usize = 40;
/// At most this many clean addresses per report.
pub const MAX_CLEAN: usize = 10;
const RANKINGS_MAX_BYTES: usize = 4 * 1024 * 1024;

/// One tested server, by its link key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestResult {
    pub id: String,
    pub ok: bool,
    pub ms: u32,
}

/// One clean Cloudflare address the scanner found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanIp {
    pub ip: String,
    pub ms: u32,
}

/// Parse a rankings body; `None` for anything that is not version 1 JSON.
pub fn parse_rankings(body: &[u8]) -> Option<Rankings> {
    let rankings: Rankings = serde_json::from_slice(body).ok()?;
    (rankings.v == RANKINGS_VERSION).then_some(rankings)
}

/// The rankings: from `cache_file` when younger than [`RANKINGS_TTL`], else
/// downloaded (and the cache refreshed). A download that fails falls back
/// to the cached copy however old. `None` when there is neither.
pub async fn fetch_rankings(cache_file: Option<&Path>, timeout: Duration) -> Option<Rankings> {
    let cached = cache_file.and_then(|path| std::fs::read(path).ok().map(|body| (path, body)));
    if let Some((path, body)) = &cached {
        let fresh = std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .is_some_and(|age| age < RANKINGS_TTL);
        if fresh {
            if let Some(rankings) = parse_rankings(body) {
                return Some(rankings);
            }
        }
    }
    for url in RANKING_URLS {
        let Some(body) = get(url, RANKINGS_MAX_BYTES, timeout).await else {
            continue;
        };
        let Some(rankings) = parse_rankings(&body) else {
            continue;
        };
        // A build with a signing key refuses a ranking that is not signed
        // by it: a substitute could push anyone's server to the top.
        if crate::sign::key_configured() {
            let signature = get(&format!("{url}.sig"), 4096, timeout).await;
            let good = signature
                .is_some_and(|sig| crate::sign::verify(&body, &String::from_utf8_lossy(&sig)));
            if !good {
                tracing::warn!(%url, "rankings signature did not verify");
                continue;
            }
        }
        if let Some(path) = cache_file {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let temporary = path.with_extension("tmp");
            if std::fs::write(&temporary, &body).is_ok() {
                let _ = std::fs::rename(&temporary, path);
            }
        }
        return Some(rankings);
    }
    cached.and_then(|(_, body)| parse_rankings(&body))
}

/// The ranking buckets to read for `net`, most specific first: the exact
/// network, its country (for a cellular network), then the worldwide list.
pub fn fallbacks(net: &str) -> Vec<String> {
    let mut out = vec![net.to_string()];
    if let Some(country) = crate::crowd::country_of(net) {
        out.push(country);
    }
    out.push(ALL_NETS.to_string());
    out.dedup();
    out
}

/// Servers others got through with on `net`, best first, then the broader
/// lists, without repeats.
pub fn picks(rankings: &Rankings, net: &str, limit: usize) -> Vec<RankedServer> {
    let mut out: Vec<RankedServer> = Vec::new();
    for name in fallbacks(net) {
        let Some(ranking) = rankings.nets.get(&name) else {
            continue;
        };
        for server in &ranking.servers {
            if server.id.is_empty() || server.link.is_empty() || out.iter().any(|s| s.id == server.id) {
                continue;
            }
            out.push(server.clone());
            if out.len() >= limit {
                return out;
            }
        }
    }
    out
}

/// Clean Cloudflare addresses others found on `net` (or the broader lists).
pub fn clean_ips(rankings: &Rankings, net: &str) -> Vec<RankedIp> {
    fallbacks(net)
        .iter()
        .find_map(|name| rankings.nets.get(name).filter(|r| !r.clean_ips.is_empty()))
        .map(|ranking| ranking.clean_ips.clone())
        .unwrap_or_default()
}

/// The report body. `net` names the network when the relay cannot see it
/// (a report sent through the tunnel); `None` lets the relay file it under
/// the ISP it sees.
pub fn report_body(nonce: &str, net: Option<&str>, results: &[TestResult], clean: &[CleanIp]) -> String {
    let mut ordered: Vec<&TestResult> = results.iter().collect();
    // Successes first: the relay keeps a limited number.
    ordered.sort_by_key(|result| !result.ok);
    let mut body = json!({
        "v": 1,
        "nonce": nonce,
        "results": ordered.iter().take(MAX_RESULTS).map(|r| json!({"id": r.id, "ok": r.ok, "ms": r.ms})).collect::<Vec<_>>(),
        "clean": clean.iter().take(MAX_CLEAN).map(|c| json!({"ip": c.ip, "ms": c.ms})).collect::<Vec<_>>(),
    });
    if let Some(net) = net {
        body["net"] = json!(net);
    }
    body.to_string()
}

#[derive(Deserialize)]
struct Answer {
    #[serde(default)]
    net: String,
}

/// Send one report to the first relay that takes it. Returns the network
/// name the relay filed it under (`asn:…` when it saw the ISP), or an error
/// when no relay answered. Nothing is sent when there is nothing to say.
pub async fn report(
    relays: &[String],
    nonce: &str,
    net: Option<&str>,
    results: &[TestResult],
    clean: &[CleanIp],
) -> Result<Option<String>, String> {
    if results.is_empty() && clean.is_empty() {
        return Ok(None);
    }
    let body = report_body(nonce, net, results, clean);
    let limits = FetchLimits {
        max_bytes: 64 * 1024,
        timeout: Duration::from_secs(10),
        max_redirects: 0,
    };
    let mut last = String::from("no relay is published");
    for relay in relays.iter().filter(|relay| relay.starts_with("https://")) {
        let url = format!("{}/v1/report", relay.trim_end_matches('/'));
        match zero_net::post(&url, "application/json", body.as_bytes(), &limits).await {
            Ok(answer) => {
                let net = serde_json::from_slice::<Answer>(&answer).ok().map(|a| a.net).filter(|n| !n.is_empty());
                return Ok(net);
            }
            Err(error) => last = format!("{relay}: {error}"),
        }
    }
    Err(last)
}

async fn get(url: &str, max_bytes: usize, timeout: Duration) -> Option<Vec<u8>> {
    let limits = FetchLimits {
        max_bytes,
        timeout,
        max_redirects: 5,
    };
    let options = FetchOptions { accept_gzip: true };
    match zero_net::fetch_with(url, &limits, &Validators::default(), &options).await {
        Ok(Fetched::Body { body, .. }) => Some(body),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crowd::NetRanking;

    fn server(id: &str) -> RankedServer {
        RankedServer {
            id: id.into(),
            link: format!("vless://{id}@h:443"),
            score: 0.9,
            reporters: 3,
            ms: Some(100),
        }
    }

    #[test]
    fn picks_read_the_network_then_its_country_then_everyone() {
        let mut rankings = Rankings {
            v: 1,
            ..Rankings::default()
        };
        rankings.nets.insert("cell:43211".into(), NetRanking { servers: vec![server("a")], clean_ips: vec![] });
        rankings.nets.insert("mcc:432".into(), NetRanking { servers: vec![server("b"), server("a")], clean_ips: vec![] });
        rankings.nets.insert("all".into(), NetRanking { servers: vec![server("c")], clean_ips: vec![] });
        let ids: Vec<_> = picks(&rankings, "cell:43211", 10).into_iter().map(|s| s.id).collect();
        assert_eq!(ids, ["a", "b", "c"]);
        let ids: Vec<_> = picks(&rankings, "asn:58224", 10).into_iter().map(|s| s.id).collect();
        assert_eq!(ids, ["c"]);
        assert_eq!(picks(&rankings, "cell:43211", 2).len(), 2);
    }

    #[test]
    fn a_report_puts_successes_first_and_names_the_network_only_when_asked() {
        let results = vec![
            TestResult { id: "bad".into(), ok: false, ms: 0 },
            TestResult { id: "good".into(), ok: true, ms: 120 },
        ];
        let body: serde_json::Value = serde_json::from_str(&report_body("n", None, &results, &[])).unwrap();
        assert_eq!(body["results"][0]["id"], "good");
        assert!(body.get("net").is_none());
        let body: serde_json::Value = serde_json::from_str(&report_body("n", Some("any"), &results, &[])).unwrap();
        assert_eq!(body["net"], "any");
        assert_eq!(body["v"], 1);
    }

    #[test]
    fn only_version_one_rankings_are_accepted() {
        assert!(parse_rankings(br#"{"v":1,"generated_at":0}"#).is_some());
        assert!(parse_rankings(br#"{"v":2,"generated_at":0}"#).is_none());
        assert!(parse_rankings(b"<html>").is_none());
    }

    #[tokio::test]
    async fn a_report_reaches_a_relay_and_reads_back_the_network() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&request);
                if let Some(end) = text.find("\r\n\r\n") {
                    let length: usize = text
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let answer = br#"{"ok":true,"net":"asn:58224"}"#;
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", answer.len());
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(answer).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        // Plain http relays are refused outright; this one is only for the test.
        let refused = report(&[format!("http://127.0.0.1:{port}")], "n", None, &[TestResult { id: "a".into(), ok: true, ms: 1 }], &[]).await;
        assert!(refused.is_err());
        // Drive the POST helper directly against the local relay.
        let body = report_body("n", None, &[TestResult { id: "a".into(), ok: true, ms: 1 }], &[]);
        let answer = zero_net::post(
            &format!("http://127.0.0.1:{port}/v1/report"),
            "application/json",
            body.as_bytes(),
            &FetchLimits { max_bytes: 4096, timeout: Duration::from_secs(5), max_redirects: 0 },
        )
        .await
        .unwrap();
        assert_eq!(serde_json::from_slice::<Answer>(&answer).unwrap().net, "asn:58224");
        let request = server.await.unwrap();
        assert!(request.starts_with("POST /v1/report HTTP/1.1\r\n"));
        assert!(request.contains("Content-Type: application/json"));
        assert!(request.ends_with(&body));
    }
}
