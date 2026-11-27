//! Google front ends that can be reached when the addresses DNS gives are not.
//!
//! Google serves YouTube, Gmail, Play, the APIs and most of its other sites
//! from the same fleet of front ends: any of them answers for any of those
//! names, and the TLS handshake and certificate are the site's own. Which
//! front-end addresses a network lets through varies and changes, so a
//! connection to a Google-hosted name can fail only because DNS handed out an
//! address that is blocked, while another front end next to it works.
//!
//! ```text
//! www.youtube.com -> DNS says 142.250.x.x (times out)
//!                 -> dial 216.239.38.120 (answers) with the same TLS
//! ```
//!
//! [`reachable`] tries a short list of known front ends with a plain TCP
//! connect (no data, so no name for a filter to read) and keeps the ones that
//! answer for a while; the direct outbound puts them in front of the resolved
//! addresses for [`hosted`] names. The rule it keeps: only names Google's front
//! ends serve are listed, since an address that does not serve a name would
//! turn a slow connection into a broken one.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use zero_net::{dial_tcp, RacePolicy, SocketOptions};

/// Names served by Google's front ends: the name itself or any subdomain.
const HOSTED: &[&str] = &[
    "google.com",
    "youtube.com",
    "ytimg.com",
    "ggpht.com",
    "gstatic.com",
    "googleapis.com",
    "googleusercontent.com",
    "gvt1.com",
    "gvt2.com",
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "youtu.be",
];

/// Front ends seen answering for all of the names above.
const SEEDS: &[[u8; 4]] = &[
    [216, 239, 38, 119],
    [216, 239, 38, 120],
    [172, 217, 16, 142],
    [74, 125, 200, 100],
    [172, 253, 115, 100],
    [64, 233, 184, 100],
    [209, 85, 233, 100],
    [108, 177, 119, 100],
];

/// How long a probe's answer is trusted, and how long one may take.
const KEEP: Duration = Duration::from_secs(20 * 60);
const WITHIN: Duration = Duration::from_millis(2500);

static KNOWN: Mutex<Option<(Instant, Vec<IpAddr>)>> = Mutex::const_new(None);

/// Whether Google's front ends serve `host`.
pub fn hosted(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    HOSTED.iter().any(|name| {
        host == *name
            || host
                .strip_suffix(name)
                .is_some_and(|front| front.ends_with('.'))
    })
}

/// The seed front ends that answered a TCP connect on port 443 lately, fastest
/// first. Probed together at most once per [`KEEP`]; callers meanwhile wait for
/// that one probe (at most [`WITHIN`]).
pub async fn reachable() -> Vec<IpAddr> {
    let mut known = KNOWN.lock().await;
    if let Some((_, ips)) = known.as_ref().filter(|(at, _)| at.elapsed() < KEEP) {
        return ips.clone();
    }
    let policy = RacePolicy {
        connect_timeout: WITHIN,
        max_concurrent: 1,
        ..RacePolicy::default()
    };
    let probes = SEEDS.iter().map(|octets| {
        let addr = SocketAddr::new(IpAddr::from(*octets), 443);
        async move {
            let started = Instant::now();
            dial_tcp(&[addr], &policy, &SocketOptions::default())
                .await
                .ok()
                .map(|_| (started.elapsed(), addr.ip()))
        }
    });
    let mut found: Vec<_> = futures::future::join_all(probes)
        .await
        .into_iter()
        .flatten()
        .collect();
    found.sort();
    let ips: Vec<IpAddr> = found.into_iter().map(|(_, ip)| ip).collect();
    tracing::debug!(count = ips.len(), "Google front ends reachable");
    *known = Some((Instant::now(), ips.clone()));
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_names_are_matched_by_suffix_on_a_label_boundary() {
        assert!(hosted("www.youtube.com"));
        assert!(hosted("YouTube.com."));
        assert!(hosted("play.googleapis.com"));
        assert!(hosted("i.ytimg.com"));
        assert!(!hosted("notgoogle.com"));
        assert!(!hosted("google.com.evil.example"));
        assert!(!hosted("example.com"));
    }
}
