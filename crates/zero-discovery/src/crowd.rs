//! Crowd rankings: which public servers, and which Cloudflare addresses,
//! work on which network, from anonymous reports by other ZeroNet users.
//!
//! Apps report what their tests found — "this public server answered on this
//! network in 180 ms", "this one did not" — to a relay that only queues
//! them. A scheduled job ([`aggregate`], run by the `zeronet-crowd` binary in
//! a GitHub Action) turns the last hours of reports into `rankings.json`,
//! committed to the repository, which apps read before searching: the
//! servers most people on the same carrier got through with are tested
//! first.
//!
//! Two rules keep the data from being turned against users:
//!
//! * **Only public servers are ranked.** A report names a server by its
//!   [`link_key`](crate::link_key) only. The aggregator ranks a key only if
//!   it found that key in the public feeds it fetched itself, and takes the
//!   link it publishes from that feed. A private config that reached a
//!   report by mistake is dropped, and a report cannot put a new server into
//!   anyone's list: at worst a false report reorders servers every client
//!   already has, and every client tests before it connects.
//! * **One reporter, one voice.** The relay tags each report with two daily
//!   pseudonyms (it never stores addresses): `source`, of the sending
//!   address, and `reporter`, of the address and a value the app picks each
//!   day, so people sharing a VPN server's address still count apart. Per
//!   network and server only a reporter's latest report counts, and nothing
//!   is ranked until [`MIN_REPORTERS`] different reporters, from as many
//!   different addresses, agree: one address cannot pose as a crowd.
//!
//! Reports that came through a tunnel from a network the phone cannot name
//! (Wi-Fi) carry the network `any` and count towards [`ALL_NETS`] only.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Format of `rankings.json`.
pub const RANKINGS_VERSION: u32 = 1;
/// Reports older than this are ignored.
pub const WINDOW_SECS: i64 = 12 * 3600;
/// A report's weight halves every this many seconds.
pub const HALF_LIFE_SECS: f64 = 3.0 * 3600.0;
/// Distinct reporters needed before anything is ranked.
pub const MIN_REPORTERS: usize = 2;
/// Servers listed per network.
pub const SERVERS_PER_NET: usize = 30;
/// Clean addresses listed per network.
pub const CLEAN_IPS_PER_NET: usize = 20;
/// Every network together: what an app uses on a network nobody has
/// reported from yet.
pub const ALL_NETS: &str = "all";
/// A report from a network the app could not name; counts towards
/// [`ALL_NETS`] only.
pub const ANY_NET: &str = "any";

/// The country bucket a cellular network belongs to: `mcc:<3-digit MCC>`.
/// Reports from every carrier in a country reinforce each other, so an
/// Iranian user on a carrier with little data of its own still gets a list
/// ranked by other Iranian users rather than falling straight back to the
/// worldwide [`ALL_NETS`] bucket, where reports from uncensored countries
/// would drown theirs out. Only cellular networks carry a country (their
/// MCC); Wi-Fi (`asn:`) does not, so it keeps falling back to [`ALL_NETS`].
pub fn country_of(net: &str) -> Option<String> {
    let code = net.strip_prefix("cell:")?;
    if (5..=6).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_digit()) {
        Some(format!("mcc:{}", &code[..3]))
    } else {
        None
    }
}

/// One report, as the relay exports it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Report {
    /// Unix seconds, set by the relay.
    pub ts: i64,
    /// `cell:<mcc><mnc>` or `asn:<number>`; see [`valid_net`].
    pub net: String,
    /// The relay's daily pseudonym for the sender.
    pub reporter: String,
    /// The relay's daily pseudonym for the sending address.
    #[serde(default)]
    pub source: String,
    /// `server` or `ip`.
    pub kind: String,
    /// A server's link key, or a Cloudflare IPv4 address.
    pub item: String,
    pub ok: bool,
    /// Measured delay, for a success.
    #[serde(default)]
    pub ms: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct Rankings {
    pub v: u32,
    /// Unix seconds.
    pub generated_at: i64,
    /// Where apps send reports. Published here so relays can change
    /// without an app update.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Per network, and [`ALL_NETS`].
    #[serde(default)]
    pub nets: BTreeMap<String, NetRanking>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct NetRanking {
    #[serde(default)]
    pub servers: Vec<RankedServer>,
    #[serde(default)]
    pub clean_ips: Vec<RankedIp>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RankedServer {
    pub id: String,
    /// The link, as the public feed lists it.
    pub link: String,
    /// Lower bound of the success rate, 0–1.
    pub score: f32,
    pub reporters: u32,
    /// Median delay of the successes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RankedIp {
    pub ip: String,
    pub score: f32,
    pub reporters: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ms: Option<u32>,
}

/// Whether `net` is a network name the rankings accept: a mobile carrier
/// (`cell:` and its 5–6 digit MCC+MNC) or an ISP (`asn:` and its number).
pub fn valid_net(net: &str) -> bool {
    if let Some(code) = net.strip_prefix("cell:") {
        return (5..=6).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_digit());
    }
    if let Some(asn) = net.strip_prefix("asn:") {
        return !asn.is_empty()
            && asn.len() <= 10
            && !asn.starts_with('0')
            && asn.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

/// Whether `id` looks like a [`link_key`](crate::link_key).
pub fn valid_server_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Cloudflare's IPv4 ranges, the same list the edge scanner scans.
fn cloudflare_ranges() -> &'static [(u32, u32)] {
    static RANGES: std::sync::OnceLock<Vec<(u32, u32)>> = std::sync::OnceLock::new();
    RANGES.get_or_init(|| {
        include_str!("../../zero-scanner/data/ranges_v4.txt")
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.starts_with('#') {
                    return None;
                }
                let (addr, bits) = line.split_once('/')?;
                let addr: Ipv4Addr = addr.parse().ok()?;
                let bits: u32 = bits.parse().ok().filter(|b| *b <= 32)?;
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                Some((u32::from(addr) & mask, mask))
            })
            .collect()
    })
}

/// Whether `ip` is a Cloudflare IPv4 address, in dotted form.
pub fn is_cloudflare_ip(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    // Only the canonical spelling, so one address cannot be counted twice.
    if addr.to_string() != ip {
        return false;
    }
    let value = u32::from(addr);
    cloudflare_ranges()
        .iter()
        .any(|(network, mask)| value & mask == *network)
}

/// Lower bound of a Wilson interval (z = 1.645, one-sided 95%): a success
/// rate that three reports cannot inflate the way three hundred can.
fn wilson_lower(successes: f64, total: f64) -> f64 {
    if total <= 0.0 {
        return 0.0;
    }
    let z = 1.645_f64;
    let p = successes / total;
    let z2 = z * z;
    let centre = p + z2 / (2.0 * total);
    let spread = z * ((p * (1.0 - p) + z2 / (4.0 * total)) / total).sqrt();
    ((centre - spread) / (1.0 + z2 / total)).max(0.0)
}

fn median(values: &mut [u32]) -> Option<u32> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some(values[values.len() / 2])
}

/// A scored item before it is cut to the top of its list.
struct Scored {
    item: String,
    score: f64,
    reporters: usize,
    ms: Option<u32>,
}

/// Score every item in `reports` (already filtered to one network and one
/// kind), keeping each reporter's latest report per item.
fn score(reports: &[&Report], now: i64) -> Vec<Scored> {
    // item -> reporter -> latest report
    let mut latest: HashMap<&str, HashMap<&str, &Report>> = HashMap::new();
    for report in reports {
        let per_item = latest.entry(report.item.as_str()).or_default();
        match per_item.get(report.reporter.as_str()) {
            Some(existing) if existing.ts >= report.ts => {}
            _ => {
                per_item.insert(report.reporter.as_str(), report);
            }
        }
    }
    let mut scored = Vec::new();
    for (item, by_reporter) in latest {
        if by_reporter.len() < MIN_REPORTERS {
            continue;
        }
        let sources: HashSet<&str> = by_reporter
            .values()
            .map(|r| r.source.as_str())
            .filter(|s| !s.is_empty())
            .collect();
        if !sources.is_empty() && sources.len() < MIN_REPORTERS {
            continue;
        }
        let (mut ok, mut total) = (0.0, 0.0);
        let mut delays = Vec::new();
        for report in by_reporter.values() {
            let age = (now - report.ts).max(0) as f64;
            let weight = 0.5_f64.powf(age / HALF_LIFE_SECS);
            total += weight;
            if report.ok {
                ok += weight;
                if let Some(ms) = report.ms {
                    delays.push(ms);
                }
            }
        }
        if ok <= 0.0 {
            continue;
        }
        scored.push(Scored {
            item: item.to_string(),
            score: wilson_lower(ok, total),
            reporters: by_reporter.len(),
            ms: median(&mut delays),
        });
    }
    scored.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then(a.ms.unwrap_or(u32::MAX).cmp(&b.ms.unwrap_or(u32::MAX)))
            .then(a.item.cmp(&b.item))
    });
    scored
}

fn round3(value: f64) -> f32 {
    ((value * 1000.0).round() / 1000.0) as f32
}

/// Build the rankings from `reports`.
///
/// `known` maps the link key of every server in the public feeds to its
/// link; reports about anything else are ignored. `now` is Unix seconds.
pub fn aggregate(
    reports: &[Report],
    known: &HashMap<String, String>,
    relays: Vec<String>,
    now: i64,
) -> Rankings {
    // Keep only reports that are recent, well formed and about public
    // servers or Cloudflare addresses.
    let usable: Vec<&Report> = reports
        .iter()
        .filter(|r| r.ts <= now + 300 && now - r.ts <= WINDOW_SECS)
        .filter(|r| (valid_net(&r.net) || r.net == ANY_NET) && !r.reporter.is_empty())
        .filter(|r| match r.kind.as_str() {
            "server" => valid_server_id(&r.item) && known.contains_key(&r.item),
            "ip" => is_cloudflare_ip(&r.item),
            _ => false,
        })
        .collect();

    let mut groups: BTreeMap<String, Vec<&Report>> = BTreeMap::new();
    for report in &usable {
        if report.net != ANY_NET {
            groups.entry(report.net.clone()).or_default().push(report);
            // A cellular report also feeds its country bucket, so a user on a
            // carrier with few reports of its own still gets a list ranked by
            // other users in the same country before the worldwide fallback.
            if let Some(country) = country_of(&report.net) {
                groups.entry(country).or_default().push(report);
            }
        }
        groups.entry(ALL_NETS.to_string()).or_default().push(report);
    }

    let mut nets = BTreeMap::new();
    for (net, reports) in groups {
        let of_kind = |kind: &str| -> Vec<&Report> {
            reports.iter().copied().filter(|r| r.kind == kind).collect()
        };
        let servers: Vec<RankedServer> = score(&of_kind("server"), now)
            .into_iter()
            .take(SERVERS_PER_NET)
            .map(|s| RankedServer {
                link: known[&s.item].clone(),
                id: s.item,
                score: round3(s.score),
                reporters: s.reporters as u32,
                ms: s.ms,
            })
            .collect();
        let clean_ips: Vec<RankedIp> = score(&of_kind("ip"), now)
            .into_iter()
            .take(CLEAN_IPS_PER_NET)
            .map(|s| RankedIp {
                ip: s.item,
                score: round3(s.score),
                reporters: s.reporters as u32,
                ms: s.ms,
            })
            .collect();
        if !servers.is_empty() || !clean_ips.is_empty() {
            nets.insert(net, NetRanking { servers, clean_ips });
        }
    }

    Rankings {
        v: RANKINGS_VERSION,
        generated_at: now,
        relays,
        nets,
    }
}

/// The link key → link map of every server in `feeds` (feed bodies as
/// fetched).
pub fn known_servers<'a>(feeds: impl IntoIterator<Item = &'a str>) -> HashMap<String, String> {
    let mut known = HashMap::new();
    for body in feeds {
        let (candidates, _) = crate::link::parse_candidates(body, &HashSet::new());
        for candidate in candidates {
            known
                .entry(candidate.info.key)
                .or_insert(candidate.info.link);
        }
    }
    known
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn report(net: &str, reporter: &str, kind: &str, item: &str, ok: bool, age: i64) -> Report {
        Report {
            ts: NOW - age,
            net: net.into(),
            reporter: reporter.into(),
            source: format!("src-{reporter}"),
            kind: kind.into(),
            item: item.into(),
            ok,
            ms: ok.then_some(150),
        }
    }

    fn known() -> HashMap<String, String> {
        [
            ("aaaaaaaaaaaaaaaa", "vless://a"),
            ("bbbbbbbbbbbbbbbb", "vless://b"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    #[test]
    fn networks_are_carriers_or_isps() {
        assert!(valid_net("cell:43211"));
        assert!(valid_net("cell:432350"));
        assert!(valid_net("asn:58224"));
        assert!(!valid_net("cell:4321"));
        assert!(!valid_net("asn:058224"));
        assert!(!valid_net("wifi:home"));
        assert!(!valid_net("all"));
    }

    #[test]
    fn only_cloudflare_addresses_count_as_clean() {
        assert!(is_cloudflare_ip("104.16.132.229"));
        assert!(is_cloudflare_ip("172.67.1.1"));
        assert!(!is_cloudflare_ip("8.8.8.8"));
        assert!(!is_cloudflare_ip("104.016.132.229"));
        assert!(!is_cloudflare_ip("::1"));
    }

    #[test]
    fn a_server_needs_two_reporters() {
        let one = vec![report(
            "cell:43211",
            "r1",
            "server",
            "aaaaaaaaaaaaaaaa",
            true,
            60,
        )];
        assert!(aggregate(&one, &known(), vec![], NOW).nets.is_empty());

        let two = vec![
            report("cell:43211", "r1", "server", "aaaaaaaaaaaaaaaa", true, 60),
            report("cell:43211", "r2", "server", "aaaaaaaaaaaaaaaa", true, 120),
        ];
        let rankings = aggregate(&two, &known(), vec!["https://relay".into()], NOW);
        let net = &rankings.nets["cell:43211"];
        assert_eq!(net.servers.len(), 1);
        assert_eq!(net.servers[0].link, "vless://a");
        assert_eq!(net.servers[0].reporters, 2);
        assert_eq!(net.servers[0].ms, Some(150));
        assert!(rankings.nets.contains_key(ALL_NETS));
        assert_eq!(rankings.relays, vec!["https://relay"]);
    }

    #[test]
    fn unknown_servers_and_foreign_addresses_are_dropped() {
        let reports = vec![
            report("cell:43211", "r1", "server", "cccccccccccccccc", true, 60),
            report("cell:43211", "r2", "server", "cccccccccccccccc", true, 60),
            report("cell:43211", "r1", "ip", "8.8.8.8", true, 60),
            report("cell:43211", "r2", "ip", "8.8.8.8", true, 60),
        ];
        assert!(aggregate(&reports, &known(), vec![], NOW).nets.is_empty());
    }

    #[test]
    fn one_reporter_cannot_vote_twice() {
        // r1 floods successes for b; r1 and r2 report a works. Only r1's
        // latest report on b counts, which leaves b one reporter short.
        let mut reports = vec![
            report("cell:43211", "r1", "server", "aaaaaaaaaaaaaaaa", true, 60),
            report("cell:43211", "r2", "server", "aaaaaaaaaaaaaaaa", true, 60),
        ];
        for age in 0..50 {
            reports.push(report(
                "cell:43211",
                "r1",
                "server",
                "bbbbbbbbbbbbbbbb",
                true,
                age,
            ));
        }
        let net = &aggregate(&reports, &known(), vec![], NOW).nets["cell:43211"];
        assert_eq!(net.servers.len(), 1);
        assert_eq!(net.servers[0].id, "aaaaaaaaaaaaaaaa");
    }

    #[test]
    fn failures_and_age_lower_a_server() {
        let reports = vec![
            // a: two fresh successes.
            report("asn:58224", "r1", "server", "aaaaaaaaaaaaaaaa", true, 60),
            report("asn:58224", "r2", "server", "aaaaaaaaaaaaaaaa", true, 60),
            // b: worked for two people, failed for two more.
            report("asn:58224", "r1", "server", "bbbbbbbbbbbbbbbb", true, 60),
            report("asn:58224", "r2", "server", "bbbbbbbbbbbbbbbb", true, 60),
            report("asn:58224", "r3", "server", "bbbbbbbbbbbbbbbb", false, 60),
            report("asn:58224", "r4", "server", "bbbbbbbbbbbbbbbb", false, 60),
        ];
        let net = &aggregate(&reports, &known(), vec![], NOW).nets["asn:58224"];
        assert_eq!(net.servers[0].id, "aaaaaaaaaaaaaaaa");
        assert!(net.servers[0].score > net.servers[1].score);

        // Beyond the window nothing counts.
        let stale = vec![
            report(
                "asn:58224",
                "r1",
                "server",
                "aaaaaaaaaaaaaaaa",
                true,
                WINDOW_SECS + 1,
            ),
            report(
                "asn:58224",
                "r2",
                "server",
                "aaaaaaaaaaaaaaaa",
                true,
                WINDOW_SECS + 1,
            ),
        ];
        assert!(aggregate(&stale, &known(), vec![], NOW).nets.is_empty());
    }

    #[test]
    fn one_address_cannot_pose_as_a_crowd() {
        // Two "reporters" from the same address: not enough.
        let mut reports = vec![
            report("cell:43211", "r1", "server", "aaaaaaaaaaaaaaaa", true, 60),
            report("cell:43211", "r2", "server", "aaaaaaaaaaaaaaaa", true, 60),
        ];
        for r in &mut reports {
            r.source = "same".into();
        }
        assert!(aggregate(&reports, &known(), vec![], NOW).nets.is_empty());
    }

    #[test]
    fn unnamed_networks_count_towards_everyone_only() {
        let reports = vec![
            report("any", "r1", "server", "aaaaaaaaaaaaaaaa", true, 60),
            report("any", "r2", "server", "aaaaaaaaaaaaaaaa", true, 60),
        ];
        let rankings = aggregate(&reports, &known(), vec![], NOW);
        assert_eq!(rankings.nets.keys().collect::<Vec<_>>(), vec![ALL_NETS]);
    }

    #[test]
    fn cellular_reports_have_a_country_bucket() {
        assert_eq!(country_of("cell:43211").as_deref(), Some("mcc:432"));
        assert_eq!(country_of("cell:432350").as_deref(), Some("mcc:432"));
        assert_eq!(country_of("asn:58224"), None);
        assert_eq!(country_of("all"), None);
    }

    #[test]
    fn carriers_in_a_country_reinforce_each_other() {
        // Two Iranian carriers (MCC 432), one reporter each: neither carrier
        // reaches MIN_REPORTERS alone, but together they rank in the country
        // bucket mcc:432, which the app reads before the worldwide list.
        let reports = vec![
            report("cell:43211", "r1", "server", "aaaaaaaaaaaaaaaa", true, 60),
            report("cell:43235", "r2", "server", "aaaaaaaaaaaaaaaa", true, 60),
        ];
        let rankings = aggregate(&reports, &known(), vec![], NOW);
        // Neither single-carrier bucket qualifies.
        assert!(!rankings.nets.contains_key("cell:43211"));
        assert!(!rankings.nets.contains_key("cell:43235"));
        // The country bucket does, and so does the worldwide fallback.
        let country = &rankings.nets["mcc:432"];
        assert_eq!(country.servers.len(), 1);
        assert_eq!(country.servers[0].id, "aaaaaaaaaaaaaaaa");
        assert!(rankings.nets.contains_key(ALL_NETS));
    }

    #[test]
    fn clean_addresses_are_ranked_per_network() {
        let reports = vec![
            report("cell:43235", "r1", "ip", "104.16.132.229", true, 60),
            report("cell:43235", "r2", "ip", "104.16.132.229", true, 60),
        ];
        let net = &aggregate(&reports, &known(), vec![], NOW).nets["cell:43235"];
        assert_eq!(net.clean_ips[0].ip, "104.16.132.229");
        assert!(net.servers.is_empty());
    }

    #[test]
    fn rankings_round_trip_as_json() {
        let reports = vec![
            report("cell:43211", "r1", "server", "aaaaaaaaaaaaaaaa", true, 60),
            report("cell:43211", "r2", "server", "aaaaaaaaaaaaaaaa", true, 60),
        ];
        let rankings = aggregate(&reports, &known(), vec![], NOW);
        let json = serde_json::to_string(&rankings).unwrap();
        assert_eq!(serde_json::from_str::<Rankings>(&json).unwrap(), rankings);
    }
}
