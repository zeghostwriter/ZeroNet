//! Which anti-sanction resolver to trust on this network, and for which names.
//!
//! Anti-sanction DNS answers a sanctioned name (a Google developer page, an AI
//! service) with the address of the provider's relay, so the site sees the
//! relay rather than an Iranian address. Measured from Center (FANAP) on
//! 2026-09-28 it is far less uniform than a fixed list suggests:
//!
//! * only one provider (Bertina) relayed at all — `developer.android.com` and
//!   `gemini.google.com` went from 403 to 200 through it;
//! * another (begzar) answered every name, domestic ones included, with a
//!   root server's address;
//! * a third (radar) did not answer;
//! * the rest answered honestly, which for a sanctioned name means the
//!   service's real address — and a direct connection there is the 403.
//!
//! So each candidate is measured on the current network: does it answer, are
//! its answers sane (a domestic name resolves where the other candidates say
//! it does), and which address does it relay through — the one it returns
//! for names of *different* companies, since an honest resolver can return
//! one address for two names of the same company. The best relayer wins, ties
//! going to the faster.
//!
//! A sanctioned name then goes direct only when the chosen resolver answers
//! it with its relay address. Any other answer would reach the service from
//! an Iranian address and be refused, so that name goes through the tunnel.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use zero_config::dns::ResolverEndpoint;
use zero_core::Address;

/// The DNS tag the Iran preset gives its anti-sanction resolvers.
pub const TAG: &str = "anti-sanction";
/// Re-measure this often on a network that has not changed.
pub const RECHECK: Duration = Duration::from_secs(30 * 60);
const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
const CERT_TIMEOUT: Duration = Duration::from_millis(3000);
/// A domestic name every honest Iranian resolver answers the same way.
const DOMESTIC_NAME: &str = "digikala.com";
/// Sanctioned names grouped by who runs them. A relay address is one
/// answered for names of at least two groups.
const PROBE_NAMES: &[(&str, &str)] = &[
    ("google", "developer.android.com"),
    ("google", "gemini.google.com"),
    ("google", "firebase.google.com"),
    ("docker", "docker.io"),
    ("jetbrains", "jetbrains.com"),
    ("anthropic", "anthropic.com"),
];

/// The built-in providers by address, for reporting a choice by name. A
/// resolver the user typed in themselves is never named in a report.
const PROVIDERS: &[(&str, &str)] = &[
    ("bertina", "193.186.32.32"),
    ("shecan", "178.22.122.100"),
    ("shecan", "185.51.200.2"),
    ("electro", "78.157.42.100"),
    ("electro", "78.157.42.101"),
    ("ipm", "194.225.152.10"),
    ("begzar", "185.55.226.26"),
    ("begzar", "185.55.225.25"),
    ("radar", "10.202.10.10"),
    ("radar", "10.202.10.11"),
];

/// The crowd-report id for a measured state: the chosen built-in provider,
/// `sanction:none` when nothing relayed, or nothing for a custom resolver.
pub fn method_id(state: &SanctionState) -> Option<&'static str> {
    let Some(chosen) = state.chosen else {
        return Some("sanction:none");
    };
    let name = PROVIDERS
        .iter()
        .find(|(_, address)| address.parse::<IpAddr>().ok() == Some(chosen))?
        .0;
    Some(match name {
        "bertina" => "sanction:bertina",
        "shecan" => "sanction:shecan",
        "electro" => "sanction:electro",
        "ipm" => "sanction:ipm",
        "begzar" => "sanction:begzar",
        _ => "sanction:radar",
    })
}

/// The measured choice for the current network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanctionState {
    /// The resolver to use, or `None` when no candidate relays anything
    /// here — then sanctioned names go through the tunnel.
    pub chosen: Option<IpAddr>,
    /// The chosen resolver's relay addresses.
    pub relay: Vec<IpAddr>,
}

impl SanctionState {
    /// The resolver tag pinned to the chosen server.
    pub fn pinned_tag(&self) -> Option<String> {
        self.chosen.map(|ip| format!("{TAG}@{ip}"))
    }

    /// Whether `answers` (the chosen resolver's answer for a name) point at
    /// its relay, so a direct connection gets the relayed service.
    pub fn relays(&self, answers: &[IpAddr]) -> bool {
        answers.iter().any(|answer| self.relay.contains(answer))
    }
}

/// One candidate's measurements.
#[derive(Debug, Clone)]
struct Measured {
    server: IpAddr,
    latency: Duration,
    domestic: Vec<IpAddr>,
    /// Probe answers, one entry per probe name that was answered.
    answers: Vec<(&'static str, Vec<IpAddr>)>,
    /// The same answers by name, to check a relay's certificate for a name
    /// it actually relayed.
    named: Vec<(&'static str, Vec<IpAddr>)>,
}

/// The anti-sanction candidates in `dns`: plain resolvers on port 53 with an
/// address (the only kind a censored network can reach without a lookup).
pub fn candidates(dns: &zero_config::dns::DnsSettings) -> Vec<IpAddr> {
    let mut found = Vec::new();
    for server in dns.servers.iter() {
        if server.tag.as_deref() != Some(TAG) {
            continue;
        }
        if let ResolverEndpoint::Udp {
            address: Address::Ip(ip),
            port: 53,
        } = server.endpoint
        {
            if !found.contains(&ip) {
                found.push(ip);
            }
        }
    }
    found
}

/// Measure every candidate at once and choose. Costs one domestic and six
/// sanctioned lookups per candidate, a few kilobytes in all.
pub async fn probe(candidates: &[IpAddr]) -> SanctionState {
    let mut measured: Vec<Measured> =
        futures::future::join_all(candidates.iter().map(|ip| measure(*ip)))
            .await
            .into_iter()
            .flatten()
            .collect();
    loop {
        let state = choose(measured.clone());
        let Some(server) = state.chosen else {
            return state;
        };
        let names = relayed_names(&measured, server, &state.relay);
        if relay_certificate_holds(&state.relay, &names).await {
            return state;
        }
        // A relay whose certificate does not verify is a middlebox, not a
        // pass-through: HSTS sites would refuse it with no way past. Try the
        // next best resolver instead.
        tracing::debug!(%server, "anti-sanction relay failed the certificate check");
        measured.retain(|candidate| candidate.server != server);
    }
}

/// Up to two probe names the chosen resolver answered with its relay.
fn relayed_names(measured: &[Measured], server: IpAddr, relay: &[IpAddr]) -> Vec<&'static str> {
    measured
        .iter()
        .find(|candidate| candidate.server == server)
        .map(|candidate| {
            candidate
                .named
                .iter()
                .filter(|(_, ips)| ips.iter().any(|ip| relay.contains(ip)))
                .map(|(name, _)| *name)
                .take(2)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a TLS handshake to the relay for one of the names it relayed
/// verifies against the public roots.
async fn relay_certificate_holds(relay: &[IpAddr], names: &[&'static str]) -> bool {
    let Some(address) = relay.first().copied() else {
        return false;
    };
    for name in names {
        if zero_net::verify_tls(SocketAddr::new(address, 443), name, CERT_TIMEOUT)
            .await
            .is_ok()
        {
            return true;
        }
    }
    false
}

async fn measure(server: IpAddr) -> Option<Measured> {
    let address = SocketAddr::new(server, 53);
    let (domestic, latency) = zero_dns::probe_udp(address, DOMESTIC_NAME, QUERY_TIMEOUT)
        .await
        .ok()?;
    if domestic.is_empty() {
        return None;
    }
    let probed: Vec<(&'static str, &'static str, Vec<IpAddr>)> =
        futures::future::join_all(PROBE_NAMES.iter().map(|(group, name)| async move {
            zero_dns::probe_udp(address, name, QUERY_TIMEOUT)
                .await
                .ok()
                .filter(|(ips, _)| !ips.is_empty())
                .map(|(ips, _)| (*group, *name, ips))
        }))
        .await
        .into_iter()
        .flatten()
        .collect();
    let answers = probed
        .iter()
        .map(|(group, _, ips)| (*group, ips.clone()))
        .collect();
    let named = probed
        .into_iter()
        .map(|(_, name, ips)| (name, ips))
        .collect();
    Some(Measured {
        server,
        latency,
        domestic,
        answers,
        named,
    })
}

/// The provider tried first (Shecan, both of its addresses). It is chosen
/// whenever it really relays here and keeps up with the best candidate (see
/// [`choose`]); otherwise the automatic choice below stands.
const PREFERRED: &[&str] = &["178.22.122.100", "185.51.200.2"];

/// Pick the candidate that relays the most, among those whose domestic
/// answer agrees with the majority; ties go to the faster.
///
/// The [`PREFERRED`] provider wins over that when it relays at least half as
/// many of the probe names as the best candidate does. A preferred resolver
/// that answers honestly (no relay), is insane, or relays far less is passed
/// over, so the choice stays automatic whenever it fails.
fn choose(measured: Vec<Measured>) -> SanctionState {
    // The /16 most candidates put the domestic name in. A resolver that
    // disagrees is broken or lying, and its "relay" means nothing.
    let mut votes: HashMap<[u8; 2], usize> = HashMap::new();
    for candidate in &measured {
        let mut seen = Vec::new();
        for ip in &candidate.domestic {
            if let Some(prefix) = prefix16(*ip) {
                if !seen.contains(&prefix) {
                    seen.push(prefix);
                    *votes.entry(prefix).or_default() += 1;
                }
            }
        }
    }
    let consensus = votes
        .into_iter()
        .max_by_key(|(prefix, count)| (*count, *prefix))
        .map(|(prefix, _)| prefix);

    // (names relayed, latency, server, relay) of every sane candidate that relays.
    let mut relaying: Vec<(usize, Duration, IpAddr, Vec<IpAddr>)> = Vec::new();
    for candidate in measured {
        let sane = candidate
            .domestic
            .iter()
            .any(|ip| prefix16(*ip).is_some() && prefix16(*ip) == consensus);
        if !sane {
            continue;
        }
        let relay = relay_addresses(&candidate.answers);
        if relay.is_empty() {
            continue;
        }
        let relayed = candidate
            .answers
            .iter()
            .filter(|(_, ips)| ips.iter().any(|ip| relay.contains(ip)))
            .count();
        relaying.push((relayed, candidate.latency, candidate.server, relay));
    }
    // Most names relayed first, the faster first among equals.
    let ranking = |a: &(usize, Duration, IpAddr, Vec<IpAddr>),
                   b: &(usize, Duration, IpAddr, Vec<IpAddr>)| {
        b.0.cmp(&a.0).then(a.1.cmp(&b.1))
    };
    relaying.sort_by(ranking);
    let most = relaying.first().map_or(0, |best| best.0);
    let preferred = relaying.iter().position(|(relayed, _, server, _)| {
        relayed * 2 >= most
            && PREFERRED
                .iter()
                .any(|p| p.parse::<IpAddr>().ok() == Some(*server))
    });
    match preferred.or(if relaying.is_empty() { None } else { Some(0) }) {
        Some(at) => {
            let (_, _, server, relay) = relaying.swap_remove(at);
            SanctionState {
                chosen: Some(server),
                relay,
            }
        }
        None => SanctionState {
            chosen: None,
            relay: Vec::new(),
        },
    }
}

/// Addresses answered for names of at least two different groups.
fn relay_addresses(answers: &[(&'static str, Vec<IpAddr>)]) -> Vec<IpAddr> {
    let mut groups: HashMap<IpAddr, Vec<&'static str>> = HashMap::new();
    for (group, ips) in answers {
        for ip in ips {
            let entry = groups.entry(*ip).or_default();
            if !entry.contains(group) {
                entry.push(group);
            }
        }
    }
    let mut relay: Vec<IpAddr> = groups
        .into_iter()
        .filter(|(_, groups)| groups.len() >= 2)
        .map(|(ip, _)| ip)
        .collect();
    relay.sort();
    relay
}

fn prefix16(ip: IpAddr) -> Option<[u8; 2]> {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some([octets[0], octets[1]])
        }
        IpAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn measured(
        server: &str,
        ms: u64,
        domestic: &str,
        answers: &[(&'static str, &str)],
    ) -> Measured {
        Measured {
            server: ip(server),
            latency: Duration::from_millis(ms),
            domestic: vec![ip(domestic)],
            answers: answers
                .iter()
                .map(|(group, answer)| (*group, vec![ip(answer)]))
                .collect(),
            named: Vec::new(),
        }
    }

    /// The answers measured from Center on 2026-09-28, trimmed.
    fn center() -> Vec<Measured> {
        vec![
            // Honest: the services' real addresses; two Google names share one.
            measured(
                "178.22.122.100",
                80,
                "185.188.104.10",
                &[
                    ("google", "142.250.202.174"),
                    ("google", "142.250.202.174"),
                    ("docker", "34.230.221.175"),
                    ("jetbrains", "3.167.227.123"),
                ],
            ),
            // Bertina: one relay address for every company.
            measured(
                "193.186.32.32",
                82,
                "185.188.104.10",
                &[
                    ("google", "132.243.209.113"),
                    ("google", "132.243.209.113"),
                    ("docker", "132.243.209.113"),
                    ("jetbrains", "132.243.209.113"),
                    ("anthropic", "132.243.209.113"),
                ],
            ),
            // begzar: a root server's address for everything, domestic too.
            measured(
                "185.55.226.26",
                76,
                "198.41.0.4",
                &[
                    ("google", "198.41.0.4"),
                    ("docker", "198.41.0.4"),
                    ("jetbrains", "198.41.0.4"),
                ],
            ),
            measured(
                "78.157.42.100",
                81,
                "185.188.104.10",
                &[("google", "142.251.150.2"), ("jetbrains", "3.167.227.89")],
            ),
        ]
    }

    #[test]
    fn picks_the_relaying_resolver_and_rejects_the_broken_one() {
        let state = choose(center());
        assert_eq!(state.chosen, Some(ip("193.186.32.32")));
        assert_eq!(state.relay, vec![ip("132.243.209.113")]);
        assert_eq!(
            state.pinned_tag().as_deref(),
            Some("anti-sanction@193.186.32.32")
        );
        assert!(state.relays(&[ip("132.243.209.113")]));
        // Bertina answered chatgpt.com with a plain Cloudflare address:
        // direct there is the 403, so it must not count as relayed.
        assert!(!state.relays(&[ip("188.114.98.0")]));
    }

    #[test]
    fn one_company_sharing_an_address_is_not_a_relay() {
        let honest = &center()[0];
        assert!(relay_addresses(&honest.answers).is_empty());
    }

    #[test]
    fn with_no_relay_anywhere_nothing_is_chosen() {
        let mut measured = center();
        measured.remove(1);
        let state = choose(measured);
        assert_eq!(state.chosen, None);
        assert!(!state.relays(&[ip("142.250.202.174")]));
    }

    #[test]
    fn reports_name_built_in_providers_only() {
        let chosen = |address: &str| SanctionState {
            chosen: Some(ip(address)),
            relay: Vec::new(),
        };
        assert_eq!(
            method_id(&chosen("193.186.32.32")),
            Some("sanction:bertina")
        );
        assert_eq!(method_id(&chosen("185.51.200.2")), Some("sanction:shecan"));
        // A resolver the user typed in could identify them: never reported.
        assert_eq!(method_id(&chosen("203.0.113.53")), None);
        let none = SanctionState {
            chosen: None,
            relay: Vec::new(),
        };
        assert_eq!(method_id(&none), Some("sanction:none"));
    }

    #[test]
    fn candidates_are_the_tagged_plain_resolvers() {
        let dns = zero_config::dns::DnsSettings {
            servers: vec![
                zero_config::dns::DnsServer {
                    endpoint: ResolverEndpoint::parse("193.186.32.32").unwrap(),
                    domains: Vec::new(),
                    expect_ips: Vec::new(),
                    unexpect_ips: Vec::new(),
                    skip_fallback: false,
                    tag: Some(TAG.into()),
                },
                zero_config::dns::DnsServer {
                    endpoint: ResolverEndpoint::parse("https://1.1.1.1/dns-query").unwrap(),
                    domains: Vec::new(),
                    expect_ips: Vec::new(),
                    unexpect_ips: Vec::new(),
                    skip_fallback: false,
                    tag: Some(TAG.into()),
                },
                zero_config::dns::DnsServer {
                    endpoint: ResolverEndpoint::parse("8.8.8.8").unwrap(),
                    domains: Vec::new(),
                    expect_ips: Vec::new(),
                    unexpect_ips: Vec::new(),
                    skip_fallback: false,
                    tag: Some("remote".into()),
                },
            ]
            .into_boxed_slice(),
            ..Default::default()
        };
        assert_eq!(candidates(&dns), vec![ip("193.186.32.32")]);
    }

    /// A measured resolver whose probe names all answer with one relay address.
    fn relaying(server: &str, ms: u64, relay: &str, groups: &[&'static str]) -> Measured {
        let answers: Vec<(&'static str, &str)> = groups.iter().map(|g| (*g, relay)).collect();
        measured(server, ms, "185.188.104.10", &answers)
    }

    #[test]
    fn shecan_is_preferred_when_it_relays_even_if_slower() {
        let state = choose(vec![
            relaying(
                "193.186.32.32",
                40,
                "132.243.209.113",
                &["google", "docker", "jetbrains", "anthropic"],
            ),
            relaying(
                "178.22.122.100",
                200,
                "10.1.1.1",
                &["google", "docker", "jetbrains", "anthropic"],
            ),
        ]);
        assert_eq!(state.chosen, Some(ip("178.22.122.100")));
        assert_eq!(state.relay, vec![ip("10.1.1.1")]);
    }

    #[test]
    fn shecan_keeps_the_choice_while_it_relays_at_least_half_as_much() {
        let state = choose(vec![
            relaying(
                "193.186.32.32",
                40,
                "132.243.209.113",
                &["google", "docker", "jetbrains", "anthropic"],
            ),
            relaying("178.22.122.100", 90, "10.1.1.1", &["google", "docker"]),
        ]);
        assert_eq!(state.chosen, Some(ip("178.22.122.100")));
    }

    #[test]
    fn auto_takes_over_when_shecan_relays_too_little_or_nothing() {
        // Two of five names against five: under half, so the best resolver stays.
        let few = choose(vec![
            relaying(
                "193.186.32.32",
                40,
                "132.243.209.113",
                &["google", "google", "docker", "jetbrains", "anthropic"],
            ),
            relaying("178.22.122.100", 90, "10.1.1.1", &["google", "docker"]),
        ]);
        assert_eq!(few.chosen, Some(ip("193.186.32.32")));
        // The Center measurements: Shecan answered honestly, so it is passed over.
        assert_eq!(choose(center()).chosen, Some(ip("193.186.32.32")));
    }

    #[test]
    fn the_second_shecan_address_counts_as_shecan() {
        let state = choose(vec![
            relaying(
                "193.186.32.32",
                40,
                "132.243.209.113",
                &["google", "docker"],
            ),
            relaying("185.51.200.2", 120, "10.2.2.2", &["google", "docker"]),
        ]);
        assert_eq!(state.chosen, Some(ip("185.51.200.2")));
    }
}
