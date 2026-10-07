//! Is the Cloudflare CDN usable from this network, and how?
//!
//! Iran throttles TLS to Cloudflare's usual edge addresses when the
//! ClientHello names a Worker: the handshake completes, then no data flows.
//! Measured from Tehran (FANAP) on 2026-09-28 against a `workers.dev` edge:
//!
//! | ClientHello              | result          |
//! |--------------------------|-----------------|
//! | as is                    | stalls, 0 of 3  |
//! | `tlshello` re-framing    | stalls, 0 of 3  |
//! | TCP segments of 40–80 B  | works, 10 of 10 |
//! | ECH (name encrypted)     | works, 10 of 10 |
//!
//! By 2026-10-07 the same line had changed: TCP segments got 0 of 2, and one
//! empty TLS record in front of the ClientHello got 2 of 2 (see
//! `zero_config::FragmentConfig::empty_record`).
//!
//! So the right handling depends on the network, and can change with it.
//! This module probes one CDN outbound four ways — as is, behind an empty
//! record, split, with ECH — each with real data through the tunnel (a handshake alone proves nothing:
//! the throttled handshakes all completed), and reports the cheapest that
//! works. The server applies that to every CDN outbound and, if none works,
//! stops choosing CDN outbounds and says so.
//!
//! Cost is bounded: at most four small HTTP exchanges per probe, one probe
//! per network change or per [`RECHECK`] period, never a sweep.

use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zero_config::{Outbound, Security, Transport};
use zero_core::{Address, Destination};

use crate::outbound;

/// Woken when the device changes networks, so the watcher re-probes.
pub static NETWORK_CHANGED: std::sync::LazyLock<tokio::sync::Notify> =
    std::sync::LazyLock::new(tokio::sync::Notify::new);

/// How long one probe attempt may take. A throttled edge never answers, so
/// this bounds the cost of finding out.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(8);
/// Re-probe this often while things work, to notice a new restriction.
pub const RECHECK: Duration = Duration::from_secs(20 * 60);
/// Re-probe this often while the CDN is unusable, to notice it recover.
pub const RECHECK_BLOCKED: Duration = Duration::from_secs(5 * 60);
/// A small, fast answer from a host outside Cloudflare (a Worker cannot
/// reach Cloudflare-hosted names, so a Cloudflare target would always fail).
const PROBE_HOST: &str = "www.gstatic.com";
const PROBE_REQUEST: &[u8] =
    b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n";

/// What works for Cloudflare CDN outbounds on the current network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CdnCondition {
    /// Not probed: no CDN outbound, or no answer yet.
    Unknown,
    /// Works as configured.
    Clear,
    /// Throttled; splitting the ClientHello into TCP segments gets through.
    Fragment,
    /// Throttled; encrypting the name with ECH gets through.
    Ech,
    /// Nothing tried gets through; CDN outbounds are not used.
    Blocked,
    /// Throttled; an empty TLS record in front of the ClientHello gets
    /// through. Listed last so the numbers saved by older builds keep their
    /// meaning; it is tried second.
    EmptyRecord,
    /// Throttled; a decoy ClientHello naming an allowed site, sent ahead of
    /// the real one, gets through (`zero_evasion::decoy`). Tried third: it
    /// adds a few hundred milliseconds to every connection, where the empty
    /// record adds nothing.
    Decoy,
    /// Throttled; one byte of TCP urgent data in the middle of the server
    /// name gets through (`zero_evasion::urgent`). Tried second: like the
    /// empty record it adds no delay, and it works on any phone.
    Urgent,
}

impl CdnCondition {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Clear => 1,
            Self::Fragment => 2,
            Self::Ech => 3,
            Self::Blocked => 4,
            Self::EmptyRecord => 5,
            Self::Decoy => 6,
            Self::Urgent => 7,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Clear,
            2 => Self::Fragment,
            3 => Self::Ech,
            4 => Self::Blocked,
            5 => Self::EmptyRecord,
            6 => Self::Decoy,
            7 => Self::Urgent,
            _ => Self::Unknown,
        }
    }

    /// One sentence for the user, when there is something to say.
    pub fn notice(self) -> Option<&'static str> {
        match self {
            Self::Unknown | Self::Clear => None,
            Self::Fragment | Self::EmptyRecord => Some(
                "Cloudflare connections are throttled on this network; ZeroNet splits the handshake to get through.",
            ),
            Self::Decoy | Self::Urgent => Some(
                "Cloudflare connections are filtered by name on this network; ZeroNet sends a decoy name first to get through, so connections start a little slower.",
            ),
            Self::Ech => Some(
                "Cloudflare connections are throttled on this network; ZeroNet hides the server name with ECH to get through.",
            ),
            Self::Blocked => Some(
                "Cloudflare CDN configs don't work on this network right now, so ZeroNet is skipping them; use a direct or WARP config.",
            ),
        }
    }
}

/// What `condition` says about each CDN technique, as crowd-report
/// observations: the ways tried before the one that worked failed.
pub fn observations(condition: CdnCondition) -> &'static [(&'static str, bool)] {
    match condition {
        CdnCondition::Unknown => &[],
        CdnCondition::Clear => &[("cdn:plain", true)],
        CdnCondition::EmptyRecord => &[("cdn:plain", false), ("cdn:empty", true)],
        CdnCondition::Urgent => &[
            ("cdn:plain", false),
            ("cdn:empty", false),
            ("cdn:urgent", true),
        ],
        // From here on a device may have skipped a rung it cannot do, so
        // nothing is said about the urgent byte or the decoy on the way.
        CdnCondition::Decoy => &[
            ("cdn:plain", false),
            ("cdn:empty", false),
            ("cdn:decoy", true),
        ],
        // A device that cannot send a decoy skips it, so nothing is said
        // about the decoy on the way to the later rungs.
        CdnCondition::Fragment => &[
            ("cdn:plain", false),
            ("cdn:empty", false),
            ("cdn:fragment", true),
        ],
        CdnCondition::Ech => &[
            ("cdn:plain", false),
            ("cdn:empty", false),
            ("cdn:fragment", false),
            ("cdn:ech", true),
        ],
        CdnCondition::Blocked => &[
            ("cdn:plain", false),
            ("cdn:empty", false),
            ("cdn:fragment", false),
            ("cdn:ech", false),
        ],
    }
}

/// Whether `outbound` reaches its server through Cloudflare's CDN: TLS over
/// a CDN transport, to a Worker/Pages name or a Cloudflare address.
pub fn is_cloudflare_cdn(outbound: &Outbound) -> bool {
    let cdn_transport = matches!(
        outbound.stream.transport,
        Transport::WebSocket(_)
            | Transport::HttpUpgrade(_)
            | Transport::Grpc(_)
            | Transport::Xhttp(_)
    );
    let Security::Tls(tls) = &outbound.stream.security else {
        return false;
    };
    if !cdn_transport {
        return false;
    }
    let cloudflare_name = |name: &str| {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        name.ends_with(".workers.dev") || name.ends_with(".pages.dev")
    };
    if tls.server_name.as_deref().is_some_and(cloudflare_name) {
        return true;
    }
    match outbound.endpoint() {
        Some((Address::Ip(ip), _)) => is_cloudflare_ip(ip),
        Some((Address::Domain(name), _)) => cloudflare_name(&name),
        None => false,
    }
}

/// Cloudflare's published IPv6 prefixes, as (network, prefix length). On
/// networks that filter the IPv4 edge harder than the IPv6 one, a CDN config
/// is pointed at one of these, and it is still a CDN config.
const CLOUDFLARE_PREFIXES_V6: [(u128, u8); 7] = [
    (0x2400_cb00 << 96, 32),
    (0x2606_4700 << 96, 32),
    (0x2803_f800 << 96, 32),
    (0x2405_b500 << 96, 32),
    (0x2405_8100 << 96, 32),
    (0x2a06_98c0 << 96, 29),
    (0x2c0f_f248 << 96, 32),
];

fn is_cloudflare_ip(ip: IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            return CLOUDFLARE_PREFIXES_V6
                .iter()
                .any(|(network, prefix)| (bits ^ network) >> (128 - u32::from(*prefix)) == 0);
        }
    };
    let bits = u32::from(v4);
    zero_net::clean_ip::CLOUDFLARE_PREFIXES
        .iter()
        .any(|(network, prefix)| {
            let mask = if *prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(*prefix))
            };
            bits & mask == u32::from(*network) & mask
        })
}

/// The outbound with this module's own evasion removed, so each probe
/// variant starts from the same plain ClientHello.
fn plain(outbound: &Outbound) -> Outbound {
    let mut plain = outbound.clone();
    plain.stream.evasion.tcp_fragment = None;
    plain.stream.evasion.sni_desync = None;
    if let Security::Tls(tls) = &mut plain.stream.security {
        tls.ech = None;
    }
    plain
}

/// Make `outbound` use what `condition` says works. Leaves an outbound the
/// operator already configured with fragmentation or ECH alone.
pub fn apply(condition: CdnCondition, outbound: &mut Outbound) {
    if !is_cloudflare_cdn(outbound) {
        return;
    }
    let Security::Tls(tls) = &mut outbound.stream.security else {
        return;
    };
    let configured = tls.ech.is_some()
        || outbound.stream.evasion.tcp_fragment.is_some()
        || outbound.stream.evasion.sni_desync.is_some();
    match condition {
        CdnCondition::EmptyRecord if !configured => {
            outbound.stream.evasion.tcp_fragment =
                Some(zero_config::FragmentConfig::empty_record());
        }
        CdnCondition::Urgent if !configured => {
            outbound.stream.evasion.sni_desync = Some(zero_config::SniDesyncConfig::urgent());
        }
        CdnCondition::Decoy if !configured => {
            outbound.stream.evasion.sni_desync = Some(zero_config::SniDesyncConfig::decoy());
        }
        CdnCondition::Fragment if !configured => {
            outbound.stream.evasion.tcp_fragment = Some(zero_config::FragmentConfig::default());
        }
        CdnCondition::Ech if !configured => {
            // An empty list asks the runtime to fetch it from DNS.
            tls.ech = Some(zero_config::EchConfig {
                config_list: Box::default(),
                server_name: None,
            });
        }
        _ => {}
    }
}

/// Probe `outbound` (a Cloudflare CDN outbound): as is, then each way of
/// getting past a filter, cheapest first — an empty record (five bytes, no
/// delay), an urgent byte in the name (one byte, no delay), a decoy hello
/// (one resend per connection, and only where this device can send one),
/// TCP segments (a delay per piece), ECH (a DNS lookup first).
/// Returns the first that carries real data, or [`CdnCondition::Blocked`].
pub async fn probe(outbound: &Outbound, resolver: &zero_dns::Resolver) -> CdnCondition {
    let base = plain(outbound);
    if carries_data(&base, resolver).await {
        return CdnCondition::Clear;
    }
    for way in [
        CdnCondition::EmptyRecord,
        CdnCondition::Urgent,
        CdnCondition::Decoy,
        CdnCondition::Fragment,
        CdnCondition::Ech,
    ] {
        let possible = match way {
            CdnCondition::Urgent => {
                zero_evasion::decoy::enabled() && zero_evasion::urgent::supported()
            }
            CdnCondition::Decoy => zero_evasion::decoy::available(),
            _ => true,
        };
        if !possible {
            continue;
        }
        let mut shaped = base.clone();
        apply(way, &mut shaped);
        if carries_data(&shaped, resolver).await {
            return way;
        }
    }
    CdnCondition::Blocked
}

/// Fetch a 204 through `outbound`. True only when the answer arrives.
async fn carries_data(outbound: &Outbound, resolver: &zero_dns::Resolver) -> bool {
    let attempt = async {
        let destination = Destination::tcp(Address::Domain(PROBE_HOST.into()), 80);
        let stream = outbound::connect_with_resolver(outbound, &destination, resolver)
            .await
            .ok()?;
        let mut stream = outbound::strip_response(outbound, stream);
        stream.write_all(PROBE_REQUEST).await.ok()?;
        let mut head = [0u8; 12];
        stream.read_exact(&mut head).await.ok()?;
        Some(head.starts_with(b"HTTP/1.1 204") || head.starts_with(b"HTTP/1.0 204"))
    };
    matches!(
        tokio::time::timeout(ATTEMPT_TIMEOUT, attempt).await,
        Ok(Some(true))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(link: &str) -> Outbound {
        zero_config::parse_link(link).unwrap().outbound
    }

    const WORKER: &str = "vless://00000000-0000-0000-0000-000000000001@104.21.84.153:443?encryption=none&security=tls&sni=edge.example.workers.dev&type=ws&host=edge.example.workers.dev&path=%2Fp#w";

    #[test]
    fn recognises_cloudflare_cdn_outbounds() {
        assert!(is_cloudflare_cdn(&link(WORKER)));
        // A custom domain on a Cloudflare address.
        assert!(is_cloudflare_cdn(&link(
            "trojan://pw@172.67.1.2:443?security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com#t"
        )));
        // The same on a Cloudflare IPv6 address, and not on someone else's.
        assert!(is_cloudflare_cdn(&link(
            "trojan://pw@[2a06:98c1:3121::7]:443?security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com#six"
        )));
        assert!(!is_cloudflare_cdn(&link(
            "trojan://pw@[2001:db8::7]:443?security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com#other"
        )));
        // Plain TCP-TLS to an origin, REALITY, and a non-Cloudflare CDN
        // address are not Cloudflare CDN.
        assert!(!is_cloudflare_cdn(&link(
            "vless://00000000-0000-0000-0000-000000000001@203.0.113.9:443?encryption=none&security=tls&sni=a.example&type=tcp#o"
        )));
        assert!(!is_cloudflare_cdn(&link(
            "vless://00000000-0000-0000-0000-000000000001@203.0.113.9:443?encryption=none&security=reality&sni=www.speedtest.net&pbk=Bt5bY0cI6T9x3hTQ0bY7gE0oHn7YvH9o1qWlT0y0b2c&sid=6ba85179e30d4fc2&type=tcp#r"
        )));
        assert!(!is_cloudflare_cdn(&link(
            "vless://00000000-0000-0000-0000-000000000001@203.0.113.9:443?encryption=none&security=tls&sni=cdn.example.com&type=ws#n"
        )));
    }

    #[test]
    fn apply_sets_the_working_method_and_respects_the_operator() {
        let mut split = link(WORKER);
        apply(CdnCondition::Fragment, &mut split);
        let fragment = split.stream.evasion.tcp_fragment.expect("split");
        assert_eq!(
            fragment.packets,
            zero_config::FragmentPackets::Range { from: 1, to: 1 }
        );

        let mut decoy = link(WORKER);
        apply(CdnCondition::Decoy, &mut decoy);
        assert_eq!(
            decoy.stream.evasion.sni_desync.map(|d| d.method),
            Some(zero_config::SniMethod::Decoy)
        );
        let mut urgent = link(WORKER);
        apply(CdnCondition::Urgent, &mut urgent);
        assert_eq!(
            urgent.stream.evasion.sni_desync.map(|d| d.method),
            Some(zero_config::SniMethod::Urgent)
        );
        assert!(decoy.stream.evasion.tcp_fragment.is_none());

        let mut empty = link(WORKER);
        apply(CdnCondition::EmptyRecord, &mut empty);
        let fragment = empty.stream.evasion.tcp_fragment.expect("empty record");
        assert_eq!(fragment.packets, zero_config::FragmentPackets::TlsHello);
        assert_eq!(fragment.empty_records, 1);

        let mut ech = link(WORKER);
        apply(CdnCondition::Ech, &mut ech);
        let Security::Tls(tls) = &ech.stream.security else {
            panic!("TLS")
        };
        assert!(tls.ech.as_ref().is_some_and(|e| e.config_list.is_empty()));

        // Already fragmented by the operator: ECH is not layered on top.
        let mut chosen = link(WORKER);
        chosen.stream.evasion.tcp_fragment = Some(zero_config::FragmentConfig::default());
        apply(CdnCondition::Ech, &mut chosen);
        let Security::Tls(tls) = &chosen.stream.security else {
            panic!("TLS")
        };
        assert!(tls.ech.is_none());

        // Clear and Blocked change nothing on the outbound itself.
        let mut clear = link(WORKER);
        apply(CdnCondition::Clear, &mut clear);
        assert!(clear.stream.evasion.tcp_fragment.is_none());
        let Security::Tls(tls) = &clear.stream.security else {
            panic!("TLS")
        };
        assert!(tls.ech.is_none());
    }

    #[test]
    fn condition_round_trips_and_speaks_only_when_needed() {
        for condition in [
            CdnCondition::Unknown,
            CdnCondition::Clear,
            CdnCondition::Fragment,
            CdnCondition::Ech,
            CdnCondition::Blocked,
            CdnCondition::EmptyRecord,
            CdnCondition::Decoy,
            CdnCondition::Urgent,
        ] {
            assert_eq!(CdnCondition::from_u8(condition.as_u8()), condition);
        }
        assert!(CdnCondition::Clear.notice().is_none());
        assert!(CdnCondition::Blocked.notice().unwrap().contains("skipping"));
    }
}
