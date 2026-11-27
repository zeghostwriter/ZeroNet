//! Cloudflare-style config fronting, ported from BPB Worker Panel's
//! `getConfigAddresses` (design, not source — BPB is GPL-3.0).
//!
//! The idea BPB is built around: a VLESS/Trojan config that rides a Cloudflare
//! CDN (WebSocket/httpupgrade/gRPC/XHTTP over TLS) does not have to be reached
//! at the address written in the link. The same worker answers on *any* of
//! Cloudflare's edge IPs and on several alternate HTTPS ports, and the TLS SNI
//! (not the connect IP) is what routes it. So one config becomes many
//! candidates — each "clean" edge IP crossed with each HTTPS port — and the
//! finder keeps whichever the ISP still passes today, exactly as BPB's panel
//! hands out one config per address×port.
//!
//! Only CDN-fronted TLS links are expanded. REALITY is never fronted: its
//! handshake is bound to the specific server's key, so pointing it at another
//! IP just breaks it. Plain TCP-TLS to an origin is left alone too — there is
//! no CDN edge behind it to reach on another address.

use std::collections::BTreeSet;

use zero_config::{Security, Transport};
use zero_net::clean_ip::CDN_TLS_PORTS;

/// Expand one share link into CDN-fronted variants across `clean_ips` and the
/// Cloudflare HTTPS ports, capped at `max_variants`.
///
/// Returns an empty vec for a link that is not CDN-frontable, that will not
/// parse, or when there is nothing to front onto. Each `clean_ips` entry is a
/// bare host or IP (v4, or v6 with or without brackets); the original SNI and
/// WebSocket host header are preserved so the edge still routes the tunnel.
pub fn front_link(link: &str, clean_ips: &[String], max_variants: usize) -> Vec<String> {
    if max_variants == 0 || clean_ips.is_empty() {
        return Vec::new();
    }
    let Ok(parsed) = zero_config::parse_link(link) else {
        return Vec::new();
    };
    let stream = &parsed.outbound.stream;
    let cdn_transport = matches!(
        stream.transport,
        Transport::WebSocket(_)
            | Transport::HttpUpgrade(_)
            | Transport::Grpc(_)
            | Transport::Xhttp(_)
    );
    if !matches!(stream.security, Security::Tls(_)) || !cdn_transport {
        return Vec::new();
    }

    let Some(parts) = split_link(link) else {
        return Vec::new();
    };
    let origin_host = authority_host(parts.authority);
    // The edge routes by SNI, so the name must survive the address change. A
    // link that names its worker only in `host=` (address written as an IP)
    // still has one; a link with no name at all cannot be fronted.
    let sni = query_value(parts.query, "sni")
        .or_else(|| query_value(parts.query, "host"))
        .unwrap_or(origin_host);
    if sni
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok()
    {
        return Vec::new();
    }
    let host_header = query_value(parts.query, "host").unwrap_or(sni);

    let edges: Vec<&str> = clean_ips
        .iter()
        .map(|ip| ip.trim())
        .filter(|host| !host.is_empty() && !host.eq_ignore_ascii_case(origin_host))
        .collect();
    if edges.is_empty() {
        return Vec::new();
    }
    // Spread a small budget over as many edges *and* ports as it allows:
    // every edge once (each on a different port) before any edge twice.
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for round in 0..CDN_TLS_PORTS.len() {
        for (index, host) in edges.iter().enumerate() {
            if out.len() >= max_variants {
                return out;
            }
            let port = CDN_TLS_PORTS[(index + round) % CDN_TLS_PORTS.len()];
            let variant = rebuild(&parts, &fmt_host(host), port, sni, host_header);
            if seen.insert(variant.clone()) {
                out.push(variant);
            }
        }
    }
    out
}

/// The pieces of a `scheme://userinfo@authority?query#fragment` link, kept as
/// slices of the original so a rebuild changes only what it must.
struct LinkParts<'a> {
    prefix: &'a str, // "scheme://" plus "userinfo@" when present
    authority: &'a str,
    query: &'a str,    // without the leading '?', may be empty
    fragment: &'a str, // without the leading '#', may be empty
    has_fragment: bool,
}

fn split_link(link: &str) -> Option<LinkParts<'_>> {
    let scheme_end = link.find("://")? + 3;
    let rest = &link[scheme_end..];
    let (before_fragment, fragment, has_fragment) = match rest.split_once('#') {
        Some((body, frag)) => (body, frag, true),
        None => (rest, "", false),
    };
    let (authority_part, query) = match before_fragment.split_once('?') {
        Some((auth, q)) => (auth, q),
        None => (before_fragment, ""),
    };
    // The host:port is everything after any "userinfo@"; the prefix keeps the
    // scheme and that userinfo, so only the address is replaced.
    let authority = match authority_part.rsplit_once('@') {
        Some((_userinfo, host)) => host,
        None => authority_part,
    };
    let authority_offset = authority.as_ptr() as usize - link.as_ptr() as usize;
    let prefix = &link[..authority_offset];
    Some(LinkParts {
        prefix,
        authority,
        query,
        fragment,
        has_fragment,
    })
}

/// The host of an `authority` (`host`, `host:port`, `[v6]`, `[v6]:port`),
/// without brackets or port.
fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

fn fmt_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
}

/// Rebuild the link at a new host:port, forcing `sni`/`host` so the edge still
/// routes to the original worker.
fn rebuild(parts: &LinkParts<'_>, host: &str, port: u16, sni: &str, host_header: &str) -> String {
    let mut pairs: Vec<(String, String)> = parts
        .query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (pair.to_string(), String::new()),
        })
        .collect();
    upsert(&mut pairs, "sni", sni);
    upsert(&mut pairs, "host", host_header);

    let query: String = pairs
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                k.clone()
            } else {
                format!("{k}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join("&");

    let mut out = format!("{}{host}:{port}?{query}", parts.prefix);
    if parts.has_fragment {
        out.push('#');
        out.push_str(parts.fragment);
    }
    out
}

fn upsert(pairs: &mut Vec<(String, String)>, key: &str, value: &str) {
    match pairs.iter_mut().find(|(k, _)| k == key) {
        Some(pair) => pair.1 = value.to_string(),
        None => pairs.push((key.to_string(), value.to_string())),
    }
}

/// Front each CDN-frontable link across a bounded, deterministic sample of
/// Cloudflare edge IPs — the finder-side of BPB's trick, with the edge list
/// generated from Cloudflare's published prefixes instead of a resolver (DoH
/// is often the first thing an ISP blocks).
///
/// `seed` keeps the sample stable for a session (so probe evidence
/// accumulates against the same edges); `per_prefix` addresses are drawn from
/// each prefix and the whole result is capped at `max_variants`. Non-frontable
/// links (REALITY, plain TCP-TLS, non-TLS) contribute nothing.
pub fn front_via_edges(
    links: &[String],
    seed: u64,
    per_prefix: u8,
    max_variants: usize,
) -> Vec<String> {
    if max_variants == 0 {
        return Vec::new();
    }
    let mut edges: Vec<String> = Vec::new();
    for candidate in zero_net::clean_ip::cloudflare_candidates("cdn", &[443], per_prefix, seed) {
        let ip = candidate.address.ip().to_string();
        if !edges.contains(&ip) {
            edges.push(ip);
        }
    }
    // Interleave the links, so the first frontable one cannot take the whole
    // budget and every past find gets a few edges.
    let per_link: Vec<Vec<String>> = links
        .iter()
        .map(|link| front_link(link, &edges, max_variants))
        .filter(|variants| !variants.is_empty())
        .collect();
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let longest = per_link.iter().map(Vec::len).max().unwrap_or(0);
    'fill: for index in 0..longest {
        for variants in &per_link {
            if out.len() >= max_variants {
                break 'fill;
            }
            if let Some(variant) = variants.get(index) {
                if seen.insert(variant.clone()) {
                    out.push(variant.clone());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const WS_TLS: &str = "vless://00000000-0000-0000-0000-000000000002@cdn.example.com:443\
        ?security=tls&sni=cdn.example.com&type=ws&path=%2Fws&host=cdn.example.com&encryption=none#Edge";
    const REALITY: &str = "vless://00000000-0000-0000-0000-000000000001@203.0.113.10:443\
        ?security=reality&sni=www.googletagmanager.com&fp=chrome\
        &pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0123456789abcdef&type=tcp&encryption=none#R";
    const TCP_TLS: &str =
        "trojan://secret@origin.example.com:443?security=tls&sni=origin.example.com#Direct";

    fn front(link: &str) -> Vec<String> {
        front_link(link, &["1.2.3.4".into(), "cdn.example.com".into()], 100)
    }

    #[test]
    fn a_cdn_ws_tls_link_expands_across_clean_ips_and_ports() {
        let variants = front(WS_TLS);
        // One clean IP is usable (the other equals the origin host, skipped),
        // crossed with every Cloudflare HTTPS port.
        assert_eq!(variants.len(), CDN_TLS_PORTS.len());
        for (variant, port) in variants.iter().zip(CDN_TLS_PORTS) {
            // Address swapped to the clean IP on a Cloudflare port…
            assert!(
                variant.contains(&format!("@1.2.3.4:{port}?")),
                "address/port not fronted: {variant}"
            );
            // …but the SNI and WS host stay the worker domain, so it still routes.
            zero_config::parse_link(variant)
                .unwrap_or_else(|e| panic!("fronted link did not parse: {e}\n{variant}"));
            assert!(
                variant.contains("sni=cdn.example.com"),
                "SNI lost: {variant}"
            );
            assert!(
                variant.contains("host=cdn.example.com"),
                "host lost: {variant}"
            );
            assert!(variant.ends_with("#Edge"), "remark lost: {variant}");
        }
    }

    #[test]
    fn reality_and_plain_tcp_tls_are_never_fronted() {
        // REALITY is bound to the server key; fronting it just breaks it.
        assert!(front(REALITY).is_empty(), "REALITY was fronted");
        // A direct TCP-TLS origin has no CDN edge to reach elsewhere.
        assert!(front(TCP_TLS).is_empty(), "plain TCP-TLS was fronted");
    }

    #[test]
    fn the_variant_count_is_capped_and_the_origin_ip_is_skipped() {
        let ips: Vec<String> = (0..50).map(|i| format!("10.0.0.{i}")).collect();
        let variants = front_link(WS_TLS, &ips, 8);
        assert_eq!(variants.len(), 8, "cap not honoured");

        // A clean IP equal to the origin host contributes nothing.
        let none = front_link(WS_TLS, &["cdn.example.com".into()], 100);
        assert!(none.is_empty(), "origin host should be skipped");
    }

    #[test]
    fn a_link_with_no_sni_yet_gains_the_origin_host_as_sni() {
        let bare = "vless://uuid@worker.dev:443?security=tls&type=ws&path=%2Fp&encryption=none#N";
        let variants = front_link(bare, &["9.9.9.9".into()], 1);
        assert_eq!(variants.len(), 1);
        let v = &variants[0];
        assert!(v.contains("sni=worker.dev"), "SNI not derived: {v}");
        assert!(v.contains("host=worker.dev"), "host not derived: {v}");
        assert!(zero_config::parse_link(v).is_ok(), "did not parse: {v}");
    }

    #[test]
    fn a_worker_named_only_in_host_keeps_that_name_as_sni() {
        let link = "vless://uuid@104.16.1.1:443?security=tls&type=ws&host=my.worker.dev&path=%2F&encryption=none#W";
        let variants = front_link(link, &["9.9.9.9".into()], 1);
        assert_eq!(variants.len(), 1);
        assert!(variants[0].contains("sni=my.worker.dev"), "{}", variants[0]);
        // No name anywhere: the edge could not route it, so it is not fronted.
        let nameless =
            "vless://uuid@104.16.1.1:443?security=tls&type=ws&path=%2F&encryption=none#N";
        assert!(front_link(nameless, &["9.9.9.9".into()], 4).is_empty());
    }

    #[test]
    fn a_small_budget_covers_many_edges_and_ports() {
        let ips: Vec<String> = (1..=6).map(|i| format!("10.0.0.{i}")).collect();
        let variants = front_link(WS_TLS, &ips, 6);
        let edges: BTreeSet<&str> = variants
            .iter()
            .filter_map(|v| v.split('@').nth(1)?.split(':').next())
            .collect();
        assert_eq!(
            edges.len(),
            6,
            "each edge once before any twice: {variants:?}"
        );
        let ports: BTreeSet<&str> = variants
            .iter()
            .filter_map(|v| v.split('@').nth(1)?.split(':').nth(1)?.split('?').next())
            .collect();
        assert!(ports.len() > 1, "all on one port: {variants:?}");
    }

    #[test]
    fn every_frontable_link_gets_a_share_of_the_budget() {
        let other = WS_TLS.replace("cdn.example.com", "second.example.org");
        let variants = front_via_edges(&[WS_TLS.into(), other], 7, 1, 6);
        assert_eq!(variants.len(), 6);
        assert!(variants.iter().any(|v| v.contains("sni=cdn.example.com")));
        assert!(variants
            .iter()
            .any(|v| v.contains("sni=second.example.org")));
    }

    #[test]
    fn edge_fronting_expands_frontable_links_and_skips_the_rest() {
        // A CDN WS-TLS link gets fronted onto Cloudflare edges, capped.
        let variants = front_via_edges(&[WS_TLS.into()], 7, 1, 10);
        assert_eq!(variants.len(), 10, "cap not honoured");
        for v in &variants {
            assert!(v.starts_with("vless://"), "not a vless variant: {v}");
            assert!(v.contains("sni=cdn.example.com"), "SNI lost: {v}");
            zero_config::parse_link(v).unwrap_or_else(|e| panic!("did not parse: {e}\n{v}"));
        }
        // Deterministic for a given seed.
        assert_eq!(variants, front_via_edges(&[WS_TLS.into()], 7, 1, 10));
        // REALITY / plain TCP-TLS contribute nothing.
        assert!(front_via_edges(&[REALITY.into(), TCP_TLS.into()], 7, 1, 10).is_empty());
    }
}
