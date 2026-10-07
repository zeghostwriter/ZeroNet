//! Share links as the app sees them: a stable identity, a display summary,
//! and a coarse class used to spread liveness tests across kinds of servers.
//!
//! The parser proper lives in `zero_config::share_link`; this module only
//! decides *which* pieces of arbitrary pasted text are links, gives each one a
//! key that survives remark edits, and summarises it as a [`LinkInfo`].
//!
//! ## The key
//!
//! Public feeds republish the same server under a new remark every few hours
//! ("🇩🇪 Germany | 12ms | @channel"). A key over the whole link would treat
//! each republish as a new server and throw away everything learned about it,
//! so the key covers the link *without* its `#fragment`: the first 16 hex
//! digits of a BLAKE3 hash of the trimmed, `&amp;`-unescaped link body. The
//! remark still reaches the user as the display name.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;
use zero_config::{OutboundProtocol, Security, ShareLink, Transport};

/// What the app is told about one link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkInfo {
    pub key: String,
    pub link: String,
    pub name: String,
    pub protocol: String,
    pub transport: String,
    pub security: String,
    pub host: String,
    pub port: u16,
    pub country: String,
    /// [`LinkClass::as_str`]: the family discovery interleaves by.
    pub class: String,
    /// For a WARP account, the fingerprint of its keys (`warp::fingerprint`),
    /// which a screen draws as a small picture so accounts are told apart.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
}

/// Coarse server families, in the order candidates are interleaved.
///
/// The classes differ in *how* they fail under filtering, which is why
/// testing them round-robin finds a working server sooner than testing a feed
/// in its published order (which is usually hundreds of one kind first):
///
/// * XHTTP with an `extra` block — split upload/download paths, the newest and
///   currently hardest to classify;
/// * REALITY — direct TLS impersonation of a real site;
/// * TLS over WebSocket, gRPC or HTTPUpgrade — the CDN-fronted family;
/// * everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LinkClass {
    XhttpExtra,
    Reality,
    CdnTls,
    Other,
}

impl LinkClass {
    /// The contract's name for the class.
    pub fn as_str(self) -> &'static str {
        match self {
            LinkClass::XhttpExtra => "xhttp_extra",
            LinkClass::Reality => "reality",
            LinkClass::CdnTls => "cdn",
            LinkClass::Other => "other",
        }
    }

    pub const ALL: [LinkClass; 4] = [
        LinkClass::XhttpExtra,
        LinkClass::Reality,
        LinkClass::CdnTls,
        LinkClass::Other,
    ];
}

/// A link that parsed and validated, ready to be tested or configured.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub info: LinkInfo,
    pub outbound: zero_config::Outbound,
    pub class: LinkClass,
}

impl Candidate {
    /// Protocols carried over UDP (QUIC). A TCP connect to their port proves
    /// nothing, so the TCP stage passes them straight to the real test.
    pub fn is_udp_based(&self) -> bool {
        matches!(
            self.outbound.protocol,
            OutboundProtocol::Hysteria2(_) | OutboundProtocol::Tuic(_)
        )
    }
}

/// The stable key of a link: see the module documentation.
pub fn link_key(link: &str) -> String {
    let link = link.trim().trim_start_matches('\u{feff}');
    let unescaped;
    let link = if link.contains("&amp;") {
        unescaped = link.replace("&amp;", "&");
        unescaped.as_str()
    } else {
        link
    };
    let body = link.split_once('#').map_or(link, |(body, _)| body).trim();
    let hash = blake3::hash(body.as_bytes());
    hash.to_hex()[..16].to_string()
}

/// Turn a parsed share link into a validated [`Candidate`].
pub fn candidate_from(parsed: ShareLink) -> Result<Candidate, String> {
    parsed.outbound.validate()?;
    let class = classify(&parsed);
    let info = summarize(&parsed, class);
    Ok(Candidate {
        info,
        outbound: parsed.outbound,
        class,
    })
}

/// Parse and validate one link.
pub fn parse_candidate(link: &str) -> Result<Candidate, String> {
    let parsed = zero_config::parse_link(link)?;
    candidate_from(parsed)
}

/// Whether an endpoint may be dialled as a discovered server.
///
/// Public feeds are written by strangers. A link pointing at `127.0.0.1`, the
/// LAN, link-local or the carrier-grade NAT range would turn discovery into a
/// probe of the user's own machine or network, so feed links are held to
/// public addresses. A host name is left to the resolver: it is the answer,
/// not the spelling, that decides where a connection lands. The test and
/// documentation ranges are not refused — they reach nothing either way.
fn public_host(host: &str) -> bool {
    let Ok(ip) = host.parse::<IpAddr>() else {
        // Names that can only ever mean this machine or its network.
        let name = host.trim_end_matches('.').to_ascii_lowercase();
        return !(name == "localhost"
            || name.ends_with(".localhost")
            || name.ends_with(".local")
            || name.ends_with(".internal")
            || name.ends_with(".lan"));
    };
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    // 100.64.0.0/10: carrier-grade NAT, where a user's own router or ISP
    // equipment usually lives.
    let cgnat = octets[0] == 100 && (octets[1] & 0xc0) == 64;
    !(v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        // 0.0.0.0/8 ("this network") and 240.0.0.0/4 (reserved).
        || octets[0] == 0
        || octets[0] >= 240
        || cgnat)
}

fn public_v6(v6: Ipv6Addr) -> bool {
    // An IPv4-mapped address is an IPv4 address in disguise.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return public_v4(v4);
    }
    !(v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || v6.is_unique_local()
        || v6.is_unicast_link_local())
}

fn require_public(candidate: &Candidate) -> Result<(), String> {
    let Some((address, _)) = candidate.outbound.endpoint() else {
        return Ok(());
    };
    let host = address.host_string();
    // An IPv6 literal keeps its brackets in the display form; strip them so
    // it is parsed as an address rather than mistaken for a host name.
    let bare = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(&host);
    if public_host(bare) {
        Ok(())
    } else {
        Err(format!("host {host} must be a public address"))
    }
}

fn summarize(parsed: &ShareLink, class: LinkClass) -> LinkInfo {
    let outbound = &parsed.outbound;
    let (host, port) = outbound
        .endpoint()
        .map(|(address, port)| (address.host_string(), port))
        .unwrap_or_default();
    let quic = matches!(
        outbound.protocol,
        OutboundProtocol::Hysteria2(_) | OutboundProtocol::Tuic(_)
    );
    let protocol = match outbound.protocol.name() {
        "shadowsocks" => "ss",
        other => other,
    }
    .to_string();
    let transport = if quic {
        "quic".to_string()
    } else {
        match outbound.stream.transport.name() {
            "raw" => "tcp",
            other => other,
        }
        .to_string()
    };
    let security = if quic {
        "tls".to_string()
    } else {
        outbound.stream.security.name().to_string()
    };
    let remark = parsed.remark.trim();
    let name = if remark.is_empty() {
        host.clone()
    } else {
        remark.chars().take(120).collect()
    };
    let fp = parsed
        .link
        .starts_with(zero_config::share_link::WARP_LINK_SCHEME)
        .then(|| crate::warp::fingerprint(&parsed.link))
        .flatten();
    LinkInfo {
        key: link_key(&parsed.link),
        link: parsed.link.clone(),
        country: guess_country(remark),
        name,
        protocol,
        transport,
        security,
        host,
        port,
        class: class.as_str().to_string(),
        fp,
    }
}

fn classify(parsed: &ShareLink) -> LinkClass {
    let stream = &parsed.outbound.stream;
    match (&stream.transport, &stream.security) {
        (Transport::Xhttp(_), _) if link_has_param(&parsed.link, "extra") => LinkClass::XhttpExtra,
        (_, Security::Reality(_)) => LinkClass::Reality,
        (
            Transport::WebSocket(_) | Transport::Grpc(_) | Transport::HttpUpgrade(_),
            Security::Tls(_),
        ) => LinkClass::CdnTls,
        _ => LinkClass::Other,
    }
}

fn link_has_param(link: &str, name: &str) -> bool {
    let body = link.split_once('#').map_or(link, |(body, _)| body);
    let Some((_, query)) = body.split_once('?') else {
        return false;
    };
    query.split('&').any(|pair| {
        let key = pair.split_once('=').map_or(pair, |(key, _)| key);
        key.eq_ignore_ascii_case(name)
            && pair
                .split_once('=')
                .is_some_and(|(_, value)| !value.trim().is_empty())
    })
}

// ------------------------------------------------------------------ country

/// ISO-3166 alpha-2 codes, concatenated.
const ISO_CODES: &str = "ADAEAFAGAIALAMAOAQARASATAUAWAXAZBABBBDBEBFBGBHBIBJBLBMBNBOBQBRBSBTBVBWBYBZCACCCDCFCGCHCICKCLCMCNCOCRCUCVCWCXCYCZDEDJDKDMDODZECEEEGEHERESETFIFJFKFMFOFRGAGBGDGEGFGGGHGIGLGMGNGPGQGRGSGTGUGWGYHKHMHNHRHTHUIDIEILIMINIOIQIRISITJEJMJOJPKEKGKHKIKMKNKPKRKWKYKZLALBLCLILKLRLSLTLULVLYMAMCMDMEMFMGMHMKMLMMMNMOMPMQMRMSMTMUMVMWMXMYMZNANCNENFNGNINLNONPNRNUNZOMPAPEPFPGPHPKPLPMPNPRPSPTPWPYQARERORSRURWSASBSCSDSESGSHSISJSKSLSMSNSOSRSSSTSVSXSYSZTCTDTFTGTHTJTKTLTMTNTOTRTTTVTWTZUAUGUMUSUYUZVAVCVEVGVIVNVUWFWSYEYTZAZMZW";

/// Upper-case two-letter tokens that are ISO codes but, in a remark, are far
/// more often ordinary words or abbreviations than countries.
const AMBIGUOUS_CODES: [&str; 6] = ["TO", "AS", "AM", "PM", "IS", "ID"];

/// English country names seen in feed remarks, for remarks with neither a
/// flag nor a code.
const COUNTRY_NAMES: [(&str, &str); 36] = [
    ("germany", "DE"),
    ("netherlands", "NL"),
    ("holland", "NL"),
    ("finland", "FI"),
    ("france", "FR"),
    ("united kingdom", "GB"),
    ("england", "GB"),
    ("london", "GB"),
    ("united states", "US"),
    ("usa", "US"),
    ("america", "US"),
    ("canada", "CA"),
    ("turkey", "TR"),
    ("türkiye", "TR"),
    ("russia", "RU"),
    ("sweden", "SE"),
    ("poland", "PL"),
    ("austria", "AT"),
    ("switzerland", "CH"),
    ("singapore", "SG"),
    ("japan", "JP"),
    ("hong kong", "HK"),
    ("india", "IN"),
    ("iran", "IR"),
    ("emirates", "AE"),
    ("dubai", "AE"),
    ("armenia", "AM"),
    ("romania", "RO"),
    ("spain", "ES"),
    ("italy", "IT"),
    ("estonia", "EE"),
    ("latvia", "LV"),
    ("lithuania", "LT"),
    ("norway", "NO"),
    ("denmark", "DK"),
    ("ireland", "IE"),
];

fn is_iso_code(code: &str) -> bool {
    code.len() == 2
        && ISO_CODES
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .any(|pair| pair.as_slice() == code.as_bytes())
}

/// Guess an ISO-3166 alpha-2 country from a remark.
///
/// In order of reliability: a flag emoji (two regional-indicator symbols), an
/// upper-case two-letter code standing as its own token (`DE`, `[NL]`,
/// `US-1`), then an English country name. Empty when nothing matches.
pub fn guess_country(remark: &str) -> String {
    let chars: Vec<char> = remark.chars().collect();
    for pair in chars.windows(2) {
        let (a, b) = (pair[0] as u32, pair[1] as u32);
        if (0x1F1E6..=0x1F1FF).contains(&a) && (0x1F1E6..=0x1F1FF).contains(&b) {
            let code: String = [a, b]
                .iter()
                .map(|value| char::from(b'A' + (value - 0x1F1E6) as u8))
                .collect();
            if is_iso_code(&code) {
                return code;
            }
        }
    }
    for token in remark.split(|c: char| !c.is_ascii_alphanumeric()) {
        if token.len() == 2
            && token.chars().all(|c| c.is_ascii_uppercase())
            && is_iso_code(token)
            && !AMBIGUOUS_CODES.contains(&token)
        {
            return token.to_string();
        }
    }
    let lower = remark.to_lowercase();
    for (name, code) in COUNTRY_NAMES {
        if lower.contains(name) {
            return code.to_string();
        }
    }
    String::new()
}

// ------------------------------------------------------------ text to links

const SCHEMES: [&str; 11] = [
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "anytls://",
    "zerov1://",
    "tide://",
    "warp://",
];

/// Pull every proxy share link out of arbitrary text: one link per line, a
/// base64 subscription body, links embedded in prose or HTML, several links on
/// one line. Anything that is not a proxy link (web URLs, prose) is ignored
/// rather than counted as a failure.
pub fn extract_links(text: &str) -> Vec<String> {
    let text = text.trim_start_matches('\u{feff}');
    // Panels that serve a whole Xray or sing-box config (BPB's `?app=xray`).
    if let Some(links) = crate::json_subscription::links_from_json(text) {
        return links;
    }
    let decoded;
    let text = if !contains_scheme(text) {
        match decode_base64_body(text) {
            Some(body) => {
                decoded = body;
                decoded.as_str()
            }
            None => text,
        }
    } else {
        text
    };
    let text = text
        .replace("<br/>", "\n")
        .replace("<br />", "\n")
        .replace("<br>", "\n");
    let mut links = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        // Every scheme occurrence starts a link that runs to the next
        // whitespace or quote. Scanning positions in order keeps "ss://"
        // from matching inside "vless://…" twice.
        let mut starts: Vec<usize> = Vec::new();
        for scheme in SCHEMES {
            let mut from = 0;
            while let Some(found) = lower[from..].find(scheme) {
                let at = from + found;
                // A scheme must start a token: `vless://` contains `ss://`
                // three bytes in, and that inner match is not a link.
                let boundary = at == 0 || !lower.as_bytes()[at - 1].is_ascii_alphanumeric();
                if boundary {
                    starts.push(at);
                }
                from = at + scheme.len();
            }
        }
        starts.sort_unstable();
        starts.dedup();
        for (index, &start) in starts.iter().enumerate() {
            let limit = starts.get(index + 1).copied().unwrap_or(line.len());
            let candidate = &line[start..limit];
            let end = candidate
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`'))
                .unwrap_or(candidate.len());
            let link = candidate[..end].trim_end_matches([',', ';', ')', ']']);
            if link.len() > 8 {
                links.push(link.to_string());
            }
        }
    }
    links
}

fn contains_scheme(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SCHEMES.iter().any(|scheme| lower.contains(scheme))
}

fn decode_base64_body(body: &str) -> Option<String> {
    use base64::Engine as _;
    let compact: String = body.split_whitespace().collect();
    if compact.is_empty() {
        return None;
    }
    let engines = [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    for engine in engines {
        if let Ok(bytes) = engine.decode(compact.as_bytes()) {
            if let Ok(text) = String::from_utf8(bytes) {
                if contains_scheme(&text) {
                    return Some(text);
                }
            }
        }
    }
    None
}

/// The result of [`parse_links`], serialised as the `parseLinks` answer.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ParseReport {
    pub items: Vec<LinkInfo>,
    pub rejected: usize,
    pub reasons: BTreeMap<String, usize>,
    /// Links dropped because an earlier one had the same key.
    pub duplicates: usize,
}

/// A low-cardinality bucket for a rejection, so the app can show "12 used an
/// unsupported scheme" rather than twelve distinct parser sentences.
pub fn rejection_reason(link: &str, error: &str) -> String {
    let scheme = link
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .unwrap_or_default();
    let error = error.to_ascii_lowercase();
    let kind = if error.contains("unsupported") {
        "unsupported"
    } else if error.contains("not supported")
        || error.contains("requires")
        || error.contains("cannot be combined")
        || error.contains("must be")
    {
        "invalid"
    } else {
        "malformed"
    };
    if scheme.is_empty() {
        kind.to_string()
    } else {
        format!("{scheme}:{kind}")
    }
}

/// Parse any text into validated, de-duplicated links.
pub fn parse_links(text: &str) -> ParseReport {
    let (candidates, mut report) = parse_candidates(text, &HashSet::new());
    report.items = candidates
        .into_iter()
        .map(|candidate| candidate.info)
        .collect();
    report
}

/// Parse text into candidates, skipping any key in `exclude`. The report's
/// `items` is left empty; the candidates carry the same information.
pub fn parse_candidates(text: &str, exclude: &HashSet<String>) -> (Vec<Candidate>, ParseReport) {
    parse_candidates_inner(text, exclude, false)
}

/// [`parse_candidates`] for a downloaded feed: the same, but a link that
/// points at the local machine or network is rejected (see [`public_host`]).
pub fn parse_feed_candidates(
    text: &str,
    exclude: &HashSet<String>,
) -> (Vec<Candidate>, ParseReport) {
    parse_candidates_inner(text, exclude, true)
}

fn parse_candidates_inner(
    text: &str,
    exclude: &HashSet<String>,
    public_only: bool,
) -> (Vec<Candidate>, ParseReport) {
    let mut report = ParseReport::default();
    let mut seen: HashSet<String> = HashSet::new();
    let mut candidates = Vec::new();
    for link in extract_links(text) {
        let key = link_key(&link);
        if exclude.contains(&key) || !seen.insert(key) {
            report.duplicates += 1;
            continue;
        }
        let parsed = parse_candidate(&link).and_then(|candidate| {
            if public_only {
                require_public(&candidate)?;
            }
            Ok(candidate)
        });
        match parsed {
            Ok(candidate) => candidates.push(candidate),
            Err(error) => {
                report.rejected += 1;
                *report
                    .reasons
                    .entry(rejection_reason(&link, &error))
                    .or_insert(0) += 1;
            }
        }
    }
    (candidates, report)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const REALITY: &str = "vless://00000000-0000-0000-0000-000000000001@203.0.113.10:443\
        ?security=reality&sni=www.googletagmanager.com&fp=chrome\
        &pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0123456789abcdef\
        &type=tcp&encryption=none#%F0%9F%87%A9%F0%9F%87%AA%20Frankfurt";
    pub const WS_TLS: &str = "vless://00000000-0000-0000-0000-000000000002@cdn.example.com:443\
        ?security=tls&sni=cdn.example.com&type=ws&path=%2Fws&host=cdn.example.com\
        &encryption=none#NL-edge";
    pub const XHTTP_EXTRA: &str = "vless://00000000-0000-0000-0000-000000000003@x.example.com:443\
        ?security=tls&sni=x.example.com&type=xhttp&path=%2Fx&mode=auto\
        &extra=%7B%22xmux%22%3A%7B%7D%7D&encryption=none#xhttp";
    pub const TROJAN: &str =
        "trojan://secret@198.51.100.7:8443?security=tls&sni=t.example.com#Germany%20trojan";
    pub const SS: &str = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@192.0.2.9:8388#plain";
    pub const HYSTERIA2: &str =
        "hysteria2://secret@203.0.113.20:443?security=tls&sni=h2.example.com#hy2";

    #[test]
    fn the_key_ignores_the_remark_and_surrounding_noise() {
        let a = link_key(REALITY);
        let b = link_key(&format!("  {}  ", REALITY.replace("Frankfurt", "renamed")));
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, link_key(WS_TLS));
        // HTML-escaped separators describe the same link.
        assert_eq!(link_key(WS_TLS), link_key(&WS_TLS.replace('&', "&amp;")));
    }

    #[test]
    fn links_are_summarised_for_the_app() {
        let reality = parse_candidate(REALITY).unwrap();
        assert_eq!(reality.info.protocol, "vless");
        assert_eq!(reality.info.transport, "tcp");
        assert_eq!(reality.info.security, "reality");
        assert_eq!(reality.info.host, "203.0.113.10");
        assert_eq!(reality.info.port, 443);
        assert_eq!(reality.info.country, "DE");
        assert_eq!(reality.class, LinkClass::Reality);
        assert_eq!(reality.info.class, "reality");

        let ws = parse_candidate(WS_TLS).unwrap();
        assert_eq!(ws.info.transport, "ws");
        assert_eq!(ws.info.country, "NL");
        assert_eq!(ws.class, LinkClass::CdnTls);
        assert_eq!(ws.info.class, "cdn");

        let xhttp = parse_candidate(XHTTP_EXTRA).unwrap();
        assert_eq!(xhttp.class, LinkClass::XhttpExtra);
        assert_eq!(xhttp.info.class, "xhttp_extra");

        let ss = parse_candidate(SS).unwrap();
        assert_eq!(ss.info.protocol, "ss");
        assert_eq!(ss.info.name, "plain");
        assert_eq!(ss.class, LinkClass::Other);

        assert_eq!(parse_candidate(TROJAN).unwrap().info.country, "DE");
    }

    #[test]
    fn countries_come_from_flags_codes_and_names() {
        assert_eq!(guess_country("🇫🇮 Helsinki"), "FI");
        assert_eq!(guess_country("[US] fast"), "US");
        assert_eq!(guess_country("Server in netherlands"), "NL");
        // Lower-case words and ambiguous codes are not countries.
        assert_eq!(guess_country("go to it"), "");
        assert_eq!(guess_country("AS 13335"), "");
        assert_eq!(guess_country(""), "");
    }

    #[test]
    fn mixed_text_base64_and_duplicates_are_handled() {
        let text = format!(
            "Join our channel https://t.me/example\n{REALITY}\n\n\
             two on a line: {WS_TLS} {SS}\n\
             {}\n\
             vless://broken\nunknown://thing\n",
            REALITY.replace("Frankfurt", "copy")
        );
        let report = parse_links(&text);
        assert_eq!(report.items.len(), 3, "{report:?}");
        assert_eq!(report.duplicates, 1);
        assert_eq!(report.rejected, 1);
        assert_eq!(report.reasons.get("vless:malformed"), Some(&1));

        use base64::Engine as _;
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{REALITY}\n{TROJAN}\n"));
        let report = parse_links(&encoded);
        assert_eq!(report.items.len(), 2);
    }

    #[test]
    fn a_scheme_inside_another_is_not_a_second_link() {
        let links = extract_links(WS_TLS);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0], WS_TLS);
    }

    #[test]
    fn excluded_keys_are_skipped() {
        let exclude: HashSet<String> = [link_key(REALITY)].into_iter().collect();
        let (candidates, report) = parse_candidates(&format!("{REALITY}\n{SS}"), &exclude);
        assert_eq!(candidates.len(), 1);
        assert_eq!(report.duplicates, 1);
    }

    /// A hostile feed must not be able to point discovery at the user's own
    /// machine or network.
    #[test]
    fn feed_links_may_not_point_at_the_local_machine_or_network() {
        let private = [
            "trojan://secret@127.0.0.1:8443?security=tls&sni=t.example.com#loopback",
            "trojan://secret@10.0.0.5:8443?security=tls&sni=t.example.com#lan",
            "trojan://secret@169.254.1.1:8443?security=tls&sni=t.example.com#link-local",
            "trojan://secret@100.64.0.9:8443?security=tls&sni=t.example.com#cgnat",
            "trojan://secret@[::1]:8443?security=tls&sni=t.example.com#v6-loopback",
            "trojan://secret@[fc00::1]:8443?security=tls&sni=t.example.com#ula",
            "trojan://secret@[::ffff:192.168.1.9]:8443?security=tls&sni=t.example.com#mapped",
            "trojan://secret@localhost:8443?security=tls&sni=t.example.com#name",
            "trojan://secret@router.local:8443?security=tls&sni=t.example.com#mdns",
            "trojan://secret@0.1.2.3:8443?security=tls&sni=t.example.com#this-net",
            "trojan://secret@224.0.0.1:8443?security=tls&sni=t.example.com#multicast",
        ];
        let text = private.join("\n");
        let (candidates, report) = parse_feed_candidates(&text, &HashSet::new());
        assert!(candidates.is_empty(), "{candidates:?}");
        assert_eq!(report.rejected, private.len());
        // The same links pasted by the user are left alone: a local server is
        // their own choice, not a stranger's feed.
        assert_eq!(parse_links(&text).items.len(), private.len());
        // A public address in a feed is unaffected.
        let (candidates, report) = parse_feed_candidates(TROJAN, &HashSet::new());
        assert_eq!(candidates.len(), 1);
        assert_eq!(report.rejected, 0);
    }
}
