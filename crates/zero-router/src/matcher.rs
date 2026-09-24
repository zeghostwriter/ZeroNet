//! Compiled matchers.
//!
//! Patterns are compiled once when configuration is compiled, never per
//! session. Exact and suffix names go in hash sets probed per label, keywords
//! into one Aho-Corasick automaton, and regexes into a plain `Vec<Regex>` —
//! deliberately not a `RegexSet`, whose size limit applies to the whole set
//! and so fails in aggregate on large rule lists.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use regex::Regex;
use zero_config::routing::{ipnet_lite::Cidr, DomainPattern, IpPattern};

/// Geodata supplied by the application layer. The line format remains useful
/// for small deployments and tests; the environment loader also accepts the
/// protobuf containers used by Xray's `geosite.dat` and `geoip.dat` files.
#[derive(Debug, Clone, Default)]
pub struct GeoData {
    pub geosite: HashMap<Box<str>, Vec<DomainPattern>>,
    pub geoip: HashMap<Box<str>, Vec<Cidr>>,
}

impl GeoData {
    pub fn from_lines(geosite_lines: &str, geoip_lines: &str) -> Self {
        let mut data = Self::default();
        for line in geosite_lines.lines().chain([""]) {
            let mut fields = line.split_whitespace();
            let Some(tag) = fields.next() else { continue };
            let Some(pattern) = fields.next() else {
                continue;
            };
            data.geosite
                .entry(tag.to_ascii_lowercase().into_boxed_str())
                .or_default()
                .push(DomainPattern::parse(pattern));
        }
        for line in geoip_lines.lines() {
            let mut fields = line.split_whitespace();
            let Some(tag) = fields.next() else { continue };
            let Some(cidr) = fields.next().and_then(Cidr::parse) else {
                continue;
            };
            data.geoip
                .entry(tag.to_ascii_lowercase().into_boxed_str())
                .or_default()
                .push(cidr);
        }
        data
    }

    /// Decode Xray's public geodata protobuf containers into the same hot-path
    /// matcher representation used by line-oriented data.
    pub fn from_xray_bytes(geosite: &[u8], geoip: &[u8]) -> Result<Self, String> {
        let mut data = Self::default();
        parse_geosite_list(geosite, &mut data)?;
        parse_geoip_list(geoip, &mut data)?;
        if data.geosite.is_empty() && data.geoip.is_empty() {
            return Err("geodata containers contain no entries".into());
        }
        Ok(data)
    }

    /// Decode one Xray `geosite.dat` container on its own. The asset pipeline
    /// validates each file independently, so a broken geosite download never
    /// invalidates a good cached geoip file.
    pub fn from_xray_geosite(bytes: &[u8]) -> Result<Self, String> {
        let mut data = Self::default();
        parse_geosite_list(bytes, &mut data)?;
        if data.geosite.is_empty() {
            return Err("geosite container contains no entries".into());
        }
        Ok(data)
    }

    /// Decode one Xray `geoip.dat` container on its own.
    pub fn from_xray_geoip(bytes: &[u8]) -> Result<Self, String> {
        let mut data = Self::default();
        parse_geoip_list(bytes, &mut data)?;
        if data.geoip.is_empty() {
            return Err("geoip container contains no entries".into());
        }
        Ok(data)
    }

    /// Fold another dataset in. Later entries win, so a specialised overlay
    /// (an Iran rule bundle, say) can be layered over a general container.
    pub fn merge(&mut self, other: Self) {
        self.geosite.extend(other.geosite);
        self.geoip.extend(other.geoip);
    }

    pub fn is_empty(&self) -> bool {
        self.geosite.is_empty() && self.geoip.is_empty()
    }

    /// Load optional line-oriented geodata paths selected by the host
    /// application. Missing variables/files are treated as an empty dataset;
    /// the router still reports unresolved tags instead of changing their
    /// meaning to a wildcard.
    pub fn from_environment() -> Self {
        let geosite = std::env::var_os("ZRAY_GEOSITE_FILE")
            .and_then(|path| std::fs::read(path).ok())
            .unwrap_or_default();
        let geoip = std::env::var_os("ZRAY_GEOIP_FILE")
            .and_then(|path| std::fs::read(path).ok())
            .unwrap_or_default();
        if let Ok(data) = Self::from_xray_bytes(&geosite, &geoip) {
            return data;
        }
        Self::from_lines(
            std::str::from_utf8(&geosite).unwrap_or_default(),
            std::str::from_utf8(&geoip).unwrap_or_default(),
        )
    }
}

struct Proto<'a> {
    bytes: &'a [u8],
    at: usize,
}

type ProtoField<'a> = (u32, u8, &'a [u8]);

impl<'a> Proto<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn next(&mut self) -> Result<Option<ProtoField<'a>>, String> {
        if self.at == self.bytes.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = (key >> 3) as u32;
        let wire = (key & 7) as u8;
        if field == 0 {
            return Err("geodata protobuf contains field zero".into());
        }
        let value = match wire {
            0 => {
                let start = self.at;
                let _ = self.varint()?;
                &self.bytes[start..self.at]
            }
            2 => {
                let length = self.varint()? as usize;
                let end = self
                    .at
                    .checked_add(length)
                    .ok_or_else(|| "geodata protobuf length overflows".to_string())?;
                if end > self.bytes.len() {
                    return Err("geodata protobuf field is truncated".into());
                }
                let value = &self.bytes[self.at..end];
                self.at = end;
                value
            }
            1 => {
                let end = self
                    .at
                    .checked_add(8)
                    .ok_or_else(|| "geodata protobuf field overflows".to_string())?;
                if end > self.bytes.len() {
                    return Err("geodata protobuf fixed64 field is truncated".into());
                }
                let value = &self.bytes[self.at..end];
                self.at = end;
                value
            }
            5 => {
                let end = self
                    .at
                    .checked_add(4)
                    .ok_or_else(|| "geodata protobuf field overflows".to_string())?;
                if end > self.bytes.len() {
                    return Err("geodata protobuf fixed32 field is truncated".into());
                }
                let value = &self.bytes[self.at..end];
                self.at = end;
                value
            }
            _ => return Err("geodata protobuf uses an unsupported wire type".into()),
        };
        Ok(Some((field, wire, value)))
    }

    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = *self
                .bytes
                .get(self.at)
                .ok_or_else(|| "geodata protobuf varint is truncated".to_string())?;
            self.at += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("geodata protobuf varint is too long".into())
    }
}

fn parse_geosite_list(bytes: &[u8], data: &mut GeoData) -> Result<(), String> {
    let mut list = Proto::new(bytes);
    while let Some((field, wire, value)) = list.next()? {
        if field == 1 && wire == 2 {
            parse_geosite_entry(value, data)?;
        }
    }
    Ok(())
}

fn parse_geosite_entry(bytes: &[u8], data: &mut GeoData) -> Result<(), String> {
    let mut entry = Proto::new(bytes);
    let mut tag = None::<String>;
    let mut domains = Vec::new();
    while let Some((field, wire, value)) = entry.next()? {
        match (field, wire) {
            (1, 2) => {
                tag = Some(
                    std::str::from_utf8(value)
                        .map_err(|_| "geosite country code is not UTF-8")?
                        .to_ascii_lowercase(),
                );
            }
            (2, 2) => domains.push(parse_geosite_domain(value)?),
            _ => {}
        }
    }
    let Some(tag) = tag else { return Ok(()) };
    if !domains.is_empty() {
        data.geosite
            .entry(tag.into_boxed_str())
            .or_default()
            .extend(domains);
    }
    Ok(())
}

fn parse_geosite_domain(bytes: &[u8]) -> Result<DomainPattern, String> {
    let mut domain = Proto::new(bytes);
    let mut kind = 0u64;
    let mut value = None::<String>;
    while let Some((field, wire, bytes)) = domain.next()? {
        match (field, wire) {
            (1, 0) => {
                let mut varint = Proto::new(bytes);
                kind = varint.varint()?;
            }
            (2, 2) => {
                value = Some(
                    std::str::from_utf8(bytes)
                        .map_err(|_| "geosite domain is not UTF-8")?
                        .to_owned(),
                );
            }
            _ => {}
        }
    }
    let value = value.ok_or_else(|| "geosite domain has no value".to_string())?;
    // `xray.common.geodata.Domain.Type` (and v2fly's `routercommon`, which
    // shares the numbering): Substr/Plain = 0, Regex = 1, Domain/RootDomain =
    // 2, Full = 3. Getting this table wrong silently turns every suffix rule
    // into a regex and every full-name rule into a substring match.
    Ok(match kind {
        0 => DomainPattern::Keyword(value.into_boxed_str()),
        1 => DomainPattern::Regex(value.into_boxed_str()),
        2 => DomainPattern::Suffix(value.into_boxed_str()),
        3 => DomainPattern::Full(value.into_boxed_str()),
        _ => return Err("geosite domain uses an unknown type".into()),
    })
}

fn parse_geoip_list(bytes: &[u8], data: &mut GeoData) -> Result<(), String> {
    let mut list = Proto::new(bytes);
    while let Some((field, wire, value)) = list.next()? {
        if field == 1 && wire == 2 {
            parse_geoip_entry(value, data)?;
        }
    }
    Ok(())
}

fn parse_geoip_entry(bytes: &[u8], data: &mut GeoData) -> Result<(), String> {
    let mut entry = Proto::new(bytes);
    let mut tag = None::<String>;
    let mut ranges = Vec::new();
    while let Some((field, wire, value)) = entry.next()? {
        match (field, wire) {
            (1, 2) => {
                tag = Some(
                    std::str::from_utf8(value)
                        .map_err(|_| "geoip country code is not UTF-8")?
                        .to_ascii_lowercase(),
                );
            }
            (2, 2) => ranges.push(parse_geoip_cidr(value)?),
            _ => {}
        }
    }
    let Some(tag) = tag else { return Ok(()) };
    if !ranges.is_empty() {
        data.geoip
            .entry(tag.into_boxed_str())
            .or_default()
            .extend(ranges);
    }
    Ok(())
}

fn parse_geoip_cidr(bytes: &[u8]) -> Result<Cidr, String> {
    let mut cidr = Proto::new(bytes);
    let mut address = None::<Vec<u8>>;
    let mut prefix = None::<u8>;
    while let Some((field, wire, value)) = cidr.next()? {
        match (field, wire) {
            (1, 2) => address = Some(value.to_vec()),
            (2, 0) => {
                let mut varint = Proto::new(value);
                prefix = Some(
                    u8::try_from(varint.varint()?)
                        .map_err(|_| "geoip CIDR prefix is too large".to_string())?,
                );
            }
            _ => {}
        }
    }
    let address = address.ok_or_else(|| "geoip CIDR has no address".to_string())?;
    let ip = match address.as_slice() {
        [a, b, c, d] => IpAddr::from([*a, *b, *c, *d]),
        bytes if bytes.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            IpAddr::from(octets)
        }
        _ => return Err("geoip CIDR address must be 4 or 16 bytes".into()),
    };
    let prefix = prefix.ok_or_else(|| "geoip CIDR has no prefix".to_string())?;
    Cidr::parse(&format!("{ip}/{prefix}")).ok_or_else(|| "geoip CIDR is invalid".into())
}

/// RFC 1918 and friends, plus loopback and link-local.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                // 100.64.0.0/10, carrier-grade NAT
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[derive(Debug, Default)]
pub struct DomainMatcher {
    full: HashSet<Box<str>>,
    /// Suffixes match the name itself or any label-boundary subdomain.
    suffix: HashSet<Box<str>>,
    keywords: Option<AhoCorasick>,
    regexes: Vec<Regex>,
    /// Geosite tags that could not be resolved without geodata files.
    pub unresolved_geosites: Vec<Box<str>>,
}

impl DomainMatcher {
    pub fn build(patterns: &[DomainPattern]) -> Self {
        Self::build_with_geodata(patterns, &GeoData::default())
    }

    pub fn build_with_geodata(patterns: &[DomainPattern], data: &GeoData) -> Self {
        let mut m = DomainMatcher::default();
        let mut keywords: Vec<String> = Vec::new();

        let mut expanded = Vec::new();
        let mut stack = Vec::new();
        for pattern in patterns {
            expand_geosite(
                pattern,
                data,
                &mut stack,
                &mut expanded,
                &mut m.unresolved_geosites,
            );
        }
        for p in &expanded {
            match p {
                DomainPattern::Full(s) => {
                    m.full.insert(normalize(s).into());
                }
                DomainPattern::Suffix(s) => {
                    m.suffix.insert(normalize(s).into());
                }
                DomainPattern::Keyword(s) => keywords.push(normalize(s)),
                DomainPattern::Regex(s) => {
                    // An invalid regex must not silently match nothing: record
                    // it as unresolved so the operator can see it.
                    match Regex::new(s) {
                        Ok(r) => m.regexes.push(r),
                        Err(_) => m.unresolved_geosites.push(format!("regexp:{s}").into()),
                    }
                }
                DomainPattern::Geosite(_) => unreachable!("geosite expansion is recursive-safe"),
            }
        }

        if !keywords.is_empty() {
            m.keywords = AhoCorasick::new(&keywords).ok();
        }
        m
    }

    pub fn is_empty(&self) -> bool {
        self.full.is_empty()
            && self.suffix.is_empty()
            && self.keywords.is_none()
            && self.regexes.is_empty()
    }

    pub fn matches(&self, domain: &str) -> bool {
        // Routing runs this for every session; names arriving here are almost
        // always lowercase already, so only allocate when they are not.
        let trimmed = domain.trim().trim_end_matches('.');
        let d: std::borrow::Cow<'_, str> = if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            std::borrow::Cow::Owned(trimmed.to_ascii_lowercase())
        } else {
            std::borrow::Cow::Borrowed(trimmed)
        };

        if self.full.contains(d.as_ref()) {
            return true;
        }

        // Probe each label boundary: a.b.example.com tests itself, then
        // b.example.com, then example.com, then com.
        if !self.suffix.is_empty() {
            let mut rest = d.as_ref();
            loop {
                if self.suffix.contains(rest) {
                    return true;
                }
                match rest.find('.') {
                    Some(i) => rest = &rest[i + 1..],
                    None => break,
                }
            }
        }

        if let Some(ac) = &self.keywords {
            if ac.is_match(d.as_ref()) {
                return true;
            }
        }

        self.regexes.iter().any(|r| r.is_match(d.as_ref()))
    }
}

fn expand_geosite(
    pattern: &DomainPattern,
    data: &GeoData,
    stack: &mut Vec<Box<str>>,
    out: &mut Vec<DomainPattern>,
    unresolved: &mut Vec<Box<str>>,
) {
    let DomainPattern::Geosite(tag) = pattern else {
        out.push(pattern.clone());
        return;
    };
    let key: Box<str> = tag.to_ascii_lowercase().into_boxed_str();
    if stack.iter().any(|seen| seen == &key) {
        unresolved.push(format!("geosite:{tag}").into());
        return;
    }
    let Some(patterns) = data.geosite.get(&key) else {
        unresolved.push(tag.clone());
        return;
    };
    stack.push(key);
    for nested in patterns {
        expand_geosite(nested, data, stack, out, unresolved);
    }
    stack.pop();
}

/// Lowercase and drop a single trailing dot, matching DNS semantics.
fn normalize(s: &str) -> String {
    let s = s.trim().trim_end_matches('.');
    s.to_ascii_lowercase()
}

/// CIDR membership over sorted, merged address ranges.
///
/// A geoip tag holds thousands of prefixes (`geoip:ir` ~2k, `geoip:cn` ~8k),
/// and every routed session asks this question, so membership is a binary
/// search over disjoint `[start, end]` ranges instead of a scan over every
/// prefix.
#[derive(Debug, Default)]
struct IpRanges {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpRanges {
    fn build(cidrs: &[Cidr]) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for cidr in cidrs {
            match cidr.addr {
                IpAddr::V4(addr) => {
                    let prefix = u32::from(cidr.prefix.min(32));
                    let host_mask = u32::MAX.checked_shr(prefix).unwrap_or(0);
                    let start = u32::from(addr) & !host_mask;
                    v4.push((start, start | host_mask));
                }
                IpAddr::V6(addr) => {
                    let prefix = u32::from(cidr.prefix.min(128));
                    let host_mask = u128::MAX.checked_shr(prefix).unwrap_or(0);
                    let start = u128::from(addr) & !host_mask;
                    v6.push((start, start | host_mask));
                }
            }
        }
        Self {
            v4: merge_ranges(v4),
            v6: merge_ranges(v6),
        }
    }

    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => range_contains(&self.v4, u32::from(v4)),
            IpAddr::V6(v6) => range_contains(&self.v6, u128::from(v6)),
        }
    }
}

/// Sort and coalesce overlapping or adjacent ranges into a disjoint list.
fn merge_ranges<T: Copy + Ord + num_like::Successor>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            // Adjacent ranges merge too: `last.1 + 1 == start`.
            if start <= last.1 || last.1.successor() == Some(start) {
                if end > last.1 {
                    last.1 = end;
                }
                continue;
            }
        }
        merged.push((start, end));
    }
    merged.shrink_to_fit();
    merged
}

fn range_contains<T: Copy + Ord>(ranges: &[(T, T)], value: T) -> bool {
    // First range whose start is past the value; the candidate is the one
    // before it.
    let index = ranges.partition_point(|(start, _)| *start <= value);
    index > 0 && ranges[index - 1].1 >= value
}

mod num_like {
    pub trait Successor: Sized {
        fn successor(self) -> Option<Self>;
    }
    impl Successor for u32 {
        fn successor(self) -> Option<Self> {
            self.checked_add(1)
        }
    }
    impl Successor for u128 {
        fn successor(self) -> Option<Self> {
            self.checked_add(1)
        }
    }
}

#[derive(Debug, Default)]
pub struct IpMatcher {
    ranges: IpRanges,
    match_private: bool,
    pub unresolved_geoips: Vec<Box<str>>,
}

impl IpMatcher {
    pub fn build(patterns: &[IpPattern]) -> Self {
        Self::build_with_geodata(patterns, &GeoData::default())
    }

    pub fn build_with_geodata(patterns: &[IpPattern], data: &GeoData) -> Self {
        let mut cidrs = Vec::new();
        let mut match_private = false;
        let mut unresolved_geoips = Vec::new();
        for p in patterns {
            match p {
                IpPattern::Cidr(c) => cidrs.push(*c),
                IpPattern::Private => match_private = true,
                IpPattern::Geoip(tag) => {
                    let key = tag.to_ascii_lowercase();
                    match data.geoip.get(key.as_str()) {
                        Some(list) => cidrs.extend(list.iter().copied()),
                        None => unresolved_geoips.push(tag.clone()),
                    }
                }
            }
        }
        IpMatcher {
            ranges: IpRanges::build(&cidrs),
            match_private,
            unresolved_geoips,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty() && !self.match_private
    }

    pub fn matches(&self, ip: IpAddr) -> bool {
        // A dual-stack socket reports IPv4 peers as `::ffff:a.b.c.d`; those
        // are IPv4 addresses for every rule an operator writes.
        let ip = ip.to_canonical();
        if self.match_private && is_private_ip(ip) {
            return true;
        }
        self.ranges.contains(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dm(pats: &[&str]) -> DomainMatcher {
        let p: Vec<_> = pats.iter().map(|s| DomainPattern::parse(s)).collect();
        DomainMatcher::build(&p)
    }

    #[test]
    fn full_matches_exactly() {
        let m = dm(&["full:example.com"]);
        assert!(m.matches("example.com"));
        assert!(!m.matches("a.example.com"));
    }

    #[test]
    fn suffix_matches_at_label_boundaries_only() {
        let m = dm(&["domain:example.com"]);
        assert!(m.matches("example.com"));
        assert!(m.matches("a.example.com"));
        assert!(m.matches("a.b.example.com"));
        // Must not match a name that merely ends with the same text.
        assert!(!m.matches("notexample.com"));
        assert!(!m.matches("example.com.evil.net"));
    }

    #[test]
    fn matching_is_case_insensitive_and_ignores_trailing_dot() {
        let m = dm(&["domain:Example.COM"]);
        assert!(m.matches("A.ExAmPlE.com"));
        assert!(m.matches("a.example.com."));
    }

    #[test]
    fn keyword_matches_substring() {
        let m = dm(&["keyword:goog"]);
        assert!(m.matches("www.google.com"));
        assert!(!m.matches("example.com"));
    }

    #[test]
    fn regex_matches() {
        let m = dm(&["regexp:^ads[0-9]+\\."]);
        assert!(m.matches("ads12.example.com"));
        assert!(!m.matches("ad.example.com"));
    }

    #[test]
    fn geosite_is_recorded_as_unresolved_not_silently_ignored() {
        let m = dm(&["geosite:category-ads-all"]);
        assert!(m.is_empty(), "no usable pattern without geodata");
        assert_eq!(m.unresolved_geosites.len(), 1);
        assert!(!m.matches("ads.example.com"));
    }

    #[test]
    fn invalid_regex_is_reported_rather_than_dropped() {
        let m = dm(&["regexp:[unclosed"]);
        assert_eq!(m.unresolved_geosites.len(), 1);
    }

    #[test]
    fn private_ip_classification() {
        for ip in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
        ] {
            assert!(is_private_ip(ip.parse().unwrap()), "{ip} should be private");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "155.117.13.26"] {
            assert!(!is_private_ip(ip.parse().unwrap()), "{ip} should be public");
        }
        assert!(is_private_ip("::1".parse().unwrap()));
        assert!(is_private_ip("fd00::1".parse().unwrap()));
        assert!(is_private_ip("fe80::1".parse().unwrap()));
        assert!(!is_private_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn ip_matcher_cidr_and_private() {
        let m = IpMatcher::build(&[
            IpPattern::Cidr(Cidr::parse("203.0.113.0/24").unwrap()),
            IpPattern::Private,
        ]);
        assert!(m.matches("203.0.113.5".parse().unwrap()));
        assert!(m.matches("10.1.2.3".parse().unwrap()));
        assert!(!m.matches("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn ip_ranges_merge_and_binary_search_like_a_linear_scan() {
        let cidrs = [
            "10.0.0.0/8",
            "10.1.0.0/16",
            "192.168.0.0/24",
            "192.168.1.0/24",
            "203.0.113.7/32",
            "0.0.0.0/0",
            "2001:db8::/32",
            "2001:db8:1::/48",
            "::/0",
        ];
        for subset in [&cidrs[..5], &cidrs[6..8], &cidrs[..]] {
            let parsed: Vec<Cidr> = subset.iter().map(|c| Cidr::parse(c).unwrap()).collect();
            let patterns: Vec<IpPattern> = parsed.iter().copied().map(IpPattern::Cidr).collect();
            let matcher = IpMatcher::build(&patterns);
            for probe in [
                "10.0.0.0",
                "10.255.255.255",
                "11.0.0.0",
                "9.255.255.255",
                "192.168.0.255",
                "192.168.1.0",
                "192.168.2.0",
                "203.0.113.7",
                "203.0.113.8",
                "255.255.255.255",
                "0.0.0.0",
                "2001:db8::1",
                "2001:db9::1",
                "::",
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ] {
                let ip: IpAddr = probe.parse().unwrap();
                let linear = parsed.iter().any(|c| c.contains(ip));
                assert_eq!(matcher.matches(ip), linear, "{probe} against {subset:?}");
            }
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_addresses_match_ipv4_rules() {
        let m = IpMatcher::build(&[
            IpPattern::Cidr(Cidr::parse("203.0.113.0/24").unwrap()),
            IpPattern::Private,
        ]);
        assert!(m.matches("::ffff:203.0.113.9".parse().unwrap()));
        assert!(m.matches("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!m.matches("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn geosite_protobuf_types_follow_the_xray_enum() {
        // GeoSiteList{entry:{code:"t", domain:[{type, value:"ab.cd"}]}} for
        // each Xray type: Substr(0), Regex(1), Domain(2), Full(3).
        let container = |kind: u8| {
            let domain = [0x08, kind, 0x12, 0x05, b'a', b'b', b'.', b'c', b'd'];
            let mut entry = vec![0x0a, 0x01, b't', 0x12, domain.len() as u8];
            entry.extend_from_slice(&domain);
            let mut list = vec![0x0a, entry.len() as u8];
            list.extend_from_slice(&entry);
            GeoData::from_xray_geosite(&list).unwrap()
        };
        let matcher = |kind: u8| {
            DomainMatcher::build_with_geodata(
                &[DomainPattern::Geosite("t".into())],
                &container(kind),
            )
        };

        let substr = matcher(0);
        assert!(substr.matches("xab.cdx.example"));

        let regex = matcher(1);
        assert!(regex.matches("abxcd"), "`.` is a regex wildcard");

        let domain = matcher(2);
        assert!(domain.matches("ab.cd") && domain.matches("www.ab.cd"));
        assert!(!domain.matches("xab.cd") && !domain.matches("abxcd"));

        let full = matcher(3);
        assert!(full.matches("ab.cd"));
        assert!(!full.matches("www.ab.cd") && !full.matches("xab.cdx"));
    }

    #[test]
    fn geoip_is_recorded_as_unresolved() {
        let m = IpMatcher::build(&[IpPattern::Geoip("ir".into())]);
        assert!(m.is_empty());
        assert_eq!(m.unresolved_geoips.len(), 1);
    }

    #[test]
    fn geodata_expands_domain_and_ip_tags() {
        let data = GeoData::from_lines(
            "category-ads-all domain:ads.example\ncategory-ads-all keyword:tracker",
            "ir 203.0.113.0/24",
        );
        let domains = DomainMatcher::build_with_geodata(
            &[DomainPattern::Geosite("category-ads-all".into())],
            &data,
        );
        assert!(domains.matches("cdn.ads.example"));
        assert!(domains.matches("tracker.example"));
        assert!(domains.unresolved_geosites.is_empty());

        let ips = IpMatcher::build_with_geodata(&[IpPattern::Geoip("ir".into())], &data);
        assert!(ips.matches("203.0.113.42".parse().unwrap()));
        assert!(ips.unresolved_geoips.is_empty());
    }

    #[test]
    fn decodes_xray_geosite_and_geoip_protobuf_containers() {
        // GeoSiteList{entry: {country_code: "ads", domain: {
        // type: RootDomain, value: "example.com"}}}
        let geosite = vec![
            0x0a, 0x16, 0x0a, 0x03, b'a', b'd', b's', 0x12, 0x0f, 0x08, 0x02, 0x12, 0x0b, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        ];
        // GeoIPList{entry: {country_code: "ir", cidr: {
        // ip: 203.0.113.0, prefix: 24}}}
        let geoip = vec![
            0x0a, 0x0e, 0x0a, 0x02, b'i', b'r', 0x12, 0x08, 0x0a, 0x04, 203, 0, 113, 0, 0x10, 0x18,
        ];
        let data = GeoData::from_xray_bytes(&geosite, &geoip).unwrap();
        let domains =
            DomainMatcher::build_with_geodata(&[DomainPattern::Geosite("ads".into())], &data);
        assert!(domains.matches("cdn.example.com"));
        let ips = IpMatcher::build_with_geodata(&[IpPattern::Geoip("ir".into())], &data);
        assert!(ips.matches("203.0.113.42".parse().unwrap()));
    }
}
