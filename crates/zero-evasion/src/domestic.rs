//! A pool of allow-listed server names for the SNI decoy.
//!
//! Iran's filter decides to throttle or let a TLS connection through largely
//! from the server name it reads out of the ClientHello, so the decoy hello
//! ([`crate::decoy`]) carries a name the filter is known to let through rather
//! than the real one. Up to now that name was a single hard-coded host,
//! `www.speedtest.net`. One name is a single point of failure: the day the
//! filter starts throttling or blocking it, every decoy that uses it fails at
//! once, and nothing in the field can route around it.
//!
//! This module holds a small, curated set of such names instead and hands out
//! one per server. Two properties matter:
//!
//! * **Stable per server.** [`pick`] maps a server to the same name every
//!   time, so a connection does not flap between names from one dial to the
//!   next — a censor watching one flow sees one steady decoy name, and the
//!   balancer's verdict about whether the decoy gets through stays meaningful.
//! * **Spread across servers.** Different servers draw different names, so a
//!   censor cannot kill every Zray decoy by throttling one host, and a name
//!   that stops working on one network only costs the servers that drew it.
//!
//! The trade-off: the pool has to suit two kinds of network, and a name that
//! suits one can be useless on the other. On a blocklist network (a decoy is
//! read, and only the names on the list are cut) any name that is not blocked
//! works, domestic or foreign: measured 2026-10-13 from Iran, `digikala.com`,
//! `aparat.com`, `hcaptcha.com`, `www.google.com`, `www.bing.com`,
//! `www.cloudflare.com`, `www.speedtest.net` and an unregistered name all
//! carried a decoy to blocked sites, while a decoy that repeated the blocked
//! name did not. On an allowlist network (the destination address has to be on
//! a list too), reports from the field say only foreign names that the address
//! really serves get through (`hcaptcha.com`, `www.google.com`, `www.bing.com`,
//! `www.cloudflare.com`), and nothing shows a domestic name working there. So
//! the pool carries both kinds, and the unmeasured domestic hosts are reasoned
//! candidates: national payment, operator and super-app domains a censor is
//! unlikely to cut because doing so breaks commerce. A pick that a given
//! network does cut is not a dead end: the decoy is always one balancer-probed
//! variant among others, and [`crate::choice`] falls back to the urgent byte
//! or a plain hello when it does not get through, so a bad pick loses a probe
//! and nothing more.
//!
//! Every name here is a real site, so a censor that actively probes the decoy
//! finds one, and every name is a plain host of visible ASCII within the
//! injector's 1..=219-byte bound (see the tests), so it is a legal `fake_sni`.
//!
//! Where the names come from, so the set can be refreshed by hand: the
//! speed-test hosts are the ones the circumvention community cites as
//! un-throttled; the foreign CDN hosts are the decoy names used in the field
//! (Xray-core and sing-box examples, net4people threads); the Iranian hosts
//! are the largest public super-app, payment, operator, bank and CDN domains
//! (the kind collected in
//! `bootmortis/iran-hosted-domains` and `v2fly/domain-list-community`'s
//! `category-ir`).
//!
//! A signed, remotely-updatable list extends this set at runtime without an
//! app update, so a name the filter starts throttling can be diluted by fresh
//! ones the day it happens: `zero_discovery::domestic_feed` fetches and
//! signature-checks the list, [`parse_feed`] turns the body into extra names,
//! and [`pick_from`] draws from the bundled pool and the fetched names
//! together. The feed only ever adds — the bundled set is the offline floor
//! that always works with no network, the names a fetched line is checked
//! against for duplicates, and the home of the default host.

/// Global speed-test and bandwidth hosts, which tend to be left un-throttled
/// so a provider's own speed numbers look good. `www.speedtest.net` is the
/// one measured un-throttled from Iran and stays first, so it is also the
/// fallback (see [`pick`]).
pub const SPEEDTEST: &[&str] = &[
    "www.speedtest.net",
    "speedtest.net",
    "fast.com",
    "www.fast.com",
    "speed.cloudflare.com",
];

/// Foreign sites on large CDNs, the names the field uses where a decoy only
/// helps when the name belongs to the address it is sent to. Each carried a
/// decoy through to blocked sites on a blocklist network (see the module
/// documentation).
pub const FOREIGN_CDN: &[&str] = &[
    "hcaptcha.com",
    "www.bing.com",
    "www.google.com",
    "www.cloudflare.com",
];

/// Iranian cloud and CDN hosts. Not measured as decoys: they front many sites,
/// so a filter that cuts them is costly to itself. The decoy goes to the real
/// server's address, not to theirs, so being reachable inside Iran does not
/// help it.
pub const IRANIAN_CDN: &[&str] = &[
    "www.arvancloud.ir",
    "arvancloud.ir",
    "derak.cloud",
    "www.derak.cloud",
];

/// Large Iranian consumer, payment, operator and bank domains. Only
/// `digikala.com` and `aparat.com` are measured (as decoys on a blocklist
/// network); the rest are reasoned: a filter that cuts the national payment
/// switch, the largest mobile operators or the biggest super-apps breaks
/// everyday commerce, so they are the names least likely to be touched.
pub const DOMESTIC_SITES: &[&str] = &[
    "www.aparat.com",
    "www.digikala.com",
    "digikala.com",
    "divar.ir",
    "snapp.ir",
    "shaparak.ir",
    "www.shaparak.ir",
    "mci.ir",
    "www.irancell.ir",
    "www.bmi.ir",
];

/// The default name, used when a caller has no key to pick from and as the
/// first entry of the pool. The host Xray-core #3318 measured un-throttled
/// from Iran.
pub const DEFAULT: &str = SPEEDTEST[0];

/// Every name in the pool, speed-test hosts first (so the default is index 0),
/// then the foreign CDN hosts, then the domestic clouds and sites.
pub fn all() -> impl Iterator<Item = &'static str> {
    SPEEDTEST
        .iter()
        .chain(FOREIGN_CDN)
        .chain(IRANIAN_CDN)
        .chain(DOMESTIC_SITES)
        .copied()
}

/// The allow-listed decoy name for `key`, stable for a given key and spread
/// across keys. `key` is whatever identifies the server — its host name is the
/// natural choice, so every link to the same server draws the same decoy.
///
/// An empty key gets [`DEFAULT`] rather than a hash of nothing.
///
/// ```
/// # use zero_evasion::domestic;
/// assert_eq!(domestic::pick("example.com"), domestic::pick("example.com"));
/// assert!(domestic::all().any(|name| name == domestic::pick("a.server.net")));
/// ```
pub fn pick(key: &str) -> &'static str {
    pick_from(key, &[])
}

/// Like [`pick`], but choosing from the bundled pool together with `extra` —
/// the names a signed feed added at runtime (`zero_discovery::domestic_feed`,
/// via [`parse_feed`]). `extra` is laid after the bundled pool as more entries
/// of one flat set, so a server may draw a fetched name or a bundled one; the
/// choice is still stable per key and spread across keys, and growing `extra`
/// moves only the few keys the new names score highest for. An empty `extra`
/// makes this exactly [`pick`].
///
/// The returned reference lives as long as `extra`; bundled names and
/// [`DEFAULT`] are `'static`, so they satisfy any shorter lifetime.
pub fn pick_from<'a>(key: &str, extra: &'a [&'a str]) -> &'a str {
    if key.is_empty() {
        return DEFAULT;
    }
    // Rendezvous (highest-score) hashing: every name scores against the key and
    // the best score wins. A plain `hash % pool_size` would reshuffle almost
    // every server the day the feed grows by one name, flapping every decoy at
    // once; here a new name only takes the servers it scores highest for, about
    // `1 / (pool size)` of them, and the rest keep the name they had.
    all()
        .map(|name| name as &'a str)
        .chain(extra.iter().copied())
        .max_by_key(|name| score(key, name))
        .unwrap_or(DEFAULT)
}

/// How well `name` suits `key`: FNV-1a over both, then a finaliser. FNV's last
/// bytes mix poorly into the high bits, and the comparison looks at all of them,
/// so the splitmix64 finaliser spreads them out.
fn score(key: &str, name: &str) -> u64 {
    let mut hash = fnv1a(key.as_bytes());
    // A separator no host contains, so ("ab", "c") and ("a", "bc") differ.
    hash ^= 0xff;
    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    for &byte in name.as_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash = (hash ^ (hash >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash = (hash ^ (hash >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^ (hash >> 31)
}

/// The most names a fetched feed may add. A decoy pool wants a handful of good
/// hosts, not a directory, so this bounds the memory a broken or hostile feed
/// can make a device hold and keeps the pick's spread meaningful.
pub const MAX_FEED_NAMES: usize = 128;

/// Turn a fetched domestic-SNI feed body into the extra decoy names to hand to
/// [`pick_from`].
///
/// The format is one host per line: blank lines and `#` comments are skipped,
/// surrounding space is trimmed, and the host is lowercased. A line is kept
/// only when it is a legal `fake_sni` host ([`is_legal_host`]) that is not
/// already bundled, so the result is purely additive and free of duplicates,
/// and never more than [`MAX_FEED_NAMES`] long. A line that does not parse is
/// dropped on its own — one bad entry must not cost the device the good ones.
///
/// The body is trusted to have been signature-checked already
/// (`zero_discovery::feed` does this before it is cached); this step is about
/// shape, not provenance.
///
/// ```
/// # use zero_evasion::domestic;
/// let names = domestic::parse_feed("# fresh\nnew.example.ir\nwww.speedtest.net\n");
/// assert_eq!(names, vec!["new.example.ir".to_string()]);
/// ```
pub fn parse_feed(body: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let host = line.to_ascii_lowercase();
        // Shape, then "not already bundled", then "not already taken from an
        // earlier line": the pick stays evenly spread only if the set is flat
        // and unique.
        if !is_legal_host(&host)
            || all().any(|bundled| bundled == host)
            || names.iter().any(|taken| taken == &host)
        {
            continue;
        }
        names.push(host);
        if names.len() >= MAX_FEED_NAMES {
            break;
        }
    }
    names
}

/// Whether `name` is a legal decoy host: a plain host of lowercase ASCII
/// letters, digits, dots and hyphens, within the injector's 1..=219-byte
/// `fake_sni` bound, with at least one dot and no empty label. The charset is
/// a subset of the "visible ASCII" the config layer requires, so a host that
/// passes here is always a legal `fake_sni`. Both the bundled pool (see the
/// tests) and every fetched line must pass it.
fn is_legal_host(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 219
        && name.contains('.')
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// FNV-1a over `bytes`: a tiny, dependency-free hash. It is used only to spread
/// servers across the pool, so it needs to be stable and well-mixed, not
/// cryptographic.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every name is a legal `fake_sni`: 1..=219 visible ASCII bytes (the
    /// bound `zero_config` and `build_fake_client_hello` enforce), and a plain
    /// host of letters, digits, dots and hyphens — no wildcard to draw, so the
    /// decoy name is exactly what is written here.
    #[test]
    fn every_name_is_a_legal_fake_sni() {
        for name in all() {
            assert!(
                !name.is_empty() && name.len() <= 219 && name.bytes().all(|b| b > 0x20),
                "{name} is not 1..=219 visible bytes"
            );
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'.'
                    || b == b'-'),
                "{name} has a character a host name should not"
            );
            // A real host: at least one dot, and no empty label.
            assert!(name.contains('.'), "{name} has no dot");
            assert!(
                !name.starts_with('.') && !name.ends_with('.') && !name.contains(".."),
                "{name} has an empty label"
            );
        }
    }

    /// No name appears twice, so the pick is spread evenly and the pool size is
    /// honest.
    #[test]
    fn the_pool_has_no_duplicates() {
        let names: Vec<_> = all().collect();
        assert_eq!(names.iter().collect::<HashSet<_>>().len(), names.len());
    }

    /// `pick` is stable for a key and uses the whole pool across keys.
    #[test]
    fn pick_is_stable_and_covers_the_pool() {
        assert_eq!(pick(""), DEFAULT);
        for key in ["a.com", "server.example.net", "1.2.3.4", "یک.ir"] {
            assert_eq!(pick(key), pick(key), "{key} must be stable");
            assert!(all().any(|name| name == pick(key)), "{key} off the pool");
        }
        // Over many distinct keys the pick lands on more than one name — it is
        // not pinned to a single host.
        let seen: HashSet<_> = (0..500)
            .map(|i| pick(&format!("h{i}.example.net")))
            .collect();
        assert!(seen.len() > 1, "pick never spread off one name");
    }

    /// The default host is index 0 and the empty-key fallback.
    #[test]
    fn speedtest_is_first_and_the_fallback() {
        assert_eq!(all().next(), Some("www.speedtest.net"));
        assert_eq!(DEFAULT, "www.speedtest.net");
    }

    /// `pick_from` lays the fetched names after the bundled pool as one flat
    /// set: every key still lands on a real name, the pick is stable, and over
    /// many keys at least one fetched name is drawn — the feed actually widens
    /// the pool rather than being ignored. An empty key stays on the default.
    #[test]
    fn pick_from_draws_bundled_and_fetched_names() {
        let extra = ["new1.example.ir", "new2.example.ir", "new3.example.ir"];
        assert_eq!(pick_from("", &extra), DEFAULT);
        let legal: HashSet<_> = all().chain(extra.iter().copied()).collect();
        for key in ["a.com", "server.example.net", "1.2.3.4"] {
            assert_eq!(pick_from(key, &extra), pick_from(key, &extra));
            assert!(legal.contains(pick_from(key, &extra)), "{key} off the set");
        }
        let drew_a_fetched_name = (0..1000)
            .map(|i| pick_from(&format!("h{i}.example.net"), &extra))
            .any(|name| extra.contains(&name));
        assert!(drew_a_fetched_name, "the feed never widened the pool");
        // With no fetched names it is exactly `pick`.
        assert_eq!(pick_from("a.server.net", &[]), pick("a.server.net"));
    }

    /// Adding names to the feed moves only the servers the new names win, not
    /// the whole pool, so a refresh does not flap every decoy at once.
    #[test]
    fn growing_the_feed_moves_only_a_few_servers() {
        let keys: Vec<String> = (0..2000).map(|i| format!("h{i}.example.net")).collect();
        let before: Vec<&str> = keys.iter().map(|k| pick_from(k, &[])).collect();
        let extra = ["new1.example.ir", "new2.example.ir", "new3.example.ir"];
        let mut moved = 0;
        for (key, old) in keys.iter().zip(&before) {
            let now = pick_from(key, &extra);
            if now != *old {
                moved += 1;
                assert!(extra.contains(&now), "{key} moved to another bundled name");
            }
        }
        // Three of 22 names are new, so about 14% move; modulo would move ~86%.
        assert!(moved < keys.len() / 4, "{moved} of {} moved", keys.len());
        assert!(moved > 0, "the new names were never picked");
    }

    /// `parse_feed` keeps only legal, new, unique hosts: comments and blanks
    /// are dropped, bundled names are not re-added, duplicates collapse, a
    /// malformed line costs only itself, and the result is capped.
    #[test]
    fn parse_feed_keeps_only_legal_new_hosts() {
        let body = "\
# a comment\n\
\n\
  New.Example.IR  \n\
www.speedtest.net\n\
new.example.ir\n\
not a host\n\
bad_host.ir\n\
UPPER.example.com\n\
with..empty.ir\n\
.leading.ir\n\
good.example.net\n";
        assert_eq!(
            parse_feed(body),
            vec![
                "new.example.ir".to_string(),
                "upper.example.com".to_string(),
                "good.example.net".to_string(),
            ]
        );

        // The cap bounds a broken or hostile feed.
        let many = (0..(MAX_FEED_NAMES + 50))
            .map(|i| format!("h{i}.example.net"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(parse_feed(&many).len(), MAX_FEED_NAMES);

        // No name a `parse_feed` keeps is already bundled, and each is a legal
        // `fake_sni`, so the two layers agree.
        for name in parse_feed(body) {
            assert!(is_legal_host(&name));
            assert!(all().all(|bundled| bundled != name));
        }
    }
}
