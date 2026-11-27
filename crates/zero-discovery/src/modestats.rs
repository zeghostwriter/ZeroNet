//! How well each connection mode does in real use, without knowing who used it.
//!
//! Apps report three facts per mode (`normal:connect`, `gaming:ping`, ...; see
//! [`MODES`] and [`METRICS`]) to the crowd relay. This turns a day of those
//! reports into totals: how many people, how many things went well, the
//! typical delay and the slow tail. The totals are then **sealed** to a public
//! key so that only the maintainer, who holds the private half, can read them,
//! and the sealed file can be published anywhere.
//!
//! What keeps this from identifying anyone:
//!
//! * a report carries a mode, a measure, a yes or no and a rounded delay, and
//!   nothing else; the relay adds only daily pseudonyms;
//! * one person counts once per figure, however many reports they sent;
//! * a network (a carrier or an ISP) is listed on its own only when at least
//!   [`MIN_REPORTERS_PER_NET`] people reported from it, so a small group is
//!   never a fingerprint;
//! * the file is sealed, so the totals are not readable by anyone else at all.

use std::collections::{BTreeMap, HashMap, HashSet};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use serde::Serialize;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crowd::Report;

/// The four connection modes, as the apps name them.
pub const MODES: [&str; 4] = ["normal", "fast", "gaming", "legacy"];
/// What is measured about each: whether a connection came up and how long it
/// took, the delay of the server in use, and whether a long session stayed
/// steady.
pub const METRICS: [&str; 3] = ["connect", "ping", "stable"];

/// A network is listed alone only with this many people behind it.
pub const MIN_REPORTERS_PER_NET: usize = 5;

/// Facts one person may add to one figure in a day; the newest count.
const PER_REPORTER: usize = 5;

/// Whether `id` is one an app may report (`normal:connect`, ...).
pub fn valid_id(id: &str) -> bool {
    id.split_once(':')
        .is_some_and(|(mode, metric)| MODES.contains(&mode) && METRICS.contains(&metric))
}

/// The totals for one figure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Figures {
    /// Different people who reported it.
    pub reporters: u32,
    /// Facts counted, at most [`PER_REPORTER`] from each person.
    pub total: u32,
    /// How many of them went well.
    pub ok: u32,
    /// Typical delay in ms (the median), where facts carried one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub median_ms: Option<u32>,
    /// The slow tail: the delay 9 in 10 facts came in under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p90_ms: Option<u32>,
}

/// One day's totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// UTC day, `YYYY-MM-DD`.
    pub day: String,
    /// Every figure over everyone, by id.
    pub overall: BTreeMap<String, Figures>,
    /// The same by network, for networks with enough people.
    pub by_net: BTreeMap<String, BTreeMap<String, Figures>>,
}

fn figures(reports: &[&Report]) -> Figures {
    // One person's newest facts, at most PER_REPORTER of them.
    let mut per: HashMap<&str, Vec<&Report>> = HashMap::new();
    for report in reports {
        per.entry(report.reporter.as_str())
            .or_default()
            .push(report);
    }
    let mut counted: Vec<&Report> = Vec::new();
    for facts in per.values_mut() {
        facts.sort_by_key(|r| std::cmp::Reverse(r.ts));
        counted.extend(facts.iter().take(PER_REPORTER));
    }
    let mut delays: Vec<u32> = counted.iter().filter_map(|r| r.ms).collect();
    delays.sort_unstable();
    let at = |q: f64| -> Option<u32> {
        (!delays.is_empty()).then(|| delays[((delays.len() - 1) as f64 * q).round() as usize])
    };
    Figures {
        reporters: per.len() as u32,
        total: counted.len() as u32,
        ok: counted.iter().filter(|r| r.ok).count() as u32,
        median_ms: at(0.5),
        p90_ms: at(0.9),
    }
}

fn by_id(reports: &[&Report]) -> BTreeMap<String, Figures> {
    let mut groups: BTreeMap<&str, Vec<&Report>> = BTreeMap::new();
    for report in reports {
        groups.entry(report.item.as_str()).or_default().push(report);
    }
    groups
        .into_iter()
        .map(|(id, facts)| (id.to_string(), figures(&facts)))
        .collect()
}

/// The totals of the mode reports stamped within the UTC day that starts at
/// `day_start` (unix seconds).
pub fn summarize(reports: &[Report], day_start: i64) -> Summary {
    let day_end = day_start + 86_400;
    let usable: Vec<&Report> = reports
        .iter()
        .filter(|r| r.kind == "mode" && valid_id(&r.item) && !r.reporter.is_empty())
        .filter(|r| (day_start..day_end).contains(&r.ts))
        .collect();
    let overall = by_id(&usable);

    let mut nets: BTreeMap<&str, Vec<&Report>> = BTreeMap::new();
    for report in &usable {
        nets.entry(report.net.as_str()).or_default().push(report);
    }
    let by_net = nets
        .into_iter()
        .filter(|(_, facts)| {
            facts
                .iter()
                .map(|r| r.reporter.as_str())
                .collect::<HashSet<_>>()
                .len()
                >= MIN_REPORTERS_PER_NET
        })
        .map(|(net, facts)| (net.to_string(), by_id(&facts)))
        .collect();
    Summary {
        day: day_name(day_start),
        overall,
        by_net,
    }
}

/// How many mode reports fall in the day (for the Action's log, which is public).
pub fn count(reports: &[Report], day_start: i64) -> usize {
    reports
        .iter()
        .filter(|r| {
            r.kind == "mode" && valid_id(&r.item) && (day_start..day_start + 86_400).contains(&r.ts)
        })
        .count()
}

/// `YYYY-MM-DD` of the UTC day containing unix time `seconds`.
pub fn day_name(seconds: i64) -> String {
    // Days since 1970-01-01 to a civil date (Hinnant's algorithm).
    let z = seconds.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", y + i64::from(m <= 2), m, d)
}

/// The start of the UTC day containing `seconds`.
pub fn day_start(seconds: i64) -> i64 {
    seconds.div_euclid(86_400) * 86_400
}

// ------------------------------------------------------------------ sealing

const SEAL_VERSION: u8 = 1;
const INFO: &[u8] = b"zeronet mode stats v1";

/// Encrypt `plaintext` so only the holder of the private key for
/// `recipient` can read it: a fresh X25519 key for each file, HKDF-SHA256 to
/// an AES-256-GCM key. Layout: version, the fresh public key (32), a nonce
/// (12), the ciphertext with its tag.
pub fn seal(recipient: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use rand::RngCore;
    let ephemeral = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient));
    let key = derive(shared.as_bytes(), ephemeral_public.as_bytes(), recipient)?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let body = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| "could not seal".to_string())?;
    let mut out = Vec::with_capacity(1 + 32 + 12 + body.len());
    out.push(SEAL_VERSION);
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Read a file made by [`seal`] with the private key.
pub fn open(secret: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < 1 + 32 + 12 + 16 || sealed[0] != SEAL_VERSION {
        return Err("not a sealed mode-stats file".into());
    }
    let mut ephemeral_public = [0u8; 32];
    ephemeral_public.copy_from_slice(&sealed[1..33]);
    let secret = StaticSecret::from(*secret);
    let recipient = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral_public));
    let key = derive(shared.as_bytes(), &ephemeral_public, recipient.as_bytes())?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    cipher
        .decrypt(Nonce::from_slice(&sealed[33..45]), &sealed[45..])
        .map_err(|_| "this key cannot open that file".to_string())
}

fn derive(shared: &[u8], ephemeral_public: &[u8], recipient: &[u8]) -> Result<[u8; 32], String> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral_public);
    salt.extend_from_slice(recipient);
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(INFO, &mut key)
        .map_err(|_| "key derivation failed".to_string())?;
    Ok(key)
}

/// A fresh key pair: (public, secret).
pub fn keygen() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    (PublicKey::from(&secret).to_bytes(), secret.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(reporter: &str, net: &str, id: &str, ok: bool, ms: Option<u32>, ts: i64) -> Report {
        Report {
            ts,
            net: net.into(),
            reporter: reporter.into(),
            source: String::new(),
            kind: "mode".into(),
            item: id.into(),
            ok,
            ms,
        }
    }

    const DAY: i64 = 1_790_000_000 - 1_790_000_000 % 86_400;

    #[test]
    fn only_the_fixed_ids_are_taken() {
        assert!(valid_id("normal:connect"));
        assert!(valid_id("gaming:ping"));
        assert!(valid_id("legacy:stable"));
        for bad in [
            "normal",
            "normal:",
            ":connect",
            "turbo:connect",
            "normal:speed",
            "normal:connect:x",
            "NORMAL:connect",
        ] {
            assert!(!valid_id(bad), "{bad}");
        }
    }

    #[test]
    fn totals_count_people_facts_successes_and_delays() {
        let mut reports = Vec::new();
        for (i, person) in ["a", "b", "c", "d"].iter().enumerate() {
            reports.push(report(
                person,
                "cell:43211",
                "normal:connect",
                i != 3,
                Some(1000 + 500 * i as u32),
                DAY + 100,
            ));
        }
        let s = summarize(&reports, DAY);
        let f = &s.overall["normal:connect"];
        assert_eq!((f.reporters, f.total, f.ok), (4, 4, 3));
        assert_eq!(f.median_ms, Some(2000));
        assert_eq!(f.p90_ms, Some(2500));
        assert!(!s.overall.contains_key("gaming:ping"));
    }

    #[test]
    fn one_person_cannot_outweigh_the_rest() {
        let mut reports: Vec<Report> = (0..40)
            .map(|i| {
                report(
                    "loud",
                    "cell:43211",
                    "fast:connect",
                    true,
                    Some(100),
                    DAY + i,
                )
            })
            .collect();
        reports.push(report(
            "quiet",
            "cell:43211",
            "fast:connect",
            false,
            Some(9000),
            DAY + 50,
        ));
        let f = &summarize(&reports, DAY).overall["fast:connect"];
        assert_eq!(f.reporters, 2);
        assert_eq!(f.total, (PER_REPORTER + 1) as u32);
        assert_eq!(f.ok, PER_REPORTER as u32);
    }

    #[test]
    fn a_small_network_is_never_listed_on_its_own() {
        let mut reports = Vec::new();
        for person in ["a", "b", "c", "d", "e"] {
            reports.push(report(
                person,
                "cell:43211",
                "normal:connect",
                true,
                Some(900),
                DAY + 10,
            ));
        }
        for person in ["a", "b", "c"] {
            reports.push(report(
                person,
                "asn:58224",
                "normal:connect",
                true,
                Some(900),
                DAY + 10,
            ));
        }
        let s = summarize(&reports, DAY);
        assert!(s.by_net.contains_key("cell:43211"));
        assert!(
            !s.by_net.contains_key("asn:58224"),
            "three people are a fingerprint"
        );
        // Everyone still counts in the overall figures.
        assert_eq!(s.overall["normal:connect"].reporters, 5);
    }

    #[test]
    fn other_days_other_kinds_and_bad_ids_are_left_out() {
        let reports = vec![
            report("a", "any", "normal:connect", true, Some(500), DAY - 1),
            report("a", "any", "normal:connect", true, Some(500), DAY + 86_400),
            Report {
                kind: "server".into(),
                ..report("a", "any", "normal:connect", true, Some(500), DAY + 5)
            },
            report("a", "any", "turbo:connect", true, Some(500), DAY + 5),
            report("", "any", "normal:connect", true, Some(500), DAY + 5),
            report("a", "any", "normal:connect", true, Some(500), DAY + 5),
        ];
        let s = summarize(&reports, DAY);
        assert_eq!(s.overall.len(), 1);
        assert_eq!(s.overall["normal:connect"].total, 1);
        assert_eq!(count(&reports, DAY), 2);
    }

    #[test]
    fn days_are_named_in_utc() {
        assert_eq!(day_name(0), "1970-01-01");
        assert_eq!(day_name(951_782_400), "2000-02-29");
        assert_eq!(day_name(1_790_000_000), "2026-09-21");
        assert_eq!(day_name(-1), "1969-12-31");
        assert_eq!(day_start(1_790_000_123), 1_789_948_800);
    }

    #[test]
    fn what_is_sealed_opens_only_with_the_matching_key() {
        let (public, secret) = keygen();
        let text = br#"{"day":"2026-09-29"}"#;
        let sealed = seal(&public, text).unwrap();
        assert_eq!(open(&secret, &sealed).unwrap(), text);
        // The plaintext is not in the file.
        assert!(!sealed.windows(text.len()).any(|w| w == text));
        // Another key, a flipped byte and a short file all fail, in words.
        let (_, other) = keygen();
        assert!(open(&other, &sealed).is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&secret, &tampered).is_err());
        assert!(open(&secret, &sealed[..20]).is_err());
        // Every file is sealed with a fresh key, so two are never alike.
        assert_ne!(sealed, seal(&public, text).unwrap());
    }
}
