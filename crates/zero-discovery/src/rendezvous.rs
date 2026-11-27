//! Learning new carriers over encrypted DNS when the usual feeds are blocked.
//!
//! How this works. A *descriptor* is a short signed list of carrier links
//! (JSON: `{"v":1,"epoch":N,"carriers":[...]}`), signed with the same key as
//! the other lists ([`crate::sign`]). It is published as TXT records of a
//! domain the maintainer controls, cut into packets so that no single record
//! or name has to survive: a client asks a DNS-over-HTTPS resolver for
//! `f<i>.<zone>` for random `i` until it has enough packets, whichever ones
//! arrive.
//!
//! The packets are a *fountain code*: each is the XOR of a pseudo-random half
//! of the `k` source blocks, chosen by the packet's `seed`. Any `k` packets
//! whose choices are independent recover the blob (about `k + 2` random ones
//! do), so which packets arrive does not matter, and a blocked or poisoned
//! name only costs one more query. Decoding is Gaussian elimination over
//! GF(2); with `k <= 64` it is a handful of `u64` operations.
//!
//! The rules it keeps:
//!  * nothing is trusted before [`verify`]: the signature must verify, the
//!    epoch must be newer than the last one accepted (so a recorded old
//!    descriptor cannot be replayed) and not far in the future, and every
//!    link must parse. A descriptor only *names* carriers; each is still
//!    tested before use, like any candidate;
//!  * DNS answers are data: a packet that is malformed, inconsistent with the
//!    first, or for a different blob is skipped, never trusted to be part of
//!    the result (a wrong blob fails the signature);
//!  * a resolver sees a query for a random `f<i>` name, nothing that
//!    identifies the user or the carriers.
//!
//! The surprise: whether a DoH resolver is reachable at all from a censored
//! network is not something this file can promise; the resolver list is
//! configuration, and which ones answer from Iran has to be measured.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use base64::Engine as _;
use serde::Deserialize;

use crate::sign;

/// Bytes of the blob in each packet.
pub const BLOCK: usize = 120;
/// The most source blocks a descriptor may need (the mask is a `u64`).
pub const MAX_BLOCKS: usize = 64;
/// Packet header: version, block count, blob length, seed.
const HEADER: usize = 1 + 1 + 4 + 4;
const VERSION: u8 = 1;
/// Carriers a descriptor may name.
const MAX_CARRIERS: usize = 32;
/// How far ahead of the clock a descriptor's epoch may be (hours).
const EPOCH_SLACK: u64 = 48;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// The bit set of source blocks packet `seed` is the XOR of: never empty.
fn mask(seed: u32, k: usize) -> u64 {
    // splitmix64 of the seed: cheap, well mixed, and identical everywhere.
    let mut z = u64::from(seed).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    let all = if k == 64 { u64::MAX } else { (1u64 << k) - 1 };
    match z & all {
        0 => 1u64 << (seed as usize % k),
        picked => picked,
    }
}

/// How many source blocks a blob needs.
pub fn blocks_for(len: usize) -> usize {
    len.div_ceil(BLOCK).max(1)
}

/// Packet number `seed` of `blob`, as the text of a TXT record.
pub fn encode_packet(blob: &[u8], seed: u32) -> Result<String, String> {
    let k = blocks_for(blob.len());
    if k > MAX_BLOCKS {
        return Err(format!("a descriptor of {} bytes is too large", blob.len()));
    }
    let mut payload = [0u8; BLOCK];
    let picked = mask(seed, k);
    for index in (0..k).filter(|index| picked >> index & 1 == 1) {
        let part = &blob[index * BLOCK..blob.len().min((index + 1) * BLOCK)];
        for (byte, source) in payload.iter_mut().zip(part) {
            *byte ^= source;
        }
    }
    let mut packet = Vec::with_capacity(HEADER + BLOCK);
    packet.push(VERSION);
    packet.push(k as u8);
    packet.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    packet.extend_from_slice(&seed.to_be_bytes());
    packet.extend_from_slice(&payload);
    Ok(b64().encode(packet))
}

/// The TXT records to publish for `blob`: `(name, text)` for `f0` to
/// `f<count-1>`, names relative to the zone. Publish at least `3 * k`.
pub fn zone_records(blob: &[u8], count: u32) -> Result<Vec<(String, String)>, String> {
    (0..count)
        .map(|seed| Ok((format!("f{seed}"), encode_packet(blob, seed)?)))
        .collect()
}

/// Collects packets until the blob can be read.
#[derive(Default)]
pub struct Decoder {
    shape: Option<(usize, usize)>,
    /// Reduced rows, indexed by their lowest set bit.
    rows: Vec<Option<(u64, [u8; BLOCK])>>,
    rank: usize,
}

impl Decoder {
    /// Add a packet from a TXT record's text. Returns whether it was useful
    /// (well formed, consistent, and independent of those already held).
    pub fn add(&mut self, text: &str) -> bool {
        let Ok(packet) = b64().decode(text.trim()) else {
            return false;
        };
        if packet.len() != HEADER + BLOCK || packet[0] != VERSION {
            return false;
        }
        let k = packet[1] as usize;
        let len = u32::from_be_bytes(packet[2..6].try_into().expect("4 bytes")) as usize;
        let seed = u32::from_be_bytes(packet[6..10].try_into().expect("4 bytes"));
        if k == 0 || k > MAX_BLOCKS || blocks_for(len) != k {
            return false;
        }
        match self.shape {
            None => {
                self.shape = Some((k, len));
                self.rows = vec![None; k];
            }
            Some(shape) if shape != (k, len) => return false,
            Some(_) => {}
        }
        let mut row = mask(seed, k);
        let mut data = [0u8; BLOCK];
        data.copy_from_slice(&packet[HEADER..]);
        // Reduce against the rows already held until it is new or zero.
        while row != 0 {
            let pivot = row.trailing_zeros() as usize;
            match &self.rows[pivot] {
                Some((held, held_data)) => {
                    row ^= held;
                    for (byte, other) in data.iter_mut().zip(held_data) {
                        *byte ^= other;
                    }
                }
                None => {
                    self.rows[pivot] = Some((row, data));
                    self.rank += 1;
                    return true;
                }
            }
        }
        false
    }

    pub fn is_complete(&self) -> bool {
        self.shape.is_some_and(|(k, _)| self.rank == k)
    }

    /// The blob, once [`Self::is_complete`].
    pub fn finish(&self) -> Option<Vec<u8>> {
        let (k, len) = self.shape.filter(|(k, _)| self.rank == *k)?;
        // Back-substitute from the highest pivot down: each row holds only
        // bits at or above its pivot, so a lower row can be cleared of every
        // higher bit by the (already solved) higher rows.
        let mut solved: Vec<[u8; BLOCK]> = vec![[0u8; BLOCK]; k];
        for pivot in (0..k).rev() {
            let (row, mut data) = self.rows[pivot]?;
            for (higher, known) in solved.iter().enumerate().skip(pivot + 1) {
                if row >> higher & 1 == 1 {
                    for (byte, other) in data.iter_mut().zip(known) {
                        *byte ^= other;
                    }
                }
            }
            solved[pivot] = data;
        }
        let mut blob: Vec<u8> = solved.iter().flatten().copied().collect();
        blob.truncate(len);
        Some(blob)
    }
}

/// A signed, checked descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub epoch: u64,
    pub carriers: Vec<String>,
}

#[derive(Deserialize)]
struct Body {
    v: u8,
    epoch: u64,
    carriers: Vec<String>,
}

/// Make the blob to publish: the signature line, a newline, the JSON body.
pub fn sign_blob(secret: &[u8; 32], epoch: u64, carriers: &[String]) -> Vec<u8> {
    let body = serde_json::json!({"v": 1, "epoch": epoch, "carriers": carriers}).to_string();
    format!("{}\n{body}", sign::sign_with(secret, body.as_bytes())).into_bytes()
}

/// Check a blob from the network against `public_key_hex`. `last_epoch` is
/// the newest epoch accepted before (0 for none) and `now_hours` the clock in
/// hours since 1970.
pub fn verify(
    blob: &[u8],
    public_key_hex: &str,
    last_epoch: u64,
    now_hours: u64,
) -> Result<Descriptor, String> {
    let text = std::str::from_utf8(blob).map_err(|_| "descriptor is not text")?;
    let (signature, body) = text.split_once('\n').ok_or("descriptor has no signature")?;
    if !sign::verify_with(public_key_hex, body.as_bytes(), signature) {
        return Err("descriptor signature does not verify".into());
    }
    let parsed: Body = serde_json::from_str(body).map_err(|e| format!("descriptor: {e}"))?;
    if parsed.v != 1 {
        return Err(format!("descriptor version {} is not understood", parsed.v));
    }
    if parsed.epoch <= last_epoch {
        return Err("descriptor is not newer than the last one".into());
    }
    if parsed.epoch > now_hours + EPOCH_SLACK {
        return Err("descriptor is dated in the future".into());
    }
    if parsed.carriers.is_empty() || parsed.carriers.len() > MAX_CARRIERS {
        return Err("descriptor names no carriers, or too many".into());
    }
    let mut seen = HashSet::new();
    let mut carriers = Vec::new();
    for link in parsed.carriers {
        crate::link::parse_candidate(&link).map_err(|e| format!("a carrier is not a link: {e}"))?;
        if seen.insert(link.clone()) {
            carriers.push(link);
        }
    }
    Ok(Descriptor {
        epoch: parsed.epoch,
        carriers,
    })
}

pub type TxtFuture<'a> = Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>>;

/// Where TXT answers come from: a DoH resolver in production, a table in
/// tests.
pub trait TxtSource: Send + Sync {
    /// The TXT text of `name`, or `None` for any failure.
    fn txt<'a>(&'a self, name: &'a str) -> TxtFuture<'a>;
}

/// How many names are asked at once.
const WIDTH: usize = 4;

/// Ask for random packets of `zone` (`f0` to `f<count-1>`), [`WIDTH`] names at
/// a time, until the blob can be read; every name is asked at most once.
/// `pick` yields the next random index below its argument. Returns the blob
/// (not yet verified).
pub async fn collect(
    source: &dyn TxtSource,
    zone: &str,
    count: u32,
    mut pick: impl FnMut(u32) -> u32,
) -> Option<Vec<u8>> {
    let mut decoder = Decoder::default();
    let mut asked = HashSet::new();
    let mut misses = 0u32;
    while (asked.len() as u32) < count {
        let mut round = Vec::new();
        // Random picks, then a sweep, so a small `count` is still exhausted.
        while round.len() < WIDTH && (asked.len() + round.len()) < count as usize {
            let mut index = pick(count);
            if asked.contains(&index) || round.contains(&index) {
                misses += 1;
                if misses > count.saturating_mul(4) {
                    index = (0..count).find(|i| !asked.contains(i) && !round.contains(i))?;
                } else {
                    continue;
                }
            }
            round.push(index);
        }
        let names: Vec<String> = round.iter().map(|i| format!("f{i}.{zone}")).collect();
        let answers = futures::future::join_all(names.iter().map(|name| source.txt(name))).await;
        asked.extend(round);
        for text in answers.into_iter().flatten() {
            decoder.add(&text);
        }
        if decoder.is_complete() {
            return decoder.finish();
        }
    }
    None
}

/// What a host asks for in a search to use this.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RendezvousRequest {
    /// The domain whose TXT records carry the descriptor.
    pub zone: String,
    /// How many packets are published (`f0` to `f<count-1>`).
    pub count: u32,
    /// DoH JSON resolvers, tried in order for each name.
    pub doh: Vec<String>,
    /// The key the descriptor must verify against; the app's own when unset.
    #[serde(default)]
    pub public_key_hex: Option<String>,
}

/// Fetch, check and remember one descriptor. `cache_dir` keeps the newest
/// epoch accepted (`rendezvous.epoch`), so an older descriptor served later
/// is refused. `None` for any failure, within 20 seconds.
pub async fn fetch(
    request: &RendezvousRequest,
    cache_dir: Option<&std::path::Path>,
) -> Option<Descriptor> {
    use rand::Rng;
    let epoch_file = cache_dir.map(|dir| dir.join("rendezvous.epoch"));
    let last = epoch_file
        .as_ref()
        .and_then(|file| std::fs::read_to_string(file).ok())
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let source = DohJson {
        endpoints: request.doh.clone(),
    };
    let work = async {
        // The generator is fetched per pick: it must not live across an await.
        let blob = collect(&source, &request.zone, request.count, |bound| {
            rand::thread_rng().gen_range(0..bound)
        })
        .await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() / 3600);
        let key = request
            .public_key_hex
            .as_deref()
            .unwrap_or(sign::PUBLIC_KEY_HEX);
        verify(&blob, key, last, now).ok()
    };
    let descriptor = tokio::time::timeout(std::time::Duration::from_secs(20), work)
        .await
        .ok()??;
    if let Some(file) = epoch_file {
        let _ = std::fs::write(file, descriptor.epoch.to_string());
    }
    Some(descriptor)
}

/// DNS-over-HTTPS in its JSON form (`/resolve?name=..&type=TXT`), tried
/// resolver by resolver.
pub struct DohJson {
    /// Base URLs such as `https://dns.google/resolve`.
    pub endpoints: Vec<String>,
}

#[derive(Deserialize)]
struct Answer {
    #[serde(default, rename = "Answer")]
    answer: Vec<Record>,
}

#[derive(Deserialize)]
struct Record {
    #[serde(rename = "type")]
    kind: u16,
    data: String,
}

/// The text of a TXT answer: the quoted strings joined, or the bare text.
fn unquote(data: &str) -> String {
    if !data.starts_with('"') {
        return data.to_string();
    }
    data.split('"')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, part)| part)
        .collect()
}

impl TxtSource for DohJson {
    fn txt<'a>(&'a self, name: &'a str) -> TxtFuture<'a> {
        Box::pin(async move {
            let limits = zero_net::FetchLimits {
                max_bytes: 64 * 1024,
                timeout: std::time::Duration::from_secs(8),
                max_redirects: 0,
            };
            for endpoint in &self.endpoints {
                let sep = if endpoint.contains('?') { '&' } else { '?' };
                let url = format!("{endpoint}{sep}name={name}&type=TXT&ct=application/dns-json");
                let Ok(zero_net::Fetched::Body { body, .. }) =
                    zero_net::fetch(&url, &limits, &zero_net::Validators::default()).await
                else {
                    continue;
                };
                let Ok(answer) = serde_json::from_slice::<Answer>(&body) else {
                    continue;
                };
                if let Some(record) = answer.answer.iter().find(|r| r.kind == 16) {
                    return Some(unquote(&record.data));
                }
            }
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SECRET: [u8; 32] = [7u8; 32];

    fn key() -> String {
        sign::public_hex(&SECRET)
    }

    fn links() -> Vec<String> {
        vec![
            "vless://11111111-1111-1111-1111-111111111111@one.example.com:443?security=tls&sni=one.example.com&type=tcp#one".into(),
            "trojan://secret@two.example.com:443?security=tls&sni=two.example.com#two".into(),
        ]
    }

    fn blob(epoch: u64) -> Vec<u8> {
        sign_blob(&SECRET, epoch, &links())
    }

    struct Table(HashMap<String, String>);

    impl TxtSource for Table {
        fn txt<'a>(&'a self, name: &'a str) -> TxtFuture<'a> {
            Box::pin(async move { self.0.get(name).cloned() })
        }
    }

    fn table(blob: &[u8], zone: &str, count: u32) -> Table {
        Table(
            zone_records(blob, count)
                .unwrap()
                .into_iter()
                .map(|(name, text)| (format!("{name}.{zone}"), text))
                .collect(),
        )
    }

    fn lcg(seed: u64) -> impl FnMut(u32) -> u32 {
        let mut state = seed;
        move |bound| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((state >> 33) % u64::from(bound)) as u32
        }
    }

    #[test]
    fn any_enough_packets_rebuild_the_blob_whatever_arrived() {
        let original: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 256) as u8).collect();
        let k = blocks_for(original.len());
        for round in 0..40u64 {
            let mut pick = lcg(round + 1);
            let mut decoder = Decoder::default();
            let mut used = 0;
            while !decoder.is_complete() {
                let seed = pick(10_000);
                decoder.add(&encode_packet(&original, seed).unwrap());
                used += 1;
                assert!(used < k + 40, "needed {used} packets for {k} blocks");
            }
            assert_eq!(decoder.finish().unwrap(), original, "round {round}");
        }
    }

    #[test]
    fn a_single_block_and_an_exact_multiple_both_work() {
        for len in [1, BLOCK - 1, BLOCK, BLOCK + 1, 3 * BLOCK, 64 * BLOCK] {
            let original: Vec<u8> = (0..len).map(|i| (i * 31 % 253) as u8).collect();
            let mut decoder = Decoder::default();
            for seed in 0..(blocks_for(len) as u32 * 3 + 20) {
                decoder.add(&encode_packet(&original, seed).unwrap());
            }
            assert_eq!(decoder.finish().unwrap(), original, "length {len}");
        }
        assert!(encode_packet(&vec![0; 64 * BLOCK + 1], 0).is_err());
    }

    #[test]
    fn junk_and_foreign_packets_are_ignored() {
        let one: Vec<u8> = vec![1; 500];
        let two: Vec<u8> = vec![2; 600];
        let mut decoder = Decoder::default();
        assert!(!decoder.add("not base64 !!"));
        assert!(!decoder.add(&b64().encode([0u8; 7])));
        assert!(decoder.add(&encode_packet(&one, 3).unwrap()));
        // A packet of another blob (different length) is refused.
        assert!(!decoder.add(&encode_packet(&two, 4).unwrap()));
        // The same packet twice adds nothing.
        assert!(!decoder.add(&encode_packet(&one, 3).unwrap()));
    }

    #[tokio::test]
    async fn a_descriptor_comes_through_dns_and_verifies() {
        let signed = blob(500);
        let source = table(&signed, "example.org", 40);
        let got = collect(&source, "example.org", 40, lcg(9)).await.unwrap();
        assert_eq!(got, signed);
        let descriptor = verify(&got, &key(), 0, 1000).unwrap();
        assert_eq!(descriptor.epoch, 500);
        assert_eq!(descriptor.carriers, links());
    }

    #[tokio::test]
    async fn it_survives_missing_names_but_not_too_many() {
        let signed = blob(500);
        let mut source = table(&signed, "example.org", 60);
        // A third of the names blocked.
        source.0.retain(|name, _| name.len() % 3 != 0);
        assert!(collect(&source, "example.org", 60, lcg(5)).await.is_some());
        source.0.clear();
        assert!(collect(&source, "example.org", 60, lcg(5)).await.is_none());
    }

    #[test]
    fn a_descriptor_is_checked_before_it_is_believed() {
        let good = blob(500);
        assert!(verify(&good, &key(), 0, 1000).is_ok());
        // Wrong key.
        let other = sign::public_hex(&[8u8; 32]);
        assert!(verify(&good, &other, 0, 1000)
            .unwrap_err()
            .contains("signature"));
        // Altered body.
        let mut forged = good.clone();
        let last = forged.len() - 3;
        forged[last] ^= 1;
        assert!(verify(&forged, &key(), 0, 1000).is_err());
        // Replayed (not newer) and dated in the future.
        assert!(verify(&good, &key(), 500, 1000)
            .unwrap_err()
            .contains("newer"));
        assert!(verify(&blob(5000), &key(), 0, 1000)
            .unwrap_err()
            .contains("future"));
        // No carriers, and a carrier that is not a link.
        assert!(verify(&sign_blob(&SECRET, 600, &[]), &key(), 0, 1000).is_err());
        let bad = sign_blob(&SECRET, 600, &["not a link".to_string()]);
        assert!(verify(&bad, &key(), 0, 1000).is_err());
    }

    /// The DoH client against a stand-in resolver on a local port: it asks
    /// for the right name and type, reads the JSON answer, and moves on to
    /// the next resolver when one fails.
    #[tokio::test]
    async fn the_doh_client_reads_json_answers_and_skips_a_dead_resolver() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = vec![0u8; 4096];
                    let n = tcp.read(&mut request).await.unwrap();
                    let head = String::from_utf8_lossy(&request[..n]).to_string();
                    assert!(head.contains("name=f7.example.org"), "{head}");
                    assert!(head.contains("type=TXT"), "{head}");
                    let body = r#"{"Status":0,"Answer":[{"name":"f7.example.org","type":1,"data":"1.2.3.4"},{"name":"f7.example.org","type":16,"data":"\"abc\" \"def\""}]}"#;
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/dns-json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    tcp.write_all(reply.as_bytes()).await.unwrap();
                });
            }
        });
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let doh = DohJson {
            endpoints: vec![
                format!("http://127.0.0.1:{dead_port}/resolve"),
                format!("http://127.0.0.1:{port}/resolve"),
            ],
        };
        assert_eq!(doh.txt("f7.example.org").await.as_deref(), Some("abcdef"));
    }

    /// The whole path a host takes: random names asked of a resolver over
    /// HTTP, the answer decoded, verified, remembered; the same descriptor
    /// offered again later is refused as old.
    #[tokio::test]
    async fn a_search_learns_carriers_once_and_refuses_a_replay() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let signed = blob(700);
        let records: HashMap<String, String> = zone_records(&signed, 40)
            .unwrap()
            .into_iter()
            .map(|(name, text)| (format!("{name}.example.org"), text))
            .collect();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let records = records.clone();
                tokio::spawn(async move {
                    let mut request = vec![0u8; 4096];
                    let n = tcp.read(&mut request).await.unwrap();
                    let head = String::from_utf8_lossy(&request[..n]).to_string();
                    let name = head
                        .split("name=")
                        .nth(1)
                        .and_then(|rest| rest.split('&').next())
                        .unwrap_or("");
                    let body = match records.get(name) {
                        Some(text) => format!(
                            r#"{{"Status":0,"Answer":[{{"name":"{name}","type":16,"data":"\"{text}\""}}]}}"#
                        ),
                        None => r#"{"Status":3}"#.to_string(),
                    };
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    tcp.write_all(reply.as_bytes()).await.unwrap();
                });
            }
        });
        let dir = std::env::temp_dir().join(format!("rendezvous-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let request = RendezvousRequest {
            zone: "example.org".into(),
            count: 40,
            doh: vec![format!("http://127.0.0.1:{port}/resolve")],
            public_key_hex: Some(key()),
        };
        let first = fetch(&request, Some(&dir)).await.expect("a descriptor");
        assert_eq!(first.carriers, links());
        assert_eq!(
            std::fs::read_to_string(dir.join("rendezvous.epoch")).unwrap(),
            "700"
        );
        assert!(
            fetch(&request, Some(&dir)).await.is_none(),
            "a replay got in"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn txt_answers_are_unquoted() {
        assert_eq!(unquote("\"abc\" \"def\""), "abcdef");
        assert_eq!(unquote("\"abc\""), "abc");
        assert_eq!(unquote("abc"), "abc");
    }
}
