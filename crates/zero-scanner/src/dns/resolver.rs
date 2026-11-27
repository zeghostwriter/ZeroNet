use super::cache::{CompactDnsEntry, DnsCache, DnsCacheKey, DnsFlags};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio::task::JoinSet;

/// Per-query budget: all upstreams are raced, so this is also the worst-case
/// latency of a lookup.
const A_QUERY_TIMEOUT: Duration = Duration::from_millis(1200);
const TXT_QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
/// How long a failed lookup is remembered, so a blocked or broken resolver
/// path is not retried for every caller.
const NEGATIVE_TTL_SECS: u32 = 30;
/// Largest UDP DNS payload we accept (EDNS-less answers are at most 512, but
/// some resolvers send more).
const UDP_RECV_BYTES: usize = 4096;

type Inflight = DashMap<DnsCacheKey, broadcast::Sender<Result<Vec<IpAddr>, String>>>;

pub struct FastResolver {
    cache: DnsCache,
    inflight: Arc<Inflight>,
    resolvers: Arc<[SocketAddr]>,
}

impl Default for FastResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Removes the single-flight entry when the leading query finishes *or is
/// cancelled*. Without it a dropped leader would leave its sender in the map
/// forever and every later caller would subscribe and wait on it.
struct InflightGuard<'a> {
    map: &'a Inflight,
    key: DnsCacheKey,
    armed: bool,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.map.remove(&self.key);
        }
    }
}

impl FastResolver {
    pub fn new() -> Self {
        let mut resolvers = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
        ];

        // Read system nameserver from /etc/resolv.conf if present
        if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in resolv.lines() {
                let mut parts = line.split_whitespace();
                if parts.next() != Some("nameserver") {
                    continue;
                }
                if let Some(ip) = parts.next().and_then(|p| p.parse::<IpAddr>().ok()) {
                    let sa = SocketAddr::new(ip, 53);
                    if !resolvers.contains(&sa) {
                        resolvers.insert(0, sa);
                    }
                }
            }
        }

        Self {
            cache: DnsCache::new(60), // 60s stale grace
            inflight: Arc::new(DashMap::new()),
            resolvers: resolvers.into(),
        }
    }

    pub async fn resolve_ips(&self, name: &str) -> Result<Vec<IpAddr>, String> {
        let key = DnsCacheKey::new(name, 1); // QTYPE A

        // 1. Check cache
        if let Some((entry, is_stale)) = self.cache.get(&key) {
            if entry.flags.contains(DnsFlags::NEGATIVE) {
                if !is_stale {
                    return Err(format!("DNS resolution failed for {} (cached)", name));
                }
            } else {
                let ips = entry.extract_ips();
                if !ips.is_empty() {
                    if is_stale {
                        // Serve stale, refresh in the background into the
                        // same cache.
                        let resolver = self.clone_ref();
                        let domain = name.to_string();
                        tokio::spawn(async move {
                            let _ = resolver.race_query(&domain, 1).await;
                        });
                    }
                    return Ok(ips);
                }
            }
        }

        // 2. Single-flight request coalescing. The entry API makes "am I the
        // leader" atomic; checking and inserting separately let every caller
        // think it was the leader.
        let follower_rx = match self.inflight.entry(key.clone()) {
            Entry::Occupied(e) => Some(e.get().subscribe()),
            Entry::Vacant(v) => {
                let (tx, _) = broadcast::channel(1);
                v.insert(tx);
                None
            }
        };

        match follower_rx {
            None => {
                let mut guard = InflightGuard {
                    map: &self.inflight,
                    key,
                    armed: true,
                };
                let result = self.race_query(name, 1).await;
                // Disarm before removing: once our entry is gone a new leader
                // may insert its own, which the guard must not delete.
                guard.armed = false;
                if let Some((_, sender)) = self.inflight.remove(&guard.key) {
                    let _ = sender.send(result.clone());
                }
                result
            }
            Some(mut rx) => match rx.recv().await {
                Ok(res) => res,
                // Leader was cancelled: do the query ourselves.
                Err(_) => self.race_query(name, 1).await,
            },
        }
    }

    pub async fn resolve_txt(&self, name: &str) -> Result<String, String> {
        let key = DnsCacheKey::new(name, 16); // QTYPE TXT
        if let Some((entry, is_stale)) = self.cache.get(&key) {
            if entry.flags.contains(DnsFlags::NEGATIVE) {
                if !is_stale {
                    return Err(format!("TXT lookup failed for {} (cached)", name));
                }
            } else if let Some(txt) = entry.extract_txt() {
                return Ok(txt);
            }
        }

        let result = race_upstreams(
            &self.resolvers,
            name,
            16,
            TXT_QUERY_TIMEOUT,
            parse_dns_txt_response,
        )
        .await;
        match result {
            Some((txt, ttl)) => {
                self.cache.insert(key, CompactDnsEntry::new_txt(&txt, ttl));
                Ok(txt)
            }
            None => {
                self.cache
                    .insert(key, CompactDnsEntry::new_negative(NEGATIVE_TTL_SECS));
                Err(format!("TXT lookup failed for {}", name))
            }
        }
    }

    async fn race_query(&self, name: &str, qtype: u16) -> Result<Vec<IpAddr>, String> {
        let key = DnsCacheKey::new(name, qtype);
        match race_upstreams(
            &self.resolvers,
            name,
            qtype,
            A_QUERY_TIMEOUT,
            parse_dns_a_response,
        )
        .await
        {
            Some((ips, ttl)) => {
                self.cache
                    .insert(key, CompactDnsEntry::new_ip(&ips, ttl, DnsFlags::empty()));
                Ok(ips)
            }
            None => {
                self.cache
                    .insert(key, CompactDnsEntry::new_negative(NEGATIVE_TTL_SECS.min(5)));
                Err(format!("DNS resolution failed for {}", name))
            }
        }
    }

    /// A handle sharing this resolver's cache, for background refreshes.
    fn clone_ref(&self) -> Arc<Self> {
        Arc::new(Self {
            cache: self.cache.clone(),
            inflight: self.inflight.clone(),
            resolvers: self.resolvers.clone(),
        })
    }
}

/// Sends the query to up to three upstreams at once and returns the first
/// answer that parses. Waiting on them in order meant one dead upstream cost
/// its full timeout even when another had already answered.
async fn race_upstreams<T: Send + 'static>(
    resolvers: &[SocketAddr],
    name: &str,
    qtype: u16,
    timeout: Duration,
    parse: fn(&[u8]) -> Option<T>,
) -> Option<T> {
    let mut tasks = JoinSet::new();
    for &resolver in resolvers.iter().take(3) {
        let packet = build_dns_query(name, qtype);
        tasks.spawn(async move {
            let resp = query_udp(resolver, &packet, timeout).await.ok()?;
            parse(&resp)
        });
    }
    while let Some(joined) = tasks.join_next().await {
        if let Ok(Some(answer)) = joined {
            // Dropping the JoinSet aborts the slower queries.
            return Some(answer);
        }
    }
    None
}

pub fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    let id: u16 = rand::random();
    buf.extend_from_slice(&id.to_be_bytes()); // ID
    buf.extend_from_slice(&[0x01, 0x00]); // Flags: Standard query, RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        // Labels are limited to 63 bytes on the wire; longer ones would
        // corrupt the length prefix.
        let label = &label.as_bytes()[..label.len().min(63)];
        buf.push(label.len() as u8);
        buf.extend_from_slice(label);
    }
    buf.push(0); // Root label

    buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN (1)
    buf
}

async fn query_udp(
    target: SocketAddr,
    packet: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, std::io::Error> {
    let local_bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(local_bind).await?;
    // A connected socket only receives datagrams from `target`.
    socket.connect(target).await?;

    let exchange = async {
        socket.send(packet).await?;
        let mut buf = vec![0u8; UDP_RECV_BYTES];
        loop {
            let len = socket.recv(&mut buf).await?;
            // Ignore stray datagrams whose ID does not match our query.
            if len >= 2 && packet.len() >= 2 && buf[..2] == packet[..2] {
                buf.truncate(len);
                return Ok(buf);
            }
        }
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(res) => res,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "DNS query timed out",
        )),
    }
}

/// Skips a (possibly compressed) domain name starting at `offset`, returning
/// the offset just past it. Handles labels followed by a pointer, which the
/// old "check only the first byte for 0xC0" logic misread as a label length.
fn skip_name(buf: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let len = *buf.get(offset)?;
        match len & 0xC0 {
            0x00 if len == 0 => return Some(offset + 1),
            0x00 => offset += 1 + len as usize,
            0xC0 => {
                buf.get(offset + 1)?;
                return Some(offset + 2);
            }
            _ => return None, // reserved label types
        }
    }
}

/// Walks the answer section of a response, calling `f(rtype, ttl, rdata)`
/// for each record. Returns `None` for malformed or error responses.
fn for_each_answer(buf: &[u8], mut f: impl FnMut(u16, u32, &[u8])) -> Option<()> {
    if buf.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let is_response = flags & 0x8000 != 0;
    let rcode = flags & 0x000F;
    if !is_response || rcode != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_name(buf, offset)? + 4; // QTYPE + QCLASS
    }

    for _ in 0..ancount {
        offset = skip_name(buf, offset)?;
        let fixed = buf.get(offset..offset + 10)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let rdlength = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        offset += 10;
        let rdata = buf.get(offset..offset + rdlength)?;
        f(rtype, ttl, rdata);
        offset += rdlength;
    }
    Some(())
}

pub fn parse_dns_a_response(buf: &[u8]) -> Option<(Vec<IpAddr>, u32)> {
    let mut ips = Vec::new();
    let mut min_ttl = 300u32;
    // A truncated trailing record still leaves the earlier answers usable.
    let _ = for_each_answer(buf, |rtype, ttl, rdata| {
        if let (1, Ok(octets)) = (rtype, <[u8; 4]>::try_from(rdata)) {
            ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
            min_ttl = min_ttl.min(ttl);
        }
    });
    if ips.is_empty() {
        None
    } else {
        Some((ips, min_ttl))
    }
}

pub fn parse_dns_txt_response(buf: &[u8]) -> Option<(String, u32)> {
    let mut found = None;
    let _ = for_each_answer(buf, |rtype, ttl, rdata| {
        if rtype != 16 || found.is_some() {
            return;
        }
        // RDATA is one or more <len><bytes> character-strings; join them.
        let mut text = Vec::new();
        let mut i = 0;
        while let Some(&len) = rdata.get(i) {
            let Some(chunk) = rdata.get(i + 1..i + 1 + len as usize) else {
                break;
            };
            text.extend_from_slice(chunk);
            i += 1 + len as usize;
        }
        if !text.is_empty() {
            found = Some((String::from_utf8_lossy(&text).into_owned(), ttl));
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_query() {
        let q = build_dns_query("cloudflare.com", 1);
        assert!(q.len() > 12);
        assert_eq!(q[2], 0x01); // Flags
    }

    fn response(qname: &[u8], answers: &[u8], ancount: u16, rcode: u8) -> Vec<u8> {
        let mut r = vec![0x12, 0x34, 0x81, 0x80 | rcode, 0, 1];
        r.extend_from_slice(&ancount.to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 0]);
        r.extend_from_slice(qname);
        r.extend_from_slice(&[0, 1, 0, 1]);
        r.extend_from_slice(answers);
        r
    }

    const QNAME: &[u8] = b"\x07example\x03com\x00";

    #[test]
    fn parses_a_records_including_label_plus_pointer_names() {
        let mut answers = Vec::new();
        // Name "www" + pointer to offset 12 ("example.com").
        answers.extend_from_slice(b"\x03www\xc0\x0c");
        answers.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        // Plain pointer name.
        answers.extend_from_slice(b"\xc0\x0c");
        answers.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 5, 6, 7, 8]);
        let r = response(QNAME, &answers, 2, 0);
        let (ips, ttl) = parse_dns_a_response(&r).unwrap();
        assert_eq!(
            ips,
            vec![IpAddr::from([1, 2, 3, 4]), IpAddr::from([5, 6, 7, 8])]
        );
        assert_eq!(ttl, 30);
    }

    #[test]
    fn rejects_error_rcode_and_truncated_input() {
        let mut answers = b"\xc0\x0c".to_vec();
        answers.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        assert!(parse_dns_a_response(&response(QNAME, &answers, 1, 3)).is_none());
        let full = response(QNAME, &answers, 1, 0);
        for cut in 0..full.len() {
            let _ = parse_dns_a_response(&full[..cut]);
            let _ = parse_dns_txt_response(&full[..cut]);
        }
    }

    #[test]
    fn parses_multi_string_txt() {
        let mut answers = b"\xc0\x0c".to_vec();
        let rdata = b"\x0513335\x0d | 104.16.0.0";
        answers.extend_from_slice(&[0, 16, 0, 1, 0, 0, 1, 0, 0, rdata.len() as u8]);
        answers.extend_from_slice(rdata);
        let (txt, ttl) = parse_dns_txt_response(&response(QNAME, &answers, 1, 0)).unwrap();
        assert_eq!(txt, "13335 | 104.16.0.0");
        assert_eq!(ttl, 256);
    }

    #[tokio::test]
    async fn cancelled_leader_does_not_wedge_single_flight() {
        let r = FastResolver {
            cache: DnsCache::new(60),
            inflight: Arc::new(DashMap::new()),
            // Unroutable: the query hangs until its timeout.
            resolvers: vec![SocketAddr::from(([192, 0, 2, 1], 53))].into(),
        };
        let _ = tokio::time::timeout(Duration::from_millis(50), r.resolve_ips("example.com")).await;
        assert!(
            r.inflight.is_empty(),
            "leader's in-flight entry must be removed on cancel"
        );
    }
}
