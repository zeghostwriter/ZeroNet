use bitflags::bitflags;
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct DnsFlags: u8 {
        const AUTHENTICATED = 1 << 0;
        const NEGATIVE      = 1 << 1;
        const SERVE_STALE   = 1 << 2;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsCacheKey {
    pub name: Box<str>,
    pub qtype: u16, // 1 for A, 28 for AAAA, 16 for TXT
}

impl DnsCacheKey {
    pub fn new(name: &str, qtype: u16) -> Self {
        let normalized = name.trim().trim_end_matches('.').to_lowercase();
        Self {
            name: normalized.into_boxed_str(),
            qtype,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompactDnsEntry {
    pub inserted_at_secs: u64,
    pub ttl_secs: u32,
    pub flags: DnsFlags,
    pub offsets: [u16; 3],  // [answer_offset, auth_offset, additional_offset]
    pub payload: Box<[u8]>, // contiguous wire bytes or packed IP bytes
}

impl CompactDnsEntry {
    pub fn new_ip(ips: &[IpAddr], ttl_secs: u32, flags: DnsFlags) -> Self {
        let mut scratch = Vec::with_capacity(ips.len() * 16);
        for ip in ips {
            match ip {
                IpAddr::V4(v4) => {
                    scratch.push(4u8);
                    scratch.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    scratch.push(6u8);
                    scratch.extend_from_slice(&v6.octets());
                }
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            inserted_at_secs: now,
            ttl_secs,
            flags,
            offsets: [0, scratch.len() as u16, scratch.len() as u16],
            payload: scratch.into_boxed_slice(),
        }
    }

    pub fn new_txt(text: &str, ttl_secs: u32) -> Self {
        let bytes = text.as_bytes();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            inserted_at_secs: now,
            ttl_secs,
            flags: DnsFlags::empty(),
            offsets: [0, bytes.len() as u16, bytes.len() as u16],
            payload: bytes.to_vec().into_boxed_slice(),
        }
    }

    pub fn new_negative(ttl_secs: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            inserted_at_secs: now,
            ttl_secs,
            flags: DnsFlags::NEGATIVE,
            offsets: [0, 0, 0],
            payload: Box::new([]),
        }
    }

    pub fn is_fresh(&self, now_secs: u64) -> bool {
        now_secs <= self.inserted_at_secs.saturating_add(self.ttl_secs as u64)
    }

    pub fn is_stale_usable(&self, now_secs: u64, stale_grace_secs: u64) -> bool {
        let expire = self.inserted_at_secs.saturating_add(self.ttl_secs as u64);
        now_secs > expire && now_secs <= expire.saturating_add(stale_grace_secs)
    }

    pub fn extract_ips(&self) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        let mut i = 0;
        let buf = &self.payload;
        while i < buf.len() {
            let tag = buf[i];
            i += 1;
            if tag == 4 && i + 4 <= buf.len() {
                if let Ok(octets) = <[u8; 4]>::try_from(&buf[i..i + 4]) {
                    ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
                }
                i += 4;
            } else if tag == 6 && i + 16 <= buf.len() {
                if let Ok(octets) = <[u8; 16]>::try_from(&buf[i..i + 16]) {
                    ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                i += 16;
            } else {
                break;
            }
        }
        ips
    }

    pub fn extract_txt(&self) -> Option<String> {
        String::from_utf8(self.payload.to_vec()).ok()
    }
}

/// Entry count above which inserts first evict expired entries (and, if
/// that is not enough, arbitrary ones). Cymru lookups are keyed per IP, so an
/// unbounded map would grow with every healthy hit of a long scan.
pub const DNS_CACHE_MAX_ENTRIES: usize = 8192;

/// Cheap to clone: clones share the same entries.
#[derive(Clone)]
pub struct DnsCache {
    entries: Arc<DashMap<DnsCacheKey, CompactDnsEntry>>,
    stale_grace_secs: u64,
}

impl DnsCache {
    pub fn new(stale_grace_secs: u64) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            stale_grace_secs,
        }
    }

    pub fn get(&self, key: &DnsCacheKey) -> Option<(CompactDnsEntry, bool)> {
        let entry = self.entries.get(key)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if entry.is_fresh(now) {
            Some((entry.value().clone(), false))
        } else if entry.is_stale_usable(now, self.stale_grace_secs) {
            Some((entry.value().clone(), true))
        } else {
            None
        }
    }

    pub fn insert(&self, key: DnsCacheKey, entry: CompactDnsEntry) {
        if self.entries.len() >= DNS_CACHE_MAX_ENTRIES && !self.entries.contains_key(&key) {
            self.evict();
        }
        self.entries.insert(key, entry);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let grace = self.stale_grace_secs;
        self.entries
            .retain(|_, e| e.is_fresh(now) || e.is_stale_usable(now, grace));
        // Still full of live entries: drop a quarter so eviction is amortised
        // instead of running on every insert.
        let len = self.entries.len();
        if len >= DNS_CACHE_MAX_ENTRIES {
            let mut to_drop = len - DNS_CACHE_MAX_ENTRIES * 3 / 4;
            self.entries.retain(|_, _| {
                if to_drop > 0 {
                    to_drop -= 1;
                    false
                } else {
                    true
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_is_bounded() {
        let cache = DnsCache::new(0);
        for i in 0..(DNS_CACHE_MAX_ENTRIES * 2) {
            cache.insert(
                DnsCacheKey::new(&format!("{i}.example"), 16),
                CompactDnsEntry::new_txt("x", 3600),
            );
        }
        assert!(cache.len() <= DNS_CACHE_MAX_ENTRIES);
    }
}
