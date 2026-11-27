use super::cidr::{SubnetV4, SubnetV6};
use super::neighbors::{neighbors_around, DEFAULT_NEIGHBOR_PER_HIT, DEFAULT_NEIGHBOR_RADIUS};
use rand::Rng;
use roaring::RoaringBitmap;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};

const BUILTIN_V4: &str = include_str!("../../data/ranges_v4.txt");
const BUILTIN_V6: &str = include_str!("../../data/ranges_v6.txt");

/// Random draws attempted before falling back to a linear sweep for an
/// address that has not been handed out yet.
const RANDOM_ATTEMPTS: usize = 64;

/// Dedup state for one address family plus a sweep cursor.
///
/// Candidates are drawn at random first. Once random draws keep landing on
/// addresses that were already handed out (the pool is nearly used up), the
/// sweep cursor walks the merged ranges in order and returns the next unseen
/// address. Everything behind the cursor has been handed out and the seen set
/// only grows, so the cursor never goes back: the sweep costs O(pool) over the
/// whole scan, and reaching the end means the family is exhausted. Without it,
/// a small custom list could never be finished: the last few addresses would
/// be missed by chance and the scan would spin forever waiting for candidates.
struct FamilyState<S> {
    seen: S,
    cursor_range: usize,
    cursor_offset: u128,
    exhausted: bool,
}

pub struct IpSource {
    pub v4_subnets: Vec<SubnetV4>,
    pub v6_subnets: Vec<SubnetV6>,
    /// Running totals of subnet sizes, for size-weighted subnet selection.
    v4_cum_sizes: Vec<u64>,
    /// Sorted, non-overlapping `(start, end)` ranges covering `v4_subnets`.
    v4_merged: Vec<(u32, u32)>,
    /// Sorted, non-overlapping `(start, end)` ranges covering `v6_subnets`.
    v6_merged: Vec<(u128, u128)>,
    use_v4: bool,
    use_v6: bool,
    v4_state: Mutex<FamilyState<RoaringBitmap>>,
    v6_state: Mutex<FamilyState<HashSet<u128>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // The guarded data is a dedup set; a panic elsewhere cannot leave it in a
    // state that is unsafe to keep using.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn merge_ranges<T: Copy + Ord + num_like::Succ>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match out.last_mut() {
            // Overlapping or directly adjacent: extend the previous range.
            Some(last) if start <= last.1 || last.1.succ() == Some(start) => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => out.push((start, end)),
        }
    }
    out
}

mod num_like {
    pub trait Succ: Sized {
        fn succ(self) -> Option<Self>;
    }
    impl Succ for u32 {
        fn succ(self) -> Option<Self> {
            self.checked_add(1)
        }
    }
    impl Succ for u128 {
        fn succ(self) -> Option<Self> {
            self.checked_add(1)
        }
    }
}

impl IpSource {
    pub fn new(use_v4: bool, use_v6: bool, extra_cidrs: &[String], use_builtin: bool) -> Self {
        let mut v4_subnets = Vec::new();
        let mut v6_subnets = Vec::new();

        let entries = |text: &'static str| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
        };

        if use_builtin && use_v4 {
            v4_subnets.extend(entries(BUILTIN_V4).filter_map(SubnetV4::parse));
        }
        if use_builtin && use_v6 {
            v6_subnets.extend(entries(BUILTIN_V6).filter_map(SubnetV6::parse));
        }

        for entry in extra_cidrs {
            let trimmed = entry.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if use_v4 {
                if let Some(sub) = SubnetV4::parse(trimmed) {
                    v4_subnets.push(sub);
                    continue;
                } else if let Ok(ip4) = Ipv4Addr::from_str(trimmed) {
                    let u = u32::from(ip4);
                    v4_subnets.push(SubnetV4 { start: u, end: u });
                    continue;
                }
            }
            if use_v6 {
                if let Some(sub) = SubnetV6::parse(trimmed) {
                    v6_subnets.push(sub);
                } else if let Ok(ip6) = Ipv6Addr::from_str(trimmed) {
                    let u = u128::from(ip6);
                    v6_subnets.push(SubnetV6 { start: u, end: u });
                }
            }
        }

        let mut v4_cum_sizes = Vec::with_capacity(v4_subnets.len());
        let mut running_v4 = 0u64;
        for sub in &v4_subnets {
            running_v4 = running_v4.saturating_add(sub.size());
            v4_cum_sizes.push(running_v4);
        }

        let v4_merged = merge_ranges(v4_subnets.iter().map(|s| (s.start, s.end)).collect());
        let v6_merged = merge_ranges(v6_subnets.iter().map(|s| (s.start, s.end)).collect());

        let v4_state = FamilyState {
            seen: RoaringBitmap::new(),
            cursor_range: 0,
            cursor_offset: 0,
            exhausted: !use_v4 || v4_merged.is_empty(),
        };
        let v6_state = FamilyState {
            seen: HashSet::new(),
            cursor_range: 0,
            cursor_offset: 0,
            exhausted: !use_v6 || v6_merged.is_empty(),
        };

        Self {
            v4_subnets,
            v6_subnets,
            v4_cum_sizes,
            v4_merged,
            v6_merged,
            use_v4,
            use_v6,
            v4_state: Mutex::new(v4_state),
            v6_state: Mutex::new(v6_state),
        }
    }

    pub fn mark_seen(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => lock(&self.v4_state).seen.insert(u32::from(v4)),
            IpAddr::V6(v6) => lock(&self.v6_state).seen.insert(u128::from(v6)),
        }
    }

    pub fn is_seen(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => lock(&self.v4_state).seen.contains(u32::from(v4)),
            IpAddr::V6(v6) => lock(&self.v6_state).seen.contains(&u128::from(v6)),
        }
    }

    /// True once every address in every enabled range has been handed out
    /// (by `random_candidate` or as a neighbour). A scan with no target count
    /// uses this to finish instead of waiting forever for new candidates.
    pub fn is_exhausted(&self) -> bool {
        lock(&self.v4_state).exhausted && lock(&self.v6_state).exhausted
    }

    /// Returns an address that has not been handed out before, or `None`
    /// when every enabled range is exhausted.
    pub fn random_candidate(&self) -> Option<IpAddr> {
        let mut rng = rand::thread_rng();

        let v4_open = self.use_v4 && !lock(&self.v4_state).exhausted;
        let v6_open = self.use_v6 && !lock(&self.v6_state).exhausted;

        let pick_v6_first = match (v4_open, v6_open) {
            (false, false) => return None,
            (true, false) => false,
            (false, true) => true,
            (true, true) => {
                // Split draws between families by subnet count.
                let total = self.v4_subnets.len() + self.v6_subnets.len();
                rng.gen_range(0..total) >= self.v4_subnets.len()
            }
        };

        if pick_v6_first {
            self.next_v6(&mut rng)
                .map(IpAddr::V6)
                .or_else(|| self.next_v4(&mut rng).map(IpAddr::V4))
        } else {
            self.next_v4(&mut rng)
                .map(IpAddr::V4)
                .or_else(|| self.next_v6(&mut rng).map(IpAddr::V6))
        }
    }

    fn next_v4<R: Rng>(&self, rng: &mut R) -> Option<Ipv4Addr> {
        let total_size = *self.v4_cum_sizes.last()?;
        let mut st = lock(&self.v4_state);
        if st.exhausted || total_size == 0 {
            return None;
        }

        for _ in 0..RANDOM_ATTEMPTS {
            let r = rng.gen_range(0..total_size);
            // Subnet i covers draws in [cum[i-1], cum[i]), so the owner of `r`
            // is the first subnet whose running total exceeds it.
            let idx = self
                .v4_cum_sizes
                .partition_point(|&c| c <= r)
                .min(self.v4_subnets.len() - 1);
            let ip = self.v4_subnets[idx].random_ip(rng);
            if st.seen.insert(u32::from(ip)) {
                return Some(ip);
            }
        }

        while let Some(&(start, end)) = self.v4_merged.get(st.cursor_range) {
            let span = (end - start) as u128;
            while st.cursor_offset <= span {
                let ip = start + st.cursor_offset as u32;
                st.cursor_offset += 1;
                if st.seen.insert(ip) {
                    return Some(Ipv4Addr::from(ip));
                }
            }
            st.cursor_range += 1;
            st.cursor_offset = 0;
        }
        st.exhausted = true;
        None
    }

    fn next_v6<R: Rng>(&self, rng: &mut R) -> Option<Ipv6Addr> {
        if self.v6_subnets.is_empty() {
            return None;
        }
        let mut st = lock(&self.v6_state);
        if st.exhausted {
            return None;
        }

        for _ in 0..RANDOM_ATTEMPTS {
            let idx = rng.gen_range(0..self.v6_subnets.len());
            let ip = self.v6_subnets[idx].random_ip(rng);
            if st.seen.insert(u128::from(ip)) {
                return Some(ip);
            }
        }

        while let Some(&(start, end)) = self.v6_merged.get(st.cursor_range) {
            let span = end - start;
            while st.cursor_offset <= span {
                let ip = start + st.cursor_offset;
                st.cursor_offset += 1;
                if st.seen.insert(ip) {
                    return Some(Ipv6Addr::from(ip));
                }
            }
            st.cursor_range += 1;
            st.cursor_offset = 0;
        }
        st.exhausted = true;
        None
    }

    pub fn get_neighbors(&self, ip: IpAddr) -> Vec<IpAddr> {
        match ip {
            IpAddr::V4(ip4) => {
                let neighbors = neighbors_around(
                    ip4,
                    &self.v4_subnets,
                    DEFAULT_NEIGHBOR_RADIUS,
                    DEFAULT_NEIGHBOR_PER_HIT,
                );
                let mut st = lock(&self.v4_state);
                neighbors
                    .into_iter()
                    .filter(|&n| st.seen.insert(u32::from(n)))
                    .map(IpAddr::V4)
                    .collect()
            }
            IpAddr::V6(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn small_custom_list_is_fully_covered_then_exhausted() {
        // Previously the cumulative-size lookup could never select the last
        // single-address entry, and the scan would spin forever waiting for
        // it. Every entry must come out exactly once, then `None`.
        let list = custom(&["10.0.0.1", "10.0.0.7", "10.0.0.9", "192.0.2.0/30"]);
        let src = IpSource::new(true, false, &list, false);
        let mut got = HashSet::new();
        while let Some(ip) = src.random_candidate() {
            assert!(got.insert(ip), "duplicate candidate {ip}");
            assert!(got.len() <= 7);
        }
        assert_eq!(got.len(), 7);
        assert!(got.contains(&"10.0.0.9".parse::<IpAddr>().unwrap()));
        assert!(src.is_exhausted());
        assert!(src.random_candidate().is_none());
    }

    #[test]
    fn overlapping_ranges_are_deduplicated() {
        let list = custom(&["192.0.2.0/29", "192.0.2.4/30", "192.0.2.6"]);
        let src = IpSource::new(true, false, &list, false);
        let mut n = 0;
        while src.random_candidate().is_some() {
            n += 1;
            assert!(n <= 8);
        }
        assert_eq!(n, 8);
    }

    #[test]
    fn empty_source_is_exhausted() {
        let src = IpSource::new(true, false, &[], false);
        assert!(src.is_exhausted());
        assert!(src.random_candidate().is_none());
    }

    #[test]
    fn single_ipv6_entries_are_returned_verbatim() {
        let list = custom(&["2606:4700::1", "2606:4700::2"]);
        let src = IpSource::new(false, true, &list, false);
        let mut got: Vec<IpAddr> = std::iter::from_fn(|| src.random_candidate()).collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                "2606:4700::1".parse::<IpAddr>().unwrap(),
                "2606:4700::2".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn mixed_families_fall_back_when_one_is_exhausted() {
        let list = custom(&["192.0.2.1", "2606:4700::1"]);
        let src = IpSource::new(true, true, &list, false);
        let got: Vec<IpAddr> = std::iter::from_fn(|| src.random_candidate()).collect();
        assert_eq!(got.len(), 2);
        assert!(src.is_exhausted());
    }

    #[test]
    fn builtin_ranges_produce_candidates_inside_them() {
        let src = IpSource::new(true, false, &[], true);
        for _ in 0..1000 {
            let IpAddr::V4(ip) = src.random_candidate().unwrap() else {
                panic!("v6 candidate from a v4-only source");
            };
            let u = u32::from(ip);
            assert!(src.v4_subnets.iter().any(|s| s.contains(u)));
        }
        assert!(!src.is_exhausted());
    }
}
