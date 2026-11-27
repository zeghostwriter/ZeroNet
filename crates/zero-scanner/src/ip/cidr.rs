use rand::Rng;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubnetV4 {
    pub start: u32,
    pub end: u32,
}

impl SubnetV4 {
    pub fn parse(cidr: &str) -> Option<Self> {
        let (addr, prefix) = cidr.trim().split_once('/')?;
        let ip = Ipv4Addr::from_str(addr).ok()?;
        let prefix: u32 = prefix.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        let ip_u32 = u32::from(ip);
        let mask = if prefix == 0 {
            0
        } else {
            !((1u32 << (32 - prefix)) - 1)
        };
        let start = ip_u32 & mask;
        // `1u32 << 32` for a /0 overflowed (a panic in debug builds, a
        // one-address range in release); the host bits are simply !mask.
        let end = start | !mask;
        Some(Self { start, end })
    }

    pub fn size(&self) -> u64 {
        (self.end as u64) - (self.start as u64) + 1
    }

    pub fn contains(&self, ip: u32) -> bool {
        ip >= self.start && ip <= self.end
    }

    pub fn random_ip<R: Rng>(&self, rng: &mut R) -> Ipv4Addr {
        let size = self.size();
        let offset = if size <= 1 { 0 } else { rng.gen_range(0..size) };
        Ipv4Addr::from(self.start + offset as u32)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetV6 {
    pub start: u128,
    pub end: u128,
}

impl SubnetV6 {
    pub fn parse(cidr: &str) -> Option<Self> {
        let (addr, prefix) = cidr.trim().split_once('/')?;
        let ip = Ipv6Addr::from_str(addr).ok()?;
        let prefix: u32 = prefix.parse().ok()?;
        if prefix > 128 {
            return None;
        }
        let ip_u128 = u128::from(ip);
        let mask = if prefix == 0 {
            0
        } else {
            !((1u128 << (128 - prefix)) - 1)
        };
        let start = ip_u128 & mask;
        let host_count = if prefix == 128 {
            1
        } else if prefix < 64 {
            // Cap at 2^64 to avoid overflow during weighted calculations
            1u128 << 64
        } else {
            1u128 << (128 - prefix)
        };
        let end = start.saturating_add(host_count.saturating_sub(1));
        Some(Self { start, end })
    }

    pub fn contains(&self, ip: u128) -> bool {
        ip >= self.start && ip <= self.end
    }

    /// Number of addresses this range covers, capped at 2^64 by `parse`.
    pub fn size(&self) -> u128 {
        self.end - self.start + 1
    }

    /// Picks a uniformly random address inside `[start, end]`.
    ///
    /// Ranges wider than 2^64 are capped by `parse` to their first 2^64
    /// addresses, so the span always fits in a `u64`. The offset is bounded
    /// by the span: a single-address entry (`start == end`, as produced for a
    /// bare IPv6 address in a custom list) or a narrow prefix such as a /120
    /// must never yield an address outside the range the user asked for.
    pub fn random_ip<R: Rng>(&self, rng: &mut R) -> Ipv6Addr {
        let span = (self.end - self.start).min(u64::MAX as u128) as u64;
        let offset = if span == 0 {
            0
        } else {
            rng.gen_range(0..=span)
        };
        Ipv6Addr::from(self.start + offset as u128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_v4_parsing() {
        let sub = SubnetV4::parse("104.16.0.0/13").unwrap();
        assert_eq!(sub.start, u32::from(Ipv4Addr::new(104, 16, 0, 0)));
        assert_eq!(sub.end, u32::from(Ipv4Addr::new(104, 23, 255, 255)));
        assert_eq!(sub.size(), 524288);
        assert!(sub.contains(u32::from(Ipv4Addr::new(104, 18, 5, 2))));
        assert!(!sub.contains(u32::from(Ipv4Addr::new(104, 24, 0, 0))));
    }

    #[test]
    fn test_random_v6_stays_inside_narrow_ranges() {
        let mut rng = rand::thread_rng();
        let single = SubnetV6 {
            start: u128::from(Ipv6Addr::from_str("2606:4700::1").unwrap()),
            end: u128::from(Ipv6Addr::from_str("2606:4700::1").unwrap()),
        };
        let narrow = SubnetV6::parse("2606:4700::/120").unwrap();
        let wide = SubnetV6::parse("2606:4700::/32").unwrap();
        for _ in 0..1000 {
            assert_eq!(
                single.random_ip(&mut rng),
                Ipv6Addr::from_str("2606:4700::1").unwrap()
            );
            assert!(narrow.contains(u128::from(narrow.random_ip(&mut rng))));
            assert!(wide.contains(u128::from(wide.random_ip(&mut rng))));
        }
    }

    #[test]
    fn test_parse_rejects_malformed() {
        assert!(SubnetV4::parse("1.2.3.4").is_none());
        assert!(SubnetV4::parse("1.2.3.4/33").is_none());
        assert!(SubnetV4::parse("1.2.3.4/8/1").is_none());
        assert_eq!(SubnetV4::parse("0.0.0.0/0").unwrap().size(), 1u64 << 32);
        assert!(SubnetV6::parse("::/129").is_none());
    }

    #[test]
    fn test_random_v4() {
        let sub = SubnetV4::parse("1.1.1.0/24").unwrap();
        let mut rng = rand::thread_rng();
        let ip = sub.random_ip(&mut rng);
        assert!(sub.contains(u32::from(ip)));
    }
}
