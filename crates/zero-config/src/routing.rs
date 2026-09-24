//! Compiled routing rules.

use std::sync::Arc;

use zero_core::Network;

/// What a matched rule does with a session.
///
/// `DirectVia` is the third verdict Iran needs (PLAN-02 §4.4): go direct, but
/// resolve through a named resolver. Sanctioned services must be reached from
/// an Iranian address using an anti-sanction resolver; tunnelling them makes
/// things worse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleTarget {
    Outbound(Arc<str>),
    /// A health-aware group; resolved against the balancer table, which is a
    /// separate namespace from outbound tags.
    Balancer(Arc<str>),
    DirectVia {
        resolver: Arc<str>,
    },
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }

    /// Parse `"443"`, `"1000-2000"`, or a comma list handled by the caller.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if let Some((a, b)) = s.split_once('-') {
            Some(Self {
                start: a.trim().parse().ok()?,
                end: b.trim().parse().ok()?,
            })
        } else {
            let p = s.parse().ok()?;
            Some(Self { start: p, end: p })
        }
    }
}

/// How a domain pattern matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPattern {
    /// Exact name only.
    Full(Box<str>),
    /// The name or any label-boundary subdomain of it.
    Suffix(Box<str>),
    /// Substring anywhere in the name.
    Keyword(Box<str>),
    Regex(Box<str>),
    /// `geosite:xxx`, resolved against loaded geodata.
    Geosite(Box<str>),
}

impl DomainPattern {
    /// Parse Xray's prefixed matcher syntax. A bare name is a suffix match.
    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("full:") {
            DomainPattern::Full(rest.into())
        } else if let Some(rest) = s.strip_prefix("domain:") {
            DomainPattern::Suffix(rest.into())
        } else if let Some(rest) = s.strip_prefix("keyword:") {
            DomainPattern::Keyword(rest.into())
        } else if let Some(rest) = s.strip_prefix("regexp:") {
            DomainPattern::Regex(rest.into())
        } else if let Some(rest) = s.strip_prefix("geosite:") {
            DomainPattern::Geosite(rest.into())
        } else if let Some(rest) = s.strip_prefix("ext:") {
            // Xray accepts `ext:geosite.dat:tag`; the file name selects the
            // geodata source while the matcher namespace is still `tag`.
            let tag = rest.rsplit_once(':').map_or(rest, |(_, tag)| tag);
            DomainPattern::Geosite(tag.into())
        } else {
            DomainPattern::Suffix(s.into())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpPattern {
    Cidr(ipnet_lite::Cidr),
    Geoip(Box<str>),
    Private,
}

/// One ordered routing rule. Populated selectors within a rule are ANDed.
#[derive(Debug, Clone)]
pub struct Rule {
    pub domains: Vec<DomainPattern>,
    pub ips: Vec<IpPattern>,
    pub source_ips: Vec<IpPattern>,
    pub ports: Vec<PortRange>,
    pub source_ports: Vec<PortRange>,
    pub networks: Vec<Network>,
    pub inbound_tags: Vec<Box<str>>,
    pub protocols: Vec<Box<str>>,
    pub target: RuleTarget,
}

impl Rule {
    pub fn new(target: RuleTarget) -> Self {
        Self {
            domains: Vec::new(),
            ips: Vec::new(),
            source_ips: Vec::new(),
            ports: Vec::new(),
            source_ports: Vec::new(),
            networks: Vec::new(),
            inbound_tags: Vec::new(),
            protocols: Vec::new(),
            target,
        }
    }

    /// A rule with no selectors matches everything, which is almost always a
    /// configuration mistake rather than an intent.
    pub fn is_unconditional(&self) -> bool {
        self.domains.is_empty()
            && self.ips.is_empty()
            && self.source_ips.is_empty()
            && self.ports.is_empty()
            && self.source_ports.is_empty()
            && self.networks.is_empty()
            && self.inbound_tags.is_empty()
            && self.protocols.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    /// Resolve and retest rules against every resolved address.
    IpIfNonMatch,
    /// Resolve only when a rule actually needs an IP.
    IpOnDemand,
}

impl DomainStrategy {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim() {
            "AsIs" => DomainStrategy::AsIs,
            "IPIfNonMatch" => DomainStrategy::IpIfNonMatch,
            "IPOnDemand" => DomainStrategy::IpOnDemand,
            _ => return None,
        })
    }
}

/// A health-aware group of outbounds.
#[derive(Debug, Clone)]
pub struct Balancer {
    pub tag: Arc<str>,
    /// Tag prefixes expanded against the outbound table at compile time.
    pub selector: Vec<Box<str>>,
    pub strategy: BalancerStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BalancerStrategy {
    #[default]
    Random,
    RoundRobin,
    LeastPing,
    LeastLoad,
}

impl BalancerStrategy {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "random" => BalancerStrategy::Random,
            "roundrobin" => BalancerStrategy::RoundRobin,
            "leastping" => BalancerStrategy::LeastPing,
            "leastload" => BalancerStrategy::LeastLoad,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Routing {
    pub domain_strategy: DomainStrategy,
    pub rules: Box<[Rule]>,
    pub balancers: Box<[Balancer]>,
}

/// A very small CIDR type, so the model crate does not pull a dependency that
/// the matcher crate will own anyway.
pub mod ipnet_lite {
    use std::net::IpAddr;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Cidr {
        pub addr: IpAddr,
        pub prefix: u8,
    }

    impl Cidr {
        pub fn parse(s: &str) -> Option<Self> {
            let s = s.trim();
            let (addr, prefix) = match s.split_once('/') {
                Some((a, p)) => (a, p.parse().ok()?),
                None => {
                    let a: IpAddr = s.parse().ok()?;
                    let bits = if a.is_ipv4() { 32 } else { 128 };
                    return Some(Cidr {
                        addr: a,
                        prefix: bits,
                    });
                }
            };
            let addr: IpAddr = addr.parse().ok()?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return None;
            }
            Some(Cidr { addr, prefix })
        }

        pub fn contains(&self, ip: IpAddr) -> bool {
            match (self.addr, ip) {
                (IpAddr::V4(net), IpAddr::V4(other)) => {
                    prefix_eq(&net.octets(), &other.octets(), self.prefix)
                }
                (IpAddr::V6(net), IpAddr::V6(other)) => {
                    prefix_eq(&net.octets(), &other.octets(), self.prefix)
                }
                _ => false,
            }
        }
    }

    fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
        let full = (prefix / 8) as usize;
        if a[..full] != b[..full] {
            return false;
        }
        let rem = prefix % 8;
        if rem == 0 {
            return true;
        }
        let mask = 0xffu8 << (8 - rem);
        (a[full] & mask) == (b[full] & mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn domain_prefixes() {
        assert_eq!(
            DomainPattern::parse("full:a.com"),
            DomainPattern::Full("a.com".into())
        );
        assert_eq!(
            DomainPattern::parse("a.com"),
            DomainPattern::Suffix("a.com".into())
        );
        assert_eq!(
            DomainPattern::parse("geosite:cn"),
            DomainPattern::Geosite("cn".into())
        );
        assert_eq!(
            DomainPattern::parse("ext:geosite.dat:ir"),
            DomainPattern::Geosite("ir".into())
        );
    }

    #[test]
    fn cidr_containment() {
        let c = ipnet_lite::Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.1.2.3".parse::<IpAddr>().unwrap()));
        assert!(!c.contains("11.0.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn cidr_non_byte_aligned_prefix() {
        let c = ipnet_lite::Cidr::parse("192.168.1.0/28").unwrap();
        assert!(c.contains("192.168.1.15".parse::<IpAddr>().unwrap()));
        assert!(!c.contains("192.168.1.16".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn cidr_rejects_family_mismatch() {
        let c = ipnet_lite::Cidr::parse("10.0.0.0/8").unwrap();
        assert!(!c.contains("::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn port_ranges() {
        let p = PortRange::parse("100-200").unwrap();
        assert!(p.contains(150));
        assert!(!p.contains(201));
    }
}
