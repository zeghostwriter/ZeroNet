//! Compiled DNS settings.

use std::collections::BTreeMap;
use std::sync::Arc;

use zero_core::Address;

/// A resolver endpoint and the policy that selects it.
#[derive(Debug, Clone)]
pub struct DnsServer {
    pub endpoint: ResolverEndpoint,
    /// Domains this server is preferred for; empty means "any".
    pub domains: Vec<crate::routing::DomainPattern>,
    /// Answers must fall in these ranges to be accepted.
    pub expect_ips: Vec<crate::routing::IpPattern>,
    /// When set, a miss here does not fall through to later servers.
    pub skip_fallback: bool,
    /// Routing tag applied to this server's own traffic.
    pub tag: Option<Arc<str>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverEndpoint {
    /// Classic DNS over UDP, falling back to TCP on truncation.
    Udp {
        address: Address,
        port: u16,
    },
    Tcp {
        address: Address,
        port: u16,
    },
    /// DNS over TLS.
    Dot {
        address: Address,
        port: u16,
    },
    /// DNS over HTTPS.
    Doh {
        url: Arc<str>,
        host: Arc<str>,
        port: u16,
    },
    /// DNS over HTTPS with an HTTP/2 request stream.
    Doh2 {
        url: Arc<str>,
        host: Arc<str>,
        port: u16,
    },
    /// DNS over HTTP/3 and QUIC.
    Doh3 {
        url: Arc<str>,
        host: Arc<str>,
        port: u16,
    },
    /// DNS over QUIC (RFC 9250).
    Doq {
        address: Address,
        port: u16,
    },
    /// The platform resolver. Never usable for destination lookups inside a
    /// full tunnel, because it would recurse back through the tunnel.
    System,
    /// Synthesises addresses without a query, for TUN-style routing.
    FakeDns,
}

impl ResolverEndpoint {
    /// Parse Xray's server string forms.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("localhost") || s.eq_ignore_ascii_case("system") {
            return Some(ResolverEndpoint::System);
        }
        if s.eq_ignore_ascii_case("fakedns") {
            return Some(ResolverEndpoint::FakeDns);
        }
        if let Some(rest) = s.strip_prefix("h2://") {
            let parsed = url::Url::parse(&format!("https://{rest}")).ok()?;
            let host = parsed.host_str()?;
            return Some(ResolverEndpoint::Doh2 {
                url: Arc::from(format!("https://{rest}")),
                host: Arc::from(host),
                port: parsed.port_or_known_default()?,
            });
        }
        if let Some(rest) = s
            .strip_prefix("h3://")
            .or_else(|| s.strip_prefix("https+quic://"))
        {
            let parsed = url::Url::parse(&format!("https://{rest}")).ok()?;
            let host = parsed.host_str()?;
            return Some(ResolverEndpoint::Doh3 {
                url: Arc::from(format!("https://{rest}")),
                host: Arc::from(host),
                port: parsed.port_or_known_default()?,
            });
        }
        if let Some(rest) = s.strip_prefix("doq://") {
            let (address, port) = split_addr_port(rest, 853)?;
            return Some(ResolverEndpoint::Doq { address, port });
        }
        if s.strip_prefix("https://").is_some() {
            let parsed = url::Url::parse(s).ok()?;
            let host = parsed.host_str()?;
            return Some(ResolverEndpoint::Doh {
                url: Arc::from(s),
                host: Arc::from(host),
                port: parsed.port_or_known_default()?,
            });
        }
        if let Some(rest) = s.strip_prefix("tls://") {
            let (addr, port) = split_addr_port(rest, 853)?;
            return Some(ResolverEndpoint::Dot {
                address: addr,
                port,
            });
        }
        if let Some(rest) = s.strip_prefix("tcp://") {
            let (addr, port) = split_addr_port(rest, 53)?;
            return Some(ResolverEndpoint::Tcp {
                address: addr,
                port,
            });
        }
        let rest = s.strip_prefix("udp://").unwrap_or(s);
        let (addr, port) = split_addr_port(rest, 53)?;
        Some(ResolverEndpoint::Udp {
            address: addr,
            port,
        })
    }

    /// Whether resolving this endpoint itself needs bootstrap DNS.
    pub fn needs_bootstrap(&self) -> bool {
        match self {
            ResolverEndpoint::Udp { address, .. }
            | ResolverEndpoint::Tcp { address, .. }
            | ResolverEndpoint::Dot { address, .. } => !address.is_ip(),
            ResolverEndpoint::Doh { host, .. }
            | ResolverEndpoint::Doh2 { host, .. }
            | ResolverEndpoint::Doh3 { host, .. } => Address::parse_host(host).as_ip().is_none(),
            ResolverEndpoint::Doq { address, .. } => !address.is_ip(),
            ResolverEndpoint::System | ResolverEndpoint::FakeDns => false,
        }
    }
}

fn split_addr_port(s: &str, default_port: u16) -> Option<(Address, u16)> {
    let s = s.trim_end_matches('/');
    if let Some((host, port)) = zero_core::address::split_host_port(s) {
        Some((Address::parse_host(host), port))
    } else {
        Some((Address::parse_host(s), default_port))
    }
}

/// What happens when the preferred resolver fails.
///
/// Zray must never silently leak DNS because an encrypted resolver failed
/// (RESEARCH-01 §30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LeakPolicy {
    /// Encrypted/tunnelled resolver fails means resolution fails.
    #[default]
    Strict,
    /// System DNS may be used as a last resort.
    Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueryStrategy {
    #[default]
    UseIp,
    UseIpv4,
    UseIpv6,
}

impl QueryStrategy {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim() {
            "UseIP" | "UseIPv4v6" => QueryStrategy::UseIp,
            "UseIPv4" => QueryStrategy::UseIpv4,
            "UseIPv6" => QueryStrategy::UseIpv6,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct DnsSettings {
    pub servers: Box<[DnsServer]>,
    /// Static answers. `#3` and similar sentinel values mean "block".
    pub hosts: BTreeMap<Box<str>, HostValue>,
    pub query_strategy: QueryStrategy,
    pub leak_policy: LeakPolicy,
    pub disable_cache: bool,
    pub tag: Option<Arc<str>>,
    /// Extra trust anchors for encrypted resolvers, PEM or DER.
    ///
    /// The same bounded statement of trust the outbound TLS path accepts, and
    /// for the same reason: an operator running their own DoT, DoH or DoQ
    /// resolver behind a private CA has no other way to reach it, and the
    /// alternative people reach for is disabling verification entirely.
    /// Anti-sanction and enterprise resolvers are both commonly in this
    /// position (PLAN-02 §3.5).
    pub trusted_roots: Vec<Box<[u8]>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostValue {
    Addresses(Vec<Address>),
    /// Resolve this other name instead.
    Alias(Box<str>),
    /// Answer with a blocked/empty response.
    Block,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_doh_url() {
        let e = ResolverEndpoint::parse("https://8.8.8.8/dns-query").unwrap();
        match e {
            ResolverEndpoint::Doh { host, .. } => assert_eq!(&*host, "8.8.8.8"),
            _ => panic!("expected doh"),
        }
    }

    #[test]
    fn parses_plain_ip_with_default_port() {
        let e = ResolverEndpoint::parse("178.22.122.100").unwrap();
        assert_eq!(
            e,
            ResolverEndpoint::Udp {
                address: Address::parse_host("178.22.122.100"),
                port: 53
            }
        );
    }

    #[test]
    fn parses_dot_default_port() {
        match ResolverEndpoint::parse("tls://dns.google").unwrap() {
            ResolverEndpoint::Dot { port, .. } => assert_eq!(port, 853),
            _ => panic!("expected dot"),
        }
    }

    #[test]
    fn ip_doh_needs_no_bootstrap() {
        assert!(!ResolverEndpoint::parse("https://8.8.8.8/dns-query")
            .unwrap()
            .needs_bootstrap());
        assert!(ResolverEndpoint::parse("https://dns.google/dns-query")
            .unwrap()
            .needs_bootstrap());
    }

    #[test]
    fn parses_doh2_endpoint_without_implicitly_using_system_dns() {
        let e = ResolverEndpoint::parse("h2://8.8.8.8/dns-query").unwrap();
        assert!(matches!(e, ResolverEndpoint::Doh2 { port: 443, .. }));
        assert!(!e.needs_bootstrap());
    }

    #[test]
    fn parses_doh3_and_doq_endpoints() {
        let doh3 = ResolverEndpoint::parse("h3://8.8.8.8/dns-query").unwrap();
        assert!(matches!(doh3, ResolverEndpoint::Doh3 { port: 443, .. }));
        assert!(!doh3.needs_bootstrap());
        let doq = ResolverEndpoint::parse("doq://dns.example:8853").unwrap();
        assert!(matches!(doq, ResolverEndpoint::Doq { port: 8853, .. }));
        assert!(doq.needs_bootstrap());
    }
}
