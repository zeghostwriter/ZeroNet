//! Address and destination types shared by every layer.
//!
//! Protocol code must never carry a `String` hostname around on the hot path;
//! it carries an `Address`, and the compiled configuration owns the strings.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

/// Transport-layer network for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A destination address that may not be resolved yet.
///
/// Domains are kept as `Arc<str>` so that cloning a destination into a
/// connection plan, a route decision and a DNS lookup does not copy the name
/// three times.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ip(IpAddr),
    Domain(Arc<str>),
}

impl Address {
    pub fn domain(name: impl AsRef<str>) -> Self {
        Address::Domain(Arc::from(name.as_ref()))
    }

    /// Parse a host that may be a v4 literal, a bracketed or bare v6 literal,
    /// or a domain name.
    pub fn parse_host(host: &str) -> Self {
        let trimmed = host.trim();
        let unbracketed = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(trimmed);
        match unbracketed.parse::<IpAddr>() {
            Ok(ip) => Address::Ip(ip),
            Err(_) => Address::domain(trimmed),
        }
    }

    pub fn is_ip(&self) -> bool {
        matches!(self, Address::Ip(_))
    }

    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Address::Domain(d) => Some(d),
            Address::Ip(_) => None,
        }
    }

    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Address::Ip(ip) => Some(*ip),
            Address::Domain(_) => None,
        }
    }

    /// The form that goes into an SNI field or a `Host:` header.
    pub fn host_string(&self) -> String {
        match self {
            Address::Ip(IpAddr::V6(ip)) => format!("[{ip}]"),
            Address::Ip(IpAddr::V4(ip)) => ip.to_string(),
            Address::Domain(d) => d.to_string(),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ip(ip) => write!(f, "{ip}"),
            Address::Domain(d) => f.write_str(d),
        }
    }
}

impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Self {
        Address::Ip(ip)
    }
}

impl From<Ipv4Addr> for Address {
    fn from(ip: Ipv4Addr) -> Self {
        Address::Ip(IpAddr::V4(ip))
    }
}

impl From<Ipv6Addr> for Address {
    fn from(ip: Ipv6Addr) -> Self {
        Address::Ip(IpAddr::V6(ip))
    }
}

/// A full destination: where a session is trying to go.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Destination {
    pub address: Address,
    pub port: u16,
    pub network: Network,
}

impl Destination {
    pub fn new(address: Address, port: u16, network: Network) -> Self {
        Self {
            address,
            port,
            network,
        }
    }

    pub fn tcp(address: Address, port: u16) -> Self {
        Self::new(address, port, Network::Tcp)
    }

    pub fn udp(address: Address, port: u16) -> Self {
        Self::new(address, port, Network::Udp)
    }

    /// Parse `host:port`, accepting `[v6]:port`.
    pub fn parse(s: &str, network: Network) -> Option<Self> {
        let (host, port) = split_host_port(s)?;
        Some(Self::new(Address::parse_host(host), port, network))
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.address
            .as_ip()
            .map(|ip| SocketAddr::new(ip, self.port))
    }

    /// `host:port` with v6 bracketing, suitable for logs and `Host:` headers.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.address.host_string(), self.port)
    }
}

impl From<SocketAddr> for Destination {
    fn from(addr: SocketAddr) -> Self {
        Destination::tcp(Address::Ip(addr.ip()), addr.port())
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}/{}", self.address, self.port, self.network)
    }
}

/// Split `host:port`, handling `[::1]:443` and bare-domain forms.
pub fn split_host_port(s: &str) -> Option<(&str, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((host, port));
    }
    let (host, port) = s.rsplit_once(':')?;
    // A bare IPv6 literal has several colons and no port.
    if host.contains(':') {
        return None;
    }
    Some((host, port.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_host() {
        assert!(Address::parse_host("1.2.3.4").is_ip());
    }

    #[test]
    fn parses_bracketed_ipv6_host() {
        let a = Address::parse_host("[::1]");
        assert_eq!(a.as_ip(), Some("::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn treats_name_as_domain() {
        let a = Address::parse_host("example.com");
        assert_eq!(a.as_domain(), Some("example.com"));
    }

    #[test]
    fn splits_host_port_forms() {
        assert_eq!(
            split_host_port("example.com:443"),
            Some(("example.com", 443))
        );
        assert_eq!(split_host_port("[::1]:80"), Some(("::1", 80)));
        assert_eq!(split_host_port("::1"), None);
    }

    #[test]
    fn brackets_v6_in_authority() {
        let d = Destination::tcp(Address::parse_host("[::1]"), 443);
        assert_eq!(d.authority(), "[::1]:443");
    }
}
