//! The normalized session description.
//!
//! Every inbound — SOCKS5, HTTP CONNECT, TUN, a future API — produces one of
//! these. Nothing downstream should be able to tell which one it was.
//! See RESEARCH-01 §37.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::address::{Destination, Network};

/// Identifies the compiled configuration a session is bound to.
///
/// A session keeps its generation for its whole life, so a config reload can
/// never make one flow observe two different rule sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GenerationId(pub u64);

/// Index into the compiled inbound table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InboundId(pub u32);

/// Index into the compiled outbound table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutboundId(pub u32);

/// Index into the compiled routing rule table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteId(pub u32);

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

/// Monotonic per-process session identifier, for logs and connection listings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

impl SessionId {
    pub fn next() -> Self {
        SessionId(NEXT_SESSION.fetch_add(1, Ordering::Relaxed))
    }
}

/// What a sniffer learned about a connection's first bytes.
#[derive(Debug, Clone, Default)]
pub struct Sniffed {
    /// Domain from a TLS SNI extension or an HTTP `Host:` header.
    pub domain: Option<Arc<str>>,
    /// Application protocol label: `tls`, `http`, `quic` or `bittorrent`.
    pub protocol: Option<&'static str>,
    /// The request line and headers of a sniffed HTTP request, for routing
    /// rules that match on `attrs`.
    pub http: Option<Arc<HttpAttrs>>,
}

/// What a sniffed HTTP request looked like, in the names Xray's `attrs`
/// routing rules use: `:method`, `:path`, and each header under its
/// lower-case name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpAttrs {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl HttpAttrs {
    /// The value of attribute `name` (`:method`, `:path` or a header name,
    /// case-insensitive), if the request had it.
    pub fn get(&self, name: &str) -> Option<&str> {
        match name.to_ascii_lowercase().as_str() {
            ":method" => Some(&self.method),
            ":path" => Some(&self.path),
            other => self
                .headers
                .iter()
                .find(|(key, _)| key == other)
                .map(|(_, value)| value.as_str()),
        }
    }
}

/// Everything the router and the connection planner are allowed to see.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub id: SessionId,
    pub generation: GenerationId,
    pub inbound: InboundId,
    pub inbound_tag: Arc<str>,
    pub source: Option<SocketAddr>,
    /// The local address the client connected to, for `localIP` and
    /// `localPort` routing rules.
    pub local: Option<SocketAddr>,
    /// The account that authenticated (its `email`), for `user` rules.
    pub user: Option<Arc<str>>,
    /// The route number in the middle of the VLESS user id that connected.
    pub vless_route: Option<u16>,
    /// Where the client asked to go.
    pub destination: Destination,
    /// Pre-sniffing destination, when sniffing rewrote it.
    pub original_destination: Option<Destination>,
    pub sniffed: Sniffed,
    /// Set once the router has decided.
    pub route: Option<RouteId>,
    /// Set once an outbound has been selected.
    pub outbound: Option<OutboundId>,
    /// Suppresses recursive DNS resolution for internal resolver traffic.
    pub skip_dns_resolve: bool,
}

impl SessionContext {
    pub fn new(
        generation: GenerationId,
        inbound: InboundId,
        inbound_tag: Arc<str>,
        destination: Destination,
    ) -> Self {
        Self {
            id: SessionId::next(),
            generation,
            inbound,
            inbound_tag,
            source: None,
            local: None,
            user: None,
            vless_route: None,
            destination,
            original_destination: None,
            sniffed: Sniffed::default(),
            route: None,
            outbound: None,
            skip_dns_resolve: false,
        }
    }

    pub fn with_source(mut self, source: SocketAddr) -> Self {
        self.source = Some(source);
        self
    }

    pub fn with_local(mut self, local: SocketAddr) -> Self {
        self.local = Some(local);
        self
    }

    pub fn with_user(mut self, user: Option<Arc<str>>) -> Self {
        self.user = user;
        self
    }

    pub fn network(&self) -> Network {
        self.destination.network
    }

    /// The name routing should match on: a sniffed domain outranks a literal
    /// destination IP, but never replaces an explicit destination domain.
    pub fn effective_domain(&self) -> Option<&str> {
        self.destination
            .address
            .as_domain()
            .or(self.sniffed.domain.as_deref())
    }

    /// Record a sniffing result, preserving the pre-sniff destination.
    pub fn apply_sniff(&mut self, sniffed: Sniffed, rewrite_destination: bool) {
        if rewrite_destination {
            if let Some(domain) = &sniffed.domain {
                if self.destination.address.is_ip() {
                    self.original_destination = Some(self.destination.clone());
                    self.destination.address = crate::address::Address::domain(domain);
                }
            }
        }
        self.sniffed = sniffed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, Destination};

    fn ctx() -> SessionContext {
        SessionContext::new(
            GenerationId(1),
            InboundId(0),
            Arc::from("in"),
            Destination::tcp(Address::parse_host("1.2.3.4"), 443),
        )
    }

    #[test]
    fn session_ids_are_unique() {
        assert_ne!(SessionId::next(), SessionId::next());
    }

    #[test]
    fn sniff_rewrites_ip_destination_and_keeps_original() {
        let mut c = ctx();
        c.apply_sniff(
            Sniffed {
                domain: Some(Arc::from("example.com")),
                protocol: Some("tls"),
                ..Default::default()
            },
            true,
        );
        assert_eq!(c.destination.address.as_domain(), Some("example.com"));
        assert!(c.original_destination.is_some());
    }

    #[test]
    fn sniff_does_not_override_explicit_domain() {
        let mut c = SessionContext::new(
            GenerationId(1),
            InboundId(0),
            Arc::from("in"),
            Destination::tcp(Address::domain("real.com"), 443),
        );
        c.apply_sniff(
            Sniffed {
                domain: Some(Arc::from("sniffed.com")),
                protocol: Some("tls"),
                ..Default::default()
            },
            true,
        );
        assert_eq!(c.destination.address.as_domain(), Some("real.com"));
        assert!(c.original_destination.is_none());
    }

    #[test]
    fn routeonly_sniff_leaves_destination_alone() {
        let mut c = ctx();
        c.apply_sniff(
            Sniffed {
                domain: Some(Arc::from("example.com")),
                protocol: Some("tls"),
                ..Default::default()
            },
            false,
        );
        assert!(c.destination.address.is_ip());
        assert_eq!(c.effective_domain(), Some("example.com"));
    }
}
