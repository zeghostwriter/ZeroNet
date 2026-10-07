//! Leak-aware DNS resolution for Zray.
//!
//! The resolver owns DNS wire encoding, transport selection, caching and
//! FakeDNS allocation. It deliberately does not expose a generic system-DNS
//! fallback: an encrypted resolver failure is an error under the default
//! [`LeakPolicy::Strict`] policy.

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::{Duration, Instant};

use bytes::Buf;
use bytes::Bytes;
use http::Request;
use regex::Regex;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{oneshot, watch, Mutex};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use url::Url;
use zero_config::dns::{
    DnsServer, DnsSettings, HostValue, LeakPolicy, QueryStrategy, ResolverEndpoint,
};
use zero_config::routing::{DomainPattern, IpPattern};
use zero_core::Address;

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Classic UDP retransmission interval: a single lost datagram costs one
/// second, not the whole query budget.
const UDP_RETRANSMIT: Duration = Duration::from_secs(1);
/// Without EDNS a UDP answer is at most 512 bytes; this leaves generous room
/// for servers that overshoot without paying for a 64 KiB buffer per query.
const UDP_RECV_BUFFER: usize = 4096;
const MAX_PACKET: usize = 65_535;
const MAX_NAME: usize = 253;
const FAKE_V4_BASE: u32 = (198 << 24) | (18 << 16);
/// Addresses in the FakeDNS pool: 198.18.0.0/15 minus the network address
/// and the top address.
const FAKE_POOL_SIZE: u32 = 0x1fffe;
/// Upper bound on cached answers per resolver. A TUN client resolves every
/// name the device touches; without a bound the cache grows for the life of
/// the process.
const CACHE_CAPACITY: usize = 4096;
/// Negative answers (NXDOMAIN/NODATA) are cached for the SOA-derived TTL
/// (RFC 2308), clamped to this range. Without negative caching a UseIP lookup
/// of an IPv4-only name re-asks for AAAA on every single connection.
const NEGATIVE_TTL_MIN: Duration = Duration::from_secs(5);
const NEGATIVE_TTL_MAX: Duration = Duration::from_secs(120);
const NEGATIVE_TTL_DEFAULT: Duration = Duration::from_secs(30);
/// Pooled encrypted-resolver connections idle longer than this are
/// discarded instead of reused: a NAT or middlebox may have silently dropped
/// them, and discovering that costs a full query timeout.
const POOL_IDLE: Duration = Duration::from_secs(30);
const DOT_POOL_IDLE: Duration = Duration::from_secs(15);
const DOT_POOL_PER_KEY: usize = 4;
/// Budget for a query on a pooled connection before it is presumed dead and
/// the query is retried on a fresh one.
const REUSED_TIMEOUT: Duration = Duration::from_secs(3);
/// Allowance for the HTTP/1.1 response head on top of the DNS message.
const HTTP_HEAD_LIMIT: usize = 16 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResolveError {
    #[error("DNS name is empty")]
    EmptyName,
    #[error("DNS name is too long")]
    NameTooLong,
    #[error("DNS answer is blocked by hosts policy")]
    Blocked,
    #[error("no DNS resolver is configured")]
    NoResolvers,
    #[error("DNS resolver bootstrap would use the system resolver for {0}")]
    BootstrapRequired(String),
    #[error("resolver transport is unavailable: {0}")]
    Unsupported(String),
    #[error("DNS protocol error: {0}")]
    Protocol(String),
    #[error("DNS transport error: {0}")]
    Transport(String),
    #[error("DNS returned no usable address for {0}")]
    NoData(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum QueryType {
    A,
    Aaaa,
    /// HTTPS/SVCB records, used for ECH configuration discovery.
    Https,
}

impl QueryType {
    fn wire(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Https => 65,
        }
    }

    fn accepts(self, ip: IpAddr) -> bool {
        match self {
            Self::A => ip.is_ipv4(),
            Self::Aaaa => ip.is_ipv6(),
            Self::Https => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QueryKey {
    name: Arc<str>,
    kind: QueryType,
}

/// Contiguous DNS cache entry storing IPs in a flat slice. An empty slice is
/// a cached negative answer.
#[derive(Debug, Clone)]
struct CachedAnswer {
    ips: Box<[IpAddr]>,
    expires: Instant,
}

#[derive(Debug, Clone)]
struct CachedEch {
    config_list: Box<[u8]>,
    expires: Instant,
}

#[derive(Debug, Clone)]
struct PacketAnswer {
    addresses: Vec<IpAddr>,
    records: Vec<Vec<u8>>,
    /// Positive TTL, or — for an empty (NXDOMAIN/NODATA) answer — the
    /// negative-caching TTL.
    ttl: Duration,
    truncated: bool,
}

#[derive(Debug, Default)]
struct FakeState {
    by_name: HashMap<(Box<str>, QueryType), IpAddr>,
    by_ip: HashMap<IpAddr, Box<str>>,
}

type InflightResult = Option<Result<Vec<IpAddr>, ResolveError>>;
type InflightMap = HashMap<QueryKey, watch::Sender<InflightResult>>;

/// Removes a leader's in-flight entry however its lookup ends — completed,
/// failed, or dropped mid-await.
struct InflightGuard<'a> {
    map: &'a StdMutex<InflightMap>,
    key: &'a QueryKey,
    sender: &'a watch::Sender<InflightResult>,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        let mut map = lock(self.map);
        if map
            .get(self.key)
            .is_some_and(|current| current.same_channel(self.sender))
        {
            map.remove(self.key);
        }
    }
}

/// The outcome of a failed uncached query. `negative_ttl` is set only when
/// the failure was an authoritative "no such data" answer that may be cached.
#[derive(Debug)]
struct QueryFailure {
    error: ResolveError,
    negative_ttl: Option<Duration>,
}

impl From<ResolveError> for QueryFailure {
    fn from(error: ResolveError) -> Self {
        Self {
            error,
            negative_ttl: None,
        }
    }
}

/// Lock a std mutex, recovering from poisoning. Every critical section in
/// this crate is a plain map operation that leaves the map consistent even if
/// a panic unwinds through it.
fn lock<T>(mutex: &StdMutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The four TLS client configurations, built once and shared by every view
/// of a resolver.
struct TlsConfigs {
    /// DoT: no ALPN.
    plain: Arc<rustls::ClientConfig>,
    /// DoH: offers h2 and falls back to HTTP/1.1.
    doh: Arc<rustls::ClientConfig>,
    h2: Arc<rustls::ClientConfig>,
    h3: Arc<rustls::ClientConfig>,
    doq: Arc<rustls::ClientConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    address: SocketAddr,
    server_name: Arc<str>,
}

impl PoolKey {
    fn new(address: SocketAddr, server_name: &str) -> Self {
        Self {
            address,
            server_name: Arc::from(server_name),
        }
    }
}

/// A pooled HTTP/2 connection. Dropping the entry drops `_close`, which stops
/// the connection driver task and closes the socket.
struct H2Entry {
    generation: u64,
    sender: h2::client::SendRequest<Bytes>,
    last_used: Instant,
    _close: oneshot::Sender<()>,
}

/// A pooled QUIC connection for DoQ.
struct QuicEntry {
    generation: u64,
    connection: quinn::Connection,
    last_used: Instant,
    _endpoint: quinn::Endpoint,
}

/// An idle DoT connection and when it was returned to the pool.
type IdleDot = (TlsStream<TcpStream>, Instant);

/// Reusable encrypted-resolver connections. Opening TCP+TLS (or QUIC) per
/// query costs two to three round trips before the question is even asked;
/// reuse makes a warm encrypted lookup a single round trip.
#[derive(Default)]
struct Pools {
    generation: AtomicU64,
    h2: StdMutex<HashMap<PoolKey, H2Entry>>,
    dot: StdMutex<HashMap<PoolKey, Vec<IdleDot>>>,
    doq: StdMutex<HashMap<PoolKey, QuicEntry>>,
    /// Measured response time per endpoint, shared by every view, so the
    /// fastest resolver of a tier is asked first (see [`rank`]).
    rtt: StdMutex<HashMap<ResolverEndpoint, Rtt>>,
    /// Upstream group queries so far; every [`EXPLORE_EVERY`]th asks the top
    /// two at once, so a resolver that got faster is noticed.
    explored: AtomicU32,
}

impl Pools {
    fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::Relaxed)
    }

    fn checkout_h2(&self, key: &PoolKey) -> Option<(u64, h2::client::SendRequest<Bytes>)> {
        let mut pool = lock(&self.h2);
        let entry = pool.get_mut(key)?;
        if entry.last_used.elapsed() > POOL_IDLE {
            pool.remove(key);
            return None;
        }
        entry.last_used = Instant::now();
        Some((entry.generation, entry.sender.clone()))
    }

    fn evict_h2(&self, key: &PoolKey, generation: u64) {
        let mut pool = lock(&self.h2);
        if pool
            .get(key)
            .is_some_and(|entry| entry.generation == generation)
        {
            pool.remove(key);
        }
    }

    fn checkout_dot(&self, key: &PoolKey) -> Option<TlsStream<TcpStream>> {
        let mut pool = lock(&self.dot);
        let idle = pool.get_mut(key)?;
        while let Some((stream, since)) = idle.pop() {
            if since.elapsed() <= DOT_POOL_IDLE {
                return Some(stream);
            }
        }
        pool.remove(key);
        None
    }

    fn checkin_dot(&self, key: PoolKey, stream: TlsStream<TcpStream>) {
        let mut pool = lock(&self.dot);
        let idle = pool.entry(key).or_default();
        idle.retain(|(_, since)| since.elapsed() <= DOT_POOL_IDLE);
        if idle.len() < DOT_POOL_PER_KEY {
            idle.push((stream, Instant::now()));
        }
    }

    fn checkout_doq(&self, key: &PoolKey) -> Option<(u64, quinn::Connection)> {
        let mut pool = lock(&self.doq);
        let entry = pool.get_mut(key)?;
        if entry.last_used.elapsed() > POOL_IDLE || entry.connection.close_reason().is_some() {
            pool.remove(key);
            return None;
        }
        entry.last_used = Instant::now();
        Some((entry.generation, entry.connection.clone()))
    }

    fn evict_doq(&self, key: &PoolKey, generation: u64) {
        let mut pool = lock(&self.doq);
        if pool
            .get(key)
            .is_some_and(|entry| entry.generation == generation)
        {
            pool.remove(key);
        }
    }
}

/// The `regexp:` patterns of one configured server, parallel to its `domains`
/// list: element `i` is `domains[i]` compiled when that entry is a
/// [`DomainPattern::Regex`] that compiled, and `None` otherwise.
type CompiledRegexes = Vec<Option<Regex>>;

/// Compile every `regexp:` domain pattern in `servers`, indexed by server and
/// then by domain.
///
/// The matcher used to compile at match time, and `Regex::new` builds an
/// automaton: 66 us against 104 ns for five matches of
/// `^([a-z0-9-]+\.)*example\.com$`. Compiling is what a lookup paid, once per
/// candidate server. These are static configuration, so they are compiled here
/// instead -- 20 us for eight servers, once, which a config breaks even on
/// after a fifth of one uncached query.
///
/// A pattern that does not compile is stored as `None`, which is where
/// `Regex::new` would have failed and matched nothing, so a bad pattern is
/// still matched exactly as before.
fn compile_server_regexes(servers: &[DnsServer]) -> Vec<CompiledRegexes> {
    servers
        .iter()
        .map(|server| {
            server
                .domains
                .iter()
                .map(|pattern| match pattern {
                    DomainPattern::Regex(value) => Regex::new(value).ok(),
                    _ => None,
                })
                .collect()
        })
        .collect()
}

/// Parse every DoH URL in `servers` once, keyed by the URL string.
///
/// `Url::parse` builds a whole URL structure: 260 ns for
/// `https://dns.google/dns-query` against 0.3 ns for a borrow of the parsed
/// form, paid on every DoH, DoH2 and DoH3 query before a byte went out.
///
/// A URL that does not parse is stored as the message the parse produced, so
/// the error a query reports is unchanged.
fn compile_doh_urls(servers: &[DnsServer]) -> HashMap<Arc<str>, Result<Url, String>> {
    servers
        .iter()
        .filter_map(|server| match &server.endpoint {
            ResolverEndpoint::Doh { url, .. }
            | ResolverEndpoint::Doh2 { url, .. }
            | ResolverEndpoint::Doh3 { url, .. } => {
                Some((Arc::clone(url), Url::parse(url).map_err(|e| e.to_string())))
            }
            _ => None,
        })
        .collect()
}

/// The order [`Resolver::candidates`] walks: every server index, domain-scoped
/// ones first, catch-all ones last, each group in configured order.
///
/// Exactly the stable sort by `domains.is_empty()` that `candidates` used to
/// run per lookup -- 162 ns for eight servers -- lifted to where it is
/// computed once. `sort_by_key` is stable, so the order within each tier is
/// the declared one.
fn server_tiers(servers: &[DnsServer]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..servers.len()).collect();
    order.sort_by_key(|index| servers[*index].domains.is_empty());
    order
}

/// A resolver compiled from [`DnsSettings`]. Cloning it is cheap and safe for
/// concurrent sessions; cache and in-flight state are shared.
#[derive(Clone)]
pub struct Resolver {
    settings: Arc<DnsSettings>,
    cache: Arc<StdMutex<HashMap<QueryKey, CachedAnswer>>>,
    ech_cache: Arc<StdMutex<HashMap<Arc<str>, CachedEch>>>,
    inflight: Arc<StdMutex<InflightMap>>,
    fake: Arc<Mutex<FakeState>>,
    fake_next: Arc<AtomicU32>,
    tls: Arc<TlsConfigs>,
    pools: Arc<Pools>,
    /// Memoized [`Resolver::for_tag`] views. Routing asks for a view per
    /// session (and per UDP datagram); building one used to mean four fresh
    /// rustls configurations and an empty cache every time.
    views: Arc<StdMutex<HashMap<Arc<str>, Resolver>>>,
    /// Compiled once in [`Self::with_shared`]; see
    /// [`Resolver::compile_server_regexes`].
    regexes: Arc<Vec<CompiledRegexes>>,
    /// Parsed once in [`Self::with_shared`]; see
    /// [`Resolver::compile_doh_urls`].
    doh_urls: Arc<HashMap<Arc<str>, Result<Url, String>>>,
    /// Ordered once in [`Self::with_shared`]; see
    /// [`Resolver::server_tiers`].
    tiers: Arc<Vec<usize>>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("servers", &self.settings.servers.len())
            .field("cache", &"shared")
            .finish()
    }
}

impl Resolver {
    pub fn new(settings: DnsSettings) -> Self {
        // One root store, built once, shared by all four encrypted transports.
        // Building it per transport was four chances for them to disagree
        // about what the resolver trusts.
        let roots = trust_store(&settings.trusted_roots);
        let config = |alpn: Option<&[u8]>| {
            let mut config = rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
            if let Some(alpn) = alpn {
                config.alpn_protocols = vec![alpn.to_vec()];
            }
            config
        };
        let mut doh = config(Some(b"h2"));
        doh.alpn_protocols.push(b"http/1.1".to_vec());
        let tls = TlsConfigs {
            plain: Arc::new(config(None)),
            doh: Arc::new(doh),
            h2: Arc::new(config(Some(b"h2"))),
            h3: Arc::new(config(Some(b"h3"))),
            doq: Arc::new(config(Some(b"doq"))),
        };
        Self::with_shared(
            Arc::new(settings),
            Arc::new(tls),
            Arc::new(Pools::default()),
        )
    }

    fn with_shared(settings: Arc<DnsSettings>, tls: Arc<TlsConfigs>, pools: Arc<Pools>) -> Self {
        let regexes = Arc::new(compile_server_regexes(&settings.servers));
        let doh_urls = Arc::new(compile_doh_urls(&settings.servers));
        let tiers = Arc::new(server_tiers(&settings.servers));
        Self {
            settings,
            cache: Arc::new(StdMutex::new(HashMap::new())),
            ech_cache: Arc::new(StdMutex::new(HashMap::new())),
            inflight: Arc::new(StdMutex::new(HashMap::new())),
            fake: Arc::new(Mutex::new(FakeState::default())),
            fake_next: Arc::new(AtomicU32::new(1)),
            tls,
            pools,
            views: Arc::new(StdMutex::new(HashMap::new())),
            regexes,
            doh_urls,
            tiers,
        }
    }

    pub fn settings(&self) -> &DnsSettings {
        &self.settings
    }

    /// Create a resolver view restricted to one configured server tag. The
    /// view gets independent cache state so a domestic DirectVia policy cannot
    /// reuse an answer learned from a different resolver tier.
    ///
    /// Views are memoized: repeated calls for one tag return the same view,
    /// so its cache and in-flight coalescing persist across sessions.
    ///
    /// `tag@address` narrows the view to the one server of that tag at that
    /// address — how a measured choice among several resolvers of one tier
    /// is applied without rewriting the configuration.
    pub fn for_tag(&self, tag: &str) -> Self {
        if let Some(view) = lock(&self.views).get(tag) {
            return view.clone();
        }
        let (server_tag, pinned) = match tag.split_once('@') {
            Some((server_tag, address)) => (server_tag, Some(address)),
            None => (tag, None),
        };
        let mut settings = (*self.settings).clone();
        settings.servers = settings
            .servers
            .iter()
            .filter(|server| server.tag.as_deref() == Some(server_tag))
            .filter(|server| pinned.is_none_or(|address| server.endpoint.host() == address))
            .cloned()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        // Connections are keyed by endpoint, not by answer tier, so sharing
        // the pools and TLS configurations cannot leak answers between views.
        let view = Self::with_shared(
            Arc::new(settings),
            Arc::clone(&self.tls),
            Arc::clone(&self.pools),
        );
        lock(&self.views)
            .entry(Arc::from(tag))
            .or_insert(view)
            .clone()
    }

    /// Whether any configured server hands out FakeDNS addresses.
    pub fn has_fake(&self) -> bool {
        self.settings
            .servers
            .iter()
            .any(|server| server.endpoint == ResolverEndpoint::FakeDns)
    }

    /// A view that never answers with FakeDNS addresses, for the runtime's
    /// own lookups: proxy server names, direct connections, ECH records.
    ///
    /// FakeDNS exists for the applications behind the TUN: they get a
    /// synthetic address at once, and the name travels to the proxy, which
    /// resolves it remotely. The runtime itself must connect somewhere real,
    /// so handing the dialer `198.18.x.y` for a proxy server's own name would
    /// break every connection. Without FakeDNS in the configuration this is
    /// the resolver itself, sharing its cache.
    ///
    /// Memoized like [`Resolver::for_tag`], so the view's cache persists.
    pub fn without_fake(&self) -> Self {
        if !self.has_fake() {
            return self.clone();
        }
        const KEY: &str = "\0real";
        if let Some(view) = lock(&self.views).get(KEY) {
            return view.clone();
        }
        let mut settings = (*self.settings).clone();
        settings.servers = settings
            .servers
            .iter()
            .filter(|server| server.endpoint != ResolverEndpoint::FakeDns)
            .cloned()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let view = Self::with_shared(
            Arc::new(settings),
            Arc::clone(&self.tls),
            Arc::clone(&self.pools),
        );
        lock(&self.views)
            .entry(Arc::from(KEY))
            .or_insert(view)
            .clone()
    }

    /// Keep `previous`'s FakeDNS allocations when this resolver replaces it
    /// on a configuration reload. Applications cache the synthetic addresses
    /// they were given; a fresh pool would leave every one of them pointing
    /// at nothing (or, once reallocated, at another name).
    pub fn adopt_fake_state(mut self, previous: &Resolver) -> Self {
        self.fake = Arc::clone(&previous.fake);
        self.fake_next = Arc::clone(&previous.fake_next);
        self
    }

    /// Resolve an address without ever changing a literal IP into a DNS query.
    pub async fn resolve_address(
        &self,
        address: &Address,
        strategy: QueryStrategy,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        match address {
            Address::Ip(ip) => Ok(vec![*ip]),
            Address::Domain(name) => self.lookup(name, strategy).await,
        }
    }

    /// Reverse a FakeDNS allocation for the TUN bridge. Real addresses are
    /// never reverse-resolved here, so a packet cannot accidentally trigger a
    /// local DNS lookup while being classified.
    pub async fn fake_reverse(&self, address: IpAddr) -> Option<Arc<str>> {
        self.fake
            .lock()
            .await
            .by_ip
            .get(&address)
            .cloned()
            .map(Arc::from)
    }

    /// Resolve A/AAAA according to the configured query strategy.
    pub async fn lookup(
        &self,
        name: &str,
        strategy: QueryStrategy,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        let name = normalize_name(name)?;
        if let Some(answer) = self.host_answer(&name, 0)? {
            let answer = filter_strategy(answer, strategy);
            if !answer.is_empty() {
                return Ok(answer);
            }
        }

        // Both families are asked concurrently: sequential A-then-AAAA made
        // every dual-stack lookup pay two round trips.
        let results = match strategy {
            QueryStrategy::UseIp => {
                let (v4, v6) = tokio::join!(
                    self.lookup_kind(&name, QueryType::A),
                    self.lookup_kind(&name, QueryType::Aaaa)
                );
                vec![v4, v6]
            }
            QueryStrategy::UseIpv4 => vec![self.lookup_kind(&name, QueryType::A).await],
            QueryStrategy::UseIpv6 => vec![self.lookup_kind(&name, QueryType::Aaaa).await],
        };
        let mut output = Vec::new();
        let mut last_error = None;
        for result in results {
            match result {
                Ok(mut ips) => output.append(&mut ips),
                Err(ResolveError::NoData(_)) => {}
                Err(e) => last_error = Some(e),
            }
        }
        output.sort();
        output.dedup();
        if output.is_empty() {
            Err(last_error.unwrap_or_else(|| ResolveError::NoData(name.to_string())))
        } else {
            Ok(output)
        }
    }

    /// Resolve the HTTPS/SVCB ECH configuration for a public name through the
    /// configured resolver policy. The returned bytes are the TLS-encoded
    /// ECHConfigList consumed by Rustls; no system resolver is introduced by
    /// this helper under strict leak policy.
    pub async fn lookup_ech_config_list(
        &self,
        name: &str,
        _strategy: QueryStrategy,
    ) -> Result<Vec<u8>, ResolveError> {
        let name = normalize_name(name)?;
        if !self.settings.disable_cache {
            let mut cache = lock(&self.ech_cache);
            let now = Instant::now();
            match cache.get(&name) {
                Some(entry) if entry.expires > now => return Ok(entry.config_list.to_vec()),
                Some(_) => {
                    cache.remove(&name);
                }
                None => {}
            }
            if cache.len() >= CACHE_CAPACITY {
                cache.retain(|_, entry| entry.expires > now);
            }
        }
        let answer = self
            .query_uncached(&name, QueryType::Https)
            .await
            .map_err(|failure| failure.error)?;
        let config_list = answer
            .records
            .iter()
            .find_map(|record| parse_https_ech_config(record))
            .ok_or_else(|| ResolveError::NoData(format!("no ECH configuration for {name}")))?;
        if !self.settings.disable_cache {
            let ttl = answer.ttl.min(Duration::from_secs(86_400));
            if !ttl.is_zero() {
                lock(&self.ech_cache).insert(
                    Arc::clone(&name),
                    CachedEch {
                        config_list: config_list.clone().into_boxed_slice(),
                        expires: Instant::now() + ttl,
                    },
                );
            }
        }
        Ok(config_list)
    }

    /// Return a synthetic address-to-name mapping for a FakeDNS address.
    pub async fn reverse_fake(&self, address: IpAddr) -> Option<Box<str>> {
        self.fake.lock().await.by_ip.get(&address).cloned()
    }

    async fn lookup_kind(
        &self,
        name: &Arc<str>,
        kind: QueryType,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        let key = QueryKey {
            name: Arc::clone(name),
            kind,
        };
        loop {
            if !self.settings.disable_cache {
                if let Some(answer) = self.cached(&key) {
                    return answer;
                }
            }

            // Many concurrent lookups of one name share a single upstream
            // query. The follower holds only a receiver: if the leader's
            // future is dropped mid-query (the caller timed out or went
            // away), its guard removes the entry and drops the last sender,
            // the follower sees the channel close, and it retries — as the
            // new leader if nobody else got there first. Holding a sender
            // clone here instead would park every follower, and every later
            // lookup of the name, forever.
            let role = {
                let mut inflight = lock(&self.inflight);
                match inflight.get(&key) {
                    Some(sender) => Err(sender.subscribe()),
                    None => {
                        let (sender, _) = watch::channel(None);
                        inflight.insert(key.clone(), sender.clone());
                        Ok(sender)
                    }
                }
            };
            let sender = match role {
                Ok(sender) => sender,
                Err(mut receiver) => {
                    loop {
                        if let Some(result) = receiver.borrow_and_update().clone() {
                            return result;
                        }
                        if receiver.changed().await.is_err() {
                            // Final check: the value may have been published
                            // just before the sender went away.
                            if let Some(result) = receiver.borrow().clone() {
                                return result;
                            }
                            break;
                        }
                    }
                    continue;
                }
            };
            let _guard = InflightGuard {
                map: &self.inflight,
                key: &key,
                sender: &sender,
            };
            let result = match self.query_uncached(name, kind).await {
                Ok(answer) => {
                    if !self.settings.disable_cache {
                        self.store_cache(key.clone(), answer.addresses.clone(), answer.ttl);
                    }
                    Ok(answer.addresses)
                }
                Err(QueryFailure {
                    error,
                    negative_ttl,
                }) => {
                    if let (false, Some(ttl)) = (self.settings.disable_cache, negative_ttl) {
                        self.store_cache(key.clone(), Vec::new(), ttl);
                    }
                    Err(error)
                }
            };
            let _ = sender.send(Some(result.clone()));
            return result;
        }
    }

    /// A fresh cache entry: `Ok(ips)` for a positive answer, `Err(NoData)`
    /// for a cached negative one.
    fn cached(&self, key: &QueryKey) -> Option<Result<Vec<IpAddr>, ResolveError>> {
        let mut cache = lock(&self.cache);
        match cache.get(key) {
            Some(entry) if entry.expires > Instant::now() => Some(if entry.ips.is_empty() {
                Err(ResolveError::NoData(key.name.to_string()))
            } else {
                Ok(entry.ips.to_vec())
            }),
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    fn store_cache(&self, key: QueryKey, addresses: Vec<IpAddr>, ttl: Duration) {
        let ttl = ttl.min(Duration::from_secs(86_400));
        if ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let mut cache = lock(&self.cache);
        if cache.len() >= CACHE_CAPACITY && !cache.contains_key(&key) {
            // Amortized: sweep expired entries, and if the cache is still
            // full drop an arbitrary eighth of it, so the next several
            // hundred inserts pay nothing.
            cache.retain(|_, entry| entry.expires > now);
            if cache.len() >= CACHE_CAPACITY {
                let excess = cache.len() + 1 - CACHE_CAPACITY * 7 / 8;
                let victims: Vec<QueryKey> = cache.keys().take(excess).cloned().collect();
                for victim in victims {
                    cache.remove(&victim);
                }
            }
        }
        cache.insert(
            key,
            CachedAnswer {
                ips: addresses.into_boxed_slice(),
                expires: now + ttl,
            },
        );
    }

    fn host_answer(&self, name: &str, depth: usize) -> Result<Option<Vec<IpAddr>>, ResolveError> {
        if depth > 8 {
            return Err(ResolveError::Protocol("hosts alias cycle".into()));
        }
        let Some(value) = self.settings.hosts.get(name) else {
            return Ok(None);
        };
        match value {
            HostValue::Addresses(addresses) => {
                Ok(Some(addresses.iter().filter_map(Address::as_ip).collect()))
            }
            HostValue::Block => Err(ResolveError::Blocked),
            HostValue::Alias(alias) => self.host_answer(&normalize_name(alias)?, depth + 1),
        }
    }

    async fn query_uncached(
        &self,
        name: &Arc<str>,
        kind: QueryType,
    ) -> Result<PacketAnswer, QueryFailure> {
        let servers = self.candidates(name);
        if servers.is_empty() {
            if self.settings.leak_policy == LeakPolicy::Fallback {
                let answer = self.system_lookup(name, kind).await?;
                if answer.addresses.is_empty() {
                    return Err(QueryFailure {
                        error: ResolveError::NoData(name.to_string()),
                        negative_ttl: Some(answer.ttl),
                    });
                }
                return Ok(answer);
            }
            return Err(ResolveError::NoResolvers.into());
        }

        let mut last_error = None;
        // A negative answer is cacheable only when every server that was
        // asked said, authoritatively, that there is nothing: a transport
        // error or an answer discarded by `expectIPs` is not evidence that
        // the name has no data.
        let mut negative_ttl: Option<Duration> = None;
        let mut all_negative = true;
        let mut index = 0;
        while index < servers.len() {
            let end = peer_group_end(&servers, index);
            let group = &servers[index..end];
            index = end;
            let (result, stop) = if group.len() > 1 {
                self.race_group(group, name, kind).await
            } else {
                let server = group[0];
                let started = Instant::now();
                let result = self.ask(server, name, kind).await;
                self.note_rtt(&server.endpoint, started, result.is_ok());
                (
                    result.map(|answer| screen(server, kind, answer)),
                    server.skip_fallback,
                )
            };
            match result {
                Ok(Screened::Usable(answer)) => return Ok(answer),
                Ok(Screened::Empty { authoritative, ttl }) => {
                    if authoritative {
                        negative_ttl = Some(negative_ttl.map_or(ttl, |previous| previous.min(ttl)));
                    } else {
                        all_negative = false;
                    }
                    last_error = Some(ResolveError::NoData(name.to_string()));
                }
                Err(e) => {
                    all_negative = false;
                    last_error = Some(e);
                }
            }
            if stop {
                break;
            }
        }
        Err(QueryFailure {
            error: last_error.unwrap_or_else(|| ResolveError::NoData(name.to_string())),
            negative_ttl: negative_ttl.filter(|_| all_negative),
        })
    }

    /// Ask one server, without judging the answer.
    async fn ask(
        &self,
        server: &DnsServer,
        name: &str,
        kind: QueryType,
    ) -> Result<PacketAnswer, ResolveError> {
        match &server.endpoint {
            ResolverEndpoint::System if self.settings.leak_policy == LeakPolicy::Strict => Err(
                ResolveError::Unsupported("system DNS is disabled by strict leak policy".into()),
            ),
            ResolverEndpoint::System => self.system_lookup(name, kind).await,
            ResolverEndpoint::FakeDns => self.fake_lookup(name, kind).await,
            endpoint => self.query_endpoint(endpoint, name, kind).await,
        }
    }

    /// Ask interchangeable resolvers, fastest first, with hedging: the next
    /// one is asked only if the current best has not answered within about
    /// twice its usual time, or failed. A healthy tier costs one query per
    /// lookup; a resolver that became slow or blocked costs one hedge delay
    /// instead of the whole timeout, and drops down the ranking.
    ///
    /// The second value is always `false`: members of a group never set
    /// `skip_fallback`.
    async fn race_group(
        &self,
        group: &[&DnsServer],
        name: &Arc<str>,
        kind: QueryType,
    ) -> (Result<Screened, ResolveError>, bool) {
        let order = {
            let rtt = lock(&self.pools.rtt);
            rank(
                group
                    .iter()
                    .map(|server| rtt.get(&server.endpoint).copied()),
            )
        };
        let mut tasks = tokio::task::JoinSet::new();
        let mut next = 0;
        let mut last_error = None;
        let mut negative: Option<Duration> = None;
        let launch = |tasks: &mut tokio::task::JoinSet<_>, position: usize| {
            let server = group[order[position]].clone();
            let resolver = self.clone();
            let name = Arc::clone(name);
            tasks.spawn(async move {
                // Records the time even when this query loses the race and
                // is aborted: that time is a lower bound on its latency, and
                // without it a resolver that never answers would stay
                // "unmeasured" and keep its place at the front.
                let mut timing = Timing {
                    resolver: &resolver,
                    endpoint: &server.endpoint,
                    started: Instant::now(),
                    ok: None,
                };
                let result = timing.resolver.ask(&server, &name, kind).await;
                timing.ok = Some(result.is_ok());
                drop(timing);
                result.map(|answer| screen(&server, kind, answer))
            });
        };
        launch(&mut tasks, next);
        next += 1;
        if self
            .pools
            .explored
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(EXPLORE_EVERY)
        {
            launch(&mut tasks, next);
            next += 1;
        }
        loop {
            let hedge = {
                let rtt = lock(&self.pools.rtt);
                order
                    .get(next)
                    .map(|_| hedge_delay(rtt.get(&group[order[next - 1]].endpoint).copied()))
            };
            let joined = match hedge {
                Some(delay) => match timeout(delay, tasks.join_next()).await {
                    Ok(joined) => joined,
                    Err(_) => {
                        launch(&mut tasks, next);
                        next += 1;
                        continue;
                    }
                },
                None => tasks.join_next().await,
            };
            let Some(joined) = joined else { break };
            match joined {
                Ok(Ok(Screened::Usable(answer))) => {
                    // Dropping the set aborts the slower queries.
                    return (Ok(Screened::Usable(answer)), false);
                }
                // The resolvers are equivalent, so one authoritative "no
                // such name" is the group's answer; asking the rest would
                // only spend the user's data.
                Ok(Ok(Screened::Empty {
                    authoritative: true,
                    ttl,
                })) => negative = Some(ttl),
                Ok(Ok(Screened::Empty { .. })) => {
                    last_error = Some(ResolveError::NoData(name.to_string()))
                }
                Ok(Err(e)) => last_error = Some(e),
                Err(e) => last_error = Some(ResolveError::Transport(e.to_string())),
            }
            if let Some(ttl) = negative {
                return (
                    Ok(Screened::Empty {
                        authoritative: true,
                        ttl,
                    }),
                    false,
                );
            }
            if next < order.len() {
                launch(&mut tasks, next);
                next += 1;
            }
        }
        (
            Err(last_error.unwrap_or_else(|| ResolveError::NoData(name.to_string()))),
            false,
        )
    }

    fn note_rtt(&self, endpoint: &ResolverEndpoint, started: Instant, ok: bool) {
        self.note_rtt_sample(endpoint, started, Some(ok));
    }

    /// `None`: the query was abandoned; its elapsed time counts as a sample.
    fn note_rtt_sample(&self, endpoint: &ResolverEndpoint, started: Instant, ok: Option<bool>) {
        if matches!(
            endpoint,
            ResolverEndpoint::System | ResolverEndpoint::FakeDns
        ) {
            return;
        }
        let elapsed = started.elapsed();
        let mut rtt = lock(&self.pools.rtt);
        if rtt.len() >= 64 && !rtt.contains_key(endpoint) {
            rtt.clear();
        }
        let entry = rtt.entry(endpoint.clone()).or_default();
        match ok {
            Some(true) => entry.observe(elapsed),
            Some(false) => entry.fail(),
            None => entry.observe_at_least(elapsed),
        }
    }

    fn candidates<'a>(&'a self, name: &str) -> Vec<&'a DnsServer> {
        self.tiers
            .iter()
            .filter(|index| {
                let server = &self.settings.servers[**index];
                server.domains.is_empty()
                    || server
                        .domains
                        .iter()
                        .enumerate()
                        .any(|(position, pattern)| {
                            // A `regexp:` pattern that compiled when this resolver was
                            // built is matched against that automaton. It is the same
                            // one `domain_matches` would compile from the same string,
                            // so it answers identically -- it is simply already built.
                            // Everything else, including a `regexp:` that does not
                            // compile, goes to `domain_matches` unchanged.
                            match self.regexes[**index][position].as_ref() {
                                Some(regex) => regex.is_match(name),
                                None => domain_matches(pattern, name),
                            }
                        })
            })
            .map(|index| &self.settings.servers[*index])
            .collect()
    }

    async fn system_lookup(
        &self,
        name: &str,
        kind: QueryType,
    ) -> Result<PacketAnswer, ResolveError> {
        let result = timeout(DNS_TIMEOUT, tokio::net::lookup_host((name, 0)))
            .await
            .map_err(|_| ResolveError::Transport("system DNS timed out".into()))?
            .map_err(|e| ResolveError::Transport(e.to_string()))?;
        let mut ips: Vec<_> = result
            .map(|addr| addr.ip())
            .filter(|ip| kind.accepts(*ip))
            .collect();
        ips.sort();
        ips.dedup();
        // The name exists (the platform answered) but has no address of
        // this family: a negative answer, reported as such so it can be
        // cached briefly.
        let ttl = if ips.is_empty() {
            NEGATIVE_TTL_DEFAULT
        } else {
            Duration::from_secs(30)
        };
        Ok(PacketAnswer {
            addresses: ips,
            records: Vec::new(),
            ttl,
            truncated: false,
        })
    }

    async fn fake_lookup(&self, name: &str, kind: QueryType) -> Result<PacketAnswer, ResolveError> {
        let mut fake = self.fake.lock().await;
        let key = (name.into(), kind);
        let ip = if let Some(ip) = fake.by_name.get(&key).copied() {
            ip
        } else {
            if kind == QueryType::Https {
                return Err(ResolveError::Unsupported(
                    "FakeDNS does not synthesize HTTPS records".into(),
                ));
            }
            // The pool is recycled oldest-first once it wraps, as Xray's
            // FakeDNS does, instead of refusing every new name for the rest
            // of the process's life after ~131k distinct names.
            let counter = self.fake_next.fetch_add(1, Ordering::Relaxed);
            let slot = (counter.wrapping_sub(1) % FAKE_POOL_SIZE) + 1;
            let ip = match kind {
                QueryType::A => IpAddr::V4(Ipv4Addr::from(FAKE_V4_BASE | slot)),
                _ => {
                    // All 17 bits of the slot, not a truncated u16: a
                    // truncation aliased slot N and N+65536 onto one address,
                    // so the reverse map sent one name's traffic to another.
                    let mut octets = [0u8; 16];
                    octets[0] = 0xfd;
                    octets[12..].copy_from_slice(&slot.to_be_bytes());
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
            };
            if let Some(previous) = fake.by_ip.remove(&ip) {
                fake.by_name.remove(&(previous, kind));
            }
            fake.by_name.insert(key, ip);
            fake.by_ip.insert(ip, name.into());
            ip
        };
        if kind.accepts(ip) {
            Ok(PacketAnswer {
                addresses: vec![ip],
                records: Vec::new(),
                ttl: Duration::from_secs(300),
                truncated: false,
            })
        } else {
            Err(ResolveError::NoData(name.to_string()))
        }
    }

    /// The parsed form of a configured DoH URL.
    ///
    /// [`Resolver::doh_urls`] holds every DoH URL of the configuration, so this is
    /// a hash lookup rather than a parse. The `Err` arm is the
    /// [`ResolveError::Protocol`] a per-query `Url::parse` would have built,
    /// carrying the message the parse produced.
    fn doh_url(&self, url: &Arc<str>) -> Result<&Url, ResolveError> {
        match self.doh_urls.get(url) {
            Some(Ok(parsed)) => Ok(parsed),
            Some(Err(message)) => Err(ResolveError::Protocol(message.clone())),
            // Unreachable for a URL from `settings`: the map is built from exactly
            // those. Treated as unparseable rather than panicking, which is what
            // the per-query parse did with it.
            None => Err(ResolveError::Protocol(format!("invalid DoH url: {url}"))),
        }
    }

    async fn query_endpoint(
        &self,
        endpoint: &ResolverEndpoint,
        name: &str,
        kind: QueryType,
    ) -> Result<PacketAnswer, ResolveError> {
        match endpoint {
            ResolverEndpoint::Udp { address, port } => {
                let addrs = self.endpoint_addrs(address, *port).await?;
                let (packet, truncated) = self.query_udp(&addrs, name, kind).await?;
                if truncated {
                    self.query_tcp(&addrs, name, kind).await
                } else {
                    Ok(packet)
                }
            }
            ResolverEndpoint::Tcp { address, port } => {
                let addrs = self.endpoint_addrs(address, *port).await?;
                self.query_tcp(&addrs, name, kind).await
            }
            ResolverEndpoint::Dot { address, port } => {
                let addrs = self.endpoint_addrs(address, *port).await?;
                self.query_dot(&addrs, &address.host_string(), name, kind)
                    .await
            }
            ResolverEndpoint::Doh { url, host, port } => {
                let parsed = self.doh_url(url)?;
                let address = Address::parse_host(host);
                let addrs = self.endpoint_addrs(&address, *port).await?;
                self.query_https(&addrs, host, parsed, name, kind, false)
                    .await
            }
            ResolverEndpoint::Doh2 { url, host, port } => {
                let parsed = self.doh_url(url)?;
                let address = Address::parse_host(host);
                let addrs = self.endpoint_addrs(&address, *port).await?;
                self.query_https(&addrs, host, parsed, name, kind, true)
                    .await
            }
            ResolverEndpoint::Doh3 { url, host, port } => {
                let parsed = self.doh_url(url)?;
                let address = Address::parse_host(host);
                let addrs = self.endpoint_addrs(&address, *port).await?;
                self.query_doh3(&addrs, host, parsed, name, kind).await
            }
            ResolverEndpoint::Doq { address, port } => {
                let addrs = self.endpoint_addrs(address, *port).await?;
                self.query_doq(&addrs, &address.host_string(), name, kind)
                    .await
            }
            ResolverEndpoint::System | ResolverEndpoint::FakeDns => Err(ResolveError::Unsupported(
                "internal resolver endpoint".into(),
            )),
        }
    }

    async fn endpoint_addrs(
        &self,
        address: &Address,
        port: u16,
    ) -> Result<Vec<SocketAddr>, ResolveError> {
        match address {
            Address::Ip(ip) => Ok(vec![SocketAddr::new(*ip, port)]),
            Address::Domain(host) => {
                // A pinned hosts entry is the explicit bootstrap mechanism
                // for encrypted resolvers. It must be consulted before the
                // strict leak-policy rejection; otherwise configuring
                // `hosts: {dns.example: 203.0.113.7}` would still fall back
                // to the system resolver or fail needlessly.
                if let Some(ips) = self.host_answer(host, 0)? {
                    let addresses: Vec<_> = ips
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect();
                    if !addresses.is_empty() {
                        return Ok(addresses);
                    }
                }
                if self.settings.leak_policy == LeakPolicy::Strict {
                    return Err(ResolveError::BootstrapRequired(host.to_string()));
                }
                timeout(DNS_TIMEOUT, tokio::net::lookup_host((host.as_ref(), port)))
                    .await
                    .map_err(|_| ResolveError::Transport("resolver bootstrap timed out".into()))?
                    .map(|iter| iter.collect())
                    .map_err(|e| ResolveError::Transport(e.to_string()))
            }
        }
    }

    async fn query_udp(
        &self,
        addrs: &[SocketAddr],
        name: &str,
        kind: QueryType,
    ) -> Result<(PacketAnswer, bool), ResolveError> {
        let target = *addrs
            .first()
            .ok_or_else(|| ResolveError::Transport("no resolver address".into()))?;
        let bind: std::net::SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().expect("a literal bind address")
        } else {
            "[::]:0".parse().expect("a literal bind address")
        };
        let std_socket = zero_core::platform::bind_protected_udp(bind).map_err(io_error)?;
        std_socket.set_nonblocking(true).map_err(io_error)?;
        let socket = UdpSocket::from_std(std_socket).map_err(io_error)?;
        // Connected, so the kernel discards datagrams from any other source.
        socket.connect(target).await.map_err(io_error)?;
        let id = self.next_id();
        let query = build_query(id, name, kind)?;
        let deadline = tokio::time::Instant::now() + DNS_TIMEOUT;
        let mut buf = vec![0u8; UDP_RECV_BUFFER];
        loop {
            tokio::time::timeout_at(deadline, socket.send(&query))
                .await
                .map_err(|_| ResolveError::Transport("UDP DNS send timed out".into()))?
                .map_err(io_error)?;
            // Retransmit on silence rather than spending the whole budget
            // waiting on one datagram that may have been lost.
            let resend_at = (tokio::time::Instant::now() + UDP_RETRANSMIT).min(deadline);
            loop {
                let received = match tokio::time::timeout_at(resend_at, socket.recv(&mut buf)).await
                {
                    Err(_) => break,
                    Ok(received) => received.map_err(io_error)?,
                };
                let response = &buf[..received];
                // A datagram that does not answer *this* question (wrong ID,
                // wrong name, a late answer to an earlier query, or an
                // off-path forgery) is ignored, not treated as the answer.
                if !answers_query(response, &query) {
                    continue;
                }
                let packet = parse_response(response, id, kind)?;
                let truncated = packet.truncated;
                return Ok((packet, truncated));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ResolveError::Transport("UDP DNS receive timed out".into()));
            }
        }
    }

    async fn query_tcp(
        &self,
        addrs: &[SocketAddr],
        name: &str,
        kind: QueryType,
    ) -> Result<PacketAnswer, ResolveError> {
        let target = *addrs
            .first()
            .ok_or_else(|| ResolveError::Transport("no resolver address".into()))?;
        let mut stream = timeout(DNS_TIMEOUT, zero_core::platform::connect_protected(target))
            .await
            .map_err(|_| ResolveError::Transport("TCP DNS connect timed out".into()))?
            .map_err(io_error)?;
        let _ = stream.set_nodelay(true);
        let id = self.next_id();
        let query = build_query(id, name, kind)?;
        let response = timeout(DNS_TIMEOUT, exchange_framed(&mut stream, &frame(&query)))
            .await
            .map_err(|_| ResolveError::Transport("TCP DNS response timed out".into()))??;
        parse_answer(&response, &query, kind)
    }

    async fn query_dot(
        &self,
        addrs: &[SocketAddr],
        server_name: &str,
        name: &str,
        kind: QueryType,
    ) -> Result<PacketAnswer, ResolveError> {
        let target = *addrs
            .first()
            .ok_or_else(|| ResolveError::Transport("no resolver address".into()))?;
        let key = PoolKey::new(target, server_name);
        let id = self.next_id();
        let query = build_query(id, name, kind)?;
        let framed = frame(&query);

        // A warm connection turns the lookup into one round trip. If the
        // server closed it while idle, the exchange fails fast (EOF) and a
        // fresh connection is opened; DNS queries are idempotent.
        if let Some(mut stream) = self.pools.checkout_dot(&key) {
            if let Ok(Ok(response)) =
                timeout(REUSED_TIMEOUT, exchange_framed(&mut stream, &framed)).await
            {
                let parsed = parse_answer(&response, &query, kind);
                if parsed.is_ok() {
                    self.pools.checkin_dot(key, stream);
                }
                return parsed;
            }
        }

        let tcp = timeout(DNS_TIMEOUT, zero_core::platform::connect_protected(target))
            .await
            .map_err(|_| ResolveError::Transport("DoT connect timed out".into()))?
            .map_err(io_error)?;
        let _ = tcp.set_nodelay(true);
        let tls_name = rustls_pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| ResolveError::Protocol(format!("invalid DoT server name: {e}")))?;
        let connector = TlsConnector::from(Arc::clone(&self.tls.plain));
        let mut stream = timeout(DNS_TIMEOUT, connector.connect(tls_name, tcp))
            .await
            .map_err(|_| ResolveError::Transport("DoT handshake timed out".into()))?
            .map_err(|e| ResolveError::Transport(e.to_string()))?;
        let response = timeout(DNS_TIMEOUT, exchange_framed(&mut stream, &framed))
            .await
            .map_err(|_| ResolveError::Transport("DoT response timed out".into()))??;
        let parsed = parse_answer(&response, &query, kind);
        if parsed.is_ok() {
            self.pools.checkin_dot(key, stream);
        }
        parsed
    }

    /// DNS over HTTPS. `h2_only` is the `h2://` endpoint form; the plain
    /// `https://` form offers h2 and HTTP/1.1 and uses whichever the server
    /// picks. HTTP/2 connections are pooled and multiplexed.
    async fn query_https(
        &self,
        addrs: &[SocketAddr],
        server_name: &str,
        url: &Url,
        name: &str,
        kind: QueryType,
        h2_only: bool,
    ) -> Result<PacketAnswer, ResolveError> {
        let target = *addrs
            .first()
            .ok_or_else(|| ResolveError::Transport("no resolver address".into()))?;
        let key = PoolKey::new(target, server_name);
        let id = self.next_id();
        let query = build_query(id, name, kind)?;
        let path = request_path(url);
        let authority = match url.port() {
            Some(port) => format!("{server_name}:{port}"),
            None => server_name.to_string(),
        };
        let label = if h2_only { "DoH2" } else { "DoH" };

        if let Some((generation, sender)) = self.pools.checkout_h2(&key) {
            match timeout(
                REUSED_TIMEOUT,
                h2_exchange(sender, &path, &authority, &query, label),
            )
            .await
            {
                Ok(Ok(body)) => return parse_answer(&body, &query, kind),
                Ok(Err(H2Failure::Answer(error))) => return Err(error),
                // A dead or stalled pooled connection: forget it and retry
                // on a fresh one below.
                Ok(Err(H2Failure::Connection(_))) | Err(_) => self.pools.evict_h2(&key, generation),
            }
        }

        let tcp = timeout(DNS_TIMEOUT, zero_core::platform::connect_protected(target))
            .await
            .map_err(|_| ResolveError::Transport(format!("{label} connect timed out")))?
            .map_err(io_error)?;
        let _ = tcp.set_nodelay(true);
        let tls_name = rustls_pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| ResolveError::Protocol(format!("invalid {label} server name: {e}")))?;
        let config = if h2_only { &self.tls.h2 } else { &self.tls.doh };
        let connector = TlsConnector::from(Arc::clone(config));
        let stream = timeout(DNS_TIMEOUT, connector.connect(tls_name, tcp))
            .await
            .map_err(|_| ResolveError::Transport(format!("{label} handshake timed out")))?
            .map_err(|e| ResolveError::Transport(e.to_string()))?;
        let negotiated_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
        if !h2_only && !negotiated_h2 {
            return self
                .query_http1(stream, &path, &authority, &query, kind)
                .await;
        }

        let (sender, connection) = timeout(DNS_TIMEOUT, h2::client::handshake(stream))
            .await
            .map_err(|_| ResolveError::Transport(format!("{label} HTTP/2 handshake timed out")))?
            .map_err(|e| ResolveError::Transport(format!("{label} HTTP/2 handshake: {e}")))?;
        let (close, closed) = oneshot::channel::<()>();
        tokio::spawn(async move {
            // Runs until the server closes the connection or the pool entry
            // (and with it `close`) is dropped.
            tokio::select! {
                _ = connection => {}
                _ = closed => {}
            }
        });
        lock(&self.pools.h2).insert(
            key,
            H2Entry {
                generation: self.pools.next_generation(),
                sender: sender.clone(),
                last_used: Instant::now(),
                _close: close,
            },
        );
        let body = timeout(
            DNS_TIMEOUT,
            h2_exchange(sender, &path, &authority, &query, label),
        )
        .await
        .map_err(|_| ResolveError::Transport(format!("{label} response timed out")))?
        .map_err(H2Failure::into_error)?;
        parse_answer(&body, &query, kind)
    }

    /// One-shot DNS over HTTPS/1.1 for servers that do not speak HTTP/2.
    async fn query_http1(
        &self,
        mut stream: TlsStream<TcpStream>,
        path: &str,
        authority: &str,
        query: &[u8],
        kind: QueryType,
    ) -> Result<PacketAnswer, ResolveError> {
        // Head and body in one write: two small writes cost an extra
        // segment, and with Nagle an extra round trip.
        let mut request = format!(
            "POST {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            query.len()
        )
        .into_bytes();
        request.extend_from_slice(query);
        timeout(DNS_TIMEOUT, async {
            stream.write_all(&request).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| ResolveError::Transport("DoH request timed out".into()))?
        .map_err(io_error)?;
        // Bounded: a hostile or broken server must not be able to stream an
        // unlimited body into memory.
        let mut response = Vec::new();
        timeout(
            DNS_TIMEOUT,
            (&mut stream)
                .take((MAX_PACKET + HTTP_HEAD_LIMIT) as u64)
                .read_to_end(&mut response),
        )
        .await
        .map_err(|_| ResolveError::Transport("DoH response timed out".into()))?
        .map_err(io_error)?;
        let body = parse_http_response(&response)?;
        parse_answer(&body, query, kind)
    }

    async fn query_doh3(
        &self,
        addrs: &[SocketAddr],
        server_name: &str,
        url: &Url,
        name: &str,
        kind: QueryType,
    ) -> Result<PacketAnswer, ResolveError> {
        if addrs.is_empty() {
            return Err(ResolveError::Transport("no DoH3 resolver address".into()));
        }
        let mut tls = (*self.tls.h3).clone();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = h3_quinn::quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|error| ResolveError::Transport(format!("DoH3 TLS configuration: {error}")))?;
        let client_config = h3_quinn::quinn::ClientConfig::new(Arc::new(crypto));
        let bind = if addrs[0].is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let mut endpoint = protected_client_endpoint(bind)
            .map_err(|error| ResolveError::Transport(format!("DoH3 endpoint: {error}")))?;
        endpoint.set_default_client_config(client_config);
        let mut connection = None;
        let mut last_error = None;
        for address in addrs {
            match endpoint.connect(*address, server_name) {
                Ok(connecting) => match timeout(DNS_TIMEOUT, connecting).await {
                    Ok(Ok(value)) => {
                        connection = Some(value);
                        break;
                    }
                    Ok(Err(error)) => last_error = Some(error.to_string()),
                    Err(_) => last_error = Some("DoH3 connect timed out".into()),
                },
                Err(error) => last_error = Some(error.to_string()),
            }
        }
        let connection = connection.ok_or_else(|| {
            ResolveError::Transport(format!(
                "DoH3 connect failed: {}",
                last_error.unwrap_or_else(|| "no candidate succeeded".into())
            ))
        })?;
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .map_err(|error| ResolveError::Transport(format!("DoH3 setup: {error}")))?;
        let driver_task = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        let id = self.next_id();
        let query = build_query(id, name, kind)?;
        let mut path = url.path().to_string();
        if path.is_empty() {
            path.push('/');
        }
        if let Some(query_string) = url.query() {
            path.push('?');
            path.push_str(query_string);
        }
        let request = Request::builder()
            .method("POST")
            .uri(format!("https://{server_name}{path}"))
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(())
            .map_err(|error| ResolveError::Protocol(format!("DoH3 request: {error}")))?;
        let mut stream = sender
            .send_request(request)
            .await
            .map_err(|error| ResolveError::Transport(format!("DoH3 request: {error}")))?;
        stream
            .send_data(Bytes::copy_from_slice(&query))
            .await
            .map_err(|error| ResolveError::Transport(format!("DoH3 request body: {error}")))?;
        stream
            .finish()
            .await
            .map_err(|error| ResolveError::Transport(format!("DoH3 request finish: {error}")))?;
        let response = timeout(DNS_TIMEOUT, stream.recv_response())
            .await
            .map_err(|_| ResolveError::Transport("DoH3 response timed out".into()))?
            .map_err(|error| ResolveError::Transport(format!("DoH3 response: {error}")))?;
        if response.status() != http::StatusCode::OK {
            return Err(ResolveError::Transport(format!(
                "DoH3 HTTP status {}",
                response.status()
            )));
        }
        let mut data = Vec::new();
        while let Some(mut chunk) = timeout(DNS_TIMEOUT, stream.recv_data())
            .await
            .map_err(|_| ResolveError::Transport("DoH3 body timed out".into()))?
            .map_err(|error| ResolveError::Transport(format!("DoH3 body: {error}")))?
        {
            while chunk.has_remaining() {
                let piece = chunk.chunk();
                data.extend_from_slice(piece);
                chunk.advance(piece.len());
            }
            if data.len() > MAX_PACKET {
                return Err(ResolveError::Protocol("DoH3 response is too large".into()));
            }
        }
        let parsed = parse_answer(&data, &query, kind);
        // A DoH3 resolver is intentionally one query per QUIC connection in
        // this bounded resolver path. The H3 driver has no useful idle event
        // for a server that keeps the connection alive, so stop it after the
        // response stream closes instead of waiting forever for connection
        // shutdown.
        driver_task.abort();
        let _ = driver_task.await;
        drop(endpoint);
        parsed
    }

    async fn query_doq(
        &self,
        addrs: &[SocketAddr],
        server_name: &str,
        name: &str,
        kind: QueryType,
    ) -> Result<PacketAnswer, ResolveError> {
        if addrs.is_empty() {
            return Err(ResolveError::Transport("no DoQ resolver address".into()));
        }
        let key = PoolKey::new(addrs[0], server_name);
        // RFC 9250 §4.2.1: the message ID must be zero on DoQ.
        let query = build_query(0, name, kind)?;
        let framed = frame(&query);

        if let Some((generation, connection)) = self.pools.checkout_doq(&key) {
            match timeout(REUSED_TIMEOUT, doq_exchange(&connection, &framed)).await {
                Ok(Ok(response)) => return parse_answer(&response, &query, kind),
                _ => self.pools.evict_doq(&key, generation),
            }
        }

        let mut tls = (*self.tls.doq).clone();
        tls.alpn_protocols = vec![b"doq".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|error| ResolveError::Transport(format!("DoQ TLS configuration: {error}")))?;
        let mut endpoint = protected_client_endpoint(if addrs[0].is_ipv6() {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        })
        .map_err(|error| ResolveError::Transport(format!("DoQ endpoint: {error}")))?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let mut last_error = None;
        let mut connection = None;
        for address in addrs {
            match endpoint.connect(*address, server_name) {
                Ok(connecting) => match timeout(DNS_TIMEOUT, connecting).await {
                    Ok(Ok(value)) => {
                        connection = Some(value);
                        break;
                    }
                    Ok(Err(error)) => last_error = Some(error.to_string()),
                    Err(_) => last_error = Some("DoQ connect timed out".into()),
                },
                Err(error) => last_error = Some(error.to_string()),
            }
        }
        let connection = connection.ok_or_else(|| {
            ResolveError::Transport(format!(
                "DoQ connect failed: {}",
                last_error.unwrap_or_else(|| "no candidate succeeded".into())
            ))
        })?;
        lock(&self.pools.doq).insert(
            key,
            QuicEntry {
                generation: self.pools.next_generation(),
                connection: connection.clone(),
                last_used: Instant::now(),
                _endpoint: endpoint,
            },
        );
        let response = timeout(DNS_TIMEOUT, doq_exchange(&connection, &framed))
            .await
            .map_err(|_| ResolveError::Transport("DoQ response timed out".into()))?
            .map_err(ResolveError::Transport)?;
        parse_answer(&response, &query, kind)
    }

    fn next_id(&self) -> u16 {
        // Unpredictable per query: a sequential ID lets an off-path attacker
        // who sees one query guess the next.
        rand::random()
    }
}

/// The public roots, plus whatever extra anchors the configuration named.
///
/// An operator-supplied anchor is additive and never replaces the public set:
/// naming a private CA for an internal resolver must not stop the public ones
/// from being trusted, and must not be a back door to accepting anything.
fn trust_store(extra: &[Box<[u8]>]) -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for blob in extra {
        for certificate in parse_trust_anchor(blob) {
            if let Err(error) = store.add(certificate) {
                // Refusing the whole resolver over one unusable anchor would
                // take DNS down for a typo; the rest of the store is intact,
                // and a resolver that then fails to verify says so clearly.
                tracing::warn!(%error, "ignoring an unusable DNS trust anchor");
            }
        }
    }
    store
}

/// Decode one anchor. PEM may carry a chain; DER is a single certificate.
fn parse_trust_anchor(blob: &[u8]) -> Vec<rustls_pki_types::CertificateDer<'static>> {
    let text = std::str::from_utf8(blob).unwrap_or("");
    if text.contains("-----BEGIN CERTIFICATE-----") {
        let mut reader = std::io::BufReader::new(blob);
        return rustls_pki_types::pem::PemObject::pem_reader_iter(&mut reader)
            .filter_map(Result::ok)
            .collect();
    }
    vec![rustls_pki_types::CertificateDer::from(blob.to_vec())]
}

fn normalize_name(name: &str) -> Result<Arc<str>, ResolveError> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() {
        return Err(ResolveError::EmptyName);
    }
    // `to_ascii_lowercase` preserves length, so this bound is the same either
    // way round and can be checked before the copy is considered.
    if name.len() > MAX_NAME {
        return Err(ResolveError::NameTooLong);
    }
    // Names are nearly always already lowercase, and the result is an
    // `Arc<str>` that allocates regardless, so skip the `String` when we can.
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        Ok(Arc::from(name.to_ascii_lowercase()))
    } else {
        Ok(Arc::from(name))
    }
}

fn filter_strategy(mut ips: Vec<IpAddr>, strategy: QueryStrategy) -> Vec<IpAddr> {
    ips.retain(|ip| match strategy {
        QueryStrategy::UseIp => true,
        QueryStrategy::UseIpv4 => ip.is_ipv4(),
        QueryStrategy::UseIpv6 => ip.is_ipv6(),
    });
    ips
}

/// `value.trim().trim_end_matches('.').to_ascii_lowercase()`, borrowed when it
/// already is. Patterns are matched per pattern per candidate server on every
/// uncached query, so the `String` is worth avoiding.
fn normalize_pattern(value: &str) -> Cow<'_, str> {
    let value = value.trim().trim_end_matches('.');
    if value.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

fn domain_matches(pattern: &DomainPattern, name: &str) -> bool {
    match pattern {
        DomainPattern::Full(value) => normalize_pattern(value).as_ref() == name,
        DomainPattern::Suffix(value) => {
            let value = normalize_pattern(value);
            // `name` is `value` with one more label in front of it, so the part
            // before `value` has to end at a label boundary.
            value.as_ref() == name
                || name
                    .strip_suffix(value.as_ref())
                    .is_some_and(|head| head.ends_with('.'))
        }
        // `name` is already lowercase, so `normalize_pattern` borrows.
        DomainPattern::Keyword(value) => name.contains(normalize_pattern(value).as_ref()),
        DomainPattern::Regex(value) => Regex::new(value)
            .map(|regex| regex.is_match(name))
            .unwrap_or(false),
        DomainPattern::Geosite(_) => false,
    }
}

#[cfg(test)]
fn normalize_pattern_allocating(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The allocating form of [`domain_matches`], kept as the definition the
/// allocation-free one is checked against.
#[cfg(test)]
fn domain_matches_allocating(pattern: &DomainPattern, name: &str) -> bool {
    match pattern {
        DomainPattern::Full(value) => normalize_pattern_allocating(value) == name,
        DomainPattern::Suffix(value) => {
            let value = normalize_pattern_allocating(value);
            name == value || name.ends_with(&format!(".{value}"))
        }
        DomainPattern::Keyword(value) => name.contains(&value.to_ascii_lowercase()),
        DomainPattern::Regex(value) => Regex::new(value)
            .map(|regex| regex.is_match(name))
            .unwrap_or(false),
        DomainPattern::Geosite(_) => false,
    }
}

#[cfg(test)]
mod domain_pattern_tests {
    use super::{domain_matches, domain_matches_allocating, normalize_name, ResolveError};

    fn pattern(value: &str) -> zero_config::routing::DomainPattern {
        zero_config::routing::DomainPattern::parse(value)
    }

    /// The two forms must agree on every pattern kind, at every casing and
    /// trailing-dot shape, against names as `candidates` passes them.
    #[test]
    fn the_allocation_free_matcher_agrees_with_the_allocating_one() {
        let patterns = [
            "full:example.com",
            "full:Example.COM",
            "full:example.com.",
            "full:  example.com  ",
            "full:ex",
            "full:example.co",
            "full:example.comm",
            "domain:example.com",
            "domain:Example.COM",
            "domain:example.com.",
            "domain:com",
            "domain:ample.com",
            "domain:example.co",
            "keyword:tracker",
            "keyword:Tracker",
            "keyword:track",
            "regexp:^ads[0-9]+\\.",
            "regexp:[unclosed",
            "geosite:category-ads-all",
        ];
        let names = [
            "example.com",
            "a.example.com",
            "a.b.example.com",
            "notexample.com",
            "example.com.evil.net",
            "ex",
            "example.co",
            "example.comm",
            "com",
            "ample.com",
            "tracker.example",
            "ads12.example",
            "ad.example",
        ];
        for spec in patterns {
            let parsed = pattern(spec);
            for name in names {
                assert_eq!(
                    domain_matches(&parsed, name),
                    domain_matches_allocating(&parsed, name),
                    "{spec} against {name}"
                );
            }
        }
    }

    /// `normalize_name` skips the lowercase copy when it can, so the
    /// properties that copy provided are checked on their own.
    #[test]
    fn normalize_name_agrees_with_a_straight_lowercase() {
        for input in [
            "example.com",
            "EXAMPLE.com",
            "Example.Com",
            "example.com.",
            "  example.com  ",
            "ExAmPlE.CoM.",
            "a",
            "xn--bcher-kva.example",
        ] {
            let want = input.trim().trim_end_matches('.').to_ascii_lowercase();
            assert_eq!(
                normalize_name(input).map(|got| got.to_string()),
                Ok(want),
                "{input:?}"
            );
        }
        assert!(matches!(normalize_name(""), Err(ResolveError::EmptyName)));
        assert!(matches!(
            normalize_name("   "),
            Err(ResolveError::EmptyName)
        ));
        assert!(matches!(normalize_name("."), Err(ResolveError::EmptyName)));
        let long = "a".repeat(300);
        assert!(matches!(
            normalize_name(&long),
            Err(ResolveError::NameTooLong)
        ));
    }
}

/// Reports a raced query's time when it finishes or is aborted.
struct Timing<'a> {
    resolver: &'a Resolver,
    endpoint: &'a ResolverEndpoint,
    started: Instant,
    ok: Option<bool>,
}

impl Drop for Timing<'_> {
    fn drop(&mut self) {
        self.resolver
            .note_rtt_sample(self.endpoint, self.started, self.ok);
    }
}

/// An answer after the server's own acceptance rules were applied.
enum Screened {
    Usable(PacketAnswer),
    /// Nothing usable. `authoritative` when the server said the name has no
    /// such data, rather than returning addresses `expectIPs` rejected.
    Empty {
        authoritative: bool,
        ttl: Duration,
    },
}

fn screen(server: &DnsServer, kind: QueryType, mut answer: PacketAnswer) -> Screened {
    let authoritative = answer.addresses.is_empty() && answer.records.is_empty();
    let usable = if kind == QueryType::Https {
        answer.records.retain(|record| !record.is_empty());
        !answer.records.is_empty()
    } else {
        answer
            .addresses
            .retain(|ip| kind.accepts(*ip) && expected_ip_allowed(server, *ip));
        !answer.addresses.is_empty()
    };
    if usable {
        Screened::Usable(answer)
    } else {
        Screened::Empty {
            authoritative,
            ttl: answer.ttl,
        }
    }
}

/// Whether a server can stand in for another: an encrypted or plain network
/// resolver with no stop-here rule. The system resolver and FakeDNS are
/// never raced; they are not the same kind of answer.
fn interchangeable(server: &DnsServer) -> bool {
    !server.skip_fallback
        && !matches!(
            server.endpoint,
            ResolverEndpoint::System | ResolverEndpoint::FakeDns
        )
}

/// End of the run of interchangeable servers starting at `start`: the same
/// domains, answer filter and routing tag, so any of them may answer for all
/// and none is reached by a different path.
fn peer_group_end(servers: &[&DnsServer], start: usize) -> usize {
    let first = servers[start];
    if !interchangeable(first) {
        return start + 1;
    }
    let mut end = start + 1;
    while end < servers.len()
        && interchangeable(servers[end])
        && servers[end].domains == first.domains
        && servers[end].expect_ips == first.expect_ips
        // Same route out: racing a tunnelled resolver against a direct one
        // would send every hedged query to the local network.
        && servers[end].tag == first.tag
    {
        end += 1;
    }
    end
}

/// Smoothed response time of one resolver, in the style of TCP's SRTT:
/// an exponential average with weight 1/4, and a penalty per consecutive
/// failure so a blocked resolver sinks without being forgotten.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Rtt {
    /// Milliseconds; zero means never measured.
    smoothed_ms: u32,
    failures: u8,
}

/// Assumed for a resolver that has not answered yet: ordinary for DoH
/// through a tunnel from Iran, so an unmeasured resolver neither jumps the
/// queue nor is starved.
const UNMEASURED_MS: u32 = 400;
/// One in this many upstream lookups measures the runner-up too: about 3%
/// more DNS traffic, a few hundred bytes an hour for a typical phone.
const EXPLORE_EVERY: u32 = 32;
const HEDGE_MIN: Duration = Duration::from_millis(150);
const HEDGE_MAX: Duration = Duration::from_millis(1_200);

impl Rtt {
    fn observe(&mut self, elapsed: Duration) {
        let sample = u32::try_from(elapsed.as_millis())
            .unwrap_or(u32::MAX)
            .max(1);
        self.smoothed_ms = if self.smoothed_ms == 0 {
            sample
        } else {
            // 3/4 old + 1/4 new, in u64 so large values cannot overflow.
            ((u64::from(self.smoothed_ms) * 3 + u64::from(sample)) / 4) as u32
        };
        self.failures = 0;
    }

    /// An abandoned query: it took at least `elapsed`. Moves the average up
    /// but never down, and does not clear failures, since nothing answered.
    fn observe_at_least(&mut self, elapsed: Duration) {
        let failures = self.failures;
        let previous = self.smoothed_ms;
        if previous == 0 {
            // Losing a race says nothing good: never rank above the
            // assumption for an unmeasured resolver.
            let sample = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX);
            self.smoothed_ms = sample.max(UNMEASURED_MS);
            return;
        }
        self.observe(elapsed);
        self.smoothed_ms = self.smoothed_ms.max(previous);
        self.failures = failures;
    }

    fn fail(&mut self) {
        self.failures = self.failures.saturating_add(1);
    }

    /// Lower is better: the expected wait, times four per consecutive
    /// failure. One lost datagram is forgiven against a large latency gap;
    /// two are not.
    fn cost(self) -> u64 {
        let base = if self.smoothed_ms == 0 {
            UNMEASURED_MS
        } else {
            self.smoothed_ms
        };
        u64::from(base) << (2 * u32::from(self.failures.min(5)))
    }
}

/// Order a group's positions by cost, keeping the configured order on ties
/// so the user's or preset's first choice wins when nothing is known.
fn rank(stats: impl Iterator<Item = Option<Rtt>>) -> Vec<usize> {
    let costs: Vec<u64> = stats.map(|rtt| rtt.unwrap_or_default().cost()).collect();
    let mut order: Vec<usize> = (0..costs.len()).collect();
    order.sort_by_key(|&position| costs[position]);
    order
}

/// How long to wait on a resolver before also asking the next: twice its
/// smoothed time, bounded so a fast resolver's hiccup does not fire a
/// needless second query and a slow one does not stall the lookup.
fn hedge_delay(rtt: Option<Rtt>) -> Duration {
    let rtt = rtt.unwrap_or_default();
    if rtt.failures > 0 {
        return HEDGE_MIN;
    }
    let base = if rtt.smoothed_ms == 0 {
        UNMEASURED_MS
    } else {
        rtt.smoothed_ms
    };
    Duration::from_millis(u64::from(base) * 2).clamp(HEDGE_MIN, HEDGE_MAX)
}

fn expected_ip_allowed(server: &DnsServer, ip: IpAddr) -> bool {
    server.expect_ips.is_empty()
        || server.expect_ips.iter().any(|pattern| match pattern {
            IpPattern::Cidr(cidr) => cidr.contains(ip),
            IpPattern::Private => is_private(ip),
            IpPattern::Geoip(_) => false,
        })
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

fn io_error(error: std::io::Error) -> ResolveError {
    ResolveError::Transport(error.to_string())
}

fn build_query(id: u16, name: &str, kind: QueryType) -> Result<Vec<u8>, ResolveError> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ResolveError::Protocol("invalid DNS label".into()));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&kind.wire().to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Ok(out)
}

/// Prefix a DNS message with its two-byte length (RFC 7766 / RFC 9250).
fn frame(query: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    framed
}

/// One length-framed exchange on a stream transport, written as a single
/// buffer so the length prefix and the message leave in one segment.
async fn exchange_framed<S>(stream: &mut S, framed: &[u8]) -> Result<Vec<u8>, ResolveError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream.write_all(framed).await.map_err(io_error)?;
    stream.flush().await.map_err(io_error)?;
    let len = stream.read_u16().await.map_err(io_error)? as usize;
    if len == 0 {
        return Err(ResolveError::Protocol("invalid DNS TCP length 0".into()));
    }
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response).await.map_err(io_error)?;
    Ok(response)
}

async fn doq_exchange(connection: &quinn::Connection, framed: &[u8]) -> Result<Vec<u8>, String> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| format!("DoQ stream: {error}"))?;
    send.write_all(framed)
        .await
        .map_err(|error| format!("DoQ query: {error}"))?;
    send.finish()
        .map_err(|error| format!("DoQ query finish: {error}"))?;
    let len = recv
        .read_u16()
        .await
        .map_err(|error| format!("DoQ response length: {error}"))? as usize;
    if len == 0 {
        return Err("invalid DoQ response length 0".into());
    }
    let mut response = vec![0u8; len];
    recv.read_exact(&mut response)
        .await
        .map_err(|error| format!("DoQ response: {error}"))?;
    Ok(response)
}

fn request_path(url: &Url) -> String {
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query_string) = url.query() {
        path.push('?');
        path.push_str(query_string);
    }
    path
}

/// Why an HTTP/2 DoH exchange failed: the connection (retry elsewhere) or
/// the answer itself (a real result to report).
enum H2Failure {
    Connection(String),
    Answer(ResolveError),
}

impl H2Failure {
    fn into_error(self) -> ResolveError {
        match self {
            Self::Connection(message) => ResolveError::Transport(message),
            Self::Answer(error) => error,
        }
    }
}

async fn h2_exchange(
    sender: h2::client::SendRequest<Bytes>,
    path: &str,
    authority: &str,
    query: &[u8],
    label: &str,
) -> Result<Vec<u8>, H2Failure> {
    let connection =
        |what: &str, error: h2::Error| H2Failure::Connection(format!("{label} {what}: {error}"));
    let mut sender = sender
        .ready()
        .await
        .map_err(|e| connection("stream capacity", e))?;
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://{authority}{path}"))
        .header("accept", "application/dns-message")
        .header("content-type", "application/dns-message")
        .header("content-length", query.len())
        .body(())
        .map_err(|e| {
            H2Failure::Answer(ResolveError::Protocol(format!(
                "invalid {label} request: {e}"
            )))
        })?;
    let (response, mut send) = sender
        .send_request(request, false)
        .map_err(|e| connection("request", e))?;
    send.send_data(Bytes::copy_from_slice(query), true)
        .map_err(|e| connection("request body", e))?;
    let response = response.await.map_err(|e| connection("response", e))?;
    if response.status() != http::StatusCode::OK {
        return Err(H2Failure::Answer(ResolveError::Transport(format!(
            "{label} HTTP status {}",
            response.status()
        ))));
    }
    let mut body = response.into_body();
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| connection("body", e))?;
        let _ = body.flow_control().release_capacity(chunk.len());
        data.extend_from_slice(&chunk);
        if data.len() > MAX_PACKET {
            return Err(H2Failure::Answer(ResolveError::Protocol(format!(
                "{label} response is too large"
            ))));
        }
    }
    Ok(data)
}

/// Whether `response` answers `query`: same ID and, when the server echoed
/// it, the same question (name compared case-insensitively, type, class).
fn answers_query(response: &[u8], query: &[u8]) -> bool {
    if response.len() < 12 || query.len() < 12 || response[..2] != query[..2] {
        return false;
    }
    let questions = u16::from_be_bytes([response[4], response[5]]);
    if questions == 0 {
        return true;
    }
    let question = &query[12..];
    response
        .get(12..12 + question.len())
        .is_some_and(|echoed| echoed.eq_ignore_ascii_case(question))
}

/// Parse a response to a specific query, rejecting one that answers a
/// different question.
fn parse_answer(data: &[u8], query: &[u8], kind: QueryType) -> Result<PacketAnswer, ResolveError> {
    if query.len() < 12 {
        return Err(ResolveError::Protocol("DNS query is malformed".into()));
    }
    let id = u16::from_be_bytes([query[0], query[1]]);
    if data.len() >= 12 && data[..2] == query[..2] && !answers_query(data, query) {
        return Err(ResolveError::Protocol(
            "DNS response answers a different question".into(),
        ));
    }
    parse_response(data, id, kind)
}

fn parse_response(data: &[u8], id: u16, kind: QueryType) -> Result<PacketAnswer, ResolveError> {
    if data.len() < 12 {
        return Err(ResolveError::Protocol(
            "DNS response is shorter than its header".into(),
        ));
    }
    let response_id = u16::from_be_bytes([data[0], data[1]]);
    if response_id != id {
        return Err(ResolveError::Protocol("DNS response ID mismatch".into()));
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 {
        return Err(ResolveError::Protocol(
            "DNS response is not a response".into(),
        ));
    }
    let rcode = flags & 0x000f;
    if rcode != 0 && rcode != 3 {
        return Err(ResolveError::Protocol(format!(
            "DNS server returned rcode {rcode}"
        )));
    }
    let questions = u16::from_be_bytes([data[4], data[5]]) as usize;
    let answers = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(data, offset)?;
        if offset + 4 > data.len() {
            return Err(ResolveError::Protocol("truncated DNS question".into()));
        }
        offset += 4;
    }
    let mut addresses = Vec::new();
    let mut records = Vec::new();
    let mut ttl = Duration::MAX;
    for _ in 0..answers {
        offset = skip_name(data, offset)?;
        if offset + 10 > data.len() {
            return Err(ResolveError::Protocol("truncated DNS answer".into()));
        }
        let record_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let class = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let record_ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let length = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;
        if offset + length > data.len() {
            return Err(ResolveError::Protocol("truncated DNS rdata".into()));
        }
        if class == 1 && record_type == kind.wire() {
            if kind == QueryType::Https {
                records.push(data[offset..offset + length].to_vec());
                ttl = ttl.min(Duration::from_secs(record_ttl as u64));
                offset += length;
                continue;
            }
            let ip = match kind {
                QueryType::A if length == 4 => IpAddr::V4(Ipv4Addr::new(
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                )),
                QueryType::Aaaa if length == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&data[offset..offset + length]);
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                _ => {
                    offset += length;
                    continue;
                }
            };
            addresses.push(ip);
            ttl = ttl.min(Duration::from_secs(record_ttl as u64));
        }
        offset += length;
    }
    let has_data = !addresses.is_empty() || !records.is_empty();
    if rcode == 3 || !has_data {
        // NXDOMAIN or NODATA. Returned as an empty answer carrying the
        // negative-caching TTL (RFC 2308) so the resolver can cache it; a
        // truncated empty answer keeps its flag so UDP retries over TCP.
        let authority = u16::from_be_bytes([data[8], data[9]]) as usize;
        return Ok(PacketAnswer {
            addresses: Vec::new(),
            records: Vec::new(),
            ttl: negative_ttl(data, offset, authority),
            truncated: rcode != 3 && flags & 0x0200 != 0,
        });
    }
    if ttl == Duration::MAX {
        ttl = Duration::from_secs(30);
    }
    Ok(PacketAnswer {
        addresses,
        records,
        ttl,
        truncated: flags & 0x0200 != 0,
    })
}

/// The negative-caching TTL from the authority section's SOA record:
/// `min(SOA TTL, SOA.minimum)`, clamped. Best effort — a malformed authority
/// section only loses the precise TTL, never the answer.
fn negative_ttl(data: &[u8], mut offset: usize, authority: usize) -> Duration {
    let clamp = |seconds: u32| {
        Duration::from_secs(u64::from(seconds)).clamp(NEGATIVE_TTL_MIN, NEGATIVE_TTL_MAX)
    };
    for _ in 0..authority {
        let Ok(after_name) = skip_name(data, offset) else {
            break;
        };
        let Some(fixed) = data.get(after_name..after_name + 10) else {
            break;
        };
        let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let record_ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let length = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let rdata = after_name + 10;
        let Some(end) = rdata.checked_add(length).filter(|end| *end <= data.len()) else {
            break;
        };
        if record_type == 6 {
            // SOA RDATA: MNAME, RNAME, then five u32s, MINIMUM last.
            let minimum = skip_name(data, rdata)
                .and_then(|at| skip_name(data, at))
                .ok()
                .filter(|at| at + 20 <= end)
                .and_then(|at| data.get(at + 16..at + 20))
                .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
            if let Some(minimum) = minimum {
                return clamp(record_ttl.min(minimum));
            }
        }
        offset = end;
    }
    NEGATIVE_TTL_DEFAULT
}

fn skip_name(data: &[u8], mut offset: usize) -> Result<usize, ResolveError> {
    let start = offset;
    loop {
        if offset >= data.len() {
            return Err(ResolveError::Protocol("truncated DNS name".into()));
        }
        let length = data[offset];
        if length == 0 {
            return Ok(offset + 1);
        }
        if length & 0xc0 == 0xc0 {
            if offset + 1 >= data.len() {
                return Err(ResolveError::Protocol("truncated DNS name pointer".into()));
            }
            return Ok(offset + 2);
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(ResolveError::Protocol("invalid DNS label length".into()));
        }
        offset += 1 + length as usize;
        if offset > data.len() || offset - start > MAX_NAME + 2 {
            return Err(ResolveError::Protocol(
                "DNS name exceeds maximum length".into(),
            ));
        }
    }
}

fn parse_https_ech_config(rdata: &[u8]) -> Option<Vec<u8>> {
    // HTTPS RR: priority, target name, then SvcParamKey/SvcParamValue pairs.
    // ECH is SvcParamKey 5 and its value is already an ECHConfigList.
    if rdata.len() < 3 {
        return None;
    }
    let mut offset = 2;
    offset = skip_name(rdata, offset).ok()?;
    while offset + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
        let length = u16::from_be_bytes([rdata[offset + 2], rdata[offset + 3]]) as usize;
        offset += 4;
        let end = offset.checked_add(length)?;
        if end > rdata.len() {
            return None;
        }
        if key == 5 && length > 0 && length <= 64 * 1024 {
            return Some(rdata[offset..end].to_vec());
        }
        offset = end;
    }
    None
}

fn parse_http_response(data: &[u8]) -> Result<Vec<u8>, ResolveError> {
    let marker = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            ResolveError::Protocol("DoH response has no HTTP header terminator".into())
        })?;
    let body_start = marker + 4;
    let header = std::str::from_utf8(&data[..marker])
        .map_err(|_| ResolveError::Protocol("DoH response headers are not UTF-8".into()))?;
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| ResolveError::Protocol("invalid DoH status line".into()))?;
    if status != 200 {
        return Err(ResolveError::Transport(format!("DoH HTTP status {status}")));
    }
    if header.lines().any(|line| {
        line.split_once(':')
            .map(|(key, value)| {
                key.eq_ignore_ascii_case("transfer-encoding")
                    && value.trim().eq_ignore_ascii_case("chunked")
            })
            .unwrap_or(false)
    }) {
        return decode_chunked(&data[body_start..]);
    }
    if let Some(length) = header.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if !key.eq_ignore_ascii_case("content-length") {
            return None;
        }
        value.trim().parse::<usize>().ok()
    }) {
        if length > MAX_PACKET || body_start + length > data.len() {
            return Err(ResolveError::Protocol("invalid DoH content length".into()));
        }
        return Ok(data[body_start..body_start + length].to_vec());
    }
    Ok(data[body_start..].to_vec())
}

fn decode_chunked(data: &[u8]) -> Result<Vec<u8>, ResolveError> {
    let mut output = Vec::new();
    let mut offset = 0;
    loop {
        if offset >= data.len() {
            return Err(ResolveError::Protocol("invalid chunked DoH size".into()));
        }
        let line_end = data[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| ResolveError::Protocol("invalid chunked DoH size".into()))?
            + offset;
        let size = usize::from_str_radix(
            data[offset..line_end]
                .split(|byte| *byte == b';')
                .next()
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .ok_or_else(|| ResolveError::Protocol("invalid chunked DoH size".into()))?
                .trim(),
            16,
        )
        .map_err(|_| ResolveError::Protocol("invalid chunked DoH size".into()))?;
        offset = line_end + 2;
        if size == 0 {
            return Ok(output);
        }
        if size > MAX_PACKET || offset + size + 2 > data.len() {
            return Err(ResolveError::Protocol("invalid chunked DoH body".into()));
        }
        output.extend_from_slice(&data[offset..offset + size]);
        offset += size;
        if &data[offset..offset + 2] != b"\r\n" {
            return Err(ResolveError::Protocol(
                "invalid chunked DoH terminator".into(),
            ));
        }
        offset += 2;
        if output.len() > MAX_PACKET {
            return Err(ResolveError::Protocol("DoH body is too large".into()));
        }
    }
}

/// Build a QUIC client endpoint on a socket the host has already been allowed
/// to protect.
///
/// `Endpoint::client` binds its own socket, which leaves no moment at which a
/// mobile host could exempt it from the tunnel the process is serving — and an
/// unprotected resolver socket there does not degrade, it loops back into the
/// proxy (`zero_core::platform`). Encrypted DNS is the worst place for that:
/// the resolver is what everything else waits on.
fn protected_client_endpoint(bind: std::net::SocketAddr) -> std::io::Result<quinn::Endpoint> {
    let socket = zero_core::platform::bind_protected_udp(bind)?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        std::sync::Arc::new(quinn::TokioRuntime),
    )
}

/// Ask one plain-UDP resolver for `name`'s IPv4 addresses, bypassing every
/// configured policy, cache and fallback: what *this* server says, and how
/// long it took. For measuring resolvers against each other, not for
/// resolving. The socket is protected, so on a phone the probe reaches the
/// real network rather than the tunnel the process serves.
pub async fn probe_udp(
    server: SocketAddr,
    name: &str,
    wait: Duration,
) -> Result<(Vec<IpAddr>, Duration), ResolveError> {
    let (answer, elapsed) = probe_one(server, name, QueryType::A, wait).await?;
    Ok((answer.addresses, elapsed))
}

/// Ask one plain-UDP resolver for `name`'s ECH configuration (the `ech`
/// parameter of its HTTPS record), bypassing policy and cache. For fetching a
/// current ECHConfigList before any resolver is configured — WARP
/// registration runs before the tunnel does.
pub async fn probe_ech(
    server: SocketAddr,
    name: &str,
    wait: Duration,
) -> Result<Vec<u8>, ResolveError> {
    let (answer, _) = probe_one(server, name, QueryType::Https, wait).await?;
    answer
        .records
        .iter()
        .find_map(|record| parse_https_ech_config(record))
        .ok_or_else(|| ResolveError::NoData(format!("no ECH configuration for {name}")))
}

async fn probe_one(
    server: SocketAddr,
    name: &str,
    kind: QueryType,
    wait: Duration,
) -> Result<(PacketAnswer, Duration), ResolveError> {
    let id: u16 = rand::random();
    let query = build_query(id, &normalize_name(name)?, kind)?;
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let io = |error: std::io::Error| ResolveError::Transport(error.to_string());
    let socket = zero_core::platform::bind_protected_udp(bind).map_err(io)?;
    socket.set_nonblocking(true).map_err(io)?;
    let socket = UdpSocket::from_std(socket).map_err(io)?;
    let started = Instant::now();
    socket.send_to(&query, server).await.map_err(io)?;
    let mut buffer = [0u8; 1500];
    loop {
        let left = wait
            .checked_sub(started.elapsed())
            .ok_or_else(|| ResolveError::Transport(format!("{server} did not answer")))?;
        let (length, from) = timeout(left, socket.recv_from(&mut buffer))
            .await
            .map_err(|_| ResolveError::Transport(format!("{server} did not answer")))?
            .map_err(io)?;
        // Anything else on this socket is not the answer; nor is a reply
        // that does not parse as one (an on-path injector's forgery can).
        if from != server {
            continue;
        }
        if let Ok(answer) = parse_response(&buffer[..length], id, kind) {
            return Ok((answer, started.elapsed()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn probe_udp_reads_one_servers_answer() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
            let query = &buffer[..length];
            let mut reply = query.to_vec();
            reply[2] = 0x81;
            reply[3] = 0x80;
            reply[7] = 1; // one answer
            reply
                .extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 185, 188, 104, 10]);
            server.send_to(&reply, peer).await.unwrap();
        });
        let (answers, _) = probe_udp(address, "digikala.com", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(answers, vec![IpAddr::from([185, 188, 104, 10])]);
    }

    #[tokio::test]
    async fn pinned_view_keeps_only_that_server() {
        let settings = DnsSettings {
            servers: vec![
                zero_config::dns::DnsServer {
                    endpoint: zero_config::dns::ResolverEndpoint::parse("193.186.32.32").unwrap(),
                    domains: Vec::new(),
                    expect_ips: Vec::new(),
                    skip_fallback: false,
                    tag: Some("anti-sanction".into()),
                },
                zero_config::dns::DnsServer {
                    endpoint: zero_config::dns::ResolverEndpoint::parse("178.22.122.100").unwrap(),
                    domains: Vec::new(),
                    expect_ips: Vec::new(),
                    skip_fallback: false,
                    tag: Some("anti-sanction".into()),
                },
            ]
            .into_boxed_slice(),
            ..DnsSettings::default()
        };
        let resolver = Resolver::new(settings);
        assert_eq!(
            resolver.for_tag("anti-sanction").settings().servers.len(),
            2
        );
        let pinned = resolver.for_tag("anti-sanction@178.22.122.100");
        assert_eq!(pinned.settings().servers.len(), 1);
        assert_eq!(
            pinned.settings().servers[0].endpoint,
            zero_config::dns::ResolverEndpoint::parse("178.22.122.100").unwrap()
        );
    }

    #[test]
    fn query_contains_one_question_and_requested_type() {
        let query = build_query(0x1234, "Example.COM", QueryType::Aaaa).unwrap();
        assert_eq!(&query[..2], &[0x12, 0x34]);
        assert_eq!(&query[2..4], &[1, 0]);
        assert_eq!(&query[query.len() - 4..], &[0, 28, 0, 1]);
    }

    #[test]
    fn parses_compressed_a_answer_and_ttl() {
        let mut response = build_query(7, "example.com", QueryType::A).unwrap();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0;
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 20, 0, 4, 1, 2, 3, 4]);
        let parsed = parse_response(&response, 7, QueryType::A).unwrap();
        assert_eq!(parsed.addresses, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(parsed.ttl, Duration::from_secs(20));
    }

    #[test]
    fn parses_https_ech_service_parameter() {
        let mut response = build_query(9, "example.com", QueryType::Https).unwrap();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0;
        response[7] = 1;
        let rdata = [0, 0, 0, 0, 5, 0, 3, 1, 2, 3];
        response.extend_from_slice(&[0xc0, 0x0c, 0, 65, 0, 1, 0, 0, 0, 30]);
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(&rdata);
        let parsed = parse_response(&response, 9, QueryType::Https).unwrap();
        assert_eq!(parsed.records, vec![rdata.to_vec()]);
        assert_eq!(parsed.ttl, Duration::from_secs(30));
        assert_eq!(parse_https_ech_config(&rdata), Some(vec![1, 2, 3]));
    }

    #[test]
    fn rejects_response_id_mismatch() {
        let response = build_query(8, "example.com", QueryType::A).unwrap();
        assert!(matches!(
            parse_response(&response, 7, QueryType::A),
            Err(ResolveError::Protocol(message)) if message.contains("ID mismatch")
        ));
    }

    #[tokio::test]
    async fn fake_dns_is_stable_and_reversible() {
        let settings = DnsSettings {
            servers: vec![DnsServer {
                endpoint: ResolverEndpoint::FakeDns,
                domains: Vec::new(),
                expect_ips: Vec::new(),
                skip_fallback: false,
                tag: None,
            }]
            .into_boxed_slice(),
            ..DnsSettings::default()
        };
        let resolver = Resolver::new(settings);
        let first = resolver
            .lookup("example.com", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        let second = resolver
            .lookup("example.com", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            resolver.reverse_fake(first[0]).await.as_deref(),
            Some("example.com")
        );
    }

    /// A fake catch-all in front of a real resolver: the applications get
    /// synthetic addresses, the runtime's own view gets the real one, and a
    /// replacement resolver keeps the mappings handed out before it.
    #[tokio::test]
    async fn the_runtime_view_never_sees_fake_addresses() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                let mut response = buffer[..len].to_vec();
                response[2] = 0x81;
                response[3] = 0x80;
                response[6] = 0;
                response[7] = 1;
                response.extend_from_slice(&[
                    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 93, 184, 216, 34,
                ]);
                let _ = socket.send_to(&response, peer).await;
            }
        });
        let server = |endpoint| DnsServer {
            endpoint,
            domains: Vec::new(),
            expect_ips: Vec::new(),
            skip_fallback: false,
            tag: None,
        };
        let settings = DnsSettings {
            servers: vec![
                server(ResolverEndpoint::FakeDns),
                server(ResolverEndpoint::Udp {
                    address: Address::parse_host("127.0.0.1"),
                    port: address.port(),
                }),
            ]
            .into_boxed_slice(),
            ..DnsSettings::default()
        };
        let resolver = Resolver::new(settings.clone());
        assert!(resolver.has_fake());

        let client = resolver
            .lookup("proxy.example", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        assert!(
            matches!(client[0], IpAddr::V4(v4) if v4.octets()[0] == 198 && v4.octets()[1] == 18)
        );

        let real = resolver.without_fake();
        assert!(!real.has_fake());
        let answer = real
            .lookup("proxy.example", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        assert_eq!(answer, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        // Memoized: the same view (and cache) every time.
        assert!(Arc::ptr_eq(&real.cache, &resolver.without_fake().cache));
        // A synthetic address is still reversible, on the client resolver only.
        assert_eq!(
            resolver.reverse_fake(client[0]).await.as_deref(),
            Some("proxy.example")
        );

        // A reload with changed DNS settings builds a new resolver; adopting
        // the old FakeDNS state keeps the address the application holds.
        let replacement = Resolver::new(settings).adopt_fake_state(&resolver);
        assert_eq!(
            replacement.reverse_fake(client[0]).await.as_deref(),
            Some("proxy.example")
        );
        let again = replacement
            .lookup("proxy.example", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        assert_eq!(again, client);
        let other = replacement
            .lookup("other.example", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        assert_ne!(
            other, client,
            "the adopted pool continues, it does not restart"
        );
    }

    #[tokio::test]
    async fn a_resolver_without_fakedns_is_its_own_runtime_view() {
        let resolver = Resolver::new(DnsSettings::default());
        assert!(!resolver.has_fake());
        assert!(Arc::ptr_eq(&resolver.cache, &resolver.without_fake().cache));
    }

    #[tokio::test]
    async fn udp_resolver_roundtrips_against_a_local_dns_server() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let mut response = buffer[..len].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            response[6] = 0;
            response[7] = 1;
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 7]);
            socket.send_to(&response, peer).await.unwrap();
        });
        let settings = DnsSettings {
            servers: vec![DnsServer {
                endpoint: ResolverEndpoint::Udp {
                    address: Address::parse_host("127.0.0.1"),
                    port: address.port(),
                },
                domains: Vec::new(),
                expect_ips: Vec::new(),
                skip_fallback: false,
                tag: None,
            }]
            .into_boxed_slice(),
            ..DnsSettings::default()
        };
        let resolver = Resolver::new(settings);
        let ips = resolver
            .lookup("example.com", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        assert_eq!(ips, vec!["10.0.0.7".parse::<IpAddr>().unwrap()]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn poisoned_udp_answer_is_rejected_before_the_fallback_resolver_is_used() {
        let poisoned = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let poisoned_address = poisoned.local_addr().unwrap();
        let poisoned_server = tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            let (len, peer) = poisoned.recv_from(&mut buffer).await.unwrap();
            let mut response = buffer[..len].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            response[6] = 0;
            response[7] = 1;
            // A plausible-looking public answer for a resolver policy that
            // expects a domestic/private relay. It must be discarded before
            // the result reaches routing or the cache.
            response
                .extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 7]);
            poisoned.send_to(&response, peer).await.unwrap();
        });

        let fallback = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fallback_address = fallback.local_addr().unwrap();
        let fallback_server = tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            let (len, peer) = fallback.recv_from(&mut buffer).await.unwrap();
            let mut response = buffer[..len].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            response[6] = 0;
            response[7] = 1;
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 7]);
            fallback.send_to(&response, peer).await.unwrap();
        });

        let settings = DnsSettings {
            servers: vec![
                DnsServer {
                    endpoint: ResolverEndpoint::Udp {
                        address: Address::parse_host("127.0.0.1"),
                        port: poisoned_address.port(),
                    },
                    domains: Vec::new(),
                    expect_ips: vec![IpPattern::Private],
                    skip_fallback: false,
                    tag: None,
                },
                DnsServer {
                    endpoint: ResolverEndpoint::Udp {
                        address: Address::parse_host("127.0.0.1"),
                        port: fallback_address.port(),
                    },
                    domains: Vec::new(),
                    expect_ips: vec![IpPattern::Private],
                    skip_fallback: false,
                    tag: None,
                },
            ]
            .into_boxed_slice(),
            ..DnsSettings::default()
        };
        let resolver = Resolver::new(settings);
        let ips = resolver
            .lookup("service.example", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        assert_eq!(ips, vec!["10.0.0.7".parse::<IpAddr>().unwrap()]);

        poisoned_server.await.unwrap();
        fallback_server.await.unwrap();
    }

    #[tokio::test]
    async fn strict_policy_does_not_bootstrap_remote_resolver_with_system_dns() {
        let resolver = Resolver::new(DnsSettings {
            servers: vec![DnsServer {
                endpoint: ResolverEndpoint::Udp {
                    address: Address::parse_host("dns.example.com"),
                    port: 53,
                },
                domains: Vec::new(),
                expect_ips: Vec::new(),
                skip_fallback: false,
                tag: None,
            }]
            .into_boxed_slice(),
            ..DnsSettings::default()
        });
        let result = resolver.lookup("example.com", QueryStrategy::UseIpv4).await;
        assert!(matches!(result, Err(ResolveError::BootstrapRequired(_))));
    }

    #[tokio::test]
    async fn strict_policy_uses_pinned_hosts_for_resolver_bootstrap() {
        let mut hosts = std::collections::BTreeMap::new();
        hosts.insert(
            Box::<str>::from("dns.example.com"),
            HostValue::Addresses(vec![Address::parse_host("203.0.113.7")]),
        );
        let resolver = Resolver::new(DnsSettings {
            hosts,
            ..DnsSettings::default()
        });
        let addresses = resolver
            .endpoint_addrs(&Address::parse_host("dns.example.com"), 853)
            .await
            .unwrap();
        assert_eq!(addresses, vec!["203.0.113.7:853".parse().unwrap()]);
    }

    #[tokio::test]
    async fn strict_policy_rejects_explicit_system_dns() {
        let resolver = Resolver::new(DnsSettings {
            servers: vec![DnsServer {
                endpoint: ResolverEndpoint::System,
                domains: Vec::new(),
                expect_ips: Vec::new(),
                skip_fallback: false,
                tag: None,
            }]
            .into_boxed_slice(),
            ..DnsSettings::default()
        });
        assert!(matches!(
            resolver.lookup("localhost", QueryStrategy::UseIpv4).await,
            Err(ResolveError::Unsupported(message)) if message.contains("strict")
        ));
    }

    #[tokio::test]
    async fn fake_dns_keeps_ipv4_and_ipv6_allocations_stable_independently() {
        let resolver = Resolver::new(DnsSettings {
            servers: vec![DnsServer {
                endpoint: ResolverEndpoint::FakeDns,
                domains: Vec::new(),
                expect_ips: Vec::new(),
                skip_fallback: false,
                tag: None,
            }]
            .into_boxed_slice(),
            ..DnsSettings::default()
        });
        let v4 = resolver
            .lookup("example.com", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        let v6 = resolver
            .lookup("example.com", QueryStrategy::UseIpv6)
            .await
            .unwrap();
        assert_ne!(v4, v6);
        assert_eq!(
            resolver
                .lookup("example.com", QueryStrategy::UseIpv4)
                .await
                .unwrap(),
            v4
        );
        assert_eq!(
            resolver
                .lookup("example.com", QueryStrategy::UseIpv6)
                .await
                .unwrap(),
            v6
        );
    }

    fn udp_settings(port: u16) -> DnsSettings {
        DnsSettings {
            servers: vec![DnsServer {
                endpoint: ResolverEndpoint::Udp {
                    address: Address::parse_host("127.0.0.1"),
                    port,
                },
                domains: Vec::new(),
                expect_ips: Vec::new(),
                skip_fallback: false,
                tag: None,
            }]
            .into_boxed_slice(),
            ..DnsSettings::default()
        }
    }

    /// Turn a received query into a response with the given answer and
    /// authority records appended.
    fn respond(query: &[u8], answers: u16, authority: u16, records: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6..8].copy_from_slice(&answers.to_be_bytes());
        response[8..10].copy_from_slice(&authority.to_be_bytes());
        response.extend_from_slice(records);
        response
    }

    /// An SOA authority record owned by the question name with the given TTL
    /// and MINIMUM.
    fn soa(ttl: u32, minimum: u32) -> Vec<u8> {
        let mut rdata = vec![0u8, 0u8]; // MNAME ".", RNAME "."
        for value in [1u32, 2, 3, 4, minimum] {
            rdata.extend_from_slice(&value.to_be_bytes());
        }
        let mut record = vec![0xc0, 0x0c, 0, 6, 0, 1];
        record.extend_from_slice(&ttl.to_be_bytes());
        record.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        record.extend_from_slice(&rdata);
        record
    }

    #[test]
    fn negative_answers_carry_the_soa_negative_ttl() {
        let query = build_query(3, "missing.example", QueryType::Aaaa).unwrap();
        let response = respond(&query, 0, 1, &soa(3600, 60));
        let parsed = parse_answer(&response, &query, QueryType::Aaaa).unwrap();
        assert!(parsed.addresses.is_empty());
        assert_eq!(parsed.ttl, Duration::from_secs(60));

        // No SOA: a short default rather than no caching at all.
        let bare = respond(&query, 0, 0, &[]);
        assert_eq!(
            parse_answer(&bare, &query, QueryType::Aaaa).unwrap().ttl,
            NEGATIVE_TTL_DEFAULT
        );
        // A huge SOA minimum is clamped.
        let long = respond(&query, 0, 1, &soa(86_400, 86_400));
        assert_eq!(
            parse_answer(&long, &query, QueryType::Aaaa).unwrap().ttl,
            NEGATIVE_TTL_MAX
        );
    }

    #[test]
    fn a_response_to_a_different_question_is_rejected() {
        let query = build_query(5, "example.com", QueryType::A).unwrap();
        let other = build_query(5, "example.org", QueryType::A).unwrap();
        let response = respond(
            &other,
            1,
            0,
            &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 1, 2, 3, 4],
        );
        assert!(parse_answer(&response, &query, QueryType::A).is_err());
        // Case differences in the echoed name are fine (0x20 encoding).
        let upper = build_query(5, "EXAMPLE.com", QueryType::A).unwrap();
        let response = respond(
            &upper,
            1,
            0,
            &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 1, 2, 3, 4],
        );
        assert!(parse_answer(&response, &query, QueryType::A).is_ok());
    }

    #[tokio::test]
    async fn negative_answers_are_cached_instead_of_requeried_per_lookup() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&queries);
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            while let Ok((len, peer)) = socket.recv_from(&mut buffer).await {
                counter.fetch_add(1, Ordering::SeqCst);
                let response = respond(&buffer[..len], 0, 1, &soa(300, 60));
                let _ = socket.send_to(&response, peer).await;
            }
        });
        let resolver = Resolver::new(udp_settings(port));
        for _ in 0..3 {
            assert!(matches!(
                resolver
                    .lookup("v4only.example", QueryStrategy::UseIpv6)
                    .await,
                Err(ResolveError::NoData(_))
            ));
        }
        assert_eq!(queries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn udp_ignores_datagrams_that_do_not_answer_the_query() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let answer = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 9];
            // A forged answer with the wrong ID arrives first.
            let mut forged = respond(&buffer[..len], 1, 0, &answer);
            forged[0] ^= 0xff;
            let last = forged.len() - 1;
            forged[last] = 66;
            socket.send_to(&forged, peer).await.unwrap();
            let genuine = respond(&buffer[..len], 1, 0, &answer);
            socket.send_to(&genuine, peer).await.unwrap();
        });
        let resolver = Resolver::new(udp_settings(port));
        let ips = resolver
            .lookup("example.com", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        assert_eq!(ips, vec!["10.0.0.9".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn udp_retransmits_after_a_lost_datagram() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            // Drop the first transmission on the floor.
            let _ = socket.recv_from(&mut buffer).await.unwrap();
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let response = respond(
                &buffer[..len],
                1,
                0,
                &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 3],
            );
            socket.send_to(&response, peer).await.unwrap();
        });
        let resolver = Resolver::new(udp_settings(port));
        let started = Instant::now();
        let ips = resolver
            .lookup("example.com", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        assert_eq!(ips, vec!["10.0.0.3".parse::<IpAddr>().unwrap()]);
        assert!(started.elapsed() < DNS_TIMEOUT);
    }

    /// The regression: a coalesced lookup whose leader is cancelled must not
    /// leave the name wedged. Followers used to hold a sender clone, so the
    /// channel never closed and they — and every later lookup of the name —
    /// waited forever.
    #[tokio::test]
    async fn a_cancelled_leader_does_not_wedge_followers_or_later_lookups() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            // The leader's query (and its retransmission) go unanswered
            // until the leader is gone; everything after is answered.
            let first = socket.recv_from(&mut buffer).await.unwrap().1;
            loop {
                let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
                if peer == first {
                    continue;
                }
                let response = respond(
                    &buffer[..len],
                    1,
                    0,
                    &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 5],
                );
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        let resolver = Resolver::new(udp_settings(port));
        let leader_resolver = resolver.clone();
        let leader = tokio::spawn(async move {
            leader_resolver
                .lookup("example.com", QueryStrategy::UseIpv4)
                .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let follower_resolver = resolver.clone();
        let follower = tokio::spawn(async move {
            follower_resolver
                .lookup("example.com", QueryStrategy::UseIpv4)
                .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        leader.abort();

        let expected = vec!["10.0.0.5".parse::<IpAddr>().unwrap()];
        let followed = timeout(Duration::from_secs(4), follower)
            .await
            .expect("the follower must not hang after its leader is cancelled")
            .unwrap()
            .unwrap();
        assert_eq!(followed, expected);
        let later = timeout(
            Duration::from_secs(4),
            resolver.lookup("example.com", QueryStrategy::UseIpv4),
        )
        .await
        .expect("a later lookup must not hang")
        .unwrap();
        assert_eq!(later, expected);
    }

    #[tokio::test]
    async fn fake_dns_ipv6_addresses_do_not_alias_past_65536_allocations() {
        let resolver = Resolver::new(DnsSettings {
            servers: vec![DnsServer {
                endpoint: ResolverEndpoint::FakeDns,
                domains: Vec::new(),
                expect_ips: Vec::new(),
                skip_fallback: false,
                tag: None,
            }]
            .into_boxed_slice(),
            ..DnsSettings::default()
        });
        let first = resolver
            .lookup("first.example", QueryStrategy::UseIpv6)
            .await
            .unwrap();
        resolver.fake_next.store(1 + 65_536, Ordering::Relaxed);
        let second = resolver
            .lookup("second.example", QueryStrategy::UseIpv6)
            .await
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            resolver.reverse_fake(first[0]).await.as_deref(),
            Some("first.example")
        );

        // Once the pool wraps, the oldest mapping is recycled rather than
        // every new name failing.
        resolver
            .fake_next
            .store(FAKE_POOL_SIZE + 1, Ordering::Relaxed);
        let recycled = resolver
            .lookup("third.example", QueryStrategy::UseIpv6)
            .await
            .unwrap();
        assert_eq!(recycled, first);
        assert_eq!(
            resolver.reverse_fake(first[0]).await.as_deref(),
            Some("third.example")
        );
    }

    /// Opt-in: reaches public encrypted resolvers. Run with
    /// `cargo test -p zero-dns -- --ignored live_encrypted`.
    #[tokio::test]
    #[ignore = "requires outbound network access to public resolvers"]
    async fn live_encrypted_resolvers_reuse_their_connections() {
        // Named endpoints pinned through hosts: some networks drop a TLS
        // ClientHello without SNI on 443, which an IP-literal URL produces.
        let mut hosts = std::collections::BTreeMap::new();
        hosts.insert(
            Box::<str>::from("one.one.one.one"),
            HostValue::Addresses(vec![Address::parse_host("1.1.1.1")]),
        );
        for endpoint in [
            "tls://1.1.1.1",
            "https://one.one.one.one/dns-query",
            "h2://one.one.one.one/dns-query",
            "doq://94.140.14.140",
        ] {
            let resolver = Resolver::new(DnsSettings {
                servers: vec![DnsServer {
                    endpoint: ResolverEndpoint::parse(endpoint).unwrap(),
                    domains: Vec::new(),
                    expect_ips: Vec::new(),
                    skip_fallback: false,
                    tag: None,
                }]
                .into_boxed_slice(),
                hosts: hosts.clone(),
                disable_cache: true,
                ..DnsSettings::default()
            });
            let cold = Instant::now();
            let first = resolver.lookup("example.com", QueryStrategy::UseIpv4).await;
            let cold = cold.elapsed();
            let warm = Instant::now();
            let second = resolver.lookup("example.org", QueryStrategy::UseIpv4).await;
            let warm = warm.elapsed();
            println!("{endpoint}: cold {cold:?} {first:?}; warm {warm:?} {second:?}");
            assert!(first.is_ok() && second.is_ok(), "{endpoint}");
            let pooled = lock(&resolver.pools.h2).len()
                + lock(&resolver.pools.dot)
                    .values()
                    .map(Vec::len)
                    .sum::<usize>()
                + lock(&resolver.pools.doq).len();
            assert_eq!(pooled, 1, "{endpoint} must leave one reusable connection");
        }
    }

    /// A self-signed certificate for `dns.test` / 127.0.0.1, used as its own
    /// trust anchor by the local encrypted-resolver tests.
    const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIBlTCCATugAwIBAgIUGS+8Fs1U1nZuhCCERiq/cE2I/EwwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAwwIZG5zLnRlc3QwIBcNMjYwOTIzMDM0MjE0WhgPMjEyNjA4MzAw\nMzQyMTRaMBMxETAPBgNVBAMMCGRucy50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\nAQcDQgAE4SqQn7qEa4DtfdAqi9OaEwN90Nw7fFYqJZpApbzJvAx1SEqxXCzJyCEB\na8NVtrWewNSLFBsFbk6lRLJoZU/NkKNrMGkwHQYDVR0OBBYEFJK+70IhxQ31fNnu\nfzTg7k6NSpO9MB8GA1UdIwQYMBaAFJK+70IhxQ31fNnufzTg7k6NSpO9MBkGA1Ud\nEQQSMBCCCGRucy50ZXN0hwR/AAABMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwID\nSAAwRQIgNg84WOdtnUk+Q6MYOs83T0huf9SA6szJaAKPxRL6vf8CIQDqMr+gBsfi\n5i5jHcRxCnpNYCzjPGH0FgdOY12pKnFHpQ==\n-----END CERTIFICATE-----";
    const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7Gv8nckw9qy+6eL/\ng88Sxzpwfuq9C7IA8LrrBIkNWIChRANCAAThKpCfuoRrgO190CqL05oTA33Q3Dt8\nViolmkClvMm8DHVISrFcLMnIIQFrw1W2tZ7A1IsUGwVuTqVEsmhlT82Q\n-----END PRIVATE KEY-----";

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum TlsMode {
        Dot,
        H2,
        Http1,
    }

    /// A local encrypted resolver answering every A query with 10.0.0.1.
    /// Returns its port and a count of accepted TCP connections.
    async fn tls_dns_server(mode: TlsMode) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        use rustls_pki_types::pem::PemObject;
        let certs =
            vec![rustls_pki_types::CertificateDer::from_pem_slice(TEST_CERT.as_bytes()).unwrap()];
        let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(TEST_KEY.as_bytes()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        config.alpn_protocols = match mode {
            TlsMode::Dot => Vec::new(),
            TlsMode::H2 => vec![b"h2".to_vec()],
            TlsMode::Http1 => vec![b"http/1.1".to_vec()],
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        let answer = |query: &[u8]| {
            respond(
                query,
                1,
                0,
                &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 1],
            )
        };
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    match mode {
                        TlsMode::Dot => loop {
                            let Ok(len) = tls.read_u16().await else {
                                return;
                            };
                            let mut query = vec![0u8; len as usize];
                            if tls.read_exact(&mut query).await.is_err() {
                                return;
                            }
                            if tls.write_all(&frame(&answer(&query))).await.is_err() {
                                return;
                            }
                        },
                        TlsMode::H2 => {
                            let Ok(mut connection) = h2::server::handshake(tls).await else {
                                return;
                            };
                            while let Some(Ok((request, mut respond_to))) =
                                connection.accept().await
                            {
                                assert_eq!(
                                    request.uri().authority().map(|a| a.as_str()),
                                    Some(format!("dns.test:{port}").as_str())
                                );
                                let mut body = request.into_body();
                                let mut query = Vec::new();
                                while let Some(Ok(chunk)) = body.data().await {
                                    let _ = body.flow_control().release_capacity(chunk.len());
                                    query.extend_from_slice(&chunk);
                                }
                                let response = http::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/dns-message")
                                    .body(())
                                    .unwrap();
                                let mut send = respond_to.send_response(response, false).unwrap();
                                let _ = send.send_data(Bytes::from(answer(&query)), true);
                            }
                        }
                        TlsMode::Http1 => {
                            let mut head = Vec::new();
                            let mut byte = [0u8; 1];
                            while !head.ends_with(b"\r\n\r\n") {
                                if tls.read_exact(&mut byte).await.is_err() {
                                    return;
                                }
                                head.push(byte[0]);
                            }
                            let head = String::from_utf8(head).unwrap();
                            let length: usize = head
                                .lines()
                                .find_map(|line| {
                                    line.strip_prefix("Content-Length: ")
                                        .and_then(|v| v.trim().parse().ok())
                                })
                                .unwrap();
                            let mut query = vec![0u8; length];
                            tls.read_exact(&mut query).await.unwrap();
                            let body = answer(&query);
                            let mut response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .into_bytes();
                            response.extend_from_slice(&body);
                            let _ = tls.write_all(&response).await;
                            let _ = tls.shutdown().await;
                        }
                    }
                });
            }
        });
        (port, connections)
    }

    fn tls_resolver(endpoint: ResolverEndpoint) -> Resolver {
        let mut hosts = std::collections::BTreeMap::new();
        hosts.insert(
            Box::<str>::from("dns.test"),
            HostValue::Addresses(vec![Address::parse_host("127.0.0.1")]),
        );
        Resolver::new(DnsSettings {
            servers: vec![DnsServer {
                endpoint,
                domains: Vec::new(),
                expect_ips: Vec::new(),
                skip_fallback: false,
                tag: None,
            }]
            .into_boxed_slice(),
            hosts,
            disable_cache: true,
            trusted_roots: vec![TEST_CERT.as_bytes().into()],
            ..DnsSettings::default()
        })
    }

    async fn three_lookups(resolver: &Resolver) {
        for name in ["a.example", "b.example", "c.example"] {
            let ips = resolver.lookup(name, QueryStrategy::UseIpv4).await.unwrap();
            assert_eq!(ips, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
        }
    }

    #[tokio::test]
    async fn dot_reuses_one_connection_across_queries() {
        let (port, connections) = tls_dns_server(TlsMode::Dot).await;
        let resolver = tls_resolver(ResolverEndpoint::Dot {
            address: Address::parse_host("dns.test"),
            port,
        });
        three_lookups(&resolver).await;
        assert_eq!(connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn doh_multiplexes_over_one_pooled_http2_connection() {
        let (port, connections) = tls_dns_server(TlsMode::H2).await;
        for h2_only in [false, true] {
            let before = connections.load(Ordering::SeqCst);
            let url: Arc<str> = Arc::from(format!("https://dns.test:{port}/dns-query"));
            let host: Arc<str> = Arc::from("dns.test");
            let resolver = tls_resolver(if h2_only {
                ResolverEndpoint::Doh2 { url, host, port }
            } else {
                ResolverEndpoint::Doh { url, host, port }
            });
            three_lookups(&resolver).await;
            assert_eq!(connections.load(Ordering::SeqCst) - before, 1);
        }
    }

    #[tokio::test]
    async fn doh_falls_back_to_http1_when_the_server_does_not_offer_h2() {
        let (port, connections) = tls_dns_server(TlsMode::Http1).await;
        let resolver = tls_resolver(ResolverEndpoint::Doh {
            url: Arc::from(format!("https://dns.test:{port}/dns-query")),
            host: Arc::from("dns.test"),
            port,
        });
        three_lookups(&resolver).await;
        // HTTP/1.1 with `Connection: close` is one connection per query.
        assert_eq!(connections.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_pooled_connection_the_server_closed_is_replaced_transparently() {
        let (port, connections) = tls_dns_server(TlsMode::Dot).await;
        let resolver = tls_resolver(ResolverEndpoint::Dot {
            address: Address::parse_host("dns.test"),
            port,
        });
        three_lookups(&resolver).await;
        // Simulate the server dropping the idle connection: half-close the
        // pooled client stream so the server sees EOF and hangs up.
        let pooled: Vec<_> = lock(&resolver.pools.dot).drain().collect();
        for (key, streams) in pooled {
            for (mut stream, _) in streams {
                let _ = stream.get_mut().0.shutdown().await;
                tokio::time::sleep(Duration::from_millis(50)).await;
                resolver.pools.checkin_dot(key.clone(), stream);
            }
        }
        three_lookups(&resolver).await;
        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn tagged_views_are_memoized() {
        let resolver = Resolver::new(DnsSettings::default());
        let a = resolver.for_tag("domestic");
        let b = resolver.for_tag("domestic");
        assert!(Arc::ptr_eq(&a.cache, &b.cache));
        assert!(Arc::ptr_eq(&a.pools, &resolver.pools));
        assert!(!Arc::ptr_eq(&a.cache, &resolver.cache));
    }

    #[test]
    fn malformed_chunked_body_is_an_error_not_a_panic() {
        assert!(
            parse_http_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").is_err()
        );
    }

    /// A resolver carrying `domains` on one endpoint, for the matching tests.
    fn scoped(domains: &[&str], endpoint: &str) -> DnsServer {
        DnsServer {
            endpoint: ResolverEndpoint::parse(endpoint).unwrap(),
            domains: domains
                .iter()
                .map(|pattern| zero_config::routing::DomainPattern::parse(pattern))
                .collect(),
            expect_ips: Vec::new(),
            skip_fallback: false,
            tag: None,
        }
    }

    /// A precompiled `regexp:` has to select exactly the servers the
    /// compile-per-match path did, including for a pattern that does not
    /// compile -- which `compile_server_regexes` records as `None` so it still
    /// reaches `domain_matches`.
    #[test]
    fn precompiled_regexps_match_exactly_as_compiling_at_match_time() {
        let server = scoped(
            &[
                "regexp:^ads[0-9]+\\.",
                "regexp:^([a-z0-9-]+\\.)*example\\.com$",
                "regexp:[unclosed",
                "domain:plain.example",
            ],
            "1.1.1.1",
        );
        let compiled = compile_server_regexes(std::slice::from_ref(&server));
        for (position, pattern) in server.domains.iter().enumerate() {
            for name in [
                "ads12.example",
                "ads.example",
                "example.com",
                "a.b.example.com",
                "notexample.com",
                "plain.example",
            ] {
                // What the previous implementation did: compile, then match.
                let want = domain_matches(pattern, name);
                let got = match compiled[0][position].as_ref() {
                    Some(regex) => regex.is_match(name),
                    None => domain_matches(pattern, name),
                };
                assert_eq!(got, want, "domain {position} against {name}");
            }
        }
    }

    /// `candidates` must produce the sequence the old per-lookup stable sort
    /// produced, for every mix of scoped and catch-all servers.
    #[test]
    fn candidate_order_is_what_the_per_lookup_sort_produced() {
        let mixes: Vec<Vec<DnsServer>> = vec![
            vec![scoped(&[], "1.1.1.1"), scoped(&[], "8.8.8.8")],
            vec![
                scoped(&["domain:d0.example"], "1.1.1.1"),
                scoped(&["domain:d1.example"], "8.8.8.8"),
            ],
            // interleaved, the case the ordering exists for
            vec![
                scoped(&[], "1.1.1.1"),
                scoped(&["domain:ir"], "8.8.8.8"),
                scoped(&[], "9.9.9.9"),
                scoped(&["domain:example.com"], "1.0.0.1"),
                scoped(&[], "8.8.4.4"),
            ],
            vec![
                scoped(&[], "1.1.1.1"),
                scoped(&["regexp:^ads[0-9]+\\."], "8.8.8.8"),
                scoped(&["regexp:[unclosed"], "9.9.9.9"),
                scoped(&["keyword:tracker"], "1.0.0.1"),
            ],
        ];
        for servers in mixes {
            let resolver = Resolver::new(DnsSettings {
                servers: servers.clone().into_boxed_slice(),
                ..DnsSettings::default()
            });
            for name in [
                "example.com",
                "d1.example",
                "ads12.ads",
                "x.tracker.example",
                "unrelated.test",
            ] {
                // What the previous implementation computed: filter in
                // declaration order, then stable-sort by is_empty.
                let mut expected: Vec<DnsServer> = servers
                    .iter()
                    .filter(|server| {
                        server.domains.is_empty()
                            || server
                                .domains
                                .iter()
                                .any(|pattern| domain_matches(pattern, name))
                    })
                    .cloned()
                    .collect();
                expected.sort_by_key(|server| server.domains.is_empty());

                let got: Vec<String> = resolver
                    .candidates(name)
                    .into_iter()
                    .map(|server| server.endpoint.host())
                    .collect();
                let want: Vec<String> = expected
                    .iter()
                    .map(|server| server.endpoint.host())
                    .collect();
                assert_eq!(got, want, "candidate order for {name}");
            }
        }
    }

    /// A DoH URL must report what the per-query parse reported, bad URLs included.
    #[test]
    fn doh_urls_are_parsed_once_and_failures_are_preserved() {
        let doh = |url: &str| DnsServer {
            endpoint: ResolverEndpoint::Doh {
                url: url.into(),
                host: "dns.example".into(),
                port: 443,
            },
            domains: Vec::new(),
            expect_ips: Vec::new(),
            skip_fallback: false,
            tag: None,
        };
        let resolver = Resolver::new(DnsSettings {
            servers: vec![
                doh("https://dns.example/dns-query"),
                doh("https://other.example/dns-query"),
                doh("not a url"),
            ]
            .into_boxed_slice(),
            ..DnsSettings::default()
        });

        for url in [
            "https://dns.example/dns-query",
            "https://other.example/dns-query",
        ] {
            // Exactly what the per-query parse returned.
            assert_eq!(
                resolver.doh_url(&url.into()).map(|u| u.to_string()),
                Ok(url.to_string()),
                "{url}"
            );
        }
        let bad = "not a url";
        assert_eq!(
            resolver.doh_url(&bad.into()).map(|u| u.to_string()),
            Url::parse(bad)
                .map(|u| u.to_string())
                .map_err(|e| ResolveError::Protocol(e.to_string()))
        );
    }
}

#[cfg(test)]
mod race_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// A UDP resolver that answers every A query with `answer` after
    /// `delay`, or never when `answer` is `None`... unless `nxdomain`.
    async fn resolver_stub(
        delay: Duration,
        answer: Option<[u8; 4]>,
        nxdomain: bool,
    ) -> (u16, Arc<AtomicUsize>) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let port = socket.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&count);
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut reply = buffer[..len].to_vec();
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    if answer.is_none() && !nxdomain {
                        return; // a black hole
                    }
                    tokio::time::sleep(delay).await;
                    reply[2] = 0x81;
                    reply[3] = if nxdomain { 0x83 } else { 0x80 };
                    if let Some(ip) = answer {
                        reply[7] = 1;
                        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
                        reply.extend_from_slice(&ip);
                    }
                    let _ = socket.send_to(&reply, peer).await;
                });
            }
        });
        (port, count)
    }

    fn udp(port: u16) -> DnsServer {
        DnsServer {
            endpoint: ResolverEndpoint::Udp {
                address: Address::parse_host("127.0.0.1"),
                port,
            },
            domains: Vec::new(),
            expect_ips: Vec::new(),
            skip_fallback: false,
            tag: None,
        }
    }

    fn resolver(servers: Vec<DnsServer>) -> Resolver {
        Resolver::new(DnsSettings {
            servers: servers.into_boxed_slice(),
            disable_cache: true,
            ..DnsSettings::default()
        })
    }

    #[tokio::test]
    async fn a_black_holed_first_resolver_costs_one_hedge_delay_then_sinks() {
        let (dead, dead_hits) = resolver_stub(Duration::ZERO, None, false).await;
        let (live, live_hits) = resolver_stub(Duration::ZERO, Some([10, 0, 0, 9]), false).await;
        let resolver = resolver(vec![udp(dead), udp(live)]);

        let started = Instant::now();
        let ips = resolver
            .lookup("example.com", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        assert_eq!(ips, vec![IpAddr::from([10, 0, 0, 9])]);
        // One hedge delay for an unmeasured resolver, not the 5 s timeout.
        assert!(started.elapsed() < Duration::from_millis(1_500));
        assert_eq!(dead_hits.load(Ordering::SeqCst), 1);

        // From now on the live resolver is asked first and alone.
        for _ in 0..5 {
            let started = Instant::now();
            resolver
                .lookup("example.com", QueryStrategy::UseIpv4)
                .await
                .unwrap();
            assert!(started.elapsed() < Duration::from_millis(100));
        }
        assert_eq!(dead_hits.load(Ordering::SeqCst), 1);
        assert_eq!(live_hits.load(Ordering::SeqCst), 6);
    }

    #[tokio::test]
    async fn a_fast_resolver_answers_alone_without_a_second_query() {
        let (fast, fast_hits) = resolver_stub(Duration::ZERO, Some([10, 0, 0, 1]), false).await;
        let (other, other_hits) =
            resolver_stub(Duration::from_millis(40), Some([10, 0, 0, 2]), false).await;
        let resolver = resolver(vec![udp(fast), udp(other)]);
        // The first upstream lookup explores both; the rest ask one.
        for _ in 0..(EXPLORE_EVERY as usize) {
            let ips = resolver
                .lookup("example.com", QueryStrategy::UseIpv4)
                .await
                .unwrap();
            assert_eq!(ips, vec![IpAddr::from([10, 0, 0, 1])]);
        }
        assert_eq!(fast_hits.load(Ordering::SeqCst), EXPLORE_EVERY as usize);
        assert_eq!(other_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn one_authoritative_nxdomain_answers_for_the_whole_group() {
        let (first, _) = resolver_stub(Duration::ZERO, None, true).await;
        let (second, second_hits) =
            resolver_stub(Duration::from_millis(200), Some([10, 0, 0, 2]), false).await;
        let resolver = resolver(vec![udp(first), udp(second)]);
        for _ in 0..3 {
            let result = resolver
                .lookup("missing.example", QueryStrategy::UseIpv4)
                .await;
            assert!(matches!(result, Err(ResolveError::NoData(_))), "{result:?}");
        }
        // Only the exploring first lookup reached the second resolver.
        assert_eq!(second_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exploration_finds_a_faster_resolver_behind_a_fine_one() {
        let (live, _) = resolver_stub(Duration::ZERO, Some([10, 0, 0, 3]), false).await;
        let (slow, _) = resolver_stub(Duration::from_millis(50), Some([10, 0, 0, 4]), false).await;
        let resolver = resolver(vec![udp(slow), udp(live)]);
        // Warm the table: slow first (configured order), then measured.
        for _ in 0..3 {
            resolver
                .lookup("example.com", QueryStrategy::UseIpv4)
                .await
                .unwrap();
        }
        let ips = resolver
            .lookup("example.com", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        // Once measured, the faster one leads.
        assert_eq!(ips, vec![IpAddr::from([10, 0, 0, 3])]);
    }

    #[test]
    fn ranking_prefers_measured_speed_and_keeps_order_on_ties() {
        let fast = Rtt {
            smoothed_ms: 80,
            failures: 0,
        };
        let slow = Rtt {
            smoothed_ms: 700,
            failures: 0,
        };
        assert_eq!(rank([None, None, None].into_iter()), vec![0, 1, 2]);
        assert_eq!(rank([Some(slow), Some(fast)].into_iter()), vec![1, 0]);
        // Unmeasured (400 ms assumed) sits between fast and slow.
        assert_eq!(
            rank([Some(slow), None, Some(fast)].into_iter()),
            vec![2, 1, 0]
        );
        // Two failures outweigh a latency advantage.
        let failing = Rtt {
            smoothed_ms: 80,
            failures: 2,
        };
        assert_eq!(rank([Some(failing), Some(slow)].into_iter()), vec![1, 0]);
        // One failure does not.
        let wobbly = Rtt {
            smoothed_ms: 80,
            failures: 1,
        };
        assert_eq!(rank([Some(wobbly), Some(slow)].into_iter()), vec![0, 1]);
    }

    #[test]
    fn rtt_smooths_and_abandoned_queries_only_push_up() {
        let mut rtt = Rtt::default();
        rtt.observe(Duration::from_millis(100));
        assert_eq!(rtt.smoothed_ms, 100);
        rtt.observe(Duration::from_millis(500));
        assert_eq!(rtt.smoothed_ms, 200);
        rtt.observe_at_least(Duration::from_millis(10));
        assert_eq!(rtt.smoothed_ms, 200);
        rtt.fail();
        rtt.observe_at_least(Duration::from_millis(1_000));
        assert_eq!(rtt.failures, 1);
        assert_eq!(rtt.smoothed_ms, 400);
        rtt.observe(Duration::from_millis(400));
        assert_eq!(rtt.failures, 0);
    }

    #[test]
    fn hedge_delay_is_bounded() {
        assert_eq!(hedge_delay(None), Duration::from_millis(800));
        let fast = Rtt {
            smoothed_ms: 5,
            failures: 0,
        };
        assert_eq!(hedge_delay(Some(fast)), HEDGE_MIN);
        let slow = Rtt {
            smoothed_ms: 3_000,
            failures: 0,
        };
        assert_eq!(hedge_delay(Some(slow)), HEDGE_MAX);
        let failing = Rtt {
            smoothed_ms: 3_000,
            failures: 1,
        };
        assert_eq!(hedge_delay(Some(failing)), HEDGE_MIN);
    }

    #[tokio::test]
    async fn resolvers_on_different_routes_are_never_raced() {
        let (tunnelled, _) =
            resolver_stub(Duration::from_millis(1_500), Some([10, 0, 0, 1]), false).await;
        let (direct, direct_hits) = resolver_stub(Duration::ZERO, Some([10, 0, 0, 2]), false).await;
        let mut first = udp(tunnelled);
        first.tag = Some("remote".into());
        let mut second = udp(direct);
        second.tag = Some("local".into());
        let resolver = resolver(vec![first, second]);
        let ips = resolver
            .lookup("example.com", QueryStrategy::UseIpv4)
            .await
            .unwrap();
        // Slow, but answered by the configured first server alone.
        assert_eq!(ips, vec![IpAddr::from([10, 0, 0, 1])]);
        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
    }
}
