//! Composing an outbound connection.
//!
//! This is the one place where dialing, evasion, security, transport and
//! protocol are stacked. Each layer below is unaware of the others; the order
//! they are applied in lives here and nowhere else.
//!
//! ```text
//! TCP socket
//!   └─ fragment        (optional, wraps writes)
//!        └─ TLS        (optional)
//!             └─ WebSocket  (optional)
//!                  └─ VLESS / Trojan header
//! ```
//!
//! Fragmentation sits *below* TLS deliberately: it must see the ClientHello
//! record as bytes in order to split it.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use zero_config::{
    FragmentPackets, Outbound, OutboundProtocol, Security, StreamSettings, Transport,
    XhttpHttpVersion, XhttpMode,
};
use zero_core::{boxed, Address, BoxStream, Confidence, Destination, Failure, FailureKind, Stage};
use zero_evasion::fragment::{FragmentPolicy, FragmentStream, Packets};
use zero_net::{dial_tcp, RacePolicy, SocketOptions};
use zero_security::{FingerprintProfile, TlsParams};
use zero_transport::grpc;
use zero_transport::httpupgrade;
use zero_transport::ws::{self, WsConfig};
use zero_transport::xhttp;

type MuxPoolCache = Mutex<HashMap<String, Vec<Arc<zero_protocol::mux::ClientPool>>>>;

static MUX_POOLS: OnceLock<MuxPoolCache> = OnceLock::new();

struct EnvProxy {
    addr: SocketAddr,
    https: bool,
}

fn env_proxy_for(host: &str) -> Option<EnvProxy> {
    if no_proxy_matches(host) {
        return None;
    }
    let (raw, https) = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .map(|value| (value, true))
        .or_else(|_| {
            std::env::var("HTTP_PROXY")
                .or_else(|_| std::env::var("http_proxy"))
                .map(|value| (value, false))
        })
        .ok()?;
    parse_proxy_addr(&raw).map(|addr| EnvProxy { addr, https })
}

fn no_proxy_matches(host: &str) -> bool {
    let list = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    list.split(',').map(str::trim).any(|entry| {
        let entry = entry.trim_start_matches('.').to_ascii_lowercase();
        !entry.is_empty() && (entry == "*" || host == entry || host.ends_with(&format!(".{entry}")))
    })
}

fn parse_proxy_addr(raw: &str) -> Option<SocketAddr> {
    let raw = raw
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let hostport = raw.split('/').next()?.split('@').next_back()?;
    hostport.parse().ok()
}

/// Resolve the outbound's own endpoint.
///
/// Only the proxy server's address is resolved locally. Destination names are
/// carried inside the protocol header and resolved by the server, so ordinary
/// browsing never produces a local DNS query — the leak-free path is the
/// default rather than something to remember to switch on.
pub async fn resolve_endpoint(address: &Address, port: u16) -> Result<Vec<SocketAddr>, Failure> {
    match address {
        Address::Ip(ip) => Ok(vec![SocketAddr::new(*ip, port)]),
        Address::Domain(name) => resolve_domain(name, port).await,
    }
}

/// Why the system resolver gave nothing usable.
enum SystemMiss {
    /// It answered with the block page or another address no server has.
    Hijacked,
    Failed(String),
}

/// Why encrypted DNS gave nothing usable.
enum EncryptedMiss {
    /// It answered, and every address was one no server has.
    NoUsable,
    Failed(String),
}

/// A domain's addresses: the system resolver first, encrypted DNS beside it.
///
/// The system resolver is fast and, for most names, right. In Iran it is also
/// the ISP's, which answers a filtered name with the block page (10.10.34.x)
/// or a dead address, so those answers are thrown away rather than dialled:
/// connecting to them only ever yields "connection refused". Encrypted DNS can
/// be blocked by a middlebox but not forged, so it is the fallback.
///
/// The fallback starts at once when the system resolver misses, and after
/// [`SYSTEM_HEAD_START`] when it is only slow (an ISP resolver that drops the
/// query would otherwise cost its whole timeout before the second try). The
/// first usable answer wins; the other is dropped.
async fn resolve_domain(name: &str, port: u16) -> Result<Vec<SocketAddr>, Failure> {
    let system = system_lookup(name, port);
    let encrypted = encrypted_lookup(name, port);
    tokio::pin!(system, encrypted);
    let mut early = None;
    tokio::select! {
        found = &mut system => match found {
            Ok(addrs) => return Ok(addrs),
            Err(miss) => early = Some(miss),
        },
        _ = tokio::time::sleep(SYSTEM_HEAD_START) => {}
    }
    // Each branch awaits only a future that has not finished yet.
    let (system_miss, encrypted_miss) = match early {
        Some(miss) => match (&mut encrypted).await {
            Ok(addrs) => return Ok(addrs),
            Err(other) => (miss, other),
        },
        None => tokio::select! {
            found = &mut system => match found {
                Ok(addrs) => return Ok(addrs),
                Err(miss) => match (&mut encrypted).await {
                    Ok(addrs) => return Ok(addrs),
                    Err(other) => (miss, other),
                },
            },
            found = &mut encrypted => match found {
                Ok(addrs) => return Ok(addrs),
                Err(other) => match (&mut system).await {
                    Ok(addrs) => return Ok(addrs),
                    Err(miss) => (miss, other),
                },
            },
        },
    };
    Err(endpoint_failure(name, system_miss, encrypted_miss))
}

async fn system_lookup(name: &str, port: u16) -> Result<Vec<SocketAddr>, SystemMiss> {
    let found = tokio::time::timeout(
        SYSTEM_DNS_TIMEOUT,
        tokio::net::lookup_host(format!("{name}:{port}")),
    )
    .await;
    let all: Vec<SocketAddr> = match found {
        Ok(Ok(iter)) => iter.collect(),
        Ok(Err(e)) => return Err(SystemMiss::Failed(e.to_string())),
        Err(_) => return Err(SystemMiss::Failed("timed out".into())),
    };
    // `localhost` is loopback by definition, not by forgery.
    let local_name =
        name.eq_ignore_ascii_case("localhost") || name.to_ascii_lowercase().ends_with(".localhost");
    let usable: Vec<SocketAddr> = all
        .iter()
        .copied()
        .filter(|a| local_name || !is_hijacked_answer(a.ip()))
        .collect();
    if !usable.is_empty() {
        Ok(usable)
    } else if all.is_empty() {
        Err(SystemMiss::Failed("no addresses".into()))
    } else {
        Err(SystemMiss::Hijacked)
    }
}

async fn encrypted_lookup(name: &str, port: u16) -> Result<Vec<SocketAddr>, EncryptedMiss> {
    let ips = fallback_resolver()
        .lookup(name, zero_config::dns::QueryStrategy::UseIp)
        .await
        .map_err(|error| EncryptedMiss::Failed(error.to_string()))?;
    let usable: Vec<SocketAddr> = ips
        .into_iter()
        .filter(|ip| !is_hijacked_answer(*ip))
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    if usable.is_empty() {
        Err(EncryptedMiss::NoUsable)
    } else {
        Ok(usable)
    }
}

#[cold]
fn endpoint_failure(name: &str, system: SystemMiss, encrypted: EncryptedMiss) -> Failure {
    let error = match encrypted {
        EncryptedMiss::NoUsable => {
            return Failure::new(FailureKind::DnsNoData, Stage::Resolving)
                .with_confidence(Confidence::Confirmed)
                .with_detail(format!("no usable addresses for {name}"))
        }
        EncryptedMiss::Failed(error) => error,
    };
    let (kind, detail) = match system {
        SystemMiss::Hijacked => (
            FailureKind::DnsSuspectedInterference,
            format!(
                "{name} resolves to a filtering address on this network, \
                 and encrypted DNS failed: {error}"
            ),
        ),
        SystemMiss::Failed(why) => (
            FailureKind::DnsNoData,
            format!("{name}: {why}; encrypted DNS: {error}"),
        ),
    };
    Failure::new(kind, Stage::Resolving).with_detail(detail)
}

/// How long the system resolver gets before it is given up on. A name that is
/// not cached yet can take several seconds through a slow upstream, and the
/// encrypted lookup runs beside it, so waiting longer costs nothing unless
/// both are failing.
const SYSTEM_DNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
/// How long the system resolver is on its own before encrypted DNS is asked
/// beside it.
const SYSTEM_HEAD_START: std::time::Duration = std::time::Duration::from_millis(400);

/// An answer no public proxy server has: Iran's filtering block page
/// (10.10.34.34–36), the unspecified address and loopback, which filtering
/// resolvers return for names they refuse to answer.
///
/// The same resolvers answer the AAAA query too, with the block page written
/// into an IPv6 address: `2001:4188:2:600:10:10:34:34` is `10.10.34.34` with
/// each number taken as hexadecimal. Dialling it is "network is unreachable"
/// on any phone without IPv6, and it must not count as an answer, or the
/// encrypted-DNS fallback is never asked and a name that resolves fine is
/// reported as unreachable. An IPv4 address carried in an IPv6 one
/// (`::ffff:10.10.34.34`) is judged by the IPv4 it carries.
pub fn is_hijacked_answer(ip: IpAddr) -> bool {
    is_block_page(ip)
        || match ip {
            IpAddr::V4(v4) => v4.is_unspecified() || v4.is_loopback() || v4.is_broadcast(),
            IpAddr::V6(v6) => v6.is_unspecified() || v6.is_loopback(),
        }
}

/// The ISP's block page itself, in its IPv4 form and its IPv6 form, and an
/// IPv4 one carried in an IPv6 address. Narrower than [`is_hijacked_answer`]:
/// loopback and the unspecified address are forgeries from a resolver that
/// refuses a name, but a profile that maps a name to `127.0.0.1` on purpose
/// means it.
pub fn is_block_page(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 && o[1] == 10 && o[2] == 34
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_block_page(IpAddr::V4(v4));
            }
            let s = v6.segments();
            s[4] == 0x10 && s[5] == 0x10 && s[6] == 0x34 && (0x34..=0x36).contains(&s[7])
        }
    }
}

/// A server's own name, resolved through the engine's resolver.
///
/// The engine's DNS setting is whatever the profile asked for, and on a
/// filtered network a plain-UDP choice is answered by the filter with the
/// block page (`10.10.34.34`, or its IPv6 form), which the server's name must
/// never resolve to: dialling it is "refused" or "unreachable" for a server
/// that is fine. So those answers are thrown away, and when nothing else is
/// left the name is asked of the encrypted resolvers, which cannot be forged
/// on the way (see [`resolve_domain`], which does the same for the system
/// resolver).
pub trait ResolveServer {
    fn resolve_server(
        &self,
        address: &Address,
    ) -> impl std::future::Future<Output = Result<Vec<IpAddr>, zero_dns::ResolveError>> + Send;
}

impl ResolveServer for zero_dns::Resolver {
    async fn resolve_server(
        &self,
        address: &Address,
    ) -> Result<Vec<IpAddr>, zero_dns::ResolveError> {
        let answers = self
            .resolve_address(address, self.settings().query_strategy)
            .await?;
        let Address::Domain(name) = address else {
            return Ok(answers);
        };
        let usable: Vec<IpAddr> = answers
            .iter()
            .copied()
            .filter(|ip| !is_block_page(*ip))
            .collect();
        if !usable.is_empty() || answers.is_empty() {
            return Ok(if answers.is_empty() { answers } else { usable });
        }
        // Everything the resolver said was a block page.
        let clean: Vec<IpAddr> = fallback_resolver()
            .lookup(name, zero_config::dns::QueryStrategy::UseIp)
            .await?
            .into_iter()
            .filter(|ip| !is_block_page(*ip))
            .collect();
        if clean.is_empty() {
            Err(zero_dns::ResolveError::Blocked)
        } else {
            Ok(clean)
        }
    }
}

/// Encrypted resolvers addressed by IP, so they need no DNS of their own.
/// Tried in order; their sockets are protected like every other dial.
fn fallback_resolver() -> &'static zero_dns::Resolver {
    static RESOLVER: OnceLock<zero_dns::Resolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        let servers = [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
            "https://9.9.9.9/dns-query",
        ]
        .into_iter()
        .filter_map(zero_config::dns::ResolverEndpoint::parse)
        .map(|endpoint| zero_config::dns::DnsServer {
            endpoint,
            domains: Vec::new(),
            expect_ips: Vec::new(),
            unexpect_ips: Vec::new(),
            skip_fallback: false,
            tag: None,
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
        zero_dns::Resolver::new(zero_config::dns::DnsSettings {
            servers,
            ..zero_config::dns::DnsSettings::default()
        })
    })
}

fn race_policy(stream: &StreamSettings) -> RacePolicy {
    let mut p = RacePolicy::default();
    if let Some(he) = &stream.sockopt.happy_eyeballs {
        p.try_delay = he.try_delay;
        p.prioritize_ipv6 = he.prioritize_ipv6;
        p.interleave = he.interleave;
        p.max_concurrent = he.max_concurrent;
    }
    p
}

/// Whether a dial to a client-first port puts the hello in the SYN (Fast Open): the
/// configuration asks for it, or the device chose it and the server's record
/// says so (`zero_evasion::choice`).
fn fast_open_rule(stream: &StreamSettings) -> Option<fn(SocketAddr) -> bool> {
    use zero_config::SniMethod;
    if !zero_net::fastopen::supported() {
        return None;
    }
    match stream.evasion.sni_desync.as_ref()?.method {
        SniMethod::FastOpen => Some(|peer| zero_net::fastopen::client_first_port(peer.port())),
        // REALITY and ShadowTLS cannot take the empty record, and the pick
        // after the dial has to see the same ways as this question.
        SniMethod::Auto if hides_behind_own_handshake(stream) => Some(|peer| {
            zero_net::fastopen::client_first_port(peer.port())
                && zero_evasion::choice::wants_fast(peer, ways_towards(peer, false, true))
        }),
        SniMethod::Auto => Some(|peer| {
            zero_net::fastopen::client_first_port(peer.port())
                && zero_evasion::choice::wants_fast(peer, ways_towards(peer, true, true))
        }),
        _ => None,
    }
}

/// Whether the security layer reads the first record itself (REALITY,
/// ShadowTLS) and so drops a connection that opens with an empty one.
fn hides_behind_own_handshake(stream: &StreamSettings) -> bool {
    matches!(
        stream.security,
        zero_config::Security::Reality(_) | zero_config::Security::ShadowTls(_)
    )
}

/// The ways `auto` may hide a name from a filter towards `peer`, without Fast
/// Open (the dial decides that). Cloudflare's addresses let a hello with an
/// urgent byte, another record version or an empty record through and then
/// go quiet, so there only Fast Open and the decoy are left. `empty_ok` is
/// false for a security layer that cannot take the empty record, `decoy` is
/// what the caller found about the decoy.
fn ways_towards(peer: SocketAddr, empty_ok: bool, decoy: bool) -> zero_evasion::choice::Have {
    let odd = !crate::cdn_check::is_cloudflare_ip(peer.ip());
    zero_evasion::choice::Have {
        urgent: odd && zero_evasion::urgent::supported(),
        record: odd,
        empty: odd && empty_ok,
        fast: false,
        decoy,
    }
}

fn socket_options(stream: &StreamSettings) -> SocketOptions {
    SocketOptions {
        fast_open_if: fast_open_rule(stream),
        tcp_fast_open: stream.sockopt.tcp_fast_open,
        mark: stream.sockopt.mark,
        bind_address: stream.sockopt.bind_address,
        custom: stream.sockopt.custom.clone(),
        bind_interface: stream
            .sockopt
            .bind_interface
            .as_ref()
            .map(|s| s.to_string()),
        tcp_congestion: stream
            .sockopt
            .tcp_congestion
            .as_ref()
            .map(|s| s.to_string()),
        keepalive: stream.sockopt.keepalive,
        user_timeout_ms: stream.sockopt.user_timeout_ms,
        window_clamp: stream.sockopt.window_clamp,
        max_seg: stream.sockopt.max_seg,
        mptcp: stream.sockopt.mptcp,
        ..Default::default()
    }
}

/// `tcp` as a boxed stream, with whatever the outbound asks to be done to its
/// first write: a decoy ClientHello in front of it (`sniSpoof`), or its
/// fragment mask. A plain connection gets neither wrapper.
///
/// `injected` says a raw-socket decoy already went out for this connection,
/// which is the cheaper way where the process may open one. Otherwise the
/// name is hidden from the socket itself, by the method the configuration
/// names (`zero_config::SniMethod`): a decoy (`zero_evasion::decoy`) or an
/// urgent byte (`zero_evasion::urgent`). Left to the device, it is the
/// urgent byte, which costs nothing, and the decoy, which costs a round trip,
/// only for a server the urgent byte went unanswered at
/// (`zero_evasion::choice`). A system that can do neither leaves the
/// fragment mask, as before. These and the mask are not stacked: the mask
/// would cut the hello into pieces that neither of them can read a name out
/// of.
fn shaped(tcp: TcpStream, stream: &StreamSettings, injected: bool) -> BoxStream {
    shaped_with(tcp, stream, injected, &mut None)
}

/// The `legacy_version` the Record way writes into the hello itself, next to
/// the record header (`zero_evasion::record`). Servers read the field as
/// "TLS 1.2 or later", a filter that picks hellos out by it does not know the
/// value, and the two settings are separate gaps in it.
const ODD_HELLO_VERSION: u16 = 0x0304;

/// [`shaped`], also saying through `hello_version` what the TLS layer on top
/// has to write in the hello for the chosen way to hold.
fn shaped_with(
    tcp: TcpStream,
    stream: &StreamSettings,
    injected: bool,
    hello_version: &mut Option<u16>,
) -> BoxStream {
    use zero_config::SniMethod;
    if let Some(spoof) = stream.evasion.sni_desync.as_ref().filter(|_| !injected) {
        use zero_evasion::choice::{self, Way};
        let policy = zero_evasion::DecoyPolicy {
            name: spoof.fake_sni.clone(),
            fooling: match spoof.fooling {
                zero_config::DecoyFooling::Auto => zero_evasion::Fooling::Auto,
                zero_config::DecoyFooling::Md5 => zero_evasion::Fooling::Md5,
                zero_config::DecoyFooling::Ttl => zero_evasion::Fooling::Ttl,
            },
            ttl: spoof.ttl,
        };
        let urgent = zero_evasion::urgent::supported();
        // REALITY and ShadowTLS read the first record themselves and drop a
        // connection that opens with an empty one.
        let empty = !hides_behind_own_handshake(stream);
        // A socket whose SYN is still waiting for the hello (Fast Open) has
        // no peer to ask; the dial recorded it.
        let deferred = zero_net::fastopen::deferred(&tcp);
        let peer = zero_net::fastopen::peer_addr(&tcp);
        // On a kernel with no MD5 option the decoy is stopped by a hop limit,
        // which has to match the path. `zero_evasion::autottl` learns that
        // distance from the server itself, so the decoy counts as a possible
        // way here even when no hop count was configured; the value is settled
        // below once the way is Decoy. Where the kernel has MD5 (`ttl_available`
        // is then false) this stays off and no probe is ever sent.
        let learn_ttl = peer.is_some()
            && zero_evasion::autottl::supported()
            && zero_evasion::decoy::ttl_available()
            && matches!(
                policy.fooling,
                zero_evasion::Fooling::Auto | zero_evasion::Fooling::Ttl
            );
        let decoy = policy.sendable() || learn_ttl;
        let way = match spoof.method {
            SniMethod::Decoy => decoy.then_some(Way::Decoy),
            SniMethod::Urgent => urgent.then_some(Way::Urgent),
            SniMethod::Record => Some(Way::Record),
            SniMethod::EmptyRecord => empty.then_some(Way::Empty),
            SniMethod::FastOpen => deferred.then_some(Way::Fast),
            // The free ways first, the decoy where they went unanswered
            // (`zero_evasion::choice`). Without a peer address there is no
            // memory to ask, so the urgent byte it is. A deferred socket can
            // only carry the hello in its SYN: it was dialled for that.
            SniMethod::Auto if deferred => Some(Way::Fast),
            SniMethod::Auto => match peer {
                Some(peer) => {
                    let ways = ways_towards(peer, empty, decoy);
                    if zero_evasion::choice::wants_fast(peer, ways) {
                        // The dial asked for Fast Open and the server gave
                        // none: leave it alone for a while.
                        zero_evasion::choice::no_fast(peer);
                    }
                    choice::pick(peer, ways)
                }
                None => Some(if urgent { Way::Urgent } else { Way::Record }),
            },
        };
        match (way, spoof.method, peer) {
            (Some(Way::Decoy), ..) => {
                // Settle the hop limit the TTL decoy needs. A distance learned
                // from the path beats the configured guess; on a cache miss
                // `fake_ttl` starts one background probe and this connection
                // falls back to the urgent byte, so the next one to this server
                // finds the answer ready.
                let mut policy = policy;
                if learn_ttl {
                    if let Some(ttl) = peer.and_then(|p| zero_evasion::autottl::fake_ttl(p.ip())) {
                        policy.ttl = ttl;
                    }
                }
                if policy.sendable() {
                    return boxed(zero_evasion::DecoyStream::new(tcp, policy));
                }
                if urgent {
                    return boxed(zero_evasion::UrgentStream::new(tcp));
                }
            }
            // Only a way the device chose is watched: one the configuration
            // asked for is kept whatever happens.
            (Some(Way::Fast), SniMethod::Auto, Some(peer)) => {
                return boxed(choice::Watched::new(tcp, peer, Way::Fast))
            }
            (Some(Way::Fast), ..) => return boxed(tcp),
            (Some(Way::Urgent), SniMethod::Auto, Some(peer)) => {
                return boxed(choice::Watched::new(
                    zero_evasion::UrgentStream::new(tcp),
                    peer,
                    Way::Urgent,
                ))
            }
            (Some(Way::Urgent), ..) => return boxed(zero_evasion::UrgentStream::new(tcp)),
            (Some(Way::Record), SniMethod::Auto, Some(peer)) => {
                *hello_version = Some(ODD_HELLO_VERSION);
                return boxed(choice::Watched::new(
                    zero_evasion::RecordVersionStream::new(tcp),
                    peer,
                    Way::Record,
                ));
            }
            (Some(Way::Record), ..) => {
                *hello_version = Some(ODD_HELLO_VERSION);
                return boxed(zero_evasion::RecordVersionStream::new(tcp));
            }
            (Some(Way::Empty), SniMethod::Auto, Some(peer)) => {
                return boxed(choice::Watched::new(
                    zero_evasion::EmptyRecordStream::new(tcp),
                    peer,
                    Way::Empty,
                ))
            }
            (Some(Way::Empty), ..) => return boxed(zero_evasion::EmptyRecordStream::new(tcp)),
            (None, ..) => {}
        }
    }
    // Two masks stack as they do in Xray: the one underneath cuts up what
    // the one on top writes (an empty record and a re-framed hello in one
    // write, then split across TCP segments, is the pairing in use).
    let evasion = &stream.evasion;
    match (&evasion.tcp_fragment, &evasion.tcp_fragment_under) {
        (Some(top), Some(under)) => boxed(FragmentStream::new(
            FragmentStream::new(tcp, fragment_policy(under)),
            fragment_policy(top),
        )),
        (Some(only), None) | (None, Some(only)) => {
            boxed(FragmentStream::new(tcp, fragment_policy(only)))
        }
        (None, None) => boxed(tcp),
    }
}

fn fragment_policy(f: &zero_config::FragmentConfig) -> FragmentPolicy {
    let millis =
        |d: &zero_config::RangeDuration| (d.min.as_millis() as i64, d.max.as_millis() as i64);
    FragmentPolicy {
        packets: match f.packets {
            FragmentPackets::TlsHello => Packets::TlsHello,
            FragmentPackets::TlsSni => Packets::TlsSni,
            FragmentPackets::Range { from, to } => Packets::Range {
                from: from as u64,
                to: to as u64,
            },
        },
        length_min: f.length.min as i64,
        length_max: f.length.max as i64,
        interval_min_ms: f.delay.min.as_millis() as i64,
        interval_max_ms: f.delay.max.as_millis() as i64,
        max_split_min: f.max_split.min as i64,
        max_split_max: f.max_split.max as i64,
        empty_records: f.empty_records,
        lead_lengths: f
            .lead_lengths
            .iter()
            .map(|l| (i64::from(l.min), i64::from(l.max)))
            .collect(),
        lead_delays: f.lead_delays.iter().map(millis).collect(),
    }
}

/// The keepalive shape for this stream, if the planner or the operator asked
/// for one.
///
/// Applied at the outermost carrier that owns a legal no-op frame — a
/// WebSocket's Ping, or REALITY's own TLS 1.3 record layer. Ordinary
/// certificate TLS over the rustls backend is deliberately left out: rustls
/// offers no way to emit a zero-length application-data record, and padding
/// the tunnel with real bytes would corrupt it. That gap is a consequence of
/// not owning that stack, and it is why REALITY — which Zray does own — gets
/// the better half of this remedy.
fn keepalive_policy(stream: &StreamSettings) -> Option<zero_evasion::KeepalivePolicy> {
    let keepalive = stream.evasion.keepalive.as_ref()?;
    Some(zero_evasion::KeepalivePolicy {
        idle_after: keepalive.idle_after,
        max_flow_lifetime: keepalive.max_flow_lifetime,
    })
}

/// Which SNI to present, and which `Host:` header to send.
pub(crate) fn tls_params(stream: &StreamSettings, fallback_host: &str) -> Option<TlsParams> {
    match &stream.security {
        Security::None => None,
        Security::Tls(t) => {
            let sni = t
                .server_name
                .as_deref()
                .unwrap_or(fallback_host)
                .to_string();
            let profile = FingerprintProfile::parse(fingerprint_family_name(&t.fingerprint))
                .unwrap_or_default();
            let mut p = TlsParams::new(sni)
                .with_profile(profile)
                .with_insecure(t.allow_insecure)
                .with_pinned_certs(t.pinned_cert_sha256.clone())
                .with_verify_names(t.verify_names.iter().map(|name| name.to_string()).collect());
            if let Some(path) = &t.key_log_file {
                p = p.with_key_log(path.to_string());
            }
            p = p.with_fingerprint_name(t.fingerprint.name());
            if matches!(
                stream.transport,
                Transport::WebSocket(_) | Transport::HttpUpgrade(_)
            ) {
                // These upgrade an HTTP/1.1 request, so HTTP/1.1 is the only
                // protocol to offer: a server that is offered `h2` picks it
                // and answers the upgrade in HTTP/2 frames, which this
                // client cannot read (Cloudflare does exactly that). Panels
                // write `h2,http/1.1` anyway; Xray drops the `h2` here too.
                let kept: Vec<String> = t
                    .alpn
                    .iter()
                    .filter(|a| &***a != "h2")
                    .map(|a| a.to_string())
                    .collect();
                p = if kept.is_empty() {
                    p.with_alpn(&["http/1.1"])
                } else {
                    p.with_alpn(&kept)
                };
            } else if !t.alpn.is_empty() {
                p = p.with_alpn(&t.alpn.iter().map(|a| a.to_string()).collect::<Vec<_>>());
            } else if matches!(stream.transport, Transport::Grpc(_)) {
                p = p.with_alpn(&["h2"]);
            } else if matches!(
                &stream.transport,
                Transport::Xhttp(x) if x.xhttp_http_version == XhttpHttpVersion::Http2
            ) {
                // Xray's default for XHTTP without an ALPN list: offer both,
                // speak HTTP/2.
                p = p.with_alpn(&["h2", "http/1.1"]);
            }
            if !t.trusted_roots.is_empty() {
                p = p.with_extra_roots(
                    t.trusted_roots
                        .iter()
                        .map(|anchor| anchor.to_vec())
                        .collect(),
                );
            }
            if let Some(ech) = &t.ech {
                if ech.config_list.is_empty() {
                    return None;
                }
                p = p.with_ech(
                    ech.config_list.to_vec(),
                    ech.server_name.as_deref().map(str::to_owned),
                );
            }
            Some(p)
        }
        // REALITY is not a rustls connection; it is handled separately and is
        // rejected earlier for carriers that cannot host it.
        Security::Reality(_) => None,
        // ShadowTLS builds its own browser-shaped ClientHello and never runs a
        // rustls session, so there is nothing to hand to the TLS layer.
        Security::ShadowTls(_) => None,
    }
}

fn fingerprint_family_name(f: &zero_config::Fingerprint) -> &'static str {
    use zero_config::Fingerprint as F;
    match f {
        F::Chrome => "chrome",
        F::Firefox => "firefox",
        F::Safari => "safari",
        F::Edge => "edge",
        F::Ios => "ios",
        F::Android => "android",
        F::Random | F::Randomized => "chrome",
        F::Named(name) => {
            let name = name.as_ref();
            if name.starts_with("hellofirefox") {
                "firefox"
            } else if name.starts_with("hellosafari") {
                "safari"
            } else if name.starts_with("helloios") {
                "ios"
            } else if name.starts_with("helloedge") {
                "edge"
            } else if name.starts_with("helloandroid") {
                "android"
            } else {
                "chrome"
            }
        }
        F::Unshaped => "unshaped",
    }
}

/// Longest an outbound may take from a connected socket to a usable stream.
/// The TCP dial has its own bound; this one covers TLS or REALITY, the
/// transport upgrade and the protocol handshake, so a server that accepts
/// and then goes quiet cannot hold a session open indefinitely.
const OUTBOUND_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) async fn within_setup_deadline<T>(
    setup: impl std::future::Future<Output = Result<T, Failure>>,
) -> Result<T, Failure> {
    tokio::time::timeout(OUTBOUND_SETUP_TIMEOUT, setup)
        .await
        .unwrap_or_else(|_| {
            Err(
                Failure::new(FailureKind::TlsTimeout, Stage::TlsStarted).with_detail(format!(
                    "outbound handshake did not finish within {} s",
                    OUTBOUND_SETUP_TIMEOUT.as_secs()
                )),
            )
        })
}

/// Open a proxied connection to `destination` through `outbound`.
pub async fn connect(outbound: &Outbound, destination: &Destination) -> Result<BoxStream, Failure> {
    if let OutboundProtocol::Tor(tor) = &outbound.protocol {
        return connect_tor(tor, destination).await;
    }
    if let OutboundProtocol::MasterDns(masterdns) = &outbound.protocol {
        return crate::masterdns::connect(masterdns, destination).await;
    }
    let (address, port) = outbound.endpoint().ok_or_else(|| {
        Failure::new(FailureKind::LocalPolicy, Stage::Resolving)
            .with_detail(format!("outbound {} has no endpoint", outbound.tag))
    })?;

    let t0 = std::time::Instant::now();
    let addrs = resolve_endpoint(&address, port).await?;
    within_setup_deadline(connect_resolved(
        outbound,
        destination,
        address,
        port,
        addrs,
        t0,
        None,
    ))
    .await
}

/// Open an outbound after resolving its proxy endpoint through the managed
/// resolver. Server-side sessions use this entry point so a configured DNS
/// policy is not bypassed by the operating system resolver.
pub async fn connect_with_resolver(
    outbound: &Outbound,
    destination: &Destination,
    resolver: &zero_dns::Resolver,
) -> Result<BoxStream, Failure> {
    if let OutboundProtocol::Tor(tor) = &outbound.protocol {
        return connect_tor(tor, destination).await;
    }
    if let OutboundProtocol::MasterDns(masterdns) = &outbound.protocol {
        return crate::masterdns::connect(masterdns, destination).await;
    }
    let (address, port) = outbound.endpoint().ok_or_else(|| {
        Failure::new(FailureKind::LocalPolicy, Stage::Resolving)
            .with_detail(format!("outbound {} has no endpoint", outbound.tag))
    })?;
    let outbound = materialize_ech(outbound, resolver, &address.host_string()).await?;
    let t0 = std::time::Instant::now();
    let addrs = resolver
        .resolve_server(&address)
        .await
        .map_err(|error| {
            Failure::new(FailureKind::DnsNoData, Stage::Resolving).with_detail(error.to_string())
        })?
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(Failure::new(FailureKind::DnsNoData, Stage::Resolving)
            .with_detail(format!("no addresses for {}", address.host_string())));
    }
    within_setup_deadline(connect_resolved(
        &outbound,
        destination,
        address,
        port,
        addrs,
        t0,
        Some(resolver),
    ))
    .await
}

/// Open a stream through the embedded Tor client.
///
/// Deliberately outside `within_setup_deadline`: a cold Tor start downloads the
/// network directory and legitimately takes longer than any other outbound's
/// handshake, so `zero_tor` applies its own, longer bounds. The name is handed
/// to Tor unresolved so the lookup happens at the exit, not on this network.
#[cfg(feature = "tor")]
async fn connect_tor(
    tor: &zero_config::TorConfig,
    destination: &Destination,
) -> Result<BoxStream, Failure> {
    if destination.network != zero_core::Network::Tcp {
        return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
            .with_detail("Tor carries TCP only"));
    }
    zero_tor::connect(tor, &destination.address, destination.port)
        .await
        .map(boxed)
        .map_err(|error| {
            Failure::new(FailureKind::TcpUnreachable, Stage::SocketConnected).with_detail(error)
        })
}

#[cfg(not(feature = "tor"))]
async fn connect_tor(
    _tor: &zero_config::TorConfig,
    _destination: &Destination,
) -> Result<BoxStream, Failure> {
    Err(Failure::new(FailureKind::LocalPolicy, Stage::Resolving)
        .with_detail("this build was made without Tor support; use a build with the `tor` feature"))
}

/// The tunnel parameters of a WireGuard/AmneziaWG outbound.
pub fn wireguard_stack_params(
    wireguard: &zero_config::AmneziaWireguardConfig,
) -> zero_protocol::wg_stack::WgStackParams {
    use zero_protocol::amnezia::{AmneziaParams, HeaderRange, RangeU16};
    let range = |r: zero_config::AmneziaHeaderRange| HeaderRange {
        min: r.min,
        max: r.max,
    };
    zero_protocol::wg_stack::WgStackParams {
        private_key: wireguard.private_key,
        peer_public_key: wireguard.peer_public_key,
        preshared_key: wireguard.preshared_key,
        addresses: vec![wireguard.tunnel_address],
        persistent_keepalive: wireguard.persistent_keepalive,
        obfuscation: AmneziaParams {
            junk_count: wireguard.junk_count,
            junk_size: RangeU16 {
                min: wireguard.junk_min,
                max: wireguard.junk_max,
            },
            init_padding: RangeU16::fixed(wireguard.s1),
            response_padding: RangeU16::fixed(wireguard.s2),
            cookie_padding: RangeU16::fixed(wireguard.s3),
            transport_padding: RangeU16::fixed(wireguard.s4),
            init_header: range(wireguard.h1),
            response_header: range(wireguard.h2),
            cookie_header: range(wireguard.h3),
            transport_header: range(wireguard.h4),
        },
        reserved: wireguard.reserved,
        // Names are resolved inside the tunnel (Cloudflare's resolver, which
        // WARP and most WireGuard exits reach), never on the local network.
        dns: if wireguard.tunnel_address.is_ipv4() {
            "1.1.1.1:53".parse().expect("a literal address")
        } else {
            "[2606:4700:4700::1111]:53"
                .parse()
                .expect("a literal address")
        },
    }
}

async fn connect_resolved(
    outbound: &Outbound,
    destination: &Destination,
    address: Address,
    _port: u16,
    addrs: Vec<SocketAddr>,
    t0: std::time::Instant,
    resolver: Option<&zero_dns::Resolver>,
) -> Result<BoxStream, Failure> {
    if outbound.mux.enabled {
        if destination.network != zero_core::Network::Tcp {
            return Err(
                Failure::new(FailureKind::LocalPolicy, Stage::RequestSent).with_detail(
                    "VLESS Mux UDP sessions use the datagram exchange path, not a byte stream",
                ),
            );
        }
        if outbound.mux.max_concurrency == 0 || outbound.mux.max_concurrency > 1 {
            return connect_mux_pooled(outbound, destination, address, addrs, resolver).await;
        }
    }
    if let OutboundProtocol::Tide(tide) = &outbound.protocol {
        return connect_tide(outbound, tide, destination, &address, addrs).await;
    }
    if let OutboundProtocol::AmneziaWireguard(wireguard) = &outbound.protocol {
        // Streams ride a user-space TCP stack inside the tunnel, which the
        // outbound's UDP datagrams share (one WireGuard session per peer).
        let peer = *addrs.first().ok_or_else(|| {
            Failure::new(FailureKind::DnsNoData, Stage::Resolving)
                .with_detail("WireGuard peer has no address")
        })?;
        let stack = crate::warp::tunnel_for(wireguard, Some(peer), resolver)
            .await
            .map_err(|error| {
                Failure::new(FailureKind::LocalPolicy, Stage::SocketConnected).with_detail(error)
            })?;
        // The tunnel alone, or through the exits the account lists, each the
        // other's failsafe; the tunnel reports how connections went so route
        // selection can learn from it.
        let connected = crate::warp::connect(wireguard, &stack, destination).await;
        return connected.map_err(|error| {
            Failure::new(FailureKind::TcpTimeout, Stage::RequestSent).with_detail(error)
        });
    }
    if let OutboundProtocol::Hysteria2(hysteria) = &outbound.protocol {
        let fallback_host = address.host_string();
        let tls = tls_params(&outbound.stream, &fallback_host).ok_or_else(|| {
            Failure::new(FailureKind::LocalPolicy, Stage::TlsStarted)
                .with_detail("Hysteria2 requires ordinary certificate TLS")
        })?;
        let shape = hysteria2_shape(outbound, hysteria).map_err(|error| {
            Failure::new(FailureKind::LocalPolicy, Stage::TlsStarted).with_detail(error)
        })?;
        return zero_transport::hysteria2::connect(
            &addrs,
            &tls,
            &hysteria.password,
            &shape,
            destination,
        )
        .await
        .map_err(|error| {
            Failure::new(FailureKind::ProtocolRejected, Stage::RequestSent).with_detail(error)
        });
    }
    if let OutboundProtocol::Tuic(tuic) = &outbound.protocol {
        let fallback_host = address.host_string();
        let tls = tls_params(&outbound.stream, &fallback_host).ok_or_else(|| {
            Failure::new(FailureKind::LocalPolicy, Stage::TlsStarted)
                .with_detail("TUIC requires ordinary certificate TLS")
        })?;
        if destination.network == zero_core::Network::Udp {
            return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
                .with_detail("TUIC UDP is dispatched through the datagram exchange"));
        }
        return zero_transport::tuic::connect(
            &addrs,
            &tls,
            &tuic.uuid,
            &tuic.password,
            destination,
        )
        .await
        .map_err(|error| {
            Failure::new(FailureKind::ProtocolRejected, Stage::RequestSent).with_detail(error)
        });
    }
    if let OutboundProtocol::Juicity(juicity) = &outbound.protocol {
        let fallback_host = address.host_string();
        let tls = tls_params(&outbound.stream, &fallback_host).ok_or_else(|| {
            Failure::new(FailureKind::LocalPolicy, Stage::TlsStarted)
                .with_detail("Juicity requires ordinary certificate TLS")
        })?;
        if destination.network == zero_core::Network::Udp {
            return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
                .with_detail("Juicity UDP is dispatched through the datagram exchange"));
        }
        // Boxed: this future's state would otherwise sit in this function's
        // frame, and chained dialers nest frames (see the dialer-proxy tests).
        return Box::pin(zero_transport::juicity::connect(
            &addrs,
            &tls,
            &juicity.uuid,
            &juicity.password,
            destination,
        ))
        .await
        .map_err(|error| {
            Failure::new(FailureKind::ProtocolRejected, Stage::RequestSent).with_detail(error)
        });
    }
    if matches!(
        &outbound.stream.transport,
        Transport::Xhttp(zero_config::WebSocketConfig {
            xhttp_http_version: XhttpHttpVersion::Http1 | XhttpHttpVersion::Http2,
            xhttp_mode: XhttpMode::Auto | XhttpMode::StreamUp | XhttpMode::PacketUp,
            ..
        })
    ) {
        let stream = connect_xhttp_split(outbound, destination, &address, &addrs, resolver).await?;
        if outbound.mux.enabled {
            return zero_protocol::mux::spawn_client(stream, destination.clone())
                .await
                .map_err(|error| {
                    Failure::new(FailureKind::ProtocolRejected, Stage::RequestSent)
                        .with_detail(format!("VLESS Mux: {error}"))
                });
        }
        return Ok(stream);
    }
    if matches!(
        &outbound.stream.transport,
        Transport::Xhttp(zero_config::WebSocketConfig {
            xhttp_http_version: XhttpHttpVersion::Http3,
            ..
        })
    ) {
        return connect_xhttp_h3(outbound, destination, &address, &addrs).await;
    }
    let t_resolve = t0.elapsed();

    let out = if reuses_h2_stream_one(outbound) {
        connect_xhttp_stream_one(outbound, destination, &address, &addrs).await?
    } else {
        let t1 = std::time::Instant::now();
        let tcp = dial_tcp(
            &addrs,
            &race_policy(&outbound.stream),
            &socket_options(&outbound.stream),
        )
        .await?;
        let t_dial = t1.elapsed();

        let t2 = std::time::Instant::now();
        let out = build_stack(outbound, destination, tcp.stream, &address.host_string()).await;
        tracing::debug!(
            resolve_ms = t_resolve.as_millis(),
            dial_ms = t_dial.as_millis(),
            stack_ms = t2.elapsed().as_millis(),
            candidates = addrs.len(),
            attempts = tcp.attempts,
            "outbound timing"
        );
        out?
    };
    if outbound.mux.enabled {
        return zero_protocol::mux::spawn_client(out, destination.clone())
            .await
            .map_err(|error| {
                Failure::new(FailureKind::ProtocolRejected, Stage::RequestSent)
                    .with_detail(format!("VLESS Mux: {error}"))
            });
    }
    Ok(out)
}

/// The name Cloudflare serves its one shared ECH list under. Every site on
/// Cloudflare accepts a hello encrypted to it, so it stands in for a site
/// whose own HTTPS record has none (a Worker's custom domain, a name whose
/// zone has ECH switched off in the listing but not at the edge).
const SHARED_ECH_NAME: &str = "cloudflare-ech.com";

/// The outbound with its ECH configuration list filled in, borrowed unchanged
/// when there is nothing to discover (every connection that does not use
/// ECH discovery, i.e. almost all of them, avoids a deep clone).
///
/// The list is looked up under the name the config gives (`query_name`), else
/// the TLS server name, and then under [`SHARED_ECH_NAME`]. The fallback
/// cannot downgrade anything: a server that is not Cloudflare ignores a hello
/// encrypted to Cloudflare's key, and ECH is mandatory once it is on, so the
/// handshake fails instead of going out in the clear.
async fn materialize_ech<'a>(
    outbound: &'a Outbound,
    resolver: &zero_dns::Resolver,
    fallback_host: &str,
) -> Result<std::borrow::Cow<'a, Outbound>, Failure> {
    let needs_discovery = matches!(
        &outbound.stream.security,
        Security::Tls(zero_config::TlsConfig {
            ech: Some(ech), ..
        }) if ech.config_list.is_empty()
    );
    if !needs_discovery {
        return Ok(std::borrow::Cow::Borrowed(outbound));
    }
    let public_name = match &outbound.stream.security {
        Security::Tls(tls) => tls
            .ech
            .as_ref()
            .and_then(|ech| ech.query_name.as_deref())
            .or(tls.server_name.as_deref())
            .unwrap_or(fallback_host)
            .to_string(),
        _ => unreachable!("ECH discovery requires certificate TLS"),
    };
    let strategy = resolver.settings().query_strategy;
    let mut found = resolver
        .lookup_ech_config_list(&public_name, strategy)
        .await;
    if found.is_err() && !public_name.eq_ignore_ascii_case(SHARED_ECH_NAME) {
        if let Ok(list) = resolver
            .lookup_ech_config_list(SHARED_ECH_NAME, strategy)
            .await
        {
            found = Ok(list);
        }
    }
    let config_list = found.map_err(|error| {
        Failure::new(FailureKind::DnsNoData, Stage::Resolving)
            .with_detail(format!("ECH discovery for {public_name}: {error}"))
    })?;
    let mut compiled = outbound.clone();
    if let Security::Tls(tls) = &mut compiled.stream.security {
        if let Some(ech) = &mut tls.ech {
            ech.config_list = config_list.into_boxed_slice();
        }
    }
    Ok(std::borrow::Cow::Owned(compiled))
}

type TideClients = Mutex<HashMap<String, Arc<zero_transport::tide::Client>>>;
static TIDE_CLIENTS: OnceLock<TideClients> = OnceLock::new();

/// Open a stream through a Tide server.
///
/// One client is kept per server (and per set of addresses it resolved to):
/// it holds the session and the HTTP/2 connections under it, so every stream
/// after the first costs no handshake at all. The client closes its own
/// connections when idle and reconnects when they break; all this function
/// does is find it or make it.
async fn connect_tide(
    outbound: &Outbound,
    tide: &zero_config::TideConfig,
    destination: &Destination,
    address: &Address,
    addrs: Vec<SocketAddr>,
) -> Result<BoxStream, Failure> {
    if destination.network != zero_core::Network::Tcp {
        return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
            .with_detail("ZeroV1 carries UDP only when its link has dg=1 (a datagram flow, not a byte stream)"));
    }
    tide_client(outbound, tide, address, addrs)
        .open(destination.clone())
        .await
        .map(boxed)
        .map_err(|error| {
            Failure::from_io(&error, Stage::RequestSent).with_detail(format!("Tide: {error}"))
        })
}

/// Open a UDP flow through a Tide server: the persistent counterpart of the
/// per-datagram exchanges other protocols use here. The flow lives as long as
/// its caller keeps it; the session under it is shared with the TCP streams.
/// Fails with `Unsupported` when the link does not ask for datagrams or the
/// server does not grant them.
pub async fn connect_tide_udp(
    outbound: &Outbound,
    first: &Destination,
    resolver: &zero_dns::Resolver,
) -> Result<zero_protocol::tide::UdpFlow, String> {
    let OutboundProtocol::Tide(tide) = &outbound.protocol else {
        return Err("not a Tide outbound".into());
    };
    if !tide.datagrams {
        return Err("this ZeroV1 link does not ask for UDP (no dg=1)".into());
    }
    let (address, port) = outbound
        .endpoint()
        .ok_or_else(|| "Tide outbound has no endpoint".to_string())?;
    let addrs: Vec<SocketAddr> = resolver
        .resolve_server(&address)
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    if addrs.is_empty() {
        return Err("Tide server has no address".into());
    }
    tide_client(outbound, tide, &address, addrs)
        .open_udp(first.clone())
        .await
        .map_err(|error| format!("Tide: {error}"))
}

/// The client for one Tide server, made on first use and kept: it owns the
/// session and the HTTP/2 connections under it.
fn tide_client(
    outbound: &Outbound,
    tide: &zero_config::TideConfig,
    address: &Address,
    addrs: Vec<SocketAddr>,
) -> Arc<zero_transport::tide::Client> {
    let key = mux_pool_key(outbound, address, &addrs);
    let host = address.host_string();
    // Tide is HTTP/2 whatever the profile says about ALPN.
    let shaped = Arc::new(tide_shaped(outbound));
    let dial: zero_transport::tide::Dialer = {
        let host = host.clone();
        Arc::new(move || {
            let (outbound, addrs, host) = (shaped.clone(), addrs.clone(), host.clone());
            Box::pin(async move {
                let tcp = dial_tcp(
                    &addrs,
                    &race_policy(&outbound.stream),
                    &socket_options(&outbound.stream),
                )
                .await
                .map_err(|failure| std::io::Error::other(failure.to_string()))?;
                protect_socket(&outbound, tcp.stream, &host)
                    .await
                    .map_err(|failure| std::io::Error::other(failure.to_string()))
            })
        })
    };
    tide_client_with(outbound, tide, key, &host, dial)
}

/// `outbound` with HTTP/2 as its only ALPN: what every Tide server speaks.
fn tide_shaped(outbound: &Outbound) -> Outbound {
    let mut shaped = outbound.clone();
    if let Security::Tls(tls) = &mut shaped.stream.security {
        tls.alpn = vec!["h2".into()];
    }
    shaped
}

/// The Tide client kept under `key`, or a new one that connects with `dial`.
/// `host` is the server's address, used as the HTTP authority when the link
/// names no TLS server name.
fn tide_client_with(
    outbound: &Outbound,
    tide: &zero_config::TideConfig,
    key: String,
    host: &str,
    dial: zero_transport::tide::Dialer,
) -> Arc<zero_transport::tide::Client> {
    let existing = {
        let clients = TIDE_CLIENTS.get_or_init(Default::default);
        let clients = clients.lock().unwrap_or_else(|p| p.into_inner());
        clients.get(&key).cloned()
    };
    if let Some(client) = existing {
        return client;
    }
    let client = zero_transport::tide::Client::new(tide_client_config(outbound, tide, host), dial);
    let clients = TIDE_CLIENTS.get_or_init(Default::default);
    let mut clients = clients.lock().unwrap_or_else(|p| p.into_inner());
    // Profiles come and go; keep the map from growing with them.
    if clients.len() >= 64 {
        clients.clear();
    }
    clients.entry(key).or_insert(client).clone()
}

/// How a Hysteria 2 outbound's QUIC carrier is shaped: its Salamander
/// password, its port-hopping plan and the QUIC parameters of its
/// `finalmask`. The result is the same for the same outbound, so the pooled
/// connection it makes is shared.
pub(crate) fn hysteria2_shape(
    outbound: &Outbound,
    hysteria: &zero_config::Hysteria2Config,
) -> Result<zero_transport::quic_shape::QuicShape, String> {
    use std::time::Duration;
    use zero_transport::quic_shape::{Congestion, QuicParams, QuicShape};
    let evasion = &outbound.stream.evasion;
    let salamander = hysteria
        .obfs_password
        .as_deref()
        .map(zero_transport::salamander::Salamander::new)
        .transpose()?;
    let hop = evasion
        .udp_hop
        .as_ref()
        .map(|hop| zero_transport::hop::Hop {
            ports: hop.all_ports(),
            interval: (
                Duration::from_secs(hop.interval_secs.0.into()),
                Duration::from_secs(hop.interval_secs.1.into()),
            ),
        });
    let params = evasion
        .quic
        .as_ref()
        .map_or_else(QuicParams::default, |quic| {
            let secs = |value: Option<u32>| value.map(|s| Duration::from_secs(s.into()));
            QuicParams {
                congestion: match quic.congestion {
                    zero_config::QuicCongestion::Default => Congestion::Default,
                    zero_config::QuicCongestion::Reno => Congestion::Reno,
                    zero_config::QuicCongestion::Bbr => Congestion::Bbr,
                    zero_config::QuicCongestion::Brutal => Congestion::Brutal,
                    zero_config::QuicCongestion::ForceBrutal => Congestion::ForceBrutal,
                },
                up_bytes_per_sec: quic.up_bytes_per_sec,
                down_bytes_per_sec: quic.down_bytes_per_sec,
                init_stream_window: quic.init_stream_window,
                max_stream_window: quic.max_stream_window,
                init_connection_window: quic.init_connection_window,
                max_connection_window: quic.max_connection_window,
                max_idle: secs(quic.max_idle_secs),
                keep_alive: secs(quic.keep_alive_secs),
                disable_mtu_discovery: quic.disable_mtu_discovery,
                max_incoming_streams: quic.max_incoming_streams,
            }
        });
    Ok(QuicShape {
        salamander,
        hop,
        params,
    })
}

/// The transport settings a Tide link stands for: the link's own choices where
/// it makes them, Tide's defaults everywhere else.
///
/// The HTTP authority is, in order of preference, the link's `authority`, the
/// TLS server name, then the server's address; a CDN front sets the first two
/// apart (`sni=front.example`, `authority=real.example`).
fn tide_client_config(
    outbound: &Outbound,
    tide: &zero_config::TideConfig,
    host: &str,
) -> zero_transport::tide::ClientConfig {
    use std::time::Duration;
    use zero_transport::tide::{Look, Rotation, Tuning};
    let t = &tide.tuning;
    let host = t
        .authority
        .as_deref()
        .map(str::to_string)
        .unwrap_or_else(|| match &outbound.stream.security {
            Security::Tls(tls) => tls
                .server_name
                .as_deref()
                .map_or_else(|| host.to_string(), str::to_string),
            _ => host.to_string(),
        });
    let defaults = Tuning::default();
    let look = Look {
        user_agent: t
            .user_agent
            .as_deref()
            .map_or(defaults.look.user_agent, str::to_string),
        language: t
            .language
            .as_deref()
            .map_or(defaults.look.language, str::to_string),
        headers: t
            .headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
    };
    let rotation = tide.rotate.then(|| {
        let base = Rotation::default();
        let (min_age, max_age) = t
            .age_secs
            .map_or((base.min_age, base.max_age), |(low, high)| {
                (
                    Duration::from_secs(low.into()),
                    Duration::from_secs(high.into()),
                )
            });
        Rotation {
            min_age,
            max_age,
            max_bytes: t.volume_mb.map_or(base.max_bytes, |mb| u64::from(mb) << 20),
        }
    });
    zero_transport::tide::ClientConfig {
        host,
        path: tide.path.to_string(),
        server_public: tide.server_key,
        user: tide.user,
        split: tide.split,
        linger: match (t.linger_ms, tide.packet_upload) {
            (Some(ms), _) => Duration::from_millis(ms.into()),
            (None, true) => Duration::ZERO,
            (None, false) => Duration::from_secs(2),
        },
        lane: tide.datagrams,
        rotation,
        tuning: Tuning {
            look,
            down_pipes: t.down_pipes.map_or(defaults.down_pipes, usize::from),
            up_pipes: t.up_pipes.map_or(defaults.up_pipes, usize::from),
            ping: t
                .ping_secs
                .map_or(defaults.ping, |s| Duration::from_secs(s.into())),
            idle: t
                .idle_secs
                .map_or(defaults.idle, |s| Duration::from_secs(s.into())),
        },
    }
}

/// How a Tide client reaches its server through other hops: each call opens
/// a new connection to the Tide server's address, carried by the hops before
/// it, and returns it as it left the last of them (no TLS yet).
pub type TideCarrier = Arc<
    dyn Fn() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<BoxStream, Failure>> + Send>,
        > + Send
        + Sync,
>;

/// Open a stream through a Tide server that is itself reached through other
/// outbounds (`dialerProxy`).
///
/// Tide keeps several HTTP/2 connections and replaces them as it rotates
/// them, so it cannot run over the one carried stream [`connect_over`] gets.
/// `carrier` is called for every connection the client wants; each answer is
/// a fresh stream to the Tide server's address, which gets TLS (HTTP/2) here.
/// `route` names the hops the carrier goes through, so two chains to the same
/// server never share a client.
pub async fn connect_tide_via(
    outbound: &Outbound,
    destination: &Destination,
    route: &str,
    carrier: TideCarrier,
) -> Result<BoxStream, Failure> {
    if destination.network != zero_core::Network::Tcp {
        return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
            .with_detail("ZeroV1 carries UDP only when its link has dg=1 (a datagram flow, not a byte stream)"));
    }
    tide_client_via(outbound, route, carrier)?
        .open(destination.clone())
        .await
        .map(boxed)
        .map_err(|error| {
            Failure::from_io(&error, Stage::RequestSent).with_detail(format!("Tide: {error}"))
        })
}

/// [`connect_tide_udp`] for a Tide server reached through other outbounds:
/// the same client as [`connect_tide_via`] makes, so streams and datagrams
/// share one session.
pub async fn connect_tide_udp_via(
    outbound: &Outbound,
    first: &Destination,
    route: &str,
    carrier: TideCarrier,
) -> Result<zero_protocol::tide::UdpFlow, String> {
    let OutboundProtocol::Tide(tide) = &outbound.protocol else {
        return Err("not a Tide outbound".into());
    };
    if !tide.datagrams {
        return Err("this ZeroV1 link does not ask for UDP (no dg=1)".into());
    }
    tide_client_via(outbound, route, carrier)
        .map_err(|failure| failure.to_string())?
        .open_udp(first.clone())
        .await
        .map_err(|error| format!("Tide: {error}"))
}

/// The client for a Tide server whose connections come from `carrier`.
fn tide_client_via(
    outbound: &Outbound,
    route: &str,
    carrier: TideCarrier,
) -> Result<Arc<zero_transport::tide::Client>, Failure> {
    let OutboundProtocol::Tide(tide) = &outbound.protocol else {
        return Err(
            Failure::new(FailureKind::LocalPolicy, Stage::SocketConnected)
                .with_detail(format!("outbound {} is not a Tide outbound", outbound.tag)),
        );
    };
    let host = outbound
        .endpoint()
        .map(|(address, _)| address.host_string())
        .unwrap_or_default();
    let key = mux_pool_key_of(&format!("{outbound:?}|via|{route}"));
    let shaped = Arc::new(tide_shaped(outbound));
    let dial: zero_transport::tide::Dialer = Arc::new(move || {
        let (shaped, carrier) = (shaped.clone(), carrier.clone());
        Box::pin(async move {
            let carried = carrier()
                .await
                .map_err(|failure| std::io::Error::other(failure.to_string()))?;
            secure_over(&shaped, carried)
                .await
                .map(|(stream, _)| stream)
                .map_err(|failure| std::io::Error::other(failure.to_string()))
        })
    });
    Ok(tide_client_with(outbound, tide, key, &host, dial))
}

/// The dialer a Tide relay uses to reach its egress: an ordinary client
/// connection (TCP, then certificate TLS negotiating `h2`, shaped like the
/// client profile), made fresh on every call so a moved egress is followed.
///
/// The outbound it dials with is built from a throwaway Tide link whose keys
/// are all zero. Only its TLS settings are used; the relay holds no key and
/// never sends a handshake of its own, it passes the clients' through.
pub(crate) fn tide_relay_dialer(
    config: &zero_config::TideRelayConfig,
) -> Result<zero_transport::tide::Dialer, String> {
    let host = config.upstream_address.host_string();
    let name = config.upstream_name.as_deref().unwrap_or(&host).to_string();
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let link = format!(
        "zerov1://{}@{}:{}?key={}&path=/x&security=tls&fp=chrome&sni={}",
        "A".repeat(22),
        authority,
        config.upstream_port,
        "A".repeat(43),
        name
    );
    let mut outbound = zero_config::share_link::parse_link(&link)?.outbound;
    if let Security::Tls(tls) = &mut outbound.stream.security {
        tls.alpn = vec!["h2".into()];
        tls.trusted_roots = config.upstream_roots.clone();
    }
    let (outbound, port) = (Arc::new(outbound), config.upstream_port);
    Ok(Arc::new(move || {
        let (outbound, host) = (outbound.clone(), host.clone());
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                .await?
                .collect();
            let tcp = dial_tcp(
                &addrs,
                &race_policy(&outbound.stream),
                &socket_options(&outbound.stream),
            )
            .await
            .map_err(|failure| std::io::Error::other(failure.to_string()))?;
            protect_socket(&outbound, tcp.stream, &host)
                .await
                .map_err(|failure| std::io::Error::other(failure.to_string()))
        })
    }))
}

async fn connect_mux_pooled(
    outbound: &Outbound,
    destination: &Destination,
    address: Address,
    addrs: Vec<SocketAddr>,
    resolver: Option<&zero_dns::Resolver>,
) -> Result<BoxStream, Failure> {
    let key = mux_pool_key(outbound, &address, &addrs);
    let cache = MUX_POOLS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(pools) = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&key)
        .cloned()
    {
        let mut dead = Vec::new();
        for pool in &pools {
            match pool.open(destination.clone()) {
                Ok(stream) => return Ok(stream),
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                    dead.push(Arc::as_ptr(pool) as usize);
                }
                Err(_) => continue,
            }
        }
        if !dead.is_empty() {
            if let Some(live) = cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_mut(&key)
            {
                live.retain(|pool| !dead.contains(&(Arc::as_ptr(pool) as usize)));
            }
        }
    }

    let carrier = connect_mux_carrier_resolved(outbound, address, addrs, resolver).await?;
    let pool = zero_protocol::mux::ClientPool::new(carrier, outbound.mux.max_concurrency);
    let stream = pool.open(destination.clone()).map_err(|error| {
        Failure::new(FailureKind::ProtocolRejected, Stage::RequestSent)
            .with_detail(format!("VLESS Mux: {error}"))
    })?;
    cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(key)
        .or_default()
        .push(pool);
    Ok(stream)
}

/// Open a VLESS Mux carrier for a packet-oriented exchange. The outer VLESS
/// request is written before this returns, while its response header remains
/// unread for the Mux/XUDP codec.
pub async fn connect_mux_carrier_with_resolver(
    outbound: &Outbound,
    resolver: &zero_dns::Resolver,
) -> Result<BoxStream, Failure> {
    if !outbound.mux.enabled {
        return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
            .with_detail("VLESS Mux carrier requested for a disabled Mux outbound"));
    }
    let (address, port) = outbound.endpoint().ok_or_else(|| {
        Failure::new(FailureKind::LocalPolicy, Stage::Resolving)
            .with_detail(format!("outbound {} has no endpoint", outbound.tag))
    })?;
    let outbound = materialize_ech(outbound, resolver, &address.host_string()).await?;
    let addrs = resolver
        .resolve_server(&address)
        .await
        .map_err(|error| {
            Failure::new(FailureKind::DnsNoData, Stage::Resolving).with_detail(error.to_string())
        })?
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(Failure::new(FailureKind::DnsNoData, Stage::Resolving)
            .with_detail(format!("no addresses for {}", address.host_string())));
    }
    within_setup_deadline(connect_mux_carrier_resolved(
        &outbound,
        address,
        addrs,
        Some(resolver),
    ))
    .await
}

async fn connect_mux_carrier_resolved(
    outbound: &Outbound,
    address: Address,
    addrs: Vec<SocketAddr>,
    resolver: Option<&zero_dns::Resolver>,
) -> Result<BoxStream, Failure> {
    let control = Destination::tcp(
        Address::domain(zero_protocol::mux::CONTROL_HOST),
        zero_protocol::mux::CONTROL_PORT,
    );
    if matches!(
        &outbound.stream.transport,
        Transport::Xhttp(zero_config::WebSocketConfig {
            xhttp_http_version: XhttpHttpVersion::Http1 | XhttpHttpVersion::Http2,
            xhttp_mode: XhttpMode::Auto | XhttpMode::StreamUp | XhttpMode::PacketUp,
            ..
        })
    ) {
        return connect_xhttp_split(outbound, &control, &address, &addrs, resolver).await;
    }
    let tcp = dial_tcp(
        &addrs,
        &race_policy(&outbound.stream),
        &socket_options(&outbound.stream),
    )
    .await?;
    build_stack(outbound, &control, tcp.stream, &address.host_string()).await
}

fn mux_pool_key(outbound: &Outbound, address: &Address, addrs: &[SocketAddr]) -> String {
    mux_pool_key_of(&format!("{outbound:?}|{address:?}|{addrs:?}"))
}

/// Hash the complete compiled outbound rather than storing credentials in
/// the process-wide pool key. The debug representation is only transient
/// input to the digest and is never retained.
fn mux_pool_key_of(material: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(material.as_bytes()))
}

async fn protect_socket(
    outbound: &Outbound,
    tcp: TcpStream,
    fallback_host: &str,
) -> Result<BoxStream, Failure> {
    let stream = &outbound.stream;
    let mut injected = false;
    // A raw decoy is a decoy: the urgent-byte method sends none. Nor does a
    // decoy asked to expire by TTL, which is a way of its own that auto mode
    // tests separately; a raw packet in its place would test something else.
    let wants_decoy = |config: &&zero_config::SniDesyncConfig| {
        !matches!(
            config.method,
            zero_config::SniMethod::Urgent
                | zero_config::SniMethod::FastOpen
                | zero_config::SniMethod::Record
                | zero_config::SniMethod::EmptyRecord
        ) && config.fooling != zero_config::DecoyFooling::Ttl
            && !zero_net::fastopen::deferred(&tcp)
    };
    if let Some(config) = stream.evasion.sni_desync.as_ref().filter(wants_decoy) {
        let config = zero_evasion::SniDesyncConfig {
            fake_sni: config.fake_sni.to_string(),
            sequence: config.sequence,
        };
        match zero_evasion::inject_fake_client_hello(&tcp, &config) {
            Ok(true) => {
                injected = true;
                tracing::debug!(fake_sni = %config.fake_sni, "injected fake SNI ClientHello")
            }
            Ok(false) => {
                tracing::debug!(
                    "no raw socket for the SNI decoy; sending it from the socket itself"
                )
            }
            Err(error) => {
                tracing::debug!(%error, "raw SNI decoy failed; sending it from the socket itself")
            }
        }
    }
    let mut hello_version = None;
    let base = shaped_with(tcp, stream, injected, &mut hello_version);
    secure(outbound, base, fallback_host, hello_version).await
}

/// TLS or REALITY over an already open byte stream: a TCP socket, or a
/// connection carried by another outbound (`dialerProxy`).
async fn secure(
    outbound: &Outbound,
    base: BoxStream,
    fallback_host: &str,
    hello_version: Option<u16>,
) -> Result<BoxStream, Failure> {
    let stream = &outbound.stream;
    match &stream.security {
        Security::None => Ok(base),
        Security::Tls(_) => {
            let mut params = tls_params(stream, fallback_host).ok_or_else(|| {
                Failure::new(FailureKind::LocalPolicy, Stage::TlsStarted)
                    .with_detail("ECH configuration discovery did not produce a usable list")
            })?;
            if let Some(version) = hello_version {
                params = params.with_hello_version(version);
            }
            Ok(boxed(zero_security::connect(base, &params).await?))
        }
        Security::Reality(reality) => {
            if matches!(
                stream.transport,
                Transport::Xhttp(zero_config::WebSocketConfig {
                    xhttp_http_version: XhttpHttpVersion::Http3,
                    ..
                })
            ) {
                return Err(Failure::new(FailureKind::LocalPolicy, Stage::TlsStarted)
                    .with_detail("REALITY is not supported over XHTTP HTTP/3"));
            }
            let params = zero_security::RealityParams::from_config_with_fingerprint_and_mldsa(
                reality.server_name.clone(),
                reality.public_key,
                &reality.short_id,
                reality_fingerprint(&reality.fingerprint),
                reality.mldsa65_verify.clone(),
            )
            .with_fingerprint_name(match &reality.fingerprint {
                zero_config::Fingerprint::Named(name) => Some(name.to_string()),
                _ => None,
            })
            .with_hello_version(hello_version);
            let secured = zero_security::reality_connect(base, &params).await?;
            // Vision must reach the REALITY stream itself: once the inner TLS
            // handshake is through, both ends switch that stream to raw bytes
            // at the same moment. A keepalive wrapper hid it from Vision's
            // switch, so this end went on decrypting records the server had
            // stopped sending and the first one "failed authentication"; its
            // empty keepalive records would corrupt the raw stream as well.
            let vision =
                matches!(&outbound.protocol, OutboundProtocol::Vless(v) if v.flow.is_vision());
            let policy = if vision {
                None
            } else {
                keepalive_policy(stream)
            };
            Ok(match policy {
                Some(policy) => boxed(zero_evasion::KeepaliveStream::new(secured, policy)),
                None => boxed(secured),
            })
        }
        Security::ShadowTls(cfg) => {
            let alpn: Vec<Vec<u8>> = cfg.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
            Box::pin(zero_transport::shadowtls::connect(
                base,
                &cfg.password,
                &cfg.server_name,
                &alpn,
                FingerprintProfile::Chrome,
            ))
            .await
            .map_err(|error| {
                Failure::new(FailureKind::TlsHandshakeMalformed, Stage::TlsStarted)
                    .with_detail(error.to_string())
            })
        }
    }
}

async fn connect_xhttp_split(
    outbound: &Outbound,
    destination: &Destination,
    address: &Address,
    addrs: &[SocketAddr],
    resolver: Option<&zero_dns::Resolver>,
) -> Result<BoxStream, Failure> {
    let Transport::Xhttp(settings) = &outbound.stream.transport else {
        unreachable!("split XHTTP helper called for another transport")
    };
    if settings.xhttp_http_version == XhttpHttpVersion::Http3 {
        return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
            .with_detail("XHTTP HTTP/3 requires the QUIC carrier"));
    }
    if settings.xhttp_http_version == XhttpHttpVersion::Http2
        && !matches!(
            settings.xhttp_mode,
            XhttpMode::StreamUp | XhttpMode::PacketUp
        )
    {
        return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
            .with_detail("XHTTP HTTP/2 split requires stream-up or packet-up"));
    }
    let mut download_outbound = outbound.clone();
    let (download_address, download_port, download_settings) =
        if let Some(download) = &settings.xhttp_download {
            download_outbound.stream = (*download.stream).clone();
            (
                download.address.clone(),
                download.port,
                download_outbound.stream.clone(),
            )
        } else {
            (
                address.clone(),
                outbound.endpoint().map_or(0, |(_, port)| port),
                outbound.stream.clone(),
            )
        };
    let download_transport = match &download_settings.transport {
        Transport::Xhttp(config) => config,
        _ => {
            return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
                .with_detail("XHTTP downloadSettings must use the XHTTP carrier"));
        }
    };
    if download_transport.xhttp_http_version != settings.xhttp_http_version {
        return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
            .with_detail("XHTTP upload and download legs must use the same HTTP version"));
    }
    let download_addrs = if download_address == *address
        && download_port == outbound.endpoint().map_or(0, |(_, port)| port)
    {
        addrs.to_vec()
    } else {
        match resolver {
            Some(resolver) => resolver
                .resolve_server(&download_address)
                .await
                .map_err(|error| {
                    Failure::new(FailureKind::DnsNoData, Stage::Resolving)
                        .with_detail(error.to_string())
                })?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, download_port))
                .collect(),
            None => resolve_endpoint(&download_address, download_port).await?,
        }
    };
    let download_fallback = download_address.host_string();
    // The download is set up first, as before: a plain connection for
    // HTTP/1.1, an HTTP/2 carrier (from the XMUX pool when it reuses) for
    // HTTP/2.
    let dial_download = || async {
        let download = dial_tcp(
            &download_addrs,
            &race_policy(&download_outbound.stream),
            &socket_options(&download_outbound.stream),
        )
        .await?;
        protect_socket(&download_outbound, download.stream, &download_fallback).await
    };
    let fallback_host = address.host_string();
    // The connections this proxied request runs on, kept with it to the end.
    let mut leases = Vec::new();
    let upload_cfg = xhttp_ws_config(settings, &fallback_host, &outbound.stream.security);
    let download_cfg = xhttp_ws_config(
        download_transport,
        &download_fallback,
        &download_settings.security,
    );
    let carrier = match (settings.xhttp_http_version, settings.xhttp_mode) {
        (XhttpHttpVersion::Http2, XhttpMode::StreamUp) => {
            let download = xhttp_h2_carrier(
                &download_outbound,
                &download_address,
                &download_addrs,
                &download_fallback,
                &mut leases,
            )
            .await?;
            let upload =
                xhttp_h2_carrier(outbound, address, addrs, &fallback_host, &mut leases).await?;
            xhttp::connect_stream_up_h2(&upload, &download, &upload_cfg, &download_cfg).await
        }
        (XhttpHttpVersion::Http2, XhttpMode::PacketUp) => {
            let download = xhttp_h2_carrier(
                &download_outbound,
                &download_address,
                &download_addrs,
                &download_fallback,
                &mut leases,
            )
            .await?;
            // Uploads ride the download's connection unless the download
            // comes from another server.
            let upload = if settings.xhttp_download.is_some() {
                Some(xhttp_h2_carrier(outbound, address, addrs, &fallback_host, &mut leases).await?)
            } else {
                None
            };
            xhttp::connect_packet_up_h2(download, &download_cfg, &upload_cfg, upload).await
        }
        (XhttpHttpVersion::Http1, XhttpMode::StreamUp) => {
            let download = dial_download().await?;
            let upload = dial_tcp(
                addrs,
                &race_policy(&outbound.stream),
                &socket_options(&outbound.stream),
            )
            .await?;
            let upload = protect_socket(outbound, upload.stream, &fallback_host).await?;
            xhttp::connect_stream_up(upload, download, &upload_cfg, &download_cfg).await
        }
        (XhttpHttpVersion::Http1, XhttpMode::Auto | XhttpMode::PacketUp) => {
            let download = dial_download().await?;
            let template = outbound.clone();
            let candidates = addrs.to_vec();
            let fallback = fallback_host.clone();
            let dialer: xhttp::PacketDialer = Arc::new(move || {
                let template = template.clone();
                let candidates = candidates.clone();
                let fallback = fallback.clone();
                Box::pin(async move {
                    let tcp = dial_tcp(
                        &candidates,
                        &race_policy(&template.stream),
                        &socket_options(&template.stream),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                    protect_socket(&template, tcp.stream, &fallback)
                        .await
                        .map_err(|error| error.to_string())
                })
            });
            xhttp::connect_packet_up(download, &download_cfg, &upload_cfg, dialer).await
        }
        _ => unreachable!("split helper called for stream-one or auto"),
    };
    // A request that failed on a reused connection retires it, so the next
    // one does not find out the same way.
    let carrier = carrier.map_err(|error| {
        leases.iter().for_each(crate::xmux::Lease::retire);
        Failure::new(FailureKind::HttpMalformed, Stage::RequestSent).with_detail(error)
    })?;
    wrap_protocol(outbound, destination, crate::xmux::hold(carrier, leases)).await
}

/// The protocol's own layer over an XHTTP carrier: the VMess handshake, the
/// VLESS Encryption one, or the plain request header in front of the first
/// payload.
async fn wrap_protocol(
    outbound: &Outbound,
    destination: &Destination,
    carrier: BoxStream,
) -> Result<BoxStream, Failure> {
    let header = protocol_header(outbound, destination)?;
    if let OutboundProtocol::Vmess(vmess) = &outbound.protocol {
        return wrap_vmess(carrier, vmess, destination).await;
    }
    if let OutboundProtocol::Vless(v) = &outbound.protocol {
        if v.encrypted() {
            return send_vless(carrier, v, destination, &header).await;
        }
    }
    Ok(with_header(carrier, header))
}

/// An HTTP/2 connection for XHTTP to `outbound`'s server: one from its XMUX
/// pool when the outbound reuses connections (its lease pushed onto
/// `leases`, to be held as long as the proxied request runs), or a new one
/// of its own when it does not.
async fn xhttp_h2_carrier(
    outbound: &Outbound,
    address: &Address,
    addrs: &[SocketAddr],
    fallback_host: &str,
    leases: &mut Vec<crate::xmux::Lease>,
) -> Result<xhttp::H2Carrier, Failure> {
    let Transport::Xhttp(settings) = &outbound.stream.transport else {
        unreachable!("XHTTP carrier asked for another transport")
    };
    let xmux = &settings.xhttp.xmux;
    let dial = || async {
        let tcp = dial_tcp(
            addrs,
            &race_policy(&outbound.stream),
            &socket_options(&outbound.stream),
        )
        .await?;
        protect_socket(outbound, tcp.stream, fallback_host).await
    };
    if !xmux.reuses() {
        return xhttp::H2Carrier::open_with_keepalive(dial().await?, xmux.h_keep_alive_period)
            .await
            .map_err(|error| {
                Failure::new(FailureKind::HttpMalformed, Stage::RequestSent).with_detail(error)
            });
    }
    let key = mux_pool_key(outbound, address, addrs);
    let lease = crate::xmux::lease(&key, xmux, dial).await?;
    let carrier = lease.carrier().clone();
    leases.push(lease);
    Ok(carrier)
}

/// Whether `outbound` is XHTTP stream-one over HTTP/2 with connection reuse,
/// which [`connect_xhttp_stream_one`] serves from the XMUX pool.
fn reuses_h2_stream_one(outbound: &Outbound) -> bool {
    matches!(
        &outbound.stream.transport,
        Transport::Xhttp(zero_config::WebSocketConfig {
            xhttp_http_version: XhttpHttpVersion::Http2,
            xhttp_mode: XhttpMode::Auto | XhttpMode::StreamOne,
            xhttp,
            ..
        }) if xhttp.xmux.reuses()
    )
}

/// XHTTP stream-one over a pooled HTTP/2 connection: the proxied request is
/// one more stream on a connection the pool already has open, or on a new
/// one it opens. A reused connection may have died since it was last asked,
/// so a stream that cannot be opened on one gets one more try on another.
async fn connect_xhttp_stream_one(
    outbound: &Outbound,
    destination: &Destination,
    address: &Address,
    addrs: &[SocketAddr],
) -> Result<BoxStream, Failure> {
    let Transport::Xhttp(settings) = &outbound.stream.transport else {
        unreachable!("stream-one helper called for another transport")
    };
    let fallback_host = address.host_string();
    let config = xhttp_ws_config(settings, &fallback_host, &outbound.stream.security);
    let mut tries = 0;
    loop {
        let mut leases = Vec::new();
        let carrier =
            xhttp_h2_carrier(outbound, address, addrs, &fallback_host, &mut leases).await?;
        match carrier.stream_one(&config).await {
            Ok(stream) => {
                return wrap_protocol(outbound, destination, crate::xmux::hold(stream, leases))
                    .await
            }
            Err(error) => {
                leases.iter().for_each(crate::xmux::Lease::retire);
                tries += 1;
                if tries == 2 {
                    return Err(Failure::new(FailureKind::HttpMalformed, Stage::RequestSent)
                        .with_detail(error));
                }
            }
        }
    }
}

async fn connect_xhttp_h3(
    outbound: &Outbound,
    destination: &Destination,
    address: &Address,
    addrs: &[SocketAddr],
) -> Result<BoxStream, Failure> {
    let Transport::Xhttp(settings) = &outbound.stream.transport else {
        unreachable!("HTTP/3 helper called for another transport")
    };
    if !matches!(outbound.stream.security, Security::Tls(_)) {
        return Err(Failure::new(FailureKind::LocalPolicy, Stage::TlsStarted)
            .with_detail("XHTTP HTTP/3 requires ordinary certificate TLS"));
    }
    let fallback_host = address.host_string();
    let config = xhttp_ws_config(settings, &fallback_host, &outbound.stream.security);
    let mut params = tls_params(&outbound.stream, &fallback_host).ok_or_else(|| {
        Failure::new(FailureKind::LocalPolicy, Stage::TlsStarted)
            .with_detail("XHTTP HTTP/3 TLS parameters are missing")
    })?;
    params.alpn = vec![b"h3".to_vec()];
    if settings.xhttp_mode == XhttpMode::StreamUp {
        return xhttp::connect_stream_up_h3(addrs, &config, &params)
            .await
            .map_err(|error| {
                Failure::new(FailureKind::HttpMalformed, Stage::RequestSent).with_detail(error)
            });
    }
    if settings.xhttp_mode == XhttpMode::PacketUp {
        return xhttp::connect_packet_up_h3(addrs, &config, &config, &params)
            .await
            .map_err(|error| {
                Failure::new(FailureKind::HttpMalformed, Stage::RequestSent).with_detail(error)
            });
    }
    let carrier = xhttp::connect_h3(addrs, &config, &params)
        .await
        .map_err(|error| {
            Failure::new(FailureKind::TlsHandshakeMalformed, Stage::TlsStarted).with_detail(error)
        })?;
    let header = protocol_header(outbound, destination)?;
    if let OutboundProtocol::Vmess(vmess) = &outbound.protocol {
        return wrap_vmess(carrier, vmess, destination).await;
    }
    if let OutboundProtocol::Vless(v) = &outbound.protocol {
        if v.encrypted() {
            return send_vless(boxed(carrier), v, destination, &header).await;
        }
    }
    Ok(with_header(carrier, header))
}

fn xhttp_ws_config(
    config: &zero_config::WebSocketConfig,
    fallback_host: &str,
    security: &Security,
) -> WsConfig {
    WsConfig {
        path: config.path.to_string(),
        host: config.host.as_deref().unwrap_or(fallback_host).to_string(),
        headers: config
            .headers
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        early_data_len: 0,
        xhttp: Arc::new(xhttp_options(&config.xhttp)),
        secure: !matches!(security, Security::None),
        grpc_multi_path: None,
        grpc_multi: false,
    }
}

/// The transport's view of the parsed XHTTP settings.
fn xhttp_options(
    settings: &zero_config::xhttp::XhttpSettings,
) -> zero_transport::xhttp_request::XhttpOptions {
    use zero_transport::xhttp_request::{PaddingMethod, Placement, Range, XhttpOptions};
    let range = |(from, to): (u32, u32)| Range { from, to };
    let placement = |name: &str, fallback: Placement| Placement::parse(name).unwrap_or(fallback);
    XhttpOptions {
        x_padding_bytes: range(settings.x_padding_bytes),
        x_padding_obfs_mode: settings.x_padding_obfs_mode,
        x_padding_key: settings.x_padding_key.to_string(),
        x_padding_header: settings.x_padding_header.to_string(),
        x_padding_placement: placement(&settings.x_padding_placement, Placement::QueryInHeader),
        x_padding_method: if &*settings.x_padding_method == "tokenish" {
            PaddingMethod::Tokenish
        } else {
            PaddingMethod::RepeatX
        },
        uplink_http_method: settings.uplink_http_method.to_string(),
        session_placement: placement(&settings.session_placement, Placement::Path),
        session_key: settings.session_key.to_string(),
        session_id_table: settings.session_id_table.to_string(),
        session_id_length: range(settings.session_id_length),
        seq_placement: placement(&settings.seq_placement, Placement::Path),
        seq_key: settings.seq_key.to_string(),
        uplink_data_placement: placement(&settings.uplink_data_placement, Placement::Auto),
        uplink_data_key: settings.uplink_data_key.to_string(),
        uplink_chunk_size: (settings.uplink_chunk_size.1 > 0)
            .then(|| range(settings.uplink_chunk_size)),
        no_grpc_header: settings.no_grpc_header,
        no_sse_header: settings.no_sse_header,
        sc_max_each_post_bytes: range(settings.sc_max_each_post_bytes),
        sc_min_posts_interval_ms: range(settings.sc_min_posts_interval_ms),
    }
}

pub(crate) fn raw_http_header_config(
    raw: &zero_config::RawHttpHeader,
) -> zero_transport::tcp_header::HttpHeaderConfig {
    zero_transport::tcp_header::HttpHeaderConfig {
        request: zero_transport::tcp_header::HttpRequest {
            version: raw.request.version.clone(),
            method: raw.request.method.clone(),
            path: raw.request.path.clone(),
            headers: raw
                .request
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        },
        response: raw
            .response
            .as_ref()
            .map(|response| zero_transport::tcp_header::HttpResponse {
                version: response.version.clone(),
                status: response.status,
                reason: response.reason.clone(),
                headers: response
                    .headers
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect(),
            }),
    }
}

/// Stack the carrier and protocol layers onto an established socket.
///
/// Split out from `connect` so tests can drive it over an in-memory duplex.
pub async fn build_stack(
    outbound: &Outbound,
    destination: &Destination,
    tcp: TcpStream,
    fallback_host: &str,
) -> Result<BoxStream, Failure> {
    // 1. Fragmentation and security.
    let t_tls = std::time::Instant::now();
    let secured = protect_socket(outbound, tcp, fallback_host).await?;
    tracing::debug!(
        security_ms = t_tls.elapsed().as_millis(),
        "security handshake"
    );
    finish_stack(outbound, destination, secured, fallback_host).await
}

/// Open `outbound` to `destination` over `carried`, a connection to its
/// server that another outbound already opened — one hop of Xray's
/// `sockopt.dialerProxy` chain.
///
/// The point in Iran: with the carrier a WARP tunnel, the censor sees only
/// WireGuard to Cloudflare, and the server's own address never appears on the
/// local network, so it cannot be learned or blocked there. Fragmenting and
/// SNI desync are skipped: inside the tunnel nobody is inspecting.
pub async fn connect_over(
    outbound: &Outbound,
    carried: BoxStream,
    destination: &Destination,
) -> Result<BoxStream, Failure> {
    if !chainable(outbound) {
        return Err(
            Failure::new(FailureKind::LocalPolicy, Stage::SocketConnected).with_detail(format!(
                "outbound {} ({}) cannot run through dialerProxy yet",
                outbound.tag,
                outbound.protocol.name()
            )),
        );
    }
    let fallback_host = outbound
        .endpoint()
        .map(|(address, _)| address.host_string())
        .unwrap_or_default();
    let secured = secure(outbound, carried, &fallback_host, None).await?;
    finish_stack(outbound, destination, secured, &fallback_host).await
}

/// Whether a connection for `outbound` can be opened before its
/// destination is known — a "warm carrier": TCP, TLS and the transport
/// upgrade done ahead of time, the protocol header (which names the
/// destination) written only when a real connection needs it.
///
/// That takes a protocol whose header is plain bytes after the upgrade
/// (VLESS without Vision or encryption, Trojan), over TLS with a WebSocket or
/// HTTPUpgrade transport, without Mux. Measured from Center on 2026-09-28,
/// the handshakes are most of a new connection's cost on a chained CDN path:
/// 0.87 s to the first byte on a new connection against 0.21 s on an open one.
pub fn warmable(outbound: &Outbound) -> bool {
    let plain_header = match &outbound.protocol {
        OutboundProtocol::Vless(v) => !v.encrypted() && !v.flow.is_vision(),
        OutboundProtocol::Trojan(_) => true,
        _ => false,
    };
    plain_header
        && !outbound.mux.enabled
        && outbound.stream.raw_http_header.is_none()
        && matches!(outbound.stream.security, Security::Tls(_))
        && matches!(
            outbound.stream.transport,
            Transport::WebSocket(_) | Transport::HttpUpgrade(_)
        )
}

/// TCP and TLS to `outbound`'s own server, dialled directly (fragmenting and
/// SNI desync apply). Returns the secured stream and the name TLS used.
pub(crate) async fn open_secured(
    outbound: &Outbound,
    resolver: &zero_dns::Resolver,
) -> Result<(BoxStream, String), Failure> {
    let (address, port) = outbound.endpoint().ok_or_else(|| {
        Failure::new(FailureKind::LocalPolicy, Stage::Resolving)
            .with_detail(format!("outbound {} has no endpoint", outbound.tag))
    })?;
    let fallback_host = address.host_string();
    let outbound = materialize_ech(outbound, resolver, &fallback_host).await?;
    let addrs = resolver
        .resolve_server(&address)
        .await
        .map_err(|error| {
            Failure::new(FailureKind::DnsNoData, Stage::Resolving).with_detail(error.to_string())
        })?
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect::<Vec<_>>();
    let tcp = dial_tcp(
        &addrs,
        &race_policy(&outbound.stream),
        &socket_options(&outbound.stream),
    )
    .await?;
    let secured = protect_socket(&outbound, tcp.stream, &fallback_host).await?;
    Ok((secured, fallback_host))
}

/// TLS over `carried`, a connection to `outbound`'s server another outbound
/// opened: one hop of a `dialerProxy` chain.
pub(crate) async fn secure_over(
    outbound: &Outbound,
    carried: BoxStream,
) -> Result<(BoxStream, String), Failure> {
    let fallback_host = outbound
        .endpoint()
        .map(|(address, _)| address.host_string())
        .unwrap_or_default();
    let secured = secure(outbound, carried, &fallback_host, None).await?;
    Ok((secured, fallback_host))
}

/// Upgrade a secured stream to `outbound`'s transport and stop: a warm
/// carrier, ready for [`finish_carrier`]. Only for [`warmable`] outbounds.
pub(crate) async fn open_carrier(
    outbound: &Outbound,
    secured: BoxStream,
    fallback_host: &str,
) -> Result<BoxStream, Failure> {
    let config = |w: &zero_config::WebSocketConfig, early_data_len: usize| WsConfig {
        path: w.path.to_string(),
        host: w.host.as_deref().unwrap_or(fallback_host).to_string(),
        headers: w
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        early_data_len,
        xhttp: Default::default(),
        secure: false,
        grpc_multi_path: None,
        grpc_multi: false,
    };
    match &outbound.stream.transport {
        Transport::WebSocket(w) => {
            let s = ws::connect(secured, &config(w, w.early_data_len), &[]).await?;
            Ok(match keepalive_policy(&outbound.stream) {
                Some(policy) => boxed(zero_evasion::KeepaliveStream::new(s, policy)),
                None => boxed(s),
            })
        }
        Transport::HttpUpgrade(w) => {
            let s = httpupgrade::connect(secured, &config(w, 0))
                .await
                .map_err(|error| {
                    Failure::new(FailureKind::WebsocketRejected, Stage::RequestSent)
                        .with_detail(error)
                })?;
            Ok(boxed(s))
        }
        _ => Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
            .with_detail(format!("outbound {} cannot be warmed", outbound.tag))),
    }
}

/// Use a warm carrier for `destination`: write the protocol header that
/// names it. The response header is stripped by the caller, as for any
/// stream ([`strip_response`]).
pub(crate) async fn finish_carrier(
    outbound: &Outbound,
    carrier: BoxStream,
    destination: &Destination,
) -> Result<BoxStream, Failure> {
    let header = protocol_header(outbound, destination)?;
    Ok(with_header(carrier, header))
}

/// Whether `outbound` is a byte-stream protocol over a plain stream
/// transport, which is what [`connect_over`] can layer over another outbound.
pub fn chainable(outbound: &Outbound) -> bool {
    outbound.chainable()
}

/// Everything above security: header obfuscation, transport, protocol.
async fn finish_stack(
    outbound: &Outbound,
    destination: &Destination,
    secured: BoxStream,
    fallback_host: &str,
) -> Result<BoxStream, Failure> {
    let stream = &outbound.stream;

    let secured = if let Some(raw) = &stream.raw_http_header {
        let config = raw_http_header_config(raw);
        boxed(zero_transport::tcp_header::HttpHeaderStream::client(
            secured, &config,
        ))
    } else {
        secured
    };

    if let OutboundProtocol::AnyTls(anytls) = &outbound.protocol {
        let stream =
            zero_protocol::anytls::client_handshake(secured, &anytls.password, destination)
                .await
                .map_err(|error| {
                    Failure::new(FailureKind::ProtocolRejected, Stage::RequestSent)
                        .with_detail(format!("AnyTLS handshake: {error}"))
                })?;
        return Ok(boxed(stream));
    }

    if let OutboundProtocol::Socks(socks) = &outbound.protocol {
        let credential = socks
            .auth
            .as_ref()
            .map(|a| zero_protocol::socks::Credential {
                username: a.username.clone(),
                password: a.password.clone(),
            });
        let tunnel = if socks.http {
            Box::pin(zero_protocol::socks::connect_http(
                secured,
                credential.as_ref(),
                destination,
            ))
            .await
        } else {
            Box::pin(zero_protocol::socks::connect_socks5(
                secured,
                credential.as_ref(),
                destination,
            ))
            .await
        };
        let stream = tunnel.map_err(|error| {
            Failure::new(FailureKind::ProtocolRejected, Stage::RequestSent).with_detail(error)
        })?;
        return Ok(boxed(stream));
    }

    // 3. Carrier, and the protocol header that rides in its first bytes.
    let header = protocol_header(outbound, destination)?;

    match &stream.transport {
        Transport::Raw => {
            let s = secured;
            if let OutboundProtocol::Vmess(v) = &outbound.protocol {
                return wrap_vmess(s, v, destination).await;
            }
            if let OutboundProtocol::Shadowsocks(config) = &outbound.protocol {
                if config.method.is_2022() {
                    let stream = zero_protocol::shadowsocks2022::Stream::client(
                        s,
                        ss2022_method(config.method),
                        &config.password,
                        destination,
                    )
                    .await
                    .map_err(|error| {
                        Failure::new(FailureKind::ProtocolRejected, Stage::RequestSent)
                            .with_detail(format!("Shadowsocks 2022: {error}"))
                    })?;
                    return Ok(boxed(stream));
                }
                let shadowsocks = zero_protocol::shadowsocks::Stream::new_client(
                    s,
                    shadowsocks_method(config.method),
                    config.password.as_bytes(),
                )
                .with_destination(destination)
                .map_err(|error| {
                    Failure::new(FailureKind::ProtocolRejected, Stage::RequestSent)
                        .with_detail(error.to_string())
                })?;
                return Ok(boxed(shadowsocks));
            }
            if let OutboundProtocol::Vless(v) = &outbound.protocol {
                return send_vless(s, v, destination, &header).await;
            }
            Ok(with_header(s, header))
        }
        Transport::WebSocket(w) => {
            let cfg = WsConfig {
                path: w.path.to_string(),
                host: w.host.as_deref().unwrap_or(fallback_host).to_string(),
                headers: w
                    .headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                early_data_len: w.early_data_len,
                xhttp: Default::default(),
                secure: false,
                grpc_multi_path: None,
                grpc_multi: false,
            };

            // The protocol header goes in the upgrade request when it fits,
            // saving a round trip on exactly the long-latency paths that need
            // it most. Anything over budget is written normally afterwards.
            let encrypted_vless =
                matches!(&outbound.protocol, OutboundProtocol::Vless(v) if v.encrypted());
            let (early, rest) = if encrypted_vless {
                // The header travels inside the encrypted layer, which only
                // exists after the upgrade.
                (&[][..], &[][..])
            } else if header.len() <= cfg.early_data_len {
                (header.as_slice(), &[][..])
            } else {
                (&[][..], header.as_slice())
            };

            let t_ws = std::time::Instant::now();
            let mut s = ws::connect(secured, &cfg, early).await?;
            tracing::debug!(
                ws_ms = t_ws.elapsed().as_millis(),
                early = early.len(),
                "websocket upgrade"
            );
            if !rest.is_empty() {
                s.write_all(rest)
                    .await
                    .map_err(|e| Failure::from_io(&e, Stage::RequestSent))?;
                s.flush()
                    .await
                    .map_err(|e| Failure::from_io(&e, Stage::RequestSent))?;
            }
            if let OutboundProtocol::Vmess(v) = &outbound.protocol {
                return wrap_vmess(s, v, destination).await;
            }
            let s = match keepalive_policy(&outbound.stream) {
                Some(policy) => boxed(zero_evasion::KeepaliveStream::new(s, policy)),
                None => boxed(s),
            };
            match &outbound.protocol {
                OutboundProtocol::Vless(v) if v.encrypted() => {
                    send_vless(s, v, destination, &header).await
                }
                _ => Ok(s),
            }
        }
        Transport::HttpUpgrade(w) => {
            let cfg = WsConfig {
                path: w.path.to_string(),
                host: w.host.as_deref().unwrap_or(fallback_host).to_string(),
                headers: w
                    .headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                early_data_len: 0,
                xhttp: Default::default(),
                secure: false,
                grpc_multi_path: None,
                grpc_multi: false,
            };
            let s = httpupgrade::connect(secured, &cfg).await.map_err(|error| {
                Failure::new(FailureKind::WebsocketRejected, Stage::RequestSent).with_detail(error)
            })?;
            // VMess carries its own request header inside its cipher state.
            if let OutboundProtocol::Vmess(v) = &outbound.protocol {
                return wrap_vmess(s, v, destination).await;
            }
            if let OutboundProtocol::Vless(v) = &outbound.protocol {
                if v.encrypted() {
                    return send_vless(boxed(s), v, destination, &header).await;
                }
            }
            // Everything else states its destination in a protocol header that
            // must be the first thing on the carrier. HTTPUpgrade has no
            // early-data channel to fold it into, so it rides in front of the
            // first payload after the 101, exactly as on the gRPC carrier.
            Ok(with_header(s, header))
        }
        Transport::Grpc(w) => {
            let cfg = WsConfig {
                // multiMode calls the multi method, if it has a name of its own.
                path: match (&w.grpc_multi_path, w.grpc_multi) {
                    (Some(multi), true) => multi.to_string(),
                    _ => w.path.to_string(),
                },
                host: w.host.as_deref().unwrap_or(fallback_host).to_string(),
                headers: w
                    .headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                early_data_len: 0,
                xhttp: Default::default(),
                secure: false,
                grpc_multi_path: None,
                grpc_multi: w.grpc_multi,
            };
            let carrier = grpc::connect(secured, &cfg).await.map_err(|error| {
                Failure::new(FailureKind::HttpMalformed, Stage::RequestSent).with_detail(error)
            })?;
            if let OutboundProtocol::Vmess(v) = &outbound.protocol {
                return wrap_vmess(carrier, v, destination).await;
            }
            if let OutboundProtocol::Vless(v) = &outbound.protocol {
                if v.encrypted() {
                    return send_vless(boxed(carrier), v, destination, &header).await;
                }
            }
            Ok(with_header(carrier, header))
        }
        Transport::Xhttp(w) => {
            let cfg = xhttp_ws_config(w, fallback_host, &outbound.stream.security);
            if !matches!(w.xhttp_mode, XhttpMode::Auto | XhttpMode::StreamOne) {
                return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
                    .with_detail(format!(
                        "XHTTP mode {:?} requires the split upload/download engine",
                        w.xhttp_mode
                    )));
            }
            match w.xhttp_http_version {
                XhttpHttpVersion::Http1 => {
                    let carrier = xhttp::connect(secured, &cfg).await.map_err(|error| {
                        Failure::new(FailureKind::HttpMalformed, Stage::RequestSent)
                            .with_detail(error)
                    })?;
                    if let OutboundProtocol::Vmess(v) = &outbound.protocol {
                        return wrap_vmess(carrier, v, destination).await;
                    }
                    if let OutboundProtocol::Vless(v) = &outbound.protocol {
                        if v.encrypted() {
                            return send_vless(boxed(carrier), v, destination, &header).await;
                        }
                    }
                    Ok(with_header(carrier, header))
                }
                XhttpHttpVersion::Http2 => {
                    let carrier = xhttp::connect_h2(secured, &cfg).await.map_err(|error| {
                        Failure::new(FailureKind::HttpMalformed, Stage::RequestSent)
                            .with_detail(error)
                    })?;
                    if let OutboundProtocol::Vmess(v) = &outbound.protocol {
                        return wrap_vmess(carrier, v, destination).await;
                    }
                    if let OutboundProtocol::Vless(v) = &outbound.protocol {
                        if v.encrypted() {
                            return send_vless(boxed(carrier), v, destination, &header).await;
                        }
                    }
                    Ok(with_header(carrier, header))
                }
                XhttpHttpVersion::Http3 => {
                    Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
                        .with_detail("XHTTP HTTP/3 requires the QUIC carrier"))
                }
            }
        }
    }
}

/// Shared VLESS Encryption clients, one per server and key set, so a 0-RTT
/// ticket from one connection serves the next (Xray keeps one
/// `ClientInstance` per outbound).
fn vless_encryption_client(
    v: &zero_config::VlessConfig,
) -> Result<Arc<zero_protocol::vless_encryption::Client>, Failure> {
    use zero_protocol::vless_encryption::{Client, ClientConfig};
    static CLIENTS: OnceLock<Mutex<HashMap<String, Arc<Client>>>> = OnceLock::new();
    let key = format!("{}:{}/{}", v.address.host_string(), v.port, v.encryption);
    let clients = CLIENTS.get_or_init(Default::default);
    let mut clients = clients.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(client) = clients.get(&key) {
        return Ok(Arc::clone(client));
    }
    let config = ClientConfig::parse(&v.encryption).map_err(|error| {
        Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
            .with_detail(format!("VLESS Encryption: {error}"))
    })?;
    // Subscriptions come and go; keep the cache from growing with them.
    if clients.len() >= 256 {
        clients.clear();
    }
    let client = Client::new(config);
    clients.insert(key, Arc::clone(&client));
    Ok(client)
}

/// Finish a VLESS stream on any carrier: the VLESS Encryption handshake when
/// configured, then the request header, framed by Vision for that flow.
async fn send_vless(
    s: BoxStream,
    v: &zero_config::VlessConfig,
    destination: &Destination,
    header: &[u8],
) -> Result<BoxStream, Failure> {
    let s = if v.encrypted() {
        let client = vless_encryption_client(v)?;
        let t = std::time::Instant::now();
        let stream = client.handshake(s).await.map_err(|error| {
            Failure::new(FailureKind::ProtocolRejected, Stage::RequestSent)
                .with_detail(format!("VLESS Encryption handshake: {error}"))
        })?;
        tracing::debug!(ms = t.elapsed().as_millis(), "VLESS Encryption handshake");
        boxed(stream)
    } else {
        s
    };
    if v.flow.is_vision() {
        if !matches!(destination.network, zero_core::Network::Tcp) {
            return Err(Failure::new(FailureKind::LocalPolicy, Stage::RequestSent)
                .with_detail("Vision TCP flow cannot carry UDP without XUDP"));
        }
        let vision = zero_protocol::vision::VisionStream::new_client(s, v.uuid)
            .with_seed(
                v.vision_seed
                    .map_or_else(Default::default, zero_protocol::vision::VisionSeed::new),
            )
            .with_request_header(header)
            .with_direct_read_switch(|carrier| {
                let carrier = carrier.as_mut().get_mut().as_any_mut();
                // With VLESS Encryption the server's raw stream starts under
                // the encryption layer, above any TLS (Xray's UnwrapRawConn
                // stops there), so TLS is left alone.
                if let Some(encrypted) = carrier
                    .downcast_mut::<zero_protocol::vless_encryption::EncryptedStream<BoxStream>>()
                {
                    encrypted.enter_direct_mode();
                } else if let Some(reality) =
                    carrier.downcast_mut::<zero_security::tls13::Tls13Stream<BoxStream>>()
                {
                    reality.enter_direct_mode();
                }
            });
        return Ok(boxed(vision));
    }
    Ok(with_header(s, header.to_vec()))
}

/// Put a protocol's request header at the front of `s` without writing it
/// yet: it leaves in the same write as the first payload, so the connection
/// does not open with a short packet of a recognisable size. See
/// [`zero_protocol::first_flight`] for the rule and its one exception.
fn with_header(s: BoxStream, header: Vec<u8>) -> BoxStream {
    if header.is_empty() {
        return s;
    }
    boxed(zero_protocol::first_flight::HeaderFirst::new(s, header))
}

fn reality_fingerprint(f: &zero_config::Fingerprint) -> FingerprintProfile {
    use zero_config::Fingerprint as F;
    match f {
        F::Chrome => FingerprintProfile::Chrome,
        F::Firefox => FingerprintProfile::Firefox,
        F::Safari => FingerprintProfile::Safari,
        F::Edge => FingerprintProfile::Edge,
        F::Ios => FingerprintProfile::Ios,
        F::Android => FingerprintProfile::Android,
        // Random keeps REALITY's required X25519 shape while selecting a
        // valid browser family at the current implementation boundary. An
        // unshaped hello is never valid for REALITY.
        F::Random | F::Randomized => FingerprintProfile::Chrome,
        F::Named(name) => {
            FingerprintProfile::parse(fingerprint_family_name(&F::Named(name.clone())))
                .unwrap_or(FingerprintProfile::Chrome)
        }
        F::Unshaped => FingerprintProfile::Unshaped,
    }
}

fn protocol_header(outbound: &Outbound, destination: &Destination) -> Result<Vec<u8>, Failure> {
    match &outbound.protocol {
        OutboundProtocol::Vless(v) => {
            // Dialling a portal as a reverse-proxy bridge: the destination is
            // the reverse name, and the request is the reverse command.
            if destination.port == 0
                && matches!(&destination.address, zero_core::Address::Domain(host)
                    if &**host == zero_protocol::vless::REVERSE_HOST)
            {
                return Ok(
                    zero_protocol::vless::encode_reverse_request(&v.uuid, v.flow.as_str()).to_vec(),
                );
            }
            if outbound.mux.enabled {
                Ok(zero_protocol::vless::encode_mux_request(&v.uuid, v.flow.as_str()).to_vec())
            } else {
                Ok(
                    zero_protocol::vless::encode_request(&v.uuid, v.flow.as_str(), destination)
                        .to_vec(),
                )
            }
        }
        OutboundProtocol::Trojan(t) => {
            Ok(zero_protocol::trojan::encode_request(&t.password_hash, destination).to_vec())
        }
        OutboundProtocol::Shadowsocks(_) => Ok(Vec::new()),
        OutboundProtocol::Vmess(_) => Ok(Vec::new()),
        OutboundProtocol::AnyTls(_) => Ok(Vec::new()),
        OutboundProtocol::Socks(_) => Ok(Vec::new()),
        OutboundProtocol::Tor(_) => Ok(Vec::new()),
        OutboundProtocol::MasterDns(_) => Ok(Vec::new()),
        OutboundProtocol::Tide(_) => Ok(Vec::new()),
        OutboundProtocol::Hysteria2(_) => Ok(Vec::new()),
        OutboundProtocol::Tuic(_) => Ok(Vec::new()),
        OutboundProtocol::Juicity(_) => Ok(Vec::new()),
        OutboundProtocol::AmneziaWireguard(_) => Ok(Vec::new()),
        other => Err(
            Failure::new(FailureKind::LocalPolicy, Stage::RequestSent).with_detail(format!(
                "outbound protocol {} does not open proxied streams",
                other.name()
            )),
        ),
    }
}

/// Wrap a proxied stream so the protocol's response header is stripped as
/// data arrives, rather than waited for.
///
/// This must stay lazy. A server may not emit its response header until it has
/// forwarded the client's first payload and received an answer, so blocking on
/// the header before relaying deadlocks the connection.
pub fn strip_response(outbound: &Outbound, stream: BoxStream) -> BoxStream {
    match &outbound.protocol {
        // The Mux worker consumes the VLESS response header before it starts
        // decoding metadata frames. Applying VlessStream here as well would
        // leave it waiting for a second header and corrupt the first frame.
        OutboundProtocol::Vless(_) if outbound.mux.enabled => stream,
        OutboundProtocol::Vless(_) => boxed(zero_protocol::vless::VlessStream::new(stream)),
        OutboundProtocol::Shadowsocks(_) => stream,
        OutboundProtocol::Vmess(_) => stream,
        OutboundProtocol::AmneziaWireguard(_) => stream,
        // Trojan sends no response header; the remote's bytes start immediately.
        _ => stream,
    }
}

async fn wrap_vmess<S>(
    stream: S,
    config: &zero_config::VmessConfig,
    destination: &Destination,
) -> Result<BoxStream, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    zero_protocol::vmess::client_handshake(
        stream,
        config.uuid,
        vmess_cipher(config.cipher),
        destination,
    )
    .await
    .map(boxed)
    .map_err(|error| {
        Failure::new(FailureKind::ProtocolRejected, Stage::RequestSent)
            .with_detail(error.to_string())
    })
}

pub(crate) fn vmess_cipher(cipher: zero_config::VmessCipher) -> zero_protocol::vmess::Cipher {
    match cipher {
        zero_config::VmessCipher::Auto => zero_protocol::vmess::Cipher::Auto,
        zero_config::VmessCipher::Aes128Gcm => zero_protocol::vmess::Cipher::Aes128Gcm,
        zero_config::VmessCipher::Chacha20Poly1305 => {
            zero_protocol::vmess::Cipher::Chacha20Poly1305
        }
        zero_config::VmessCipher::None => zero_protocol::vmess::Cipher::None,
    }
}

fn shadowsocks_method(
    method: zero_config::ShadowsocksMethod,
) -> zero_protocol::shadowsocks::Method {
    match method {
        zero_config::ShadowsocksMethod::Aes128Gcm => zero_protocol::shadowsocks::Method::Aes128Gcm,
        zero_config::ShadowsocksMethod::Aes256Gcm => zero_protocol::shadowsocks::Method::Aes256Gcm,
        zero_config::ShadowsocksMethod::Chacha20Poly1305 => {
            zero_protocol::shadowsocks::Method::Chacha20Poly1305
        }
        zero_config::ShadowsocksMethod::Blake3Aes128Gcm
        | zero_config::ShadowsocksMethod::Blake3Aes256Gcm
        | zero_config::ShadowsocksMethod::Blake3Chacha20Poly1305 => {
            unreachable!("2022 methods use ss2022_method")
        }
    }
}

fn ss2022_method(method: zero_config::ShadowsocksMethod) -> zero_protocol::shadowsocks2022::Method {
    match method {
        zero_config::ShadowsocksMethod::Blake3Aes128Gcm => {
            zero_protocol::shadowsocks2022::Method::Aes128Gcm
        }
        zero_config::ShadowsocksMethod::Blake3Aes256Gcm => {
            zero_protocol::shadowsocks2022::Method::Aes256Gcm
        }
        zero_config::ShadowsocksMethod::Blake3Chacha20Poly1305 => {
            zero_protocol::shadowsocks2022::Method::Chacha20Poly1305
        }
        _ => unreachable!("legacy methods use shadowsocks_method"),
    }
}

/// Direct connection, for the `freedom` outbound.
pub async fn connect_direct(
    destination: &Destination,
    stream: &StreamSettings,
) -> Result<BoxStream, Failure> {
    let destination = &redirected(destination, stream.direct.as_deref());
    let addrs = match &destination.address {
        Address::Ip(ip) => vec![SocketAddr::new(*ip, destination.port)],
        Address::Domain(_) => filter_direct_addresses(
            resolve_endpoint(&destination.address, destination.port).await?,
            stream.sockopt.domain_strategy,
            &destination.address,
        )?,
    };
    if let Some(proxy) = env_proxy_for(&destination.address.host_string()) {
        return dial_via_env_proxy(proxy, destination, stream).await;
    }
    dial_direct(addrs, destination, stream).await
}

/// The last steps of a direct connection, once the destination's addresses
/// are known: drop the ones Freedom's `finalRules` forbid, dial what is left,
/// and send the PROXY protocol header when the outbound asks for one.
async fn dial_direct(
    addrs: Vec<SocketAddr>,
    destination: &Destination,
    stream: &StreamSettings,
) -> Result<BoxStream, Failure> {
    let policy = stream.direct.as_deref();
    let addrs = match policy {
        Some(policy) => allowed_by_final_rules(policy, destination.network, addrs).await?,
        None => addrs,
    };
    let addrs = google_fronts_first(addrs, destination, stream).await;
    let dialed = dial_tcp(&addrs, &race_policy(stream), &socket_options(stream)).await?;
    let local = dialed.stream.local_addr().ok();
    let mut connection = shaped(dialed.stream, stream, false);
    if let Some(version) = policy
        .map(|policy| policy.proxy_protocol)
        .filter(|version| *version != 0)
    {
        // Who the backend should believe connected: the client, when the
        // caller said who it is, and this machine's own address otherwise.
        let client = CLIENT_ADDR.try_with(|addr| *addr).ok();
        let target = addrs.first().copied().or_else(|| {
            destination
                .address
                .as_ip()
                .map(|ip| SocketAddr::new(ip, destination.port))
        });
        let header = zero_protocol::proxy_protocol::encode(version, client.or(local), target);
        connection.write_all(&header).await.map_err(|error| {
            Failure::new(FailureKind::TcpReset, Stage::RequestSent).with_detail(error.to_string())
        })?;
    }
    Ok(connection)
}

/// For a direct connection that hides its name and goes to a Google-hosted
/// site, the front ends known to answer (`crate::google_front`) go ahead of
/// the addresses DNS gave, which may be the blocked ones. Anything else is
/// left as resolved.
async fn google_fronts_first(
    addrs: Vec<SocketAddr>,
    destination: &Destination,
    stream: &StreamSettings,
) -> Vec<SocketAddr> {
    let Address::Domain(host) = &destination.address else {
        return addrs;
    };
    if stream.evasion.sni_desync.is_none()
        || destination.port != 443
        || !crate::google_front::hosted(host)
    {
        return addrs;
    }
    let mut ordered: Vec<SocketAddr> = crate::google_front::reachable()
        .await
        .into_iter()
        .map(|ip| SocketAddr::new(ip, destination.port))
        .collect();
    let rest: Vec<_> = addrs
        .into_iter()
        .filter(|addr| !ordered.contains(addr))
        .collect();
    tracing::debug!(%host, fronts = ordered.len(), "Google front ends go first");
    ordered.extend(rest);
    ordered
}

tokio::task_local! {
    /// The client whose connection is being made, for the PROXY protocol
    /// header a Freedom outbound can send.
    static CLIENT_ADDR: SocketAddr;
}

/// Run `connect` knowing which client it is for.
pub async fn with_client_addr<F: std::future::Future>(client: SocketAddr, connect: F) -> F::Output {
    CLIENT_ADDR.scope(client, connect).await
}

/// `destination` after the Freedom policy's `redirect`: its address and/or
/// port replaced.
pub fn redirected(
    destination: &Destination,
    policy: Option<&zero_config::DirectPolicy>,
) -> Destination {
    match policy.and_then(|policy| policy.redirect.as_ref()) {
        Some(redirect) => Destination {
            address: redirect
                .address
                .clone()
                .unwrap_or_else(|| destination.address.clone()),
            port: redirect.port.unwrap_or(destination.port),
            network: destination.network,
        },
        None => destination.clone(),
    }
}

/// The addresses of `addrs` the policy's `finalRules` let through. A
/// connection with none left is held for the rule's block delay and then
/// refused; the delay is random in its range so the time says nothing about
/// which rule fired.
pub async fn allowed_by_final_rules(
    policy: &zero_config::DirectPolicy,
    network: zero_core::Network,
    addrs: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, Failure> {
    if policy.final_rules.is_empty() {
        return Ok(addrs);
    }
    let mut blocked_by = None;
    let allowed: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(
            |addr| match policy.decide(network, addr.ip(), addr.port()) {
                Some(rule) if !rule.allow => {
                    blocked_by.get_or_insert(rule.block_delay_secs);
                    false
                }
                _ => true,
            },
        )
        .collect();
    if !allowed.is_empty() {
        return Ok(allowed);
    }
    if let Some((low, high)) = blocked_by {
        let secs = if high > low {
            rand::Rng::gen_range(&mut rand::thread_rng(), low..=high)
        } else {
            low
        };
        tokio::time::sleep(std::time::Duration::from_secs(secs.into())).await;
    }
    Err(Failure::new(FailureKind::LocalPolicy, Stage::Resolving)
        .with_detail("the destination is blocked by the freedom finalRules"))
}

/// Direct connection using the compiled, leak-aware DNS resolver.
pub async fn connect_direct_with_resolver(
    destination: &Destination,
    stream: &StreamSettings,
    resolver: &zero_dns::Resolver,
) -> Result<BoxStream, Failure> {
    let policy = stream.direct.as_deref();
    let destination = &redirected(destination, policy);
    let ips = resolver
        .resolve_address(&destination.address, resolver.settings().query_strategy)
        .await
        .map_err(|error| {
            Failure::new(FailureKind::DnsNoData, Stage::Resolving)
                .with_confidence(Confidence::Confirmed)
                .with_detail(error.to_string())
        })?;
    let addrs = ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, destination.port))
        .collect::<Vec<_>>();
    let addrs = match &destination.address {
        Address::Ip(_) => addrs,
        Address::Domain(_) => {
            filter_direct_addresses(addrs, stream.sockopt.domain_strategy, &destination.address)?
        }
    };
    if let Some(proxy) = env_proxy_for(&destination.address.host_string()) {
        return dial_via_env_proxy(proxy, destination, stream).await;
    }
    dial_direct(addrs, destination, stream).await
}

async fn dial_via_env_proxy(
    proxy: EnvProxy,
    destination: &Destination,
    stream: &StreamSettings,
) -> Result<BoxStream, Failure> {
    if proxy.https {
        return Err(
            Failure::new(FailureKind::LocalPolicy, Stage::SocketConnected)
                .with_detail("HTTPS_PROXY TLS proxies are not supported; use HTTP_PROXY"),
        );
    }
    let dialed = dial_tcp(&[proxy.addr], &race_policy(stream), &socket_options(stream)).await?;
    let mut tcp = dialed.stream;
    let host = format!("{}:{}", destination.address.host_string(), destination.port);
    let request =
        format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nProxy-Connection: keep-alive\r\n\r\n");
    tcp.write_all(request.as_bytes()).await.map_err(|error| {
        Failure::new(FailureKind::TcpReset, Stage::RequestSent).with_detail(error.to_string())
    })?;
    // Read exactly up to the end of the CONNECT response header. Reading more
    // would swallow the first bytes of the tunnelled stream; reading a fixed
    // block and hoping it lands on the boundary is the bug this avoids.
    let mut response = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = tokio::io::AsyncReadExt::read(&mut tcp, &mut byte)
            .await
            .map_err(|error| {
                Failure::new(FailureKind::TcpReset, Stage::FirstByteReceived)
                    .with_detail(error.to_string())
            })?;
        if n == 0 {
            return Err(
                Failure::new(FailureKind::TcpReset, Stage::FirstByteReceived)
                    .with_detail("upstream proxy closed before completing CONNECT"),
            );
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
        if response.len() > 8192 {
            return Err(
                Failure::new(FailureKind::ProtocolRejected, Stage::FirstByteReceived)
                    .with_detail("upstream proxy CONNECT response header too large"),
            );
        }
    }
    let status = std::str::from_utf8(&response)
        .ok()
        .and_then(|text| text.lines().next())
        .unwrap_or("");
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return Err(
            Failure::new(FailureKind::ProtocolRejected, Stage::FirstByteReceived)
                .with_detail(format!("upstream proxy rejected CONNECT: {status}")),
        );
    }
    Ok(boxed(tcp))
}

/// Apply Freedom's/Sockopt's requested address family immediately before the
/// socket race.  A resolver can legitimately return both families; leaving
/// that list unfiltered made an explicit `UseIPv4` or `UseIPv6` setting merely
/// decorative and could send traffic to the family the operator ruled out.
fn filter_direct_addresses(
    addrs: Vec<SocketAddr>,
    strategy: zero_config::DomainStrategy,
    destination: &Address,
) -> Result<Vec<SocketAddr>, Failure> {
    let filtered = filter_family(addrs, strategy);
    if filtered.is_empty() {
        return Err(Failure::new(FailureKind::DnsNoData, Stage::Resolving)
            .with_confidence(Confidence::Confirmed)
            .with_detail(format!(
                "resolver returned no addresses for {} allowed by {strategy:?}",
                destination.host_string()
            )));
    }
    Ok(filtered)
}

/// Filter resolved addresses by the configured family policy.
pub fn filter_family(
    addrs: Vec<SocketAddr>,
    strategy: zero_config::DomainStrategy,
) -> Vec<SocketAddr> {
    let want4 = strategy.wants_ipv4();
    let want6 = strategy.wants_ipv6();
    addrs
        .into_iter()
        .filter(|a| match a.ip() {
            IpAddr::V4(_) => want4,
            IpAddr::V6(_) => want6,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Iran's resolvers answer a filtered name with the block page; those
    /// answers must never be dialled. Ordinary private and public addresses
    /// stay usable (a self-hosted server can legitimately be on a LAN).
    #[test]
    fn forged_dns_answers_are_recognised() {
        for forged in [
            "10.10.34.34",
            "10.10.34.35",
            "10.10.34.36",
            "0.0.0.0",
            "127.0.0.1",
            "::",
            "::1",
            // The same block page, as the AAAA answer and in mapped form.
            "2001:4188:2:600:10:10:34:34",
            "2001:4188:2:600:10:10:34:36",
            "::ffff:10.10.34.34",
        ] {
            assert!(is_hijacked_answer(forged.parse().unwrap()), "{forged}");
        }
        for real in [
            "104.16.1.1",
            "192.168.1.10",
            "10.0.0.5",
            "2606:4700::1111",
            "2001:4188:2:600:10:10:34:37",
            "::ffff:104.16.1.1",
        ] {
            assert!(!is_hijacked_answer(real.parse().unwrap()), "{real}");
        }
    }

    /// The server's own name, resolved by the engine's resolver, never comes
    /// back as the filter's block page when anything real is beside it, and an
    /// address given as an IP is never second-guessed.
    #[tokio::test]
    async fn a_servers_name_drops_the_block_page_from_its_answers() {
        use zero_config::dns::{DnsSettings, HostValue};
        let mut hosts = std::collections::BTreeMap::new();
        hosts.insert(
            Box::from("mixed.example"),
            HostValue::Addresses(vec![
                Address::parse_host("10.10.34.34"),
                Address::parse_host("2001:4188:2:600:10:10:34:34"),
                Address::parse_host("203.0.113.9"),
            ]),
        );
        let resolver = zero_dns::Resolver::new(DnsSettings {
            hosts,
            ..DnsSettings::default()
        });
        let found = resolver
            .resolve_server(&Address::parse_host("mixed.example"))
            .await
            .unwrap();
        assert_eq!(found, vec!["203.0.113.9".parse::<IpAddr>().unwrap()]);
        let literal = Address::parse_host("10.10.34.34");
        assert_eq!(
            resolver.resolve_server(&literal).await.unwrap(),
            vec!["10.10.34.34".parse::<IpAddr>().unwrap()],
            "an address the user wrote is theirs to dial"
        );
    }

    #[tokio::test]
    async fn an_ip_endpoint_is_used_as_is() {
        let address = Address::parse_host("203.0.113.9");
        let resolved = resolve_endpoint(&address, 443).await.unwrap();
        assert_eq!(resolved, vec!["203.0.113.9:443".parse().unwrap()]);
    }
    use zero_config::DomainStrategy;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn ip_endpoint_needs_no_resolution() {
        let a = resolve_endpoint(&Address::parse_host("1.2.3.4"), 443)
            .await
            .unwrap();
        assert_eq!(a, vec![sa("1.2.3.4:443")]);
    }

    #[test]
    fn family_filter_respects_strategy() {
        let addrs = vec![sa("1.2.3.4:443"), sa("[::1]:443")];
        assert_eq!(
            filter_family(addrs.clone(), DomainStrategy::UseIpv4).len(),
            1
        );
        assert_eq!(
            filter_family(addrs.clone(), DomainStrategy::UseIpv6).len(),
            1
        );
        assert_eq!(filter_family(addrs, DomainStrategy::UseIp).len(), 2);
    }

    #[test]
    fn fragment_policy_maps_from_config() {
        use zero_config::{FragmentConfig, RangeDuration, RangeU32};
        let p = fragment_policy(&FragmentConfig {
            packets: FragmentPackets::TlsHello,
            length: RangeU32::new(100, 200),
            delay: RangeDuration::millis(1, 1),
            lead_lengths: vec![RangeU32::new(104, 104)],
            lead_delays: vec![RangeDuration::millis(2, 3)],
            ..FragmentConfig::empty_record()
        });
        assert_eq!(p.packets, Packets::TlsHello);
        assert_eq!(p.length_min, 100);
        assert_eq!(p.length_max, 200);
        assert_eq!(p.interval_min_ms, 1);
        assert_eq!(p.empty_records, 1);
        assert_eq!(p.lead_lengths, [(104, 104)]);
        assert_eq!(p.lead_delays, [(2, 3)]);
    }

    /// Two masks, as the recipes passed around in Iran pair them: the top
    /// one puts an empty record and a re-framed hello in one write, the one
    /// underneath cuts that write into TCP segments. What arrives is the
    /// top mask's bytes, whole and in order.
    #[tokio::test]
    async fn two_stacked_masks_deliver_the_top_masks_bytes() {
        use tokio::io::AsyncReadExt;
        use zero_config::{FragmentConfig, RangeDuration, RangeU32};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut settings = StreamSettings::default();
        settings.evasion.tcp_fragment = Some(FragmentConfig {
            length: RangeU32::new(1, 1),
            lead_lengths: vec![RangeU32::new(10, 10)],
            max_split: RangeU32::new(4, 4),
            ..FragmentConfig::empty_record()
        });
        settings.evasion.tcp_fragment_under = Some(FragmentConfig {
            packets: FragmentPackets::Range { from: 1, to: 1 },
            length: RangeU32::new(1, 1),
            lead_lengths: vec![RangeU32::new(20, 20)],
            delay: RangeDuration::millis(1, 1),
            max_split: RangeU32::new(5, 5),
            ..FragmentConfig::default()
        });
        let resolver = zero_dns::Resolver::new(zero_config::dns::DnsSettings::default());
        let destination = Destination::tcp(Address::Ip(std::net::Ipv4Addr::LOCALHOST.into()), port);
        let mut stream = connect_direct_with_resolver(&destination, &settings, &resolver)
            .await
            .unwrap();
        let body: Vec<u8> = (0..40).collect();
        let hello = [&[0x16, 3, 1, 0, 40][..], &body].concat();
        stream.write_all(&hello).await.unwrap();
        stream.flush().await.unwrap();
        let (mut accepted, _) = listener.accept().await.unwrap();
        // Empty, ten bytes, one byte, and the fourth piece takes the rest.
        let mut expected = vec![0x16, 3, 3, 0, 0];
        for piece in [&body[..10], &body[10..11], &body[11..]] {
            expected.extend_from_slice(&[0x16, 3, 1, 0, piece.len() as u8]);
            expected.extend_from_slice(piece);
        }
        let mut seen = vec![0u8; expected.len()];
        accepted.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen, expected);
    }

    /// A direct (`freedom`) connection shapes its first write like any other
    /// outbound: the mask is on the stream settings, not on a protocol.
    #[tokio::test]
    async fn a_direct_connection_applies_its_fragment_mask() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut settings = StreamSettings::default();
        settings.evasion.tcp_fragment = Some(zero_config::FragmentConfig::empty_record());
        let resolver = zero_dns::Resolver::new(zero_config::dns::DnsSettings::default());
        let destination = Destination::tcp(Address::Ip(std::net::Ipv4Addr::LOCALHOST.into()), port);
        let mut stream = connect_direct_with_resolver(&destination, &settings, &resolver)
            .await
            .unwrap();
        // A ClientHello-shaped record, as a browser behind the proxy sends it.
        let hello = [&[0x16, 3, 1, 0, 4][..], b"helo"].concat();
        stream.write_all(&hello).await.unwrap();
        stream.flush().await.unwrap();
        let (mut accepted, _) = listener.accept().await.unwrap();
        let mut seen = [0u8; 14];
        accepted.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen[..5], [0x16, 3, 3, 0, 0], "the empty record leads");
        assert_eq!(seen[5..], hello[..]);
    }

    #[test]
    fn congestion_control_flows_to_the_dial() {
        use std::sync::Arc;
        use zero_config::Sockopt;
        let s = StreamSettings {
            sockopt: Sockopt {
                tcp_congestion: Some(Arc::from("bbr")),
                ..Default::default()
            },
            ..Default::default()
        };
        let o = socket_options(&s);
        assert_eq!(o.tcp_congestion.as_deref(), Some("bbr"));
        // None must reach the dial as None: "leave the system default alone"
        // is a distinct request from any name.
        assert!(socket_options(&StreamSettings::default())
            .tcp_congestion
            .is_none());
    }

    #[test]
    fn tls_params_fall_back_to_the_endpoint_host() {
        use zero_config::TlsConfig;
        let s = StreamSettings {
            security: Security::Tls(TlsConfig {
                server_name: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        let p = tls_params(&s, "fallback.example").unwrap();
        assert_eq!(p.server_name, "fallback.example");
    }

    #[test]
    fn explicit_sni_overrides_the_host_and_keeps_case() {
        use std::sync::Arc;
        use zero_config::TlsConfig;
        let s = StreamSettings {
            security: Security::Tls(TlsConfig {
                server_name: Some(Arc::from("ExAmPle.WorKERS.dev")),
                alpn: vec!["http/1.1".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let p = tls_params(&s, "other.host").unwrap();
        assert_eq!(p.server_name, "ExAmPle.WorKERS.dev");
        assert_eq!(p.alpn, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn websocket_never_offers_h2() {
        use zero_config::{TlsConfig, WebSocketConfig};
        let alpn_of = |alpn: &[&str], transport: Transport| {
            let s = StreamSettings {
                transport,
                security: Security::Tls(TlsConfig {
                    alpn: alpn.iter().map(|a| Box::from(*a)).collect(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            tls_params(&s, "host.example").unwrap().alpn
        };
        let h1 = vec![b"http/1.1".to_vec()];
        let ws = || Transport::WebSocket(WebSocketConfig::default());
        // What a BPB panel writes, and what a link without a list means.
        assert_eq!(alpn_of(&["h2", "http/1.1"], ws()), h1);
        assert_eq!(alpn_of(&[], ws()), h1);
        assert_eq!(alpn_of(&["h2"], ws()), h1);
        assert_eq!(
            alpn_of(
                &["h2", "http/1.1"],
                Transport::HttpUpgrade(WebSocketConfig::default())
            ),
            h1
        );
        // Carriers that speak HTTP/2 keep what they were given.
        assert_eq!(
            alpn_of(&["h2", "http/1.1"], Transport::Raw),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn unresolved_ech_never_downgrades_to_plain_tls() {
        use zero_config::{EchConfig, TlsConfig};
        let s = StreamSettings {
            security: Security::Tls(TlsConfig {
                ech: Some(EchConfig {
                    config_list: Box::new([]),
                    server_name: Some("inner.example".into()),
                    query_name: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(tls_params(&s, "public.example").is_none());
    }

    #[test]
    fn plain_security_produces_no_tls_layer() {
        assert!(tls_params(&StreamSettings::default(), "h").is_none());
    }

    #[test]
    fn a_zerov1_link_becomes_the_transport_settings_it_names() {
        use std::time::Duration;
        let key = "A".repeat(43);
        let user = "A".repeat(22);
        let config = |extra: &str| {
            let link = format!(
                "zerov1://{user}@203.0.113.9:443?key={key}&path=/static/ab&sni=front.test{extra}"
            );
            let outbound = zero_config::share_link::parse_link(&link).unwrap().outbound;
            let OutboundProtocol::Tide(tide) = &outbound.protocol else {
                panic!("expected a ZeroV1 outbound")
            };
            tide_client_config(&outbound, tide, "203.0.113.9")
        };
        // A plain link keeps every default, and the TLS name is the authority.
        let plain = config("");
        assert_eq!(plain.host, "front.test");
        assert_eq!(plain.tuning, zero_transport::tide::Tuning::default());
        assert_eq!(plain.linger, Duration::from_secs(2));
        assert_eq!(
            plain.rotation,
            Some(zero_transport::tide::Rotation::default())
        );

        let tuned = config(
            "&authority=Real.Example&pipes=1&uploads=2&ping=30&idle=200&linger=250\
             &age=60-90&volume=128&ua=safari&headers=referer:https://x.test/",
        );
        assert_eq!(tuned.host, "real.example");
        assert_eq!(tuned.tuning.down_pipes, 1);
        assert_eq!(tuned.tuning.up_pipes, 2);
        assert_eq!(tuned.tuning.ping, Duration::from_secs(30));
        assert_eq!(tuned.tuning.idle, Duration::from_secs(200));
        assert_eq!(tuned.linger, Duration::from_millis(250));
        assert!(tuned.tuning.look.user_agent.contains("Safari/"));
        assert_eq!(tuned.tuning.look.headers.len(), 1);
        let rotation = tuned.rotation.unwrap();
        assert_eq!(
            (rotation.min_age, rotation.max_age, rotation.max_bytes),
            (Duration::from_secs(60), Duration::from_secs(90), 128 << 20)
        );
        // `rotate=0` still wins over the age and volume.
        assert!(config("&rotate=0&age=60-90").rotation.is_none());
        // Packet upload is zero linger unless the link says otherwise.
        assert_eq!(config("&upload=packet").linger, Duration::ZERO);
        assert_eq!(
            config("&upload=packet&linger=300").linger,
            Duration::from_millis(300)
        );
    }
}
