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
        Address::Domain(d) => {
            let name: &str = d;
            // The system resolver first: it is fast and, for most names,
            // right. In Iran it is also the ISP's, which answers a filtered
            // name with the block page (10.10.34.x) or a dead address, so
            // those answers are thrown away rather than dialled: connecting
            // to them only ever yields "connection refused".
            let system = tokio::time::timeout(
                SYSTEM_DNS_TIMEOUT,
                tokio::net::lookup_host(format!("{name}:{port}")),
            )
            .await;
            let mut hijacked = false;
            let system_error = match system {
                Ok(Ok(iter)) => {
                    let all: Vec<SocketAddr> = iter.collect();
                    // `localhost` is loopback by definition, not by forgery.
                    let local_name = name.eq_ignore_ascii_case("localhost")
                        || name.to_ascii_lowercase().ends_with(".localhost");
                    let usable: Vec<SocketAddr> = all
                        .iter()
                        .copied()
                        .filter(|a| local_name || !is_hijacked_answer(a.ip()))
                        .collect();
                    if !usable.is_empty() {
                        return Ok(usable);
                    }
                    hijacked = !all.is_empty();
                    None
                }
                Ok(Err(e)) => Some(e.to_string()),
                Err(_) => Some("timed out".to_string()),
            };
            // Then encrypted DNS, which a middlebox can block but not forge.
            let encrypted = fallback_resolver()
                .lookup(name, zero_config::dns::QueryStrategy::UseIp)
                .await;
            match encrypted {
                Ok(ips) => {
                    let usable: Vec<SocketAddr> = ips
                        .into_iter()
                        .filter(|ip| !is_hijacked_answer(*ip))
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect();
                    if !usable.is_empty() {
                        return Ok(usable);
                    }
                    Err(Failure::new(FailureKind::DnsNoData, Stage::Resolving)
                        .with_confidence(Confidence::Confirmed)
                        .with_detail(format!("no usable addresses for {name}")))
                }
                Err(error) => {
                    let detail = if hijacked {
                        format!(
                            "{name} resolves to a filtering address on this network, \
                             and encrypted DNS failed: {error}"
                        )
                    } else {
                        format!(
                            "{name}: {}; encrypted DNS: {error}",
                            system_error.unwrap_or_else(|| "no addresses".into())
                        )
                    };
                    let kind = if hijacked {
                        FailureKind::DnsSuspectedInterference
                    } else {
                        FailureKind::DnsNoData
                    };
                    Err(Failure::new(kind, Stage::Resolving).with_detail(detail))
                }
            }
        }
    }
}

/// How long the system resolver gets before encrypted DNS is asked instead.
const SYSTEM_DNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);

/// An answer no public proxy server has: Iran's filtering block page
/// (10.10.34.34–36), the unspecified address and loopback, which filtering
/// resolvers return for names they refuse to answer.
pub fn is_hijacked_answer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0] == 10 && o[1] == 10 && o[2] == 34)
                || v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_loopback(),
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

fn socket_options(stream: &StreamSettings) -> SocketOptions {
    SocketOptions {
        tcp_fast_open: stream.sockopt.tcp_fast_open,
        mark: stream.sockopt.mark,
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
/// urgent byte (`zero_evasion::urgent`). Left to the device, it is the decoy
/// where the kernel can send one and the urgent byte where it cannot. A
/// system that can do neither leaves the fragment mask, as before. These
/// and the mask are not stacked: the mask would cut the hello into pieces
/// that neither of them can read a name out of.
fn shaped(tcp: TcpStream, stream: &StreamSettings, injected: bool) -> BoxStream {
    use zero_config::SniMethod;
    if let Some(spoof) = stream.evasion.sni_desync.as_ref().filter(|_| !injected) {
        let decoy = zero_evasion::decoy::supported();
        let urgent = zero_evasion::urgent::supported();
        match spoof.method {
            SniMethod::Decoy | SniMethod::Auto if decoy => {
                return boxed(zero_evasion::DecoyStream::new(tcp, &spoof.fake_sni))
            }
            SniMethod::Urgent | SniMethod::Auto if urgent => {
                return boxed(zero_evasion::UrgentStream::new(tcp))
            }
            _ => {}
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
            let mut p = TlsParams::new(sni).with_profile(profile);
            p = p.with_fingerprint_name(t.fingerprint.name());
            if !t.alpn.is_empty() {
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
    let (address, port) = outbound.endpoint().ok_or_else(|| {
        Failure::new(FailureKind::LocalPolicy, Stage::Resolving)
            .with_detail(format!("outbound {} has no endpoint", outbound.tag))
    })?;
    let outbound = materialize_ech(outbound, resolver, &address.host_string()).await?;
    let t0 = std::time::Instant::now();
    let addrs = resolver
        .resolve_address(&address, resolver.settings().query_strategy)
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
        return zero_transport::hysteria2::connect(&addrs, &tls, &hysteria.password, destination)
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
    let out = out?;
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

/// The outbound with its ECH configuration list filled in, borrowed unchanged
/// when there is nothing to discover (every connection that does not use
/// ECH discovery, i.e. almost all of them, avoids a deep clone).
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
            .server_name
            .as_deref()
            .unwrap_or(fallback_host)
            .to_string(),
        _ => unreachable!("ECH discovery requires certificate TLS"),
    };
    let config_list = resolver
        .lookup_ech_config_list(&public_name, resolver.settings().query_strategy)
        .await
        .map_err(|error| {
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
            .with_detail("Tide carries TCP streams only for now"));
    }
    let key = mux_pool_key(outbound, address, &addrs);
    let existing = {
        let clients = TIDE_CLIENTS.get_or_init(Default::default);
        let clients = clients.lock().unwrap_or_else(|p| p.into_inner());
        clients.get(&key).cloned()
    };
    let client = match existing {
        Some(client) => client,
        None => {
            let host = address.host_string();
            // Tide is HTTP/2 whatever the profile says about ALPN.
            let mut shaped = outbound.clone();
            if let Security::Tls(tls) = &mut shaped.stream.security {
                tls.alpn = vec!["h2".into()];
            }
            let shaped = Arc::new(shaped);
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
            let client = zero_transport::tide::Client::new(
                zero_transport::tide::ClientConfig {
                    host: match &outbound.stream.security {
                        Security::Tls(tls) => tls
                            .server_name
                            .as_deref()
                            .map_or_else(|| host.clone(), str::to_string),
                        _ => host.clone(),
                    },
                    path: tide.path.to_string(),
                    server_public: tide.server_key,
                    user: tide.user,
                    split: tide.split,
                    linger: if tide.packet_upload {
                        std::time::Duration::ZERO
                    } else {
                        std::time::Duration::from_secs(2)
                    },
                },
                dial,
            );
            let clients = TIDE_CLIENTS.get_or_init(Default::default);
            let mut clients = clients.lock().unwrap_or_else(|p| p.into_inner());
            // Profiles come and go; keep the map from growing with them.
            if clients.len() >= 64 {
                clients.clear();
            }
            clients.entry(key).or_insert(client).clone()
        }
    };
    client
        .open(destination.clone())
        .await
        .map(boxed)
        .map_err(|error| {
            Failure::from_io(&error, Stage::RequestSent).with_detail(format!("Tide: {error}"))
        })
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
        .resolve_address(&address, resolver.settings().query_strategy)
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
    // Hash the complete compiled outbound rather than storing credentials in
    // the process-wide pool key. The debug representation is only transient
    // input to the digest and is never retained.
    use sha2::{Digest, Sha256};
    let material = format!("{outbound:?}|{address:?}|{addrs:?}");
    let digest = Sha256::digest(material.as_bytes());
    hex::encode(digest)
}

async fn protect_socket(
    outbound: &Outbound,
    tcp: TcpStream,
    fallback_host: &str,
) -> Result<BoxStream, Failure> {
    let stream = &outbound.stream;
    let mut injected = false;
    // A raw decoy is a decoy: the urgent-byte method sends none.
    let wants_decoy =
        |config: &&zero_config::SniDesyncConfig| config.method != zero_config::SniMethod::Urgent;
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
    secure(outbound, shaped(tcp, stream, injected), fallback_host).await
}

/// TLS or REALITY over an already open byte stream: a TCP socket, or a
/// connection carried by another outbound (`dialerProxy`).
async fn secure(
    outbound: &Outbound,
    base: BoxStream,
    fallback_host: &str,
) -> Result<BoxStream, Failure> {
    let stream = &outbound.stream;
    match &stream.security {
        Security::None => Ok(base),
        Security::Tls(_) => {
            let params = tls_params(stream, fallback_host).ok_or_else(|| {
                Failure::new(FailureKind::LocalPolicy, Stage::TlsStarted)
                    .with_detail("ECH configuration discovery did not produce a usable list")
            })?;
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
            });
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
                .resolve_address(&download_address, resolver.settings().query_strategy)
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
    let download = dial_tcp(
        &download_addrs,
        &race_policy(&download_outbound.stream),
        &socket_options(&download_outbound.stream),
    )
    .await?;
    let download_fallback = download_address.host_string();
    let download = protect_socket(&download_outbound, download.stream, &download_fallback).await?;
    let fallback_host = address.host_string();
    let upload_cfg = xhttp_ws_config(settings, &fallback_host, &outbound.stream.security);
    let download_cfg = xhttp_ws_config(
        download_transport,
        &download_fallback,
        &download_settings.security,
    );
    let carrier = match (settings.xhttp_http_version, settings.xhttp_mode) {
        (XhttpHttpVersion::Http2, XhttpMode::StreamUp) => {
            let upload = dial_tcp(
                addrs,
                &race_policy(&outbound.stream),
                &socket_options(&outbound.stream),
            )
            .await?;
            let upload = protect_socket(outbound, upload.stream, &fallback_host).await?;
            xhttp::connect_stream_up_h2(upload, download, &upload_cfg, &download_cfg).await
        }
        (XhttpHttpVersion::Http2, XhttpMode::PacketUp) => {
            // Uploads ride the download's connection unless the download
            // comes from another server.
            let upload = if settings.xhttp_download.is_some() {
                let upload = dial_tcp(
                    addrs,
                    &race_policy(&outbound.stream),
                    &socket_options(&outbound.stream),
                )
                .await?;
                Some(protect_socket(outbound, upload.stream, &fallback_host).await?)
            } else {
                None
            };
            xhttp::connect_packet_up_h2(download, &download_cfg, &upload_cfg, upload).await
        }
        (XhttpHttpVersion::Http1, XhttpMode::StreamUp) => {
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
    }
    .map_err(|error| {
        Failure::new(FailureKind::HttpMalformed, Stage::RequestSent).with_detail(error)
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
    let secured = secure(outbound, carried, &fallback_host).await?;
    finish_stack(outbound, destination, secured, &fallback_host).await
}

/// Whether a connection for `outbound` can be opened before its
/// destination is known — a "warm carrier": TCP, TLS and the transport
/// upgrade done ahead of time, the protocol header (which names the
/// destination) written only when a real connection needs it.
///
/// That takes a protocol whose header is plain bytes after the upgrade
/// (VLESS without Vision or encryption, Trojan), over TLS with a WebSocket or
/// HTTPUpgrade transport, without Mux. Measured from Tehran on 2026-09-28,
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
        .resolve_address(&address, resolver.settings().query_strategy)
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
    let secured = secure(outbound, carried, &fallback_host).await?;
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
        OutboundProtocol::Tide(_) => Ok(Vec::new()),
        OutboundProtocol::Hysteria2(_) => Ok(Vec::new()),
        OutboundProtocol::Tuic(_) => Ok(Vec::new()),
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
    let dialed = dial_tcp(&addrs, &race_policy(stream), &socket_options(stream)).await?;
    Ok(shaped(dialed.stream, stream, false))
}

/// Direct connection using the compiled, leak-aware DNS resolver.
pub async fn connect_direct_with_resolver(
    destination: &Destination,
    stream: &StreamSettings,
    resolver: &zero_dns::Resolver,
) -> Result<BoxStream, Failure> {
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
    let dialed = dial_tcp(&addrs, &race_policy(stream), &socket_options(stream)).await?;
    Ok(shaped(dialed.stream, stream, false))
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
        ] {
            assert!(is_hijacked_answer(forged.parse().unwrap()), "{forged}");
        }
        for real in ["104.16.1.1", "192.168.1.10", "10.0.0.5", "2606:4700::1111"] {
            assert!(!is_hijacked_answer(real.parse().unwrap()), "{real}");
        }
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
        let mut expected = vec![0x16, 3, 1, 0, 0];
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
        assert_eq!(seen[..5], [0x16, 3, 1, 0, 0], "the empty record leads");
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
    fn unresolved_ech_never_downgrades_to_plain_tls() {
        use zero_config::{EchConfig, TlsConfig};
        let s = StreamSettings {
            security: Security::Tls(TlsConfig {
                ech: Some(EchConfig {
                    config_list: Box::new([]),
                    server_name: Some("inner.example".into()),
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
}
