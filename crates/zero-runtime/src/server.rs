//! Inbound listeners and dispatch.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};
use zero_config::{
    InboundProtocol, NoiseConfig, NoiseKind, OutboundProtocol, RuntimeConfig, VlessInboundConfig,
};
use zero_core::{boxed, Address, Destination, GenerationId, InboundId, Network, SessionContext};
use zero_protocol::socks::{self, Accepted, InboundKind};
use zero_router::{Decision, Router};

use crate::outbound;
use crate::relay::{relay, Transferred};

#[derive(Debug, Default)]
pub struct Stats {
    pub accepted: AtomicU64,
    pub succeeded: AtomicU64,
    pub failed: AtomicU64,
    pub blocked: AtomicU64,
    pub uploaded: AtomicU64,
    pub downloaded: AtomicU64,
    /// TCP sessions currently being served. A graceful drain waits for this to
    /// reach zero before the process exits.
    pub active: AtomicU64,
    /// Per-tag byte counters keyed by the Xray stat name
    /// (`inbound>>>{tag}>>>traffic>>>uplink`, etc.). Populated only for tags
    /// that have carried traffic, matching Xray, which reports absent counters
    /// as zero. A session end is not a hot path, so a mutex-guarded map is
    /// cheaper than an atomic per possible tag.
    pub traffic: StdMutex<HashMap<String, u64>>,
}

impl Stats {
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            succeeded: self.succeeded.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            uploaded: self.uploaded.load(Ordering::Relaxed),
            downloaded: self.downloaded.load(Ordering::Relaxed),
        }
    }

    /// Accumulate one relay's bytes against its inbound tag and, when the
    /// session used a named proxy outbound, that outbound tag too. Xray's
    /// convention is uplink = client→destination and downlink = the reverse,
    /// which is exactly the relay's `uploaded`/`downloaded`.
    pub fn record_tag_traffic(
        &self,
        inbound_tag: &str,
        outbound_tag: Option<&str>,
        transferred: &Transferred,
    ) {
        if transferred.uploaded == 0 && transferred.downloaded == 0 {
            return;
        }
        let mut traffic = self
            .traffic
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !inbound_tag.is_empty() {
            *traffic
                .entry(format!("inbound>>>{inbound_tag}>>>traffic>>>uplink"))
                .or_insert(0) += transferred.uploaded;
            *traffic
                .entry(format!("inbound>>>{inbound_tag}>>>traffic>>>downlink"))
                .or_insert(0) += transferred.downloaded;
        }
        if let Some(outbound_tag) = outbound_tag.filter(|tag| !tag.is_empty()) {
            *traffic
                .entry(format!("outbound>>>{outbound_tag}>>>traffic>>>uplink"))
                .or_insert(0) += transferred.uploaded;
            *traffic
                .entry(format!("outbound>>>{outbound_tag}>>>traffic>>>downlink"))
                .or_insert(0) += transferred.downloaded;
        }
    }

    /// Xray-style `{name, value}` counters, sorted by name for stable output.
    /// `reset` zeroes each counter as it is read, matching the semantics of
    /// Xray's `QueryStats reset=true`.
    pub fn traffic_counters(&self, reset: bool) -> Vec<(String, u64)> {
        let mut traffic = self
            .traffic
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut counters: Vec<(String, u64)> = traffic
            .iter()
            .map(|(name, value)| (name.clone(), *value))
            .collect();
        if reset {
            for value in traffic.values_mut() {
                *value = 0;
            }
        }
        counters.sort_by(|a, b| a.0.cmp(&b.0));
        counters
    }
}

/// Increments the active-session gauge on creation and decrements it on drop,
/// so the count is correct no matter which path a handler returns or panics on.
pub struct ActiveGuard(Arc<Stats>);

impl ActiveGuard {
    pub fn new(stats: Arc<Stats>) -> Self {
        stats.active.fetch_add(1, Ordering::Relaxed);
        Self(stats)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct StatsSnapshot {
    pub accepted: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub blocked: u64,
    pub uploaded: u64,
    pub downloaded: u64,
}

pub struct ServerConfig {
    pub config: Arc<RuntimeConfig>,
    pub generation: GenerationId,
}

/// Upper bound on everything a client does before its first proxied byte:
/// the TLS/REALITY handshake, the transport upgrade, and the protocol request
/// header. Matches Xray's default `handshake` policy. Without it a client that
/// connects and then says nothing -- a slow-loris, or a censor's half-open
/// probe -- pins a task and a descriptor for as long as it cares to.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// How many datagrams one UDP ingress may have in flight at once. Each one
/// waits up to the exchange deadline for its answer, so the ingress must not
/// wait for them one at a time -- a single unanswered query would stall every
/// other flow behind it -- yet a flood must not turn into unbounded tasks and
/// sockets either. Datagrams beyond the limit are dropped, which is what UDP
/// promises anyway.
const UDP_INFLIGHT_LIMIT: usize = 512;

/// Hard deadline on one proxied UDP exchange, including dialing the outbound.
/// Several carriers read their answer without a timeout of their own, and a
/// server that never answers must not leak the task and its connection.
const UDP_EXCHANGE_DEADLINE: Duration = Duration::from_secs(15);

async fn within_handshake<F: std::future::Future>(future: F) -> Result<F::Output, String> {
    timeout(HANDSHAKE_TIMEOUT, future).await.map_err(|_| {
        format!(
            "client handshake timed out after {}s",
            HANDSHAKE_TIMEOUT.as_secs()
        )
    })
}

struct ServerState {
    config: Arc<RuntimeConfig>,
    router: Arc<Router>,
    /// The resolver as configured, FakeDNS included: it answers the
    /// applications' own queries (`dns-out`) and maps synthetic addresses
    /// back to names.
    client_resolver: Arc<zero_dns::Resolver>,
    /// The same resolver without FakeDNS, for every lookup the runtime makes
    /// to connect somewhere (see [`zero_dns::Resolver::without_fake`]).
    resolver: Arc<zero_dns::Resolver>,
    generation: GenerationId,
    /// Per-inbound material derived from configuration once per generation
    /// instead of once per accepted connection, indexed like
    /// `config.inbounds`.
    inbounds: Arc<[InboundRuntime]>,
}

/// Inbound settings compiled once per configuration generation.
///
/// Building a rustls `ServerConfig` parses the certificate chain and private
/// key and allocates a fresh session cache and ticketer. Doing that per
/// connection cost CPU on every accept and, worse, made TLS session resumption
/// impossible, since no two connections ever shared a cache.
#[derive(Default)]
struct InboundRuntime {
    tls: Option<Result<Arc<rustls::ServerConfig>, String>>,
    reality: Option<zero_security::tls13::server::RealityServerParams>,
    transport: Option<zero_transport::ws::WsConfig>,
    raw_http_header: Option<zero_transport::tcp_header::HttpHeaderConfig>,
}

impl InboundRuntime {
    fn compile(inbound: &zero_config::Inbound) -> Self {
        let tls = match &inbound.security {
            zero_config::InboundSecurity::Tls(tls) => Some(zero_security::server::server_config(
                &tls.certificate,
                &tls.private_key,
                &tls.alpn,
            )),
            _ => None,
        };
        let reality = match &inbound.security {
            zero_config::InboundSecurity::Reality(reality) => {
                Some(zero_security::tls13::server::RealityServerParams {
                    private_key: reality.private_key,
                    server_names: reality.server_names.clone(),
                    short_ids: reality.short_ids.clone(),
                })
            }
            _ => None,
        };
        let transport = match &inbound.transport {
            zero_config::Transport::Raw => None,
            zero_config::Transport::WebSocket(w)
            | zero_config::Transport::HttpUpgrade(w)
            | zero_config::Transport::Grpc(w)
            | zero_config::Transport::Xhttp(w) => Some(zero_transport::ws::WsConfig {
                path: w.path.to_string(),
                host: w.host.as_deref().unwrap_or("").to_string(),
                headers: w
                    .headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                early_data_len: 0,
                xhttp: Default::default(),
                secure: false,
            }),
        };
        Self {
            tls,
            reality,
            transport,
            raw_http_header: inbound
                .raw_http_header
                .as_ref()
                .map(outbound::raw_http_header_config),
        }
    }
}

/// What terminating an inbound's security layer produced.
enum Secured {
    Stream(zero_core::BoxStream),
    /// An unauthenticated REALITY client, to be handed to the camouflage
    /// target with the ClientHello it already sent.
    Fallback {
        stream: tokio::net::TcpStream,
        client_hello: Vec<u8>,
        failure: String,
    },
}

/// Aborts the tasks it owns when dropped, so cancelling [`Server::run`] also
/// closes the listeners it spawned instead of leaving them accepting.
struct AbortOnDrop(Vec<tokio::task::JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

pub struct Server {
    state: arc_swap::ArcSwap<ServerState>,
    /// Routing rule-set data, held outside `ServerState` because it has its
    /// own lifecycle: a refresh replaces it without a configuration reload,
    /// and a reload must not discard data that is already current.
    geodata: Arc<arc_swap::ArcSwap<zero_router::GeoData>>,
    asset_status: Arc<StdMutex<Vec<AssetStatus>>>,
    planner: Arc<Mutex<zero_observatory::ConnectionPlanner>>,
    health: Arc<StdMutex<zero_observatory::HealthTable>>,
    clean_ip_results: Arc<StdMutex<Vec<zero_net::clean_ip::CleanIpResult>>>,
    xhttp_hub: zero_transport::xhttp::SharedSplitHub,
    xhttp_packet_hub: zero_transport::xhttp::SharedPacketHub,
    /// Shared ticket source for balancer selection. Keeping this outside the
    /// immutable config graph means reloads do not reset a live rotation back
    /// to the first member.
    selection_counter: AtomicU64,
    /// Flipped once every inbound listener is bound and accepting.
    ///
    /// Callers otherwise have no way to tell "starting up" from "started" but
    /// to poll the ports, and probing a port is not a safe way to ask: a UDP
    /// bind probe competes with the listener for the very port it is asking
    /// about, and can take it away. A host application embedding the runtime
    /// needs this for the same reason a test does.
    listening: tokio::sync::watch::Sender<bool>,
    /// Lock-free mirror of the planner rung used when materialising an
    /// outbound for a new session.
    planner_strategy: AtomicU8,
    /// Lock-free mirror of the shortest time-triggered reset the planner has
    /// measured, in milliseconds; `0` means no such evidence exists.
    ///
    /// Keepalive shaping needs the *number*, not just the rung: a carrier has
    /// to be retired before whatever deadline was actually observed, and a
    /// fixed guess would be useless on a short timeout and wasteful on a long
    /// one. Mirrored here for the same reason the rung is — materialising an
    /// outbound must not take the planner lock on every new session.
    planner_flow_lifetime_ms: AtomicU64,
    pub stats: Arc<Stats>,
}

/// A transport's first stream, and for multiplexing transports the channel
/// its later streams arrive on.
type AcceptedTransport = (
    zero_core::BoxStream,
    Option<tokio::sync::mpsc::Receiver<zero_core::BoxStream>>,
);

/// The configuration generation a session was accepted under. Handlers
/// borrow their inbound settings from it rather than cloning user lists,
/// credentials and sniffing rules for every connection.
struct InboundSession {
    state: Arc<ServerState>,
}

struct Hysteria2UdpSession {
    connection: h3_quinn::quinn::Connection,
    session_id: u32,
    packet_id: u16,
    peer: SocketAddr,
    destination: Destination,
    payload: Vec<u8>,
}

/// Last refresh result per rule-set file, for the management API.
#[derive(Debug, Clone)]
struct AssetStatus {
    name: String,
    outcome: String,
    detail: Option<String>,
    entries: Option<usize>,
    at: std::time::SystemTime,
}

impl Server {
    pub fn new(cfg: ServerConfig) -> Self {
        let geodata = Arc::new(arc_swap::ArcSwap::from_pointee(Self::initial_geodata(
            &cfg.config,
        )));
        let state = Self::build_state(cfg.config, cfg.generation, &geodata.load_full());
        Server {
            state: arc_swap::ArcSwap::from_pointee(state),
            geodata,
            asset_status: Arc::new(StdMutex::new(Vec::new())),
            planner: Arc::new(Mutex::new(zero_observatory::ConnectionPlanner::new(
                b"zray-local-network-profile",
            ))),
            health: Arc::new(StdMutex::new(zero_observatory::HealthTable::default())),
            clean_ip_results: Arc::new(StdMutex::new(Vec::new())),
            xhttp_hub: Arc::new(zero_transport::xhttp::SplitHub::new()),
            xhttp_packet_hub: Arc::new(zero_transport::xhttp::PacketHub::new()),
            selection_counter: AtomicU64::new(0),
            listening: tokio::sync::watch::channel(false).0,
            planner_strategy: AtomicU8::new(zero_observatory::PathStrategy::DirectReality.as_u8()),
            planner_flow_lifetime_ms: AtomicU64::new(0),
            stats: Arc::new(Stats::default()),
        }
    }

    /// Return bounded, local-only outbound health evidence for the management
    /// API. It contains endpoint tags and timing counters, never destinations
    /// or payload data.
    pub fn health_snapshot(&self) -> serde_json::Value {
        let health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entries = self
            .config()
            .outbounds
            .iter()
            .map(|outbound| {
                let sample = health.sample(&outbound.tag);
                serde_json::json!({
                    "tag": outbound.tag.as_ref(),
                    "successes": sample.successes,
                    "failures": sample.failures,
                    "consecutiveFailures": sample.consecutive_failures,
                    "latencyMs": sample.latency.map(|value| value.as_secs_f64() * 1000.0),
                })
            })
            .collect::<Vec<_>>();
        serde_json::Value::Array(entries)
    }

    /// Return the latest bounded clean-IP application probes. Only the
    /// operator-supplied edge address and response progress are retained.
    pub fn clean_ip_snapshot(&self) -> serde_json::Value {
        let results = self
            .clean_ip_results
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        serde_json::Value::Array(
            results
                .iter()
                .map(|result| {
                    serde_json::json!({
                        "address": result.address.to_string(),
                        "elapsedMs": result.elapsed.as_secs_f64() * 1000.0,
                        "status": result.status,
                        "responseBytes": result.response_bytes,
                        "success": result.success,
                    })
                })
                .collect(),
        )
    }

    /// Assemble the startup dataset: whatever the host supplied through the
    /// environment, overlaid with any validated cached rule sets. A cache that
    /// fails validation is reported and skipped, never merged.
    fn initial_geodata(config: &RuntimeConfig) -> zero_router::GeoData {
        let mut geodata = zero_router::GeoData::from_environment();
        let Some(assets) = config.assets.as_ref() else {
            return geodata;
        };
        let store = asset_store(assets);
        let specs = asset_specs(assets);
        if specs.is_empty() {
            return geodata;
        }
        let (cached, problems) = store.load_geodata(&specs);
        for problem in &problems {
            warn!(%problem, "cached rule set is unusable and was not loaded");
        }
        geodata.merge(cached);
        geodata
    }

    fn build_router(config: &RuntimeConfig, geodata: &zero_router::GeoData) -> Arc<Router> {
        let router = Arc::new(Router::build_with_geodata(config, geodata));
        if !router.unresolved.is_empty() {
            warn!(
                count = router.unresolved.len(),
                tags = %router.unresolved.iter().take(8).map(|t| t.to_string()).collect::<Vec<_>>().join(", "),
                "geosite/geoip rules are skipped: no geodata loaded"
            );
        }
        router
    }

    fn build_state(
        config: Arc<RuntimeConfig>,
        generation: GenerationId,
        geodata: &zero_router::GeoData,
    ) -> ServerState {
        let router = Self::build_router(&config, geodata);
        let client_resolver = Arc::new(zero_dns::Resolver::new(config.dns.clone()));
        ServerState {
            resolver: Arc::new(client_resolver.without_fake()),
            client_resolver,
            inbounds: config
                .inbounds
                .iter()
                .map(InboundRuntime::compile)
                .collect::<Vec<_>>()
                .into(),
            config,
            router,
            generation,
        }
    }

    /// Atomically replace the routing, DNS, outbound and authentication graph.
    ///
    /// Existing sessions retain the old `Arc` state until they finish. The
    /// listener topology is deliberately kept stable: changing a bound port
    /// or protocol during reload would create a partial generation and can
    /// strand clients. Callers must restart for that topology change.
    pub fn reload(
        &self,
        config: Arc<RuntimeConfig>,
        generation: GenerationId,
    ) -> Result<(), String> {
        let current = self.state.load();
        if current.config.inbounds.len() != config.inbounds.len() {
            return Err("reload cannot change the inbound listener topology".into());
        }
        for (old, new) in current.config.inbounds.iter().zip(config.inbounds.iter()) {
            if old.listen != new.listen
                || old.port != new.port
                || std::mem::discriminant(&old.protocol) != std::mem::discriminant(&new.protocol)
            {
                return Err(format!(
                    "reload cannot change inbound {} listener topology",
                    old.tag
                ));
            }
        }
        config.validate()?;
        // Balancer health is keyed by outbound tag. A host that re-orders its
        // servers on reload (the mobile app lists them best first) points a
        // tag at a different server, which must not inherit the latency and
        // failures measured for the one it replaced.
        {
            let mut health = self
                .health
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for old in current.config.outbounds.iter() {
                let unchanged = config
                    .outbound_by_tag(&old.tag)
                    .is_some_and(|new| format!("{new:?}") == format!("{old:?}"));
                if !unchanged {
                    health.forget(&old.tag);
                }
            }
        }
        let mut next = Self::build_state(config, generation, &self.geodata.load_full());
        // A reload builds a fresh resolver on purpose: a network change is a
        // reload too (`zray_network_changed`), and pooled DoH/DoT connections
        // bound to the old interface must go. The FakeDNS mappings the
        // applications already hold must survive it, though, or every
        // address they cached would lead nowhere.
        if next.client_resolver.has_fake() {
            let adopted = (*next.client_resolver).clone().adopt_fake_state(&current.client_resolver);
            next.resolver = Arc::new(adopted.without_fake());
            next.client_resolver = Arc::new(adopted);
        }
        self.state.store(Arc::new(next));
        Ok(())
    }

    /// Recompile the router against newly installed rule-set data, keeping the
    /// current configuration generation. Sessions in flight keep the old
    /// `Arc`; new sessions see the new rules.
    ///
    /// Only the router changes. The resolver in particular is kept: a fresh
    /// one would forget every FakeDNS mapping it handed out, so each session
    /// opened afterwards to an address an application had already resolved
    /// would be routed by a meaningless synthetic IP. It would also discard
    /// the DNS cache and the compiled inbound TLS state for no reason.
    ///
    /// `rcu` rather than load-then-store: a reload landing in between must
    /// not be overwritten by a router compiled for the configuration it
    /// replaced.
    fn rebuild_router_for_new_geodata(&self) {
        let geodata = self.geodata.load_full();
        self.state.rcu(|current| ServerState {
            config: Arc::clone(&current.config),
            router: Self::build_router(&current.config, &geodata),
            client_resolver: Arc::clone(&current.client_resolver),
            resolver: Arc::clone(&current.resolver),
            generation: current.generation,
            inbounds: Arc::clone(&current.inbounds),
        });
    }

    /// Bind every supported inbound and serve until cancelled.
    ///
    /// Every listener and background task is owned by this future: dropping
    /// it (a shutdown signal winning a `select!`, or an aborted task) closes
    /// the listeners, so a drain that follows sees no new sessions. Sessions
    /// already accepted keep running until they finish on their own.
    pub async fn run(self: Arc<Self>) -> std::io::Result<()> {
        let mut background = AbortOnDrop(Vec::with_capacity(3));
        let mut handles = AbortOnDrop(Vec::new());
        let handles_vec = &mut handles.0;

        let initial = self.state.load_full();
        // Keep one watcher alive for the lifetime of the server. It observes
        // the current generation on every pass, so an API reload can enable,
        // disable, or retune the observatory without restarting listeners.
        let me = Arc::clone(&self);
        background.0.push(tokio::spawn(async move {
            me.run_observatory().await;
        }));
        let me = Arc::clone(&self);
        background.0.push(tokio::spawn(async move {
            me.run_asset_refresh().await;
        }));
        let me = Arc::clone(&self);
        background.0.push(tokio::spawn(async move {
            me.run_strategy_descent().await;
        }));
        for (idx, inbound) in initial.config.inbounds.iter().enumerate() {
            let addr = SocketAddr::new(
                inbound
                    .listen
                    .as_ip()
                    .unwrap_or_else(|| "127.0.0.1".parse().unwrap()),
                inbound.port,
            );

            if let InboundProtocol::Tun(tun) = &inbound.protocol {
                let me = Arc::clone(&self);
                let id = InboundId(idx as u32);
                let tag = inbound.tag.clone();
                let tun = tun.clone();
                handles_vec.push(tokio::spawn(async move {
                    me.serve_tun(id, tag, tun).await;
                }));
                continue;
            }

            if let InboundProtocol::Hysteria2(_) = &inbound.protocol {
                let zero_config::InboundSecurity::Tls(tls) = &inbound.security else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Hysteria2 inbound requires certificate TLS",
                    ));
                };
                let endpoint = zero_transport::xhttp::h3_server_endpoint(
                    addr,
                    &tls.certificate,
                    &tls.private_key,
                )
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
                info!(tag = %inbound.tag, %addr, protocol = ?inbound.protocol, "listening");
                let me = Arc::clone(&self);
                let id = InboundId(idx as u32);
                handles_vec.push(tokio::spawn(async move {
                    me.accept_hysteria2_loop(endpoint, id).await;
                }));
                continue;
            }

            if let InboundProtocol::Tuic(_) = &inbound.protocol {
                let zero_config::InboundSecurity::Tls(tls) = &inbound.security else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "TUIC inbound requires certificate TLS",
                    ));
                };
                let endpoint = zero_transport::xhttp::h3_server_endpoint(
                    addr,
                    &tls.certificate,
                    &tls.private_key,
                )
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
                info!(tag = %inbound.tag, %addr, protocol = ?inbound.protocol, "listening");
                let me = Arc::clone(&self);
                let id = InboundId(idx as u32);
                handles_vec.push(tokio::spawn(async move {
                    me.accept_tuic_loop(endpoint, id).await;
                }));
                continue;
            }

            if let zero_config::Transport::Xhttp(settings) = &inbound.transport {
                if settings.xhttp_http_version == zero_config::XhttpHttpVersion::Http3 {
                    let zero_config::InboundSecurity::Tls(tls) = &inbound.security else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "XHTTP HTTP/3 inbound requires certificate TLS",
                        ));
                    };
                    let endpoint = zero_transport::xhttp::h3_server_endpoint(
                        addr,
                        &tls.certificate,
                        &tls.private_key,
                    )
                    .map_err(|error| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
                    })?;
                    info!(tag = %inbound.tag, %addr, protocol = ?inbound.protocol, "listening");
                    let me = Arc::clone(&self);
                    let id = InboundId(idx as u32);
                    handles_vec.push(tokio::spawn(async move {
                        me.accept_h3_loop(endpoint, id).await;
                    }));
                    continue;
                }
            }

            if let InboundProtocol::Dokodemo {
                target: Some(target),
                network: Network::Udp,
            } = &inbound.protocol
            {
                let socket = UdpSocket::bind(addr).await?;
                info!(tag = %inbound.tag, %addr, protocol = ?inbound.protocol, "listening");
                let me = Arc::clone(&self);
                let tag = inbound.tag.clone();
                let target = target.clone();
                let id = InboundId(idx as u32);
                handles_vec.push(tokio::spawn(async move {
                    me.serve_dokodemo_udp(socket, id, tag, target).await;
                }));
                continue;
            }
            if matches!(inbound.protocol, InboundProtocol::Dokodemo { .. }) {
                debug!(tag = %inbound.tag, "dokodemo-door TCP inbound needs a fixed target; skipping");
                continue;
            }

            let listener = zero_net::prepare_listener(addr)?;
            info!(tag = %inbound.tag, %addr, protocol = ?inbound.protocol, "listening");

            let me = Arc::clone(&self);
            let id = InboundId(idx as u32);
            handles_vec.push(tokio::spawn(async move {
                me.accept_loop(listener, id).await;
            }));
        }

        if handles_vec.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no supported inbound to listen on",
            ));
        }

        // Every listener above is bound before its accept loop is spawned, so
        // reaching here means the server is accepting.
        // `send_replace`, not `send`: a `watch` send fails and leaves the
        // value untouched when no receiver happens to exist at that instant,
        // which for a signal that is latched once is a silent loss — every
        // later subscriber would then wait forever for a transition that
        // already happened.
        self.listening.send_replace(true);

        for handle in handles_vec.iter_mut() {
            let _ = handle.await;
        }
        drop(background);
        Ok(())
    }

    /// Resolve once every inbound listener is bound and accepting.
    ///
    /// Returns immediately if that has already happened, and never resolves if
    /// `run` failed before binding — so callers should pair it with a timeout
    /// or with the `run` handle itself.
    pub async fn wait_until_listening(&self) {
        let mut rx = self.listening.subscribe();
        if *rx.borrow_and_update() {
            return;
        }
        let _ = rx.changed().await;
    }

    /// Whether every inbound listener is bound.
    pub fn is_listening(&self) -> bool {
        *self.listening.borrow()
    }

    /// Sessions currently being served.
    pub fn active_sessions(&self) -> u64 {
        self.stats.active.load(Ordering::Relaxed)
    }

    /// Wait until every in-flight TCP session has finished, or `timeout`
    /// elapses. Returns the number of sessions still active when it returned:
    /// `0` means a clean drain, non-zero means the timeout forced the issue.
    /// Listeners are expected to be cancelled by the caller before this is
    /// awaited, so no new sessions arrive while it counts down.
    pub async fn drain(&self, timeout: std::time::Duration) -> u64 {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let active = self.active_sessions();
            if active == 0 {
                return 0;
            }
            if tokio::time::Instant::now() >= deadline {
                return active;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener, id: InboundId) {
        let mut backoff_ms = 10u64;
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    backoff_ms = 10;
                    let _ = stream.set_nodelay(true);
                    #[cfg(target_os = "linux")]
                    {
                        let _ = socket2::SockRef::from(&stream).set_quickack(true);
                    }
                    let me = Arc::clone(&self);
                    tokio::spawn(me.serve_tcp_connection(stream, peer, id));
                }
                // The connection died between SYN and accept: that is the
                // peer's problem, not the listener's, so do not slow down.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    debug!(error = %e, "accepted connection was already gone");
                }
                Err(e) => {
                    // Resource exhaustion (EMFILE/ENFILE/ENOBUFS) must not kill
                    // the listener or spin on it; back off and keep serving.
                    error!(error = %e, backoff_ms, "accept failed");
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(1000);
                }
            }
        }
    }

    /// Everything one accepted TCP connection goes through: security,
    /// transport, then the inbound protocol.
    async fn serve_tcp_connection(
        self: Arc<Self>,
        stream: tokio::net::TcpStream,
        peer: SocketAddr,
        id: InboundId,
    ) {
        let stats = Arc::clone(&self.stats);
        stats.accepted.fetch_add(1, Ordering::Relaxed);
        let _active = ActiveGuard::new(Arc::clone(&stats));
        let state = self.state.load_full();
        let index = id.0 as usize;
        let (Some(inbound), Some(compiled)) =
            (state.config.inbounds.get(index), state.inbounds.get(index))
        else {
            stats.failed.fetch_add(1, Ordering::Relaxed);
            return;
        };

        let secured = match timeout(
            HANDSHAKE_TIMEOUT,
            Self::secure_inbound(stream, &inbound.security, compiled),
        )
        .await
        {
            Ok(Ok(Secured::Stream(stream))) => stream,
            Ok(Ok(Secured::Fallback {
                stream,
                client_hello,
                failure,
            })) => {
                self.relay_reality_fallback(stream, client_hello, failure, peer, &inbound.security)
                    .await;
                return;
            }
            Ok(Err(error)) => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                debug!(%peer, %error, "inbound security handshake failed");
                return;
            }
            Err(_) => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                debug!(%peer, "inbound security handshake timed out");
                return;
            }
        };
        let secured: zero_core::BoxStream = match &compiled.raw_http_header {
            Some(config) => boxed(zero_transport::tcp_header::HttpHeaderStream::server(
                secured, config,
            )),
            None => secured,
        };
        let stream = match self.accept_transport(secured, inbound, compiled).await {
            Ok(Some((stream, more))) => {
                if let Some(more) = more {
                    Arc::clone(&self).serve_additional_streams(more, peer, id, Arc::clone(&state));
                }
                stream
            }
            // The request was folded into an existing split-XHTTP session.
            Ok(None) => return,
            Err(error) => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                debug!(%peer, %error, "inbound transport upgrade failed");
                return;
            }
        };
        if let Err(e) = self
            .handle(stream, peer, id, InboundSession { state })
            .await
        {
            stats.failed.fetch_add(1, Ordering::Relaxed);
            debug!(%peer, error = %e, "session failed");
        }
    }

    /// Serve the further streams a multiplexing transport (gRPC) opens on a
    /// connection that is already established, each as its own session.
    fn serve_additional_streams(
        self: Arc<Self>,
        mut more: tokio::sync::mpsc::Receiver<zero_core::BoxStream>,
        peer: SocketAddr,
        id: InboundId,
        state: Arc<ServerState>,
    ) {
        tokio::spawn(async move {
            while let Some(stream) = more.recv().await {
                let this = Arc::clone(&self);
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let stats = Arc::clone(&this.stats);
                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                    let _active = ActiveGuard::new(Arc::clone(&stats));
                    if let Err(e) = this
                        .handle(stream, peer, id, InboundSession { state })
                        .await
                    {
                        stats.failed.fetch_add(1, Ordering::Relaxed);
                        debug!(%peer, error = %e, "multiplexed session failed");
                    }
                });
            }
        });
    }

    /// Terminate the inbound's TLS or REALITY layer.
    async fn secure_inbound(
        stream: tokio::net::TcpStream,
        security: &zero_config::InboundSecurity,
        compiled: &InboundRuntime,
    ) -> Result<Secured, String> {
        match security {
            zero_config::InboundSecurity::None => Ok(Secured::Stream(boxed(stream))),
            zero_config::InboundSecurity::Tls(_) => {
                let config = match &compiled.tls {
                    Some(Ok(config)) => Arc::clone(config),
                    Some(Err(error)) => {
                        return Err(format!("inbound TLS configuration failed: {error}"))
                    }
                    None => return Err("inbound TLS configuration is missing".into()),
                };
                zero_security::server::accept(stream, config)
                    .await
                    .map(|stream| Secured::Stream(boxed(stream)))
                    .map_err(|error| format!("inbound TLS handshake failed: {error}"))
            }
            zero_config::InboundSecurity::Reality(_) => {
                let params = compiled
                    .reality
                    .as_ref()
                    .ok_or_else(|| "inbound REALITY configuration is missing".to_string())?;
                match zero_security::tls13::server::handshake_or_fallback(stream, params).await {
                    zero_security::tls13::server::HandshakeOutcome::Accepted(stream) => {
                        Ok(Secured::Stream(boxed(stream)))
                    }
                    zero_security::tls13::server::HandshakeOutcome::Fallback {
                        stream,
                        client_hello,
                        failure,
                    } => Ok(Secured::Fallback {
                        stream,
                        client_hello,
                        failure: failure.to_string(),
                    }),
                    zero_security::tls13::server::HandshakeOutcome::Rejected(error) => {
                        Err(format!("inbound REALITY handshake failed: {error}"))
                    }
                }
            }
        }
    }

    /// Hand an unauthenticated REALITY client to the camouflage target, so a
    /// prober sees the real site. This relay is deliberately outside the
    /// handshake deadline: to the prober it is an ordinary long-lived session.
    async fn relay_reality_fallback(
        &self,
        stream: tokio::net::TcpStream,
        client_hello: Vec<u8>,
        failure: String,
        peer: SocketAddr,
        security: &zero_config::InboundSecurity,
    ) {
        let zero_config::InboundSecurity::Reality(reality) = security else {
            return;
        };
        let Some(target) = reality.target.clone() else {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
            debug!(
                %peer,
                error = %failure,
                "REALITY handshake rejected without a fallback target"
            );
            return;
        };
        let destination = Destination::tcp(target.0, target.1);
        let resolver = self.resolver();
        let mut remote = match outbound::connect_direct_with_resolver(
            &destination,
            &zero_config::StreamSettings::default(),
            &resolver,
        )
        .await
        {
            Ok(remote) => remote,
            Err(error) => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                debug!(%peer, error = %error, "REALITY fallback target connection failed");
                return;
            }
        };
        if let Err(error) = remote.write_all(&client_hello).await {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
            debug!(%peer, error = %error, "REALITY fallback ClientHello replay failed");
            return;
        }
        if let Err(error) = remote.flush().await {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
            debug!(%peer, error = %error, "REALITY fallback flush failed");
            return;
        }
        let outcome = relay(boxed(stream), remote).await;
        self.stats
            .uploaded
            .fetch_add(outcome.transferred.uploaded, Ordering::Relaxed);
        self.stats
            .downloaded
            .fetch_add(outcome.transferred.downloaded, Ordering::Relaxed);
        if outcome.is_useful() {
            self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
        }
        debug!(
            %peer,
            target = %destination,
            up = outcome.transferred.uploaded,
            down = outcome.transferred.downloaded,
            stage = ?outcome.stage,
            error = ?outcome.error,
            "REALITY fallback relay finished"
        );
    }

    /// Complete the inbound transport. `Ok(None)` means the connection was
    /// consumed by an existing split-XHTTP session and has nothing left to
    /// serve on its own.
    async fn accept_transport(
        &self,
        secured: zero_core::BoxStream,
        inbound: &zero_config::Inbound,
        compiled: &InboundRuntime,
    ) -> Result<Option<AcceptedTransport>, String> {
        let transport = &inbound.transport;
        if matches!(transport, zero_config::Transport::Raw) {
            return Ok(Some((secured, None)));
        }
        let cfg = compiled
            .transport
            .as_ref()
            .ok_or_else(|| "inbound transport configuration is missing".to_string())?;
        // Split XHTTP legs carry the whole session inside their accept call,
        // so they cannot be bounded by the handshake deadline.
        if let zero_config::Transport::Xhttp(w) = transport {
            return self.accept_xhttp(secured, w, cfg).await;
        }
        let upgrade = async {
            match transport {
                zero_config::Transport::WebSocket(_) => {
                    zero_transport::ws::accept_server(secured, cfg)
                        .await
                        .map(|stream| (boxed(stream), None))
                        .map_err(|error| format!("WebSocket upgrade: {error}"))
                }
                zero_config::Transport::HttpUpgrade(_) => {
                    zero_transport::httpupgrade::accept(secured, cfg)
                        .await
                        .map(|stream| (stream, None))
                        .map_err(|error| format!("HTTPUpgrade: {error}"))
                }
                zero_config::Transport::Grpc(_) => zero_transport::grpc::accept_multi(secured, cfg)
                    .await
                    .map(|(first, more)| (first, Some(more)))
                    .map_err(|error| format!("gRPC upgrade: {error}")),
                zero_config::Transport::Raw | zero_config::Transport::Xhttp(_) => {
                    unreachable!("handled above")
                }
            }
        };
        within_handshake(upgrade).await?.map(Some)
    }

    async fn accept_xhttp(
        &self,
        secured: zero_core::BoxStream,
        w: &zero_config::WebSocketConfig,
        cfg: &zero_transport::ws::WsConfig,
    ) -> Result<Option<AcceptedTransport>, String> {
        use zero_transport::xhttp::{self, H2Server};
        if w.xhttp_http_version == zero_config::XhttpHttpVersion::Http2 {
            // One HTTP/2 connection carries many XHTTP requests; every
            // logical stream after the first is served alongside it.
            let server = match w.xhttp_mode {
                zero_config::XhttpMode::StreamUp => H2Server::StreamUp(Arc::clone(&self.xhttp_hub)),
                zero_config::XhttpMode::Auto | zero_config::XhttpMode::PacketUp => {
                    H2Server::PacketUp(Arc::clone(&self.xhttp_packet_hub))
                }
                zero_config::XhttpMode::StreamOne => H2Server::StreamOne,
            };
            return xhttp::accept_h2_multi(secured, cfg, server)
                .await
                .map(|accepted| accepted.map(|(first, more)| (first, Some(more))))
                .map_err(|error| format!("XHTTP HTTP/2: {error}"));
        }
        let stream = match w.xhttp_mode {
            zero_config::XhttpMode::StreamUp => {
                xhttp::accept_stream_up(secured, cfg, &self.xhttp_hub)
                    .await
                    .map_err(|error| format!("XHTTP split pairing: {error}"))?
            }
            zero_config::XhttpMode::Auto | zero_config::XhttpMode::PacketUp => {
                xhttp::accept_packet_up(secured, cfg, &self.xhttp_packet_hub)
                    .await
                    .map_err(|error| format!("XHTTP packet pairing: {error}"))?
            }
            zero_config::XhttpMode::StreamOne => Some(
                xhttp::accept(secured, cfg)
                    .await
                    .map_err(|error| format!("XHTTP upgrade: {error}"))?,
            ),
        };
        Ok(stream.map(|stream| (stream, None)))
    }

    async fn accept_h3_loop(self: Arc<Self>, endpoint: h3_quinn::quinn::Endpoint, id: InboundId) {
        while let Some(incoming) = endpoint.accept().await {
            // The QUIC handshake is awaited inside the connection's own task:
            // awaiting it here would let one slow or silent client hold up
            // every other connection waiting behind it in the accept queue.
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                let connection = match timeout(HANDSHAKE_TIMEOUT, incoming).await {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(error)) => {
                        debug!(%error, "HTTP/3 connection failed");
                        return;
                    }
                    Err(_) => {
                        debug!("HTTP/3 handshake timed out");
                        return;
                    }
                };
                let peer = connection.remote_address();
                let mut h3_connection = match timeout(
                    HANDSHAKE_TIMEOUT,
                    h3::server::Connection::new(h3_quinn::Connection::new(connection)),
                )
                .await
                {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(error)) => {
                        debug!(%peer, %error, "HTTP/3 session setup failed");
                        return;
                    }
                    Err(_) => {
                        debug!(%peer, "HTTP/3 session setup timed out");
                        return;
                    }
                };
                loop {
                    let resolver = match h3_connection.accept().await {
                        Ok(Some(resolver)) => resolver,
                        Ok(None) => break,
                        Err(error) => {
                            debug!(%peer, %error, "HTTP/3 connection ended");
                            break;
                        }
                    };
                    let state = me.state.load_full();
                    let index = id.0 as usize;
                    let (Some(inbound), Some(compiled)) =
                        (state.config.inbounds.get(index), state.inbounds.get(index))
                    else {
                        me.stats.failed.fetch_add(1, Ordering::Relaxed);
                        break;
                    };
                    let (zero_config::Transport::Xhttp(settings), Some(cfg)) =
                        (&inbound.transport, compiled.transport.as_ref())
                    else {
                        me.stats.failed.fetch_add(1, Ordering::Relaxed);
                        break;
                    };
                    // Requests are resolved in arrival order: a packet-up GET
                    // must open its session before the POSTs that feed it are
                    // delivered. Only the resolved session is handed off.
                    let accepted = match settings.xhttp_mode {
                        zero_config::XhttpMode::StreamUp => {
                            zero_transport::xhttp::accept_stream_up_h3(resolver, cfg, &me.xhttp_hub)
                                .await
                        }
                        zero_config::XhttpMode::PacketUp => {
                            zero_transport::xhttp::accept_packet_up_h3(
                                resolver,
                                cfg,
                                &me.xhttp_packet_hub,
                            )
                            .await
                        }
                        _ => zero_transport::xhttp::accept_h3_request(resolver, cfg)
                            .await
                            .map(Some),
                    };
                    let stream = match accepted {
                        Ok(Some(stream)) => stream,
                        Ok(None) => continue,
                        Err(error) => {
                            me.stats.failed.fetch_add(1, Ordering::Relaxed);
                            debug!(%error, "HTTP/3 request rejected");
                            continue;
                        }
                    };
                    me.stats.accepted.fetch_add(1, Ordering::Relaxed);
                    // HTTP/3 packet-up keeps the GET downlink open while POST
                    // packet requests arrive on the same QUIC connection.
                    // Handle each resolved request independently so one
                    // logical stream cannot block the connection's request
                    // accept loop.
                    let handler = Arc::clone(&me);
                    let stats = Arc::clone(&me.stats);
                    let session = InboundSession {
                        state: Arc::clone(&state),
                    };
                    tokio::spawn(async move {
                        let _active = ActiveGuard::new(Arc::clone(&stats));
                        if let Err(error) = handler.handle(stream, peer, id, session).await {
                            stats.failed.fetch_add(1, Ordering::Relaxed);
                            debug!(%peer, %error, "HTTP/3 session failed");
                        }
                    });
                }
            });
        }
    }

    async fn accept_hysteria2_loop(
        self: Arc<Self>,
        endpoint: h3_quinn::quinn::Endpoint,
        id: InboundId,
    ) {
        let mut acceptor = zero_transport::hysteria2::Acceptor::new(endpoint);
        loop {
            let state = self.state.load_full();
            let Some(inbound) = state.config.inbounds.get(id.0 as usize) else {
                return;
            };
            let InboundProtocol::Hysteria2(config) = &inbound.protocol else {
                return;
            };
            let accepted = match acceptor.accept(&config.passwords).await {
                Ok(Some(value)) => value,
                Ok(None) => return,
                Err(error) => {
                    self.stats.failed.fetch_add(1, Ordering::Relaxed);
                    debug!(%error, "Hysteria2 connection rejected");
                    continue;
                }
            };
            let tag = inbound.tag.clone();
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                match accepted {
                    zero_transport::hysteria2::Accepted::Tcp {
                        stream,
                        destination,
                        peer,
                    } => {
                        me.stats.accepted.fetch_add(1, Ordering::Relaxed);
                        if let Err(error) = Arc::clone(&me)
                            .handle_hysteria2(stream, peer, id, tag, destination)
                            .await
                        {
                            me.stats.failed.fetch_add(1, Ordering::Relaxed);
                            debug!(%error, "Hysteria2 session failed");
                        }
                    }
                    zero_transport::hysteria2::Accepted::Udp {
                        connection,
                        session_id,
                        packet_id,
                        destination,
                        payload,
                        peer,
                    } => {
                        me.stats.accepted.fetch_add(1, Ordering::Relaxed);
                        if let Err(error) = Arc::clone(&me)
                            .handle_hysteria2_udp(
                                Hysteria2UdpSession {
                                    connection,
                                    session_id,
                                    packet_id,
                                    peer,
                                    destination,
                                    payload,
                                },
                                id,
                                tag,
                            )
                            .await
                        {
                            me.stats.failed.fetch_add(1, Ordering::Relaxed);
                            debug!(%error, "Hysteria2 UDP session failed");
                        }
                    }
                }
            });
        }
    }

    async fn accept_tuic_loop(self: Arc<Self>, endpoint: h3_quinn::quinn::Endpoint, id: InboundId) {
        let mut acceptor = zero_transport::tuic::Acceptor::new(endpoint);
        loop {
            let state = self.state.load_full();
            let Some(inbound) = state.config.inbounds.get(id.0 as usize) else {
                return;
            };
            let InboundProtocol::Tuic(config) = &inbound.protocol else {
                return;
            };
            let accepted = match acceptor.accept(&config.uuid, &config.password).await {
                Ok(Some(value)) => value,
                Ok(None) => return,
                Err(error) => {
                    self.stats.failed.fetch_add(1, Ordering::Relaxed);
                    debug!(%error, "TUIC connection rejected");
                    continue;
                }
            };
            let tag = inbound.tag.clone();
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                match accepted {
                    zero_transport::tuic::Accepted::Tcp {
                        stream,
                        destination,
                        peer,
                    } => {
                        me.stats.accepted.fetch_add(1, Ordering::Relaxed);
                        if let Err(error) = Arc::clone(&me)
                            .handle_hysteria2(stream, peer, id, tag, destination)
                            .await
                        {
                            me.stats.failed.fetch_add(1, Ordering::Relaxed);
                            debug!(%error, "TUIC session failed");
                        }
                    }
                    zero_transport::tuic::Accepted::Udp {
                        connection,
                        association,
                        packet,
                        destination,
                        payload,
                        peer,
                    } => {
                        me.stats.accepted.fetch_add(1, Ordering::Relaxed);
                        if let Err(error) = Arc::clone(&me)
                            .handle_tuic_udp(
                                connection,
                                association,
                                packet,
                                peer,
                                destination,
                                payload,
                                id,
                                tag,
                            )
                            .await
                        {
                            me.stats.failed.fetch_add(1, Ordering::Relaxed);
                            debug!(%error, "TUIC UDP session failed");
                        }
                    }
                }
            });
        }
    }

    fn config(&self) -> Arc<RuntimeConfig> {
        Arc::clone(&self.state.load_full().config)
    }

    async fn restore_fake_destination(&self, destination: &Destination) -> Destination {
        let Some(ip) = destination.address.as_ip() else {
            return destination.clone();
        };
        let Some(domain) = self.client_resolver().reverse_fake(ip).await else {
            return destination.clone();
        };
        let mut restored = destination.clone();
        restored.address = Address::domain(domain);
        restored
    }

    fn router(&self) -> Arc<Router> {
        Arc::clone(&self.state.load_full().router)
    }

    /// The resolver for the runtime's own connections: never FakeDNS.
    fn resolver(&self) -> Arc<zero_dns::Resolver> {
        Arc::clone(&self.state.load_full().resolver)
    }

    /// The resolver that answers applications, FakeDNS included.
    fn client_resolver(&self) -> Arc<zero_dns::Resolver> {
        Arc::clone(&self.state.load_full().client_resolver)
    }

    fn generation(&self) -> GenerationId {
        self.state.load().generation
    }

    pub fn current_generation(&self) -> GenerationId {
        self.generation()
    }

    async fn handle(
        self: Arc<Self>,
        mut stream: zero_core::BoxStream,
        peer: SocketAddr,
        id: InboundId,
        session: InboundSession,
    ) -> Result<(), String> {
        let Some(inbound) = session.state.config.inbounds.get(id.0 as usize) else {
            return Err("inbound disappeared from its own generation".into());
        };
        let tag = inbound.tag.clone();
        let sniffing = &inbound.sniffing;
        match &inbound.protocol {
            InboundProtocol::Vless(config) => {
                return self.handle_vless(stream, peer, id, tag, config).await;
            }
            InboundProtocol::Trojan(config) => {
                return self.handle_trojan(stream, peer, id, tag, config).await;
            }
            InboundProtocol::Vmess(config) => {
                return self.handle_vmess(stream, peer, id, tag, config).await;
            }
            InboundProtocol::Shadowsocks(config) => {
                return self.handle_shadowsocks(stream, peer, id, tag, config).await;
            }
            InboundProtocol::AnyTls(config) => {
                return self.handle_anytls(stream, peer, id, tag, config).await;
            }
            InboundProtocol::Dokodemo {
                target: Some(target),
                network: Network::Tcp,
            } => {
                return self
                    .handle_dokodemo_tcp(stream, peer, id, tag, target.clone())
                    .await;
            }
            _ => {}
        }

        let socks_auth = &inbound.socks_auth;
        let (mut accepted, mut stream): (Accepted, zero_core::BoxStream) =
            within_handshake(async move {
                let mut first = [0u8; 1];
                let n = stream
                    .read(&mut first)
                    .await
                    .map_err(|e| format!("reading first byte: {e}"))?;
                if n == 0 {
                    return Err("client closed before sending anything".to_string());
                }
                match socks::detect(first[0]) {
                    InboundKind::Socks5 => {
                        // The greeting's first byte was consumed by detection,
                        // so replay it into a chained reader.
                        let mut chained = ChainedStream::new(first.to_vec(), stream);
                        let credentials = match socks_auth {
                            zero_config::SocksAuth::None => Vec::new(),
                            zero_config::SocksAuth::Password(accounts) => accounts
                                .iter()
                                .map(|account| zero_protocol::socks::Credential {
                                    username: account.username.clone(),
                                    password: account.password.clone(),
                                })
                                .collect(),
                        };
                        let accepted =
                            socks::accept_socks5_with_credentials(&mut chained, &credentials)
                                .await?;
                        Ok((accepted, boxed(chained)))
                    }
                    _ => {
                        let accepted = socks::accept_http(&mut stream, first[0]).await?;
                        Ok((accepted, stream))
                    }
                }
            })
            .await??;

        // FakeDNS addresses are local handles for domains. Restore the name
        // before routing and proxying so synthetic addresses never cross the
        // process boundary and domain rules still match.
        accepted.destination = self.restore_fake_destination(&accepted.destination).await;

        if accepted.destination.network == Network::Udp {
            return self.handle_udp_association(stream, peer, id, tag).await;
        }

        let mut prefetched = Vec::new();
        let mut probe = accepted.prefix.clone();
        if sniffing.enabled && accepted.destination.network == Network::Tcp {
            let mut extra = vec![0u8; 8192usize.saturating_sub(probe.len())];
            if !extra.is_empty() {
                if let Ok(Ok(read)) =
                    timeout(Duration::from_millis(50), stream.read(&mut extra)).await
                {
                    extra.truncate(read);
                    probe.extend_from_slice(&extra);
                    prefetched = extra;
                }
            }
        }

        let mut ctx = SessionContext::new(self.generation(), id, tag, accepted.destination.clone())
            .with_source(peer);
        if sniffing.enabled {
            let sniffed =
                zero_core::sniff::inspect(&probe, sniffing.sniff_http, sniffing.sniff_tls);
            if sniffed.domain.is_some() || sniffed.protocol.is_some() {
                ctx.apply_sniff(sniffed, !sniffing.route_only);
                accepted.destination = ctx.destination.clone();
            }
        }

        let decision = self.route(&ctx).await;
        debug!(dest = %ctx.destination, ?decision, "routed");

        match decision {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                self.finish_handshake(&mut stream, &accepted, false).await;
                Ok(())
            }
            Decision::Outbound(tag) | Decision::Balancer(tag) => {
                let ob = self
                    .pick_outbound(&tag)
                    .ok_or_else(|| format!("no usable outbound for {tag:?}"))?;
                ctx.outbound = None;

                let remote = match &ob.protocol {
                    OutboundProtocol::Freedom { .. } => outbound::connect_direct_with_resolver(
                        &accepted.destination,
                        &ob.stream,
                        &self.resolver(),
                    )
                    .await
                    .map_err(|e| e.to_string())?,
                    OutboundProtocol::Blackhole => {
                        self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                        self.finish_handshake(&mut stream, &accepted, false).await;
                        return Ok(());
                    }
                    OutboundProtocol::Vless(_)
                    | OutboundProtocol::Trojan(_)
                    | OutboundProtocol::Shadowsocks(_)
                    | OutboundProtocol::Vmess(_)
                    | OutboundProtocol::AnyTls(_)
                    | OutboundProtocol::Hysteria2(_)
                    | OutboundProtocol::Tuic(_) => {
                        let s = outbound::connect_with_resolver(
                            &ob,
                            &accepted.destination,
                            &self.resolver(),
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                        outbound::strip_response(&ob, s)
                    }
                    other => {
                        return Err(format!(
                            "outbound protocol {} cannot carry a session",
                            other.name()
                        ))
                    }
                };

                self.finish_handshake(&mut stream, &accepted, true).await;

                let mut remote = remote;
                if !accepted.prefix.is_empty() {
                    remote
                        .write_all(&accepted.prefix)
                        .await
                        .map_err(|e| format!("replaying request prefix: {e}"))?;
                }

                let client = if prefetched.is_empty() {
                    boxed(stream)
                } else {
                    boxed(ChainedStream::new(prefetched, stream))
                };
                let outcome = relay(client, remote).await;
                self.record_outbound_observation(&ob.tag, &outcome);
                self.record_observation(&outcome).await;
                self.stats.record_tag_traffic(
                    &ctx.inbound_tag,
                    Some(&ob.tag),
                    &outcome.transferred,
                );
                self.stats
                    .uploaded
                    .fetch_add(outcome.transferred.uploaded, Ordering::Relaxed);
                self.stats
                    .downloaded
                    .fetch_add(outcome.transferred.downloaded, Ordering::Relaxed);
                if outcome.is_useful() {
                    self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.failed.fetch_add(1, Ordering::Relaxed);
                }
                debug!(
                    dest = %accepted.destination,
                    up = outcome.transferred.uploaded,
                    down = outcome.transferred.downloaded,
                    stage = ?outcome.stage,
                    error = ?outcome.error,
                    "session finished"
                );
                Ok(())
            }
            Decision::DirectVia { resolver } => {
                let resolver = self.resolver().for_tag(&resolver);
                let remote = outbound::connect_direct_with_resolver(
                    &accepted.destination,
                    &zero_config::StreamSettings::default(),
                    &resolver,
                )
                .await
                .map_err(|e| e.to_string())?;
                self.finish_handshake(&mut stream, &accepted, true).await;
                let mut remote = remote;
                if !accepted.prefix.is_empty() {
                    remote
                        .write_all(&accepted.prefix)
                        .await
                        .map_err(|e| format!("replaying request prefix: {e}"))?;
                }
                let client = if prefetched.is_empty() {
                    boxed(stream)
                } else {
                    boxed(ChainedStream::new(prefetched, stream))
                };
                let outcome = relay(client, remote).await;
                self.record_observation(&outcome).await;
                self.stats
                    .record_tag_traffic(&ctx.inbound_tag, None, &outcome.transferred);
                self.stats
                    .uploaded
                    .fetch_add(outcome.transferred.uploaded, Ordering::Relaxed);
                self.stats
                    .downloaded
                    .fetch_add(outcome.transferred.downloaded, Ordering::Relaxed);
                if outcome.is_useful() {
                    self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.failed.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }
        }
    }

    async fn handle_udp_association(
        self: Arc<Self>,
        mut control: zero_core::BoxStream,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
    ) -> Result<(), String> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("binding SOCKS5 UDP association: {e}"))?;
        let bound = socket
            .local_addr()
            .map_err(|e| format!("reading SOCKS5 UDP association address: {e}"))?;
        socks::reply(
            &mut control,
            socks::REP_SUCCESS,
            Some(Destination::udp(Address::Ip(bound.ip()), bound.port())),
        )
        .await
        .map_err(|e| format!("sending SOCKS5 UDP association reply: {e}"))?;

        // The association belongs to the control connection's host, and to
        // the first address that uses it from there; replies go to wherever
        // that client last sent from.
        let mut client: Option<SocketAddr> = None;
        let (mut udp, mut replies) = UdpRelay::<()>::new(Arc::clone(&self), id, tag, 64);
        let mut control_byte = [0u8; 1];
        let mut packet = vec![0u8; 65_535];
        loop {
            tokio::select! {
                result = control.read(&mut control_byte) => {
                    let n = result.map_err(|e| format!("reading SOCKS5 UDP control connection: {e}"))?;
                    if n == 0 {
                        return Ok(());
                    }
                    return Err("SOCKS5 UDP control connection sent unexpected data".into());
                }
                result = socket.recv_from(&mut packet) => {
                    let (len, source) = match result {
                        Ok(value) => value,
                        // An ICMP error for an earlier reply; not fatal.
                        Err(error) if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
                        ) => continue,
                        Err(error) => return Err(format!("receiving SOCKS5 UDP datagram: {error}")),
                    };
                    if source.ip() != peer.ip()
                        || client.is_some_and(|client| client.ip() != source.ip())
                    {
                        continue;
                    }
                    client = Some(source);
                    let parsed = match socks::parse_udp_datagram(&packet[..len]) {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            debug!(%source, %error, "discarding malformed SOCKS5 UDP datagram");
                            continue;
                        }
                    };
                    udp.dispatch((), source, parsed.destination, parsed.payload).await;
                }
                Some(reply) = replies.recv() => {
                    let Some(client) = client else { continue };
                    let encoded = match socks::encode_udp_datagram(&reply.source, &reply.payload) {
                        Ok(encoded) => encoded,
                        Err(error) => {
                            debug!(%error, "SOCKS5 UDP reply cannot be framed; dropped");
                            continue;
                        }
                    };
                    match socket.send_to(&encoded, client).await {
                        Ok(_) => {
                            self.stats
                                .downloaded
                                .fetch_add(reply.payload.len() as u64, Ordering::Relaxed);
                            self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(error) => debug!(%client, %error, "sending SOCKS5 UDP reply failed"),
                    }
                }
            }
        }
    }

    async fn handle_dokodemo_tcp(
        self: Arc<Self>,
        stream: zero_core::BoxStream,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
        target: (Address, u16),
    ) -> Result<(), String> {
        let destination = Destination::tcp(target.0, target.1);
        let ctx =
            SessionContext::new(self.generation(), id, tag, destination.clone()).with_source(peer);
        let decision = self.route(&ctx).await;
        let mut health_tag = None;
        let remote = match decision {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Decision::DirectVia { resolver } => {
                let resolver = self.resolver().for_tag(&resolver);
                outbound::connect_direct_with_resolver(
                    &destination,
                    &zero_config::StreamSettings::default(),
                    &resolver,
                )
                .await
                .map_err(|error| error.to_string())?
            }
            Decision::Outbound(outbound_tag) | Decision::Balancer(outbound_tag) => {
                let outbound = self
                    .pick_outbound(&outbound_tag)
                    .ok_or_else(|| format!("no usable outbound for {outbound_tag:?}"))?;
                health_tag = Some(outbound.tag.clone());
                match &outbound.protocol {
                    OutboundProtocol::Freedom { .. } => outbound::connect_direct_with_resolver(
                        &destination,
                        &outbound.stream,
                        &self.resolver(),
                    )
                    .await
                    .map_err(|error| error.to_string())?,
                    OutboundProtocol::Vless(_)
                    | OutboundProtocol::Trojan(_)
                    | OutboundProtocol::Shadowsocks(_)
                    | OutboundProtocol::Vmess(_)
                    | OutboundProtocol::AnyTls(_)
                    | OutboundProtocol::Hysteria2(_)
                    | OutboundProtocol::Tuic(_) => {
                        let stream = outbound::connect_with_resolver(
                            &outbound,
                            &destination,
                            &self.resolver(),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                        outbound::strip_response(&outbound, stream)
                    }
                    other => {
                        return Err(format!(
                            "{} cannot carry a dokodemo TCP session",
                            other.name()
                        ))
                    }
                }
            }
        };
        let outcome = relay(boxed(stream), remote).await;
        if let Some(tag) = health_tag {
            self.record_outbound_observation(&tag, &outcome);
        }
        self.record_observation(&outcome).await;
        self.stats
            .uploaded
            .fetch_add(outcome.transferred.uploaded, Ordering::Relaxed);
        self.stats
            .downloaded
            .fetch_add(outcome.transferred.downloaded, Ordering::Relaxed);
        if outcome.is_useful() {
            self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn serve_tun(
        self: Arc<Self>,
        id: InboundId,
        tag: Arc<str>,
        config: zero_config::TunInboundConfig,
    ) {
        // A host that created the interface itself hands the descriptor over
        // rather than letting this process open one: on Android and iOS
        // opening a TUN device is not permitted, and the interface the user
        // approved already exists (`zero_tun::inherited`).
        let inherited = zero_tun::inherited::take();
        let device_config = zero_tun::TunConfig {
            name: config.name.to_string(),
            no_packet_info: true,
            max_packet_size: 65_535,
            mtu: inherited.map_or(config.mtu, |handover| handover.mtu),
        };
        let opened = match inherited {
            // SAFETY: the descriptor came from `inherited::take`, which yields
            // it exactly once, and the host contract is that it stops using it
            // at that point.
            Some(handover) => unsafe {
                zero_tun::TunDevice::from_raw_fd(handover.fd, device_config, handover.header_len)
            },
            None => zero_tun::TunDevice::open(device_config),
        };
        let device = match opened {
            Ok(device) => Arc::new(device),
            Err(error) => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                error!(%error, %tag, adopted = inherited.is_some(), "TUN device unavailable");
                return;
            }
        };
        if let Some(handover) = inherited {
            info!(
                %tag,
                header_len = handover.header_len,
                mtu = handover.mtu,
                "adopted a TUN descriptor from the host application"
            );
        }
        let parts = match zero_tun::build_netstack(zero_tun::NetstackConfig {
            mtu: config.mtu,
            enable_tcp: config.enable_tcp,
            enable_udp: config.enable_udp,
            enable_icmp: config.enable_icmp,
        }) {
            Ok(parts) => parts,
            Err(error) => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                error!(%error, %tag, "TUN userspace stack failed to build");
                return;
            }
        };
        let addresses = match config
            .addresses
            .iter()
            .map(|value| zero_tun::TunAddress::parse(value))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(addresses) => addresses,
            Err(error) => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                error!(%error, %tag, "TUN address configuration rejected");
                return;
            }
        };
        let routes = match config
            .routes
            .iter()
            .map(|value| zero_tun::TunRoute::parse(value))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(routes) => routes,
            Err(error) => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                error!(%error, %tag, "TUN route configuration rejected");
                return;
            }
        };
        // Only configure the link when this process created it. On an adopted
        // interface the addresses, routes and MTU came from a system dialog
        // the user agreed to; running `ip` behind that would be both refused
        // and wrong.
        let _network = if inherited.is_some() {
            debug!(
                %tag,
                "skipping link configuration: the host owns this interface"
            );
            None
        } else {
            let mut bypass_ips = Vec::new();
            for outbound in &self.config().outbounds {
                // AmneziaWG's peer is deliberately left to the tunnel's own
                // routing, as it always has been; every stream proxy's server
                // address must bypass the TUN or its traffic loops back in.
                if matches!(outbound.protocol, OutboundProtocol::AmneziaWireguard(_)) {
                    continue;
                }
                if let Some((Address::Ip(ip), _)) = outbound.endpoint() {
                    bypass_ips.push(ip);
                }
            }
            match device.configure_network(zero_tun::TunNetworkConfig {
                addresses,
                routes,
                bypass_ips,
                auto_route: config.auto_route,
                strict_route: config.strict_route,
            }) {
                Ok(network) => Some(network),
                Err(error) => {
                    self.stats.failed.fetch_add(1, Ordering::Relaxed);
                    error!(%error, %tag, "TUN network configuration failed");
                    return;
                }
            }
        };
        // With the default routes pointing into the tunnel, the engine's own
        // direct connections would follow them back in and loop. Pin them to
        // the interface traffic left by before, for as long as this TUN runs.
        // (An adopted interface's host does this itself.)
        let _bound = _network
            .as_ref()
            .and_then(|network| network.uplink_interface())
            .map(|uplink| zero_core::platform::BoundInterface::set(&uplink));
        let _bridge = zero_tun::spawn_netstack_bridge(Arc::clone(&device), parts.stack);
        if let Some(runner) = parts.runner {
            tokio::spawn(async move {
                if let Err(error) = runner.await {
                    tracing::debug!(%error, "TUN userspace stack stopped");
                }
            });
        }

        if let Some(udp) = parts.udp {
            let me = Arc::clone(&self);
            let udp_tag = tag.clone();
            tokio::spawn(async move {
                me.serve_tun_udp(udp, id, udp_tag).await;
            });
        }
        let Some(mut tcp) = parts.tcp else {
            // A UDP-only TUN remains useful for DNS and datagram transports.
            std::future::pending::<()>().await;
            return;
        };
        info!(%tag, device = %config.name, "TUN userspace stack started");
        // `local` is the address the application connected *from* and `remote`
        // is the one it was trying to reach — the netstack names them from its
        // own point of view, which is the opposite of a listening socket's.
        // Proxying to the wrong one sends every session back to the machine it
        // came from, and does so without any error to notice.
        while let Some((stream, source, destination)) = tcp.next().await {
            let me = Arc::clone(&self);
            let session_tag = tag.clone();
            tokio::spawn(async move {
                if let Err(error) = me
                    .handle_dokodemo_tcp(
                        boxed(stream),
                        source,
                        id,
                        session_tag,
                        (Address::Ip(destination.ip()), destination.port()),
                    )
                    .await
                {
                    debug!(%error, "TUN TCP session failed");
                }
            });
        }
    }

    async fn serve_tun_udp(
        self: Arc<Self>,
        udp: zero_tun::UdpSocket,
        id: InboundId,
        tag: Arc<str>,
    ) {
        let (mut reader, mut writer) = udp.split();
        // One flow per application socket and destination: the TUN writes
        // every answer as if it came from the address the application sent
        // to, which is what a connected UDP socket insists on.
        let (mut relay, mut replies) =
            UdpRelay::<(SocketAddr, SocketAddr)>::new(Arc::clone(&self), id, tag, 4096);
        loop {
            tokio::select! {
                datagram = reader.next() => {
                    let Some((payload, source, target)) = datagram else {
                        return;
                    };
                    let destination = Destination::udp(Address::Ip(target.ip()), target.port());
                    relay.dispatch((source, target), source, destination, payload).await;
                }
                Some(reply) = replies.recv() => {
                    let (source, target) = reply.key;
                    // Full-cone answers keep their real origin, unless the
                    // request went to a FakeDNS handle: the application only
                    // knows that address, so the answer must come from it.
                    let from = match reply.source.address {
                        Address::Ip(ip) if !reply.restored => {
                            SocketAddr::new(ip, reply.source.port)
                        }
                        _ => target,
                    };
                    let length = reply.payload.len() as u64;
                    if writer.send((reply.payload, from, source)).await.is_ok() {
                        self.stats.downloaded.fetch_add(length, Ordering::Relaxed);
                        self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
                    } else {
                        self.stats.failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    async fn serve_dokodemo_udp(
        self: Arc<Self>,
        socket: UdpSocket,
        id: InboundId,
        tag: Arc<str>,
        target: (Address, u16),
    ) {
        let destination = Destination::udp(target.0, target.1);
        let (mut relay, mut replies) =
            UdpRelay::<SocketAddr>::new(Arc::clone(&self), id, tag, 4096);
        let mut buffer = vec![0u8; 65_535];
        loop {
            tokio::select! {
                received = socket.recv_from(&mut buffer) => {
                    let (len, source) = match received {
                        Ok(value) => value,
                        Err(error) if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
                        ) => continue,
                        Err(error) => {
                            error!(%error, "dokodemo UDP receive failed");
                            return;
                        }
                    };
                    relay
                        .dispatch(source, source, destination.clone(), buffer[..len].to_vec())
                        .await;
                }
                Some(reply) = replies.recv() => {
                    match socket.send_to(&reply.payload, reply.key).await {
                        Ok(_) => {
                            self.stats
                                .downloaded
                                .fetch_add(reply.payload.len() as u64, Ordering::Relaxed);
                            self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(error) => {
                            self.stats.failed.fetch_add(1, Ordering::Relaxed);
                            debug!(client = %reply.key, %error, "dokodemo UDP reply failed");
                        }
                    }
                }
            }
        }
    }

    async fn handle_vmess(
        self: Arc<Self>,
        stream: zero_core::BoxStream,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
        config: &zero_config::VmessInboundConfig,
    ) -> Result<(), String> {
        let users: Vec<_> = config
            .users
            .iter()
            .map(|user| zero_protocol::vmess::User {
                uuid: user.uuid,
                cipher: outbound::vmess_cipher(user.cipher),
            })
            .collect();
        let accepted = within_handshake(zero_protocol::vmess::server_handshake(stream, &users))
            .await?
            .map_err(|error| format!("reading VMess request: {error}"))?;
        if accepted.destination.network != Network::Tcp {
            return self
                .handle_vmess_udp(accepted.stream, peer, id, tag, accepted.destination)
                .await;
        }
        let destination = self.restore_fake_destination(&accepted.destination).await;
        let ctx =
            SessionContext::new(self.generation(), id, tag, destination.clone()).with_source(peer);
        let remote = match self.route(&ctx).await {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Decision::DirectVia { resolver } => {
                let resolver = self.resolver().for_tag(&resolver);
                outbound::connect_direct_with_resolver(
                    &destination,
                    &zero_config::StreamSettings::default(),
                    &resolver,
                )
                .await
                .map_err(|error| error.to_string())?
            }
            Decision::Outbound(outbound_tag) | Decision::Balancer(outbound_tag) => {
                let outbound = self
                    .pick_outbound(&outbound_tag)
                    .ok_or_else(|| format!("no usable outbound for {outbound_tag:?}"))?;
                match &outbound.protocol {
                    OutboundProtocol::Freedom { .. } => outbound::connect_direct_with_resolver(
                        &destination,
                        &outbound.stream,
                        &self.resolver(),
                    )
                    .await
                    .map_err(|error| error.to_string())?,
                    OutboundProtocol::Vless(_)
                    | OutboundProtocol::Trojan(_)
                    | OutboundProtocol::Shadowsocks(_)
                    | OutboundProtocol::Vmess(_)
                    | OutboundProtocol::AnyTls(_)
                    | OutboundProtocol::Hysteria2(_)
                    | OutboundProtocol::Tuic(_) => {
                        let stream = outbound::connect_with_resolver(
                            &outbound,
                            &destination,
                            &self.resolver(),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                        outbound::strip_response(&outbound, stream)
                    }
                    OutboundProtocol::Blackhole => {
                        self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                        return Ok(());
                    }
                    other => {
                        return Err(format!("{} cannot carry a VMess TCP session", other.name()))
                    }
                }
            }
        };
        let outcome = relay(boxed(accepted.stream), remote).await;
        self.record_observation(&outcome).await;
        self.stats
            .record_tag_traffic(&ctx.inbound_tag, None, &outcome.transferred);
        self.stats
            .uploaded
            .fetch_add(outcome.transferred.uploaded, Ordering::Relaxed);
        self.stats
            .downloaded
            .fetch_add(outcome.transferred.downloaded, Ordering::Relaxed);
        if outcome.is_useful() {
            self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
        }
        debug!(
            %peer,
            dest = %destination,
            up = outcome.transferred.uploaded,
            down = outcome.transferred.downloaded,
            stage = ?outcome.stage,
            error = ?outcome.error,
            "VMess session finished"
        );
        Ok(())
    }

    async fn handle_anytls(
        self: Arc<Self>,
        stream: zero_core::BoxStream,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
        config: &zero_config::AnyTlsInboundConfig,
    ) -> Result<(), String> {
        let passwords: Vec<[u8; 32]> = config
            .passwords
            .iter()
            .map(|password| {
                use sha2::{Digest, Sha256};
                let mut hash = [0u8; 32];
                hash.copy_from_slice(Sha256::digest(password.as_bytes()).as_slice());
                hash
            })
            .collect();
        let (stream, announced) =
            within_handshake(zero_protocol::anytls::server_handshake(stream, &passwords))
                .await?
                .map_err(|error| format!("AnyTLS handshake: {error}"))?;
        let destination = self.restore_fake_destination(&announced).await;
        let ctx =
            SessionContext::new(self.generation(), id, tag, destination.clone()).with_source(peer);
        let remote = match self.route(&ctx).await {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Decision::DirectVia { resolver } => {
                let resolver = self.resolver().for_tag(&resolver);
                outbound::connect_direct_with_resolver(
                    &destination,
                    &zero_config::StreamSettings::default(),
                    &resolver,
                )
                .await
                .map_err(|error| error.to_string())?
            }
            Decision::Outbound(outbound_tag) | Decision::Balancer(outbound_tag) => {
                let outbound = self
                    .pick_outbound(&outbound_tag)
                    .ok_or_else(|| format!("no usable outbound for {outbound_tag:?}"))?;
                match &outbound.protocol {
                    OutboundProtocol::Freedom { .. } => outbound::connect_direct_with_resolver(
                        &destination,
                        &outbound.stream,
                        &self.resolver(),
                    )
                    .await
                    .map_err(|error| error.to_string())?,
                    OutboundProtocol::Vless(_)
                    | OutboundProtocol::Trojan(_)
                    | OutboundProtocol::Shadowsocks(_)
                    | OutboundProtocol::Vmess(_)
                    | OutboundProtocol::AnyTls(_)
                    | OutboundProtocol::Hysteria2(_)
                    | OutboundProtocol::Tuic(_) => {
                        let stream = outbound::connect_with_resolver(
                            &outbound,
                            &destination,
                            &self.resolver(),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                        outbound::strip_response(&outbound, stream)
                    }
                    OutboundProtocol::Blackhole => {
                        self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                        return Ok(());
                    }
                    other => {
                        return Err(format!(
                            "{} cannot carry an AnyTLS TCP session",
                            other.name()
                        ))
                    }
                }
            }
        };
        let outcome = relay(boxed(stream), remote).await;
        self.record_observation(&outcome).await;
        self.stats
            .uploaded
            .fetch_add(outcome.transferred.uploaded, Ordering::Relaxed);
        self.stats
            .downloaded
            .fetch_add(outcome.transferred.downloaded, Ordering::Relaxed);
        if outcome.is_useful() {
            self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
        }
        debug!(
            dest = %destination,
            up = outcome.transferred.uploaded,
            down = outcome.transferred.downloaded,
            stage = ?outcome.stage,
            error = ?outcome.error,
            "AnyTLS session finished"
        );
        Ok(())
    }

    async fn handle_hysteria2(
        self: Arc<Self>,
        stream: zero_core::BoxStream,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
        destination: Destination,
    ) -> Result<(), String> {
        let destination = self.restore_fake_destination(&destination).await;
        let ctx =
            SessionContext::new(self.generation(), id, tag, destination.clone()).with_source(peer);
        let remote = match self.route(&ctx).await {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Decision::DirectVia { resolver } => {
                let resolver = self.resolver().for_tag(&resolver);
                outbound::connect_direct_with_resolver(
                    &destination,
                    &zero_config::StreamSettings::default(),
                    &resolver,
                )
                .await
                .map_err(|error| error.to_string())?
            }
            Decision::Outbound(outbound_tag) | Decision::Balancer(outbound_tag) => {
                let outbound = self
                    .pick_outbound(&outbound_tag)
                    .ok_or_else(|| format!("no usable outbound for {outbound_tag:?}"))?;
                match &outbound.protocol {
                    OutboundProtocol::Freedom { .. } => outbound::connect_direct_with_resolver(
                        &destination,
                        &outbound.stream,
                        &self.resolver(),
                    )
                    .await
                    .map_err(|error| error.to_string())?,
                    OutboundProtocol::Vless(_)
                    | OutboundProtocol::Trojan(_)
                    | OutboundProtocol::Shadowsocks(_)
                    | OutboundProtocol::Vmess(_)
                    | OutboundProtocol::AnyTls(_)
                    | OutboundProtocol::Hysteria2(_)
                    | OutboundProtocol::Tuic(_) => {
                        let stream = outbound::connect_with_resolver(
                            &outbound,
                            &destination,
                            &self.resolver(),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                        outbound::strip_response(&outbound, stream)
                    }
                    OutboundProtocol::Blackhole => {
                        self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                        return Ok(());
                    }
                    other => {
                        return Err(format!(
                            "{} cannot carry a Hysteria2 TCP session",
                            other.name()
                        ))
                    }
                }
            }
        };
        let outcome = relay(boxed(stream), remote).await;
        self.record_observation(&outcome).await;
        self.stats
            .uploaded
            .fetch_add(outcome.transferred.uploaded, Ordering::Relaxed);
        self.stats
            .downloaded
            .fetch_add(outcome.transferred.downloaded, Ordering::Relaxed);
        if outcome.is_useful() {
            self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
        }
        debug!(
            dest = %destination,
            up = outcome.transferred.uploaded,
            down = outcome.transferred.downloaded,
            stage = ?outcome.stage,
            error = ?outcome.error,
            "Hysteria2 session finished"
        );
        Ok(())
    }

    async fn handle_hysteria2_udp(
        self: Arc<Self>,
        session: Hysteria2UdpSession,
        id: InboundId,
        tag: Arc<str>,
    ) -> Result<(), String> {
        let Hysteria2UdpSession {
            connection,
            session_id,
            packet_id,
            peer,
            destination,
            payload,
        } = session;
        let destination = self.restore_fake_destination(&destination).await;
        let datagram = socks::UdpDatagram {
            destination: destination.clone(),
            payload,
        };
        let ctx =
            SessionContext::new(self.generation(), id, tag, destination.clone()).with_source(peer);
        let decision = self.route(&ctx).await;
        let resolver = match &decision {
            Decision::DirectVia { resolver } => Arc::new(self.resolver().for_tag(resolver)),
            _ => self.resolver(),
        };
        let proxy = match decision {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Decision::DirectVia { .. } => None,
            Decision::Outbound(outbound_tag) | Decision::Balancer(outbound_tag) => {
                Some(self.pick_outbound(&outbound_tag).ok_or_else(|| {
                    format!("no outbound for Hysteria2 UDP route {outbound_tag:?}")
                })?)
            }
        };
        let (response_destination, response) = if let Some(outbound) = proxy {
            if matches!(outbound.protocol, OutboundProtocol::Freedom { .. }) {
                self.direct_udp(&resolver, &datagram, &outbound.stream.evasion.udp_noise)
                    .await?
            } else {
                self.proxy_udp(&outbound, &datagram).await?
            }
        } else {
            self.direct_udp(&resolver, &datagram, &[]).await?
        };
        let frame = zero_transport::hysteria2::encode_udp_datagram(
            session_id,
            packet_id,
            &response_destination,
            &response,
        )?;
        connection
            .send_datagram(bytes::Bytes::from(frame))
            .map_err(|error| format!("sending Hysteria2 UDP response: {error}"))?;
        self.stats
            .uploaded
            .fetch_add(datagram.payload.len() as u64, Ordering::Relaxed);
        self.stats
            .downloaded
            .fetch_add(response.len() as u64, Ordering::Relaxed);
        self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_tuic_udp(
        self: Arc<Self>,
        connection: h3_quinn::quinn::Connection,
        association: u16,
        packet: u16,
        peer: SocketAddr,
        destination: Destination,
        payload: Vec<u8>,
        id: InboundId,
        tag: Arc<str>,
    ) -> Result<(), String> {
        let destination = self.restore_fake_destination(&destination).await;
        let datagram = socks::UdpDatagram {
            destination: destination.clone(),
            payload,
        };
        let ctx =
            SessionContext::new(self.generation(), id, tag, destination.clone()).with_source(peer);
        let decision = self.route(&ctx).await;
        let resolver = match &decision {
            Decision::DirectVia { resolver } => Arc::new(self.resolver().for_tag(resolver)),
            _ => self.resolver(),
        };
        let proxy = match decision {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Decision::DirectVia { .. } => None,
            Decision::Outbound(outbound_tag) | Decision::Balancer(outbound_tag) => Some(
                self.pick_outbound(&outbound_tag)
                    .ok_or_else(|| format!("no outbound for TUIC UDP route {outbound_tag:?}"))?,
            ),
        };
        let (response_destination, response) = if let Some(outbound) = proxy {
            if matches!(outbound.protocol, OutboundProtocol::Freedom { .. }) {
                self.direct_udp(&resolver, &datagram, &outbound.stream.evasion.udp_noise)
                    .await?
            } else {
                self.proxy_udp(&outbound, &datagram).await?
            }
        } else {
            self.direct_udp(&resolver, &datagram, &[]).await?
        };
        let max_datagram = connection
            .max_datagram_size()
            .ok_or_else(|| "TUIC peer does not support QUIC datagrams".to_string())?;
        for frame in zero_transport::tuic::encode_packet_fragments(
            max_datagram,
            association,
            packet,
            &response_destination,
            &response,
        )? {
            connection
                .send_datagram(bytes::Bytes::from(frame))
                .map_err(|error| format!("sending TUIC UDP response: {error}"))?;
        }
        self.stats
            .uploaded
            .fetch_add(datagram.payload.len() as u64, Ordering::Relaxed);
        self.stats
            .downloaded
            .fetch_add(response.len() as u64, Ordering::Relaxed);
        self.stats.succeeded.fetch_add(1, Ordering::Relaxed);

        // `send_datagram` only queues. A QUIC connection closes as soon as its
        // last handle drops, taking anything still queued with it, so returning
        // here would routinely discard the reply that was just produced. Hold
        // the connection until the peer closes it, bounded so a client that
        // never closes cannot pin the connection open.
        tokio::spawn(async move {
            let _ = timeout(Duration::from_secs(30), connection.closed()).await;
        });
        Ok(())
    }

    async fn handle_vmess_udp(
        self: Arc<Self>,
        mut stream: zero_protocol::vmess::Stream<zero_core::BoxStream>,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
        destination: Destination,
    ) -> Result<(), String> {
        let destination = self.restore_fake_destination(&destination).await;
        let ctx =
            SessionContext::new(self.generation(), id, tag, destination.clone()).with_source(peer);
        let decision = self.route(&ctx).await;
        let outbound = match decision {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Decision::DirectVia { .. } => None,
            Decision::Outbound(tag) | Decision::Balancer(tag) => Some(
                self.pick_outbound(&tag)
                    .ok_or_else(|| format!("no usable outbound for {tag:?}"))?,
            ),
        };
        if let Some(outbound) = outbound {
            if matches!(outbound.protocol, OutboundProtocol::Freedom { .. }) {
                return self.relay_vmess_udp_direct(&mut stream, &destination).await;
            }
            let mut payload = vec![0u8; 65_535];
            loop {
                let n = match timeout(UDP_SESSION_IDLE, stream.read(&mut payload)).await {
                    Ok(read) => {
                        read.map_err(|error| format!("reading VMess UDP payload: {error}"))?
                    }
                    Err(_) => return Ok(()),
                };
                if n == 0 {
                    return Ok(());
                }
                let datagram = socks::UdpDatagram {
                    destination: destination.clone(),
                    payload: payload[..n].to_vec(),
                };
                let response = match self.proxy_udp(&outbound, &datagram).await {
                    Ok((_, response)) => response,
                    // One unanswered datagram is not a reason to end the
                    // client's whole UDP session.
                    Err(error) => {
                        self.stats.failed.fetch_add(1, Ordering::Relaxed);
                        debug!(%destination, %error, "VMess UDP exchange failed");
                        continue;
                    }
                };
                stream
                    .write_all(&response)
                    .await
                    .map_err(|error| format!("writing VMess UDP response: {error}"))?;
                stream
                    .flush()
                    .await
                    .map_err(|error| format!("flushing VMess UDP response: {error}"))?;
            }
        }
        self.relay_vmess_udp_direct(&mut stream, &destination).await
    }

    async fn relay_vmess_udp_direct(
        &self,
        stream: &mut zero_protocol::vmess::Stream<zero_core::BoxStream>,
        destination: &Destination,
    ) -> Result<(), String> {
        let addrs = self
            .resolver()
            .resolve_address(
                &destination.address,
                self.resolver().settings().query_strategy,
            )
            .await
            .map_err(|error| error.to_string())?;
        let target = SocketAddr::new(
            *addrs
                .first()
                .ok_or_else(|| "resolver returned no VMess UDP destinations".to_string())?,
            destination.port,
        );
        let socket = bind_outbound_udp(target.is_ipv4())
            .await
            .map_err(|error| format!("binding VMess UDP socket: {error}"))?;
        socket
            .connect(target)
            .await
            .map_err(|error| format!("connecting VMess UDP socket: {error}"))?;
        let mut client_payload = vec![0u8; 65_535];
        let mut remote_payload = vec![0u8; 65_535];
        let idle = tokio::time::sleep(UDP_SESSION_IDLE);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                () = &mut idle => return Ok(()),
                result = stream.read(&mut client_payload) => {
                    idle.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_IDLE);
                    let length = result.map_err(|error| format!("reading VMess UDP payload: {error}"))?;
                    if length == 0 { return Ok(()); }
                    match socket.send(&client_payload[..length]).await {
                        Ok(_) => {}
                        Err(error) if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
                        ) => {}
                        Err(error) => return Err(format!("sending VMess UDP payload: {error}")),
                    }
                }
                result = socket.recv(&mut remote_payload) => {
                    idle.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_IDLE);
                    let length = match result {
                        Ok(length) => length,
                        // ICMP unreachable reported on the connected socket.
                        Err(error) if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
                        ) => continue,
                        Err(error) => return Err(format!("receiving VMess UDP response: {error}")),
                    };
                    stream.write_all(&remote_payload[..length]).await
                        .map_err(|error| format!("writing VMess UDP response: {error}"))?;
                    stream.flush().await
                        .map_err(|error| format!("flushing VMess UDP response: {error}"))?;
                }
            }
        }
    }

    async fn handle_vless(
        self: Arc<Self>,
        mut stream: zero_core::BoxStream,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
        config: &VlessInboundConfig,
    ) -> Result<(), String> {
        let (mut request, consumed, buffered) =
            within_handshake(read_vless_request(&mut stream)).await??;
        let user = config
            .users
            .iter()
            .find(|user| user.uuid == request.uuid)
            .ok_or_else(|| "VLESS UUID is not authorised".to_string())?;
        let request_is_vision = request.flow.is_some();
        let user_is_vision = user.flow.is_vision();
        if request_is_vision != user_is_vision {
            return Err("VLESS Vision flow does not match the authorised user".into());
        }

        if request.mux {
            if user_is_vision {
                return Err("VLESS Mux cannot be combined with Vision".into());
            }
            let mut outer = ChainedStream::new(buffered[consumed..].to_vec(), stream);
            let first = within_handshake(zero_protocol::mux::read_frame(&mut outer))
                .await?
                .map_err(|error| format!("reading VLESS Mux frame: {error}"))?;
            let destination = first
                .target
                .clone()
                .ok_or_else(|| "VLESS Mux first frame has no destination".to_string())?;
            if destination.network == Network::Udp {
                return self.handle_vless_mux_udp(outer, first, peer, id, tag).await;
            }
            return self
                .handle_vless_mux(outer, first, peer, id, tag, destination)
                .await;
        }

        request.destination = self.restore_fake_destination(&request.destination).await;

        if request.destination.network == Network::Udp {
            if user_is_vision {
                return Err("VLESS Vision is only valid for TCP sessions".into());
            }
            return self
                .handle_vless_udp(
                    stream,
                    peer,
                    id,
                    tag,
                    request.destination,
                    buffered[consumed..].to_vec(),
                )
                .await;
        }

        let ctx = SessionContext::new(self.generation(), id, tag, request.destination.clone())
            .with_source(peer);
        let decision = self.route(&ctx).await;
        let remote = match decision {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Decision::Outbound(outbound_tag) | Decision::Balancer(outbound_tag) => {
                let outbound = self
                    .pick_outbound(&outbound_tag)
                    .ok_or_else(|| format!("no usable outbound for {outbound_tag:?}"))?;
                match &outbound.protocol {
                    OutboundProtocol::Freedom { .. } => outbound::connect_direct_with_resolver(
                        &request.destination,
                        &outbound.stream,
                        &self.resolver(),
                    )
                    .await
                    .map_err(|error| error.to_string())?,
                    OutboundProtocol::Vless(_)
                    | OutboundProtocol::Trojan(_)
                    | OutboundProtocol::Shadowsocks(_)
                    | OutboundProtocol::Vmess(_)
                    | OutboundProtocol::AnyTls(_)
                    | OutboundProtocol::Hysteria2(_)
                    | OutboundProtocol::Tuic(_) => {
                        let stream = outbound::connect_with_resolver(
                            &outbound,
                            &request.destination,
                            &self.resolver(),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                        outbound::strip_response(&outbound, stream)
                    }
                    OutboundProtocol::Blackhole => {
                        self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                        return Ok(());
                    }
                    other => {
                        return Err(format!("{} cannot carry a VLESS TCP session", other.name()))
                    }
                }
            }
            Decision::DirectVia { resolver } => {
                let resolver = self.resolver().for_tag(&resolver);
                outbound::connect_direct_with_resolver(
                    &request.destination,
                    &zero_config::StreamSettings::default(),
                    &resolver,
                )
                .await
                .map_err(|error| error.to_string())?
            }
        };

        debug!(%peer, vision = user_is_vision, "VLESS route connected; sending response header");
        stream
            .write_all(&[0, 0])
            .await
            .map_err(|error| format!("writing VLESS response: {error}"))?;
        stream
            .flush()
            .await
            .map_err(|error| format!("flushing VLESS response: {error}"))?;
        debug!(%peer, "VLESS response header sent; starting relay");
        let client = ChainedStream::new(buffered[consumed..].to_vec(), stream);
        let client: zero_core::BoxStream = if user_is_vision {
            boxed(zero_protocol::vision::VisionStream::new_server(
                client,
                request.uuid,
            ))
        } else {
            boxed(client)
        };
        let outcome = relay(client, remote).await;
        self.record_observation(&outcome).await;
        self.stats
            .record_tag_traffic(&ctx.inbound_tag, None, &outcome.transferred);
        self.stats
            .uploaded
            .fetch_add(outcome.transferred.uploaded, Ordering::Relaxed);
        self.stats
            .downloaded
            .fetch_add(outcome.transferred.downloaded, Ordering::Relaxed);
        if outcome.is_useful() {
            self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
        }
        debug!(
            %peer,
            dest = %request.destination,
            up = outcome.transferred.uploaded,
            down = outcome.transferred.downloaded,
            stage = ?outcome.stage,
            error = ?outcome.error,
            "VLESS session finished"
        );
        Ok(())
    }

    async fn handle_vless_mux_udp(
        self: Arc<Self>,
        mut outer: ChainedStream,
        first: zero_protocol::mux::Frame,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
    ) -> Result<(), String> {
        if first.status != zero_protocol::mux::STATUS_NEW
            || first
                .target
                .as_ref()
                .is_none_or(|target| target.network != Network::Udp)
            || first.option & zero_protocol::mux::OPTION_DATA == 0
        {
            return Err("VLESS XUDP must start with a UDP NEW data frame".into());
        }

        outer
            .write_all(&[0, 0])
            .await
            .map_err(|error| format!("writing VLESS XUDP response: {error}"))?;
        outer
            .flush()
            .await
            .map_err(|error| format!("flushing VLESS XUDP response: {error}"))?;

        let mut targets = HashMap::<u16, Destination>::new();
        let mut pending = Some(first);
        loop {
            let frame = if let Some(frame) = pending.take() {
                frame
            } else {
                match zero_protocol::mux::read_frame(&mut outer).await {
                    Ok(frame) => frame,
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(error) => return Err(format!("reading VLESS XUDP frame: {error}")),
                }
            };

            match frame.status {
                zero_protocol::mux::STATUS_NEW | zero_protocol::mux::STATUS_KEEP => {
                    let destination = match frame.status {
                        zero_protocol::mux::STATUS_NEW => {
                            let destination = frame.target.clone().ok_or_else(|| {
                                "VLESS XUDP NEW frame has no destination".to_string()
                            })?;
                            if destination.network != Network::Udp {
                                return Err("VLESS XUDP NEW frame is not UDP".into());
                            }
                            targets.insert(frame.session_id, destination.clone());
                            destination
                        }
                        _ => {
                            if let Some(destination) = frame.target.clone() {
                                if destination.network != Network::Udp {
                                    return Err("VLESS XUDP KEEP target is not UDP".into());
                                }
                                targets.insert(frame.session_id, destination.clone());
                                destination
                            } else {
                                targets.get(&frame.session_id).cloned().ok_or_else(|| {
                                    "VLESS XUDP KEEP frame has no known destination".to_string()
                                })?
                            }
                        }
                    };
                    if frame.option & zero_protocol::mux::OPTION_DATA == 0
                        || frame.payload.is_empty()
                    {
                        continue;
                    }

                    let destination = self.restore_fake_destination(&destination).await;
                    let ctx = SessionContext::new(
                        self.generation(),
                        id,
                        tag.clone(),
                        destination.clone(),
                    )
                    .with_source(peer);
                    let decision = self.route(&ctx).await;
                    let session_id = frame.session_id;
                    let resolver = match &decision {
                        Decision::DirectVia { resolver } => {
                            Arc::new(self.resolver().for_tag(resolver))
                        }
                        _ => self.resolver(),
                    };
                    let response = match decision {
                        Decision::Block => {
                            self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        Decision::DirectVia { .. } => {
                            self.direct_udp(
                                &resolver,
                                &socks::UdpDatagram {
                                    destination: destination.clone(),
                                    payload: frame.payload,
                                },
                                &[],
                            )
                            .await
                        }
                        Decision::Outbound(outbound_tag) | Decision::Balancer(outbound_tag) => {
                            let outbound = self.pick_outbound(&outbound_tag).ok_or_else(|| {
                                format!("no outbound for VLESS XUDP route {outbound_tag:?}")
                            })?;
                            let datagram = socks::UdpDatagram {
                                destination: destination.clone(),
                                payload: frame.payload,
                            };
                            if matches!(outbound.protocol, OutboundProtocol::Freedom { .. }) {
                                self.direct_udp(
                                    &resolver,
                                    &datagram,
                                    &outbound.stream.evasion.udp_noise,
                                )
                                .await
                            } else {
                                self.proxy_udp(&outbound, &datagram).await
                            }
                        }
                    };
                    // The carrier multiplexes many UDP sessions; one datagram
                    // that goes unanswered must not tear all of them down.
                    let response = match response {
                        Ok(response) => response,
                        Err(error) => {
                            self.stats.failed.fetch_add(1, Ordering::Relaxed);
                            debug!(%destination, %error, "VLESS XUDP exchange failed");
                            continue;
                        }
                    };
                    let response_frame = zero_protocol::mux::Frame::udp_keep(
                        session_id,
                        Some(response.0),
                        response.1,
                    );
                    zero_protocol::mux::write_frame(&mut outer, &response_frame)
                        .await
                        .map_err(|error| format!("writing VLESS XUDP response frame: {error}"))?;
                    outer
                        .flush()
                        .await
                        .map_err(|error| format!("flushing VLESS XUDP response frame: {error}"))?;
                    self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
                }
                zero_protocol::mux::STATUS_END => {
                    targets.remove(&frame.session_id);
                }
                zero_protocol::mux::STATUS_KEEP_ALIVE => {}
                other => return Err(format!("unexpected VLESS XUDP status {other}")),
            }
        }
        Ok(())
    }

    async fn handle_vless_mux(
        self: Arc<Self>,
        mut outer: ChainedStream,
        first: zero_protocol::mux::Frame,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
        destination: Destination,
    ) -> Result<(), String> {
        if first.status != zero_protocol::mux::STATUS_NEW
            || first.session_id == 0
            || destination.network != Network::Tcp
        {
            return Err("VLESS Mux currently accepts nonzero TCP NEW sessions only".into());
        }
        let (_, remote) = self
            .connect_vless_mux_target(&destination, peer, id, tag.clone())
            .await?;

        outer
            .write_all(&[0, 0])
            .await
            .map_err(|error| format!("writing VLESS Mux response: {error}"))?;
        outer
            .flush()
            .await
            .map_err(|error| format!("flushing VLESS Mux response: {error}"))?;

        let server = self.clone();
        let route_tag = tag.clone();
        let route = move |target: Destination| {
            let server = server.clone();
            let route_tag = route_tag.clone();
            async move {
                server
                    .connect_vless_mux_target(&target, peer, id, route_tag)
                    .await
                    .map(|(_, stream)| stream)
                    .map_err(|error| {
                        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, error)
                    })
            }
        };
        zero_protocol::mux::relay_server_pool(boxed(outer), first, remote, route)
            .await
            .map_err(|error| format!("VLESS Mux relay: {error}"))?;
        self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn connect_vless_mux_target(
        &self,
        requested: &Destination,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
    ) -> Result<(Destination, zero_core::BoxStream), String> {
        let destination = self.restore_fake_destination(requested).await;
        let ctx =
            SessionContext::new(self.generation(), id, tag, destination.clone()).with_source(peer);
        let remote = match self.route(&ctx).await {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return Err("VLESS Mux target is blocked".into());
            }
            Decision::Outbound(outbound_tag) | Decision::Balancer(outbound_tag) => {
                let outbound = self
                    .pick_outbound(&outbound_tag)
                    .ok_or_else(|| format!("no usable outbound for {outbound_tag:?}"))?;
                match &outbound.protocol {
                    OutboundProtocol::Freedom { .. } => outbound::connect_direct_with_resolver(
                        &destination,
                        &outbound.stream,
                        &self.resolver(),
                    )
                    .await
                    .map_err(|error| error.to_string())?,
                    OutboundProtocol::Vless(_)
                    | OutboundProtocol::Trojan(_)
                    | OutboundProtocol::Shadowsocks(_)
                    | OutboundProtocol::Vmess(_)
                    | OutboundProtocol::AnyTls(_)
                    | OutboundProtocol::Hysteria2(_)
                    | OutboundProtocol::Tuic(_) => {
                        let stream = outbound::connect_with_resolver(
                            &outbound,
                            &destination,
                            &self.resolver(),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                        outbound::strip_response(&outbound, stream)
                    }
                    other => {
                        return Err(format!(
                            "{} cannot carry a VLESS Mux TCP session",
                            other.name()
                        ))
                    }
                }
            }
            Decision::DirectVia { resolver } => {
                let resolver = self.resolver().for_tag(&resolver);
                outbound::connect_direct_with_resolver(
                    &destination,
                    &zero_config::StreamSettings::default(),
                    &resolver,
                )
                .await
                .map_err(|error| error.to_string())?
            }
        };
        Ok((destination, remote))
    }

    async fn handle_trojan(
        self: Arc<Self>,
        mut stream: zero_core::BoxStream,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
        config: &zero_config::TrojanInboundConfig,
    ) -> Result<(), String> {
        let (mut request, consumed, buffered) =
            within_handshake(read_trojan_request(&mut stream)).await??;
        request.destination = self.restore_fake_destination(&request.destination).await;
        if !config
            .password_hashes
            .iter()
            .any(|candidate| candidate == &request.password_hash)
        {
            return Err("Trojan password is not authorised".into());
        }
        if request.destination.network == Network::Udp {
            return self
                .handle_trojan_udp(stream, peer, id, tag, buffered[consumed..].to_vec())
                .await;
        }
        let ctx = SessionContext::new(self.generation(), id, tag, request.destination.clone())
            .with_source(peer);
        let decision = self.route(&ctx).await;
        let remote = match decision {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Decision::Outbound(outbound_tag) | Decision::Balancer(outbound_tag) => {
                let outbound = self
                    .pick_outbound(&outbound_tag)
                    .ok_or_else(|| format!("no usable outbound for {outbound_tag:?}"))?;
                match &outbound.protocol {
                    OutboundProtocol::Freedom { .. } => outbound::connect_direct_with_resolver(
                        &request.destination,
                        &outbound.stream,
                        &self.resolver(),
                    )
                    .await
                    .map_err(|error| error.to_string())?,
                    OutboundProtocol::Vless(_)
                    | OutboundProtocol::Trojan(_)
                    | OutboundProtocol::Shadowsocks(_)
                    | OutboundProtocol::Vmess(_)
                    | OutboundProtocol::AnyTls(_)
                    | OutboundProtocol::Hysteria2(_)
                    | OutboundProtocol::Tuic(_) => {
                        let stream = outbound::connect_with_resolver(
                            &outbound,
                            &request.destination,
                            &self.resolver(),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                        outbound::strip_response(&outbound, stream)
                    }
                    OutboundProtocol::Blackhole => {
                        self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                        return Ok(());
                    }
                    other => {
                        return Err(format!(
                            "{} cannot carry a Trojan TCP session",
                            other.name()
                        ))
                    }
                }
            }
            Decision::DirectVia { resolver } => {
                let resolver = self.resolver().for_tag(&resolver);
                outbound::connect_direct_with_resolver(
                    &request.destination,
                    &zero_config::StreamSettings::default(),
                    &resolver,
                )
                .await
                .map_err(|error| error.to_string())?
            }
        };
        let client = ChainedStream::new(buffered[consumed..].to_vec(), stream);
        let outcome = relay(boxed(client), remote).await;
        self.record_observation(&outcome).await;
        self.stats
            .record_tag_traffic(&ctx.inbound_tag, None, &outcome.transferred);
        self.stats
            .uploaded
            .fetch_add(outcome.transferred.uploaded, Ordering::Relaxed);
        self.stats
            .downloaded
            .fetch_add(outcome.transferred.downloaded, Ordering::Relaxed);
        if outcome.is_useful() {
            self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn handle_shadowsocks(
        self: Arc<Self>,
        stream: zero_core::BoxStream,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
        config: &zero_config::ShadowsocksInboundConfig,
    ) -> Result<(), String> {
        if config.method.is_2022() {
            let (stream, destination) =
                within_handshake(zero_protocol::shadowsocks2022::Stream::server(
                    stream,
                    ss2022_method(config.method),
                    &config.password,
                ))
                .await?
                .map_err(|error| format!("reading Shadowsocks 2022 destination: {error}"))?;
            return self
                .complete_shadowsocks(boxed(stream), destination, peer, id, tag)
                .await;
        }
        let mut stream = zero_protocol::shadowsocks::Stream::new_server(
            stream,
            shadowsocks_method(config.method),
            config.password.as_bytes(),
        );
        let (destination, _) = within_handshake(stream.read_destination())
            .await?
            .map_err(|error| format!("reading Shadowsocks destination: {error}"))?;
        self.complete_shadowsocks(boxed(stream), destination, peer, id, tag)
            .await
    }

    async fn complete_shadowsocks(
        &self,
        stream: zero_core::BoxStream,
        destination: zero_core::Destination,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
    ) -> Result<(), String> {
        let destination = self.restore_fake_destination(&destination).await;
        let ctx =
            SessionContext::new(self.generation(), id, tag, destination.clone()).with_source(peer);
        let decision = self.route(&ctx).await;
        let remote = match decision {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Decision::DirectVia { resolver } => {
                let resolver = self.resolver().for_tag(&resolver);
                outbound::connect_direct_with_resolver(
                    &destination,
                    &zero_config::StreamSettings::default(),
                    &resolver,
                )
                .await
                .map_err(|error| error.to_string())?
            }
            Decision::Outbound(outbound_tag) | Decision::Balancer(outbound_tag) => {
                let outbound = self
                    .pick_outbound(&outbound_tag)
                    .ok_or_else(|| format!("no usable outbound for {outbound_tag:?}"))?;
                match &outbound.protocol {
                    OutboundProtocol::Freedom { .. } => outbound::connect_direct_with_resolver(
                        &destination,
                        &outbound.stream,
                        &self.resolver(),
                    )
                    .await
                    .map_err(|error| error.to_string())?,
                    OutboundProtocol::Vless(_)
                    | OutboundProtocol::Trojan(_)
                    | OutboundProtocol::Shadowsocks(_)
                    | OutboundProtocol::Vmess(_)
                    | OutboundProtocol::AnyTls(_)
                    | OutboundProtocol::Hysteria2(_)
                    | OutboundProtocol::Tuic(_) => {
                        let stream = outbound::connect_with_resolver(
                            &outbound,
                            &destination,
                            &self.resolver(),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                        outbound::strip_response(&outbound, stream)
                    }
                    OutboundProtocol::Blackhole => {
                        self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                        return Ok(());
                    }
                    other => {
                        return Err(format!(
                            "{} cannot carry a Shadowsocks TCP session",
                            other.name()
                        ))
                    }
                }
            }
        };
        let outcome = relay(boxed(stream), remote).await;
        self.record_observation(&outcome).await;
        self.stats
            .uploaded
            .fetch_add(outcome.transferred.uploaded, Ordering::Relaxed);
        self.stats
            .downloaded
            .fetch_add(outcome.transferred.downloaded, Ordering::Relaxed);
        if outcome.is_useful() {
            self.stats.succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
        }
        debug!(
            %peer,
            dest = %destination,
            up = outcome.transferred.uploaded,
            down = outcome.transferred.downloaded,
            stage = ?outcome.stage,
            error = ?outcome.error,
            "Shadowsocks session finished"
        );
        Ok(())
    }

    async fn handle_trojan_udp(
        self: Arc<Self>,
        stream: zero_core::BoxStream,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
        buffered: Vec<u8>,
    ) -> Result<(), String> {
        let (mut reader, writer) = tokio::io::split(ChainedStream::new(buffered, stream));
        let (mut udp, replies) = UdpRelay::<()>::new(Arc::clone(&self), id, tag, 64);
        let writer = AbortOnDrop(vec![tokio::spawn(write_udp_replies(
            writer,
            replies,
            Arc::clone(&self.stats),
            |reply: &UdpReply<()>| {
                zero_protocol::trojan::encode_udp_packet(&reply.source, &reply.payload)
            },
        ))]);
        let mut pending = Vec::with_capacity(2048);
        let mut scratch = vec![0u8; 16 * 1024];
        let mut seen = udp.activity();
        loop {
            let packet = match timeout(
                UDP_SESSION_IDLE,
                read_trojan_udp_packet(&mut reader, &mut pending, &mut scratch),
            )
            .await
            {
                Ok(packet) => packet?,
                Err(_) => {
                    let now = udp.activity();
                    if now == seen {
                        return Ok(());
                    }
                    seen = now;
                    continue;
                }
            };
            let Some((destination, payload)) = packet else {
                return Ok(());
            };
            if writer.0.iter().all(|task| task.is_finished()) {
                return Err("Trojan UDP client stopped accepting replies".into());
            }
            udp.dispatch((), peer, destination, payload).await;
        }
    }

    async fn handle_vless_udp(
        self: Arc<Self>,
        mut stream: zero_core::BoxStream,
        peer: SocketAddr,
        id: InboundId,
        tag: Arc<str>,
        destination: Destination,
        buffered: Vec<u8>,
    ) -> Result<(), String> {
        stream
            .write_all(&[0, 0])
            .await
            .map_err(|error| format!("writing VLESS UDP response: {error}"))?;
        stream
            .flush()
            .await
            .map_err(|error| format!("flushing VLESS UDP response: {error}"))?;
        let (mut reader, writer) = tokio::io::split(ChainedStream::new(buffered, stream));
        let (mut udp, replies) = UdpRelay::<()>::new(Arc::clone(&self), id, tag, 4);
        let writer = AbortOnDrop(vec![tokio::spawn(write_udp_replies(
            writer,
            replies,
            Arc::clone(&self.stats),
            |reply: &UdpReply<()>| zero_protocol::vless::encode_udp_frame(&reply.payload),
        ))]);
        let mut pending = Vec::new();
        let mut seen = udp.activity();
        loop {
            let payload = match timeout(
                UDP_SESSION_IDLE,
                read_vless_udp_frame(&mut reader, &mut pending),
            )
            .await
            {
                Ok(payload) => payload?,
                Err(_) => {
                    let now = udp.activity();
                    if now == seen {
                        return Ok(());
                    }
                    seen = now;
                    continue;
                }
            };
            let Some(payload) = payload else {
                return Ok(());
            };
            if writer.0.iter().all(|task| task.is_finished()) {
                return Err("VLESS UDP client stopped accepting replies".into());
            }
            udp.dispatch((), peer, destination.clone(), payload).await;
        }
    }

    async fn direct_udp(
        &self,
        resolver: &zero_dns::Resolver,
        datagram: &socks::UdpDatagram,
        noise: &[NoiseConfig],
    ) -> Result<(Destination, Vec<u8>), String> {
        let addrs = resolver
            .resolve_address(
                &datagram.destination.address,
                resolver.settings().query_strategy,
            )
            .await
            .map_err(|error| error.to_string())?;
        let remote_socket = bind_outbound_udp(addrs.first().map(|ip| ip.is_ipv4()).unwrap_or(true))
            .await
            .map_err(|e| format!("binding direct UDP socket: {e}"))?;
        let target = SocketAddr::new(
            *addrs
                .first()
                .ok_or_else(|| "resolver returned no UDP destinations".to_string())?,
            datagram.destination.port,
        );
        // The first payload is sent after the decoys. This preserves the
        // configured wire order; sending the real datagram first would make
        // the noise visible only to a receiver that already knows the flow.
        for (packet, delay) in noise_policy(noise).plan() {
            if !packet.is_empty() {
                remote_socket
                    .send_to(&packet, target)
                    .await
                    .map_err(|error| format!("sending UDP noise: {error}"))?;
            }
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        }
        remote_socket
            .send_to(&datagram.payload, target)
            .await
            .map_err(|error| format!("sending UDP payload: {error}"))?;
        let mut response = vec![0u8; 65_535];
        let (len, remote) = timeout(
            Duration::from_secs(5),
            remote_socket.recv_from(&mut response),
        )
        .await
        .map_err(|_| "UDP response timed out".to_string())?
        .map_err(|e| format!("receiving UDP response: {e}"))?;
        Ok((
            Destination::udp(Address::Ip(remote.ip()), remote.port()),
            response[..len].to_vec(),
        ))
    }

    async fn proxy_udp(
        &self,
        outbound: &zero_config::Outbound,
        datagram: &socks::UdpDatagram,
    ) -> Result<(Destination, Vec<u8>), String> {
        let started = std::time::Instant::now();
        let result = timeout(
            UDP_EXCHANGE_DEADLINE,
            self.proxy_udp_inner(outbound, datagram),
        )
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "UDP exchange through {} timed out after {}s",
                outbound.tag,
                UDP_EXCHANGE_DEADLINE.as_secs()
            ))
        });
        let mut health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match result.is_ok() {
            true => health.record_success(&outbound.tag, started.elapsed()),
            false => health.record_failure(&outbound.tag),
        }
        result
    }

    async fn proxy_udp_inner(
        &self,
        outbound: &zero_config::Outbound,
        datagram: &socks::UdpDatagram,
    ) -> Result<(Destination, Vec<u8>), String> {
        if outbound.mux.enabled {
            let carrier = outbound::connect_mux_carrier_with_resolver(outbound, &self.resolver())
                .await
                .map_err(|error| error.to_string())?;
            let (source, response) = timeout(
                Duration::from_secs(5),
                zero_protocol::mux::exchange_udp(
                    carrier,
                    datagram.destination.clone(),
                    &datagram.payload,
                    [0; 8],
                ),
            )
            .await
            .map_err(|_| "VLESS XUDP response timed out".to_string())?
            .map_err(|error| format!("VLESS XUDP exchange failed: {error}"))?;
            return Ok((
                source.unwrap_or_else(|| datagram.destination.clone()),
                response,
            ));
        }
        if let OutboundProtocol::AmneziaWireguard(wireguard) = &outbound.protocol {
            let (address, port) = outbound
                .endpoint()
                .ok_or_else(|| "AmneziaWG outbound has no endpoint".to_string())?;
            let peer_endpoints = self
                .resolver()
                .resolve_address(&address, self.resolver().settings().query_strategy)
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect::<Vec<_>>();
            let peer = *peer_endpoints
                .first()
                .ok_or_else(|| "AmneziaWG peer has no address".to_string())?;
            let stack =
                zero_protocol::wg_stack::shared(peer, outbound::wireguard_stack_params(wireguard))?;
            let destination = match &datagram.destination.address {
                Address::Ip(ip) => SocketAddr::new(*ip, datagram.destination.port),
                // Resolved inside the tunnel, like the TCP path.
                Address::Domain(name) => stack
                    .resolve(name)
                    .await?
                    .into_iter()
                    .find(|ip| stack.carries(*ip))
                    .map(|ip| SocketAddr::new(ip, datagram.destination.port))
                    .ok_or_else(|| "AmneziaWG destination has no usable address".to_string())?,
            };
            let result = stack.exchange_udp(destination, &datagram.payload).await;
            let (source, response) = result?;
            return Ok((
                Destination::udp(Address::Ip(source.ip()), source.port()),
                response,
            ));
        }
        if let OutboundProtocol::Tuic(tuic) = &outbound.protocol {
            let (address, port) = outbound
                .endpoint()
                .ok_or_else(|| "TUIC outbound has no endpoint".to_string())?;
            let addrs = self
                .resolver()
                .resolve_address(&address, self.resolver().settings().query_strategy)
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect::<Vec<_>>();
            let tls = outbound::tls_params(&outbound.stream, &address.host_string())
                .ok_or_else(|| "TUIC requires ordinary certificate TLS".to_string())?;
            return zero_transport::tuic::exchange_udp(
                &addrs,
                &tls,
                &tuic.uuid,
                &tuic.password,
                &datagram.destination,
                &datagram.payload,
            )
            .await;
        }
        if let OutboundProtocol::Hysteria2(hysteria) = &outbound.protocol {
            let (address, port) = outbound
                .endpoint()
                .ok_or_else(|| "Hysteria2 outbound has no endpoint".to_string())?;
            let addrs = self
                .resolver()
                .resolve_address(&address, self.resolver().settings().query_strategy)
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect::<Vec<_>>();
            let tls = outbound::tls_params(&outbound.stream, &address.host_string())
                .ok_or_else(|| "Hysteria2 requires ordinary certificate TLS".to_string())?;
            return zero_transport::hysteria2::exchange_udp(
                &addrs,
                &tls,
                &hysteria.password,
                &datagram.destination,
                &datagram.payload,
            )
            .await;
        }
        let stream =
            outbound::connect_with_resolver(outbound, &datagram.destination, &self.resolver())
                .await
                .map_err(|error| error.to_string())?;
        let mut stream = outbound::strip_response(outbound, stream);
        match &outbound.protocol {
            OutboundProtocol::Vless(_) => {
                let frame = zero_protocol::vless::encode_udp_frame(&datagram.payload)?;
                stream
                    .write_all(&frame)
                    .await
                    .map_err(|error| format!("writing VLESS UDP frame: {error}"))?;
                stream
                    .flush()
                    .await
                    .map_err(|error| format!("flushing VLESS UDP frame: {error}"))?;
                let mut length = [0u8; 2];
                timeout(Duration::from_secs(5), stream.read_exact(&mut length))
                    .await
                    .map_err(|_| "VLESS UDP response timed out".to_string())?
                    .map_err(|error| format!("reading VLESS UDP length: {error}"))?;
                let length = u16::from_be_bytes(length) as usize;
                if length == 0 {
                    return Err("VLESS returned an empty UDP response".into());
                }
                let mut response = vec![0u8; length];
                stream
                    .read_exact(&mut response)
                    .await
                    .map_err(|error| format!("reading VLESS UDP payload: {error}"))?;
                Ok((datagram.destination.clone(), response))
            }
            OutboundProtocol::Trojan(_) => {
                let frame = zero_protocol::trojan::encode_udp_packet(
                    &datagram.destination,
                    &datagram.payload,
                )?;
                stream
                    .write_all(&frame)
                    .await
                    .map_err(|error| format!("writing Trojan UDP frame: {error}"))?;
                stream
                    .flush()
                    .await
                    .map_err(|error| format!("flushing Trojan UDP frame: {error}"))?;
                let mut response = vec![0u8; 65_535];
                let mut filled = 0;
                loop {
                    let n = stream
                        .read(&mut response[filled..])
                        .await
                        .map_err(|error| format!("reading Trojan UDP response: {error}"))?;
                    if n == 0 {
                        return Err("Trojan closed before returning a UDP response".into());
                    }
                    filled += n;
                    if let Ok((destination, payload, _)) =
                        zero_protocol::trojan::decode_udp_packet(&response[..filled])
                    {
                        return Ok((destination, payload));
                    }
                    if filled == response.len() {
                        return Err("Trojan UDP response exceeded the frame limit".into());
                    }
                }
            }
            OutboundProtocol::Vmess(_) => {
                stream
                    .write_all(&datagram.payload)
                    .await
                    .map_err(|error| format!("writing VMess UDP payload: {error}"))?;
                stream
                    .flush()
                    .await
                    .map_err(|error| format!("flushing VMess UDP payload: {error}"))?;
                let mut payload = vec![0u8; 65_535];
                let n = stream
                    .read(&mut payload)
                    .await
                    .map_err(|error| format!("reading VMess UDP response: {error}"))?;
                if n == 0 {
                    return Err("VMess closed before returning a UDP response".into());
                }
                Ok((datagram.destination.clone(), payload[..n].to_vec()))
            }
            other => Err(format!("{} cannot carry UDP", other.name())),
        }
    }

    /// Pick a concrete outbound, expanding a balancer tag if needed.
    async fn route(&self, ctx: &SessionContext) -> Decision {
        let resolved = match (
            ctx.destination.address.as_domain(),
            self.config().routing.domain_strategy,
        ) {
            (Some(_), zero_config::routing::DomainStrategy::AsIs) => None,
            (Some(domain), _) => self
                .resolver()
                .lookup(domain, self.resolver().settings().query_strategy)
                .await
                .ok()
                .and_then(|addresses| addresses.into_iter().next()),
            _ => None,
        };
        self.router().route(ctx, resolved)
    }

    fn pick_outbound(&self, tag: &str) -> Option<zero_config::Outbound> {
        let config = self.config();
        if let Some(o) = config.outbound_by_tag(tag) {
            let mut outbound = o.clone();
            self.apply_planner_strategy(&mut outbound);
            return Some(outbound);
        }
        let b = config.balancer_by_tag(tag)?;
        let members = config.expand_balancer(b);
        if members.is_empty() {
            return None;
        }

        let ticket = self.selection_counter.fetch_add(1, Ordering::Relaxed);
        let index = match b.strategy {
            zero_config::routing::BalancerStrategy::LeastPing => {
                let tags = members
                    .iter()
                    .map(|id| config.outbounds[id.0 as usize].tag.clone())
                    .collect::<Vec<_>>();
                self.health
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .choose(
                        zero_observatory::BalancerHealthStrategy::LeastPing,
                        &tags,
                        ticket,
                    )
            }
            zero_config::routing::BalancerStrategy::LeastLoad => {
                let tags = members
                    .iter()
                    .map(|id| config.outbounds[id.0 as usize].tag.clone())
                    .collect::<Vec<_>>();
                self.health
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .choose(
                        zero_observatory::BalancerHealthStrategy::LeastLoad,
                        &tags,
                        ticket,
                    )
            }
            strategy => choose_balancer_index(strategy, ticket, members.len()),
        };
        let mut outbound = config.outbounds[members[index].0 as usize].clone();
        self.apply_planner_strategy(&mut outbound);
        Some(outbound)
    }

    /// Materialise the planner's current rung for a new session. Every
    /// adaptation here either changes a compiled, bounded field or selects a
    /// separately validated outbound class; raw packet injection is kept out
    /// of this safe stream boundary.
    fn apply_planner_strategy(&self, outbound: &mut zero_config::Outbound) {
        let strategy =
            zero_observatory::PathStrategy::from_u8(self.planner_strategy.load(Ordering::Relaxed));
        self.apply_strategy_to(outbound, strategy);
    }

    /// Materialise one specific rung onto an outbound. Separated from the
    /// session path so a descent probe can test a rung without first making it
    /// live for real traffic.
    fn apply_strategy_to(
        &self,
        outbound: &mut zero_config::Outbound,
        strategy: zero_observatory::PathStrategy,
    ) {
        if let Some(candidate) = self.planner_candidate(strategy) {
            debug!(
                from = %outbound.tag,
                to = %candidate.tag,
                ?strategy,
                "planner switched outbound access class"
            );
            *outbound = candidate;
        }
        if strategy == zero_observatory::PathStrategy::FingerprintRotation {
            self.rotate_fingerprint(outbound);
        }
        if strategy == zero_observatory::PathStrategy::CdnCleanIp {
            self.apply_clean_ip(outbound);
        }
        if strategy == zero_observatory::PathStrategy::KeepaliveShaping
            && outbound.stream.evasion.keepalive.is_none()
        {
            // Size the shape from what was actually measured. With no
            // measurement — a probe testing this rung before any timeout has
            // been seen — fall back to the conservative default rather than
            // inventing a deadline.
            let observed = self.planner_flow_lifetime_ms.load(Ordering::Relaxed);
            let policy = (observed > 0)
                .then(|| {
                    zero_evasion::KeepalivePolicy::from_observed_reset(
                        std::time::Duration::from_millis(observed),
                    )
                })
                .flatten();
            let config = match policy {
                Some(policy) => zero_config::KeepaliveConfig {
                    idle_after: policy.idle_after,
                    max_flow_lifetime: policy.max_flow_lifetime,
                },
                None => zero_config::KeepaliveConfig::default(),
            };
            debug!(
                outbound = %outbound.tag,
                observed_ms = observed,
                idle_ms = config.idle_after.as_millis(),
                lifetime_ms = config.max_flow_lifetime.map(|l| l.as_millis()),
                "planner enabled keepalive shaping"
            );
            outbound.stream.evasion.keepalive = Some(config);
        }
        if matches!(
            strategy,
            zero_observatory::PathStrategy::ClientHelloFragment
                | zero_observatory::PathStrategy::SniDesync
        ) && !matches!(outbound.stream.security, zero_config::Security::None)
            && !matches!(
                &outbound.stream.security,
                zero_config::Security::Tls(zero_config::TlsConfig { ech: Some(_), .. })
            )
            && outbound.stream.evasion.tcp_fragment.is_none()
        {
            outbound.stream.evasion.tcp_fragment = Some(zero_config::FragmentConfig::default());
            debug!(
                outbound = %outbound.tag,
                ?strategy,
                "planner enabled ClientHello fragmentation"
            );
        }
        if strategy == zero_observatory::PathStrategy::SniDesync
            && !matches!(
                &outbound.stream.security,
                zero_config::Security::Tls(zero_config::TlsConfig { ech: Some(_), .. })
            )
        {
            outbound.stream.evasion.sni_desync = Some(zero_config::SniDesyncConfig::default());
        }
    }

    fn planner_candidate(
        &self,
        strategy: zero_observatory::PathStrategy,
    ) -> Option<zero_config::Outbound> {
        let config = self.config();
        config
            .outbounds
            .iter()
            .find(|candidate| match strategy {
                zero_observatory::PathStrategy::RealityXhttp => {
                    matches!(
                        &candidate.stream.transport,
                        zero_config::Transport::Xhttp(_)
                    ) && matches!(
                        &candidate.stream.security,
                        zero_config::Security::Reality(_)
                    )
                }
                zero_observatory::PathStrategy::CdnWebSocket
                | zero_observatory::PathStrategy::CdnAlternatePort
                | zero_observatory::PathStrategy::CdnCleanIp => {
                    matches!(
                        &candidate.stream.transport,
                        zero_config::Transport::WebSocket(_)
                            | zero_config::Transport::HttpUpgrade(_)
                            | zero_config::Transport::Grpc(_)
                            | zero_config::Transport::Xhttp(_)
                    ) && matches!(&candidate.stream.security, zero_config::Security::Tls(_))
                        && (strategy != zero_observatory::PathStrategy::CdnAlternatePort
                            || candidate.endpoint().is_some_and(|(_, port)| port != 443))
                }
                zero_observatory::PathStrategy::AmneziaWireguard => {
                    matches!(
                        &candidate.protocol,
                        zero_config::OutboundProtocol::AmneziaWireguard(_)
                    )
                }
                _ => false,
            })
            .cloned()
    }

    fn rotate_fingerprint(&self, outbound: &mut zero_config::Outbound) {
        const PROFILES: [zero_config::Fingerprint; 6] = [
            zero_config::Fingerprint::Chrome,
            zero_config::Fingerprint::Firefox,
            zero_config::Fingerprint::Safari,
            zero_config::Fingerprint::Edge,
            zero_config::Fingerprint::Ios,
            zero_config::Fingerprint::Android,
        ];
        let ticket = self.selection_counter.fetch_add(1, Ordering::Relaxed) as usize;
        match &mut outbound.stream.security {
            zero_config::Security::Tls(tls) => {
                tls.fingerprint = PROFILES[ticket % PROFILES.len()].clone()
            }
            zero_config::Security::Reality(reality) => {
                // Not every browser shape carries an X25519 key share, and a
                // REALITY hello without one cannot hide its tag. Rotating into
                // such a profile would turn a working connection into a silent
                // fallback to the decoy site, so the rotation draws only from
                // the shapes that can actually carry it.
                let usable: Vec<&zero_config::Fingerprint> = PROFILES
                    .iter()
                    .filter(|profile| profile.supports_reality())
                    .collect();
                if let Some(profile) = usable.get(ticket % usable.len().max(1)) {
                    reality.fingerprint = (*profile).clone();
                }
            }
            zero_config::Security::None => {}
        }
    }

    /// Materialise the best measured CDN edge only for the clean-IP rung. The
    /// original hostname is retained as SNI/Host so replacing the TCP address
    /// does not turn a fronted connection into certificate verification for an
    /// IP literal. A candidate is never used before the HTTP probe has shown
    /// application progress.
    fn apply_clean_ip(&self, outbound: &mut zero_config::Outbound) {
        let candidate = self
            .clean_ip_results
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .find(|result| result.success)
            .map(|result| (result.address.ip(), result.address.port()));
        let Some((ip, port)) = candidate else {
            return;
        };
        let Some((address, _)) = outbound.endpoint() else {
            return;
        };
        let Some(host) = address.as_domain().map(str::to_owned) else {
            return;
        };
        let replacement = Address::Ip(ip);
        replace_outbound_endpoint(outbound, replacement.clone(), port);
        preserve_stream_host(&mut outbound.stream, &host);
        if let zero_config::Transport::Xhttp(settings) = &mut outbound.stream.transport {
            if let Some(download) = &mut settings.xhttp_download {
                if let Some(download_host) = download.address.as_domain().map(str::to_owned) {
                    download.address = replacement;
                    download.port = port;
                    preserve_stream_host(&mut download.stream, &download_host);
                }
            }
        }
        debug!(outbound = %outbound.tag, %ip, port, "planner selected measured clean IP");
    }

    fn record_outbound_observation(&self, tag: &str, outcome: &crate::relay::RelayOutcome) {
        let mut health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Liveness only: `outcome.elapsed` is the whole session, not a round
        // trip, so latency stays with the observatory's probes.
        if outcome.is_useful() {
            health.record_alive(tag);
        } else {
            health.record_failure(tag);
        }
    }

    async fn record_observation(&self, outcome: &crate::relay::RelayOutcome) {
        let mut planner = self.planner.lock().await;
        if outcome.is_useful() {
            planner.record_success(outcome.stage, outcome.elapsed);
        } else {
            let kind = outcome
                .error
                .as_deref()
                .map(|error| crate::relay::classify_error(error, outcome.stage))
                .unwrap_or(zero_core::FailureKind::Unknown);
            let failure = zero_core::Failure::new(kind, outcome.stage)
                .with_bytes(outcome.transferred.uploaded + outcome.transferred.downloaded)
                .with_elapsed(outcome.elapsed)
                .with_detail(
                    outcome
                        .error
                        .clone()
                        .unwrap_or_else(|| "relay ended without useful progress".into()),
                );
            match planner.record_failure(&failure) {
                zero_observatory::Transition::Hold => {}
                zero_observatory::Transition::Climb { to } => {
                    info!(
                        ?to,
                        kind = kind.as_str(),
                        "planner climbed the evasion ladder"
                    );
                }
                zero_observatory::Transition::ClassChange { to, at } => {
                    // The loud one: the endpoint family itself is gone, and
                    // every session from here on uses a different class.
                    warn!(
                        class = ?to,
                        strategy = ?at,
                        kind = kind.as_str(),
                        "access class is unreachable; failing over"
                    );
                }
            }
        }
        self.planner_strategy
            .store(planner.current().as_u8(), Ordering::Relaxed);
        self.planner_flow_lifetime_ms.store(
            planner
                .observed_flow_lifetime()
                .map(|lifetime| lifetime.as_millis().min(u64::MAX as u128) as u64)
                .unwrap_or(0),
            Ordering::Relaxed,
        );
    }

    /// Periodically re-test one rung below the current one.
    ///
    /// Blocking in Iran is event-driven and often temporary. Without this a
    /// client that climbed to a CDN during a shutdown stays there indefinitely,
    /// paying the detour long after the direct path came back (PLAN-02 §5,
    /// "descend too"). The probe is a real connection through a real outbound,
    /// because a rung that merely opens a socket is not a rung that works.
    async fn run_strategy_descent(self: Arc<Self>) {
        const INTERVAL: Duration = Duration::from_secs(300);
        loop {
            tokio::time::sleep(INTERVAL).await;

            let candidate = {
                let mut planner = self.planner.lock().await;
                planner.schedule_downgrade_probe()
            };
            let Some(candidate) = candidate else { continue };

            let Some(config) = self.config().observatory.clone() else {
                // Without a probe target there is no way to test a rung
                // honestly, so the probe is withdrawn rather than guessed.
                let mut planner = self.planner.lock().await;
                planner.record_probe(candidate, false);
                continue;
            };
            let Ok(target) = parse_probe_target(&config.probe_url) else {
                let mut planner = self.planner.lock().await;
                planner.record_probe(candidate, false);
                continue;
            };

            let Some(mut outbound) = self.descent_probe_outbound(candidate) else {
                let mut planner = self.planner.lock().await;
                planner.record_probe(candidate, false);
                continue;
            };
            self.apply_strategy_to(&mut outbound, candidate);

            let succeeded = timeout(
                Duration::from_secs(15),
                self.probe_outbound(&outbound, &target),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .is_some();

            let adopted = {
                let mut planner = self.planner.lock().await;
                let adopted = planner.record_probe(candidate, succeeded);
                self.planner_strategy
                    .store(planner.current().as_u8(), Ordering::Relaxed);
                adopted
            };
            if adopted {
                info!(
                    strategy = ?candidate,
                    "cheaper path is working again; descended the evasion ladder"
                );
            } else {
                debug!(strategy = ?candidate, succeeded, "descent probe did not adopt");
            }
        }
    }

    /// The outbound a descent probe should test: the class candidate for the
    /// lower rung, or the current default when the rung does not change class.
    fn descent_probe_outbound(
        &self,
        strategy: zero_observatory::PathStrategy,
    ) -> Option<zero_config::Outbound> {
        if let Some(candidate) = self.planner_candidate(strategy) {
            return Some(candidate);
        }
        let config = self.config();
        config
            .outbounds
            .iter()
            .find(|outbound| outbound.protocol.is_proxy())
            .cloned()
    }

    /// Keep routing rule sets current.
    ///
    /// The loop re-reads configuration every pass, so a reload can add, remove
    /// or retune assets without a restart. It sleeps for the retry interval
    /// after a failure and for the refresh interval otherwise, which keeps a
    /// permanently blocked mirror from being re-dialled in a tight loop — the
    /// situation a censored network produces by design.
    async fn run_asset_refresh(self: Arc<Self>) {
        let mut first_pass = true;
        loop {
            let config = self.config();
            let Some(assets) = config.assets.clone() else {
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            };
            let specs = asset_specs(&assets);
            if specs.is_empty() {
                tokio::time::sleep(assets.refresh_interval).await;
                continue;
            }
            let store = asset_store(&assets);
            let force = first_pass && assets.refresh_on_start;
            first_pass = false;

            let outcomes = store.refresh_all(&specs, force).await;
            let mut any_failed = false;
            let mut changed = false;
            let mut statuses = Vec::with_capacity(outcomes.len());
            for (name, outcome) in &outcomes {
                let (label, detail, entries) = match outcome {
                    zero_router::RefreshOutcome::Fresh => ("fresh", None, None),
                    zero_router::RefreshOutcome::Unchanged => ("unchanged", None, None),
                    zero_router::RefreshOutcome::Updated { bytes, entries } => {
                        changed = true;
                        info!(asset = %name, bytes, entries, "rule set updated");
                        ("updated", None, Some(*entries))
                    }
                    zero_router::RefreshOutcome::Failed { reasons } => {
                        any_failed = true;
                        let detail = reasons.join("; ");
                        // Downloading rule sets over a censored network fails
                        // routinely. It is a warning, not an error: the cached
                        // copy keeps serving.
                        warn!(asset = %name, %detail, "rule set refresh failed; keeping the cached copy");
                        ("failed", Some(detail), None)
                    }
                };
                statuses.push(AssetStatus {
                    name: name.clone(),
                    outcome: label.into(),
                    detail,
                    entries,
                    at: std::time::SystemTime::now(),
                });
            }
            *self
                .asset_status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = statuses;

            if changed {
                let mut merged = zero_router::GeoData::from_environment();
                let (cached, problems) = store.load_geodata(&specs);
                for problem in &problems {
                    warn!(%problem, "rule set is unusable after refresh");
                }
                merged.merge(cached);
                let counts = (merged.geosite.len(), merged.geoip.len());
                self.geodata.store(Arc::new(merged));
                self.rebuild_router_for_new_geodata();
                info!(
                    geosite_tags = counts.0,
                    geoip_tags = counts.1,
                    "router recompiled against refreshed rule sets"
                );
            }

            let sleep = if any_failed {
                assets.retry_interval
            } else {
                assets.refresh_interval
            };
            tokio::time::sleep(sleep).await;
        }
    }

    /// Refresh every configured rule set immediately, bypassing the TTL, and
    /// recompile the router if anything changed. Used by the management API
    /// and the CLI; the periodic task keeps running independently.
    pub async fn refresh_assets_now(&self) -> serde_json::Value {
        let config = self.config();
        let Some(assets) = config.assets.clone() else {
            return serde_json::json!({"error": "no assets are configured"});
        };
        let specs = asset_specs(&assets);
        if specs.is_empty() {
            return serde_json::json!({"error": "no rule-set files are configured"});
        }
        let store = asset_store(&assets);
        let outcomes = store.refresh_all(&specs, true).await;
        let changed = outcomes.iter().any(|(_, outcome)| outcome.changed());
        if changed {
            let mut merged = zero_router::GeoData::from_environment();
            let (cached, _) = store.load_geodata(&specs);
            merged.merge(cached);
            self.geodata.store(Arc::new(merged));
            self.rebuild_router_for_new_geodata();
        }
        serde_json::json!({
            "changed": changed,
            "files": outcomes
                .iter()
                .map(|(name, outcome)| {
                    let (state, detail) = match outcome {
                        zero_router::RefreshOutcome::Fresh => ("fresh", None),
                        zero_router::RefreshOutcome::Unchanged => ("unchanged", None),
                        zero_router::RefreshOutcome::Updated { .. } => ("updated", None),
                        zero_router::RefreshOutcome::Failed { reasons } => {
                            ("failed", Some(reasons.join("; ")))
                        }
                    };
                    serde_json::json!({"name": name, "outcome": state, "detail": detail})
                })
                .collect::<Vec<_>>(),
        })
    }

    /// Rule-set freshness for the management API.
    pub fn asset_snapshot(&self) -> serde_json::Value {
        let statuses = self
            .asset_status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let geodata = self.geodata.load();
        serde_json::json!({
            "geositeTags": geodata.geosite.len(),
            "geoipTags": geodata.geoip.len(),
            "files": statuses
                .iter()
                .map(|status| serde_json::json!({
                    "name": status.name,
                    "outcome": status.outcome,
                    "detail": status.detail,
                    "entries": status.entries,
                    "atUnixSeconds": status
                        .at
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .map(|since| since.as_secs())
                        .unwrap_or_default(),
                }))
                .collect::<Vec<_>>(),
        })
    }

    async fn run_observatory(self: Arc<Self>) {
        loop {
            let Some(config) = self.config().observatory.clone() else {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            };
            let target = match parse_probe_target(&config.probe_url) {
                Ok(target) => target,
                Err(error) => {
                    error!(%error, "observatory probe URL rejected");
                    tokio::time::sleep(config.probe_interval).await;
                    continue;
                }
            };
            let snapshot = self.config();
            for outbound in snapshot.outbounds.iter() {
                if !outbound.protocol.is_proxy()
                    && !matches!(outbound.protocol, OutboundProtocol::Freedom { .. })
                {
                    continue;
                }
                if !config.subject_selector.is_empty()
                    && !config
                        .subject_selector
                        .iter()
                        .any(|selector| outbound.tag.starts_with(selector.as_ref()))
                {
                    continue;
                }
                let tag = outbound.tag.clone();
                let result = timeout(
                    Duration::from_secs(15),
                    self.probe_outbound(outbound, &target),
                )
                .await
                .ok()
                .and_then(Result::ok);
                let mut health = self
                    .health
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match result {
                    Some(elapsed) => health.record_success(&tag, elapsed),
                    None => health.record_failure(&tag),
                }
            }
            if let Some(clean_ip) = config.clean_ip.as_ref() {
                let candidates = if clean_ip.candidates.is_empty() {
                    zero_net::clean_ip::cloudflare_candidates(
                        clean_ip.host.as_ref(),
                        &zero_net::clean_ip::CDN_TLS_PORTS,
                        1,
                        1,
                    )
                } else {
                    clean_ip
                        .candidates
                        .iter()
                        .copied()
                        .map(|address| {
                            zero_net::clean_ip::CleanIpCandidate::new(
                                address,
                                clean_ip.host.as_ref(),
                            )
                        })
                        .collect::<Vec<_>>()
                };
                let results = zero_net::clean_ip::probe_http(
                    &candidates,
                    &clean_ip.path,
                    Duration::from_secs(15),
                )
                .await;
                let mut stored = self
                    .clean_ip_results
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *stored = results;
            }
            tokio::time::sleep(config.probe_interval).await;
        }
    }

    async fn probe_outbound(
        &self,
        outbound: &zero_config::Outbound,
        target: &ProbeTarget,
    ) -> Result<Duration, String> {
        let started = std::time::Instant::now();
        let mut stream = match &outbound.protocol {
            OutboundProtocol::Freedom { .. } => outbound::connect_direct_with_resolver(
                &target.destination,
                &outbound.stream,
                &self.resolver(),
            )
            .await
            .map_err(|error| error.to_string())?,
            OutboundProtocol::Blackhole | OutboundProtocol::Dns => {
                return Err("outbound cannot be probed".into())
            }
            _ => outbound::connect_with_resolver(outbound, &target.destination, &self.resolver())
                .await
                .map_err(|error| error.to_string())?,
        };
        let host = target.destination.address.host_string();
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: zray-observatory/1\r\n\r\n",
            target.path
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        stream.flush().await.map_err(|error| error.to_string())?;
        let mut response = [0u8; 256];
        let n = stream
            .read(&mut response)
            .await
            .map_err(|error| error.to_string())?;
        if n == 0 {
            return Err("probe closed before a response".into());
        }
        let line = std::str::from_utf8(&response[..n]).unwrap_or_default();
        let status = line
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| "probe returned a malformed HTTP status".to_string())?;
        if !(200..=399).contains(&status) {
            return Err(format!("probe returned HTTP {status}"));
        }
        Ok(started.elapsed())
    }

    async fn finish_handshake(
        &self,
        stream: &mut zero_core::BoxStream,
        accepted: &Accepted,
        ok: bool,
    ) {
        match accepted.kind {
            InboundKind::Socks5 => {
                let code = if ok {
                    socks::REP_SUCCESS
                } else {
                    socks::REP_NOT_ALLOWED
                };
                let _ = socks::reply(stream, code, None).await;
            }
            InboundKind::HttpConnect => {
                let msg: &[u8] = if ok {
                    socks::CONNECT_OK
                } else {
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
                };
                let _ = stream.write_all(msg).await;
            }
            // Plain HTTP forwarding has no handshake to complete; a blocked
            // request still deserves an answer rather than a silent close.
            InboundKind::HttpForward => {
                if !ok {
                    let _ = stream
                        .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                        .await;
                }
            }
        }
    }
}

// ------------------------------------------------------------------ UDP relay

/// A datagram on its way back to the client side of a UDP ingress.
struct UdpReply<K> {
    key: K,
    /// Where the answer came from, as the client should see it.
    source: Destination,
    payload: Vec<u8>,
    /// The request's destination was a FakeDNS handle that was restored to a
    /// domain, so `source` is a real address the client never talked to.
    restored: bool,
}

/// One direct (Freedom) UDP flow: an outbound socket owned by one client flow
/// and address family, plus the task that carries its answers back.
struct NatFlow {
    socket: Arc<UdpSocket>,
    reader: tokio::task::JoinHandle<()>,
    /// Milliseconds since the relay's epoch at which the flow last carried a
    /// datagram in either direction.
    last_active: Arc<AtomicU64>,
    /// Targets this flow has already sent its configured noise to. Noise
    /// precedes the first datagram to a peer, not every datagram.
    noised: std::collections::HashSet<SocketAddr>,
    restored: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for NatFlow {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Idle limit for one direct UDP flow (Xray's UDP session default).
const UDP_FLOW_IDLE: Duration = Duration::from_secs(60);
/// Idle limit for a UDP session carried inside one client stream (Trojan,
/// VLESS, VMess): matches the TCP relay's idle policy.
const UDP_SESSION_IDLE: Duration = crate::relay::DEFAULT_IDLE_TIMEOUT;
/// Distinct targets remembered per flow for noise purposes.
const UDP_NOISE_TARGET_LIMIT: usize = 256;
/// Replies queued towards a client before the slowest reader applies
/// backpressure to the flows feeding it.
const UDP_REPLY_QUEUE: usize = 256;

/// Routing and forwarding for everything one UDP ingress receives.
///
/// Direct traffic goes through a long-lived socket per client flow, so a
/// request that produces several answers (QUIC, games, DNS over UDP
/// retransmits, STUN) gets all of them, and a datagram that produces none
/// (an ACK) costs nothing. Proxied traffic is an exchange per datagram,
/// concurrently and under a hard deadline, so no single unanswered datagram
/// can stall the ingress. Both are bounded: flows by `flow_limit`, exchanges
/// by [`UDP_INFLIGHT_LIMIT`]; beyond either, datagrams are dropped.
struct UdpRelay<K> {
    server: Arc<Server>,
    id: InboundId,
    tag: Arc<str>,
    replies: tokio::sync::mpsc::Sender<UdpReply<K>>,
    flows: HashMap<(K, bool), NatFlow>,
    flow_limit: usize,
    inflight: Arc<tokio::sync::Semaphore>,
    exchanges: tokio::task::JoinSet<()>,
    epoch: tokio::time::Instant,
    /// Bumped whenever anything moves, so a session can tell idle from busy.
    activity: Arc<AtomicU64>,
}

impl<K> UdpRelay<K>
where
    K: Copy + Eq + std::hash::Hash + Send + Sync + 'static,
{
    fn new(
        server: Arc<Server>,
        id: InboundId,
        tag: Arc<str>,
        flow_limit: usize,
    ) -> (Self, tokio::sync::mpsc::Receiver<UdpReply<K>>) {
        let (replies, receiver) = tokio::sync::mpsc::channel(UDP_REPLY_QUEUE);
        (
            Self {
                server,
                id,
                tag,
                replies,
                flows: HashMap::new(),
                flow_limit: flow_limit.max(1),
                inflight: Arc::new(tokio::sync::Semaphore::new(UDP_INFLIGHT_LIMIT)),
                exchanges: tokio::task::JoinSet::new(),
                epoch: tokio::time::Instant::now(),
                activity: Arc::new(AtomicU64::new(0)),
            },
            receiver,
        )
    }

    fn activity(&self) -> u64 {
        self.activity.load(Ordering::Relaxed)
    }

    /// Route one client datagram and send it on its way. Failures are
    /// per-datagram: they are counted and logged, never fatal to the session.
    async fn dispatch(
        &mut self,
        key: K,
        source: SocketAddr,
        destination: Destination,
        payload: Vec<u8>,
    ) {
        self.activity.fetch_add(1, Ordering::Relaxed);
        // Reap finished exchanges so the set does not grow with history.
        while self.exchanges.try_join_next().is_some() {}
        let server = Arc::clone(&self.server);
        let restored_destination = server.restore_fake_destination(&destination).await;
        let restored = restored_destination != destination;
        let destination = restored_destination;
        let ctx = SessionContext::new(
            server.generation(),
            self.id,
            self.tag.clone(),
            destination.clone(),
        )
        .with_source(source);
        let (resolver, outbound) = match server.route(&ctx).await {
            Decision::Block => {
                server.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Decision::DirectVia { resolver } => {
                (Arc::new(server.resolver().for_tag(&resolver)), None)
            }
            Decision::Outbound(tag) | Decision::Balancer(tag) => {
                let Some(outbound) = server.pick_outbound(&tag) else {
                    server.stats.failed.fetch_add(1, Ordering::Relaxed);
                    debug!(outbound = %tag, "no outbound for UDP route");
                    return;
                };
                if matches!(outbound.protocol, OutboundProtocol::Dns) {
                    self.spawn_dns_answer(key, destination, payload, restored);
                    return;
                }
                if !matches!(outbound.protocol, OutboundProtocol::Freedom { .. }) {
                    self.spawn_exchange(key, outbound, destination, payload, restored);
                    return;
                }
                (server.resolver(), Some(outbound))
            }
        };
        let noise = outbound
            .as_ref()
            .map(|outbound| outbound.stream.evasion.udp_noise.as_slice())
            .unwrap_or(&[]);
        let length = payload.len() as u64;
        match self
            .send_direct(key, &resolver, &destination, &payload, noise, restored)
            .await
        {
            Ok(()) => {
                server.stats.uploaded.fetch_add(length, Ordering::Relaxed);
            }
            Err(error) => {
                server.stats.failed.fetch_add(1, Ordering::Relaxed);
                debug!(%destination, %error, "direct UDP datagram failed");
            }
        }
    }

    /// Answer a DNS query routed to a `dns` outbound from the runtime's own
    /// resolver (`crate::dns_out`). Bounded by the same in-flight limit as
    /// proxied exchanges, so a flood of queries cannot spawn without limit.
    fn spawn_dns_answer(
        &mut self,
        key: K,
        destination: Destination,
        payload: Vec<u8>,
        restored: bool,
    ) {
        let Ok(permit) = Arc::clone(&self.inflight).try_acquire_owned() else {
            self.server.stats.failed.fetch_add(1, Ordering::Relaxed);
            debug!(%destination, "UDP exchange limit reached; dropping DNS query");
            return;
        };
        let server = Arc::clone(&self.server);
        let replies = self.replies.clone();
        let activity = Arc::clone(&self.activity);
        self.exchanges.spawn(async move {
            let _permit = permit;
            server
                .stats
                .uploaded
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
            let resolver = server.client_resolver();
            let Some(response) = crate::dns_out::answer(&resolver, &payload).await else {
                server.stats.failed.fetch_add(1, Ordering::Relaxed);
                debug!(%destination, "dropping a datagram that is not a DNS query");
                return;
            };
            activity.fetch_add(1, Ordering::Relaxed);
            let _ = replies
                .send(UdpReply {
                    key,
                    source: destination,
                    payload: response,
                    restored,
                })
                .await;
        });
    }

    fn spawn_exchange(
        &mut self,
        key: K,
        outbound: zero_config::Outbound,
        destination: Destination,
        payload: Vec<u8>,
        restored: bool,
    ) {
        let Ok(permit) = Arc::clone(&self.inflight).try_acquire_owned() else {
            self.server.stats.failed.fetch_add(1, Ordering::Relaxed);
            debug!(%destination, "UDP exchange limit reached; dropping datagram");
            return;
        };
        let server = Arc::clone(&self.server);
        let replies = self.replies.clone();
        let activity = Arc::clone(&self.activity);
        self.exchanges.spawn(async move {
            let _permit = permit;
            let datagram = socks::UdpDatagram {
                destination,
                payload,
            };
            match server.proxy_udp(&outbound, &datagram).await {
                Ok((source, response)) => {
                    server
                        .stats
                        .uploaded
                        .fetch_add(datagram.payload.len() as u64, Ordering::Relaxed);
                    activity.fetch_add(1, Ordering::Relaxed);
                    let _ = replies
                        .send(UdpReply {
                            key,
                            source,
                            payload: response,
                            restored,
                        })
                        .await;
                }
                Err(error) => {
                    server.stats.failed.fetch_add(1, Ordering::Relaxed);
                    debug!(destination = %datagram.destination, %error, "proxied UDP exchange failed");
                }
            }
        });
    }

    async fn send_direct(
        &mut self,
        key: K,
        resolver: &zero_dns::Resolver,
        destination: &Destination,
        payload: &[u8],
        noise: &[NoiseConfig],
        restored: bool,
    ) -> Result<(), String> {
        let target = match &destination.address {
            Address::Ip(ip) => SocketAddr::new(*ip, destination.port),
            Address::Domain(_) => {
                let addrs = resolver
                    .resolve_address(&destination.address, resolver.settings().query_strategy)
                    .await
                    .map_err(|error| error.to_string())?;
                let ip = addrs
                    .first()
                    .ok_or_else(|| "resolver returned no UDP destinations".to_string())?;
                SocketAddr::new(*ip, destination.port)
            }
        };
        let epoch = self.epoch;
        let flow = self.flow(key, target.is_ipv4()).await?;
        flow.restored.store(restored, Ordering::Relaxed);
        if !noise.is_empty() && !flow.noised.contains(&target) {
            if flow.noised.len() >= UDP_NOISE_TARGET_LIMIT {
                flow.noised.clear();
            }
            flow.noised.insert(target);
            // The first payload is sent after the decoys. This preserves the
            // configured wire order; sending the real datagram first would
            // make the noise visible only to a receiver that already knows
            // the flow.
            for (packet, delay) in noise_policy(noise).plan() {
                if !packet.is_empty() {
                    flow.socket
                        .send_to(&packet, target)
                        .await
                        .map_err(|error| format!("sending UDP noise: {error}"))?;
                }
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }
        flow.socket
            .send_to(payload, target)
            .await
            .map_err(|error| format!("sending UDP payload: {error}"))?;
        flow.last_active
            .store(millis_since(epoch), Ordering::Relaxed);
        Ok(())
    }

    /// The live flow for `key` and address family, opening one if needed.
    async fn flow(&mut self, key: K, ipv4: bool) -> Result<&mut NatFlow, String> {
        let slot = (key, ipv4);
        if self
            .flows
            .get(&slot)
            .is_some_and(|flow| flow.reader.is_finished())
        {
            self.flows.remove(&slot);
        }
        if !self.flows.contains_key(&slot) {
            if self.flows.len() >= self.flow_limit {
                self.flows.retain(|_, flow| !flow.reader.is_finished());
                if self.flows.len() >= self.flow_limit {
                    return Err("UDP flow table is full".into());
                }
            }
            let socket = Arc::new(
                bind_outbound_udp(ipv4)
                    .await
                    .map_err(|error| format!("binding direct UDP socket: {error}"))?,
            );
            let last_active = Arc::new(AtomicU64::new(millis_since(self.epoch)));
            let restored = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reader = tokio::spawn(read_nat_flow(
                key,
                Arc::clone(&socket),
                self.replies.clone(),
                self.epoch,
                Arc::clone(&last_active),
                Arc::clone(&self.activity),
                Arc::clone(&restored),
            ));
            self.flows.insert(
                slot,
                NatFlow {
                    socket,
                    reader,
                    last_active,
                    noised: std::collections::HashSet::new(),
                    restored,
                },
            );
        }
        self.flows
            .get_mut(&slot)
            .ok_or_else(|| "UDP flow vanished while opening".to_string())
    }
}

fn millis_since(epoch: tokio::time::Instant) -> u64 {
    epoch.elapsed().as_millis().min(u64::MAX as u128) as u64
}

/// Carry a direct flow's answers back until it has been idle for
/// [`UDP_FLOW_IDLE`] or the session stops listening.
async fn read_nat_flow<K: Copy + Send + 'static>(
    key: K,
    socket: Arc<UdpSocket>,
    replies: tokio::sync::mpsc::Sender<UdpReply<K>>,
    epoch: tokio::time::Instant,
    last_active: Arc<AtomicU64>,
    activity: Arc<AtomicU64>,
    restored: Arc<std::sync::atomic::AtomicBool>,
) {
    loop {
        match timeout(UDP_FLOW_IDLE, socket.readable()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                debug!(%error, "direct UDP flow closed");
                return;
            }
            Err(_) => {
                let idle = millis_since(epoch).saturating_sub(last_active.load(Ordering::Relaxed));
                if idle >= UDP_FLOW_IDLE.as_millis() as u64 {
                    return;
                }
                continue;
            }
        }
        // Receive into a per-thread scratch buffer and copy out exactly the
        // datagram: the answer has to be an owned buffer anyway, and a
        // 64 KiB buffer per idle flow would dwarf everything else it holds.
        let received = UDP_SCRATCH.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            socket
                .try_recv_from(&mut scratch[..])
                .map(|(length, from)| (scratch[..length].to_vec(), from))
        });
        let (payload, from) = match received {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            // An ICMP unreachable for an earlier datagram surfaces here on some
            // platforms; it concerns one peer, not the flow.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                continue
            }
            Err(error) => {
                debug!(%error, "direct UDP flow receive failed");
                return;
            }
        };
        last_active.store(millis_since(epoch), Ordering::Relaxed);
        activity.fetch_add(1, Ordering::Relaxed);
        let reply = UdpReply {
            key,
            source: Destination::udp(Address::Ip(from.ip()), from.port()),
            payload,
            restored: restored.load(Ordering::Relaxed),
        };
        if replies.send(reply).await.is_err() {
            return;
        }
    }
}

thread_local! {
    static UDP_SCRATCH: std::cell::RefCell<Box<[u8]>> =
        std::cell::RefCell::new(vec![0u8; 65_535].into_boxed_slice());
}

/// Write replies to a stream-carried UDP session, flushing once per burst
/// rather than once per datagram.
async fn write_udp_replies<W, K, F>(
    mut writer: W,
    mut replies: tokio::sync::mpsc::Receiver<UdpReply<K>>,
    stats: Arc<Stats>,
    encode: F,
) where
    W: tokio::io::AsyncWrite + Unpin,
    F: Fn(&UdpReply<K>) -> Result<Vec<u8>, String>,
{
    while let Some(first) = replies.recv().await {
        let mut next = Some(first);
        while let Some(reply) = next.take() {
            match encode(&reply) {
                Ok(frame) => {
                    if let Err(error) = writer.write_all(&frame).await {
                        debug!(%error, "writing UDP reply to the client failed");
                        return;
                    }
                    stats
                        .downloaded
                        .fetch_add(reply.payload.len() as u64, Ordering::Relaxed);
                    stats.succeeded.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => debug!(%error, "UDP reply cannot be framed; dropped"),
            }
            next = replies.try_recv().ok();
        }
        if let Err(error) = writer.flush().await {
            debug!(%error, "flushing UDP replies to the client failed");
            return;
        }
    }
}

fn replace_outbound_endpoint(outbound: &mut zero_config::Outbound, address: Address, port: u16) {
    match &mut outbound.protocol {
        OutboundProtocol::Vless(config) => {
            config.address = address;
            config.port = port;
        }
        OutboundProtocol::Trojan(config) => {
            config.address = address;
            config.port = port;
        }
        OutboundProtocol::Shadowsocks(config) => {
            config.address = address;
            config.port = port;
        }
        OutboundProtocol::Vmess(config) => {
            config.address = address;
            config.port = port;
        }
        OutboundProtocol::AnyTls(config) => {
            config.address = address;
            config.port = port;
        }
        OutboundProtocol::Hysteria2(config) => {
            config.address = address;
            config.port = port;
        }
        OutboundProtocol::Tuic(config) => {
            config.address = address;
            config.port = port;
        }
        // AmneziaWG is a UDP peer configuration. Clean-IP substitution is a
        // CDN/TCP optimization and must not rewrite its authenticated peer
        // endpoint behind the caller's back.
        OutboundProtocol::AmneziaWireguard(_)
        | OutboundProtocol::Freedom { .. }
        | OutboundProtocol::Blackhole
        | OutboundProtocol::Dns => {}
    }
}

fn preserve_stream_host(stream: &mut zero_config::StreamSettings, host: &str) {
    if let zero_config::Security::Tls(tls) = &mut stream.security {
        if tls.server_name.is_none() {
            tls.server_name = Some(Arc::from(host));
        }
    }
    match &mut stream.transport {
        zero_config::Transport::Raw => {}
        zero_config::Transport::WebSocket(config)
        | zero_config::Transport::HttpUpgrade(config)
        | zero_config::Transport::Grpc(config)
        | zero_config::Transport::Xhttp(config) => {
            if config.host.is_none() {
                config.host = Some(Arc::from(host));
            }
        }
    }
}

fn choose_balancer_index(
    strategy: zero_config::routing::BalancerStrategy,
    ticket: u64,
    member_count: usize,
) -> usize {
    debug_assert!(member_count > 0);
    match strategy {
        zero_config::routing::BalancerStrategy::RoundRobin
        | zero_config::routing::BalancerStrategy::LeastPing
        | zero_config::routing::BalancerStrategy::LeastLoad => {
            // Least-* is deliberately fair until the observatory has a
            // per-outbound sample. Choosing the first member here would
            // silently turn a health-aware config into a single-server
            // config; rotation is the safe neutral prior.
            ticket as usize % member_count
        }
        zero_config::routing::BalancerStrategy::Random => {
            // SplitMix64 gives a cheap, deterministic and unbiased sequence
            // without pulling a lock or OS randomness into every selection.
            let mut value = ticket.wrapping_add(0x9E37_79B9_7F4A_7C15);
            value ^= value >> 30;
            value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
            value ^= value >> 27;
            value = value.wrapping_mul(0x94D0_49BB_1331_11EB);
            value ^= value >> 31;
            value as usize % member_count
        }
    }
}

struct ProbeTarget {
    destination: Destination,
    path: String,
}

fn parse_probe_target(value: &str) -> Result<ProbeTarget, String> {
    let url = url::Url::parse(value).map_err(|error| error.to_string())?;
    let host = url
        .host_str()
        .ok_or_else(|| "probe URL has no host".to_string())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "probe URL has no known port".to_string())?;
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    Ok(ProbeTarget {
        destination: Destination::tcp(Address::parse_host(host), port),
        path,
    })
}

fn noise_policy(configs: &[NoiseConfig]) -> zero_evasion::NoisePolicy {
    let entries = configs
        .iter()
        .map(|config| {
            let packet = match &config.kind {
                NoiseKind::Rand { length, byte_range } => zero_evasion::NoisePacket::Rand {
                    length_min: length.min as i64,
                    length_max: length.max as i64,
                    byte_min: byte_range.0,
                    byte_max: byte_range.1,
                },
                NoiseKind::Str(value) => {
                    zero_evasion::NoisePacket::Fixed(value.as_bytes().to_vec())
                }
                NoiseKind::Hex(value) | NoiseKind::Base64(value) | NoiseKind::Array(value) => {
                    zero_evasion::NoisePacket::Fixed(value.clone())
                }
                NoiseKind::Quic { length } => zero_evasion::NoisePacket::Quic {
                    length_min: length.min as i64,
                    length_max: length.max as i64,
                },
            };
            zero_evasion::NoiseEntry {
                packet,
                delay_min_ms: config.delay.min.as_millis() as i64,
                delay_max_ms: config.delay.max.as_millis() as i64,
                count: config.count,
            }
        })
        .collect();
    zero_evasion::NoisePolicy { entries }
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

async fn read_vless_request<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(zero_protocol::vless::Request, usize, Vec<u8>), String> {
    let mut buffered = Vec::with_capacity(256);
    let mut scratch = [0u8; 2048];
    loop {
        let n = stream
            .read(&mut scratch)
            .await
            .map_err(|error| format!("reading VLESS request: {error}"))?;
        if n == 0 {
            return Err("VLESS client closed before the request header".into());
        }
        buffered.extend_from_slice(&scratch[..n]);
        match zero_protocol::vless::parse_request(&buffered)? {
            zero_protocol::vless::RequestParse::Incomplete => {
                if buffered.len() > 8192 {
                    return Err("VLESS request header exceeds the limit".into());
                }
            }
            zero_protocol::vless::RequestParse::Complete { request, consumed } => {
                return Ok((request, consumed, buffered));
            }
        }
    }
}

async fn read_trojan_request<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(zero_protocol::trojan::Request, usize, Vec<u8>), String> {
    let mut buffered = Vec::with_capacity(256);
    let mut scratch = [0u8; 2048];
    loop {
        let n = stream
            .read(&mut scratch)
            .await
            .map_err(|error| format!("reading Trojan request: {error}"))?;
        if n == 0 {
            return Err("Trojan client closed before the request header".into());
        }
        buffered.extend_from_slice(&scratch[..n]);
        match zero_protocol::trojan::parse_request(&buffered)? {
            zero_protocol::trojan::RequestParse::Incomplete => {
                if buffered.len() > 8192 {
                    return Err("Trojan request header exceeds the limit".into());
                }
            }
            zero_protocol::trojan::RequestParse::Complete { request, consumed } => {
                return Ok((request, consumed, buffered));
            }
        }
    }
}

async fn read_vless_udp_frame<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    pending: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, String> {
    let mut scratch = [0u8; 8192];
    loop {
        if pending.len() >= 2 {
            let length = u16::from_be_bytes([pending[0], pending[1]]) as usize;
            if length == 0 {
                return Err("empty VLESS UDP frame".into());
            }
            if length > 65_535 {
                return Err("VLESS UDP frame exceeds the limit".into());
            }
            if pending.len() >= length + 2 {
                let payload = pending[2..length + 2].to_vec();
                pending.drain(..length + 2);
                return Ok(Some(payload));
            }
        }
        let n = stream
            .read(&mut scratch)
            .await
            .map_err(|error| format!("reading VLESS UDP frame: {error}"))?;
        if n == 0 {
            if pending.is_empty() {
                return Ok(None);
            }
            return Err("VLESS UDP stream ended in a partial frame".into());
        }
        pending.extend_from_slice(&scratch[..n]);
        // An incomplete frame is at most 65,536 bytes; the read that completes
        // it may legitimately carry the start of the next one as well.
        if pending.len() > 65_537 + scratch.len() {
            return Err("VLESS UDP pending frame exceeds the limit".into());
        }
    }
}

/// Read the next Trojan UDP packet, keeping partial frames in `pending`.
/// `Ok(None)` is a clean end of stream between packets. Every mutation of
/// `pending` happens right after a completed read, so dropping this future
/// between reads (an idle timeout) loses nothing.
async fn read_trojan_udp_packet<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    pending: &mut Vec<u8>,
    scratch: &mut [u8],
) -> Result<Option<(Destination, Vec<u8>)>, String> {
    loop {
        match zero_protocol::trojan::parse_udp_packet(pending)? {
            zero_protocol::trojan::UdpPacketParse::Complete {
                destination,
                payload,
                consumed,
            } => {
                pending.drain(..consumed);
                return Ok(Some((destination, payload)));
            }
            zero_protocol::trojan::UdpPacketParse::Incomplete => {
                let n = stream
                    .read(scratch)
                    .await
                    .map_err(|error| format!("reading Trojan UDP frame: {error}"))?;
                if n == 0 {
                    if pending.is_empty() {
                        return Ok(None);
                    }
                    return Err("Trojan UDP stream ended in a partial frame".into());
                }
                pending.extend_from_slice(&scratch[..n]);
                // One maximal frame (a 255-byte domain and a 65,535-byte
                // payload) plus whatever of the next frame the same read
                // brought along.
                if pending.len() > 65_800 + scratch.len() {
                    return Err("Trojan UDP pending frame exceeds the limit".into());
                }
            }
        }
    }
}

/// A reader that replays already-consumed bytes before the live stream.
struct ChainedStream {
    prefix: Vec<u8>,
    offset: usize,
    inner: zero_core::BoxStream,
}

impl ChainedStream {
    fn new(prefix: Vec<u8>, inner: zero_core::BoxStream) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl tokio::io::AsyncRead for ChainedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let n = (self.prefix.len() - self.offset).min(buf.remaining());
            let start = self.offset;
            buf.put_slice(&self.prefix[start..start + n]);
            self.offset += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ChainedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Build the cache handle described by configuration.
pub fn asset_store_for(assets: &zero_config::AssetsConfig) -> zero_router::AssetStore {
    asset_store(assets)
}

/// Translate configured asset files into store specs.
pub fn asset_specs_for(assets: &zero_config::AssetsConfig) -> Vec<zero_router::AssetSpec> {
    asset_specs(assets)
}

fn asset_store(assets: &zero_config::AssetsConfig) -> zero_router::AssetStore {
    let dir = assets
        .directory
        .as_deref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(zero_router::AssetStore::default_dir);
    zero_router::AssetStore::new(
        dir,
        zero_router::AssetPolicy {
            refresh_interval: assets.refresh_interval,
            retry_interval: assets.retry_interval,
            limits: zero_net::fetch::FetchLimits {
                max_bytes: assets.max_bytes,
                timeout: assets.timeout,
                max_redirects: 5,
            },
        },
    )
}

/// Translate configured asset files into store specs. A malformed sha256 pin
/// was already rejected at parse time, so a failure here can only mean the
/// configuration was built programmatically; such an entry is dropped rather
/// than silently downgraded to an unpinned download.
fn asset_specs(assets: &zero_config::AssetsConfig) -> Vec<zero_router::AssetSpec> {
    assets
        .files
        .iter()
        .filter_map(|file| {
            let kind = match file.kind {
                zero_config::AssetFileKind::Geosite => zero_router::AssetKind::Geosite,
                zero_config::AssetFileKind::Geoip => zero_router::AssetKind::Geoip,
            };
            let spec = zero_router::AssetSpec::new(
                file.name.to_string(),
                kind,
                file.urls.iter().map(|url| url.to_string()).collect(),
            );
            match file.sha256.as_deref() {
                None => Some(spec),
                Some(pin) => match zero_router::assets::parse_sha256(pin) {
                    Ok(digest) => Some(spec.with_sha256(digest)),
                    Err(error) => {
                        warn!(asset = %file.name, %error, "dropping rule set with an invalid sha256 pin");
                        None
                    }
                },
            }
        })
        .collect()
}

/// Bind a UDP socket for traffic leaving the machine, protected first.
///
/// Only *outbound* sockets take this path. The SOCKS5 UDP association is
/// deliberately not protected: it listens for datagrams from applications on
/// this device, and exempting it from the tunnel would move it off the
/// interface those applications reach it on.
async fn bind_outbound_udp(ipv4: bool) -> Result<UdpSocket, String> {
    let bind: SocketAddr = if ipv4 {
        "0.0.0.0:0".parse().expect("a literal bind address")
    } else {
        "[::]:0".parse().expect("a literal bind address")
    };
    let socket =
        zero_core::platform::bind_protected_udp(bind).map_err(|error| error.to_string())?;
    socket
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    UdpSocket::from_std(socket).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::choose_balancer_index;
    use super::{preserve_stream_host, replace_outbound_endpoint};
    use super::{Server, ServerConfig};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use zero_config::routing::BalancerStrategy;

    /// A minimal server whose only job is to exercise the planner's
    /// materialisation of a rung onto an outbound.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_never_finishes_its_handshake_is_dropped() {
        // A slow-loris: connected, one byte of a SOCKS greeting, then nothing.
        let server = planner_test_server();
        let (client, mut peer) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut peer, &[0x05])
            .await
            .unwrap();
        let session = super::InboundSession {
            state: server.state.load_full(),
        };
        let started = tokio::time::Instant::now();
        let result = Arc::clone(&server)
            .handle(
                zero_core::boxed(client),
                "127.0.0.1:40000".parse().unwrap(),
                zero_core::InboundId(0),
                session,
            )
            .await;
        let error = result.expect_err("a stalled handshake must fail");
        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() >= super::HANDSHAKE_TIMEOUT);
        drop(peer);
    }

    #[test]
    fn inbound_material_is_compiled_once_per_generation() {
        let server = planner_test_server();
        let state = server.state.load_full();
        assert_eq!(state.inbounds.len(), state.config.inbounds.len());
        // A plain SOCKS inbound needs neither TLS nor a transport config.
        assert!(state.inbounds[0].tls.is_none());
        assert!(state.inbounds[0].transport.is_none());
    }

    fn planner_test_server() -> Arc<Server> {
        let config = serde_json::json!({
            "inbounds": [{
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": 1080,
                "protocol": "socks",
            }],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "edge.example",
                    "port": 443,
                    "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                               "encryption": "none"}],
                }]},
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {"path": "/tunnel"},
                    "security": "tls",
                },
            }],
        });
        let (generation, _) =
            zero_config::compile_config(&config, zero_core::GenerationId(1)).expect("config");
        Arc::new(Server::new(ServerConfig {
            config: Arc::clone(&generation.config),
            generation: generation.id,
        }))
    }

    /// FakeDNS answers the applications, never the runtime itself, and a
    /// reload — which is also how a network change resets DNS — keeps every
    /// synthetic address an application already holds.
    #[tokio::test]
    async fn fake_addresses_survive_a_reload_and_never_reach_the_dialer() {
        let config = serde_json::json!({
            "inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "dns": {
                "servers": [
                    "fakedns",
                    {"address": "127.0.0.1", "port": 9, "tag": "real"},
                ],
                "hosts": {"pinned.example": "203.0.113.7"},
            },
        });
        let (generation, _) =
            zero_config::compile_config(&config, zero_core::GenerationId(1)).expect("config");
        let server = Server::new(ServerConfig {
            config: Arc::clone(&generation.config),
            generation: generation.id,
        });
        let strategy = zero_config::dns::QueryStrategy::UseIpv4;
        let fake = server
            .client_resolver()
            .lookup("app.example", strategy)
            .await
            .expect("fake answer");
        assert!(matches!(fake[0], std::net::IpAddr::V4(v4) if v4.octets()[..2] == [198, 18]));
        // The runtime's own view has no FakeDNS: hosts still answer, and a
        // name nobody pins goes to the (unreachable) real resolver, never to
        // a synthetic address.
        assert!(!server.resolver().has_fake());
        assert_eq!(
            server.resolver().lookup("pinned.example", strategy).await.unwrap(),
            vec!["203.0.113.7".parse::<std::net::IpAddr>().unwrap()]
        );

        let restored = server
            .restore_fake_destination(&zero_core::Destination::tcp(
                zero_core::Address::Ip(fake[0]),
                443,
            ))
            .await;
        assert_eq!(restored.address, zero_core::Address::domain("app.example"));

        server
            .reload(Arc::clone(&generation.config), zero_core::GenerationId(2))
            .expect("reload");
        let after = server
            .restore_fake_destination(&zero_core::Destination::tcp(
                zero_core::Address::Ip(fake[0]),
                443,
            ))
            .await;
        assert_eq!(after.address, zero_core::Address::domain("app.example"), "the mapping was lost on reload");
        assert!(!server.resolver().has_fake());
    }

    fn sample_outbound(server: &Server) -> zero_config::Outbound {
        server.config().outbounds[0].clone()
    }

    #[test]
    fn round_robin_and_health_fallbacks_visit_every_member() {
        for strategy in [
            BalancerStrategy::RoundRobin,
            BalancerStrategy::LeastPing,
            BalancerStrategy::LeastLoad,
        ] {
            let chosen: Vec<_> = (0..6)
                .map(|ticket| choose_balancer_index(strategy, ticket, 3))
                .collect();
            assert_eq!(chosen, [0, 1, 2, 0, 1, 2]);
        }
    }

    #[test]
    fn random_selection_is_not_pinned_to_the_first_member() {
        let chosen: Vec<_> = (0..32)
            .map(|ticket| choose_balancer_index(BalancerStrategy::Random, ticket, 4))
            .collect();
        assert!(chosen.iter().any(|index| *index != 0));
        assert!(chosen.iter().all(|index| *index < 4));
    }

    #[test]
    fn clean_ip_rewrite_keeps_the_fronted_tls_name() {
        let mut outbound = zero_config::Outbound {
            tag: "cdn".into(),
            protocol: zero_config::OutboundProtocol::Vless(zero_config::VlessConfig {
                address: zero_core::Address::domain("edge.example"),
                port: 443,
                uuid: [0; 16],
                flow: zero_config::Flow::None,
                encryption: "none".into(),
            }),
            stream: zero_config::StreamSettings {
                transport: zero_config::Transport::WebSocket(
                    zero_config::WebSocketConfig::default(),
                ),
                security: zero_config::Security::Tls(zero_config::TlsConfig::default()),
                ..zero_config::StreamSettings::default()
            },
            mux: zero_config::MuxConfig::default(),
        };
        replace_outbound_endpoint(
            &mut outbound,
            zero_core::Address::Ip("203.0.113.7".parse().unwrap()),
            2053,
        );
        preserve_stream_host(&mut outbound.stream, "edge.example");
        assert_eq!(outbound.endpoint().unwrap().1, 2053);
        assert_eq!(outbound.endpoint().unwrap().0.host_string(), "203.0.113.7");
        let zero_config::Security::Tls(tls) = outbound.stream.security else {
            panic!("expected TLS");
        };
        assert_eq!(tls.server_name.as_deref(), Some("edge.example"));
        let zero_config::Transport::WebSocket(ws) = outbound.stream.transport else {
            panic!("expected WebSocket");
        };
        assert_eq!(ws.host.as_deref(), Some("edge.example"));
    }

    #[test]
    fn the_keepalive_rung_puts_a_usable_shape_on_the_outbound() {
        // Deciding to shape and actually shaping are different things: the
        // rung has to arrive on the outbound as concrete numbers, or the
        // planner has climbed to a strategy that does nothing.
        let server = planner_test_server();
        let mut outbound = sample_outbound(&server);
        assert!(outbound.stream.evasion.keepalive.is_none());

        server.apply_strategy_to(
            &mut outbound,
            zero_observatory::PathStrategy::KeepaliveShaping,
        );
        let shape = outbound
            .stream
            .evasion
            .keepalive
            .expect("the keepalive rung must configure keepalive shaping");
        assert!(!shape.idle_after.is_zero());
        assert!(shape
            .max_flow_lifetime
            .is_some_and(|limit| limit > shape.idle_after));
    }

    #[test]
    fn the_keepalive_shape_is_sized_from_the_measured_reset_not_a_guess() {
        let server = planner_test_server();
        // 200s is what the planner measured; the default prior is 120s, so a
        // shape that ignored the measurement would be visibly wrong here.
        server
            .planner_flow_lifetime_ms
            .store(200_000, Ordering::Relaxed);

        let mut outbound = sample_outbound(&server);
        server.apply_strategy_to(
            &mut outbound,
            zero_observatory::PathStrategy::KeepaliveShaping,
        );
        let shape = outbound.stream.evasion.keepalive.expect("shaping applied");
        let lifetime = shape
            .max_flow_lifetime
            .expect("a measured reset sets a lifetime");
        assert!(
            lifetime < std::time::Duration::from_secs(200),
            "retiring at {lifetime:?} would still reach the observed deadline"
        );
        assert_ne!(
            shape,
            zero_config::KeepaliveConfig::default(),
            "the shape is the default prior, so the measurement was ignored"
        );
    }

    #[test]
    fn a_rung_below_keepalive_leaves_the_outbound_unshaped() {
        // The rungs are ordered by cost; applying an expensive one before the
        // evidence asks for it is exactly what the ladder exists to prevent.
        let server = planner_test_server();
        let mut outbound = sample_outbound(&server);
        server.apply_strategy_to(&mut outbound, zero_observatory::PathStrategy::DirectReality);
        assert!(outbound.stream.evasion.keepalive.is_none());
        assert!(outbound.stream.evasion.tcp_fragment.is_none());
    }

    #[test]
    fn an_operator_configured_keepalive_shape_is_not_overwritten_by_the_rung() {
        let server = planner_test_server();
        let mut outbound = sample_outbound(&server);
        let chosen = zero_config::KeepaliveConfig {
            idle_after: std::time::Duration::from_secs(7),
            max_flow_lifetime: Some(std::time::Duration::from_secs(70)),
        };
        outbound.stream.evasion.keepalive = Some(chosen);
        server.apply_strategy_to(
            &mut outbound,
            zero_observatory::PathStrategy::KeepaliveShaping,
        );
        assert_eq!(outbound.stream.evasion.keepalive, Some(chosen));
    }

    #[test]
    fn fingerprint_rotation_never_selects_a_profile_reality_cannot_use() {
        // Rotating a REALITY outbound into a shape with no X25519 key share
        // turns a working connection into a silent fallback to the decoy site,
        // which is indistinguishable from success at the socket layer.
        let server = planner_test_server();
        let mut outbound = sample_outbound(&server);
        outbound.stream.transport = zero_config::Transport::Raw;
        outbound.stream.security = zero_config::Security::Reality(zero_config::RealityConfig {
            server_name: "www.googletagmanager.com".into(),
            public_key: [7u8; 32],
            short_id: vec![1, 2, 3, 4],
            fingerprint: zero_config::Fingerprint::Chrome,
            spider_x: None,
            mldsa65_verify: None,
        });

        for _ in 0..24 {
            server.apply_strategy_to(
                &mut outbound,
                zero_observatory::PathStrategy::FingerprintRotation,
            );
            let zero_config::Security::Reality(reality) = &outbound.stream.security else {
                panic!("expected REALITY");
            };
            assert!(
                reality.fingerprint.supports_reality(),
                "rotation selected {:?}, which carries no X25519 key share",
                reality.fingerprint
            );
        }
    }
}
