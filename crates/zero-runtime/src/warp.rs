//! Choosing how a WARP outbound reaches Cloudflare.
//!
//! One account can be reached three ways — WireGuard, and MASQUE over HTTP/2
//! or over HTTP/3 (`zero_transport::masque`) — and which one works depends on
//! the network and can change from one day to the next: QUIC to foreign hosts
//! is dropped on some networks, WireGuard is filtered on some days, and HTTP/2
//! under an ordinary-looking SNI is the one most likely to get through. So a
//! `route = auto` outbound does not follow a fixed order; it measures.
//!
//! * **Race.** The candidate routes are started a moment apart, in order of
//!   preference, and each must fetch a small page through its own tunnel. The
//!   first to do so wins and the rest are stopped. A blocked route costs the
//!   others nothing, and a route that connects but carries nothing never
//!   wins.
//! * **Preference.** UDP first (WireGuard, then HTTP/3), HTTP/2 last: it is
//!   TCP inside TCP and the slowest under loss, but the one most likely to get
//!   through. The route that worked before starts first.
//! * **Promotion.** While on a less preferred route, the more preferred ones
//!   are tried again in the background every ten minutes; if one works,
//!   new connections move to it and the old tunnel drains. The interval is the
//!   guard against flapping: a network that lets a handshake through and then
//!   throttles is found out by the next rule, not tried every minute.
//! * **Feedback.** Connections through the tunnel report back. Several
//!   timeouts in a row with no success in between mean the route is dead even
//!   though its tunnel is up; it is dropped and not chosen again for a while
//!   ([`PENALTY`]).
//!
//! A network change forgets all of it: what worked on Wi-Fi says little about
//! mobile data.

mod report;

#[cfg(feature = "test-util")]
pub use report::stage as stage_race;
use report::RaceLog;
pub use report::{last_race, Fail, Lane, LaneState, RaceReport};

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use std::time::{Duration, Instant};

use zero_config::{AmneziaWireguardConfig, HybridMode, MasqueConfig, WarpRoute};
use zero_protocol::wg_stack::{self, PacketLink, WgStack, WgStackParams};
use zero_transport::masque::{self, Endpoint, MasqueKey, Spec};

/// How long a candidate gets to answer a DNS query through its tunnel.
const PROBE_TIMEOUT: Duration = Duration::from_secs(6);
/// The page fetched to prove a tunnel carries traffic: Google's connectivity
/// check, which answers 204 to anyone and is not on Cloudflare's network.
const PROBE_HOST: &str = "www.gstatic.com";
const PROBE_PATH: &str = "/generate_204";
/// What the unit tests resolve, since their stand-in edge answers only DNS.
#[cfg(test)]
const PROBE_NAME: &str = "cloudflare.com";
/// The gap between starting one candidate and the next.
const RACE_STAGGER: Duration = Duration::from_millis(200);
/// How often a more preferred route is tried again while a less preferred one
/// carries the traffic, in milliseconds (a static so a test can shorten it).
static PROMOTE_EVERY_MS: AtomicU64 = AtomicU64::new(10 * 60 * 1000);

fn promote_every() -> Duration {
    Duration::from_millis(PROMOTE_EVERY_MS.load(Ordering::Relaxed))
}
/// Timeouts in a row, with no success between, that condemn the route.
const FAULTS_TO_DROP: u32 = 3;
/// How long a condemned route is left out of a selection.
const PENALTY: Duration = Duration::from_secs(15 * 60);
/// A tunnel that ends this soon after its last success was killed, not idle.
const DIED_UNDER_USE: Duration = Duration::from_secs(60);

fn rank(route: WarpRoute) -> u8 {
    match route {
        WarpRoute::WireGuard | WarpRoute::Auto => 0,
        WarpRoute::MasqueHttp3 => 1,
        WarpRoute::MasqueHttp2 => 2,
    }
}

/// What the connections through a tunnel have been seeing.
#[derive(Default)]
struct Health {
    faults: AtomicU32,
    /// Milliseconds since [`EPOCH`] of the last success.
    last_ok: AtomicU64,
    /// Set by a condemning fault count; the next selection acts on it.
    condemned: AtomicBool,
}

impl Health {
    fn record<T>(&self, result: &Result<T, String>) {
        match result {
            Ok(_) => {
                self.faults.store(0, Ordering::Relaxed);
                self.last_ok.store(now_ms(), Ordering::Relaxed);
            }
            Err(error) if is_fault(error) => {
                if self.faults.fetch_add(1, Ordering::Relaxed) + 1 >= FAULTS_TO_DROP {
                    self.condemned.store(true, Ordering::Relaxed);
                }
            }
            Err(_) => {}
        }
    }
}

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

fn now_ms() -> u64 {
    EPOCH.elapsed().as_millis() as u64
}

struct Current {
    route: WarpRoute,
    stack: WgStack,
}

#[derive(Default)]
struct Slot {
    current: Option<Current>,
    /// The route that last won.
    good: Option<WarpRoute>,
    /// Routes left out of a selection until the moment given.
    penalties: HashMap<WarpRoute, Instant>,
    /// The last time promotion was considered.
    promoted_at: Option<Instant>,
    /// Edge addresses found by [`scan_endpoints`] when the configured ones
    /// stopped answering, tried after them from then on.
    found_h2: Vec<SocketAddr>,
}

#[derive(Default)]
struct Entry {
    slot: tokio::sync::Mutex<Slot>,
    health: Health,
}

static ENTRIES: LazyLock<StdMutex<HashMap<u64, Arc<Entry>>>> = LazyLock::new(Default::default);

fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A tunnel that reports how the connections through it went.
pub struct Tunnel {
    stack: WgStack,
    route: WarpRoute,
    entry: Arc<Entry>,
    /// Reached through one of the outbound's servers (the `hybrid` order).
    carried: bool,
}

impl Deref for Tunnel {
    type Target = WgStack;

    fn deref(&self) -> &WgStack {
        &self.stack
    }
}

/// Whether an error says the tunnel itself is not carrying traffic, as
/// opposed to a destination that refused or does not exist.
fn is_fault(error: &str) -> bool {
    error.contains("timed out") || error.contains("tunnel is closed")
}

impl Tunnel {
    /// The route this tunnel runs over (never `Auto`).
    pub fn route(&self) -> WarpRoute {
        self.route
    }

    /// Whether the tunnel is reached through one of the outbound's servers
    /// (the `hybrid` order) rather than dialled directly.
    pub fn carried(&self) -> bool {
        self.carried
    }

    /// Feed the outcome of a connection or exchange back to route selection.
    pub fn report<T>(&self, result: &Result<T, String>) {
        self.entry.health.record(result);
    }
}

/// The routes an outbound could use at all.
fn available(config: &AmneziaWireguardConfig) -> Vec<WarpRoute> {
    let mut routes = Vec::new();
    if config.wireguard_usable() {
        routes.push(WarpRoute::WireGuard);
    }
    let masque = config.masque.as_ref();
    if masque.is_some_and(|masque| !masque.http3_endpoints.is_empty()) {
        routes.push(WarpRoute::MasqueHttp3);
    }
    if masque.is_some_and(|masque| !masque.http2_endpoints.is_empty()) {
        routes.push(WarpRoute::MasqueHttp2);
    }
    routes
}

/// The candidates for a selection, in the order to start them: the route that
/// worked before, then by preference, leaving out the ones under penalty
/// (unless that leaves nothing).
fn candidates(
    config: &AmneziaWireguardConfig,
    good: Option<WarpRoute>,
    penalties: &HashMap<WarpRoute, Instant>,
    now: Instant,
) -> Vec<WarpRoute> {
    if config.route != WarpRoute::Auto {
        return vec![config.route];
    }
    let all = available(config);
    let mut routes: Vec<WarpRoute> = all
        .iter()
        .copied()
        .filter(|route| penalties.get(route).is_none_or(|until| *until <= now))
        .collect();
    if routes.is_empty() {
        routes = all;
    }
    routes.sort_by_key(|route| (Some(*route) != good, rank(*route)));
    routes
}

/// Two outbounds with the same account, endpoints and WireGuard peer share a
/// tunnel. A carried tunnel is a different one from the same account dialled
/// directly, and depends on the servers that carry it, so those go in too.
fn identity(config: &AmneziaWireguardConfig, peer: Option<SocketAddr>, carried: bool) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    peer.hash(&mut hasher);
    config.private_key.hash(&mut hasher);
    config.peer_public_key.hash(&mut hasher);
    config.route.hash(&mut hasher);
    if carried {
        config.exits.hash(&mut hasher);
    }
    if let Some(masque) = &config.masque {
        masque.private_key.hash(&mut hasher);
        masque.http2_endpoints.hash(&mut hasher);
        masque.http3_endpoints.hash(&mut hasher);
    }
    hasher.finish()
}

fn resolver_of(addresses: &[IpAddr]) -> SocketAddr {
    if addresses.iter().any(IpAddr::is_ipv4) {
        SocketAddr::from(([1, 1, 1, 1], 53))
    } else {
        "[2606:4700:4700::1111]:53"
            .parse()
            .expect("a literal address")
    }
}

/// The MASQUE spec for one transport of an account.
pub fn masque_spec(masque: &MasqueConfig, route: WarpRoute) -> Result<Spec, String> {
    masque_spec_with(masque, route, &[])
}

/// [`masque_spec`] with more HTTP/2 addresses to try after the configured
/// ones.
fn masque_spec_with(
    masque: &MasqueConfig,
    route: WarpRoute,
    extra_h2: &[SocketAddr],
) -> Result<Spec, String> {
    let key = MasqueKey::from_der(&masque.private_key)?;
    let server_point = masque::point_of_spki(&masque.server_public_key)
        .ok_or("the MASQUE server key is not a P-256 public key")?
        .to_vec();
    let http2 = route == WarpRoute::MasqueHttp2;
    let (addresses, sni) = if http2 {
        (&masque.http2_endpoints, &masque.http2_sni)
    } else {
        (&masque.http3_endpoints, &masque.http3_sni)
    };
    if addresses.is_empty() {
        return Err("MASQUE has no endpoint for this transport".into());
    }
    let extra = if http2 { extra_h2 } else { &[] };
    Ok(Spec {
        endpoints: addresses
            .iter()
            .chain(extra.iter().filter(|address| !addresses.contains(address)))
            .map(|address| Endpoint {
                address: *address,
                http2,
                sni: Arc::clone(sni),
            })
            .collect(),
        key: Arc::new(key),
        server_point: Arc::from(server_point),
        authority: Arc::clone(&masque.authority),
    })
}

/// Gives a WireGuard tunnel back to the registry unless it is kept.
struct Release {
    tunnel: Option<(SocketAddr, WgStackParams)>,
}

impl Drop for Release {
    fn drop(&mut self) {
        if let Some((peer, params)) = self.tunnel.take() {
            wg_stack::release(peer, &params);
        }
    }
}

/// Open one route. The guard, dropped without being cleared, stops a
/// WireGuard tunnel that was started only to be tried; a MASQUE one stops
/// with its stack.
async fn open(
    config: &AmneziaWireguardConfig,
    route: WarpRoute,
    wireguard_peer: Option<SocketAddr>,
    found_h2: &[SocketAddr],
) -> Result<(WgStack, Release), String> {
    match route {
        WarpRoute::WireGuard | WarpRoute::Auto => {
            let peer = wireguard_peer.ok_or("WireGuard peer has no address")?;
            let params = crate::outbound::wireguard_stack_params(config);
            let stack = wg_stack::shared(peer, params.clone())?;
            Ok((
                stack,
                Release {
                    tunnel: Some((peer, params)),
                },
            ))
        }
        WarpRoute::MasqueHttp2 | WarpRoute::MasqueHttp3 => {
            let masque = config
                .masque
                .as_ref()
                .ok_or("this WARP outbound has no MASQUE key")?;
            let link = masque::start(masque_spec_with(masque, route, found_h2)?).await?;
            let stack = WgStack::start_link(
                masque.addresses.clone(),
                resolver_of(&masque.addresses),
                PacketLink {
                    up: link.up,
                    down: link.down,
                    rebind: link.rebind,
                },
            )?;
            Ok((stack, Release { tunnel: None }))
        }
    }
}

/// A tunnel that fetches a page from a host outside Cloudflare's network is
/// carrying real traffic both ways.
///
/// A DNS query to 1.1.1.1 is not enough: Cloudflare answers those on tunnels
/// that carry nothing else (an account whose policy moved to MASQUE keeps a
/// WireGuard handshake and resolver that work and gates the rest), and such
/// a route would win a race it should lose. A host of Cloudflare's own is no
/// better, since it can be let through where the rest is not.
async fn verify(stack: &WgStack) -> Result<(), String> {
    match tokio::time::timeout(PROBE_TIMEOUT, egress(stack)).await {
        // The reason is kept: "no answer through the tunnel" on its own sends
        // the reader looking at the filter when the tunnel is what is broken.
        Ok(result) => result.map_err(|error| format!("the tunnel carried nothing: {error}")),
        Err(_) => Err(format!(
            "no answer through the tunnel in {}s",
            PROBE_TIMEOUT.as_secs()
        )),
    }
}

/// Ask the probe page for its 204 over `stream`.
async fn fetch_probe(stream: &mut zero_core::BoxStream) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let request =
        format!("GET {PROBE_PATH} HTTP/1.1\r\nHost: {PROBE_HOST}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("writing the probe: {error}"))?;
    let mut head = [0u8; 64];
    let mut read = 0;
    while read < head.len() && !head[..read].contains(&b'\n') {
        match stream.read(&mut head[read..]).await {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(error) => return Err(format!("reading the probe: {error}")),
        }
    }
    // "HTTP/1.1 204 No Content": the status is the second word.
    let line = String::from_utf8_lossy(&head[..read]);
    match line.split_whitespace().nth(1) {
        Some("204") => Ok(()),
        Some(status) => Err(format!("the probe host answered {status}")),
        None => Err("no answer through the tunnel".into()),
    }
}

#[cfg(not(test))]
async fn egress(stack: &WgStack) -> Result<(), String> {
    let mut stream = stack
        .connect_host(&zero_core::Address::parse_host(PROBE_HOST), 80)
        .await?;
    fetch_probe(&mut stream).await
}

/// Whether `exit` carries a request when reached through `tunnel`, and how
/// long it took to open the connection and get the answer. For finding exits
/// worth listing (`zeronet-warp gather`); the connection is dropped.
pub async fn test_exit(
    tunnel: &Tunnel,
    exit: &zero_config::Outbound,
    timeout: Duration,
) -> Result<Duration, String> {
    let started = Instant::now();
    let destination = zero_core::Destination::tcp(zero_core::Address::parse_host(PROBE_HOST), 80);
    let attempt = async {
        let mut stream = through_exit(tunnel, exit, &destination).await?;
        fetch_probe(&mut stream).await
    };
    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(())) => Ok(started.elapsed()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err("timed out".into()),
    }
}

/// The unit tests run against a stand-in edge that answers DNS and echoes
/// everything else, so they can only test the round trip through the tunnel.
/// The live tests (`tests/warp_live.rs`) use the real probe above.
#[cfg(test)]
async fn egress(stack: &WgStack) -> Result<(), String> {
    stack.resolve(PROBE_NAME).await.map(|_| ())
}

/// Open `route` and, when `probe` is set, prove it carries traffic.
async fn attempt(
    config: &AmneziaWireguardConfig,
    route: WarpRoute,
    wireguard_peer: Option<SocketAddr>,
    found_h2: &[SocketAddr],
    probe: bool,
) -> Result<(WgStack, Release), String> {
    let started = tokio::time::Instant::now();
    let outcome = async {
        let (stack, release) = open(config, route, wireguard_peer, found_h2).await?;
        if probe {
            verify(&stack).await?;
        }
        Ok::<_, String>((stack, release))
    }
    .await;
    tracing::debug!(
        route = route.name(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        ok = outcome.is_ok(),
        "WARP route tried"
    );
    outcome
}

/// Start `routes` a moment apart and keep the first that works. With one
/// route there is nothing to be chosen against, and probing it would only
/// delay the first connection.
async fn race(
    config: &AmneziaWireguardConfig,
    routes: &[WarpRoute],
    wireguard_peer: Option<SocketAddr>,
    found_h2: &[SocketAddr],
) -> Result<(WarpRoute, WgStack), String> {
    use futures::stream::{FuturesUnordered, StreamExt};
    let probe = routes.len() > 1;
    let log = RaceLog::begin(routes, RACE_STAGGER.as_millis() as u32);
    let log = &log;
    let mut attempts = FuturesUnordered::new();
    for (index, route) in routes.iter().copied().enumerate() {
        attempts.push(async move {
            tokio::time::sleep(RACE_STAGGER * index as u32).await;
            log.trying(index);
            (
                index,
                route,
                attempt(config, route, wireguard_peer, found_h2, probe).await,
            )
        });
    }
    let mut errors = Vec::new();
    while let Some((index, route, outcome)) = attempts.next().await {
        match outcome {
            // Dropping `attempts` on return stops the ones still running, and
            // their guards give their WireGuard tunnels back.
            Ok((stack, mut release)) => {
                release.tunnel = None;
                log.finished(index, Ok(()));
                log.end();
                return Ok((route, stack));
            }
            Err(error) => {
                log.finished(index, Err(&error));
                errors.push(format!("{}: {error}", route.name()));
            }
        }
    }
    log.end();
    Err(errors.join("; "))
}

/// Addresses tried when a rescue scan looks for other edge addresses, how many
/// it wants, and how long it may take. Small on purpose: this runs only after
/// every route has failed, and each try is a full TLS handshake.
#[cfg(not(test))]
const RESCUE_SAMPLE: usize = 48;
/// The tests scan the whole of a loopback /24, where one address is the mock.
#[cfg(test)]
const RESCUE_SAMPLE: usize = 254;
const RESCUE_WANTED: usize = 3;
const RESCUE_BUDGET: Duration = Duration::from_secs(15);

/// Look for edge addresses that take this account's MASQUE tunnel over
/// HTTP/2, in the networks the configured addresses sit in (the same /24 for
/// IPv4). Up to `sample` random addresses are tried, sixteen at a time, until
/// `wanted` have answered or `budget` is spent. Returns the ones that
/// answered, fastest first, so a caller can keep or show them.
pub async fn scan_endpoints(
    masque: &MasqueConfig,
    sample: usize,
    wanted: usize,
    budget: Duration,
) -> Vec<(SocketAddr, Duration)> {
    use futures::stream::{FuturesUnordered, StreamExt};
    let Ok(base) = masque_spec(masque, WarpRoute::MasqueHttp2) else {
        return Vec::new();
    };
    let mut candidates: Vec<SocketAddr> = Vec::new();
    for known in &masque.http2_endpoints {
        let IpAddr::V4(ip) = known.ip() else { continue };
        let [a, b, c, _] = ip.octets();
        for host in 1..=254u8 {
            let address = SocketAddr::new(IpAddr::from([a, b, c, host]), known.port());
            if !masque.http2_endpoints.contains(&address) && !candidates.contains(&address) {
                candidates.push(address);
            }
        }
    }
    {
        use rand::seq::SliceRandom;
        candidates.shuffle(&mut rand::thread_rng());
    }
    candidates.truncate(sample);
    let sni = Arc::clone(&masque.http2_sni);
    let mut pending = FuturesUnordered::new();
    let mut queue = candidates.into_iter();
    let mut found = Vec::new();
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        while pending.len() < 16 {
            let Some(address) = queue.next() else { break };
            let (spec, sni) = (base.clone(), Arc::clone(&sni));
            pending.push(async move {
                let endpoint = Endpoint {
                    address,
                    http2: true,
                    sni,
                };
                (address, masque::try_endpoint(&spec, &endpoint).await)
            });
        }
        if pending.is_empty() {
            break;
        }
        match tokio::time::timeout_at(deadline, pending.next()).await {
            Ok(Some((address, Ok(took)))) => {
                found.push((address, took));
                if found.len() >= wanted {
                    break;
                }
            }
            Ok(Some((_, Err(_)))) => {}
            Ok(None) | Err(_) => break,
        }
    }
    found.sort_by_key(|(_, took)| *took);
    found
}

/// The running tunnel of a WARP outbound, chosen and started if there is none.
///
/// `wireguard_peer` is where the outbound's WireGuard endpoint resolved to;
/// MASQUE endpoints are addresses in the configuration itself.
pub async fn tunnel(
    config: &AmneziaWireguardConfig,
    wireguard_peer: Option<SocketAddr>,
) -> Result<Tunnel, String> {
    let entry = Arc::clone(
        lock(&ENTRIES)
            .entry(identity(config, wireguard_peer, false))
            .or_default(),
    );
    // One selection at a time: the streams that arrive while it runs wait for
    // its result instead of each starting their own.
    let mut slot = entry.slot.lock().await;
    let now = Instant::now();
    if let Some(current) = slot.current.take() {
        let condemned = entry.health.condemned.swap(false, Ordering::Relaxed);
        let alive = current.stack.is_alive();
        if alive && !condemned {
            let stack = current.stack.clone();
            let route = current.route;
            slot.current = Some(current);
            promote_if_due(config, wireguard_peer, &entry, &mut slot, route, now);
            return Ok(Tunnel {
                stack,
                route,
                entry: Arc::clone(&entry),
                carried: false,
            });
        }
        // Dead or useless. A tunnel that simply idled out is neither.
        let recent = now_ms().saturating_sub(entry.health.last_ok.load(Ordering::Relaxed))
            < DIED_UNDER_USE.as_millis() as u64;
        if condemned || (!alive && recent) {
            tracing::debug!(
                route = current.route.name(),
                "the WARP route failed; leaving it"
            );
            slot.penalties.insert(current.route, now + PENALTY);
        }
    }
    entry.health.faults.store(0, Ordering::Relaxed);
    let routes = candidates(config, slot.good, &slot.penalties, now);
    if routes.is_empty() {
        return Err("this WARP outbound has no usable route".into());
    }
    let found = slot.found_h2.clone();
    let (route, stack) = match race(config, &routes, wireguard_peer, &found).await {
        Ok(won) => won,
        Err(error) => {
            // Everything failed. If HTTP/2 is among the routes and its
            // addresses may simply have been blocked, look for others in the
            // same networks and try once more.
            let Some(masque) = config
                .masque
                .as_deref()
                .filter(|_| routes.contains(&WarpRoute::MasqueHttp2))
            else {
                return Err(error);
            };
            let fresh: Vec<SocketAddr> =
                scan_endpoints(masque, RESCUE_SAMPLE, RESCUE_WANTED, RESCUE_BUDGET)
                    .await
                    .into_iter()
                    .map(|(address, _)| address)
                    .collect();
            if fresh.is_empty() {
                return Err(error);
            }
            tracing::debug!(found = fresh.len(), "WARP edge addresses found by scanning");
            slot.found_h2.extend(fresh);
            slot.found_h2.truncate(16);
            let found = slot.found_h2.clone();
            race(config, &routes, wireguard_peer, &found)
                .await
                .map_err(|second| format!("{error}; after scanning: {second}"))?
        }
    };
    tracing::debug!(route = route.name(), "WARP tunnel up");
    slot.good = Some(route);
    slot.promoted_at = Some(now);
    slot.current = Some(Current {
        route,
        stack: stack.clone(),
    });
    entry.health.last_ok.store(now_ms(), Ordering::Relaxed);
    Ok(Tunnel {
        stack,
        route,
        entry: Arc::clone(&entry),
        carried: false,
    })
}

/// Try the routes preferred over `current` in the background, if it is time.
fn promote_if_due(
    config: &AmneziaWireguardConfig,
    wireguard_peer: Option<SocketAddr>,
    entry: &Arc<Entry>,
    slot: &mut Slot,
    current: WarpRoute,
    now: Instant,
) {
    if config.route != WarpRoute::Auto
        || slot
            .promoted_at
            .is_some_and(|at| now.duration_since(at) < promote_every())
    {
        return;
    }
    slot.promoted_at = Some(now);
    let better: Vec<WarpRoute> = candidates(config, None, &slot.penalties, now)
        .into_iter()
        .filter(|route| rank(*route) < rank(current))
        .collect();
    if better.is_empty() {
        return;
    }
    let (config, entry) = (config.clone(), Arc::clone(entry));
    let found = slot.found_h2.clone();
    tokio::spawn(async move {
        // A challenger always proves itself, even when it stands alone.
        let outcome = if better.len() == 1 {
            attempt(&config, better[0], wireguard_peer, &found, true)
                .await
                .map(|(stack, mut release)| {
                    release.tunnel = None;
                    (better[0], stack)
                })
        } else {
            race(&config, &better, wireguard_peer, &found).await
        };
        let Ok((route, stack)) = outcome else {
            return;
        };
        let mut slot = entry.slot.lock().await;
        // Only if nothing better arrived while this ran.
        if slot
            .current
            .as_ref()
            .is_some_and(|current| rank(current.route) > rank(route))
        {
            tracing::debug!(route = route.name(), "promoted to a preferred WARP route");
            slot.good = Some(route);
            slot.current = Some(Current { route, stack });
            entry.health.faults.store(0, Ordering::Relaxed);
        }
    });
}

// --------------------------------------------------------- carried tunnels
//
// The `hybrid` order: a server the account lists is dialled first and
// Cloudflare's edge is reached *through* it, so the local network sees an
// ordinary connection to that server and never sees Cloudflare. Only the
// HTTP/2 tunnel can ride another connection (HTTP/3 and WireGuard need a UDP
// socket of their own), so a carried tunnel is always MASQUE over HTTP/2.
//
// A carried tunnel is registered like a direct one, under its own identity,
// kept while it is alive and rebuilt through a carrier when it dies.

/// How long the listed servers get, in total, to bring a carried tunnel up and
/// prove it. Longer than [`EXIT_BUDGET`]: it covers the server's own handshake,
/// Cloudflare's TLS and CONNECT through it, and the egress probe.
const CARRY_BUDGET: Duration = Duration::from_secs(12);

/// The tunnel a WARP outbound's connections ride, in the order it asks for.
///
/// Under [`HybridMode::ServerFirst`] the tunnel is carried by one of the
/// listed servers when one can; when none can (or there is no resolver to open
/// one with) it is dialled directly instead, because a working connection on
/// the other order beats no connection. `wireguard_peer` is where the
/// WireGuard endpoint resolved to, for the direct routes.
pub async fn tunnel_for(
    config: &AmneziaWireguardConfig,
    wireguard_peer: Option<SocketAddr>,
    resolver: Option<&zero_dns::Resolver>,
) -> Result<Tunnel, String> {
    if config.hybrid == HybridMode::ServerFirst && !config.exits.is_empty() {
        if let Some(resolver) = resolver {
            match tunnel_carried(config, resolver).await {
                Ok(tunnel) => return Ok(tunnel),
                Err(error) => {
                    tracing::debug!(%error, "no listed server carried the WARP tunnel; dialling it directly")
                }
            }
        }
    }
    tunnel(config, wireguard_peer).await
}

/// One connection to `destination` through `server`, dialled directly from
/// here: the server's own connection, then its protocol asked for the
/// destination, with any reply header the protocol adds taken off.
async fn open_via(
    server: &zero_config::Outbound,
    resolver: &zero_dns::Resolver,
    destination: &zero_core::Destination,
) -> Result<zero_core::BoxStream, String> {
    let opened = async {
        let (secured, _) = crate::outbound::open_secured(server, resolver).await?;
        crate::outbound::connect_over(server, secured, destination).await
    };
    let stream = opened
        .await
        .map_err(|error| format!("server {}: {error}", server.tag))?;
    Ok(crate::outbound::strip_response(server, stream))
}

/// Opens a stream to a Cloudflare edge address through `exit`.
///
/// The opener outlives this call (it is asked again on every rebuild of the
/// session), so it owns its copies of the exit and the resolver.
fn carrier_opener(
    exit: Arc<zero_config::Outbound>,
    resolver: zero_dns::Resolver,
) -> masque::Opener {
    Arc::new(move |edge: SocketAddr| {
        let (exit, resolver) = (Arc::clone(&exit), resolver.clone());
        Box::pin(async move {
            let destination =
                zero_core::Destination::tcp(zero_core::Address::Ip(edge.ip()), edge.port());
            open_via(&exit, &resolver, &destination).await
        })
    })
}

/// Whether `server`, dialled directly from here, carries a request, and how
/// long opening it and getting the answer took. For finding servers worth
/// listing for the `hybrid` order, where Cloudflare is reached through them
/// (`zeronet-warp gather`); the connection is dropped.
pub async fn test_carrier(
    server: &zero_config::Outbound,
    resolver: &zero_dns::Resolver,
    timeout: Duration,
) -> Result<Duration, String> {
    let started = Instant::now();
    let destination = zero_core::Destination::tcp(zero_core::Address::parse_host(PROBE_HOST), 80);
    let attempt = async {
        let mut stream = open_via(server, resolver, &destination).await?;
        fetch_probe(&mut stream).await
    };
    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(())) => Ok(started.elapsed()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err("timed out".into()),
    }
}

/// Bring Cloudflare's tunnel up through one of `config`'s servers.
///
/// The two cheapest are tried a moment apart and the first one that both
/// authenticates and carries the egress probe is kept: a tunnel that finishes
/// its handshake and carries nothing is the failure that would otherwise look
/// like success. Every outcome goes into the carriers' own score book.
async fn tunnel_carried(
    config: &AmneziaWireguardConfig,
    resolver: &zero_dns::Resolver,
) -> Result<Tunnel, String> {
    let masque_config = config
        .masque
        .as_deref()
        .ok_or("this WARP outbound has no MASQUE key, so there is nothing to carry")?;
    let entry = Arc::clone(
        lock(&ENTRIES)
            .entry(identity(config, None, true))
            .or_default(),
    );
    let mut slot = entry.slot.lock().await;
    if let Some(current) = slot.current.take() {
        let condemned = entry.health.condemned.swap(false, Ordering::Relaxed);
        if current.stack.is_alive() && !condemned {
            let stack = current.stack.clone();
            slot.current = Some(current);
            return Ok(Tunnel {
                stack,
                route: WarpRoute::MasqueHttp2,
                entry: Arc::clone(&entry),
                carried: true,
            });
        }
    }
    entry.health.faults.store(0, Ordering::Relaxed);
    // Built once for every attempt: the HTTP/2 edges whatever the route says,
    // since this order cannot use the others.
    let spec = masque_spec_with(masque_config, WarpRoute::MasqueHttp2, &slot.found_h2)?;
    let addresses = &masque_config.addresses;
    let stack = race_exits(config, true, 2, CARRY_BUDGET, |exit| {
        let opener = carrier_opener(exit, resolver.clone());
        let spec = spec.clone();
        async move {
            let link = masque::start_over(spec, opener).await?;
            let stack = WgStack::start_link(
                addresses.clone(),
                resolver_of(addresses),
                PacketLink {
                    up: link.up,
                    down: link.down,
                    rebind: link.rebind,
                },
            )?;
            verify(&stack).await?;
            Ok(stack)
        }
    })
    .await?;
    slot.current = Some(Current {
        route: WarpRoute::MasqueHttp2,
        stack: stack.clone(),
    });
    entry.health.last_ok.store(now_ms(), Ordering::Relaxed);
    Ok(Tunnel {
        stack,
        route: WarpRoute::MasqueHttp2,
        entry: Arc::clone(&entry),
        carried: true,
    })
}

// ------------------------------------------------------------------ exits
//
// A WARP outbound may list `exits`: servers to dial *through* the tunnel. The
// connection goes to the tunnel, from there to an exit, and from the exit to
// the destination. That reaches servers the local network blocks (they are
// only ever dialled from inside the tunnel), and shows destinations that block
// Cloudflare's addresses the exit's instead. It costs a longer path, and how
// well an exit carries traffic varies from one to the next, so exits are
// measured and ranked, never assumed.
//
// Each path is the other's failsafe: with `prefer_exit` the exits go first and
// the tunnel alone catches what they cannot carry, and without it the order
// is reversed.

/// How long the exits get, in total, before the other path is tried.
const EXIT_BUDGET: Duration = Duration::from_secs(6);
/// A second exit is started this long after the first, if it has not
/// answered: a slow one costs the connection a moment, not its whole budget.
const EXIT_STAGGER: Duration = Duration::from_millis(1500);
/// What an exit that has not been measured yet is assumed to cost, so that a
/// measured good one is preferred to it and it is still tried in its turn.
const UNMEASURED_MS: f64 = 1500.0;
/// Failures in a row that take an exit out of use, and for how long the
/// first time. Each further failure doubles the wait, up to
/// [`EXIT_PENALTY_DOUBLINGS`] times (80 minutes): a server that stays dead is
/// asked less and less often, because every time its penalty runs out the
/// connections of that moment wait on it again.
const EXIT_FAILURES: u32 = 2;
const EXIT_PENALTY: Duration = Duration::from_secs(5 * 60);
const EXIT_PENALTY_DOUBLINGS: u32 = 4;

struct ExitState {
    link: Arc<str>,
    outbound: Arc<zero_config::Outbound>,
    /// Smoothed time to open a connection through it, in milliseconds.
    ms: Option<f64>,
    failures: u32,
    penalized_until: Option<Instant>,
}

impl ExitState {
    /// Lower is better. A failure costs as much as several seconds.
    fn cost(&self) -> f64 {
        self.ms.unwrap_or(UNMEASURED_MS) + 4000.0 * f64::from(self.failures)
    }

    fn usable(&self, now: Instant) -> bool {
        self.penalized_until.is_none_or(|until| until <= now)
    }
}

/// The exits of every WARP outbound, keyed by the list they came from.
static EXITS: LazyLock<StdMutex<HashMap<u64, Vec<ExitState>>>> = LazyLock::new(Default::default);

/// The book a server list is scored in. `direct` says the servers are dialled
/// from here (the carriers of the `hybrid` order) rather than through the
/// tunnel: the same server can work one way and be blocked the other, so the
/// two paths never share a score.
fn exits_key(config: &AmneziaWireguardConfig, direct: bool) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    direct.hash(&mut hasher);
    config.exits.hash(&mut hasher);
    hasher.finish()
}

/// The exits in the order to try them, at most `count`: those not out of use,
/// by cost. When every exit is out of use the answer is empty, so a connection
/// goes straight to the other path instead of waiting on exits known to be
/// failing; they are tried again once their penalty runs out.
fn pick_exits(
    book: &[ExitState],
    now: Instant,
    count: usize,
) -> Vec<(Arc<str>, Arc<zero_config::Outbound>)> {
    let mut order: Vec<usize> = (0..book.len()).filter(|i| book[*i].usable(now)).collect();
    order.sort_by(|a, b| {
        book[*a]
            .cost()
            .partial_cmp(&book[*b].cost())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    order
        .into_iter()
        .take(count)
        .map(|index| {
            (
                Arc::clone(&book[index].link),
                Arc::clone(&book[index].outbound),
            )
        })
        .collect()
}

/// Note how an exit did.
fn record_exit(key: u64, link: &str, took: Result<Duration, ()>, now: Instant) {
    let mut books = lock(&EXITS);
    let Some(state) = books
        .get_mut(&key)
        .and_then(|book| book.iter_mut().find(|state| &*state.link == link))
    else {
        return;
    };
    match took {
        Ok(took) => {
            let ms = took.as_secs_f64() * 1000.0;
            state.ms = Some(state.ms.map_or(ms, |old| old * 0.7 + ms * 0.3));
            state.failures = 0;
            state.penalized_until = None;
        }
        Err(()) => {
            state.failures += 1;
            if state.failures >= EXIT_FAILURES {
                let doublings = (state.failures - EXIT_FAILURES).min(EXIT_PENALTY_DOUBLINGS);
                state.penalized_until = Some(now + EXIT_PENALTY * (1 << doublings));
            }
        }
    }
}

/// Parse an outbound's exit list once and keep the book.
fn load_exits(config: &AmneziaWireguardConfig, direct: bool) -> u64 {
    let key = exits_key(config, direct);
    let mut books = lock(&EXITS);
    books.entry(key).or_insert_with(|| {
        config
            .exits
            .iter()
            .filter_map(|link| {
                let parsed = zero_config::parse_link(link).ok()?;
                parsed.outbound.chainable().then(|| ExitState {
                    link: Arc::clone(link),
                    outbound: Arc::new(parsed.outbound),
                    ms: None,
                    failures: 0,
                    penalized_until: None,
                })
            })
            .collect()
    });
    key
}

/// One connection to `destination` through `exit`, itself reached through the
/// tunnel. Each opens its own path; nothing is held open ahead of need.
async fn through_exit(
    tunnel: &Tunnel,
    exit: &zero_config::Outbound,
    destination: &zero_core::Destination,
) -> Result<zero_core::BoxStream, String> {
    let (address, port) = exit
        .endpoint()
        .ok_or_else(|| "the exit has no address".to_string())?;
    let carried = tunnel.connect_host(&address, port).await?;
    let stream = crate::outbound::connect_over(exit, carried, destination)
        .await
        .map_err(|failure| failure.to_string())?;
    // The exit's protocol may put a header of its own in front of the reply
    // (VLESS does); the caller expects the payload alone.
    Ok(crate::outbound::strip_response(exit, stream))
}

/// Try the best `count` servers of `config` with `attempt`, the next one only
/// if the one before is slow, and return the first success. `direct` picks
/// the score book (see [`exits_key`]).
///
/// Every outcome is written to the score book, and so is silence: a server
/// still running when `budget` runs out is counted as failed, or a dead one
/// would cost every later connection the whole budget.
async fn race_exits<T, F, Fut>(
    config: &AmneziaWireguardConfig,
    direct: bool,
    count: usize,
    budget: Duration,
    mut attempt: F,
) -> Result<T, String>
where
    F: FnMut(Arc<zero_config::Outbound>) -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    use futures::stream::{FuturesUnordered, StreamExt};
    let key = load_exits(config, direct);
    let chosen = {
        let books = lock(&EXITS);
        pick_exits(
            books.get(&key).map_or(&[][..], Vec::as_slice),
            Instant::now(),
            count,
        )
    };
    if chosen.is_empty() {
        return Err("this WARP outbound has no usable server".into());
    }
    let mut waiting: Vec<Arc<str>> = chosen.iter().map(|(link, _)| Arc::clone(link)).collect();
    let mut attempts = FuturesUnordered::new();
    for (position, (link, exit)) in chosen.into_iter().enumerate() {
        let attempt = attempt(exit);
        attempts.push(async move {
            tokio::time::sleep(EXIT_STAGGER * position as u32).await;
            let started = Instant::now();
            let result = attempt.await;
            (link, started.elapsed(), result)
        });
    }
    let mut last = String::from("no server answered");
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        match tokio::time::timeout_at(deadline, attempts.next()).await {
            Ok(Some((link, took, Ok(value)))) => {
                record_exit(key, &link, Ok(took), Instant::now());
                return Ok(value);
            }
            Ok(Some((link, _, Err(error)))) => {
                waiting.retain(|other| *other != link);
                record_exit(key, &link, Err(()), Instant::now());
                last = error;
            }
            Ok(None) => return Err(last),
            Err(_) => {
                for link in &waiting {
                    record_exit(key, link, Err(()), Instant::now());
                }
                return Err(format!("no server answered in time: {last}"));
            }
        }
    }
}

/// One connection to `destination` through the best of the exits, reached
/// through the tunnel.
async fn via_exits(
    config: &AmneziaWireguardConfig,
    tunnel: &Tunnel,
    destination: &zero_core::Destination,
) -> Result<zero_core::BoxStream, String> {
    let stream = race_exits(config, false, 2, EXIT_BUDGET, |exit| async move {
        through_exit(tunnel, &exit, destination).await
    })
    .await?;
    // Traffic came through, so the tunnel is fine.
    tunnel.report(&Ok::<_, String>(()));
    Ok(stream)
}

/// Open a connection to `destination` through a WARP outbound: over the
/// tunnel alone, over one of its exits, or one and then the other, in the
/// order the configuration prefers. Whichever goes second is the failsafe.
pub async fn connect(
    config: &AmneziaWireguardConfig,
    tunnel: &Tunnel,
    destination: &zero_core::Destination,
) -> Result<zero_core::BoxStream, String> {
    let plain = || async {
        let opened = tunnel
            .connect_host(&destination.address, destination.port)
            .await;
        // Route selection learns from every outcome: a run of timeouts means
        // the route, not the destination, has stopped carrying traffic.
        tunnel.report(&opened);
        opened
    };
    // A carried tunnel already went through a listed server; going through
    // one again from inside it would only lengthen the path.
    if config.exits.is_empty() || tunnel.carried {
        return plain().await;
    }
    if config.prefer_exit {
        return match via_exits(config, tunnel, destination).await {
            Ok(stream) => Ok(stream),
            Err(exit_error) => {
                tracing::debug!(error = %exit_error, "no exit carried it; using the tunnel alone");
                plain()
                    .await
                    .map_err(|error| format!("{error} (exits: {exit_error})"))
            }
        };
    }
    match plain().await {
        Ok(stream) => Ok(stream),
        // A refusal is the destination saying no; only silence and resets
        // look like a block that another address might get around.
        Err(error) if error.contains("refused") => Err(error),
        Err(error) => via_exits(config, tunnel, destination)
            .await
            .map_err(|exit_error| format!("{error} (exits: {exit_error})")),
    }
}

/// After the device changed networks: what worked before is no longer known
/// to, and MASQUE tunnels reconnect from where they are. The WireGuard ones
/// are moved by [`wg_stack::rebind_all`].
pub fn network_changed() -> usize {
    let entries: Vec<Arc<Entry>> = lock(&ENTRIES).values().cloned().collect();
    let mut moved = 0;
    for entry in entries {
        // A selection in progress is already on the new network.
        let Ok(mut slot) = entry.slot.try_lock() else {
            continue;
        };
        slot.good = None;
        slot.penalties.clear();
        slot.promoted_at = None;
        entry.health.faults.store(0, Ordering::Relaxed);
        if let Some(current) = &slot.current {
            if current.route.uses_masque() && current.stack.is_alive() {
                current.stack.rebind();
                moved += 1;
            }
        }
    }
    moved
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_transport::masque::mock::{h2_server, h3_server};

    /// Selection memory is process-wide, and a network change wipes all of
    /// it: the test that causes one takes the write side, the others the
    /// read side, so they never overlap.
    static GATE: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

    fn config(route: WarpRoute) -> AmneziaWireguardConfig {
        let mut value = serde_json::json!({"outbounds": [{
            "protocol": "warp", "tag": "warp", "settings": {"route": route.name(), "masque": {}}
        }]});
        // A minimal account: the parser wants the MASQUE key material.
        value["outbounds"][0]["settings"]["masque"] = serde_json::json!({
            "privateKey": "AAAA", "serverPublicKey": "AAAA", "address": "172.16.0.2"
        });
        let (parsed, _) = zero_config::parse_config(&value).unwrap();
        match &parsed.outbounds[0].protocol {
            zero_config::OutboundProtocol::AmneziaWireguard(config) => config.clone(),
            _ => unreachable!(),
        }
    }

    fn with_wireguard(mut config: AmneziaWireguardConfig) -> AmneziaWireguardConfig {
        config.has_wireguard = true;
        config
    }

    fn plan(
        config: &AmneziaWireguardConfig,
        good: Option<WarpRoute>,
        penalized: &[WarpRoute],
    ) -> Vec<WarpRoute> {
        let now = Instant::now();
        let penalties = penalized
            .iter()
            .map(|route| (*route, now + Duration::from_secs(60)))
            .collect();
        candidates(config, good, &penalties, now)
    }

    #[test]
    fn candidates_go_udp_first_then_by_what_worked_and_skip_the_penalized() {
        use WarpRoute::*;
        let both = with_wireguard(config(Auto));
        assert_eq!(
            plan(&both, None, &[]),
            [WireGuard, MasqueHttp3, MasqueHttp2]
        );
        // What worked last time starts first.
        assert_eq!(
            plan(&both, Some(MasqueHttp2), &[]),
            [MasqueHttp2, WireGuard, MasqueHttp3]
        );
        // What failed under use is left out for now...
        assert_eq!(plan(&both, None, &[WireGuard]), [MasqueHttp3, MasqueHttp2]);
        // ...unless that would leave nothing.
        assert_eq!(
            plan(&both, None, &[WireGuard, MasqueHttp3, MasqueHttp2]),
            [WireGuard, MasqueHttp3, MasqueHttp2]
        );
        // A pinned route is the only one, penalty or not.
        let mut pinned = both.clone();
        pinned.route = WireGuard;
        assert_eq!(plan(&pinned, Some(MasqueHttp3), &[WireGuard]), [WireGuard]);
        // A missing half is not offered.
        assert_eq!(plan(&config(Auto), None, &[]), [MasqueHttp3, MasqueHttp2]);
        let mut wireguard_only = both.clone();
        wireguard_only.masque = None;
        assert_eq!(plan(&wireguard_only, None, &[]), [WireGuard]);
        // A penalty that has run out no longer counts.
        let now = Instant::now();
        let expired = HashMap::from([(WireGuard, now - Duration::from_secs(1))]);
        assert_eq!(
            candidates(&both, None, &expired, now),
            [WireGuard, MasqueHttp3, MasqueHttp2]
        );
    }

    #[test]
    fn timeouts_condemn_a_route_but_a_refusal_or_a_success_does_not() {
        let health = Health::default();
        let timeout = || Err::<(), _>("TCP connect through the tunnel timed out".to_string());
        let state = || {
            (
                health.faults.load(Ordering::Relaxed),
                health.condemned.load(Ordering::Relaxed),
            )
        };
        health.record(&timeout());
        health.record(&timeout());
        assert_eq!(state(), (2, false));
        // A success in between clears the count.
        health.record(&Ok(()));
        health.record(&timeout());
        health.record(&Err::<(), _>(
            "connection refused through the tunnel".to_string(),
        ));
        assert_eq!(state(), (1, false));
        health.record(&timeout());
        health.record(&timeout());
        assert_eq!(state(), (3, true));
        assert!(is_fault("the tunnel is closed") && !is_fault("connection refused"));
    }

    #[test]
    fn accounts_with_the_same_keys_share_a_tunnel_and_others_do_not() {
        let a = config(WarpRoute::Auto);
        let mut b = a.clone();
        assert_eq!(identity(&a, None, false), identity(&b, None, false));
        b.route = WarpRoute::MasqueHttp2;
        assert_ne!(identity(&a, None, false), identity(&b, None, false));
        let mut c = a.clone();
        c.masque.as_mut().unwrap().http2_endpoints.clear();
        assert_ne!(identity(&a, None, false), identity(&c, None, false));
        // The same account at another WireGuard address is another tunnel.
        assert_ne!(
            identity(&a, Some("192.0.2.1:2408".parse().unwrap()), false),
            identity(&a, None, false)
        );
    }

    /// An account whose keys are real, pointing at loopback mock edges.
    fn account(
        route: WarpRoute,
        server: &MasqueKey,
        http2: Option<SocketAddr>,
        http3: Option<SocketAddr>,
    ) -> AmneziaWireguardConfig {
        let mut config = config(route);
        let client = MasqueKey::generate().unwrap();
        let masque = config.masque.as_mut().unwrap();
        masque.private_key = client.pkcs8().to_vec();
        masque.server_public_key = server.spki_der();
        masque.http2_endpoints = http2.into_iter().collect();
        masque.http3_endpoints = http3.into_iter().collect();
        config
    }

    fn closed_port() -> SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    /// A VLESS server on the loopback: the person chose it, and it is the only
    /// thing Cloudflare can be reached through here.
    async fn carrier_server() -> (u16, Arc<crate::Server>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let (generation, _) = zero_config::compile_config(
            &serde_json::json!({
                "log": {"loglevel": "warning"},
                "inbounds": [{
                    "tag": "in",
                    "listen": "127.0.0.1",
                    "port": port,
                    "protocol": "vless",
                    "settings": {"clients": [{"id": CARRIER_UUID}]},
                    "streamSettings": {"network": "raw"}
                }],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}]
            }),
            zero_core::GenerationId(1),
        )
        .expect("the carrier config parses");
        let server = Arc::new(crate::Server::new(crate::ServerConfig {
            config: Arc::clone(&generation.config),
            generation: generation.id,
        }));
        let running = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = running.run().await;
        });
        server.wait_until_listening().await;
        (port, server)
    }

    const CARRIER_UUID: &str = "00000000-0000-0000-0000-00000000cafe";

    /// An account whose tunnel is reached through the server it lists.
    fn carried_account(
        server: &MasqueKey,
        edge: SocketAddr,
        carrier: u16,
    ) -> AmneziaWireguardConfig {
        let mut config = account(WarpRoute::MasqueHttp2, server, Some(edge), None);
        config.hybrid = zero_config::HybridMode::ServerFirst;
        config.exits = vec![Arc::from(format!(
            "vless://{CARRIER_UUID}@127.0.0.1:{carrier}?encryption=none#carrier"
        ))];
        config
    }

    /// The order `hybrid` names, with a real server in front of Cloudflare.
    ///
    /// The server here is a complete one — its own inbound, its own protocol,
    /// its own dial onward — so the tunnel can only come up by going through
    /// it. What it does *not* do is bypass it: the address it is asked for is
    /// the mock edge's, and only the server knows how to get there.
    #[tokio::test]
    async fn a_carried_tunnel_brings_cloudflare_up_through_a_listed_server() {
        let _gate = GATE.read().await;
        let server = MasqueKey::generate().unwrap();
        let (edge, _, _) = h2_server(&server, false).await;
        let (carrier, relay) = carrier_server().await;
        let config = carried_account(&server, edge, carrier);
        let resolver = zero_dns::Resolver::new(zero_config::dns::DnsSettings::default());

        let tunnel = tunnel_carried(&config, &resolver)
            .await
            .expect("the tunnel came up through the server");
        assert!(tunnel.is_alive(), "the carried tunnel is not alive");
        assert!(tunnel.carried(), "the tunnel was dialled directly");
        assert_eq!(tunnel.route(), WarpRoute::MasqueHttp2);
        // A second call finds the same tunnel rather than negotiating again,
        // which is what the registry is for.
        let again = tunnel_carried(&config, &resolver)
            .await
            .expect("the same tunnel");
        assert!(again.is_alive());
        drop((tunnel, again));

        // The tunnel stays in the registry after this, so the server's byte
        // counters are not settled here; the accepted connection is the claim
        // that matters, and it can only have come from `carrier_opener` — that
        // function is the only thing in the process that ever dials this port.
        assert!(
            relay.stats.snapshot().accepted >= 1,
            "the server accepted nothing, so the tunnel went around it"
        );
    }

    /// A server dialled from here and the same server dialled through the
    /// tunnel are scored apart: failing one way says nothing about the other.
    #[test]
    fn carriers_and_exits_keep_separate_score_books() {
        let mut config = config(WarpRoute::Auto);
        config.exits = vec![Arc::from(
            "trojan://secret@203.0.113.9:8443?security=tls&sni=books.example.com#books",
        )];
        let (direct, tunnelled) = (load_exits(&config, true), load_exits(&config, false));
        assert_ne!(direct, tunnelled);
        let link = Arc::clone(&config.exits[0]);
        let now = Instant::now();
        for _ in 0..EXIT_FAILURES {
            record_exit(direct, &link, Err(()), now);
        }
        {
            let books = lock(&EXITS);
            assert!(pick_exits(&books[&direct], now, 2).is_empty());
            assert_eq!(pick_exits(&books[&tunnelled], now, 2).len(), 1);
        }
        // Back in use once the penalty is over, and out for twice as long when
        // it fails again.
        let later = now + EXIT_PENALTY;
        assert_eq!(pick_exits(&lock(&EXITS)[&direct], later, 2).len(), 1);
        record_exit(direct, &link, Err(()), later);
        let books = lock(&EXITS);
        assert!(pick_exits(&books[&direct], later + EXIT_PENALTY, 2).is_empty());
        assert_eq!(
            pick_exits(&books[&direct], later + EXIT_PENALTY * 2, 2).len(),
            1
        );
    }

    /// An account with no MASQUE key has no tunnel that could be carried, and
    /// says so rather than quietly dialing it directly.
    #[tokio::test]
    async fn a_wireguard_only_account_cannot_be_carried() {
        let _gate = GATE.read().await;
        // Built with a MASQUE half and then stripped: the parser wants key
        // material, and this is the account shape that has none at runtime.
        let mut config = config(WarpRoute::MasqueHttp2);
        config.masque = None;
        config.hybrid = zero_config::HybridMode::ServerFirst;
        let resolver = zero_dns::Resolver::new(zero_config::dns::DnsSettings::default());
        let error = match tunnel_carried(&config, &resolver).await {
            Ok(_) => panic!("a WireGuard-only account has no tunnel to carry"),
            Err(error) => error,
        };
        assert!(error.contains("MASQUE"), "{error}");
    }

    /// When none of the listed servers can carry the tunnel, the `hybrid`
    /// order falls back to dialling it directly, and the connections then use
    /// the tunnel alone.
    #[tokio::test]
    async fn the_hybrid_order_dials_directly_when_no_server_can_carry_it() {
        let _gate = GATE.read().await;
        let server = MasqueKey::generate().unwrap();
        let (edge, _, connections) = h2_server(&server, false).await;
        let dead = closed_port().port();
        let mut config = carried_account(&server, edge, dead);
        // A server of its own, so the score book is not shared with other tests.
        config.exits = vec![Arc::from(format!(
            "vless://{CARRIER_UUID}@127.0.0.1:{dead}?encryption=none#dead-carrier"
        ))];
        let resolver = zero_dns::Resolver::new(zero_config::dns::DnsSettings::default());
        let tunnel = tunnel_for(&config, None, Some(&resolver))
            .await
            .expect("the direct tunnel is the fallback");
        assert!(!tunnel.carried());
        assert!(connections.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn auto_skips_a_route_that_is_down_and_keeps_the_one_that_works() {
        let _gate = GATE.read().await;
        let server = MasqueKey::generate().unwrap();
        let (h3, _, h3_connections) = h3_server(&server).await;
        // The HTTP/2 endpoint is a closed port: refused at once.
        let config = account(WarpRoute::Auto, &server, Some(closed_port()), Some(h3));
        let first = tunnel(&config, None).await.unwrap();
        assert!(first.is_alive());
        assert_eq!(h3_connections.load(Ordering::SeqCst), 1);
        // A second call finds the same tunnel rather than negotiating again.
        let again = tunnel(&config, None).await.unwrap();
        assert!(again.is_alive());
        assert_eq!(h3_connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_race_takes_the_route_that_answers_first_and_stops_the_rest() {
        let _gate = GATE.read().await;
        let server = MasqueKey::generate().unwrap();
        let (h2, _, h2_connections) = h2_server(&server, false).await;
        let (h3, _, h3_connections) = h3_server(&server).await;
        let config = account(WarpRoute::Auto, &server, Some(h2), Some(h3));
        let started = Instant::now();
        let winner = tunnel(&config, None).await.unwrap();
        // HTTP/3 is preferred and starts first; both answer at loopback speed.
        assert!(winner.is_alive());
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(h3_connections.load(Ordering::SeqCst) >= 1);
        // HTTP/2 starts 200 ms later; if it got as far as connecting it was
        // dropped with the losing attempt, so at most one such connection.
        assert!(h2_connections.load(Ordering::SeqCst) <= 1);
    }

    #[tokio::test]
    async fn a_pinned_route_reports_its_own_failure() {
        let _gate = GATE.read().await;
        let server = MasqueKey::generate().unwrap();
        let config = account(WarpRoute::MasqueHttp2, &server, Some(closed_port()), None);
        let error = tunnel(&config, None).await.err().expect("must fail");
        assert!(error.starts_with("masque-h2:"), "{error}");
    }

    #[tokio::test]
    async fn a_condemned_route_is_replaced_by_another_and_not_chosen_at_once() {
        let _gate = GATE.read().await;
        let server = MasqueKey::generate().unwrap();
        let (h2, _, _) = h2_server(&server, false).await;
        let (h3, _, _) = h3_server(&server).await;
        let config = account(WarpRoute::Auto, &server, Some(h2), Some(h3));
        let first = tunnel(&config, None).await.unwrap();
        let first_route = {
            let slot = first.entry.slot.lock().await;
            slot.current.as_ref().unwrap().route
        };
        // Three timeouts in a row condemn it.
        for _ in 0..FAULTS_TO_DROP {
            first.report::<()>(&Err("TCP connect through the tunnel timed out".into()));
        }
        let second = tunnel(&config, None).await.unwrap();
        let (second_route, penalized) = {
            let slot = second.entry.slot.lock().await;
            (
                slot.current.as_ref().unwrap().route,
                slot.penalties.contains_key(&first_route),
            )
        };
        assert!(penalized, "the failed route should be under penalty");
        assert_ne!(
            second_route, first_route,
            "the failed route was chosen again"
        );
    }

    #[tokio::test]
    async fn a_tunnel_carries_dns_through_a_masque_route_it_selected() {
        let _gate = GATE.read().await;
        let server = MasqueKey::generate().unwrap();
        let (h2, _, connections) = h2_server(&server, false).await;
        let config = account(WarpRoute::MasqueHttp2, &server, Some(h2), None);
        let tunnel = tunnel(&config, None).await.unwrap();
        // The mock edge answers DNS, so this crosses the user-space stack and
        // the MASQUE link in both directions.
        let answers = tunnel.resolve("example.com").await.unwrap();
        assert_eq!(answers.len(), 1);
        tunnel.report(&Ok::<_, String>(()));
        assert!(tunnel.is_alive());
        assert_eq!(connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_preferred_route_that_comes_back_takes_over_new_connections() {
        let _gate = GATE.read().await;
        let server = MasqueKey::generate().unwrap();
        let (h2, _, _) = h2_server(&server, false).await;
        let (h3, _, _) = h3_server(&server).await;
        let config = account(WarpRoute::Auto, &server, Some(h2), Some(h3));
        // HTTP/3 is preferred, but it starts out under penalty (as if it had
        // failed a moment ago), so HTTP/2 carries the first connections.
        let key = identity(&config, None, false);
        let entry = Arc::clone(lock(&ENTRIES).entry(key).or_default());
        entry.slot.lock().await.penalties.insert(
            WarpRoute::MasqueHttp3,
            Instant::now() + Duration::from_secs(600),
        );
        let first = tunnel(&config, None).await.unwrap();
        assert_eq!(
            entry.slot.lock().await.current.as_ref().unwrap().route,
            WarpRoute::MasqueHttp2
        );
        // The penalty runs out and the check comes due.
        PROMOTE_EVERY_MS.store(0, Ordering::Relaxed);
        entry.slot.lock().await.penalties.clear();
        let _second = tunnel(&config, None).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let route = entry.slot.lock().await.current.as_ref().unwrap().route;
            if route == WarpRoute::MasqueHttp3 {
                break;
            }
            assert!(Instant::now() < deadline, "never promoted: {route:?}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        PROMOTE_EVERY_MS.store(10 * 60 * 1000, Ordering::Relaxed);
        // Streams already on the old tunnel are not cut off by the move.
        assert!(first.is_alive());
    }

    #[tokio::test]
    async fn a_network_change_forgets_the_memory_and_moves_masque_tunnels() {
        let _gate = GATE.write().await;
        let server = MasqueKey::generate().unwrap();
        let (h3, _, _) = h3_server(&server).await;
        let config = account(WarpRoute::Auto, &server, Some(closed_port()), Some(h3));
        let up = tunnel(&config, None).await.unwrap();
        assert!(up.is_alive());
        let entry = Arc::clone(&up.entry);
        entry.slot.lock().await.penalties.insert(
            WarpRoute::MasqueHttp2,
            Instant::now() + Duration::from_secs(600),
        );
        assert!(network_changed() >= 1);
        let slot = entry.slot.lock().await;
        assert!(slot.penalties.is_empty() && slot.good.is_none());
        assert!(up.is_alive(), "the tunnel itself stays up and reconnects");
    }

    #[tokio::test]
    async fn a_scan_finds_the_addresses_that_answer_in_the_same_network() {
        let _gate = GATE.read().await;
        let server = MasqueKey::generate().unwrap();
        let (live, _, _) = h2_server(&server, false).await;
        // The configured address sits in the same /24 but nothing answers there.
        let dead = SocketAddr::from(([127, 0, 0, 5], live.port()));
        let config = account(WarpRoute::MasqueHttp2, &server, Some(dead), None);
        let masque = config.masque.as_deref().unwrap();
        let found = scan_endpoints(masque, 254, 1, Duration::from_secs(20)).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, live);
    }

    #[tokio::test]
    async fn when_every_configured_address_is_dead_a_scan_finds_another_and_it_is_kept() {
        let _gate = GATE.read().await;
        let server = MasqueKey::generate().unwrap();
        let (live, _, connections) = h2_server(&server, false).await;
        let dead = SocketAddr::from(([127, 0, 0, 6], live.port()));
        let config = account(WarpRoute::MasqueHttp2, &server, Some(dead), None);
        // A pinned route would just fail; auto with one route is the same
        // machinery, so use auto by giving it a second (absent) half.
        let mut config = config;
        config.route = WarpRoute::Auto;
        let tunnel = tunnel(&config, None).await.expect("found another address");
        assert!(tunnel.is_alive());
        assert!(connections.load(Ordering::SeqCst) >= 1);
        let found = {
            let slot = tunnel.entry.slot.lock().await;
            slot.found_h2.clone()
        };
        assert_eq!(found, [live]);
    }

    fn exit_state(link: &str, ms: Option<f64>, failures: u32) -> ExitState {
        let parsed = zero_config::parse_link(&format!(
            "trojan://secret@203.0.113.9:8443?security=tls&sni=t.example.com#{link}"
        ))
        .unwrap();
        ExitState {
            link: Arc::from(link),
            outbound: Arc::new(parsed.outbound),
            ms,
            failures,
            penalized_until: None,
        }
    }

    #[test]
    fn exits_are_ranked_by_measured_cost_and_the_failing_ones_sink() {
        let now = Instant::now();
        let mut book = vec![
            exit_state("slow", Some(900.0), 0),
            exit_state("unmeasured", None, 0),
            exit_state("fast", Some(300.0), 0),
            exit_state("failing", Some(100.0), 1),
        ];
        let names = |picked: Vec<(Arc<str>, _)>| -> Vec<String> {
            picked
                .into_iter()
                .map(|(link, _)| link.to_string())
                .collect()
        };
        // Measured good first; an unmeasured one is tried before a slow one;
        // a recent failure outweighs a good time.
        assert_eq!(
            names(pick_exits(&book, now, 4)),
            ["fast", "slow", "unmeasured", "failing"]
        );
        assert_eq!(names(pick_exits(&book, now, 2)), ["fast", "slow"]);
        // Out of use: left out, and when none is left the answer is empty so
        // a connection does not wait on exits known to be failing.
        book[2].penalized_until = Some(now + Duration::from_secs(60));
        assert_eq!(
            names(pick_exits(&book, now, 4)),
            ["slow", "unmeasured", "failing"]
        );
        for state in &mut book {
            state.penalized_until = Some(now + Duration::from_secs(60));
        }
        assert!(pick_exits(&book, now, 4).is_empty());
        assert!(pick_exits(&[], now, 2).is_empty());
    }

    #[test]
    fn recording_smooths_the_time_and_takes_a_repeat_offender_out_of_use() {
        let config = {
            let mut config = config(WarpRoute::Auto);
            config.exits = vec![Arc::from(
                "trojan://secret@203.0.113.77:8443?security=tls&sni=t.example.com#x",
            )];
            config
        };
        let key = load_exits(&config, false);
        let link = Arc::clone(&config.exits[0]);
        let now = Instant::now();
        record_exit(key, &link, Ok(Duration::from_millis(400)), now);
        record_exit(key, &link, Ok(Duration::from_millis(800)), now);
        let (ms, failures) = {
            let books = lock(&EXITS);
            let state = &books[&key][0];
            (state.ms.unwrap(), state.failures)
        };
        assert!((ms - 520.0).abs() < 1.0, "{ms}");
        assert_eq!(failures, 0);
        record_exit(key, &link, Err(()), now);
        assert!(
            lock(&EXITS)[&key][0].usable(now),
            "one failure is not enough"
        );
        record_exit(key, &link, Err(()), now);
        assert!(!lock(&EXITS)[&key][0].usable(now));
        // A success brings it back.
        record_exit(key, &link, Ok(Duration::from_millis(500)), now);
        assert!(lock(&EXITS)[&key][0].usable(now));
    }
}
