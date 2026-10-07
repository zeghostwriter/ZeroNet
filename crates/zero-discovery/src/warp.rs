//! Getting a Cloudflare WARP account: register a device, then enroll the key
//! the MASQUE tunnel authenticates with.
//!
//! Two calls to the WARP API make an account:
//!
//! 1. `POST /reg` with a fresh WireGuard public key. The reply carries the
//!    device id and its bearer token, the tunnel addresses, the `client_id`
//!    WireGuard uses as its three reserved bytes, and Cloudflare's WireGuard
//!    key.
//! 2. `PATCH /reg/<id>` with a fresh ECDSA P-256 public key, marked
//!    `tunnel_type: masque`. The reply's peer key is the one the MASQUE edge
//!    proves itself with, which the client pins.
//!
//! Every private key is made here and never leaves the device; only public
//! halves are sent. From Iran TLS to `api.cloudflareclient.com` is dropped by
//! SNI, so the API base can be a relay (a Worker that forwards exactly these
//! calls) reached under a name that passes; the relay authenticates the caller
//! with one header and is handed nothing but public keys.
//!
//! An account whose device refuses the MASQUE key still works over WireGuard,
//! so that step failing is reported but is not fatal.

use std::net::IpAddr;
use std::time::Duration;

use base64::Engine as _;
use serde_json::{json, Value};
use zero_net::fetch::{send_with_headers, FetchError, FetchLimits};
use zero_transport::masque::MasqueKey;

/// The API as the official Android client calls it, with the request shape a
/// browser-less client gets answers with.
pub const DIRECT_BASE: &str = "https://api.cloudflareclient.com/v0a4005";
const USER_AGENT: &str = "insomnia/13.0.2";
/// The port WARP's WireGuard endpoint listens on.
const WIREGUARD_PORT: u16 = 2408;
/// How long the bootstrap gives a direct attempt before it decides the
/// service is out of reach from here and a server has to be borrowed.
pub const DIRECT_PROBE: Duration = Duration::from_secs(6);
/// AmneziaWG junk: a few short packets before the first real one, which some
/// filters that drop a bare WireGuard handshake let through.
const JUNK: (u16, u16, u16) = (4, 40, 70);
/// Bytes of the API responses that are read.
const MAX_RESPONSE: usize = 64 * 1024;

/// Where the API is reached.
#[derive(Debug, Clone)]
pub struct Api {
    /// `https://api.cloudflareclient.com/v0a4005`, or a relay's `…/warp`.
    pub base: String,
    /// Extra headers every call carries (a relay's credential).
    pub headers: Vec<(String, String)>,
    pub timeout: Duration,
    /// An HTTP proxy to reach the service through (`CONNECT`), such as the
    /// app's own listener while a tunnel is up.
    pub proxy: Option<std::net::SocketAddr>,
}

impl Api {
    pub fn direct() -> Self {
        Self {
            base: DIRECT_BASE.to_string(),
            headers: Vec::new(),
            timeout: Duration::from_secs(20),
            proxy: None,
        }
    }

    /// The API itself, reached through the HTTP proxy at `proxy`.
    pub fn through(proxy: std::net::SocketAddr) -> Self {
        Self {
            proxy: Some(proxy),
            ..Self::direct()
        }
    }

    /// A relay at `base` (`https://<worker>/<path>/warp`) that wants
    /// `X-Zray-Auth: <credential>`.
    pub fn relay(base: &str, credential: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            headers: vec![("X-Zray-Auth".into(), credential.into())],
            timeout: Duration::from_secs(20),
            proxy: None,
        }
    }

    /// The same API with a shorter deadline.
    ///
    /// The bootstrap asks "can Cloudflare be reached from here at all?" before
    /// it decides to borrow a server for the trip. A filtered address accepts
    /// the connection and then says nothing, so without a short deadline that
    /// question would cost the full registration timeout every time.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// A registered device.
#[derive(Debug, Clone)]
pub struct Account {
    pub device_id: String,
    pub wireguard_private_key: [u8; 32],
    pub wireguard_peer_key: [u8; 32],
    /// WARP's `client_id`: the reserved bytes of every WireGuard message.
    pub reserved: [u8; 3],
    pub wireguard_endpoint: std::net::SocketAddr,
    pub addresses: Vec<IpAddr>,
    /// The MASQUE half, when the device accepted the key.
    pub masque: Option<MasqueAccount>,
}

#[derive(Debug, Clone)]
pub struct MasqueAccount {
    pub private_key: Vec<u8>,
    /// The endpoint key to pin, as the PEM the API returned.
    pub server_public_key: String,
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .ok()
        .or_else(|| {
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(text)
                .ok()
        })
}

/// The body of the registration call.
fn registration_body(public_key: &[u8; 32], tos: &str) -> String {
    json!({
        "install_id": "",
        "fcm_token": "",
        "tos": tos,
        "type": "Android",
        "model": "PC",
        "locale": "en_US",
        "warp_enabled": true,
        "key": b64(public_key),
    })
    .to_string()
}

/// The body of the call that enrolls the MASQUE key (`spki`: DER
/// `SubjectPublicKeyInfo`).
fn enrollment_body(spki: &[u8]) -> String {
    json!({
        "key": b64(spki),
        "key_type": "secp256r1",
        "tunnel_type": "masque",
    })
    .to_string()
}

fn limits(api: &Api) -> FetchLimits {
    FetchLimits {
        max_bytes: MAX_RESPONSE,
        timeout: api.timeout,
        max_redirects: 0,
    }
}

fn headers<'a>(api: &'a Api, bearer: Option<&'a str>) -> Vec<(&'a str, &'a str)> {
    let mut all: Vec<(&str, &str)> = vec![("User-Agent", USER_AGENT)];
    all.extend(api.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    if let Some(bearer) = bearer {
        all.push(("Authorization", bearer));
    }
    all
}

/// One API call, with the reasons a caller can act on turned into words.
async fn call(
    api: &Api,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: &str,
) -> Result<Value, String> {
    let url = format!("{}{path}", api.base);
    let sent = match api.proxy {
        None => {
            send_with_headers(
                method,
                &url,
                "application/json; charset=UTF-8",
                &headers(api, bearer),
                body.as_bytes(),
                &limits(api),
            )
            .await
        }
        Some(proxy) => send_through(proxy, method, &url, api, bearer, body).await,
    };
    let response = sent.map_err(|error| match error {
        FetchError::Status(429) | FetchError::Status(403) => {
            "Cloudflare is limiting new WARP accounts right now; try again in a minute".to_string()
        }
        FetchError::Status(code) => format!("the WARP service answered {code}"),
        // These all mean the exchange went wrong *after* the service was
        // reached. Calling them unreachable would send the caller off to
        // borrow a server for the trip, and the tunnel would not change the
        // answer, so they are reported as what they are.
        FetchError::Url(what) => format!("the WARP address is not usable: {what}"),
        FetchError::Protocol(what) => format!("the WARP service sent something odd: {what}"),
        FetchError::TooManyRedirects => "the WARP service redirected too many times".to_string(),
        FetchError::Truncated { .. } => "the WARP service's reply was cut short".to_string(),
        FetchError::TooLarge { .. } => "the WARP service's reply was too big".to_string(),
        // What is left is a failure to get there at all: no socket, no TLS,
        // no answer in time. That, and only that, is what a borrowed server
        // can fix, so it is the only thing under the marker below.
        other => format!("could not reach the WARP service: {other}"),
    })?;
    serde_json::from_slice(&response).map_err(|_| "the WARP service sent something odd".to_string())
}

/// One call through an HTTP proxy: `CONNECT` to the service, TLS inside the
/// tunnel it opens, then the request.
async fn send_through(
    proxy: std::net::SocketAddr,
    method: &str,
    url: &str,
    api: &Api,
    bearer: Option<&str>,
    body: &str,
) -> Result<Vec<u8>, FetchError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Anything that stops the tunnel carrying the request is reported as a
    // failure to reach the service *through* it, which is what it is: the
    // server on the other end is not carrying traffic, so a different one is
    // worth trying. Reporting these as a malformed reply instead would tell
    // the caller the service answered, which it never did.
    let failure = |what: String| FetchError::Connect {
        host: "the local proxy".into(),
        source: std::io::Error::other(what),
    };
    let parsed = url::Url::parse(url).map_err(|error| FetchError::Url(error.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| FetchError::Url("no host".into()))?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let mut stream = tokio::time::timeout(api.timeout, tokio::net::TcpStream::connect(proxy))
        .await
        .map_err(|_| FetchError::Timeout(api.timeout))?
        .map_err(|error| failure(error.to_string()))?;
    stream
        .write_all(
            format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
        )
        .await
        .map_err(|error| failure(error.to_string()))?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 4096
            || tokio::time::timeout(api.timeout, stream.read(&mut byte))
                .await
                .map_err(|_| FetchError::Timeout(api.timeout))?
                .map_err(|error| failure(error.to_string()))?
                == 0
        {
            return Err(failure("it closed the connection".into()));
        }
        head.push(byte[0]);
    }
    if !head.starts_with(b"HTTP/1.1 200") && !head.starts_with(b"HTTP/1.0 200") {
        return Err(failure("it refused the connection".into()));
    }
    let name = rustls_pki_types::ServerName::try_from(host.clone())
        .map_err(|error| FetchError::Url(error.to_string()))?;
    let tls = tokio_rustls::TlsConnector::from(tls_config())
        .connect(name, stream)
        .await
        .map_err(|source| FetchError::Tls { host, source })?;
    zero_net::fetch::send_over(
        tls,
        method,
        url,
        "application/json; charset=UTF-8",
        &headers(api, bearer),
        body.as_bytes(),
        &limits(api),
    )
    .await
}

fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<std::sync::Arc<rustls::ClientConfig>> =
        std::sync::OnceLock::new();
    std::sync::Arc::clone(CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        std::sync::Arc::new(
            rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }))
}

/// What the registration reply holds.
struct Registered {
    device_id: String,
    token: String,
    reserved: [u8; 3],
    peer_key: [u8; 32],
    endpoint: std::net::SocketAddr,
    addresses: Vec<IpAddr>,
}

fn parse_registration(reply: &Value) -> Result<Registered, String> {
    let odd = || "the WARP service reply is missing something".to_string();
    let config = reply.get("config").ok_or_else(odd)?;
    let peer = config
        .get("peers")
        .and_then(Value::as_array)
        .and_then(|peers| peers.first())
        .ok_or_else(odd)?;
    let reserved: [u8; 3] = config
        .get("client_id")
        .and_then(Value::as_str)
        .and_then(unb64)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(odd)?;
    let peer_key: [u8; 32] = peer
        .get("public_key")
        .and_then(Value::as_str)
        .and_then(unb64)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(odd)?;
    // The endpoint names a host; the address next to it is what to dial, so
    // that no name has to be resolved on a network that lies about names.
    let ip = peer
        .get("endpoint")
        .and_then(|endpoint| endpoint.get("v4"))
        .and_then(Value::as_str)
        .and_then(|v4| v4.rsplit_once(':').map_or(Some(v4), |(host, _)| Some(host)))
        .and_then(|host| host.parse::<IpAddr>().ok())
        .ok_or_else(odd)?;
    // The service lists many ports, starting with an arbitrary one; 2408 is
    // the one WARP's WireGuard is documented on.
    let ports: Vec<u16> = peer
        .get("endpoint")
        .and_then(|endpoint| endpoint.get("ports"))
        .and_then(Value::as_array)
        .map(|ports| {
            ports
                .iter()
                .filter_map(|port| u16::try_from(port.as_u64()?).ok())
                .collect()
        })
        .unwrap_or_default();
    let port = if ports.contains(&WIREGUARD_PORT) || ports.is_empty() {
        WIREGUARD_PORT
    } else {
        ports[0]
    };
    let interface = config
        .get("interface")
        .and_then(|interface| interface.get("addresses"))
        .ok_or_else(odd)?;
    let addresses: Vec<IpAddr> = ["v4", "v6"]
        .iter()
        .filter_map(|family| interface.get(*family)?.as_str()?.parse().ok())
        .collect();
    if addresses.is_empty() {
        return Err(odd());
    }
    Ok(Registered {
        device_id: reply
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(odd)?
            .to_string(),
        token: reply
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(odd)?
            .to_string(),
        reserved,
        peer_key,
        endpoint: std::net::SocketAddr::new(ip, port),
        addresses,
    })
}

/// The PEM key of the MASQUE endpoint in an enrollment reply.
fn masque_server_key(reply: &Value) -> Option<String> {
    reply
        .get("config")?
        .get("peers")?
        .as_array()?
        .first()?
        .get("public_key")?
        .as_str()
        .filter(|key| zero_transport::masque::server_point_from_pem(key).is_ok())
        .map(str::to_string)
}

/// The moment of consent the API asks for, in its own format.
fn tos_now() -> String {
    // RFC 3339 with milliseconds, in UTC.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = now.as_secs();
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
        now.subsec_millis()
    )
}

/// Register a new device and enroll its MASQUE key.
///
/// Registering creates an account with Cloudflare; callers do it because the
/// user asked, and say so.
pub async fn register(api: &Api) -> Result<Account, String> {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
    let public = x25519_dalek::PublicKey::from(&secret);
    let reply = call(
        api,
        "POST",
        "/reg",
        None,
        &registration_body(public.as_bytes(), &tos_now()),
    )
    .await?;
    let registered = parse_registration(&reply)?;

    let masque = match MasqueKey::generate() {
        Ok(key) => {
            let bearer = format!("Bearer {}", registered.token);
            let path = format!("/reg/{}", registered.device_id);
            match call(
                api,
                "PATCH",
                &path,
                Some(&bearer),
                &enrollment_body(&key.spki_der()),
            )
            .await
            {
                Ok(reply) => masque_server_key(&reply).map(|server_public_key| MasqueAccount {
                    private_key: key.pkcs8().to_vec(),
                    server_public_key,
                }),
                Err(error) => {
                    tracing::debug!(%error, "MASQUE key was not enrolled");
                    None
                }
            }
        }
        Err(error) => {
            tracing::debug!(%error, "no MASQUE key");
            None
        }
    };

    Ok(Account {
        device_id: registered.device_id,
        wireguard_private_key: secret.to_bytes(),
        wireguard_peer_key: registered.peer_key,
        reserved: registered.reserved,
        wireguard_endpoint: registered.endpoint,
        addresses: registered.addresses,
        masque,
    })
}

impl Account {
    /// The settings of a `warp` outbound for this account (see
    /// `zero_config::xray_json`), routed `route`.
    pub fn outbound_settings(&self, route: &str) -> Value {
        let mut settings = json!({
            "route": route,
            "wireguard": {
                "privateKey": b64(&self.wireguard_private_key),
                "peerPublicKey": b64(&self.wireguard_peer_key),
                "endpoint": self.wireguard_endpoint.to_string(),
                "address": self.addresses.iter().map(IpAddr::to_string).collect::<Vec<_>>(),
                "reserved": self.reserved,
                "persistentKeepalive": 25,
                "amnezia": {"jc": JUNK.0, "jmin": JUNK.1, "jmax": JUNK.2},
            },
        });
        if let Some(masque) = &self.masque {
            settings["masque"] = json!({
                "privateKey": b64(&masque.private_key),
                "serverPublicKey": masque.server_public_key,
                "address": self.addresses.iter().map(IpAddr::to_string).collect::<Vec<_>>(),
            });
        }
        settings
    }

    /// A `warp://` link to import into any front end.
    pub fn link(&self, route: &str) -> String {
        zero_config::share_link::warp_link(&self.outbound_settings(route), "WARP")
    }
}

/// Find servers worth listing on a WARP account for `order`, from the public
/// feeds, best first: up to `want` of them, trying at most `sample`, within
/// `budget`.
///
/// The two orders need different servers. [`HybridMode::WarpFirst`] dials a
/// server from inside the tunnel, so candidates are tested *through* it — a
/// server the local network blocks outright can still be reached from
/// Cloudflare's network, which finds working servers where a direct test
/// finds none. [`HybridMode::ServerFirst`] dials the server first and reaches
/// Cloudflare through it, so candidates are tested directly from here, and no
/// tunnel is needed for the search at all.
///
/// Feeds are read tier by tier, and only until there are enough candidates to
/// sample. Servers that cannot carry a stream onward, and unencrypted ones,
/// are skipped.
///
/// [`HybridMode::WarpFirst`]: zero_config::HybridMode::WarpFirst
/// [`HybridMode::ServerFirst`]: zero_config::HybridMode::ServerFirst
pub async fn gather_exits(
    link: &str,
    order: zero_config::HybridMode,
    want: usize,
    sample: usize,
    budget: Duration,
    progress: impl Fn(&str),
) -> Result<Vec<String>, String> {
    use futures::stream::{FuturesUnordered, StreamExt};
    use rand::seq::SliceRandom;
    let deadline = tokio::time::Instant::now() + budget;
    let parsed = zero_config::parse_link(link)?;
    let zero_config::OutboundProtocol::AmneziaWireguard(warp) = &parsed.outbound.protocol else {
        return Err("that is not a warp:// link".into());
    };
    // Through the tunnel for the tunnel-first order, straight out otherwise.
    let tunnel = if order == zero_config::HybridMode::WarpFirst {
        let wireguard_peer = warp
            .wireguard_usable()
            .then(|| {
                warp.address
                    .as_ip()
                    .map(|ip| std::net::SocketAddr::new(ip, warp.port))
            })
            .flatten();
        let tunnel = zero_runtime::warp::tunnel(warp, wireguard_peer).await?;
        progress(&format!("Connected to WARP ({}).", tunnel.route().name()));
        Some(tunnel)
    } else {
        None
    };
    let resolver = zero_dns::Resolver::new(zero_config::dns::DnsSettings::default());

    let mut candidates: Vec<crate::link::Candidate> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    'tiers: for tier in 0..=2 {
        for source in crate::sources::enabled(&[], 2)
            .into_iter()
            .filter(|source| source.tier == tier)
        {
            let result = crate::feed::fetch_feed(&source, None, Duration::from_secs(25)).await;
            let Some(body) = result.body else {
                continue;
            };
            let (found, _) = crate::link::parse_feed_candidates(&body, &seen);
            for candidate in found {
                let encrypted = !matches!(
                    candidate.outbound.stream.security,
                    zero_config::Security::None
                );
                if candidate.outbound.chainable()
                    && encrypted
                    && seen.insert(candidate.info.key.clone())
                {
                    candidates.push(candidate);
                }
            }
            if candidates.len() >= sample * 2 {
                break 'tiers;
            }
        }
    }
    candidates.shuffle(&mut rand::thread_rng());
    candidates.truncate(sample);
    progress(&format!(
        "Trying {} servers {}…",
        candidates.len(),
        if tunnel.is_some() {
            "through the tunnel"
        } else {
            "directly"
        }
    ));

    let mut pending = FuturesUnordered::new();
    let mut queue = candidates.into_iter();
    let mut good: Vec<(Duration, String)> = Vec::new();
    loop {
        while pending.len() < 8 {
            let Some(candidate) = queue.next() else { break };
            let (tunnel, resolver) = (&tunnel, &resolver);
            pending.push(async move {
                let limit = Duration::from_secs(10);
                let took = match tunnel {
                    Some(tunnel) => {
                        zero_runtime::warp::test_exit(tunnel, &candidate.outbound, limit).await
                    }
                    None => {
                        zero_runtime::warp::test_carrier(&candidate.outbound, resolver, limit).await
                    }
                };
                (candidate, took)
            });
        }
        let Ok(next) = tokio::time::timeout_at(deadline, pending.next()).await else {
            break;
        };
        let Some((candidate, took)) = next else { break };
        if let Ok(took) = took {
            progress(&format!(
                "  {} ms  {}",
                took.as_millis(),
                candidate.info.key
            ));
            good.push((took, candidate.info.link.clone()));
            if good.len() >= want {
                break;
            }
        }
    }
    good.sort_by_key(|(took, _)| *took);
    Ok(good.into_iter().map(|(_, link)| link).collect())
}

/// Register an account through `api` and return its `warp://` link.
///
/// This is the one place a device is registered, so `register_anywhere` and
/// the bootstrap's direct-then-tunnel attempts all make the same account the
/// same way. `progress` hears the two lines the person sees.
pub async fn register_with(api: &Api, progress: &impl Fn(&str)) -> Result<String, String> {
    let account = register(api).await?;
    progress("Account created. Keys made on this device.");
    Ok(account.link("auto"))
}

/// Register an account by whichever way of reaching the service works from
/// here: through a running tunnel's HTTP proxy first (the API is filtered by
/// name on some networks, and a tunnel is the one path there that always
/// works), then a relay the person set up, then straight out when `direct`.
/// Returns the account's `warp://` link. `progress` hears what is happening.
pub async fn register_anywhere(
    tunnel: Option<std::net::SocketAddr>,
    relay: Option<(String, String)>,
    direct: bool,
    progress: &impl Fn(&str),
) -> Result<String, String> {
    let mut ways = Vec::new();
    if let Some(proxy) = tunnel {
        ways.push(Api::through(proxy));
    }
    if let Some((base, auth)) = relay {
        ways.push(Api::relay(&base, &auth));
    }
    if direct {
        ways.push(Api::direct());
    }
    progress("Asking Cloudflare for an account…");
    let mut last = String::from("no way to reach the WARP service");
    for api in ways {
        match register_with(&api, progress).await {
            Ok(link) => return Ok(link),
            Err(error) => last = error,
        }
    }
    Err(if is_unreachable(&last) {
        format!("{last}. Connect to a working server first, then try again.")
    } else {
        last
    })
}

/// Whether a registration failure means the service could not be reached from
/// here, rather than answering and refusing.
///
/// The bootstrap turns on this: only an unreachable service is worth a second
/// try through a borrowed server. A rate limit, an HTTP error, or a malformed
/// reply all prove the service *was* reached, so a tunnel would change
/// nothing and the failure is reported as it is.
///
/// The strings it reads are the ones [`call`] builds.
pub fn is_unreachable(error: &str) -> bool {
    error.starts_with("could not reach the WARP service")
}

/// What a host asks a WARP job for.
#[derive(Debug, serde::Deserialize)]
pub struct WarpRequest {
    /// `host:port` of a running tunnel's HTTP proxy, to reach the service
    /// through.
    #[serde(default)]
    pub proxy: Option<String>,
    /// Try the service directly, too. On unless a host says otherwise.
    #[serde(default = "yes")]
    pub direct: bool,
    /// The bootstrap's first look: try the service directly, with a short
    /// deadline, and nothing else. The reply says whether it was reachable at
    /// all, which is what decides between making the account now and
    /// borrowing a server for the trip.
    #[serde(default)]
    pub quick: bool,
    /// The order the account is written with and its servers searched for:
    /// `server-first` (hybrid, the default) or `warp-first` (reverse hybrid).
    #[serde(default)]
    pub order: Option<String>,
    /// How many servers to look for, how many to try, and for how long.
    #[serde(default = "default_want")]
    pub want: usize,
    #[serde(default = "default_sample")]
    pub sample: usize,
    #[serde(default = "default_budget_ms")]
    pub budget_ms: u64,
}

fn yes() -> bool {
    true
}
fn default_want() -> usize {
    4
}
fn default_sample() -> usize {
    100
}
fn default_budget_ms() -> u64 {
    60_000
}

/// The WARP job a mobile host runs: register an account, look for servers
/// that work through it, and report. Events: `{"t":"step","line":…}` as it
/// goes, then one `{"t":"done","ok":…}` carrying the account's link, how many
/// servers were found, how it connects and its fingerprint, or the reason it
/// failed. Cancelling ends it early with `ok: false`.
pub async fn warp_job(
    request: WarpRequest,
    sink: crate::events::EventSink,
    cancel: tokio_util::sync::CancellationToken,
) -> crate::discover::EndReason {
    use crate::discover::EndReason;
    let progress = {
        let sink = sink.clone();
        move |line: &str| sink.emit(json!({"t": "step", "line": line}))
    };
    let work = async {
        let tunnel = request
            .proxy
            .as_deref()
            .and_then(|proxy| proxy.parse::<std::net::SocketAddr>().ok());
        // A quick look goes straight out with a short deadline, and nothing
        // else: it is the question "is Cloudflare reachable from here?", and
        // a relay or a fallback would answer a different one.
        let link = if request.quick {
            progress("Asking Cloudflare for an account…");
            register_with(&Api::direct().with_timeout(DIRECT_PROBE), &progress).await?
        } else {
            register_anywhere(tunnel, None, request.direct, &progress).await?
        };
        let order = match request.order.as_deref() {
            Some("warp-first") => zero_config::HybridMode::WarpFirst,
            _ => zero_config::HybridMode::ServerFirst,
        };
        // The account is useful without servers, so finding none is not a
        // failure.
        let exits = gather_exits(
            &link,
            order,
            request.want.clamp(1, 20),
            request.sample.clamp(1, 400),
            Duration::from_millis(request.budget_ms.clamp(1_000, 300_000)),
            &progress,
        )
        .await
        .unwrap_or_default();
        let link = if exits.is_empty() {
            link
        } else {
            link_with_exits(&link, &exits, order, false).unwrap_or(link)
        };
        let route = summarize(&link).map_or("auto", |summary| summary.route);
        Ok::<_, String>(json!({
            "t": "done", "ok": true, "link": link, "exits": exits.len(),
            "route": route, "fingerprint": fingerprint(&link),
        }))
    };
    tokio::select! {
        result = work => match result {
            Ok(done) => {
                sink.emit(done);
                EndReason::Enough
            }
            Err(error) => {
                // `unreachable` is what tells a host to bring a server up and
                // try again through it, rather than reporting the failure.
                let unreachable = is_unreachable(&error);
                sink.emit(json!({
                    "t": "done", "ok": false, "error": error, "unreachable": unreachable,
                }));
                EndReason::Exhausted
            }
        },
        () = cancel.cancelled() => {
            sink.emit(json!({"t": "done", "ok": false, "error": "cancelled", "unreachable": false}));
            EndReason::Cancelled
        }
    }
}

/// The settings inside a `warp://` link, and its remark.
fn open_link(link: &str) -> Result<(Value, String), String> {
    use base64::Engine as _;
    let rest = link
        .trim()
        .strip_prefix(zero_config::share_link::WARP_LINK_SCHEME)
        .ok_or("that is not a warp:// link")?;
    let (body, remark) = rest.split_once('#').unwrap_or((rest, ""));
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body.trim_end_matches('='))
        .map_err(|error| format!("the link is not base64: {error}"))?;
    let settings: Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("the link is not JSON: {error}"))?;
    if !settings.is_object() {
        return Err("the link does not hold an account".into());
    }
    let remark = percent_encoding::percent_decode_str(remark)
        .decode_utf8_lossy()
        .into_owned();
    Ok((settings, remark))
}

/// A `warp://` link for `settings`, checked to import.
fn close_link(settings: &Value, remark: &str) -> Result<String, String> {
    let rebuilt = zero_config::share_link::warp_link(settings, remark);
    zero_config::parse_link(&rebuilt)?;
    Ok(rebuilt)
}

/// `link` (a `warp://` link) with `exits` and the order they go in: the same
/// account, keys and routes, plus the servers it may take part in.
///
/// Both the order and the sub-choice are written every time, so a link that is
/// saved and read back says the same thing it did when it was written.
pub fn link_with_exits(
    link: &str,
    exits: &[String],
    hybrid: zero_config::HybridMode,
    prefer_exit: bool,
) -> Result<String, String> {
    let (mut settings, remark) = open_link(link)?;
    if let Some(object) = settings.as_object_mut() {
        object.insert("exits".into(), json!(exits));
        write_order(object, hybrid, prefer_exit);
    }
    close_link(&settings, &remark)
}

/// `link` with only the order changed, keeping the account and its servers.
/// The order is kept even with no servers listed yet, so a later search looks
/// for the right kind (see [`gather_exits`]).
pub fn link_with_order(
    link: &str,
    hybrid: zero_config::HybridMode,
    prefer_exit: bool,
) -> Result<String, String> {
    let (mut settings, remark) = open_link(link)?;
    let has_exits = settings
        .get("exits")
        .and_then(Value::as_array)
        .is_some_and(|exits| !exits.is_empty());
    if prefer_exit && !has_exits {
        return Err("Find servers for this account first.".into());
    }
    if let Some(object) = settings.as_object_mut() {
        write_order(object, hybrid, prefer_exit);
    }
    close_link(&settings, &remark)
}

/// Write the order, always explicitly, so a saved link reads back the same.
fn write_order(
    object: &mut serde_json::Map<String, Value>,
    hybrid: zero_config::HybridMode,
    prefer_exit: bool,
) {
    object.insert("mode".into(), json!(hybrid.as_str()));
    if hybrid == zero_config::HybridMode::WarpFirst && prefer_exit {
        object.insert("preferExit".into(), json!(true));
    } else {
        object.remove("preferExit");
    }
}

/// A short fingerprint of an account, for showing to the person who owns it:
/// the first 16 bytes of a BLAKE3 hash over the *public* keys the account was
/// made with, as eight groups of four hex digits. Nothing secret goes into
/// what is shown, and the same account always gives the same fingerprint.
pub fn fingerprint(link: &str) -> Option<String> {
    let (settings, _) = open_link(link).ok()?;
    let mut hasher = blake3::Hasher::new();
    let mut any = false;
    if let Some(private) = settings
        .pointer("/wireguard/privateKey")
        .and_then(Value::as_str)
        .and_then(unb64)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    {
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
        hasher.update(public.as_bytes());
        any = true;
    }
    if let Some(key) = settings
        .pointer("/masque/privateKey")
        .and_then(Value::as_str)
        .and_then(unb64)
        .and_then(|der| MasqueKey::from_der(&der).ok())
    {
        hasher.update(&key.spki_der());
        any = true;
    }
    if !any {
        return None;
    }
    let digest = hasher.finalize();
    let hex = hex::encode_upper(&digest.as_bytes()[..16]);
    Some(
        hex.as_bytes()
            .chunks(4)
            .map(|group| String::from_utf8_lossy(group).into_owned())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// What a `warp://` link is set to, for showing to the person who owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSummary {
    /// Servers listed as exits.
    pub exits: usize,
    /// Which order the tunnel and those servers go in.
    pub hybrid: zero_config::HybridMode,
    /// Within the tunnel-first order, a server carries first.
    pub prefer_exit: bool,
    /// `auto`, `wireguard`, `masque-h2` or `masque-h3`.
    pub route: &'static str,
}

/// The summary of `link`, or `None` when it is not a `warp://` link.
pub fn summarize(link: &str) -> Option<LinkSummary> {
    let parsed = zero_config::parse_link(link.trim()).ok()?;
    let zero_config::OutboundProtocol::AmneziaWireguard(warp) = &parsed.outbound.protocol else {
        return None;
    };
    link.trim()
        .starts_with(zero_config::share_link::WARP_LINK_SCHEME)
        .then_some(LinkSummary {
            exits: warp.exits.len(),
            hybrid: warp.hybrid,
            prefer_exit: warp.prefer_exit,
            route: warp.route.name(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A reply shaped like the API's, for `id` and `token`, with the given
    /// peer key (base64 for WireGuard, PEM after enrollment).
    fn reply(peer_key: &str) -> Value {
        json!({
            "id": "0000-1111",
            "token": "secret-token",
            "config": {
                "client_id": b64(&[9, 8, 7]),
                "peers": [{
                    "public_key": peer_key,
                    "endpoint": {
                        "v4": "162.159.192.1:0",
                        "v6": "[2606:4700:d0::a29f:c001]:0",
                        "host": "engage.cloudflareclient.com:2408",
                        "ports": [500, 2408]
                    }
                }],
                "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8a36::1"}}
            }
        })
    }

    #[test]
    fn the_registration_reply_gives_everything_a_tunnel_needs() {
        let registered = parse_registration(&reply(&b64(&[5u8; 32]))).unwrap();
        assert_eq!(registered.device_id, "0000-1111");
        assert_eq!(registered.reserved, [9, 8, 7]);
        assert_eq!(registered.peer_key, [5u8; 32]);
        // The address next to the host is dialled, on the WireGuard port.
        assert_eq!(registered.endpoint.to_string(), "162.159.192.1:2408");
        assert_eq!(registered.addresses.len(), 2);
    }

    #[test]
    fn a_reply_missing_a_field_is_refused_in_words() {
        for missing in ["client_id", "peers", "interface"] {
            let mut value = reply(&b64(&[5u8; 32]));
            value["config"].as_object_mut().unwrap().remove(missing);
            let error = parse_registration(&value).err().expect(missing);
            assert!(error.contains("missing"), "{error}");
        }
        let mut value = reply("not-base64!!");
        assert!(parse_registration(&value).is_err());
        value = reply(&b64(&[1u8; 31]));
        assert!(parse_registration(&value).is_err());
    }

    #[test]
    fn only_public_keys_go_into_a_request() {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let public = x25519_dalek::PublicKey::from(&secret);
        let body = registration_body(public.as_bytes(), "2026-09-29T10:00:00.000Z");
        assert!(body.contains(&b64(public.as_bytes())));
        assert!(!body.contains(&b64(&secret.to_bytes())));
        let key = MasqueKey::generate().unwrap();
        let enroll = enrollment_body(&key.spki_der());
        assert!(enroll.contains("secp256r1") && enroll.contains("masque"));
        assert!(!enroll.contains(&b64(key.pkcs8())));
    }

    #[test]
    fn the_consent_time_is_rfc_3339() {
        let now = tos_now();
        assert_eq!(now.len(), 24, "{now}");
        assert!(now.ends_with('Z') && now.as_bytes()[10] == b'T');
        assert!(now.starts_with("20"));
    }

    /// A stand-in API on loopback: answers the two calls of an account and
    /// records what it was sent.
    async fn serve(masque_ok: bool) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = std::sync::Arc::clone(&seen);
        let server_key = MasqueKey::generate().unwrap();
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            b64(&server_key.spki_der())
        );
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    request.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&request).into_owned();
                    let Some(end) = text.find("\r\n\r\n") else {
                        continue;
                    };
                    let length = text
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length || n == 0 {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&request).into_owned();
                log.lock().unwrap().push(text.clone());
                let (status, body) = if text.starts_with("POST /reg ") {
                    ("200 OK", reply(&b64(&[5u8; 32])).to_string())
                } else if text.starts_with("PATCH /reg/0000-1111 ") && masque_ok {
                    ("200 OK", reply(&pem).to_string())
                } else {
                    ("403 Forbidden", "{}".to_string())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        (base, seen)
    }

    #[tokio::test]
    async fn an_account_is_registered_then_its_masque_key_enrolled() {
        let (base, seen) = serve(true).await;
        let api = Api {
            base,
            headers: vec![("X-Zray-Auth".into(), "credential".into())],
            timeout: Duration::from_secs(5),
            proxy: None,
        };
        let account = register(&api).await.unwrap();
        assert_eq!(account.reserved, [9, 8, 7]);
        assert!(account.masque.is_some());
        let requests = seen.lock().unwrap().clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("POST /reg HTTP/1.1"));
        assert!(requests[0].contains("X-Zray-Auth: credential"));
        assert!(requests[0].contains("User-Agent: insomnia"));
        // The bearer token appears only on the call that needs it.
        assert!(!requests[0].contains("Authorization"));
        assert!(requests[1].starts_with("PATCH /reg/0000-1111 HTTP/1.1"));
        assert!(requests[1].contains("Authorization: Bearer secret-token"));
        assert!(requests[1].contains("secp256r1"));

        // The account becomes an outbound that parses, with both halves.
        let link = account.link("auto");
        let parsed = zero_config::parse_link(&link).unwrap();
        let zero_config::OutboundProtocol::AmneziaWireguard(warp) = &parsed.outbound.protocol
        else {
            panic!("expected a WARP outbound")
        };
        assert!(warp.wireguard_usable() && warp.masque.is_some());
        assert_eq!(warp.reserved, [9, 8, 7]);
        assert_eq!(warp.junk_count, JUNK.0);
        assert_eq!(warp.tunnel_address.to_string(), "172.16.0.2");
    }

    #[tokio::test]
    async fn a_device_that_refuses_the_masque_key_still_gets_a_wireguard_account() {
        let (base, _) = serve(false).await;
        let api = Api {
            base,
            headers: Vec::new(),
            timeout: Duration::from_secs(5),
            proxy: None,
        };
        let account = register(&api).await.unwrap();
        assert!(account.masque.is_none());
        let parsed = zero_config::parse_link(&account.link("auto")).unwrap();
        let zero_config::OutboundProtocol::AmneziaWireguard(warp) = &parsed.outbound.protocol
        else {
            panic!("expected a WARP outbound")
        };
        assert!(warp.wireguard_usable() && warp.masque.is_none());
    }

    #[tokio::test]
    async fn a_service_that_limits_registration_says_so_plainly() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut sink = [0u8; 4096];
                let _ = socket.read(&mut sink).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        });
        let api = Api {
            base,
            headers: Vec::new(),
            timeout: Duration::from_secs(5),
            proxy: None,
        };
        let error = register(&api).await.err().unwrap();
        assert!(error.contains("try again in a minute"), "{error}");
    }

    /// A port on the loopback that nothing is listening on, standing in for a
    /// local proxy with nothing behind it.
    ///
    /// Binding a port and dropping the listener is not enough on its own: the
    /// kernel is free to hand the same port straight back to another test
    /// running beside this one, and then the connect succeeds, the failure
    /// under test never happens, and the assertion fails for no real reason.
    /// So a port is only accepted once a connect to it has actually been
    /// refused, which is the state the callers are trying to arrange.
    async fn a_closed_port() -> std::net::SocketAddr {
        for _ in 0..50 {
            let addr = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            // The listener goes out of scope here on purpose: nothing should
            // be there, and that is what has to be true before returning.
            if tokio::net::TcpStream::connect(addr).await.is_err() {
                return addr;
            }
        }
        panic!("no port on the loopback stayed closed");
    }

    #[tokio::test]
    async fn a_proxy_that_refuses_or_is_not_there_is_reported_plainly() {
        // Refuses the CONNECT.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut sink = [0u8; 4096];
                let _ = socket.read(&mut sink).await;
                assert!(String::from_utf8_lossy(&sink)
                    .starts_with("CONNECT api.cloudflareclient.com:443"));
                let _ = socket
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });
        let mut api = Api::through(proxy);
        api.timeout = Duration::from_secs(5);
        let error = register(&api).await.err().unwrap();
        assert!(error.contains("local proxy"), "{error}");
        assert!(error.contains("refused the connection"), "{error}");
        // Nothing listens.
        let closed = a_closed_port().await;
        let mut api = Api::through(closed);
        api.timeout = Duration::from_secs(5);
        let error = register(&api).await.err().unwrap();
        assert!(error.contains("local proxy"), "{error}");
        // A proxy with nothing behind it reads as a failure to reach the
        // service, which is what it is: the borrowed server carried nothing.
        assert!(is_unreachable(&error), "{error}");
    }

    /// The replies the real service sent, kept in a usque-style account file
    /// (`register` and `masque`). Run with `ZRAY_WARP_TEST_ACCOUNT` set.
    #[test]
    #[ignore = "needs a saved WARP account file"]
    fn the_real_service_replies_parse() {
        let Some(path) = std::env::var_os("ZRAY_WARP_TEST_ACCOUNT") else {
            return;
        };
        let file: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let registered = parse_registration(&file["register"]).unwrap();
        assert_eq!(registered.reserved.len(), 3);
        assert!(!registered.addresses.is_empty());
        // A port from the service's own list (2408 when it offers it).
        assert_ne!(registered.endpoint.port(), 0);
        let pem = masque_server_key(&file["masque"]).expect("a P-256 endpoint key");
        assert!(pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn exits_can_be_added_to_an_account_link() {
        let account = Account {
            device_id: "d".into(),
            wireguard_private_key: [1; 32],
            wireguard_peer_key: [2; 32],
            reserved: [1, 2, 3],
            wireguard_endpoint: "162.159.192.1:2408".parse().unwrap(),
            addresses: vec!["172.16.0.2".parse().unwrap()],
            masque: None,
        };
        let exits =
            vec!["trojan://secret@203.0.113.9:8443?security=tls&sni=t.example.com#x".to_string()];
        let link = link_with_exits(
            &account.link("auto"),
            &exits,
            zero_config::HybridMode::ServerFirst,
            false,
        )
        .unwrap();
        let parsed = zero_config::parse_link(&link).unwrap();
        assert_eq!(parsed.remark, "WARP");
        let zero_config::OutboundProtocol::AmneziaWireguard(warp) = &parsed.outbound.protocol
        else {
            panic!("expected a WARP outbound")
        };
        assert_eq!(warp.exits.len(), 1);
        assert_eq!(warp.hybrid, zero_config::HybridMode::ServerFirst);
        assert!(warp.wireguard_usable());
        // Not a link, and an exit that cannot follow a tunnel.
        assert!(link_with_exits(
            "vless://x",
            &exits,
            zero_config::HybridMode::ServerFirst,
            false
        )
        .is_err());
        let quic = vec!["hy2://pw@203.0.113.9:443?sni=h.example.com#q".to_string()];
        assert!(link_with_exits(
            &account.link("auto"),
            &quic,
            zero_config::HybridMode::ServerFirst,
            false
        )
        .is_err());
    }

    #[test]
    fn a_link_can_be_summarised_and_its_order_changed() {
        use zero_config::HybridMode;
        let account = Account {
            device_id: "d".into(),
            wireguard_private_key: [1; 32],
            wireguard_peer_key: [2; 32],
            reserved: [1, 2, 3],
            wireguard_endpoint: "162.159.192.1:2408".parse().unwrap(),
            addresses: vec!["172.16.0.2".parse().unwrap()],
            masque: None,
        };
        let plain = account.link("auto");
        // A fresh account starts tunnel first, with no servers.
        assert_eq!(
            summarize(&plain).unwrap(),
            LinkSummary {
                exits: 0,
                hybrid: HybridMode::WarpFirst,
                prefer_exit: false,
                route: "auto"
            }
        );
        // The order can be chosen before any server is found, so the search
        // looks for the right kind; preferring a server with none is refused.
        let chosen = link_with_order(&plain, HybridMode::ServerFirst, false).unwrap();
        assert_eq!(summarize(&chosen).unwrap().hybrid, HybridMode::ServerFirst);
        assert!(link_with_order(&plain, HybridMode::WarpFirst, true)
            .unwrap_err()
            .contains("Find servers"));
        let exits =
            vec!["trojan://secret@203.0.113.9:8443?security=tls&sni=t.example.com#x".to_string()];
        let with = link_with_exits(&plain, &exits, HybridMode::ServerFirst, false).unwrap();
        let summary = summarize(&with).unwrap();
        assert_eq!(summary.exits, 1);
        assert_eq!(summary.hybrid, HybridMode::ServerFirst);

        // The other order, and its sub-choice, both survive the round trip.
        let flipped = link_with_order(&with, HybridMode::WarpFirst, true).unwrap();
        let summary = summarize(&flipped).unwrap();
        assert_eq!(summary.hybrid, HybridMode::WarpFirst);
        assert!(summary.prefer_exit && summary.exits == 1);
        let back = link_with_order(&flipped, HybridMode::WarpFirst, false).unwrap();
        let summary = summarize(&back).unwrap();
        assert!(!summary.prefer_exit);
        assert_eq!(summary.hybrid, HybridMode::WarpFirst);

        // Not a warp link at all.
        assert!(
            summarize("trojan://secret@203.0.113.9:8443?security=tls&sni=t.example.com").is_none()
        );
    }

    #[test]
    fn the_fingerprint_is_stable_public_and_different_per_account() {
        let make = |seed: u8| Account {
            device_id: "d".into(),
            wireguard_private_key: [seed; 32],
            wireguard_peer_key: [2; 32],
            reserved: [1, 2, 3],
            wireguard_endpoint: "162.159.192.1:2408".parse().unwrap(),
            addresses: vec!["172.16.0.2".parse().unwrap()],
            masque: None,
        };
        let a = fingerprint(&make(1).link("auto")).unwrap();
        assert_eq!(a, fingerprint(&make(1).link("auto")).unwrap());
        assert_ne!(a, fingerprint(&make(9).link("auto")).unwrap());
        // Eight groups of four upper-case hex digits.
        let groups: Vec<&str> = a.split(' ').collect();
        assert_eq!(groups.len(), 8, "{a}");
        assert!(groups.iter().all(|g| g.len() == 4
            && g.bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))));
        // The private key is nowhere in what is shown.
        assert!(!a.contains(&hex::encode_upper([1u8; 4])));
        // The exits do not change it: it names the account, not the servers.
        let exits =
            vec!["trojan://secret@203.0.113.9:8443?security=tls&sni=t.example.com#x".to_string()];
        let with = link_with_exits(
            &make(1).link("auto"),
            &exits,
            zero_config::HybridMode::ServerFirst,
            false,
        )
        .unwrap();
        assert_eq!(fingerprint(&with).unwrap(), a);
        assert!(fingerprint("trojan://secret@203.0.113.9:8443?security=tls").is_none());
    }

    #[test]
    fn a_warp_link_carries_its_fingerprint_to_the_screens_and_other_links_do_not() {
        let account = Account {
            device_id: "d".into(),
            wireguard_private_key: [4; 32],
            wireguard_peer_key: [2; 32],
            reserved: [1, 2, 3],
            wireguard_endpoint: "162.159.192.1:2408".parse().unwrap(),
            addresses: vec!["172.16.0.2".parse().unwrap()],
            masque: None,
        };
        let link = account.link("auto");
        let report = crate::link::parse_links(&format!(
            "{link}\ntrojan://secret@203.0.113.9:8443?security=tls&sni=t.example.com#plain"
        ));
        let by_protocol = |wanted_warp: bool| {
            report
                .items
                .iter()
                .find(|item| item.link.starts_with("warp://") == wanted_warp)
                .expect("both links parse")
        };
        assert_eq!(by_protocol(true).fp, fingerprint(&link));
        assert!(by_protocol(true).fp.is_some());
        assert!(by_protocol(false).fp.is_none());
        let json = serde_json::to_string(by_protocol(false)).unwrap();
        assert!(
            !json.contains("\"fp\""),
            "an absent fingerprint is left out: {json}"
        );
    }

    #[tokio::test]
    async fn the_job_reports_a_failure_as_one_final_event() {
        let (events, mut received) = tokio::sync::mpsc::unbounded_channel::<String>();
        let callback: crate::events::EventCallback = std::sync::Arc::new(move |batch: String| {
            let _ = events.send(batch);
        });
        let (sink, flusher) = crate::events::batching_sink(callback);
        // A proxy that is not there, and no direct attempt: no network is touched.
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let request: WarpRequest = serde_json::from_value(json!({
            "proxy": closed.to_string(), "direct": false
        }))
        .unwrap();
        let reason = warp_job(
            request,
            sink.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert_eq!(reason, crate::discover::EndReason::Exhausted);
        drop(sink);
        flusher.await.unwrap();
        let mut lines = Vec::new();
        while let Ok(batch) = received.try_recv() {
            lines.extend(batch.lines().map(str::to_string));
        }
        let events: Vec<Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(events[0]["t"], "step");
        let last = events.last().unwrap();
        assert_eq!(last["t"], "done");
        assert_eq!(last["ok"], false);
        assert!(last["error"].as_str().unwrap().contains("proxy"), "{last}");
        assert_eq!(events.iter().filter(|e| e["t"] == "done").count(), 1);
        // Nothing answered, so a host is told it may bring a server up and
        // try again through it.
        assert_eq!(last["unreachable"], true);
    }

    #[test]
    fn a_quick_look_is_a_flag_a_host_can_ask_for() {
        let plain: WarpRequest = serde_json::from_value(json!({})).unwrap();
        assert!(!plain.quick);
        assert!(plain.direct, "direct stays on by default");
        assert_eq!(plain.want, 4);
        let quick: WarpRequest = serde_json::from_value(json!({"quick": true})).unwrap();
        assert!(quick.quick);
    }

    #[tokio::test]
    async fn cancelling_the_job_ends_it_with_a_final_event() {
        let (events, mut received) = tokio::sync::mpsc::unbounded_channel::<String>();
        let callback: crate::events::EventCallback = std::sync::Arc::new(move |batch: String| {
            let _ = events.send(batch);
        });
        let (sink, flusher) = crate::events::batching_sink(callback);
        // A proxy that accepts and then says nothing keeps the job waiting.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = silent.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = silent.accept().await {
                held.push(socket);
            }
        });
        let cancel = tokio_util::sync::CancellationToken::new();
        let stop = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            stop.cancel();
        });
        let request: WarpRequest = serde_json::from_value(json!({
            "proxy": proxy.to_string(), "direct": false
        }))
        .unwrap();
        let reason = warp_job(request, sink.clone(), cancel).await;
        assert_eq!(reason, crate::discover::EndReason::Cancelled);
        drop(sink);
        flusher.await.unwrap();
        let mut last = String::new();
        while let Ok(batch) = received.try_recv() {
            last = batch.lines().last().unwrap().to_string();
        }
        let last: Value = serde_json::from_str(&last).unwrap();
        assert_eq!(
            (last["t"].as_str(), last["ok"].as_bool()),
            (Some("done"), Some(false))
        );
        assert_eq!(last["error"], "cancelled");
    }

    #[test]
    fn only_a_service_that_could_not_be_reached_is_worth_a_tunnel() {
        // The failures that mean "the service was reached and refused": a
        // tunnel would change nothing, so the bootstrap must not borrow one.
        for answered in [
            "Cloudflare is limiting new WARP accounts right now; try again in a minute",
            "the WARP service answered 500",
            "the WARP service sent something odd",
        ] {
            assert!(!is_unreachable(answered), "{answered}");
        }
        // The failures that mean "nothing answered at all": these are what the
        // bootstrap falls back to a borrowed server for.
        for unreachable in [
            "could not reach the WARP service: connecting to api.cloudflareclient.com: connection timed out",
            "could not reach the WARP service: TLS to api.cloudflareclient.com: unexpected eof",
            "could not reach the WARP service: timed out after 6s",
        ] {
            assert!(is_unreachable(unreachable), "{unreachable}");
        }
        // The placeholder used when no way was even tried is not a verdict.
        assert!(!is_unreachable("no way to reach the WARP service"));
        // A failure *after* the service answered is not either, even though it
        // arrives through the same job: borrowing a server would not change
        // the answer.
        for answered_wrongly in [
            "the WARP address is not usable: relative URL without a base",
            "the WARP service sent something odd: malformed HTTP response",
            "the WARP service redirected too many times",
            "the WARP service's reply was cut short",
            "the WARP service's reply was too big",
        ] {
            assert!(!is_unreachable(answered_wrongly), "{answered_wrongly}");
        }
    }

    #[test]
    fn a_shorter_deadline_is_kept_on_the_api() {
        let quick = Api::direct().with_timeout(DIRECT_PROBE);
        assert_eq!(quick.timeout, DIRECT_PROBE);
        assert_eq!(quick.base, DIRECT_BASE);
        assert!(quick.proxy.is_none());
        // A relay keeps its credential; only the deadline changes.
        let relay = Api::relay("https://example.workers.dev/warp", "s3cret");
        assert_eq!(relay.headers.len(), 1);
        assert_eq!(relay.with_timeout(DIRECT_PROBE).timeout, DIRECT_PROBE);
    }

    #[tokio::test]
    async fn a_service_that_refuses_the_connection_reads_as_unreachable() {
        // A closed port stands in for a filtered address: the connect fails,
        // and that has to read as "could not be reached" so the bootstrap
        // knows to borrow a server.
        let addr = a_closed_port().await;
        let api = Api {
            proxy: Some(addr),
            ..Api::direct()
        };
        let said = std::sync::Mutex::new(Vec::new());
        let error = register_with(&api, &|line: &str| {
            said.lock().unwrap().push(line.to_string())
        })
        .await
        .unwrap_err();
        assert!(is_unreachable(&error), "{error}");
        // Nothing was made, so nothing is announced as made.
        assert!(said.lock().unwrap().is_empty());
    }
}
