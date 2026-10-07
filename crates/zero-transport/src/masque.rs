//! Cloudflare WARP over MASQUE: an IP tunnel carried by HTTP CONNECT-IP.
//!
//! WARP's newer tunnel is not WireGuard. The client proves who it is with a
//! self-signed ECDSA P-256 certificate whose key it enrolled with the WARP API,
//! opens one `CONNECT` request with the protocol `cf-connect-ip` (Cloudflare's
//! spelling of RFC 9484's `connect-ip`), and from then on every IP packet
//! travels as an HTTP datagram on that request:
//!
//! * over **HTTP/3**, as a QUIC datagram (RFC 9221) prefixed with the request
//!   stream's quarter id and context id 0 (RFC 9297);
//! * over **HTTP/2**, as a `DATAGRAM` capsule in the request body and response
//!   body, on an ordinary TCP + TLS connection.
//!
//! The two exist because a network may block one. From Iran QUIC to foreign
//! hosts is dropped wholesale, while HTTP/2 to an edge address with a
//! different SNI passes; elsewhere UDP is faster. A [`Spec`] therefore lists
//! endpoints of both kinds and [`start`] takes the first that connects.
//!
//! The server presents Cloudflare's own certificate under whatever name the
//! client asked for, so the name proves nothing. The server is identified
//! by its public key instead — the one the enrollment call returned — and a
//! connection to any other key is refused ([`Pinned`]).
//!
//! What this module hands back is a pair of channels of raw IP packets, which
//! is what the user-space TCP/IP stack in `zero-protocol::wg_stack` consumes.
//! The pump behind them reconnects by itself, so a dropped connection costs
//! the packets in flight and nothing else.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Buf, Bytes, BytesMut};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring as ring_provider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::sync::{mpsc, Notify};
use tokio::time::timeout;

/// The authority every WARP CONNECT-IP request names.
pub const DEFAULT_AUTHORITY: &str = "cloudflareaccess.com";
/// The `:protocol` of the request (HTTP/3) or `cf-connect-proto` (HTTP/2).
const CONNECT_PROTOCOL: &str = "cf-connect-ip";
/// The tunnel MTU the stack above runs at. A datagram of this size plus the
/// HTTP/3 framing has to fit one QUIC packet, which path MTU discovery
/// arranges within the first round trips.
pub const TUNNEL_MTU: usize = 1280;

/// The gap between starting one endpoint and the next.
const ATTEMPT_STAGGER: Duration = Duration::from_millis(300);
/// How long one endpoint gets to produce an authenticated tunnel.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
/// Idle limit and keep-alive of the underlying connection. NAT bindings on
/// mobile networks are short; the keep-alive is what holds them.
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// QUIC's first packet, sized like the official client's so the handshake
/// does not stand out.
const INITIAL_MTU: u16 = 1242;
/// Connection ids of the length the WARP edge expects; shorter ones have been
/// seen to draw a PROTOCOL_VIOLATION.
const CONNECTION_ID_LENGTH: usize = 20;
/// Packets queued each way between the stack and the pump. A full queue drops:
/// TCP inside the tunnel retransmits, and a queue that grows only adds delay.
const QUEUE: usize = 256;
/// The largest capsule or HTTP/3 frame read into memory.
const MAX_FRAME: usize = 70_000;
/// Consecutive failed reconnects before the tunnel gives up. The stack above
/// then stops, and whoever holds it picks another route.
const MAX_RECONNECTS: u32 = 4;

// ---------------------------------------------------------------- DER helpers

/// One DER element: its tag, its content, and what follows it.
fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (length, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 3 {
            return None;
        }
        let mut length = 0usize;
        for byte in input.get(2..2 + count)? {
            length = (length << 8) | usize::from(*byte);
        }
        (length, 2 + count)
    };
    let content = input.get(header..header.checked_add(length)?)?;
    Some((tag, content, &input[header + length..]))
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend_from_slice(&[0x81, n as u8]),
        n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

/// `AlgorithmIdentifier { id-ecPublicKey, prime256v1 }` and the header of the
/// `BIT STRING` holding an uncompressed point: everything of a P-256
/// `SubjectPublicKeyInfo` except the 65 point bytes.
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// `ecdsa-with-SHA256`.
const ECDSA_SHA256: [u8; 12] = [
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];
/// The version and algorithm of a P-256 PKCS#8 `PrivateKeyInfo`; the
/// `OCTET STRING` holding the SEC1 key follows.
const PKCS8_HEADER: [u8; 24] = [
    0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];

/// The uncompressed EC point inside a P-256 `SubjectPublicKeyInfo`.
pub fn point_of_spki(spki: &[u8]) -> Option<&[u8]> {
    let (tag, body, rest) = read_tlv(spki)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let (_, _algorithm, after) = read_tlv(body)?;
    let (tag, bits, _) = read_tlv(after)?;
    // BIT STRING: a zero "unused bits" byte, then 0x04 || X || Y.
    let point = bits.strip_prefix(&[0])?;
    (tag == 0x03 && point.len() == 65 && point[0] == 4).then_some(point)
}

/// The `SubjectPublicKeyInfo` of a DER certificate.
fn spki_of_certificate(certificate: &[u8]) -> Option<&[u8]> {
    let (_, cert, _) = read_tlv(certificate)?;
    let (_, tbs, _) = read_tlv(cert)?;
    let mut rest = tbs;
    // An optional [0] version, then serial, signature, issuer, validity and
    // subject, and the key info follows.
    let (tag, _, after) = read_tlv(rest)?;
    if tag == 0xa0 {
        rest = after;
    }
    for _ in 0..5 {
        rest = read_tlv(rest)?.2;
    }
    let (tag, _, after) = read_tlv(rest)?;
    (tag == 0x30).then(|| &rest[..rest.len() - after.len()])
}

/// The server key out of the PEM (or bare base64) `SubjectPublicKeyInfo` the
/// WARP API returns, as the point that identifies it.
pub fn server_point_from_pem(text: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let body: String = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|error| format!("the server public key is not base64: {error}"))?;
    point_of_spki(&der)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "the server public key is not a P-256 key".to_string())
}

// ---------------------------------------------------------------------- keys

/// The enrolled ECDSA P-256 key that authenticates this device to WARP.
pub struct MasqueKey {
    pkcs8: Vec<u8>,
    point: [u8; 65],
}

impl std::fmt::Debug for MasqueKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasqueKey(..)")
    }
}

impl Drop for MasqueKey {
    fn drop(&mut self) {
        // Best effort: the key should not linger in freed memory.
        self.pkcs8.iter_mut().for_each(|byte| *byte = 0);
    }
}

fn key_pair(pkcs8: &[u8]) -> Result<ring::signature::EcdsaKeyPair, String> {
    ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|_| "the MASQUE private key is not a P-256 key".to_string())
}

impl MasqueKey {
    /// A new key, to be enrolled with the WARP API.
    pub fn generate() -> Result<Self, String> {
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &ring::rand::SystemRandom::new(),
        )
        .map_err(|_| "could not generate a MASQUE key".to_string())?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    /// A key from PKCS#8, or from the SEC1 `ECPrivateKey` most WARP tools
    /// (usque's `config.json`, for one) store.
    pub fn from_der(sec1_or_pkcs8: &[u8]) -> Result<Self, String> {
        let sec1 = sec1_or_pkcs8;
        let (tag, body, _) = read_tlv(sec1).ok_or("the MASQUE private key is not DER")?;
        if tag != 0x30 {
            return Err("the MASQUE private key is not DER".into());
        }
        let (tag, version, _) = read_tlv(body).ok_or("the MASQUE private key is not DER")?;
        match (tag, version) {
            (0x02, [0]) => Self::from_pkcs8(sec1),
            // SEC1: version 1. Wrap it in the PKCS#8 header of a P-256 key.
            (0x02, [1]) => {
                let mut info = PKCS8_HEADER.to_vec();
                info.extend_from_slice(&der(0x04, sec1));
                Self::from_pkcs8(&der(0x30, &info))
            }
            _ => Err("the MASQUE private key is neither PKCS#8 nor SEC1".into()),
        }
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, String> {
        use ring::signature::KeyPair as _;
        let pair = key_pair(pkcs8)?;
        let mut point = [0u8; 65];
        point.copy_from_slice(pair.public_key().as_ref());
        Ok(Self {
            pkcs8: pkcs8.to_vec(),
            point,
        })
    }

    /// The key as PKCS#8, for storing.
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The public key as the DER `SubjectPublicKeyInfo` the WARP API takes.
    pub fn spki_der(&self) -> Vec<u8> {
        let mut out = SPKI_PREFIX.to_vec();
        out.extend_from_slice(&self.point);
        out
    }

    /// A self-signed certificate over this key, valid for the 24 hours around
    /// `now`. WARP's own client makes a fresh one for every connection; the
    /// server checks the key in it, not the name.
    pub fn certificate(&self, now: SystemTime) -> Result<Vec<u8>, String> {
        let pair = key_pair(&self.pkcs8)?;
        let seconds = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "the clock is before 1970".to_string())?
            .as_secs();
        // Half an hour of slack for a phone whose clock runs a little fast,
        // inside the same 24-hour lifetime the reference client uses.
        let from = utc_time(seconds.saturating_sub(30 * 60));
        let until = utc_time(seconds + 23 * 3600 + 30 * 60);
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]); // version 3
        tbs.extend_from_slice(&[0x02, 0x01, 0x00]); // serial 0
        tbs.extend_from_slice(&ECDSA_SHA256);
        tbs.extend_from_slice(&[0x30, 0x00]); // empty issuer
        tbs.extend_from_slice(&der(0x30, &[from, until].concat()));
        tbs.extend_from_slice(&[0x30, 0x00]); // empty subject
        tbs.extend_from_slice(&self.spki_der());
        let tbs = der(0x30, &tbs);
        let signature = pair
            .sign(&ring::rand::SystemRandom::new(), &tbs)
            .map_err(|_| "could not sign the MASQUE certificate".to_string())?;
        let mut bits = vec![0u8];
        bits.extend_from_slice(signature.as_ref());
        let mut cert = tbs;
        cert.extend_from_slice(&ECDSA_SHA256);
        cert.extend_from_slice(&der(0x03, &bits));
        Ok(der(0x30, &cert))
    }
}

/// An ASN.1 `UTCTime` (`YYMMDDHHMMSSZ`) for a Unix time, years 1950-2049.
fn utc_time(seconds: u64) -> Vec<u8> {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    // Days since 1970-01-01 to a calendar date (Howard Hinnant's algorithm).
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
    let text = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year % 100,
        month,
        day,
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    );
    der(0x17, text.as_bytes())
}

// ---------------------------------------------------------------------- TLS

/// Accepts the server whose certificate carries the pinned key, and nobody
/// else. The handshake signature is still verified against that certificate,
/// so holding the certificate without its private key does not pass.
#[derive(Debug)]
struct Pinned {
    point: Vec<u8>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = spki_of_certificate(end_entity.as_ref()).and_then(point_of_spki);
        if presented == Some(self.point.as_slice()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn tls_config(spec: &Spec, alpn: &[u8]) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(ring_provider::default_provider());
    let algorithms = provider.signature_verification_algorithms;
    let certificate = spec.key.certificate(SystemTime::now())?;
    let private_key = PrivateKeyDer::try_from(spec.key.pkcs8().to_vec())
        .map_err(|error| format!("MASQUE client key: {error}"))?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| format!("MASQUE TLS: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            point: spec.server_point.to_vec(),
            algorithms,
        }))
        .with_client_auth_cert(vec![CertificateDer::from(certificate)], private_key)
        .map_err(|error| format!("MASQUE client certificate: {error}"))?;
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

// ------------------------------------------------------------------- the API

/// One place to try: an address, its transport, and the name to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub address: SocketAddr,
    /// TCP + HTTP/2 when set, UDP + HTTP/3 when not.
    pub http2: bool,
    /// The SNI. Cloudflare's edge does not care what it is, which is the point
    /// where a censor filters on the real one.
    pub sni: Arc<str>,
}

/// Everything a MASQUE tunnel needs.
#[derive(Debug, Clone)]
pub struct Spec {
    pub endpoints: Vec<Endpoint>,
    pub key: Arc<MasqueKey>,
    /// The pinned server key, as [`point_of_spki`] returns it.
    pub server_point: Arc<[u8]>,
    /// The `:authority` of the CONNECT request.
    pub authority: Arc<str>,
}

/// The stack's side of a running tunnel: packets out, packets in, and a bell
/// that says the network changed. It is what `PacketLink` holds.
pub struct Link {
    pub up: mpsc::Sender<Vec<u8>>,
    pub down: mpsc::Receiver<Vec<u8>>,
    pub rebind: Arc<Notify>,
}

/// Whether `endpoint` accepts this account's tunnel right now, and how long
/// it took to say so. The connection is dropped at once; this is for choosing
/// among edge addresses, not for carrying traffic.
pub async fn try_endpoint(spec: &Spec, endpoint: &Endpoint) -> Result<Duration, String> {
    let started = tokio::time::Instant::now();
    match timeout(CONNECT_TIMEOUT, connect(spec, endpoint, None)).await {
        Ok(Ok(_session)) => Ok(started.elapsed()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err("timed out".into()),
    }
}

/// Opens a byte stream to a Cloudflare edge address through another
/// connection (a server the account lists), for the `hybrid` order.
///
/// It is a function rather than one stream because the session is rebuilt on
/// every drop and every network change, and each rebuild needs a fresh
/// connection through the carrier, to whichever edge address is tried next.
pub type Opener = Arc<
    dyn Fn(SocketAddr) -> futures::future::BoxFuture<'static, Result<zero_core::BoxStream, String>>
        + Send
        + Sync,
>;

/// Connect to the first endpoint of `spec` that authenticates, and keep the
/// tunnel up from then on. Fails when none does.
pub async fn start(spec: Spec) -> Result<Link, String> {
    start_with(spec, None).await
}

/// [`start`], with every connection to the edge opened through `opener`.
///
/// Only HTTP/2 can be carried: HTTP/3 rides QUIC, which needs a UDP socket of
/// its own, so a spec with any HTTP/3 endpoint is refused up front.
pub async fn start_over(spec: Spec, opener: Opener) -> Result<Link, String> {
    if !spec.endpoints.iter().all(|endpoint| endpoint.http2) {
        return Err("only the HTTP/2 tunnel can be carried by another connection".into());
    }
    start_with(spec, Some(opener)).await
}

async fn start_with(spec: Spec, opener: Option<Opener>) -> Result<Link, String> {
    if spec.endpoints.is_empty() {
        return Err("MASQUE has no endpoint".into());
    }
    let (session, index) = connect_any(&spec, 0, opener.as_ref()).await?;
    let (up_tx, up_rx) = mpsc::channel(QUEUE);
    let (down_tx, down_rx) = mpsc::channel(QUEUE);
    let rebind = Arc::new(Notify::new());
    tokio::spawn(supervise(
        spec,
        session,
        index,
        up_rx,
        down_tx,
        Arc::clone(&rebind),
        opener,
    ));
    Ok(Link {
        up: up_tx,
        down: down_rx,
        rebind,
    })
}

/// Start the endpoints from `first` on, each a moment after the one before,
/// and take the first that authenticates. Waiting for one to time out before
/// trying the next would cost a blocked first address its whole timeout on
/// every connect; staggering keeps the order of preference without that.
async fn connect_any(
    spec: &Spec,
    first: usize,
    opener: Option<&Opener>,
) -> Result<(Session, usize), String> {
    use futures::stream::{FuturesUnordered, StreamExt};
    let count = spec.endpoints.len();
    let mut attempts = FuturesUnordered::new();
    for offset in 0..count {
        let index = (first + offset) % count;
        let endpoint = &spec.endpoints[index];
        let opener = opener.cloned();
        attempts.push(async move {
            tokio::time::sleep(ATTEMPT_STAGGER * offset as u32).await;
            let result =
                match timeout(CONNECT_TIMEOUT, connect(spec, endpoint, opener.as_ref())).await {
                    Ok(result) => result.map_err(|error| format!("{}: {error}", endpoint.address)),
                    Err(_) => Err(format!("{}: timed out", endpoint.address)),
                };
            (index, result)
        });
    }
    let mut last = String::from("no endpoint answered");
    // Dropping `attempts` on return cancels the ones still running.
    while let Some((index, result)) = attempts.next().await {
        match result {
            Ok(session) => return Ok((session, index)),
            Err(error) => {
                tracing::debug!(%error, "MASQUE endpoint failed");
                last = error;
            }
        }
    }
    Err(last)
}

async fn supervise(
    spec: Spec,
    mut session: Session,
    mut current: usize,
    mut up: mpsc::Receiver<Vec<u8>>,
    down: mpsc::Sender<Vec<u8>>,
    rebind: Arc<Notify>,
    opener: Option<Opener>,
) {
    let mut failures = 0u32;
    loop {
        let started = tokio::time::Instant::now();
        let end = session.pump(&mut up, &down, &rebind).await;
        if down.is_closed() {
            return;
        }
        // A tunnel that carried traffic for a while was a good one; only a run
        // of connections that die at once counts against the endpoint.
        if started.elapsed() > Duration::from_secs(20) {
            failures = 0;
        }
        tracing::debug!(?end, "MASQUE tunnel ended");
        loop {
            failures += 1;
            if failures > MAX_RECONNECTS {
                tracing::debug!("MASQUE tunnel gave up");
                return;
            }
            // Packets that piled up while there was no tunnel are stale.
            while up.try_recv().is_ok() {}
            let start_at = if end == End::Rebind {
                current
            } else {
                current + 1
            };
            match connect_any(&spec, start_at % spec.endpoints.len(), opener.as_ref()).await {
                Ok((next, index)) => {
                    session = next;
                    current = index;
                    break;
                }
                Err(error) => {
                    tracing::debug!(%error, "MASQUE reconnect failed");
                    let pause = Duration::from_millis(500 << failures.min(4));
                    tokio::select! {
                        () = tokio::time::sleep(pause) => {}
                        () = down.closed() => return,
                    }
                }
            }
        }
    }
}

/// Why a session stopped.
#[derive(Debug, PartialEq, Eq)]
enum End {
    /// The stack went away.
    Stack,
    /// The connection did.
    Lost,
    /// The network changed under it.
    Rebind,
}

enum Session {
    Http2(Box<H2Session>),
    Http3(Box<H3Session>),
}

async fn connect(
    spec: &Spec,
    endpoint: &Endpoint,
    opener: Option<&Opener>,
) -> Result<Session, String> {
    if endpoint.http2 {
        let carried = match opener {
            Some(open) => Some(open(endpoint.address).await?),
            None => None,
        };
        Ok(Session::Http2(Box::new(
            H2Session::connect(spec, endpoint, carried).await?,
        )))
    } else {
        Ok(Session::Http3(Box::new(
            H3Session::connect(spec, endpoint).await?,
        )))
    }
}

impl Session {
    async fn pump(
        &mut self,
        up: &mut mpsc::Receiver<Vec<u8>>,
        down: &mpsc::Sender<Vec<u8>>,
        rebind: &Notify,
    ) -> End {
        match self {
            Session::Http2(session) => session.pump(up, down, rebind).await,
            Session::Http3(session) => session.pump(up, down, rebind).await,
        }
    }
}

/// Hand a packet from the tunnel to the stack, if it is an IP packet at all.
fn deliver(down: &mpsc::Sender<Vec<u8>>, packet: &[u8]) {
    let plausible = match packet.first().map(|byte| byte >> 4) {
        Some(4) => packet.len() >= 20,
        Some(6) => packet.len() >= 40,
        _ => false,
    };
    if plausible {
        let _ = down.try_send(packet.to_vec());
    }
}

// -------------------------------------------------------------- variable ints

fn put_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        v if v < 1 << 6 => out.push(v as u8),
        v if v < 1 << 14 => out.extend_from_slice(&(0x4000 | v as u16).to_be_bytes()),
        v if v < 1 << 30 => out.extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes()),
        v => out.extend_from_slice(&(0xc000_0000_0000_0000 | v).to_be_bytes()),
    }
}

fn get_varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let length = 1usize << (first >> 6);
    let bytes = input.get(..length)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

// ------------------------------------------------------------------ HTTP/2

struct H2Session {
    connection: h2::client::Connection<tokio_rustls::client::TlsStream<zero_core::BoxStream>>,
    _client: h2::client::SendRequest<Bytes>,
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    /// Bytes read from the response body that do not yet make a capsule.
    pending: BytesMut,
}

impl H2Session {
    /// Bring a session up, over `carried` when the caller opened the
    /// connection itself (the `hybrid` order), otherwise over a socket dialled
    /// here. Only the direct socket gets `TCP_NODELAY`: a carried stream is
    /// set up by whoever opened it.
    async fn connect(
        spec: &Spec,
        endpoint: &Endpoint,
        carried: Option<zero_core::BoxStream>,
    ) -> Result<Self, String> {
        let io: zero_core::BoxStream = match carried {
            Some(stream) => stream,
            None => {
                let tcp = zero_core::platform::connect_protected(endpoint.address)
                    .await
                    .map_err(|error| format!("connect: {error}"))?;
                let _ = tcp.set_nodelay(true);
                Box::pin(tcp)
            }
        };
        let server_name = ServerName::try_from(endpoint.sni.to_string())
            .map_err(|error| format!("SNI {}: {error}", endpoint.sni))?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(tls_config(spec, b"h2")?))
            .connect(server_name, io)
            .await
            .map_err(|error| format!("TLS: {error}"))?;
        let (mut client, connection) = h2::client::Builder::new()
            .initial_window_size(1 << 20)
            .initial_connection_window_size(4 << 20)
            .handshake::<_, Bytes>(tls)
            .await
            .map_err(|error| format!("HTTP/2: {error}"))?;
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("{}:443", spec.authority))
            .header("cf-connect-proto", CONNECT_PROTOCOL)
            .header("pq-enabled", "false")
            .header("user-agent", "")
            .body(())
            .map_err(|error| format!("request: {error}"))?;
        let (response, send) = client
            .send_request(request, false)
            .map_err(|error| format!("request: {error}"))?;
        // The connection has to be driven for the response to arrive.
        let mut connection = connection;
        let response = tokio::select! {
            response = response => response.map_err(|error| format!("response: {error}"))?,
            result = &mut connection => {
                return Err(match result {
                    Ok(()) => "the server closed the connection".to_string(),
                    Err(error) => format!("HTTP/2: {error}"),
                });
            }
        };
        if !response.status().is_success() {
            return Err(format!("the server answered {}", response.status()));
        }
        Ok(Self {
            connection,
            _client: client,
            send,
            recv: response.into_body(),
            pending: BytesMut::new(),
        })
    }

    async fn pump(
        &mut self,
        up: &mut mpsc::Receiver<Vec<u8>>,
        down: &mpsc::Sender<Vec<u8>>,
        rebind: &Notify,
    ) -> End {
        loop {
            tokio::select! {
                packet = up.recv() => {
                    let Some(packet) = packet else { return End::Stack };
                    if self.write_capsule(&packet).await.is_err() {
                        return End::Lost;
                    }
                }
                chunk = self.recv.data() => {
                    let Some(Ok(chunk)) = chunk else { return End::Lost };
                    let length = chunk.len();
                    self.pending.extend_from_slice(&chunk);
                    if self.recv.flow_control().release_capacity(length).is_err() {
                        return End::Lost;
                    }
                    if self.drain_capsules(down).is_err() {
                        return End::Lost;
                    }
                }
                result = &mut self.connection => {
                    let _ = result;
                    return End::Lost;
                }
                () = rebind.notified() => return End::Rebind,
                () = down.closed() => return End::Stack,
            }
        }
    }

    /// Send one packet as a `DATAGRAM` capsule (type 0), waiting for the
    /// stream's flow-control window so that a slow server slows the sender
    /// rather than filling memory.
    async fn write_capsule(&mut self, packet: &[u8]) -> Result<(), h2::Error> {
        let mut capsule = Vec::with_capacity(packet.len() + 4);
        put_varint(&mut capsule, 0);
        put_varint(&mut capsule, packet.len() as u64);
        capsule.extend_from_slice(packet);
        self.send.reserve_capacity(capsule.len());
        while self.send.capacity() < capsule.len() {
            let granted = std::future::poll_fn(|cx| self.send.poll_capacity(cx)).await;
            match granted {
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(error),
                None => return Err(h2::Reason::CANCEL.into()),
            }
        }
        self.send.send_data(Bytes::from(capsule), false)
    }

    fn drain_capsules(&mut self, down: &mpsc::Sender<Vec<u8>>) -> Result<(), ()> {
        loop {
            let Some((kind, type_length)) = get_varint(&self.pending) else {
                return Ok(());
            };
            let Some((length, length_length)) = get_varint(&self.pending[type_length..]) else {
                return Ok(());
            };
            let header = type_length + length_length;
            let length = usize::try_from(length).map_err(|_| ())?;
            if length > MAX_FRAME {
                return Err(());
            }
            if self.pending.len() < header + length {
                return Ok(());
            }
            if kind == 0 {
                deliver(down, &self.pending[header..header + length]);
            }
            // Address and route capsules carry nothing this client needs: the
            // tunnel addresses come from the account, not the server.
            self.pending.advance(header + length);
        }
    }
}

// ------------------------------------------------------------------ HTTP/3

/// The QPACK static table entries this client writes or reads by index.
const QPACK_METHOD_CONNECT: u8 = 15;
const QPACK_SCHEME_HTTPS: u8 = 23;
const QPACK_PATH_SLASH: u8 = 1;
/// `:authority`, used as a name reference.
const QPACK_AUTHORITY: u8 = 0;

/// The status a QPACK static-table index stands for, if it is a `:status`.
fn static_status(index: u64) -> Option<u16> {
    Some(match index {
        24 => 103,
        25 => 200,
        26 => 304,
        27 => 404,
        28 => 503,
        63 => 100,
        64 => 204,
        65 => 206,
        66 => 302,
        67 => 400,
        68 => 403,
        69 => 421,
        70 => 425,
        71 => 500,
        _ => return None,
    })
}

/// A QPACK/HPACK prefix integer (RFC 7541 §5.1).
fn prefix_int(input: &[u8], bits: u8) -> Option<(u64, usize)> {
    let mask = ((1u16 << bits) - 1) as u8;
    let mut value = u64::from(*input.first()? & mask);
    if value < u64::from(mask) {
        return Some((value, 1));
    }
    let mut shift = 0;
    for (offset, byte) in input.iter().enumerate().skip(1) {
        value += u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, offset + 1));
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
    None
}

fn put_prefix_int(out: &mut Vec<u8>, first: u8, bits: u8, mut value: u64) {
    let mask = ((1u16 << bits) - 1) as u8;
    if value < u64::from(mask) {
        out.push(first | value as u8);
        return;
    }
    out.push(first | mask);
    value -= u64::from(mask);
    while value >= 0x80 {
        out.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// A string literal (7-bit length prefix, no Huffman) after a 3-bit-prefix
/// name or a plain value.
fn put_string(out: &mut Vec<u8>, text: &str) {
    put_prefix_int(out, 0, 7, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

/// A field line with a literal name (RFC 9204 §4.5.6).
fn put_literal(out: &mut Vec<u8>, name: &str, value: &str) {
    put_prefix_int(out, 0x20, 3, name.len() as u64);
    out.extend_from_slice(name.as_bytes());
    put_string(out, value);
}

/// The HEADERS frame of the CONNECT request: no dynamic table, so the block
/// prefix is two zero bytes and every line is static or literal.
fn request_headers(authority: &str) -> Vec<u8> {
    let mut block = vec![0, 0];
    block.push(0xc0 | QPACK_METHOD_CONNECT);
    block.push(0xc0 | QPACK_SCHEME_HTTPS);
    // Literal with static name reference: 01 N=0 T=1 then a 4-bit index.
    block.push(0x50 | QPACK_AUTHORITY);
    put_string(&mut block, authority);
    block.push(0xc0 | QPACK_PATH_SLASH);
    put_literal(&mut block, ":protocol", CONNECT_PROTOCOL);
    put_literal(&mut block, "capsule-protocol", "?1");
    put_literal(&mut block, "user-agent", "");
    let mut frame = Vec::new();
    put_varint(&mut frame, 0x01);
    put_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    frame
}

/// The client's control stream: its type byte and a SETTINGS frame. Datagrams
/// are switched on twice, under the final code point and the draft one
/// (0x276) Cloudflare's own client still sends. The QPACK table stays empty.
fn control_stream() -> Vec<u8> {
    let mut settings = Vec::new();
    for (id, value) in [(0x01, 0), (0x07, 0), (0x33, 1), (0x276, 1)] {
        put_varint(&mut settings, id);
        put_varint(&mut settings, value);
    }
    let mut out = vec![0x00];
    put_varint(&mut out, 0x04);
    put_varint(&mut out, settings.len() as u64);
    out.extend_from_slice(&settings);
    out
}

/// The `:status` in a response's field section.
fn response_status(block: &[u8]) -> Result<u16, String> {
    let bad = || "malformed response headers".to_string();
    let (required_insert_count, mut at) = prefix_int(block, 8).ok_or_else(bad)?;
    if required_insert_count != 0 {
        return Err("the server used a QPACK dynamic table nobody offered".into());
    }
    at += prefix_int(block.get(at..).ok_or_else(bad)?, 7)
        .ok_or_else(bad)?
        .1;
    // A string literal at `at`, decoded if Huffman coded; returns the bytes and
    // the offset after them.
    let read_string =
        |at: usize, prefix: u8, huffman_bit: u8| -> Result<(Vec<u8>, usize), String> {
            let head = *block.get(at).ok_or_else(bad)?;
            let (length, used) = prefix_int(&block[at..], prefix).ok_or_else(bad)?;
            let start = at + used;
            let end = start
                .checked_add(usize::try_from(length).map_err(|_| bad())?)
                .ok_or_else(bad)?;
            let raw = block.get(start..end).ok_or_else(bad)?;
            let text = if head & huffman_bit != 0 {
                crate::huffman::decode(raw).ok_or_else(bad)?
            } else {
                raw.to_vec()
            };
            Ok((text, end))
        };
    while at < block.len() {
        let byte = block[at];
        if byte & 0x80 != 0 {
            // Indexed field line: 1 T index(6).
            let (index, used) = prefix_int(&block[at..], 6).ok_or_else(bad)?;
            at += used;
            if byte & 0x40 == 0 {
                return Err("the server used a QPACK dynamic table nobody offered".into());
            }
            if let Some(status) = static_status(index) {
                return Ok(status);
            }
        } else if byte & 0xc0 == 0x40 {
            // Literal with name reference: 01 N T index(4), then a value.
            let (index, used) = prefix_int(&block[at..], 4).ok_or_else(bad)?;
            at += used;
            if byte & 0x10 == 0 {
                return Err("the server used a QPACK dynamic table nobody offered".into());
            }
            let (value, next) = read_string(at, 7, 0x80)?;
            at = next;
            if static_status(index).is_some() {
                return std::str::from_utf8(&value)
                    .ok()
                    .and_then(|text| text.parse().ok())
                    .ok_or_else(bad);
            }
        } else if byte & 0xe0 == 0x20 {
            // Literal with literal name: 001 N H len(3), name, then a value.
            let (name, next) = read_string(at, 3, 0x08)?;
            let (value, next) = read_string(next, 7, 0x80)?;
            at = next;
            if name == b":status" {
                return std::str::from_utf8(&value)
                    .ok()
                    .and_then(|text| text.parse().ok())
                    .ok_or_else(bad);
            }
        } else {
            // Post-base forms need a dynamic table.
            return Err("the server used a QPACK dynamic table nobody offered".into());
        }
    }
    Err("the response has no :status".into())
}

struct H3Session {
    connection: h3_quinn::quinn::Connection,
    /// Kept open: dropping a stream the peer treats as critical would end the
    /// HTTP/3 connection.
    _endpoint: h3_quinn::quinn::Endpoint,
    _streams: Vec<h3_quinn::quinn::SendStream>,
    drain: tokio::task::JoinHandle<()>,
    /// The CONNECT request stream. Its send side stays open for good.
    _request: h3_quinn::quinn::SendStream,
    response: h3_quinn::quinn::RecvStream,
    /// The prefix every datagram of this request carries: quarter stream id
    /// and context id 0.
    prefix: Vec<u8>,
}

impl Drop for H3Session {
    fn drop(&mut self) {
        self.drain.abort();
        self.connection.close(0u32.into(), b"");
    }
}

impl H3Session {
    async fn connect(spec: &Spec, endpoint: &Endpoint) -> Result<Self, String> {
        use h3_quinn::quinn;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config(spec, b"h3")?)
            .map_err(|error| format!("QUIC TLS: {error}"))?;
        let mut transport = crate::relay::quic_transport(IDLE_TIMEOUT, Some(KEEP_ALIVE));
        transport.initial_mtu(INITIAL_MTU);
        transport.datagram_receive_buffer_size(Some(2 << 20));
        transport.datagram_send_buffer_size(2 << 20);
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        client.transport_config(Arc::new(transport));
        let bind: SocketAddr = if endpoint.address.is_ipv6() {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let socket = zero_core::platform::bind_protected_udp(bind)
            .map_err(|error| format!("UDP bind: {error}"))?;
        let mut config = quinn::EndpointConfig::default();
        config.cid_generator(|| {
            Box::new(quinn_proto::RandomConnectionIdGenerator::new(
                CONNECTION_ID_LENGTH,
            ))
        });
        let quic = quinn::Endpoint::new(config, None, socket, Arc::new(quinn::TokioRuntime))
            .map_err(|error| format!("QUIC endpoint: {error}"))?;
        let connection = quic
            .connect_with(client, endpoint.address, &endpoint.sni)
            .map_err(|error| format!("QUIC: {error}"))?
            .await
            .map_err(|error| format!("QUIC: {error}"))?;

        // Control stream and the two QPACK streams, which HTTP/3 wants every
        // endpoint to open even when the table is empty.
        let mut streams = Vec::new();
        for (kind, body) in [(0u8, control_stream()), (2, vec![0x02]), (3, vec![0x03])] {
            let mut stream = connection
                .open_uni()
                .await
                .map_err(|error| format!("HTTP/3 stream {kind}: {error}"))?;
            stream
                .write_all(&body)
                .await
                .map_err(|error| format!("HTTP/3 stream {kind}: {error}"))?;
            streams.push(stream);
        }
        // The server's own control and QPACK streams: read and ignore, and
        // keep them open.
        let drain = tokio::spawn({
            let connection = connection.clone();
            async move {
                while let Ok(mut stream) = connection.accept_uni().await {
                    tokio::spawn(async move {
                        let mut sink = [0u8; 1024];
                        while let Ok(Some(_)) = stream.read(&mut sink).await {}
                    });
                }
            }
        });

        let (mut request, mut response) = connection
            .open_bi()
            .await
            .map_err(|error| format!("HTTP/3 request: {error}"))?;
        request
            .write_all(&request_headers(&spec.authority))
            .await
            .map_err(|error| format!("HTTP/3 request: {error}"))?;
        let status = read_response_status(&mut response).await?;
        if !(200..300).contains(&status) {
            connection.close(0u32.into(), b"");
            return Err(format!("the server answered {status}"));
        }
        // The first client-initiated bidirectional stream is id 0, so the
        // quarter stream id is 0 as well.
        let prefix = vec![0x00, 0x00];
        Ok(Self {
            connection,
            _endpoint: quic,
            _streams: streams,
            drain,
            _request: request,
            response,
            prefix,
        })
    }

    async fn pump(
        &mut self,
        up: &mut mpsc::Receiver<Vec<u8>>,
        down: &mpsc::Sender<Vec<u8>>,
        rebind: &Notify,
    ) -> End {
        let mut sink = [0u8; 2048];
        loop {
            tokio::select! {
                packet = up.recv() => {
                    let Some(packet) = packet else { return End::Stack };
                    let mut datagram = Vec::with_capacity(self.prefix.len() + packet.len());
                    datagram.extend_from_slice(&self.prefix);
                    datagram.extend_from_slice(&packet);
                    // Too big for the path so far, or the queue is full: the
                    // packet is dropped and TCP inside the tunnel resends it.
                    if let Err(error) = self.connection.send_datagram(Bytes::from(datagram)) {
                        if !matches!(
                            error,
                            h3_quinn::quinn::SendDatagramError::TooLarge
                        ) {
                            return End::Lost;
                        }
                    }
                }
                datagram = self.connection.read_datagram() => {
                    let Ok(datagram) = datagram else { return End::Lost };
                    if let Some(packet) = datagram.strip_prefix(self.prefix.as_slice()) {
                        deliver(down, packet);
                    }
                }
                // Capsules on the request stream (address assignment, routes)
                // are read and dropped; the stream ending ends the tunnel.
                read = self.response.read(&mut sink) => {
                    if !matches!(read, Ok(Some(_))) {
                        return End::Lost;
                    }
                }
                _ = self.connection.closed() => return End::Lost,
                () = rebind.notified() => return End::Rebind,
                () = down.closed() => return End::Stack,
            }
        }
    }
}

/// Read HTTP/3 frames from the response stream until the HEADERS frame, and
/// return its status.
async fn read_response_status(stream: &mut h3_quinn::quinn::RecvStream) -> Result<u16, String> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let mut at = 0;
        while let Some((kind, used)) = get_varint(&buffer[at..]) {
            let Some((length, length_used)) = get_varint(&buffer[at + used..]) else {
                break;
            };
            let header = used + length_used;
            let length = usize::try_from(length).map_err(|_| "oversized frame".to_string())?;
            if length > MAX_FRAME {
                return Err("oversized response frame".into());
            }
            if buffer.len() < at + header + length {
                break;
            }
            let body = &buffer[at + header..at + header + length];
            if kind == 0x01 {
                return response_status(body);
            }
            at += header + length;
        }
        buffer.drain(..at);
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("response: {error}"))?
            .ok_or("the server closed the request without answering")?;
        buffer.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod mock;
#[cfg(test)]
mod tests;
