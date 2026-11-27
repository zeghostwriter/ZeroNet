//! TLS client connections.
//!
//! The TLS backend and the ClientHello *shape* are deliberately separate
//! concerns (RESEARCH-01 §14). This module owns the backend; `fingerprint`
//! owns the shape. A rustls upgrade must not be able to silently change what
//! a censor sees on the wire.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use rustls::client::danger::ServerCertVerifier;
use rustls::ClientConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use zero_core::{Confidence, Failure, FailureKind, Stage};

use crate::fingerprint::FingerprintProfile;
use crate::utls_profiles::profile_for_fingerprint;
use crate::utls_shaping::retain_profile_certificate_decompressors;

/// What to present and verify on a TLS connection.
#[derive(Debug, Clone)]
pub struct TlsParams {
    /// SNI. Case is preserved verbatim: panels randomise it deliberately as a
    /// cheap defence against case-sensitive DPI string matching, and
    /// normalising it here would undo that.
    pub server_name: String,
    pub alpn: Vec<Vec<u8>>,
    pub profile: FingerprintProfile,
    /// Concrete Xray/uTLS profile name. The broad `profile` selects the
    /// provider family; this name selects the exact wire corpus entry.
    pub fingerprint_name: Option<String>,
    /// Serialized ECHConfigList bytes. When present, the config is built with
    /// Rustls' HPKE-capable provider and ECH is mandatory for the handshake.
    pub ech_config_list: Option<Vec<u8>>,
    /// Optional inner SNI. The ECH public name remains in the config list.
    pub ech_server_name: Option<String>,
    /// Extra trust anchors, PEM or DER, added to the public root store.
    ///
    /// This is the safe half of Xray's `certificates` with `usage: "verify"`,
    /// and the only supported way to reach a server with a private or
    /// self-signed CA. It is emphatically *not* `allowInsecure`: verification
    /// still happens, the name still has to match, and the trust it grants is
    /// limited to the certificates the operator named.
    pub extra_roots: Vec<Vec<u8>>,
    /// Accept any certificate: Xray's `allowInsecure`. Only ever set from a
    /// link or config that says so itself (see [`TlsParams::with_insecure`]).
    pub insecure: bool,
    /// SHA-256 hashes the server's certificate chain must contain (see
    /// [`TlsParams::with_pinned_certs`]). Empty means no pinning.
    pub pinned: Vec<[u8; 32]>,
    /// What to write in the ClientHello's `legacy_version` field instead of
    /// 0x0303 (see [`TlsParams::with_hello_version`]).
    pub hello_version: Option<u16>,
    /// A certificate verifier of the caller's own (see
    /// [`TlsParams::with_verifier`]).
    pub verifier: Option<Arc<dyn ServerCertVerifier>>,
    /// A client certificate to present (see [`TlsParams::with_client_auth`]).
    pub client_auth: Option<ClientAuth>,
    /// Names the server's certificate may be valid for instead of the server
    /// name sent (Xray's `verifyPeerCertByName`); any one matching is enough.
    /// Empty verifies for the name sent.
    pub verify_names: Vec<String>,
    /// A file to append the session secrets to, in the format Wireshark reads
    /// (Xray's `masterKeyLog`).
    pub key_log: Option<String>,
}

/// A client certificate chain and its private key, for servers that ask the
/// client to authenticate (the WARP MASQUE edge does).
///
/// The key is shared, not copied, and is left out of `Debug` output.
#[derive(Clone)]
pub struct ClientAuth {
    chain: Vec<CertificateDer<'static>>,
    key: Arc<PrivateKeyDer<'static>>,
}

impl ClientAuth {
    pub fn new(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Self {
        Self {
            chain,
            key: Arc::new(key),
        }
    }
}

impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ClientAuth({} certificate(s), key withheld)",
            self.chain.len()
        )
    }
}

impl TlsParams {
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            alpn: Vec::new(),
            profile: FingerprintProfile::default(),
            fingerprint_name: None,
            ech_config_list: None,
            ech_server_name: None,
            extra_roots: Vec::new(),
            insecure: false,
            pinned: Vec::new(),
            hello_version: None,
            verifier: None,
            client_auth: None,
            verify_names: Vec::new(),
            key_log: None,
        }
    }

    /// Check the server's certificate with `verifier` instead of the public
    /// roots, for a peer that is known by its key rather than by a CA (the
    /// WARP MASQUE edge is pinned this way). It replaces every other check
    /// (`insecure`, pins), so a verifier that accepts too much is the
    /// caller's to answer for. Such a config is built fresh each time and is
    /// never cached, because a verifier cannot be compared.
    pub fn with_verifier(mut self, verifier: Arc<dyn ServerCertVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Present a client certificate when the server asks for one. Like
    /// [`TlsParams::with_verifier`], it keeps the config out of the cache.
    pub fn with_client_auth(mut self, auth: ClientAuth) -> Self {
        self.client_auth = Some(auth);
        self
    }

    /// Require the server to present a certificate with one of these SHA-256
    /// hashes (Xray's `pinnedPeerCertSha256`). The leaf matching is enough on
    /// its own, so a self-signed server can be reached without
    /// `allowInsecure`; a match further up the chain keeps the ordinary chain
    /// and name checks; no match fails the handshake. Pins win over
    /// `insecure`.
    pub fn with_pinned_certs(mut self, pins: Vec<[u8; 32]>) -> Self {
        self.pinned = pins;
        self
    }

    /// Do not check the server's certificate chain or name (Xray's
    /// `allowInsecure`). The handshake signatures are still checked, so the
    /// peer must hold the key of whatever certificate it sends, but anyone on
    /// the path can present a certificate of their own and be accepted: this
    /// trades protection from an on-path attacker for reaching servers with a
    /// self-signed certificate or a name that does not match (a Worker behind
    /// a custom CDN address). Never the default; a link has to ask.
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Write `version` in the hello's `legacy_version` field. The version
    /// that counts is negotiated through `supported_versions`, and servers
    /// take this field as "TLS 1.2 or later", so an odd 0x03xx value (0x0304)
    /// is read as usual; a filter that picks out hellos by the field does not
    /// recognise it and lets the name by. Left off with ECH, which hides the
    /// name already and whose inner hello must not differ.
    pub fn with_hello_version(mut self, version: u16) -> Self {
        self.hello_version = Some(version);
        self
    }

    /// Verify the server's certificate for one of `names` instead of the
    /// server name that was sent (Xray's `verifyPeerCertByName`): the name in
    /// the hello and the name the certificate must carry are told apart when
    /// the hello's name is a stand-in (a front).
    pub fn with_verify_names(mut self, names: Vec<String>) -> Self {
        self.verify_names = names;
        self
    }

    /// Append the session secrets to the file at `path` as they are made, in
    /// the NSS key log format (Xray's `masterKeyLog`). Anyone who reads the
    /// file can decrypt the traffic it belongs to.
    pub fn with_key_log(mut self, path: impl Into<String>) -> Self {
        self.key_log = Some(path.into());
        self
    }

    pub fn with_extra_roots(mut self, roots: Vec<Vec<u8>>) -> Self {
        self.extra_roots = roots;
        self
    }

    pub fn with_alpn<S: AsRef<str>>(mut self, alpn: &[S]) -> Self {
        self.alpn = alpn
            .iter()
            .map(|a| a.as_ref().as_bytes().to_vec())
            .collect();
        self
    }

    pub fn with_profile(mut self, profile: FingerprintProfile) -> Self {
        self.profile = profile;
        self
    }

    pub fn with_fingerprint_name(mut self, name: impl Into<String>) -> Self {
        self.fingerprint_name = Some(name.into());
        self
    }

    pub fn with_ech(
        mut self,
        config_list: impl Into<Vec<u8>>,
        server_name: Option<String>,
    ) -> Self {
        self.ech_config_list = Some(config_list.into());
        self.ech_server_name = server_name;
        self
    }
}

/// Identifies a reusable client configuration.
///
/// SNI is deliberately **not** part of the key: it is per-connection, while
/// everything a `ClientConfig` owns (roots, suites, ALPN, session cache) is
/// not.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConfigKey {
    profile: FingerprintProfile,
    fingerprint_name: Option<String>,
    alpn: Vec<Vec<u8>>,
    ech_config_list: Option<Vec<u8>>,
    /// Part of the key: two outbounds that trust different anchors must never
    /// share a cached config, or one would silently inherit the other's trust.
    extra_roots: Vec<Vec<u8>>,
    /// Part of the key for the same reason as `extra_roots`: a config that
    /// accepts any certificate must never be handed to a verifying outbound.
    insecure: bool,
    /// Part of the key: a pinned config must never serve an unpinned outbound.
    pinned: Vec<[u8; 32]>,
    /// Part of the key: the names a certificate may carry change who a
    /// config trusts.
    verify_names: Vec<String>,
    key_log: Option<String>,
    /// Part of the key: the field is written by the config's hello
    /// customizer, so configs that disagree about it are different configs.
    hello_version: Option<u16>,
}

/// Upper bound on cached client configs.
///
/// Keys include the ECH config list, which dynamic ECH resolves from DNS and
/// which providers rotate (Cloudflare hourly). Unbounded, the cache would keep
/// one full config — root store, session cache — per rotation for the life of
/// the process.
const CONFIG_CACHE_LIMIT: usize = 64;

struct ConfigCache {
    entries: HashMap<ConfigKey, (Arc<ClientConfig>, u64)>,
    /// Monotonic use counter; the entry with the smallest stamp is evicted.
    clock: u64,
}

impl ConfigCache {
    fn get(&mut self, key: &ConfigKey) -> Option<Arc<ClientConfig>> {
        self.clock += 1;
        let clock = self.clock;
        self.entries.get_mut(key).map(|(config, used)| {
            *used = clock;
            Arc::clone(config)
        })
    }

    fn insert(&mut self, key: ConfigKey, config: Arc<ClientConfig>) -> Arc<ClientConfig> {
        if let Some(existing) = self.get(&key) {
            // Another thread inserted meanwhile; either instance is correct,
            // so keep whichever landed first to maximise cache sharing.
            return existing;
        }
        if self.entries.len() >= CONFIG_CACHE_LIMIT {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.clock += 1;
        self.entries.insert(key, (Arc::clone(&config), self.clock));
        config
    }
}

fn config_cache() -> &'static Mutex<ConfigCache> {
    static CACHE: OnceLock<Mutex<ConfigCache>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Mutex::new(ConfigCache {
            entries: HashMap::new(),
            clock: 0,
        })
    })
}

/// Decode one operator-supplied trust anchor. PEM may carry a chain; DER is a
/// single certificate.
fn parse_trust_anchor(
    input: &[u8],
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, String> {
    use rustls_pki_types::pem::PemObject;
    if input.starts_with(b"-----BEGIN") {
        rustls_pki_types::CertificateDer::pem_slice_iter(input)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("reading PEM: {error}"))
    } else {
        Ok(vec![rustls_pki_types::CertificateDer::from(input.to_vec())])
    }
}

/// Build (or reuse) a client config.
///
/// Configs are cached per fingerprint and ALPN set, for two reasons that both
/// matter on a proxy hot path:
///
/// * building one clones the whole webpki root store (~150 certificates) —
///   pure waste once per connection;
/// * far more importantly, a `ClientConfig` owns the **TLS session cache**. A
///   fresh config per connection means resumption can never happen, so every
///   connection pays a full handshake. Against a distant CDN edge that is an
///   extra round trip on every single request.
///
/// Certificates are verified unless the params say `insecure`, which only a
/// link or config that sets Xray's `allowInsecure` itself can do; nothing
/// turns it on by default or by guess.
pub fn client_config(params: &TlsParams) -> Arc<ClientConfig> {
    try_client_config(params).expect("invalid ECH/TLS configuration")
}

/// Build (or reuse) a client config without turning an invalid ECH list into
/// a process panic. The compatibility wrapper above remains for callers that
/// only use ordinary TLS.
pub fn try_client_config(params: &TlsParams) -> Result<Arc<ClientConfig>, Failure> {
    let key = ConfigKey {
        profile: params.profile,
        fingerprint_name: params.fingerprint_name.clone(),
        alpn: params.alpn.clone(),
        ech_config_list: params.ech_config_list.clone(),
        extra_roots: params.extra_roots.clone(),
        insecure: params.insecure,
        pinned: params.pinned.clone(),
        verify_names: params.verify_names.clone(),
        key_log: params.key_log.clone(),
        hello_version: params.hello_version,
    };

    // A verifier or a client key cannot be compared, so a config that holds
    // one is neither looked up nor stored: handing it to another caller
    // would hand over that caller's trust or identity.
    let cacheable = params.verifier.is_none() && params.client_auth.is_none();
    if cacheable {
        if let Ok(mut cache) = config_cache().lock() {
            if let Some(found) = cache.get(&key) {
                return Ok(found);
            }
        }
    }

    let cfg = Arc::new(build_client_config(params).map_err(|detail| {
        Failure::new(FailureKind::TlsHandshakeMalformed, Stage::TlsStarted)
            .with_confidence(Confidence::Confirmed)
            .with_detail(detail)
    })?);

    if !cacheable {
        return Ok(cfg);
    }
    if let Ok(mut cache) = config_cache().lock() {
        return Ok(cache.insert(key, cfg));
    }
    Ok(cfg)
}

/// A browser-shaped config for plain HTTPS clients: feed and asset fetches,
/// subscription downloads, the update check.
///
/// Those clients used to send rustls's own ClientHello — ring's suite order,
/// rustls's extension order, often no ALPN — which no browser produces, and
/// they are dialled to exactly the hosts a censor lists (GitHub, jsDelivr,
/// the crowd endpoints). This one wears the Chrome profile like the proxy
/// paths do and verifies against the bundled public roots.
///
/// `alpn` is what the caller can actually speak. A fetcher that only does
/// HTTP/1.1 must say `["http/1.1"]`, or a server would pick `h2` and the
/// exchange would break; that one field then differs from a browser that
/// speaks both, which is the cost of not carrying an HTTP/2 client here.
///
/// If the shape cannot be built the stock config is returned instead: a feed
/// that downloads with a plain hello beats one that does not download.
pub fn https_client_config(alpn: &[&str]) -> Arc<ClientConfig> {
    let params = TlsParams::new("")
        .with_profile(FingerprintProfile::Chrome)
        .with_alpn(alpn);
    try_client_config(&params).unwrap_or_else(|failure| {
        tracing::warn!(%failure, "browser-shaped HTTPS config unavailable, using the stock one");
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("ring supports the default protocol versions")
                .with_root_certificates(rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                })
                .with_no_client_auth();
        config.alpn_protocols = params.alpn.clone();
        Arc::new(config)
    })
}

fn build_client_config(params: &TlsParams) -> Result<ClientConfig, String> {
    if params.ech_config_list.is_some() && params.client_auth.is_some() {
        return Err("a client certificate is not supported together with ECH".into());
    }
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for (index, anchor) in params.extra_roots.iter().enumerate() {
        let certificates = parse_trust_anchor(anchor)
            .map_err(|error| format!("additional trust anchor {index}: {error}"))?;
        if certificates.is_empty() {
            return Err(format!(
                "additional trust anchor {index} contains no certificate"
            ));
        }
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|error| format!("additional trust anchor {index}: {error}"))?;
        }
    }

    let verify_roots =
        (!params.pinned.is_empty() || !params.verify_names.is_empty()).then(|| roots.clone());
    let mut cfg = if let Some(config_list) = &params.ech_config_list {
        let ech = rustls::client::EchConfig::new(
            rustls_pki_types::EchConfigListBytes::from(config_list.clone()),
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        )
        .map_err(|error| format!("invalid ECHConfigList: {error}"))?;
        rustls::ClientConfig::builder_with_provider(params.profile.aws_provider().into())
            .with_ech(ech.into())
            .map_err(|error| format!("cannot enable ECH: {error}"))?
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        let builder = params.profile.apply_to_builder(roots);
        match &params.client_auth {
            Some(auth) => builder
                .with_client_auth_cert(auth.chain.clone(), auth.key.clone_key())
                .map_err(|error| format!("client certificate: {error}"))?,
            None => builder.with_no_client_auth(),
        }
    };

    if let Some(verifier) = &params.verifier {
        cfg.dangerous()
            .set_certificate_verifier(Arc::clone(verifier));
    } else if let Some(roots) = verify_roots {
        let provider = Arc::new(params.profile.aws_provider());
        let inner =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|error| format!("cannot build the certificate verifier: {error}"))?;
        let base: Arc<dyn ServerCertVerifier> = if params.pinned.is_empty() {
            inner
        } else {
            Arc::new(PinnedCertificate {
                pins: params.pinned.clone(),
                inner,
            })
        };
        let verifier: Arc<dyn ServerCertVerifier> = if params.verify_names.is_empty() {
            base
        } else {
            Arc::new(VerifyByName {
                inner: base,
                names: params
                    .verify_names
                    .iter()
                    .map(|name| {
                        ServerName::try_from(name.clone())
                            .map_err(|_| format!("{name:?} is not a name a certificate can carry"))
                    })
                    .collect::<Result<_, _>>()?,
            })
        };
        cfg.dangerous().set_certificate_verifier(verifier);
    } else if params.insecure {
        let algorithms = params
            .profile
            .aws_provider()
            .signature_verification_algorithms;
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(AcceptAnyCertificate(algorithms)));
    }
    cfg.alpn_protocols = params.alpn.clone();
    if let Some(path) = &params.key_log {
        cfg.key_log = Arc::new(FileKeyLog::open(path)?);
    }
    params.profile.apply_to_config(&mut cfg);
    let profile_name = params
        .fingerprint_name
        .as_deref()
        .unwrap_or(params.profile.as_str());
    if let Some(profile) = profile_for_fingerprint(profile_name) {
        retain_profile_certificate_decompressors(profile, &mut cfg.cert_decompressors);
    }
    // With ECH the browser shape is left off. The shaping hook cannot tell
    // the outer ClientHello from the inner one it encrypts, and reshaping
    // them broke every ECH handshake with Cloudflare ("cannot decrypt peer's
    // message", measured 2026-09-28). ECH already hides the name the shape
    // would disguise, so a working handshake is the better trade.
    if params.ech_config_list.is_none() {
        params.profile.apply_client_hello_shape_named(
            &mut cfg,
            &params.alpn,
            false,
            profile_name,
            params.hello_version,
        )?;
    }
    Ok(cfg)
}

/// The verifier behind [`TlsParams::pinned`].
///
/// How it decides, in Xray's order: the leaf's SHA-256 is in the pin list,
/// accept (no chain or name check, which is what lets a self-signed server
/// work); else a certificate higher in the chain is pinned, so the usual
/// chain and name verification must pass; else refuse. The one thing that
/// differs from Xray is that a pinned CA is checked against the public roots,
/// not treated as the only root.
#[derive(Debug)]
struct PinnedCertificate {
    pins: Vec<[u8; 32]>,
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

/// Checks the certificate for any one of a list of names instead of the name
/// the hello carried (see [`TlsParams::with_verify_names`]). Everything else
/// about the verification is the wrapped verifier's.
#[derive(Debug)]
struct VerifyByName {
    inner: Arc<dyn ServerCertVerifier>,
    names: Vec<ServerName<'static>>,
}

impl ServerCertVerifier for VerifyByName {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut last = None;
        for name in &self.names {
            match self
                .inner
                .verify_server_cert(end_entity, intermediates, name, ocsp_response, now)
            {
                Ok(verified) => return Ok(verified),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or(rustls::Error::General(
            "no name to verify the certificate for".into(),
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Appends TLS session secrets to a file in the NSS key log format, one line
/// each: `LABEL client_random_hex secret_hex`.
struct FileKeyLog(std::sync::Mutex<std::fs::File>);

impl std::fmt::Debug for FileKeyLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKeyLog")
    }
}

impl FileKeyLog {
    fn open(path: &str) -> Result<Self, String> {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(path)
            .map(|file| Self(std::sync::Mutex::new(file)))
            .map_err(|error| format!("masterKeyLog {path}: {error}"))
    }
}

impl rustls::KeyLog for FileKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        use std::io::Write;
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let line = format!("{label} {} {}\n", hex(client_random), hex(secret));
        if let Ok(mut file) = self.0.lock() {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// The reason shown when no certificate of the chain is pinned.
#[derive(Debug)]
struct PinMismatch;

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the server's certificate is not the one pinned in the link (pcs)")
    }
}

impl std::error::Error for PinMismatch {}

impl PinnedCertificate {
    fn pinned(&self, certificate: &rustls_pki_types::CertificateDer<'_>) -> bool {
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
        self.pins.contains(&hash)
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.pinned(end_entity) {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        if !intermediates.iter().any(|c| self.pinned(c)) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(PinMismatch))),
            ));
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The verifier behind [`TlsParams::insecure`]: every certificate is
/// accepted, the handshake signatures are checked against it as usual.
#[derive(Debug)]
struct AcceptAnyCertificate(rustls::crypto::WebPkiSupportedAlgorithms);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// Wrap a connected stream in TLS.
pub async fn connect<S>(stream: S, params: &TlsParams) -> Result<TlsStream<S>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = try_client_config(params)?;
    connect_with(stream, params, config).await
}

/// Wrap a stream using a pre-built config, so a pool can share one.
pub async fn connect_with<S>(
    stream: S,
    params: &TlsParams,
    config: Arc<ClientConfig>,
) -> Result<TlsStream<S>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let inner_name = params
        .ech_server_name
        .as_deref()
        .unwrap_or(&params.server_name);
    let name = parse_server_name(inner_name)?;
    let connector = TlsConnector::from(config);

    connector
        .connect(name, stream)
        .await
        .map_err(|e| classify_handshake_error(&e))
}

fn parse_server_name(name: &str) -> Result<ServerName<'static>, Failure> {
    ServerName::try_from(name.to_string()).map_err(|_| {
        Failure::new(FailureKind::TlsCertificateFailure, Stage::TlsStarted)
            .with_confidence(Confidence::Confirmed)
            .with_detail(format!("invalid SNI {name:?}"))
    })
}

/// Map a TLS handshake failure onto the taxonomy.
///
/// The distinction that matters for Iran: a certificate failure is a real
/// server or trust problem, while a timeout or truncated handshake on a
/// connection whose TCP came up cleanly is the classic signature of an
/// on-path reset injector.
fn classify_handshake_error(e: &std::io::Error) -> Failure {
    use std::io::ErrorKind as K;

    if let Some(inner) = e.get_ref().and_then(|r| r.downcast_ref::<rustls::Error>()) {
        return match inner {
            rustls::Error::InvalidCertificate(_) => {
                Failure::new(FailureKind::TlsCertificateFailure, Stage::TlsStarted)
                    .with_confidence(Confidence::Confirmed)
                    .with_detail(inner.to_string())
            }
            rustls::Error::AlertReceived(alert) => {
                Failure::new(FailureKind::TlsAlert, Stage::TlsStarted)
                    .with_confidence(Confidence::Confirmed)
                    .with_detail(format!("alert {alert:?}"))
            }
            // The first record of the reply has a type TLS does not have: the
            // peer is not speaking TLS (a web server answering `HTTP/1.1 400`
            // is the usual case), so say that instead of "corrupt message".
            rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType) => {
                Failure::new(FailureKind::TlsHandshakeMalformed, Stage::TlsStarted)
                    .with_confidence(Confidence::Likely)
                    .with_detail(
                        "the server did not answer in TLS (wrong port, or TLS is off there)",
                    )
            }
            other => Failure::new(FailureKind::TlsHandshakeMalformed, Stage::TlsStarted)
                .with_confidence(Confidence::Likely)
                .with_detail(other.to_string()),
        };
    }

    match e.kind() {
        K::TimedOut => Failure::new(FailureKind::TlsTimeout, Stage::TlsStarted)
            .with_confidence(Confidence::Likely)
            .with_detail(e.to_string()),
        // TCP came up but the handshake was cut: strongly suggests injection.
        K::UnexpectedEof | K::ConnectionReset | K::ConnectionAborted => {
            Failure::new(FailureKind::TlsHandshakeMalformed, Stage::TlsStarted)
                .with_confidence(Confidence::Likely)
                .with_detail(e.to_string())
        }
        _ => Failure::from_io(e, Stage::TlsStarted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ECH_CONFIG_LIST: &str = "AGH+DQBdAAAgACAkIyMKSFWhOMEcF6lVctzNZE71S5DqKdc3bPtN7JpZCAAkAAEAAQABAAIAAQADAAIAAQACAAIAAgADAAMAAQADAAIAAwADAA5wdWJsaWMuZXhhbXBsZQAA";

    #[test]
    fn builds_config_with_alpn() {
        let p = TlsParams::new("example.com").with_alpn(&["http/1.1"]);
        let c = client_config(&p);
        assert_eq!(c.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn builds_config_with_ech_and_uses_inner_sni_for_the_connection() {
        use base64::Engine;

        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ECH_CONFIG_LIST)
            .unwrap();
        let p = TlsParams::new("outer.example").with_ech(bytes, Some("inner.example".into()));
        let c = try_client_config(&p).expect("valid ECH config list");
        assert_eq!(c.alpn_protocols, Vec::<Vec<u8>>::new());
        assert_eq!(p.ech_server_name.as_deref(), Some("inner.example"));
    }

    #[test]
    fn invalid_ech_is_a_reported_configuration_failure() {
        let p = TlsParams::new("example.com").with_ech([1, 2, 3], None);
        let error = try_client_config(&p).unwrap_err();
        assert_eq!(error.kind, FailureKind::TlsHandshakeMalformed);
        assert!(error
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("invalid ECHConfigList")));
    }

    #[test]
    fn preserves_sni_case() {
        // Randomised casing is an intentional evasion; normalising breaks it.
        let p = TlsParams::new("ExAmPle.WorKERS.dev");
        assert_eq!(p.server_name, "ExAmPle.WorKERS.dev");
        assert!(parse_server_name(&p.server_name).is_ok());
    }

    #[test]
    fn rejects_invalid_sni() {
        assert!(parse_server_name("not a host").is_err());
    }

    #[test]
    fn identical_params_share_one_config() {
        let a = client_config(&TlsParams::new("a.example").with_alpn(&["http/1.1"]));
        let b = client_config(&TlsParams::new("b.example").with_alpn(&["http/1.1"]));
        // Same pointer means the same session cache, which is what makes
        // resumption possible across connections.
        assert!(Arc::ptr_eq(&a, &b), "configs should be shared across SNIs");
    }

    #[test]
    fn different_alpn_gets_a_distinct_config() {
        let a = client_config(&TlsParams::new("x").with_alpn(&["http/1.1"]));
        let b = client_config(&TlsParams::new("x").with_alpn(&["h2"]));
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(b.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn different_fingerprint_gets_a_distinct_config() {
        let a = client_config(&TlsParams::new("x").with_profile(FingerprintProfile::Chrome));
        let b = client_config(&TlsParams::new("x").with_profile(FingerprintProfile::Firefox));
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn shaped_profiles_emit_a_browser_sized_first_flight() {
        let config =
            client_config(&TlsParams::new("example.com").with_profile(FingerprintProfile::Chrome));
        let name = ServerName::try_from("example.com".to_owned()).unwrap();
        let mut connection = rustls::ClientConnection::new(config, name).unwrap();
        let mut first_flight = Vec::new();
        connection.write_tls(&mut first_flight).unwrap();

        assert_eq!(first_flight.first(), Some(&22), "TLS handshake record");
        assert_eq!(
            first_flight.len(),
            1721,
            "Chrome 133 PQ/uTLS first-flight shape"
        );
    }

    /// The hello must carry the profile's own cipher-suite list, whole.
    ///
    /// This is the field a JA3 is built from, and the one a censor reads
    /// without decrypting anything, so it is the shape that has to match a real
    /// browser exactly — not the subset rustls can negotiate. The list is
    /// written as shape only; a suite the provider cannot do is never selected
    /// by the handshake.
    #[test]
    fn shaped_hello_carries_the_profile_cipher_suites_verbatim() {
        use crate::utls_profiles::profile_for_fingerprint;

        let profile = profile_for_fingerprint("chrome").expect("chrome profile");
        let config = client_config(&TlsParams::new("example.com").with_fingerprint_name("chrome"));
        let name = ServerName::try_from("example.com".to_owned()).unwrap();
        let mut connection = rustls::ClientConnection::new(config, name).unwrap();
        let mut first_flight = Vec::new();
        connection.write_tls(&mut first_flight).unwrap();

        let advertised = client_hello_cipher_suites(&first_flight);
        let expected: Vec<u16> = profile
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| !is_grease(*suite))
            .collect();
        let got: Vec<u16> = advertised
            .iter()
            .copied()
            .filter(|suite| !is_grease(*suite))
            .collect();
        assert_eq!(
            got, expected,
            "the hello must carry the profile's own suites, verbatim and in order"
        );
        assert!(
            advertised.iter().any(|suite| is_grease(*suite)),
            "the profile's GREASE suite is placed, not dropped"
        );
        assert_eq!(
            advertised.first().copied(),
            Some(0x0a0a),
            "chrome leads its cipher list with GREASE"
        );
    }

    /// The cipher-suite half of the first ClientHello in a TLS flight.
    ///
    /// Walks the record and handshake headers to the field rather than trusting
    /// a fixed offset, so a change in the hello's layout surfaces as a test
    /// failure here instead of silently reading the wrong bytes.
    fn client_hello_cipher_suites(flight: &[u8]) -> Vec<u16> {
        // Record header is 5 bytes, handshake header 4; then the ClientHello
        // body starts with client_version(2), random(32), session_id(1 + len).
        let body = flight
            .get(5..)
            .and_then(|record| record.get(4..))
            .expect("first flight starts with a record holding a handshake message");
        let session_id_len = usize::from(body[34]);
        let mut at = 35 + session_id_len;
        let suites_len = usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
        at += 2;
        body[at..at + suites_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .collect()
    }

    /// RFC 8701: GREASE values are `0x?a?a` with both bytes equal.
    fn is_grease(value: u16) -> bool {
        let [high, low] = value.to_be_bytes();
        high == low && high & 0x0f == 0x0a
    }

    #[test]
    fn shaped_profile_and_ech_emit_one_valid_first_flight() {
        use base64::Engine;

        let list = base64::engine::general_purpose::STANDARD
            .decode(ECH_CONFIG_LIST)
            .unwrap();
        let config = client_config(
            &TlsParams::new("outer.example")
                .with_profile(FingerprintProfile::Chrome)
                .with_ech(list, Some("inner.example".into())),
        );
        let name = ServerName::try_from("inner.example".to_owned()).unwrap();
        let mut connection = rustls::ClientConnection::new(config, name).unwrap();
        let mut first_flight = Vec::new();
        connection.write_tls(&mut first_flight).unwrap();
        assert_eq!(first_flight.first(), Some(&22), "TLS handshake record");
    }

    #[test]
    fn every_builtin_profile_can_emit_a_first_flight() {
        for profile in [
            FingerprintProfile::Chrome,
            FingerprintProfile::Firefox,
            FingerprintProfile::Safari,
            FingerprintProfile::Edge,
            FingerprintProfile::Ios,
            FingerprintProfile::Android,
        ] {
            let config = client_config(&TlsParams::new("example.com").with_profile(profile));
            let name = ServerName::try_from("example.com".to_owned()).unwrap();
            let mut connection = rustls::ClientConnection::new(config, name).unwrap();
            let mut first_flight = Vec::new();
            connection
                .write_tls(&mut first_flight)
                .unwrap_or_else(|error| panic!("{} profile failed: {error}", profile.as_str()));
            assert_eq!(
                first_flight.first(),
                Some(&22),
                "{} profile",
                profile.as_str()
            );
        }
    }

    #[test]
    fn every_concrete_xray_profile_can_emit_a_first_flight() {
        let names = [
            "hellochrome_auto",
            "hellochrome_133",
            "hellofirefox_auto",
            "hellofirefox_148",
            "hellosafari_auto",
            "hellosafari_26_3",
            "helloios_14",
            "helloios_auto",
            "helloandroid_11_okhttp",
            "helloedge_85",
            "helloedge_auto",
            "qq",
            "helloqq_11_1",
            "helloqq_auto",
            "hellorandomized",
            "randomizednoalpn",
            "hellorandomizednoalpn",
            "hellofirefox_120",
            "hellochrome_120",
            "hellochrome_131",
            "helloios_13",
            "helloedge_106",
            "hello360_11_0",
            "hellorandomizedalpn",
            "hellofirefox_55",
            "hellofirefox_56",
            "hellofirefox_63",
            "hellofirefox_65",
            "hellofirefox_99",
            "hellofirefox_102",
            "hellofirefox_105",
            "hellochrome_58",
            "hellochrome_62",
            "hellochrome_70",
            "hellochrome_72",
            "hellochrome_83",
            "hellochrome_87",
            "hellochrome_96",
            "hellochrome_100",
            "hellochrome_102",
            "hellochrome_106_shuffle",
            "helloios_11_1",
            "helloios_12_1",
            "hellosafari_16_0",
            "hellochrome_100_psk",
            "hellochrome_112_psk_shuf",
            "hellochrome_114_padding_psk_shuf",
            "hellochrome_115_pq",
            "hellochrome_115_pq_psk",
            "hellochrome_120_pq",
        ];
        for profile_name in names {
            let config = client_config(
                &TlsParams::new("example.com")
                    .with_profile(FingerprintProfile::Chrome)
                    .with_fingerprint_name(profile_name),
            );
            let name = ServerName::try_from("example.com".to_owned()).unwrap();
            let mut connection = match rustls::ClientConnection::new(config, name) {
                Ok(connection) => connection,
                Err(error) => {
                    println!("{profile_name}: {error}");
                    continue;
                }
            };
            let mut first_flight = Vec::new();
            connection
                .write_tls(&mut first_flight)
                .unwrap_or_else(|error| panic!("{profile_name} profile failed: {error}"));
            assert_eq!(first_flight.first(), Some(&22), "{profile_name} profile");
        }
    }

    #[test]
    fn legacy_cbc_only_profile_fails_closed() {
        let params = TlsParams::new("example.com")
            .with_profile(FingerprintProfile::Chrome)
            .with_fingerprint_name("hello360_auto");
        let error = try_client_config(&params).unwrap_err();
        assert!(error
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("no cipher suite supported")));
    }

    #[test]
    fn rotating_keys_do_not_grow_the_cache_without_bound() {
        // A private cache instance: flooding the global one would evict
        // entries other tests in this process are comparing by pointer.
        let config = Arc::new(build_client_config(&TlsParams::new("x")).unwrap());
        let key = |index: usize| ConfigKey {
            profile: FingerprintProfile::Chrome,
            fingerprint_name: None,
            alpn: Vec::new(),
            // Stands in for an ECHConfigList rotated by the DNS provider.
            ech_config_list: Some(index.to_be_bytes().to_vec()),
            extra_roots: Vec::new(),
            insecure: false,
            pinned: Vec::new(),
            verify_names: Vec::new(),
            key_log: None,
            hello_version: None,
        };
        let mut cache = ConfigCache {
            entries: HashMap::new(),
            clock: 0,
        };
        cache.insert(key(0), Arc::clone(&config));
        cache.insert(key(1), Arc::clone(&config));
        for index in 2..CONFIG_CACHE_LIMIT + 8 {
            // Key 1 stays hot; key 0 is never touched again.
            assert!(cache.get(&key(1)).is_some(), "hot entry evicted at {index}");
            cache.insert(key(index), Arc::clone(&config));
            assert!(cache.entries.len() <= CONFIG_CACHE_LIMIT);
        }
        assert!(
            cache.get(&key(0)).is_none(),
            "the coldest entry is evicted first"
        );
    }

    #[test]
    fn root_store_is_populated() {
        let p = TlsParams::new("example.com");
        // A config built with an empty root store would verify nothing.
        assert!(!webpki_roots::TLS_SERVER_ROOTS.is_empty());
        let _ = client_config(&p);
    }

    #[test]
    fn certificate_errors_are_confirmed_not_interference() {
        let e = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName),
        );
        let f = classify_handshake_error(&e);
        assert_eq!(f.kind, FailureKind::TlsCertificateFailure);
        assert!(!f.kind.suggests_interference());
    }

    #[test]
    fn a_reply_that_is_not_tls_is_named() {
        let e = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType),
        );
        let f = classify_handshake_error(&e);
        assert_eq!(f.kind, FailureKind::TlsHandshakeMalformed);
        assert!(f.to_string().contains("did not answer in TLS"), "{f}");
    }

    #[test]
    fn truncated_handshake_suggests_interference() {
        let e = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let f = classify_handshake_error(&e);
        assert_eq!(f.kind, FailureKind::TlsHandshakeMalformed);
        assert!(f.kind.suggests_interference());
    }

    /// A self-signed certificate for `dns.test`, and its key.
    const SELF_SIGNED_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIBlTCCATugAwIBAgIUGS+8Fs1U1nZuhCCERiq/cE2I/EwwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAwwIZG5zLnRlc3QwIBcNMjYwOTIzMDM0MjE0WhgPMjEyNjA4MzAw\nMzQyMTRaMBMxETAPBgNVBAMMCGRucy50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\nAQcDQgAE4SqQn7qEa4DtfdAqi9OaEwN90Nw7fFYqJZpApbzJvAx1SEqxXCzJyCEB\na8NVtrWewNSLFBsFbk6lRLJoZU/NkKNrMGkwHQYDVR0OBBYEFJK+70IhxQ31fNnu\nfzTg7k6NSpO9MB8GA1UdIwQYMBaAFJK+70IhxQ31fNnufzTg7k6NSpO9MBkGA1Ud\nEQQSMBCCCGRucy50ZXN0hwR/AAABMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwID\nSAAwRQIgNg84WOdtnUk+Q6MYOs83T0huf9SA6szJaAKPxRL6vf8CIQDqMr+gBsfi\n5i5jHcRxCnpNYCzjPGH0FgdOY12pKnFHpQ==\n-----END CERTIFICATE-----";
    const SELF_SIGNED_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7Gv8nckw9qy+6eL/\ng88Sxzpwfuq9C7IA8LrrBIkNWIChRANCAAThKpCfuoRrgO190CqL05oTA33Q3Dt8\nViolmkClvMm8DHVISrFcLMnIIQFrw1W2tZ7A1IsUGwVuTqVEsmhlT82Q\n-----END PRIVATE KEY-----";

    /// A TLS server with the self-signed certificate; returns its address.
    async fn self_signed_server() -> std::net::SocketAddr {
        use rustls_pki_types::pem::PemObject;
        let certs =
            vec![
                rustls_pki_types::CertificateDer::from_pem_slice(SELF_SIGNED_CERT.as_bytes())
                    .unwrap(),
            ];
        let key =
            rustls_pki_types::PrivateKeyDer::from_pem_slice(SELF_SIGNED_KEY.as_bytes()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(stream).await;
                });
            }
        });
        address
    }

    #[tokio::test]
    async fn a_certificate_nobody_vouches_for_is_refused_unless_the_link_asked() {
        let address = self_signed_server().await;
        let dial = |params: TlsParams| async move {
            let stream = tokio::net::TcpStream::connect(address).await.unwrap();
            connect(stream, &params).await.map(|_| ())
        };
        // The name does not match and no root vouches for it.
        let refused = dial(TlsParams::new("other.example")).await.unwrap_err();
        assert_eq!(refused.kind, FailureKind::TlsCertificateFailure);
        // The same server, with `allowInsecure` set, is reached.
        dial(TlsParams::new("other.example").with_insecure(true))
            .await
            .expect("an insecure handshake completes");
        // And the verifying config was not replaced by the insecure one in
        // the cache: asking again without it is still refused.
        assert!(dial(TlsParams::new("other.example")).await.is_err());
    }
    #[tokio::test]
    async fn a_pinned_leaf_is_accepted_without_allow_insecure_and_a_wrong_pin_is_refused() {
        use rustls_pki_types::pem::PemObject;
        use sha2::{Digest, Sha256};
        let address = self_signed_server().await;
        let leaf =
            rustls_pki_types::CertificateDer::from_pem_slice(SELF_SIGNED_CERT.as_bytes()).unwrap();
        let right: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        let dial = |params: TlsParams| async move {
            let stream = tokio::net::TcpStream::connect(address).await.unwrap();
            connect(stream, &params).await.map(|_| ())
        };
        // The name does not match and no root vouches for the certificate;
        // the pin alone makes it acceptable.
        dial(TlsParams::new("other.example").with_pinned_certs(vec![[0u8; 32], right]))
            .await
            .expect("a pinned leaf completes the handshake");
        // A pin that matches nothing refuses it, even with allowInsecure.
        let refused = dial(
            TlsParams::new("other.example")
                .with_insecure(true)
                .with_pinned_certs(vec![[7u8; 32]]),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.kind, FailureKind::TlsCertificateFailure);
        // The pinned config was not handed to a plain outbound.
        assert!(dial(TlsParams::new("other.example")).await.is_err());
    }

    /// The extensions of the first ClientHello in a flight, as (type, body).
    fn client_hello_extensions(flight: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let body = &flight[9..];
        let mut at = 34;
        at += 1 + usize::from(body[at]);
        at += 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
        at += 1 + usize::from(body[at]);
        let end = at + 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
        at += 2;
        let mut found = Vec::new();
        while at < end {
            let kind = u16::from_be_bytes([body[at], body[at + 1]]);
            let len = usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
            found.push((kind, body[at + 4..at + 4 + len].to_vec()));
            at += 4 + len;
        }
        found
    }

    fn first_flight(config: Arc<ClientConfig>) -> Vec<u8> {
        let name = ServerName::try_from("example.com".to_owned()).unwrap();
        let mut connection = rustls::ClientConnection::new(config, name).unwrap();
        let mut flight = Vec::new();
        connection.write_tls(&mut flight).unwrap();
        flight
    }

    /// A plain HTTPS client must send the browser's hello, not rustls's own,
    /// but only advertise the protocol it can speak: a server that picked `h2`
    /// for an HTTP/1.1-only fetcher would break the exchange.
    #[test]
    fn the_https_helper_wears_chrome_and_offers_only_what_it_speaks() {
        use crate::utls_profiles::profile_for_fingerprint;

        let flight = first_flight(https_client_config(&["http/1.1"]));
        let chrome = profile_for_fingerprint("chrome").unwrap();
        let wanted: Vec<u16> = chrome
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| !is_grease(*suite))
            .collect();
        let got: Vec<u16> = client_hello_cipher_suites(&flight)
            .into_iter()
            .filter(|suite| !is_grease(*suite))
            .collect();
        assert_eq!(got, wanted, "the suite list is Chrome's");

        let extensions = client_hello_extensions(&flight);
        let alpn = extensions
            .iter()
            .find(|(kind, _)| *kind == 0x0010)
            .expect("an ALPN extension is sent");
        assert_eq!(alpn.1, [&[0u8, 9, 8][..], b"http/1.1"].concat());
        for kind in [0x001b, 0x44cd, 0xfe0d] {
            assert!(
                extensions.iter().any(|(k, _)| *k == kind),
                "the Chrome extension {kind:#06x} is present"
            );
        }
    }

    #[derive(Debug)]
    struct Yes(rustls::crypto::WebPkiSupportedAlgorithms);
    impl ServerCertVerifier for Yes {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &self.0)
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.0)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.supported_schemes()
        }
    }

    #[test]
    fn a_config_with_a_verifier_or_a_client_key_is_never_shared() {
        let algorithms = FingerprintProfile::Chrome
            .aws_provider()
            .signature_verification_algorithms;
        let with_verifier = || {
            TlsParams::new("x.example")
                .with_profile(FingerprintProfile::Chrome)
                .with_verifier(Arc::new(Yes(algorithms)))
        };
        let a = try_client_config(&with_verifier()).unwrap();
        let b = try_client_config(&with_verifier()).unwrap();
        assert!(!Arc::ptr_eq(&a, &b), "a verifier config is built each time");
        let plain = TlsParams::new("x.example").with_profile(FingerprintProfile::Chrome);
        assert!(Arc::ptr_eq(
            &try_client_config(&plain).unwrap(),
            &try_client_config(&plain).unwrap()
        ));
    }

    #[tokio::test]
    async fn a_caller_verifier_decides_instead_of_the_public_roots() {
        let address = self_signed_server().await;
        let algorithms = FingerprintProfile::Chrome
            .aws_provider()
            .signature_verification_algorithms;
        let params = TlsParams::new("not-the-certificate-name.example")
            .with_profile(FingerprintProfile::Chrome)
            .with_verifier(Arc::new(Yes(algorithms)));
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        connect(stream, &params)
            .await
            .expect("the verifier's yes completes the handshake");
        // The same dial without it is refused by the public roots.
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let plain = TlsParams::new("not-the-certificate-name.example")
            .with_profile(FingerprintProfile::Chrome);
        assert!(connect(stream, &plain).await.is_err());
    }

    /// The hello's own `legacy_version` is what the params say, with and
    /// without a browser shape, and the handshake still completes (the
    /// field is part of the transcript the Finished messages sign).
    #[tokio::test]
    async fn the_hello_version_field_is_written_as_asked_and_the_handshake_holds() {
        use rustls_pki_types::pem::PemObject;
        let certs =
            vec![
                rustls_pki_types::CertificateDer::from_pem_slice(SELF_SIGNED_CERT.as_bytes())
                    .unwrap(),
            ];
        let key =
            rustls_pki_types::PrivateKeyDer::from_pem_slice(SELF_SIGNED_KEY.as_bytes()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                // Bytes 9 and 10 of the stream: record header (5), handshake
                // header (4), then the hello's two version bytes.
                let mut head = [0u8; 11];
                while stream.peek(&mut head).await.is_ok_and(|n| n < 11) {}
                let _ = seen_tx.send([head[9], head[10]]);
                let _ = acceptor.accept(stream).await;
            }
        });
        for (profile, name) in [
            (FingerprintProfile::Unshaped, "unshaped"),
            (FingerprintProfile::Chrome, "chrome"),
        ] {
            for (version, expected) in [(None, [0x03, 0x03]), (Some(0x0304), [0x03, 0x04])] {
                let mut params = TlsParams::new("dns.test")
                    .with_profile(profile)
                    .with_insecure(true);
                if let Some(version) = version {
                    params = params.with_hello_version(version);
                }
                let stream = tokio::net::TcpStream::connect(address).await.unwrap();
                connect(stream, &params)
                    .await
                    .unwrap_or_else(|e| panic!("{name} {version:?}: handshake failed: {e}"));
                assert_eq!(seen.recv().await.unwrap(), expected, "{name} {version:?}");
            }
        }
    }
}
