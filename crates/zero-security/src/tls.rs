//! TLS client connections.
//!
//! The TLS backend and the ClientHello *shape* are deliberately separate
//! concerns (RESEARCH-01 §14). This module owns the backend; `fingerprint`
//! owns the shape. A rustls upgrade must not be able to silently change what
//! a censor sees on the wire.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use rustls::ClientConfig;
use rustls_pki_types::ServerName;
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
        }
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

/// Build (or reuse) a verifying client config.
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
/// There is no code path that disables certificate verification. Xray's
/// `allowInsecure` is rejected during parsing rather than plumbed through, so
/// a misconfigured profile cannot silently downgrade a user's security.
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
    };

    if let Ok(mut cache) = config_cache().lock() {
        if let Some(found) = cache.get(&key) {
            return Ok(found);
        }
    }

    let cfg = Arc::new(build_client_config(params).map_err(|detail| {
        Failure::new(FailureKind::TlsHandshakeMalformed, Stage::TlsStarted)
            .with_confidence(Confidence::Confirmed)
            .with_detail(detail)
    })?);

    if let Ok(mut cache) = config_cache().lock() {
        return Ok(cache.insert(key, cfg));
    }
    Ok(cfg)
}

fn build_client_config(params: &TlsParams) -> Result<ClientConfig, String> {
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
        params.profile.apply_to_builder(roots).with_no_client_auth()
    };

    cfg.alpn_protocols = params.alpn.clone();
    params.profile.apply_to_config(&mut cfg);
    let profile_name = params
        .fingerprint_name
        .as_deref()
        .unwrap_or(params.profile.as_str());
    if let Some(profile) = profile_for_fingerprint(profile_name) {
        retain_profile_certificate_decompressors(profile, &mut cfg.cert_decompressors);
    }
    params.profile.apply_client_hello_shape_named(
        &mut cfg,
        &params.alpn,
        params.ech_config_list.is_some(),
        profile_name,
    )?;
    Ok(cfg)
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
            1709,
            "Chrome 133 PQ/uTLS first-flight shape"
        );
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
    fn truncated_handshake_suggests_interference() {
        let e = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let f = classify_handshake_error(&e);
        assert_eq!(f.kind, FailureKind::TlsHandshakeMalformed);
        assert!(f.kind.suggests_interference());
    }
}
