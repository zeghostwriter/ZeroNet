//! Ordinary TLS termination for inbound listeners.
//!
//! REALITY is intentionally not routed through this module: it needs
//! ClientHello/session-id control that stock rustls does not expose. Keeping
//! ordinary certificate TLS here gives VLESS and Trojan server inbounds a
//! complete, well-audited path without weakening the REALITY boundary.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

use rustls::ServerConfig;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// One cached inbound configuration, keyed by the exact inputs it was built
/// from so a reloaded certificate or key yields a fresh config.
struct CachedServerConfig {
    certificate: Box<[u8]>,
    private_key: zeroize::Zeroizing<Vec<u8>>,
    alpn: Box<[Box<str>]>,
    config: Arc<ServerConfig>,
}

/// Enough for every TLS inbound of a realistic config plus a reload or two.
const SERVER_CONFIG_CACHE_LIMIT: usize = 16;

fn server_config_cache() -> &'static Mutex<VecDeque<CachedServerConfig>> {
    static CACHE: OnceLock<Mutex<VecDeque<CachedServerConfig>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Build (or reuse) the rustls config for an inbound certificate/key pair.
///
/// Inbound listeners call this per accepted connection. Rebuilding would
/// re-parse the PEM chain and key and re-derive the signing key on every
/// handshake, and — worse — give every connection its own session cache and
/// ticket state, so resumption could never succeed. The cache compares the
/// full inputs, never a hash of them, so two different keys cannot collide.
pub fn server_config(
    certificate: &[u8],
    private_key: &[u8],
    alpn: &[Box<str>],
) -> Result<Arc<ServerConfig>, String> {
    if let Ok(cache) = server_config_cache().lock() {
        if let Some(entry) = cache.iter().find(|entry| {
            *entry.certificate == *certificate
                && entry.private_key.as_slice() == private_key
                && *entry.alpn == *alpn
        }) {
            return Ok(Arc::clone(&entry.config));
        }
    }

    let config = build_server_config(certificate, private_key, alpn)?;

    if let Ok(mut cache) = server_config_cache().lock() {
        if cache.len() >= SERVER_CONFIG_CACHE_LIMIT {
            cache.pop_front();
        }
        cache.push_back(CachedServerConfig {
            certificate: certificate.into(),
            private_key: zeroize::Zeroizing::new(private_key.to_vec()),
            alpn: alpn.into(),
            config: Arc::clone(&config),
        });
    }
    Ok(config)
}

fn build_server_config(
    certificate: &[u8],
    private_key: &[u8],
    alpn: &[Box<str>],
) -> Result<Arc<ServerConfig>, String> {
    let certificates = parse_certificates(certificate)?;
    if certificates.is_empty() {
        return Err("inbound TLS certificate chain is empty".into());
    }
    let key = parse_private_key(private_key)?;
    let mut config =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("unsupported server TLS versions: {error}"))?
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .map_err(|error| format!("invalid inbound TLS certificate/key: {error}"))?;
    config.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
    Ok(Arc::new(config))
}

/// A server configuration with several certificates, one chosen per
/// handshake by the server name the client asked for (Xray lists more than
/// one entry in `certificates`).
///
/// The first identity is the default, used when the client names nothing or
/// something no identity is valid for; with `reject_unknown_sni` the
/// handshake fails in that case instead, so a prober asking for a name the
/// server does not serve learns nothing from the certificate it is shown.
pub fn server_config_multi(
    identities: &[(&[u8], &[u8])],
    alpn: &[Box<str>],
    reject_unknown_sni: bool,
) -> Result<Arc<ServerConfig>, String> {
    let provider = rustls::crypto::ring::default_provider();
    let mut keys = Vec::with_capacity(identities.len());
    for (index, (certificate, private_key)) in identities.iter().enumerate() {
        let chain = parse_certificates(certificate)?;
        if chain.is_empty() {
            return Err(format!(
                "inbound TLS certificate {index} has an empty chain"
            ));
        }
        let key = parse_private_key(private_key)?;
        let signing = provider
            .key_provider
            .load_private_key(key)
            .map_err(|error| format!("invalid inbound TLS key {index}: {error}"))?;
        keys.push(Arc::new(rustls::sign::CertifiedKey::new(chain, signing)));
    }
    if keys.is_empty() {
        return Err("inbound TLS has no certificate".into());
    }
    let mut config = ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("unsupported server TLS versions: {error}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(NameResolver {
            keys,
            reject_unknown_sni,
        }));
    config.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
    Ok(Arc::new(config))
}

/// Picks the certificate that is valid for the name in the hello.
#[derive(Debug)]
struct NameResolver {
    keys: Vec<Arc<rustls::sign::CertifiedKey>>,
    reject_unknown_sni: bool,
}

impl rustls::server::ResolvesServerCert for NameResolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let named = hello
            .server_name()
            .and_then(|name| rustls_pki_types::ServerName::try_from(name).ok())
            .and_then(|name| {
                self.keys.iter().find(|key| {
                    key.end_entity_cert()
                        .ok()
                        .and_then(|cert| rustls::server::ParsedCertificate::try_from(cert).ok())
                        .is_some_and(|cert| {
                            rustls::client::verify_server_name(&cert, &name).is_ok()
                        })
                })
            });
        match named {
            Some(key) => Some(Arc::clone(key)),
            None if self.reject_unknown_sni => None,
            None => self.keys.first().cloned(),
        }
    }
}

pub async fn accept<S>(stream: S, config: Arc<ServerConfig>) -> Result<TlsStream<S>, std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    TlsAcceptor::from(config).accept(stream).await
}

fn parse_certificates(input: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    if input.starts_with(b"-----BEGIN") {
        CertificateDer::pem_slice_iter(input)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("reading PEM certificate chain: {error}"))
    } else {
        Ok(vec![CertificateDer::from(input.to_vec())])
    }
}

fn parse_private_key(input: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    if input.starts_with(b"-----BEGIN") {
        Ok(PrivateKeyDer::from_pem_slice(input)
            .map_err(|error| format!("reading PEM private key: {error}"))?)
    } else {
        PrivateKeyDer::try_from(input.to_vec())
            .map_err(|_| "DER private key is not PKCS#1, SEC1, or PKCS#8".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_certificate_chain() {
        assert!(server_config(&[], &[1, 2, 3], &[]).is_err());
    }

    const CERT: &[u8] = include_bytes!("../../zero-runtime/tests/fixtures/loopback-cert.pem");
    const KEY: &[u8] = include_bytes!("../../zero-runtime/tests/fixtures/loopback-key.pem");

    #[test]
    fn identical_inputs_share_one_config_and_its_session_state() {
        let alpn: Vec<Box<str>> = vec!["h2".into()];
        let a = server_config(CERT, KEY, &alpn).unwrap();
        let b = server_config(CERT, KEY, &alpn).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let c = server_config(CERT, KEY, &["http/1.1".into()]).unwrap();
        assert!(
            !Arc::ptr_eq(&a, &c),
            "different ALPN must not share a config"
        );
        assert_eq!(c.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn failed_builds_are_not_cached() {
        // A failure must be reported again, not replaced by a cached success
        // or silently remembered as one.
        assert!(server_config(&[], &[1, 2, 3], &[]).is_err());
        assert!(server_config(&[], &[1, 2, 3], &[]).is_err());
    }

    const BIG_CERT: &[u8] = include_bytes!("../../zero-runtime/tests/fixtures/big-decoy-cert.pem");
    const BIG_KEY: &[u8] = include_bytes!("../../zero-runtime/tests/fixtures/big-decoy-key.pem");

    /// The first certificate a server presents to a client that asks for
    /// `name` (`None` for no name), or `None` if the handshake fails.
    async fn served_for(config: Arc<ServerConfig>, name: Option<&str>) -> Option<Vec<u8>> {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        #[derive(Debug)]
        struct TakeAnything;
        impl ServerCertVerifier for TakeAnything {
            fn verify_server_cert(
                &self,
                _: &CertificateDer<'_>,
                _: &[CertificateDer<'_>],
                _: &rustls_pki_types::ServerName<'_>,
                _: &[u8],
                _: rustls_pki_types::UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }
        let mut client = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TakeAnything))
        .with_no_client_auth();
        client.enable_sni = name.is_some();
        let (near, far) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move { accept(far, config).await.map(|_| ()) });
        let server_name = rustls_pki_types::ServerName::try_from(name.unwrap_or("unused.example"))
            .unwrap()
            .to_owned();
        let connected = tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(server_name, near)
            .await;
        let _ = server.await;
        let stream = connected.ok()?;
        let (_, session) = stream.get_ref();
        session
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|cert| cert.as_ref().to_vec())
    }

    fn der(pem: &[u8]) -> Vec<u8> {
        parse_certificates(pem).unwrap().remove(0).as_ref().to_vec()
    }

    #[tokio::test]
    async fn the_certificate_follows_the_name_the_client_asks_for() {
        let config = server_config_multi(&[(CERT, KEY), (BIG_CERT, BIG_KEY)], &[], false).unwrap();
        let (loopback, big) = (der(CERT), der(BIG_CERT));
        assert_eq!(
            served_for(config.clone(), Some("www.googletagmanager.com")).await,
            Some(big.clone())
        );
        assert_eq!(
            served_for(config.clone(), Some("zray.test")).await,
            Some(loopback.clone())
        );
        // A name neither is for, or none, gets the first (the default).
        assert_eq!(
            served_for(config.clone(), Some("elsewhere.example")).await,
            Some(loopback.clone())
        );
        assert_eq!(served_for(config, None).await, Some(loopback));
    }

    #[tokio::test]
    async fn an_unknown_name_is_refused_when_the_server_says_so() {
        let config = server_config_multi(&[(CERT, KEY), (BIG_CERT, BIG_KEY)], &[], true).unwrap();
        assert!(served_for(config.clone(), Some("zray.test"))
            .await
            .is_some());
        assert!(served_for(config.clone(), Some("elsewhere.example"))
            .await
            .is_none());
        assert!(served_for(config, None).await.is_none());
    }
}
