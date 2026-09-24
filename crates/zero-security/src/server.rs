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
}
