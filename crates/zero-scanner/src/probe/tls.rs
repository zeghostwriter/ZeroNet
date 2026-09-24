use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

#[derive(Debug)]
struct NoopServerCertVerifier;

impl ServerCertVerifier for NoopServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Process-wide probe TLS configuration.
///
/// Building a `ClientConfig` is not free (provider setup, cipher suite and
/// key-exchange lists, session cache allocation), so every probe, speed test
/// and proxy validation shares this one instead of building its own. Sharing
/// it also lets the rustls session cache resume sessions across probes.
pub fn shared_tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG.get_or_init(make_tls_config).clone()
}

pub fn make_tls_config() -> Arc<ClientConfig> {
    let mut config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoopServerCertVerifier))
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

pub async fn connect_tls(
    stream: TcpStream,
    sni: &str,
    config: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<TlsStream<TcpStream>, std::io::Error> {
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;

    let handshake_fut = connector.connect(server_name, stream);
    match tokio::time::timeout(timeout, handshake_fut).await {
        Ok(Ok(tls_stream)) => Ok(tls_stream),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "TLS handshake timed out",
        )),
    }
}
