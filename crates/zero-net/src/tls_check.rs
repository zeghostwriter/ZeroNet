//! Does a server at an address present a valid certificate for a name?
//!
//! A relay that answers for a name it should only pass through (an
//! anti-sanction resolver's relay, a captive portal, a middlebox) shows up
//! here as a certificate that does not verify. Strict-HTTPS sites (HSTS) give
//! the user no way past that, so such an address must not be used directly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::ServerName;
use tokio::net::TcpStream;

/// Connect to `addr`, run a TLS handshake for `server_name` against the
/// public web roots, and drop the connection. The handshake itself proves
/// the chain and the name; nothing is sent.
pub async fn verify_tls(
    addr: SocketAddr,
    server_name: &str,
    timeout: Duration,
) -> Result<(), std::io::Error> {
    verify_tls_with(addr, server_name, crate::fetch::tls_config(), timeout).await
}

/// [`verify_tls`] against a caller-supplied client configuration.
pub async fn verify_tls_with(
    addr: SocketAddr,
    server_name: &str,
    config: Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> Result<(), std::io::Error> {
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let handshake = async {
        let tcp = TcpStream::connect(addr).await?;
        tokio_rustls::TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .map(drop)
    };
    tokio::time::timeout(timeout, handshake)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS check timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &[u8] = include_bytes!("../../zero-runtime/tests/fixtures/loopback-ca.pem");
    const CERT: &[u8] = include_bytes!("../../zero-runtime/tests/fixtures/loopback-cert.pem");
    const KEY: &[u8] = include_bytes!("../../zero-runtime/tests/fixtures/loopback-key.pem");

    async fn serve() -> SocketAddr {
        let certs: Vec<_> = rustls_pemfile_certs(CERT);
        use rustls_pki_types::pem::PemObject;
        let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(KEY).expect("key");
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
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(tcp).await;
                });
            }
        });
        addr
    }

    fn rustls_pemfile_certs(pem: &[u8]) -> Vec<rustls_pki_types::CertificateDer<'static>> {
        use rustls_pki_types::pem::PemObject;
        rustls_pki_types::CertificateDer::pem_slice_iter(pem)
            .collect::<Result<_, _>>()
            .expect("certs")
    }

    fn trusting_fixture_ca() -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile_certs(CA) {
            roots.add(cert).unwrap();
        }
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }

    #[tokio::test]
    async fn accepts_a_certificate_that_verifies_for_the_name() {
        let addr = serve().await;
        verify_tls_with(
            addr,
            "zray.test",
            trusting_fixture_ca(),
            Duration::from_secs(3),
        )
        .await
        .expect("a valid chain for the right name");
    }

    #[tokio::test]
    async fn rejects_a_wrong_name_and_an_untrusted_issuer() {
        let addr = serve().await;
        verify_tls_with(
            addr,
            "other.example",
            trusting_fixture_ca(),
            Duration::from_secs(3),
        )
        .await
        .expect_err("the certificate is not for this name");
        verify_tls(addr, "zray.test", Duration::from_secs(3))
            .await
            .expect_err("the public roots do not trust the fixture CA");
    }
}
