//! Loopback stand-ins for the WARP edge, for tests of this crate and of the
//! ones that drive a tunnel through it (feature `test-util`).
//!
//! Each accepts TLS 1.3 with a client certificate, checks the CONNECT request
//! the way Cloudflare's edge reads it, answers 200, and echoes every packet
//! back, which is all a tunnel test needs to see both directions work.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{ring as ring_provider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::time::timeout;

use super::{get_varint, point_of_spki, spki_of_certificate, MasqueKey};

/// A client-certificate check that accepts any certificate and remembers the
/// key it carried, so a test can say which key the client authenticated with.
#[derive(Debug)]
struct AnyClient {
    algorithms: WebPkiSupportedAlgorithms,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl rustls::server::danger::ClientCertVerifier for AnyClient {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let point = spki_of_certificate(end_entity.as_ref())
            .and_then(point_of_spki)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        self.seen.lock().unwrap().push(point);
        Ok(rustls::server::danger::ClientCertVerified::assertion())
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

pub fn server_tls(
    server: &MasqueKey,
    alpn: &[u8],
) -> (rustls::ServerConfig, Arc<Mutex<Vec<Vec<u8>>>>) {
    let provider = Arc::new(ring_provider::default_provider());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let verifier = AnyClient {
        algorithms: provider.signature_verification_algorithms,
        seen: Arc::clone(&seen),
    };
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(
            vec![CertificateDer::from(
                server.certificate(SystemTime::now()).unwrap(),
            )],
            PrivateKeyDer::try_from(server.pkcs8().to_vec()).unwrap(),
        )
        .unwrap();
    config.alpn_protocols = vec![alpn.to_vec()];
    (config, seen)
}

/// An HTTP/2 WARP stand-in: TLS with client authentication, `CONNECT` with
/// Cloudflare's headers, and capsules echoed straight back. With
/// `drop_first` it hangs up on the first connection after one capsule.
pub async fn h2_server(
    server: &MasqueKey,
    drop_first: bool,
) -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>, Arc<AtomicUsize>) {
    let (config, seen) = server_tls(server, b"h2");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&connections);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let nth = counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut connection) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    assert_eq!(request.method(), http::Method::CONNECT);
                    assert_eq!(
                        request.uri().authority().unwrap().as_str(),
                        "cloudflareaccess.com:443"
                    );
                    assert_eq!(request.headers()["cf-connect-proto"], "cf-connect-ip");
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    let mut body = request.into_body();
                    let hang_up = drop_first && nth == 0;
                    tokio::spawn(async move {
                        let mut pending: Vec<u8> = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            pending.extend_from_slice(&chunk);
                            // Whole capsules only: answer each packet in it.
                            while let Some((kind, a)) = get_varint(&pending) {
                                let Some((length, b)) = get_varint(&pending[a..]) else {
                                    break;
                                };
                                let end = a + b + length as usize;
                                if pending.len() < end {
                                    break;
                                }
                                if kind == 0 {
                                    let reply = edge_reply(&pending[a + b..end]);
                                    let mut capsule = vec![0];
                                    super::put_varint(&mut capsule, reply.len() as u64);
                                    capsule.extend_from_slice(&reply);
                                    if send.send_data(capsule.into(), false).is_err() {
                                        return;
                                    }
                                }
                                pending.drain(..end);
                            }
                            if hang_up {
                                return;
                            }
                        }
                    });
                    if hang_up {
                        // Keep serving for a moment so the response and the
                        // echo go out, then drop the whole connection.
                        let _ = timeout(Duration::from_millis(400), async {
                            while connection.accept().await.is_some() {}
                        })
                        .await;
                        return;
                    }
                }
            });
        }
    });
    (address, seen, connections)
}

/// An HTTP/3 WARP stand-in on QUIC: the same checks, datagrams echoed back.
pub async fn h3_server(
    server: &MasqueKey,
) -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>, Arc<AtomicUsize>) {
    use h3_quinn::quinn;
    let (config, seen) = server_tls(server, b"h3");
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(config).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&connections);
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let control = connection.clone();
                tokio::spawn(async move {
                    // The client's control stream carries datagram support.
                    let mut streams = Vec::new();
                    while let Ok(mut stream) = control.accept_uni().await {
                        let mut bytes = Vec::new();
                        let mut chunk = [0u8; 256];
                        if let Ok(Some(n)) = stream.read(&mut chunk).await {
                            bytes.extend_from_slice(&chunk[..n]);
                        }
                        if bytes.first() == Some(&0) {
                            // SETTINGS: H3_DATAGRAM (0x33 = 1) and the draft 0x276.
                            assert!(bytes.windows(2).any(|w| w == [0x33, 0x01]), "{bytes:x?}");
                            assert!(
                                bytes.windows(3).any(|w| w == [0x42, 0x76, 0x01]),
                                "{bytes:x?}"
                            );
                        }
                        streams.push(stream);
                    }
                });
                let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                    return;
                };
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let Ok(Some(n)) = recv.read(&mut chunk).await else {
                        return;
                    };
                    request.extend_from_slice(&chunk[..n]);
                    let Some((kind, used)) = get_varint(&request) else {
                        continue;
                    };
                    let Some((length, used2)) = get_varint(&request[used..]) else {
                        continue;
                    };
                    if request.len() >= used + used2 + length as usize {
                        assert_eq!(kind, 1);
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&request).into_owned();
                assert!(text.contains("cf-connect-ip") && text.contains("cloudflareaccess.com"));
                // HEADERS: no dynamic table, ":status 200" (static index 25).
                send.write_all(&[0x01, 0x03, 0x00, 0x00, 0xc0 | 25])
                    .await
                    .unwrap();
                while let Ok(datagram) = connection.read_datagram().await {
                    // Quarter stream id 0, context id 0, then the packet.
                    let Some(packet) = datagram.strip_prefix(&[0u8, 0][..]) else {
                        continue;
                    };
                    let mut reply = vec![0u8, 0];
                    reply.extend_from_slice(&edge_reply(packet));
                    if connection.send_datagram(reply.into()).is_err() {
                        return;
                    }
                }
                drop(send);
            });
        }
    });
    (address, seen, connections)
}

/// What the edge sends back for one packet from the client: an answer for a
/// DNS query to port 53, so a tunnel can be probed the way a real one is, and
/// the packet itself for anything else.
fn edge_reply(packet: &[u8]) -> Vec<u8> {
    dns_reply(packet).unwrap_or_else(|| packet.to_vec())
}

/// An IPv4 UDP query to port 53 answered with one A record (93.184.216.34).
fn dns_reply(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 28 || packet[0] != 0x45 || packet[9] != 17 {
        return None;
    }
    let (source_port, destination_port) = (
        u16::from_be_bytes([packet[20], packet[21]]),
        u16::from_be_bytes([packet[22], packet[23]]),
    );
    let query = packet.get(28..)?;
    // A plain query: one question, nothing after it.
    if destination_port != 53 || query.len() < 17 || query[4..12] != [0, 1, 0, 0, 0, 0, 0, 0] {
        return None;
    }
    let mut answer = query.to_vec();
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[7] = 1;
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
    let total = 28 + answer.len();
    let mut out = vec![0u8; 28];
    out[0] = 0x45;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[8] = 64;
    out[9] = 17;
    out[12..16].copy_from_slice(&packet[16..20]);
    out[16..20].copy_from_slice(&packet[12..16]);
    let mut sum = 0u32;
    for pair in out[..20].chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    out[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    out[20..22].copy_from_slice(&destination_port.to_be_bytes());
    out[22..24].copy_from_slice(&source_port.to_be_bytes());
    out[24..26].copy_from_slice(&((8 + answer.len()) as u16).to_be_bytes());
    // A zero UDP checksum means "none" over IPv4.
    out.extend_from_slice(&answer);
    Some(out)
}
