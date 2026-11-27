//! Salamander, the UDP obfuscation Hysteria 2 defines (`obfs: salamander`).
//!
//! Every datagram on the wire is `salt (8 random bytes) || payload`, with the
//! payload XORed against `BLAKE2b-256(password || salt)` repeated over its
//! length. A fresh salt per datagram makes every packet look like random
//! bytes, so the QUIC header a filter would recognise never appears.
//!
//! This is obfuscation, not encryption: the password only has to be known to
//! the two ends, QUIC and TLS inside still do the protecting. Both ends must
//! use the same password, and a packet that was not obfuscated with it comes
//! out as noise that QUIC drops.
//!
//! [`ObfuscatedSocket`] applies it to a QUIC endpoint's UDP socket, one
//! datagram at a time:
//!
//! * sending keeps batching (GSO): each datagram of a batch gets its own salt
//!   and the batch's segment size grows by the salt;
//! * receiving undoes it in place, including datagrams the kernel glued
//!   together (GRO), which are cut at their stride first.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::RngCore;

/// Bytes of salt in front of every datagram.
pub const SALT_LEN: usize = 8;
/// Shortest password the Hysteria 2 server accepts.
pub const MIN_PASSWORD_LEN: usize = 4;
/// Length of the BLAKE2b-256 key stream block.
const KEY_LEN: usize = 32;

/// A Salamander password, ready to obfuscate datagrams.
#[derive(Clone)]
pub struct Salamander {
    password: Arc<[u8]>,
}

impl fmt::Debug for Salamander {
    /// The password is a credential and stays out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salamander(..)")
    }
}

impl Salamander {
    /// `Err` when the password is shorter than the server would accept.
    pub fn new(password: &str) -> Result<Self, String> {
        if password.len() < MIN_PASSWORD_LEN {
            return Err(format!(
                "the Salamander password must be at least {MIN_PASSWORD_LEN} bytes"
            ));
        }
        Ok(Self {
            password: password.as_bytes().into(),
        })
    }

    fn key(&self, salt: &[u8]) -> [u8; KEY_LEN] {
        let mut hash = Blake2b::<U32>::new();
        hash.update(&self.password);
        hash.update(salt);
        hash.finalize().into()
    }

    /// Append the obfuscated form of `plain` (salt first) to `out`.
    pub fn obfuscate(&self, plain: &[u8], out: &mut Vec<u8>) {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        self.obfuscate_with_salt(&salt, plain, out);
    }

    fn obfuscate_with_salt(&self, salt: &[u8; SALT_LEN], plain: &[u8], out: &mut Vec<u8>) {
        let key = self.key(salt);
        out.extend_from_slice(salt);
        out.extend(plain.iter().enumerate().map(|(i, b)| b ^ key[i % KEY_LEN]));
    }

    /// The obfuscation of a fixed text under a fixed salt: a value that
    /// differs between passwords and reveals neither, for telling two
    /// configurations apart (a pool key) without holding the password.
    pub(crate) fn obfuscate_with_fixed_salt(&self, out: &mut Vec<u8>) {
        self.obfuscate_with_salt(&[0u8; SALT_LEN], b"zray salamander key probe", out);
    }

    /// Undo [`Self::obfuscate`] on `datagram` in place, moving the payload to
    /// the front of the slice. Returns the payload length, or `None` when
    /// the datagram is too short to hold a salt and a byte.
    pub fn deobfuscate_in_place(&self, datagram: &mut [u8]) -> Option<usize> {
        if datagram.len() <= SALT_LEN {
            return None;
        }
        let key = self.key(&datagram[..SALT_LEN]);
        let payload = datagram.len() - SALT_LEN;
        // Forward, one byte at a time: the byte read is always ahead of the
        // byte written, so nothing is overwritten before it is used.
        for i in 0..payload {
            datagram[i] = datagram[SALT_LEN + i] ^ key[i % KEY_LEN];
        }
        Some(payload)
    }
}

/// A UDP socket whose every datagram is Salamander-obfuscated, for a QUIC
/// endpoint to run on (see the module docs).
pub struct ObfuscatedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    salamander: Salamander,
    /// The obfuscated datagram being sent; reused so a send allocates nothing.
    scratch: Mutex<Vec<u8>>,
}

impl fmt::Debug for ObfuscatedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfuscatedSocket").finish_non_exhaustive()
    }
}

impl ObfuscatedSocket {
    pub fn wrap(inner: Arc<dyn AsyncUdpSocket>, salamander: Salamander) -> Arc<dyn AsyncUdpSocket> {
        Arc::new(Self {
            inner,
            salamander,
            scratch: Mutex::new(Vec::with_capacity(1500)),
        })
    }
}

impl AsyncUdpSocket for ObfuscatedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // A transmit is one datagram, or several of one size (the last may be
        // shorter) that the kernel splits when sending (GSO). Each gets its
        // own salt, which makes every one 8 bytes longer, so the batch keeps
        // its shape with a segment size 8 larger.
        let segment = transmit.segment_size.unwrap_or(transmit.contents.len());
        let mut scratch = self
            .scratch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        scratch.clear();
        for datagram in transmit.contents.chunks(segment.max(1)) {
            self.salamander.obfuscate(datagram, &mut scratch);
        }
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &scratch,
            segment_size: transmit.segment_size.map(|size| size + SALT_LEN),
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => count,
            other => return other,
        };
        for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()).take(count) {
            let total = meta.len.min(buf.len());
            // One datagram, or several the kernel joined: every one but the
            // last is `stride` long.
            let stride = if meta.stride == 0 { total } else { meta.stride };
            let mut written = 0;
            let mut read = 0;
            while read < total {
                let end = (read + stride).min(total);
                // The payload lands at `written`, never past what was read.
                let chunk = &mut buf[read..end];
                let chunk_len = chunk.len();
                if let Some(payload) = self.salamander.deobfuscate_in_place(chunk) {
                    buf.copy_within(read..read + payload, written);
                    written += payload;
                } else {
                    debug_assert!(chunk_len <= SALT_LEN);
                }
                read = end;
            }
            meta.len = written;
            // Every joined datagram lost its salt, so the stride shrank too.
            meta.stride = if total > stride {
                stride.saturating_sub(SALT_LEN).max(1)
            } else {
                written
            };
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "gawrgura";
    const SALT: [u8; SALT_LEN] = [1, 2, 3, 4, 5, 6, 7, 8];

    /// The obfuscated form of bytes 0..80, computed with Python's
    /// `hashlib.blake2b(password + salt, digest_size=32)`, which is
    /// independent of this implementation (the Go reference uses the same
    /// construction).
    const VECTOR: &str = "0102030405060708dae43f03756d12dfa5973685c6f584d06d593f72a3f029111e05875d3c3f3434fac41f23554d32ff85b716a5e6d5a4f04d791f5283d009313e25a77d1c1f14149aa47f43352d529fe5d776c586b5c490";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn matches_an_independent_computation() {
        let salamander = Salamander::new(PASSWORD).unwrap();
        let plain: Vec<u8> = (0..80).collect();
        let mut out = Vec::new();
        salamander.obfuscate_with_salt(&SALT, &plain, &mut out);
        assert_eq!(hex(&out), VECTOR);
    }

    #[test]
    fn round_trips_every_length_and_uses_a_new_salt_each_time() {
        let salamander = Salamander::new(PASSWORD).unwrap();
        for len in [1usize, 31, 32, 33, 64, 1200, 1452] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let mut first = Vec::new();
            salamander.obfuscate(&plain, &mut first);
            let mut second = Vec::new();
            salamander.obfuscate(&plain, &mut second);
            assert_eq!(first.len(), len + SALT_LEN);
            assert_ne!(first[..SALT_LEN], second[..SALT_LEN]);
            let n = salamander.deobfuscate_in_place(&mut first).unwrap();
            assert_eq!(&first[..n], &plain[..]);
        }
    }

    #[test]
    fn a_wrong_password_gives_noise_and_short_datagrams_are_refused() {
        let right = Salamander::new(PASSWORD).unwrap();
        let wrong = Salamander::new("another password").unwrap();
        let plain = vec![0xc0u8; 100];
        let mut sealed = Vec::new();
        right.obfuscate(&plain, &mut sealed);
        let n = wrong.deobfuscate_in_place(&mut sealed).unwrap();
        assert_ne!(&sealed[..n], &plain[..]);
        assert!(right.deobfuscate_in_place(&mut [0u8; SALT_LEN]).is_none());
        assert!(right.deobfuscate_in_place(&mut []).is_none());
    }

    #[test]
    fn short_passwords_are_refused_and_the_password_is_not_in_debug() {
        assert!(Salamander::new("abc").is_err());
        assert!(Salamander::new("abcd").is_ok());
        let shown = format!("{:?}", Salamander::new(PASSWORD).unwrap());
        assert!(!shown.contains(PASSWORD));
    }

    // ----- a whole QUIC connection over obfuscated sockets

    const CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIBlTCCATugAwIBAgIUGS+8Fs1U1nZuhCCERiq/cE2I/EwwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAwwIZG5zLnRlc3QwIBcNMjYwOTIzMDM0MjE0WhgPMjEyNjA4MzAw\nMzQyMTRaMBMxETAPBgNVBAMMCGRucy50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\nAQcDQgAE4SqQn7qEa4DtfdAqi9OaEwN90Nw7fFYqJZpApbzJvAx1SEqxXCzJyCEB\na8NVtrWewNSLFBsFbk6lRLJoZU/NkKNrMGkwHQYDVR0OBBYEFJK+70IhxQ31fNnu\nfzTg7k6NSpO9MB8GA1UdIwQYMBaAFJK+70IhxQ31fNnufzTg7k6NSpO9MBkGA1Ud\nEQQSMBCCCGRucy50ZXN0hwR/AAABMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwID\nSAAwRQIgNg84WOdtnUk+Q6MYOs83T0huf9SA6szJaAKPxRL6vf8CIQDqMr+gBsfi\n5i5jHcRxCnpNYCzjPGH0FgdOY12pKnFHpQ==\n-----END CERTIFICATE-----";
    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7Gv8nckw9qy+6eL/\ng88Sxzpwfuq9C7IA8LrrBIkNWIChRANCAAThKpCfuoRrgO190CqL05oTA33Q3Dt8\nViolmkClvMm8DHVISrFcLMnIIQFrw1W2tZ7A1IsUGwVuTqVEsmhlT82Q\n-----END PRIVATE KEY-----";

    fn endpoint(obfs: Option<&str>, server: bool) -> quinn::Endpoint {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = CertificateDer::from_pem_slice(CERT.as_bytes()).unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let wrapped = runtime.wrap_udp_socket(socket).unwrap();
        let wrapped = match obfs {
            Some(password) => ObfuscatedSocket::wrap(wrapped, Salamander::new(password).unwrap()),
            None => wrapped,
        };
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            server.then(|| {
                let key = PrivateKeyDer::from_pem_slice(KEY.as_bytes()).unwrap();
                let tls = rustls::ServerConfig::builder_with_provider(provider.clone())
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(vec![cert.clone()], key)
                    .unwrap();
                quinn::ServerConfig::with_crypto(Arc::new(
                    quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
                ))
            }),
            wrapped,
            runtime,
        )
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        )));
        endpoint
    }

    /// Dial a server that echoes one stream; `Ok` carries what came back.
    async fn echo(client: Option<&str>, server: Option<&str>) -> Result<Vec<u8>, String> {
        let server = endpoint(server, true);
        let address = server.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                        if let Ok(data) = recv.read_to_end(1 << 20).await {
                            let _ = send.write_all(&data).await;
                            let _ = send.finish();
                        }
                    }
                });
            }
        });
        let client = endpoint(client, false);
        let attempt = async {
            let connection = client
                .connect(address, "dns.test")
                .map_err(|e| e.to_string())?
                .await
                .map_err(|e| e.to_string())?;
            let (mut send, mut recv) = connection.open_bi().await.map_err(|e| e.to_string())?;
            // Big enough to need many datagrams, so reordering, loss of
            // nothing and the stride handling all get exercised.
            let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
            send.write_all(&payload).await.map_err(|e| e.to_string())?;
            send.finish().map_err(|e| e.to_string())?;
            let back = recv.read_to_end(1 << 20).await.map_err(|e| e.to_string())?;
            assert_eq!(back, payload);
            Ok(back)
        };
        tokio::time::timeout(std::time::Duration::from_secs(4), attempt)
            .await
            .map_err(|_| "timed out".to_string())?
    }

    #[tokio::test]
    async fn quic_runs_over_obfuscated_sockets() {
        let back = echo(Some("gawrgura"), Some("gawrgura")).await.unwrap();
        assert_eq!(back.len(), 300_000);
    }

    #[tokio::test]
    async fn quic_does_not_connect_across_different_obfuscation() {
        assert!(echo(Some("gawrgura"), Some("another one")).await.is_err());
        assert!(echo(Some("gawrgura"), None).await.is_err());
        assert!(echo(None, Some("gawrgura")).await.is_err());
        // And the plain pair still works, so the failures above are the
        // obfuscation and not the test's setup.
        assert!(echo(None, None).await.is_ok());
    }
}
