//! REALITY — the client side.
//!
//! A REALITY handshake is a TLS 1.3 handshake whose ClientHello hides an
//! authentication tag in `legacy_session_id` and whose "certificate check" is
//! an HMAC instead of a CA chain (docs/specs/REALITY-client.md). Everything
//! else is the ordinary tls13-core handshake; that is the point — to every
//! observer, including the fallback site, this is indistinguishable from
//! browsing the decoy domain.
//!
//! Failure semantics matter for the planner: if the server does not
//! recognise us, it silently pipes us to the real site. We detect that at
//! the certificate (HMAC mismatch → `RealityFallback`) and MUST abort —
//! sending proxy traffic into the fallback connection leaks the tunnel.

use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use hmac::{Hmac, Mac};
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, Verifier, VerifyingKey};
use sha2::Sha512;
use zeroize::Zeroize;

use zero_core::{Confidence, Failure, FailureKind, Stage};

use crate::fingerprint::FingerprintProfile;
use crate::reality_compat::RealityCompatibility;
use crate::tls13::{self, PendingHello, ServerAuth, Tls13Stream};

/// Everything needed to open one REALITY connection.
#[derive(Debug, Clone)]
pub struct RealityParams {
    /// The decoy SNI. Must match the server's `serverNames` allowlist.
    pub server_name: Arc<str>,
    /// The server's static X25519 public key (`pbk` in share links).
    pub public_key: [u8; 32],
    /// The session selector (`sid`), left-aligned zero-padded to 8 bytes.
    pub short_id: [u8; 8],
    /// The requested browser-shaped ClientHello profile.
    pub fingerprint: FingerprintProfile,
    /// Optional ML-DSA-65 public key for Xray's second certificate check.
    pub mldsa65_verify: Option<Box<[u8]>>,
    /// Offer X25519MLKEM768 before the classic X25519 share.
    ///
    /// On by default: current REALITY servers refuse a hello without it, and
    /// refuse it by relaying the connection to the decoy site rather than by
    /// reporting an error. See `reality_compat::RealityGeneration`.
    pub hybrid_kem: bool,
    /// The concrete uTLS corpus entry the config named, when it named one
    /// rather than a browser family. Carried so the compatibility record can
    /// check the X25519 constraint against the exact shape going on the wire.
    pub fingerprint_name: Option<Box<str>>,
}

impl RealityParams {
    /// Build from the parsed config form, normalising the short id.
    pub fn from_config(server_name: Arc<str>, public_key: [u8; 32], short_id: &[u8]) -> Self {
        Self::from_config_with_fingerprint(
            server_name,
            public_key,
            short_id,
            FingerprintProfile::Chrome,
        )
    }

    pub fn from_config_with_fingerprint(
        server_name: Arc<str>,
        public_key: [u8; 32],
        short_id: &[u8],
        fingerprint: FingerprintProfile,
    ) -> Self {
        let mut padded = [0u8; 8];
        let n = short_id.len().min(8);
        padded[..n].copy_from_slice(&short_id[..n]);
        Self {
            server_name,
            public_key,
            short_id: padded,
            fingerprint,
            mldsa65_verify: None,
            hybrid_kem: crate::reality_compat::RealityGeneration::default().offers_hybrid_kem(),
            fingerprint_name: None,
        }
    }

    pub fn from_config_with_fingerprint_and_mldsa(
        server_name: Arc<str>,
        public_key: [u8; 32],
        short_id: &[u8],
        fingerprint: FingerprintProfile,
        mldsa65_verify: Option<Box<[u8]>>,
    ) -> Self {
        let mut params =
            Self::from_config_with_fingerprint(server_name, public_key, short_id, fingerprint);
        params.mldsa65_verify = mldsa65_verify;
        params
    }

    pub fn with_hybrid_kem(mut self, enabled: bool) -> Self {
        self.hybrid_kem = enabled;
        self
    }

    pub fn with_fingerprint_name(mut self, name: Option<impl Into<Box<str>>>) -> Self {
        self.fingerprint_name = name.map(Into::into);
        self
    }

    /// Everything version- and capability-dependent about this connection,
    /// collected into the one record that owns those rules.
    pub fn compatibility(&self) -> RealityCompatibility {
        RealityCompatibility::new(self.fingerprint)
            .with_fingerprint_name(self.fingerprint_name.clone())
            .with_hybrid_kem(self.hybrid_kem)
            .with_mldsa65(self.mldsa65_verify.is_some())
    }
}

/// `AuthKey = HKDF-SHA256(ikm = X25519(ephemeral, server_static),
///                         salt = ClientRandom[0..20], info = "REALITY")`.
///
/// The same key seals the session-id and verifies the server certificate.
fn derive_auth_key(shared_secret: &[u8; 32], salt: &[u8; 20]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"REALITY", &mut okm)
        .expect("32 bytes is a valid length");
    okm
}

/// The 16-byte plaintext sealed into the session-id:
/// `[version(3), 0x00, unix_secs u32be, shortId(8)]`.
fn session_id_plaintext(short_id: &[u8; 8], reported_version: [u8; 3]) -> [u8; 16] {
    let mut pt = [0u8; 16];
    pt[0..3].copy_from_slice(&reported_version);
    // pt[3] stays 0x00 (reserved)
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    pt[4..8].copy_from_slice(&secs.to_be_bytes());
    pt[8..16].copy_from_slice(short_id);
    pt
}

/// Seal the tag with AES-256-GCM: 16-byte plaintext + 16-byte tag = the full
/// 32-byte session-id field. AAD = the ClientHello with the session-id zeroed
/// (which is exactly the hello as built, before this patch).
fn seal_session_id(
    auth_key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8; 16],
    aad: &[u8],
) -> [u8; 32] {
    let cipher = Aes256Gcm::new_from_slice(auth_key).expect("auth key is 32 bytes");
    let ct = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("seal of a 16-byte plaintext cannot fail");
    let mut out = [0u8; 32];
    out.copy_from_slice(&ct);
    out
}

/// The `ServerAuth` policy: the leaf certificate is authentic when its
/// signature field equals `HMAC-SHA512(AuthKey, leaf_public_key)`.
///
/// On mismatch the peer is either the real fallback site or a MITM — the
/// connection must not carry proxy traffic either way, so this is a hard
/// `RealityFallback` failure, not a negotiable condition.
struct RealityAuth {
    auth_key: [u8; 32],
    mldsa65_verify: Option<Box<[u8]>>,
}

impl ServerAuth for RealityAuth {
    fn verify_certificate(&self, cert_der: &[u8]) -> Result<Vec<u8>, Failure> {
        self.verify_certificate_with_context(cert_der, &[], &[])
    }

    fn verify_certificate_with_context(
        &self,
        cert_der: &[u8],
        client_hello: &[u8],
        server_hello: &[u8],
    ) -> Result<Vec<u8>, Failure> {
        let parts = tls13::cert::parse_leaf(cert_der)?;

        if parts.spki_key.len() != 32 {
            // A real site's certificate is rarely Ed25519 — this is the
            // ordinary fallback shape.
            return Err(fallback(format!(
                "leaf public key is {} bytes, not an Ed25519 REALITY certificate",
                parts.spki_key.len()
            )));
        }
        if parts.signature.len() != 64 {
            return Err(fallback(format!(
                "certificate signature field is {} bytes, not an HMAC-SHA512 tag",
                parts.signature.len()
            )));
        }

        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&self.auth_key)
            .expect("hmac accepts any key length");
        mac.update(parts.spki_key);
        // `verify_slice` is the constant-time tag comparison.
        if mac.verify_slice(parts.signature).is_err() {
            return Err(fallback(
                "certificate HMAC did not verify: this is the fallback site, not REALITY",
            ));
        }

        if let Some(verifying_key_bytes) = self.mldsa65_verify.as_deref() {
            let encoded: EncodedVerifyingKey<MlDsa65> =
                verifying_key_bytes.try_into().map_err(|_| {
                    fallback("configured ML-DSA-65 verification key has invalid length")
                })?;
            let verifying_key = VerifyingKey::<MlDsa65>::decode(&encoded);
            let Some(extension) = parts.first_extension else {
                return Err(fallback("REALITY certificate has no ML-DSA-65 extension"));
            };
            let signature = Signature::<MlDsa65>::try_from(extension).map_err(|_| {
                fallback("REALITY certificate ML-DSA-65 extension is not a valid signature")
            })?;
            let mut signed = <Hmac<Sha512> as Mac>::new_from_slice(&self.auth_key)
                .expect("hmac accepts any key length");
            signed.update(parts.spki_key);
            signed.update(client_hello);
            signed.update(server_hello);
            let message = signed.finalize().into_bytes();
            if verifying_key
                .verify(message.as_slice(), &signature)
                .is_err()
            {
                return Err(fallback(
                    "REALITY certificate ML-DSA-65 binding did not verify",
                ));
            }
        }
        Ok(parts.spki_key.to_vec())
    }
}

impl Drop for RealityAuth {
    fn drop(&mut self) {
        self.auth_key.zeroize();
    }
}

fn fallback(detail: impl Into<String>) -> Failure {
    Failure::new(FailureKind::RealityFallback, Stage::TlsCompleted)
        .with_confidence(Confidence::Confirmed)
        .with_detail(detail)
}

/// Run the REALITY handshake over an established socket.
///
/// On success the stream is an ordinary byte stream (TLS 1.3 record layer)
/// on which VLESS + Vision ride.
pub async fn connect<S>(stream: S, params: &RealityParams) -> Result<Tls13Stream<S>, Failure>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Defence in depth: the config compiler already refuses these, but a
    // REALITY handshake built on a hello with no X25519 key share would fail
    // as an indistinguishable silent fallback rather than as a clear error.
    let compatibility = params.compatibility();
    if let Err(reason) = compatibility.validate() {
        return Err(Failure::new(FailureKind::LocalPolicy, Stage::TlsStarted)
            .with_detail(reason.to_string()));
    }

    let mut hello_params = tls13::HelloParams::new(params.server_name.to_string());
    hello_params.fingerprint = params.fingerprint;
    hello_params.hybrid_kem = compatibility.protocol_generation.offers_hybrid_kem();
    hello_params.session_id = [0u8; 32]; // the AAD form; sealed below
    let mut pending = PendingHello::new(&hello_params);

    // The REALITY shared secret uses the same ephemeral key as the TLS
    // key share — that is what makes the tag undetachable from the hello.
    let mut shared = x25519_dalek::x25519(pending.keypair().secret, params.public_key);
    let random: [u8; 32] = pending
        .random()
        .try_into()
        .expect("hello random is 32 bytes");
    let mut auth_key = derive_auth_key(&shared, random[..20].try_into().unwrap());
    shared.zeroize();

    let plaintext = session_id_plaintext(&params.short_id, compatibility.reported_client_version);
    let sealed = seal_session_id(
        &auth_key,
        random[20..32].try_into().unwrap(),
        &plaintext,
        &pending.msg,
    );
    pending.msg[39..71].copy_from_slice(&sealed);

    let auth = RealityAuth {
        auth_key,
        mldsa65_verify: params.mldsa65_verify.clone(),
    };
    auth_key.zeroize();
    let result = tls13::handshake(stream, pending, &auth).await?;
    Ok(result.stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{Keypair, MlDsa65, Seed, Signer, SigningKey};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn short_id_normalisation_left_aligns_and_zero_fills() {
        let p = RealityParams::from_config(
            std::sync::Arc::from("www.googletagmanager.com"),
            [1u8; 32],
            &hex("aabbccddeeff0011"),
        );
        assert_eq!(p.short_id, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11]);

        let short = RealityParams::from_config(std::sync::Arc::from("s"), [1u8; 32], &hex("a1b2"));
        assert_eq!(short.short_id, [0xa1, 0xb2, 0, 0, 0, 0, 0, 0]);

        let empty = RealityParams::from_config(std::sync::Arc::from("s"), [1u8; 32], &[]);
        assert_eq!(empty.short_id, [0u8; 8]);
    }

    #[test]
    fn session_id_plaintext_layout_matches_the_protocol() {
        let pt = session_id_plaintext(&[0x77u8; 8], crate::reality_compat::REPORTED_CLIENT_VERSION);
        assert_eq!(&pt[0..3], &crate::reality_compat::REPORTED_CLIENT_VERSION);
        assert_eq!(pt[3], 0);
        // timestamp parses back
        let secs = u32::from_be_bytes([pt[4], pt[5], pt[6], pt[7]]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        assert!(now.abs_diff(secs) <= 5, "timestamp is current");
        assert_eq!(&pt[8..16], &[0x77u8; 8]);
    }

    #[test]
    fn seal_produces_32_bytes_that_open_back() {
        let key = [9u8; 32];
        let nonce = [7u8; 12];
        let pt = [3u8; 16];
        let aad = [5u8; 100];
        let sealed = seal_session_id(&key, &nonce, &pt, &aad);
        assert_eq!(sealed.len(), 32);

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let opened = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &sealed,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(opened, pt);
    }

    /// Cross-check the auth key against an independent implementation of
    /// HKDF-SHA256 (the session-id seal is only as correct as this key).
    #[test]
    fn auth_key_derivation_matches_reference_hkdf() {
        // Computed with Python's cryptography HKDF:
        //   salt=bytes(range(20)), ikm=bytes(range(32)), info=b"REALITY", 32
        let shared: [u8; 32] = std::array::from_fn(|i| i as u8);
        let salt: [u8; 20] = std::array::from_fn(|i| i as u8);
        let key = derive_auth_key(&shared, &salt);
        assert_eq!(
            key,
            [
                0x14, 0x33, 0xc3, 0x53, 0x9c, 0x71, 0xbc, 0x13, 0xf0, 0xd3, 0xe1, 0x8a, 0x54, 0xd5,
                0x8e, 0x5b, 0xe8, 0x1c, 0x15, 0x42, 0xf3, 0xd9, 0x7c, 0x27, 0xea, 0xd0, 0x11, 0x4d,
                0xe9, 0xf0, 0x96, 0x22,
            ]
        );
    }

    fn der_length(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else {
            let bytes = (len as u32).to_be_bytes();
            let first = bytes.iter().position(|b| *b != 0).unwrap_or(3);
            let body = &bytes[first..];
            let mut out = vec![0x80 | body.len() as u8];
            out.extend_from_slice(body);
            out
        }
    }

    fn der_seq(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x30];
        out.extend_from_slice(&der_length(body.len()));
        out.extend_from_slice(body);
        out
    }

    fn der_bit_string(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x03];
        out.extend_from_slice(&der_length(data.len() + 1));
        out.push(0);
        out.extend_from_slice(data);
        out
    }

    fn der_octet_string(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x04];
        out.extend_from_slice(&der_length(data.len()));
        out.extend_from_slice(data);
        out
    }

    fn synthetic_reality_certificate(
        public_key: &[u8; 32],
        certificate_signature: &[u8; 64],
        extension_value: &[u8],
    ) -> Vec<u8> {
        let algorithm = der_seq(&[0x06, 0x03, 0x2b, 0x65, 0x70]);
        let mut spki_body = algorithm;
        spki_body.extend_from_slice(&der_bit_string(public_key));
        let spki = der_seq(&spki_body);

        let mut extension_body = vec![0x06, 0x01, 0x2b];
        extension_body.extend_from_slice(&der_octet_string(extension_value));
        let extension = der_seq(&extension_body);
        let extensions = der_seq(&extension);
        let mut explicit = vec![0xa3];
        explicit.extend_from_slice(&der_length(extensions.len()));
        explicit.extend_from_slice(&extensions);

        let mut tbs_body = spki;
        tbs_body.extend_from_slice(&explicit);
        let tbs = der_seq(&tbs_body);
        let mut certificate_body = tbs;
        certificate_body.extend_from_slice(&der_seq(&[0x06, 0x03, 0x2b, 0x65, 0x70]));
        certificate_body.extend_from_slice(&der_bit_string(certificate_signature));
        der_seq(&certificate_body)
    }

    #[test]
    fn verifies_the_optional_mldsa65_reality_binding() {
        let auth_key = [0x31u8; 32];
        let public_key = [0x42u8; 32];
        let client_hello = b"client hello";
        let server_hello = b"server hello";
        let mut hmac = <Hmac<Sha512> as Mac>::new_from_slice(&auth_key).unwrap();
        hmac.update(&public_key);
        let certificate_signature: [u8; 64] = hmac.finalize().into_bytes().into();

        let signing_key = SigningKey::<MlDsa65>::from_seed(&Seed::default());
        let verifying_key = signing_key.verifying_key();
        let mut signed = <Hmac<Sha512> as Mac>::new_from_slice(&auth_key).unwrap();
        signed.update(&public_key);
        signed.update(client_hello);
        signed.update(server_hello);
        let signature = signing_key.sign(signed.finalize().into_bytes().as_slice());
        let encoded = verifying_key.encode();
        let cert = synthetic_reality_certificate(
            &public_key,
            &certificate_signature,
            signature.encode().as_slice(),
        );
        let auth = RealityAuth {
            auth_key,
            mldsa65_verify: Some(encoded.as_slice().to_vec().into_boxed_slice()),
        };

        assert!(auth
            .verify_certificate_with_context(&cert, client_hello, server_hello)
            .is_ok());
        assert!(auth
            .verify_certificate_with_context(&cert, client_hello, b"changed")
            .is_err());
    }
}
