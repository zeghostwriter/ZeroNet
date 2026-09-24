//! Byte-controlled ClientHello emission.
//!
//! REALITY needs three things stock TLS stacks will not give up: the
//! `legacy_session_id` must carry the auth tag (32 bytes, position-fixed at
//! handshake-message offset 39), the X25519 key share must be the ephemeral
//! key whose ECDH derives the auth key, and the overall shape should look
//! like a browser, not like a library (PLAN-01 §7, docs/specs/REALITY-client.md
//! §7).
//!
//! The shape here follows uTLS's Chrome profile structurally — GREASE, the
//! Chrome extension set and order, ALPN `h2`/`http/1.1`, padding to 517
//! bytes — with two deliberate divergences, both for protocol-safety rather
//! than laziness:
//!
//! * no `compress_certificate` (advertising it lets a server send us a
//!   compressed Certificate message, which the minimal parser does not
//!   decompress).
//!
//! Extension order is fixed rather than Chrome-shuffled; that is a small
//! fingerprint cost, noted for the later fingerprint-parity phase.

use ml_kem::{
    kem::{Kem, KeyExport},
    MlKem768,
};
use rand::RngCore;
use zeroize::Zeroize;

use super::{CipherSuite, MAX_PLAINTEXT};
use crate::FingerprintProfile;

/// Extension types, in the order they are emitted.
mod ext {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SESSION_TICKET: u16 = 0x0023;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const SCT: u16 = 0x0012;
    pub const ALPN: u16 = 0x0010;
    pub const KEY_SHARE: u16 = 0x0033;
    pub const PSK_EXCHANGE_MODES: u16 = 0x002d;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
    pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
    pub const STATUS_REQUEST: u16 = 0x0005;
    pub const PADDING: u16 = 0x0015;
    pub const GREASE: u16 = 0x0a0a;
}

/// The uTLS/boringssl GREASE placeholder value used throughout.
const GREASE: u16 = ext::GREASE;
const GREASE_LEADING_EXTENSION: u16 = 0x7a7a;
const GREASE_TRAILING_EXTENSION: u16 = 0xaaaa;

/// Chrome's signature algorithm list (uTLS Chrome 133 profile).
pub const SIGNATURE_ALGORITHMS: [u16; 8] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
];

/// An X25519 keypair for the handshake's key share.
///
/// The secret is kept as raw bytes on purpose: REALITY must run a *second*
/// ECDH with the same key (against the server's static key), and
/// `EphemeralSecret::diffie_hellman` consumes the key. The `x25519_dalek`
/// free function over bytes serves both handshakes.
pub struct ClientKeypair {
    pub secret: [u8; 32],
    pub public: [u8; 32],
    /// Present only when the hello offers X25519MLKEM768. ML-KEM key
    /// generation is by far the most expensive step of building a hello, so
    /// a classic-only hello does not pay for a key it never sends.
    pub(crate) mlkem: Option<ml_kem::ml_kem_768::DecapsulationKey>,
}

impl Drop for ClientKeypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

fn generate_keypair(hybrid_kem: bool) -> ClientKeypair {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(seed));
    let mlkem = hybrid_kem.then(|| MlKem768::generate_keypair().0);
    ClientKeypair {
        secret: seed,
        public: public.to_bytes(),
        mlkem,
    }
}

/// Everything variable about the hello, decided before building.
#[derive(Debug, Clone)]
pub struct HelloParams {
    pub server_name: String,
    pub alpn: Vec<Vec<u8>>,
    /// Browser family used for the deterministic hello shape. REALITY only
    /// needs the X25519 key share and TLS 1.3 offer to be valid; the profile
    /// also controls the visible suite/group ordering.
    pub fingerprint: FingerprintProfile,
    /// 32 bytes placed verbatim in `legacy_session_id`. REALITY passes its
    /// sealed tag; a plain TLS 1.3 compat hello passes random bytes.
    pub session_id: [u8; 32],
    /// Include the optional X25519MLKEM768 key share.
    pub hybrid_kem: bool,
}

impl HelloParams {
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            fingerprint: FingerprintProfile::Chrome,
            session_id: [0u8; 32],
            hybrid_kem: false,
        }
    }
}

/// Total record length browsers pad the hello out to.
const PADDED_LEN: usize = 517;

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u24_into(out: &mut [u8], v: u32) {
    out[0] = (v >> 16) as u8;
    out[1] = (v >> 8) as u8;
    out[2] = v as u8;
}

fn put_ext_header(out: &mut Vec<u8>, ext_type: u16, body_len: usize) {
    put_u16(out, ext_type);
    put_u16(out, body_len as u16);
}

fn random32() -> [u8; 32] {
    let mut r = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut r);
    r
}

/// Build the ClientHello handshake message (no record header).
///
/// Returns `(message, keypair)`. The message is patchable: REALITY writes its
/// sealed tag into `message[39..71]` before the record is sent, and the AAD
/// for that seal is exactly this message (which carries a zero session-id
/// when called by REALITY) — see docs/specs/REALITY-client.md §2.3.
pub fn build(params: &HelloParams) -> (Vec<u8>, ClientKeypair) {
    let keypair = generate_keypair(params.hybrid_kem);
    let mut msg = Vec::with_capacity(PADDED_LEN);

    msg.push(0x01); // handshake type: client_hello
    msg.extend_from_slice(&[0, 0, 0]); // body length, patched at the end
    msg.extend_from_slice(&[0x03, 0x03]); // legacy_version
    msg.extend_from_slice(&random32());
    msg.push(32);
    msg.extend_from_slice(&params.session_id);

    // Cipher suites: GREASE first, then the three TLS 1.3 suites, then
    // Chrome's TLS 1.2 list (shape only — we cannot fall back to 1.2, and
    // `supported_versions` pins the negotiation to 1.3).
    let mut suites: Vec<u16> = vec![GREASE];
    let offered = match params.fingerprint {
        // Firefox's TLS 1.3 preference puts ChaCha before AES-256. The
        // remaining TLS 1.2 compatibility suites retain the browser family
        // shape without affecting the TLS 1.3-only state machine.
        FingerprintProfile::Firefox => vec![0x1301, 0x1303, 0x1302],
        _ => CipherSuite::OFFERED.iter().map(|s| s.id).collect(),
    };
    suites.extend(offered);
    suites.extend_from_slice(&[
        0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
        0x0035,
    ]);
    put_u16(&mut msg, (suites.len() * 2) as u16);
    for s in &suites {
        put_u16(&mut msg, *s);
    }

    msg.extend_from_slice(&[0x01, 0x00]); // compression: null

    let ext_base = msg.len();
    put_u16(&mut msg, 0); // extensions length, patched

    let mut e = Vec::new();

    // Leading GREASE extension.
    put_ext_header(&mut e, GREASE_LEADING_EXTENSION, 0);

    // server_name — SNI must byte-match the server's allowlist entry.
    {
        let host = params.server_name.as_bytes();
        let list_len = 1 + 2 + host.len();
        put_ext_header(&mut e, ext::SERVER_NAME, 2 + list_len);
        put_u16(&mut e, list_len as u16);
        e.push(0x00); // host_name
        put_u16(&mut e, host.len() as u16);
        e.extend_from_slice(host);
    }

    // extended_master_secret, renegotiation_info: TLS 1.2 relics Chrome sends.
    put_ext_header(&mut e, ext::EXTENDED_MASTER_SECRET, 0);
    put_ext_header(&mut e, ext::RENEGOTIATION_INFO, 1);
    e.push(0x00);

    // supported_groups: offer X25519MLKEM768 first while retaining the
    // standalone X25519 compatibility group. REALITY authentication still
    // derives from the X25519 material embedded in the hybrid share.
    {
        let groups: &[u16] = match (params.fingerprint, params.hybrid_kem) {
            // Firefox offers X25519 before the NIST curves and does not need
            // the Chromium GREASE group in this position.
            (FingerprintProfile::Firefox, true) => &[0x11ec, 0x001d, 0x0017, 0x0018],
            (FingerprintProfile::Firefox, false) => &[0x001d, 0x0017, 0x0018],
            (FingerprintProfile::Chrome, true)
            | (FingerprintProfile::Safari, true)
            | (FingerprintProfile::Edge, true)
            | (FingerprintProfile::Ios, true)
            | (FingerprintProfile::Android, true)
            | (FingerprintProfile::Unshaped, true) => &[GREASE, 0x11ec, 0x001d, 0x0017, 0x0018],
            _ => &[GREASE, 0x001d, 0x0017, 0x0018],
        };
        put_ext_header(&mut e, ext::SUPPORTED_GROUPS, 2 + groups.len() * 2);
        put_u16(&mut e, (groups.len() * 2) as u16);
        for g in groups {
            put_u16(&mut e, *g);
        }
    }

    // ec_point_formats: uncompressed.
    put_ext_header(&mut e, ext::EC_POINT_FORMATS, 2);
    e.extend_from_slice(&[0x01, 0x00]);

    // session_ticket: empty (TLS 1.2 relic; the server ignores it — resumption
    // is signalled by pre_shared_key, which we never send).
    put_ext_header(&mut e, ext::SESSION_TICKET, 0);

    // ALPN.
    if !params.alpn.is_empty() {
        let body: usize = params.alpn.iter().map(|p| p.len() + 1).sum();
        put_ext_header(&mut e, ext::ALPN, 2 + body);
        put_u16(&mut e, body as u16);
        for p in &params.alpn {
            e.push(p.len() as u8);
            e.extend_from_slice(p);
        }
    }

    // status_request (OCSP stapling request).
    put_ext_header(&mut e, ext::STATUS_REQUEST, 5);
    e.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);

    // signature_algorithms.
    put_ext_header(
        &mut e,
        ext::SIGNATURE_ALGORITHMS,
        2 + SIGNATURE_ALGORITHMS.len() * 2,
    );
    put_u16(&mut e, (SIGNATURE_ALGORITHMS.len() * 2) as u16);
    for a in &SIGNATURE_ALGORITHMS {
        put_u16(&mut e, *a);
    }

    // signed_certificate_timestamp.
    put_ext_header(&mut e, ext::SCT, 0);

    // key_share: a GREASE share, an optional X25519MLKEM768 share, and a
    // standalone X25519 fallback. The hybrid encoding is ML-KEM-768 public
    // key (1184 bytes) followed by the 32-byte X25519 public key.
    {
        let grease_len = if params.fingerprint == FingerprintProfile::Firefox {
            0
        } else {
            2 + 2 + 1
        };
        let hybrid_len = if params.hybrid_kem { 2 + 2 + 1216 } else { 0 };
        let body_len = 2 + grease_len + hybrid_len + (2 + 2 + 32);
        put_ext_header(&mut e, ext::KEY_SHARE, body_len);
        put_u16(&mut e, (body_len - 2) as u16); // client_shares length
        if params.fingerprint != FingerprintProfile::Firefox {
            put_u16(&mut e, GREASE);
            put_u16(&mut e, 1);
            e.push(0x00);
        }
        if let Some(mlkem) = keypair.mlkem.as_ref() {
            let mlkem_public = mlkem.encapsulation_key().to_bytes();
            let mlkem_public_bytes: &[u8] = mlkem_public.as_ref();
            put_u16(&mut e, 0x11ec);
            put_u16(
                &mut e,
                (mlkem_public_bytes.len() + keypair.public.len()) as u16,
            );
            e.extend_from_slice(mlkem_public_bytes);
            e.extend_from_slice(&keypair.public);
        }
        put_u16(&mut e, 0x001d);
        put_u16(&mut e, 32);
        e.extend_from_slice(&keypair.public);
    }

    // psk_key_exchange_modes: psk_dhe_ke. Shape only; without pre_shared_key
    // no resumption happens. This makes Go servers send session tickets, so
    // the post-handshake reader must tolerate them (it does).
    put_ext_header(&mut e, ext::PSK_EXCHANGE_MODES, 2);
    e.extend_from_slice(&[0x01, 0x01]);

    // supported_versions: GREASE, 1.3, 1.2.
    put_ext_header(&mut e, ext::SUPPORTED_VERSIONS, 1 + 3 * 2);
    // Unlike supported_groups, this vector is prefixed by a single byte
    // (RFC 8446 §4.2.1). Using a u16 here makes Go reject the whole hello as
    // malformed before REALITY gets a chance to inspect it.
    e.push(3 * 2);
    put_u16(&mut e, GREASE);
    put_u16(&mut e, 0x0304);
    put_u16(&mut e, 0x0303);

    // Trailing GREASE extension, then padding last so the whole record is
    // PADDED_LEN bytes — Chrome's padding behaviour.
    put_ext_header(&mut e, GREASE_TRAILING_EXTENSION, 0);

    // `msg` already contains the four-byte handshake header. Account for the
    // padding extension header and the five-byte TLS record header so the
    // resulting on-wire record, rather than the bare handshake message, lands
    // exactly on the browser-shaped target.
    let unpadded = msg.len() + e.len() + 4 + 5;
    if unpadded < PADDED_LEN {
        let pad = PADDED_LEN - unpadded;
        put_ext_header(&mut e, ext::PADDING, pad);
        e.extend(std::iter::repeat_n(0u8, pad));
    }

    msg.extend_from_slice(&e);

    // Patch the two length fields now that sizes are final.
    let ext_len = msg.len() - ext_base - 2;
    msg[ext_base..ext_base + 2].copy_from_slice(&(ext_len as u16).to_be_bytes());
    let body_len = msg.len() - 4;
    put_u24_into(&mut msg[1..4], body_len as u32);

    assert!(msg.len() <= MAX_PLAINTEXT, "hello exceeds one record");
    (msg, keypair)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_simple() -> (Vec<u8>, ClientKeypair) {
        let mut p = HelloParams::new("www.example.com");
        p.session_id = [0x42; 32];
        build(&p)
    }

    #[test]
    fn layout_offsets_match_reality_expectations() {
        let (msg, _kp) = build_simple();
        assert_eq!(msg[0], 0x01);
        // legacy_version + random(32) + sid-len occupy 4..38
        assert_eq!(msg[38], 32, "session_id length byte must be 32");
        assert_eq!(&msg[39..71], &[0x42u8; 32], "session_id is at 39..71");
        // legacy_version 0303
        assert_eq!(&msg[4..6], &[0x03, 0x03]);
    }

    #[test]
    fn body_length_and_record_total_are_consistent() {
        let (msg, _kp) = build_simple();
        let body_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
        assert_eq!(body_len, msg.len() - 4);
        assert!(
            msg.len() + 5 >= PADDED_LEN,
            "hello must not be shorter than the browser target"
        );
        assert!(
            msg.len() + 5 <= MAX_PLAINTEXT + 5,
            "hello must fit one TLS record"
        );
    }

    #[test]
    fn sni_carries_the_exact_name() {
        let (msg, _kp) = build_simple();
        let hay = b"www.example.com".as_slice();
        assert!(
            msg.windows(hay.len()).any(|w| w == hay),
            "SNI must appear verbatim"
        );
    }

    #[test]
    fn x25519_share_present_and_nonzero() {
        let (msg, kp) = build_simple();
        assert!(
            msg.windows(32).any(|w| w == kp.public),
            "the generated public key must be in the key share"
        );
        assert!(kp.public.iter().any(|b| *b != 0));
    }

    #[test]
    fn keypairs_are_fresh_per_hello() {
        let (_, a) = build_simple();
        let (_, b) = build_simple();
        assert_ne!(a.public, b.public);
    }
}
