//! Byte-controlled ClientHello emission.
//!
//! REALITY needs three things stock TLS stacks will not give up: the
//! `legacy_session_id` must carry the auth tag (32 bytes, position-fixed at
//! handshake-message offset 39), the X25519 key share must be the ephemeral
//! key whose ECDH derives the auth key, and the overall shape should look
//! like a browser, not like a library (PLAN-01 §7, docs/specs/REALITY-client.md
//! §7).
//!
//! For the Chrome family the hello is Chrome 133's, the shape uTLS's
//! `HelloChrome_133` parrot sends and so what an Xray REALITY client sends for
//! `fp=chrome`: the same eighteen extensions (including ECH GREASE, ALPS and
//! `compress_certificate`), GREASE values drawn afresh for every connection,
//! and the middle extensions in a fresh random order, as Chrome has done since
//! version 110. The first and last extension stay put (a GREASE each) and
//! padding, when the hello is short enough to need it, stays last.
//!
//! The other families keep the older, fixed Chrome-like structure; only
//! Chrome has the full parity treatment.
//!
//! `compress_certificate` is advertised only because the handshake can read
//! what it invites: a server may answer with a brotli-compressed Certificate
//! message, and `client::handshake` inflates it (see
//! [`offers_certificate_compression`]).

use ml_kem::{
    kem::{Kem, KeyExport},
    MlKem768,
};
use rand::{seq::SliceRandom, RngCore};
use zeroize::Zeroize;

use super::{CipherSuite, MAX_PLAINTEXT};
use crate::utls_profiles::{UtlsEchGrease, HPKE_AEAD_AES_128_GCM};
use crate::utls_shaping::encrypted_client_hello_payload;
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
    pub const COMPRESS_CERTIFICATE: u16 = 0x001b;
    /// ALPS under the codepoint Chrome moved to in version 131.
    pub const APPLICATION_SETTINGS: u16 = 0x44cd;
    pub const ECH: u16 = 0xfe0d;
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
    /// The `legacy_version` field: 0x0303 as every TLS 1.3 client writes it.
    /// Another 0x03xx value is read the same by servers, which take the
    /// field as "TLS 1.2 or later", and unrecognised by a filter that picks
    /// hellos out by it.
    pub legacy_version: u16,
}

impl HelloParams {
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            fingerprint: FingerprintProfile::Chrome,
            session_id: [0u8; 32],
            hybrid_kem: false,
            legacy_version: 0x0303,
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

/// Whether the hello for `fingerprint` carries `compress_certificate`, and so
/// whether the server may answer with a `CompressedCertificate` message.
pub(crate) fn offers_certificate_compression(fingerprint: FingerprintProfile) -> bool {
    fingerprint == FingerprintProfile::Chrome
}

/// The GREASE values one hello uses (RFC 8701).
///
/// BoringSSL draws one value per slot from a per-connection seed, so two
/// connections from one Chrome almost never share them, while a client that
/// sends the same GREASE every time is not Chrome. The key share's GREASE
/// group is the same value as the one in `supported_groups`, and the two
/// GREASE extensions never collide.
struct Grease {
    cipher: u16,
    group: u16,
    first: u16,
    last: u16,
    version: u16,
}

impl Grease {
    /// The fixed values the non-Chrome shapes have always sent.
    fn fixed() -> Self {
        Self {
            cipher: GREASE,
            group: GREASE,
            first: GREASE_LEADING_EXTENSION,
            last: GREASE_TRAILING_EXTENSION,
            version: GREASE,
        }
    }

    fn draw() -> Self {
        let mut seed = [0u8; 5];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        // High nibble from the seed, low nibble 0xa, repeated in both bytes.
        let value = |byte: u8| u16::from(byte & 0xf0 | 0x0a) * 0x0101;
        let first = value(seed[2]);
        let mut last = value(seed[3]);
        if last == first {
            last ^= 0x1010;
        }
        Self {
            cipher: value(seed[0]),
            group: value(seed[1]),
            first,
            last,
            version: value(seed[4]),
        }
    }
}

/// One extension, header included.
fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    put_ext_header(&mut out, kind, body.len());
    out.extend_from_slice(body);
    out
}

/// The ECH GREASE bodies a REALITY hello draws from, one per connection: the
/// four sizes BoringSSL picks between (186, 218, 250 or 282 bytes), AES-128-GCM
/// only, as Chrome sends. The body itself is built by the same function the
/// ordinary-TLS shape uses, so the encapsulated key is a genuine X25519 public
/// key and not 32 random bytes (a real one never has its top bit set).
const ECH_GREASE: UtlsEchGrease = UtlsEchGrease {
    aead_ids: &[HPKE_AEAD_AES_128_GCM],
    lengths: &[186, 218, 250, 282],
};

fn ech_grease() -> Vec<u8> {
    let body = encrypted_client_hello_payload(&ECH_GREASE).expect("the ECH GREASE sizes are valid");
    extension(ext::ECH, &body)
}

/// Build the ClientHello handshake message (no record header).
///
/// Returns `(message, keypair)`. The message is patchable: REALITY writes its
/// sealed tag into `message[39..71]` before the record is sent, and the AAD
/// for that seal is exactly this message (which carries a zero session-id
/// when called by REALITY) — see docs/specs/REALITY-client.md §2.3.
///
/// The extensions are built one by one as finished byte strings and joined at
/// the end, which is what lets the Chrome shape put the middle ones in a fresh
/// order each time without any of them knowing where it landed. Nothing here
/// depends on that order: the key share is found by type, and the session id
/// stays at offset 39.
pub fn build(params: &HelloParams) -> (Vec<u8>, ClientKeypair) {
    let keypair = generate_keypair(params.hybrid_kem);
    let chrome = offers_certificate_compression(params.fingerprint);
    let grease = if chrome {
        Grease::draw()
    } else {
        Grease::fixed()
    };
    let mut msg = Vec::with_capacity(PADDED_LEN);

    msg.push(0x01); // handshake type: client_hello
    msg.extend_from_slice(&[0, 0, 0]); // body length, patched at the end
    msg.extend_from_slice(&params.legacy_version.to_be_bytes());
    msg.extend_from_slice(&random32());
    msg.push(32);
    msg.extend_from_slice(&params.session_id);

    // Cipher suites: GREASE first, then the three TLS 1.3 suites, then
    // Chrome's TLS 1.2 list (shape only — we cannot fall back to 1.2, and
    // `supported_versions` pins the negotiation to 1.3).
    let mut suites: Vec<u16> = vec![grease.cipher];
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

    // Everything between the two GREASE extensions, in the order it is
    // listed; shuffled below for Chrome.
    let mut middle: Vec<Vec<u8>> = Vec::new();

    // server_name — SNI must byte-match the server's allowlist entry. A
    // literal IP is not a host name (RFC 6066 §3), so a link with no `sni=`
    // to an IP server sends no extension at all, as Xray does; the server
    // then matches it against the empty entry of its name list.
    if !params.server_name.is_empty() && params.server_name.parse::<std::net::IpAddr>().is_err() {
        let host = params.server_name.as_bytes();
        let mut body = Vec::with_capacity(5 + host.len());
        put_u16(&mut body, (1 + 2 + host.len()) as u16);
        body.push(0x00); // host_name
        put_u16(&mut body, host.len() as u16);
        body.extend_from_slice(host);
        middle.push(extension(ext::SERVER_NAME, &body));
    }

    // extended_master_secret, renegotiation_info: TLS 1.2 relics Chrome sends.
    middle.push(extension(ext::EXTENDED_MASTER_SECRET, &[]));
    middle.push(extension(ext::RENEGOTIATION_INFO, &[0x00]));

    // supported_groups: offer X25519MLKEM768 first while retaining the
    // standalone X25519 compatibility group. REALITY authentication still
    // derives from the X25519 material embedded in the hybrid share.
    {
        let g = grease.group;
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
            | (FingerprintProfile::Unshaped, true) => &[g, 0x11ec, 0x001d, 0x0017, 0x0018],
            _ => &[g, 0x001d, 0x0017, 0x0018],
        };
        let mut body = Vec::with_capacity(2 + groups.len() * 2);
        put_u16(&mut body, (groups.len() * 2) as u16);
        for group in groups {
            put_u16(&mut body, *group);
        }
        middle.push(extension(ext::SUPPORTED_GROUPS, &body));
    }

    // ec_point_formats: uncompressed.
    middle.push(extension(ext::EC_POINT_FORMATS, &[0x01, 0x00]));

    // session_ticket: empty (TLS 1.2 relic; the server ignores it — resumption
    // is signalled by pre_shared_key, which we never send).
    middle.push(extension(ext::SESSION_TICKET, &[]));

    // ALPN.
    if !params.alpn.is_empty() {
        let list: usize = params.alpn.iter().map(|p| p.len() + 1).sum();
        let mut body = Vec::with_capacity(2 + list);
        put_u16(&mut body, list as u16);
        for p in &params.alpn {
            body.push(p.len() as u8);
            body.extend_from_slice(p);
        }
        middle.push(extension(ext::ALPN, &body));
    }

    // status_request (OCSP stapling request).
    middle.push(extension(
        ext::STATUS_REQUEST,
        &[0x01, 0x00, 0x00, 0x00, 0x00],
    ));

    // signature_algorithms.
    {
        let mut body = Vec::with_capacity(2 + SIGNATURE_ALGORITHMS.len() * 2);
        put_u16(&mut body, (SIGNATURE_ALGORITHMS.len() * 2) as u16);
        for a in &SIGNATURE_ALGORITHMS {
            put_u16(&mut body, *a);
        }
        middle.push(extension(ext::SIGNATURE_ALGORITHMS, &body));
    }

    // signed_certificate_timestamp.
    middle.push(extension(ext::SCT, &[]));

    // key_share: a GREASE share, an optional X25519MLKEM768 share, and a
    // standalone X25519 fallback. The hybrid encoding is ML-KEM-768 public
    // key (1184 bytes) followed by the 32-byte X25519 public key.
    {
        let mut shares = Vec::new();
        if params.fingerprint != FingerprintProfile::Firefox {
            put_u16(&mut shares, grease.group);
            put_u16(&mut shares, 1);
            shares.push(0x00);
        }
        if let Some(mlkem) = keypair.mlkem.as_ref() {
            let mlkem_public = mlkem.encapsulation_key().to_bytes();
            let mlkem_public_bytes: &[u8] = mlkem_public.as_ref();
            put_u16(&mut shares, 0x11ec);
            put_u16(
                &mut shares,
                (mlkem_public_bytes.len() + keypair.public.len()) as u16,
            );
            shares.extend_from_slice(mlkem_public_bytes);
            shares.extend_from_slice(&keypair.public);
        }
        put_u16(&mut shares, 0x001d);
        put_u16(&mut shares, 32);
        shares.extend_from_slice(&keypair.public);
        let mut body = Vec::with_capacity(2 + shares.len());
        put_u16(&mut body, shares.len() as u16); // client_shares length
        body.extend_from_slice(&shares);
        middle.push(extension(ext::KEY_SHARE, &body));
    }

    // psk_key_exchange_modes: psk_dhe_ke. Shape only; without pre_shared_key
    // no resumption happens. This makes Go servers send session tickets, so
    // the post-handshake reader must tolerate them (it does).
    middle.push(extension(ext::PSK_EXCHANGE_MODES, &[0x01, 0x01]));

    // supported_versions: GREASE, 1.3, 1.2. Unlike supported_groups, this
    // vector is prefixed by a single byte (RFC 8446 §4.2.1). Using a u16 here
    // makes Go reject the whole hello as malformed before REALITY gets a
    // chance to inspect it.
    {
        let mut body = vec![3 * 2];
        put_u16(&mut body, grease.version);
        put_u16(&mut body, 0x0304);
        put_u16(&mut body, 0x0303);
        middle.push(extension(ext::SUPPORTED_VERSIONS, &body));
    }

    if chrome {
        // compress_certificate: brotli only, which is what Chrome offers and
        // what `client::handshake` can inflate.
        middle.push(extension(ext::COMPRESS_CERTIFICATE, &[0x02, 0x00, 0x02]));
        // ALPS, announced for the one protocol it is defined for. Chrome
        // sends it only when it also offers `h2`.
        if params.alpn.iter().any(|p| p == b"h2") {
            middle.push(extension(
                ext::APPLICATION_SETTINGS,
                &[0x00, 0x03, 0x02, b'h', b'2'],
            ));
        }
        middle.push(ech_grease());
        middle.shuffle(&mut rand::rngs::OsRng);
    }

    // Leading GREASE extension, the middle, then a trailing GREASE extension
    // (Chrome gives it a one-byte body) and padding last.
    let mut e = extension(grease.first, &[]);
    for x in &middle {
        e.extend_from_slice(x);
    }
    e.extend_from_slice(&extension(grease.last, if chrome { &[0x00] } else { &[] }));

    // `msg` already contains the four-byte handshake header. Account for the
    // padding extension header and the five-byte TLS record header so the
    // resulting on-wire record, rather than the bare handshake message, lands
    // exactly on the browser-shaped target. A hello already past the target
    // (Chrome's with the hybrid share) is not padded, as Chrome does not.
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
    fn the_legacy_version_is_the_one_asked_for_and_nothing_else_moves() {
        let mut p = HelloParams::new("www.example.com");
        p.fingerprint = FingerprintProfile::Safari;
        p.session_id = [0x42; 32];
        let (usual, _) = build(&p);
        p.legacy_version = 0x0304;
        let (odd, _) = build(&p);
        assert_eq!(&odd[4..6], &[0x03, 0x04]);
        assert_eq!(odd.len(), usual.len());
        // The session id stays where REALITY seals it.
        assert_eq!(&odd[39..71], &[0x42u8; 32]);
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
    fn an_ip_address_is_not_sent_as_a_server_name() {
        for name in ["203.0.113.9", "2001:db8::1", ""] {
            let (msg, _kp) = build(&HelloParams::new(name));
            let hay = name.as_bytes();
            assert!(
                hay.is_empty() || !msg.windows(hay.len()).any(|w| w == hay),
                "{name:?} must not appear in the hello"
            );
            // The extension list holds no server_name (type 0) entry.
            assert!(!has_extension(&msg, ext::SERVER_NAME), "{name:?}");
        }
        assert!(has_extension(&build_simple().0, ext::SERVER_NAME));
    }

    /// Whether the hello's extension list has an entry of type `wanted`.
    fn has_extension(msg: &[u8], wanted: u16) -> bool {
        let mut at = 4 + 2 + 32;
        at += 1 + msg[at] as usize;
        at += 2 + u16::from_be_bytes([msg[at], msg[at + 1]]) as usize;
        at += 1 + msg[at] as usize;
        let end = at + 2 + u16::from_be_bytes([msg[at], msg[at + 1]]) as usize;
        at += 2;
        while at < end {
            let kind = u16::from_be_bytes([msg[at], msg[at + 1]]);
            if kind == wanted {
                return true;
            }
            at += 4 + u16::from_be_bytes([msg[at + 2], msg[at + 3]]) as usize;
        }
        false
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

    /// The hello's extensions as (type, body), in wire order.
    fn extensions(msg: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut at = 4 + 2 + 32;
        at += 1 + msg[at] as usize;
        at += 2 + u16::from_be_bytes([msg[at], msg[at + 1]]) as usize;
        at += 1 + msg[at] as usize;
        let end = at + 2 + u16::from_be_bytes([msg[at], msg[at + 1]]) as usize;
        at += 2;
        let mut found = Vec::new();
        while at < end {
            let kind = u16::from_be_bytes([msg[at], msg[at + 1]]);
            let len = u16::from_be_bytes([msg[at + 2], msg[at + 3]]) as usize;
            found.push((kind, msg[at + 4..at + 4 + len].to_vec()));
            at += 4 + len;
        }
        assert_eq!(at, end, "the extension list is exactly consumed");
        found
    }

    fn is_grease(value: u16) -> bool {
        let [high, low] = value.to_be_bytes();
        high == low && high & 0x0f == 0x0a
    }

    fn chrome_hybrid() -> Vec<u8> {
        let mut p = HelloParams::new("www.example.com");
        p.hybrid_kem = true;
        build(&p).0
    }

    /// The Chrome hello carries exactly the extensions of the uTLS Chrome 133
    /// profile — the shape an Xray REALITY client sends — each with the body
    /// length the profile records.
    #[test]
    fn the_chrome_hello_has_the_extensions_of_the_chrome_133_profile() {
        use crate::utls_profiles::profile_for_fingerprint;
        let profile = profile_for_fingerprint("chrome").expect("chrome profile");
        let normal = |kind: u16| if is_grease(kind) { GREASE } else { kind };

        let found = extensions(&chrome_hybrid());
        let mut got: Vec<u16> = found.iter().map(|(kind, _)| normal(*kind)).collect();
        let mut want: Vec<u16> = profile
            .extensions
            .iter()
            .map(|e| normal(e.extension_type))
            .collect();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(got, want, "same set of extensions as the profile");

        // Fixed-size bodies must match the profile byte count. The SNI body
        // depends on the name and the ECH body is drawn from four sizes.
        for (kind, body) in &found {
            if matches!(*kind, ext::SERVER_NAME | ext::ECH) {
                continue;
            }
            let expected = profile
                .extensions
                .iter()
                .find(|e| normal(e.extension_type) == normal(*kind))
                .map(|e| e.payload_len);
            // The two GREASE extensions differ in body (0 and 1 bytes); both
            // are checked by position below.
            if !is_grease(*kind) {
                assert_eq!(Some(body.len()), expected, "body of {kind:#06x}");
            }
        }
        let ech = found.iter().find(|(kind, _)| *kind == ext::ECH).unwrap();
        assert!(
            [186, 218, 250, 282].contains(&ech.1.len()),
            "{}",
            ech.1.len()
        );

        // Suites and signature algorithms are the profile's, verbatim.
        let msg = chrome_hybrid();
        let sid = 4 + 2 + 32 + 1 + 32;
        let n = u16::from_be_bytes([msg[sid], msg[sid + 1]]) as usize / 2;
        let suites: Vec<u16> = (0..n)
            .map(|i| u16::from_be_bytes([msg[sid + 2 + 2 * i], msg[sid + 3 + 2 * i]]))
            .map(normal)
            .collect();
        let wanted: Vec<u16> = profile.cipher_suites.iter().copied().map(normal).collect();
        assert_eq!(suites, wanted);
        assert_eq!(
            SIGNATURE_ALGORITHMS.as_slice(),
            profile.signature_algorithms
        );
    }

    #[test]
    fn the_chrome_extension_order_is_drawn_afresh_and_the_ends_stay_put() {
        let mut orders = std::collections::HashSet::new();
        for _ in 0..40 {
            let found = extensions(&chrome_hybrid());
            let first = found.first().unwrap();
            let last = found.last().unwrap();
            assert!(is_grease(first.0) && first.1.is_empty(), "leading GREASE");
            assert!(is_grease(last.0) && last.1 == [0u8], "trailing GREASE");
            assert_ne!(first.0, last.0, "the two GREASE extensions differ");
            orders.insert(found.iter().map(|(k, _)| *k).collect::<Vec<_>>());
        }
        assert!(
            orders.len() > 20,
            "only {} distinct orders in 40",
            orders.len()
        );
    }

    #[test]
    fn grease_values_are_valid_and_change_between_hellos() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..40 {
            let msg = chrome_hybrid();
            let first_cipher =
                u16::from_be_bytes([msg[4 + 2 + 32 + 1 + 32 + 2], msg[4 + 2 + 32 + 1 + 32 + 3]]);
            assert!(is_grease(first_cipher));
            seen.insert(first_cipher);
            for (kind, body) in extensions(&msg) {
                if kind == ext::SUPPORTED_GROUPS {
                    let group = u16::from_be_bytes([body[2], body[3]]);
                    assert!(is_grease(group));
                } else if kind == ext::SUPPORTED_VERSIONS {
                    assert!(is_grease(u16::from_be_bytes([body[1], body[2]])));
                    assert_eq!(&body[3..], &[0x03, 0x04, 0x03, 0x03]);
                }
            }
        }
        assert!(seen.len() > 5, "the GREASE cipher barely varies: {seen:?}");
    }

    /// The ECH GREASE key is a real X25519 public key, whose top bit is never
    /// set; 32 random bytes would set it half the time.
    #[test]
    fn the_ech_grease_key_has_the_shape_of_an_x25519_public_key() {
        for _ in 0..40 {
            let found = extensions(&chrome_hybrid());
            let (_, body) = found.iter().find(|(k, _)| *k == ext::ECH).unwrap();
            assert_eq!(&body[..5], &[0x00, 0x00, 0x01, 0x00, 0x01]);
            assert_eq!(&body[6..8], &[0x00, 0x20]);
            assert_eq!(
                body[8 + 31] & 0x80,
                0,
                "enc is a clamped-curve u coordinate"
            );
        }
    }

    #[test]
    fn the_other_families_keep_their_fixed_shape() {
        for fingerprint in [FingerprintProfile::Safari, FingerprintProfile::Firefox] {
            let build_once = || {
                let mut p = HelloParams::new("www.example.com");
                p.fingerprint = fingerprint;
                let found = extensions(&build(&p).0);
                found.iter().map(|(k, _)| *k).collect::<Vec<_>>()
            };
            let first = build_once();
            assert_eq!(first, build_once(), "{fingerprint:?} order is fixed");
            for kind in [
                ext::COMPRESS_CERTIFICATE,
                ext::APPLICATION_SETTINGS,
                ext::ECH,
            ] {
                assert!(
                    !first.contains(&kind),
                    "{fingerprint:?} must not carry {kind:#06x}"
                );
            }
        }
    }

    #[test]
    fn alps_is_only_announced_when_h2_is_offered() {
        let mut p = HelloParams::new("www.example.com");
        p.alpn = vec![b"http/1.1".to_vec()];
        let found = extensions(&build(&p).0);
        assert!(!found.iter().any(|(k, _)| *k == ext::APPLICATION_SETTINGS));
        assert!(found.iter().any(|(k, _)| *k == ext::COMPRESS_CERTIFICATE));
    }
}
