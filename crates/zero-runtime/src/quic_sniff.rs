//! Naming QUIC connections from their first datagram.
//!
//! UDP has no handshake the proxy can read the way it reads a TCP
//! ClientHello, so a QUIC flow only carries an IP address unless something
//! sniffs it. Browsers reach most large sites over QUIC first, and IP-only
//! routing sends those flows through the IP rule instead of the domain rule
//! the user wrote — foreign lists by geosite would never match a Google or
//! Cloudflare edge.
//!
//! RFC 9001 defines everything needed, with no state of its own: the Initial
//! packet's keys are derived from the destination connection ID the client
//! chose, and the first Initial carries the TLS ClientHello in a CRYPTO
//! frame. This module reverses exactly that:
//!
//! * parse the long header and the connection ID;
//! * derive the client's initial secrets from them (HKDF-SHA256);
//! * remove header protection and open the AEAD (AES-128-GCM);
//! * read the first CRYPTO frame and hand it to
//!   [`zero_core::sniff::client_hello_sni`].
//!
//! It runs on every UDP/443 datagram of a flow only until the name is known:
//! the callers keep the answer per flow, and only an Initial-sized datagram
//! reaches the decrypt at all. A datagram it cannot make sense of is simply
//! not sniffed — a false name would be far worse than an unnamed flow.

use std::sync::Arc;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes128Gcm;
use hkdf::Hkdf;
use sha2::Sha256;
use zero_core::Sniffed;

/// The version field of QUIC v1 (RFC 9000).
const VERSION_1: u32 = 0x0000_0001;
/// The version field of QUIC v2 (RFC 9369).
const VERSION_2: u32 = 0x6b33_43cf;

/// RFC 9001 §5.2: the version-1 salt for the initial secrets.
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
/// RFC 9369 §3.3.1: the version-2 salt.
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// The client's initial keys, exactly as RFC 9001 §5.2 derives them.
struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn hkdf_expand_label(secret: &[u8], label: &[u8], out: &mut [u8]) {
    // The TLS 1.3 HkdfLabel structure, with an always-empty context.
    let mut info = Vec::with_capacity(4 + 6 + label.len() + 1);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    let hkdf = Hkdf::<Sha256>::from_prk(secret).expect("the initial secret is long enough");
    hkdf.expand(&info, out).expect("the output fits the limits");
}

fn initial_keys(salt: &[u8; 20], dcid: &[u8], version: u32) -> InitialKeys {
    let (key_label, iv_label, hp_label) = if version == VERSION_2 {
        (&b"quicv2 key"[..], &b"quicv2 iv"[..], &b"quicv2 hp"[..])
    } else {
        (&b"quic key"[..], &b"quic iv"[..], &b"quic hp"[..])
    };
    // RFC 9001 §5.2: the initial secret is HKDF-Extract over the client's
    // chosen destination connection ID, then everything else expands from it.
    let initial_secret = Hkdf::<Sha256>::extract(Some(salt), dcid).0;
    let mut client_secret = [0u8; 32];
    hkdf_expand_label(&initial_secret, b"client in", &mut client_secret);
    let mut keys = InitialKeys {
        key: [0u8; 16],
        iv: [0u8; 12],
        hp: [0u8; 16],
    };
    hkdf_expand_label(&client_secret, key_label, &mut keys.key);
    hkdf_expand_label(&client_secret, iv_label, &mut keys.iv);
    hkdf_expand_label(&client_secret, hp_label, &mut keys.hp);
    keys
}

/// Read a QUIC variable-length integer (RFC 9000 §16). Returns the value and
/// the offset after it.
fn varint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(at)?;
    let width = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for byte in bytes.get(at + 1..at + width)? {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, at + width))
}

/// The cheap shape test: a long header with the fixed bit set. True for the
/// first datagram of most client flows and for nothing else on a typical
/// path.
pub fn looks_like_long_header(datagram: &[u8]) -> bool {
    datagram.len() >= 1200 && datagram[0] & 0xc0 == 0xc0
}

/// Sniff a QUIC datagram: `Some` when it is an Initial packet, with the
/// ClientHello's SNI when the first CRYPTO frame was readable.
pub fn inspect(datagram: &[u8]) -> Option<Sniffed> {
    // Whatever the network delivers on UDP/443 arrives here, and a panic in
    // the task that serves the tunnel takes the whole tunnel with it. A
    // datagram that cannot be read must cost an unnamed flow, nothing more.
    std::panic::catch_unwind(|| inspect_initial(datagram)).unwrap_or(None)
}

fn inspect_initial(datagram: &[u8]) -> Option<Sniffed> {
    // Clients pad every Initial datagram to 1200 bytes (RFC 9000 §14.1), so
    // anything shorter is refused before a single key is derived.
    if !looks_like_long_header(datagram) {
        return None;
    }
    let keys = header(datagram)?;
    let plaintext = open(datagram, &keys)?;
    let hello = first_crypto(&plaintext)?;
    let domain = zero_core::sniff::client_hello_sni(hello).map(Arc::from);
    Some(Sniffed {
        domain,
        protocol: Some("quic"),
        http: None,
    })
}

/// Where the protected parts of a client Initial begin.
struct Parts {
    keys: InitialKeys,
    /// Offset of the packet number first byte.
    pn_offset: usize,
    /// Offset of the packet number field's end / payload start.
    payload_offset: usize,
    /// End of the packet's payload.
    payload_end: usize,
    /// The datagram's first byte with header protection removed.
    first_byte: u8,
    /// The header protection mask: its first byte covers the low bits of the
    /// first byte, the next four hide a packet number of up to four bytes.
    mask: [u8; 5],
}

fn header(datagram: &[u8]) -> Option<Parts> {
    let first = *datagram.first()?;
    // Long header, fixed bit, Initial type. v1 spells Initial 0b00, v2 0b01.
    if first & 0xc0 != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes(datagram.get(1..5)?.try_into().ok()?);
    let (salt, initial_type) = match version {
        VERSION_1 => (&SALT_V1, 0u8),
        VERSION_2 => (&SALT_V2, 1u8),
        _ => return None,
    };
    if (first & 0x30) >> 4 != initial_type {
        return None;
    }
    let mut at = 5;
    let dcid_len = *datagram.get(at)? as usize;
    at += 1;
    if dcid_len > 20 {
        return None;
    }
    let dcid = datagram.get(at..at + dcid_len)?;
    at += dcid_len;
    let scid_len = *datagram.get(at)? as usize;
    at += 1;
    if scid_len > 20 {
        return None;
    }
    at += scid_len;
    // The token is only present on Initial; both varints are bounded.
    let (token_len, next) = varint(datagram, at)?;
    at = next.checked_add(usize::try_from(token_len).ok()?)?;
    let (length, next) = varint(datagram, at)?;
    let length = usize::try_from(length).ok()?;
    if length < 8 {
        return None;
    }
    let pn_offset = next;
    let payload_end = pn_offset.checked_add(length)?;
    if payload_end > datagram.len() {
        return None;
    }
    let keys = initial_keys(salt, dcid, version);
    let sample = datagram.get(pn_offset + 4..pn_offset + 20)?;
    let mut block = [0u8; 16];
    block.copy_from_slice(sample);
    let cipher = aes::Aes128::new_from_slice(&keys.hp).ok()?;
    cipher.encrypt_block((&mut block).into());
    let mask = [block[0], block[1], block[2], block[3], block[4]];
    let first_byte = first ^ (mask[0] & 0x0f);
    let pn_len = (first_byte & 0x03) as usize + 1;
    if pn_offset + pn_len > payload_end {
        return None;
    }
    Some(Parts {
        keys,
        pn_offset,
        payload_offset: pn_offset + pn_len,
        payload_end,
        first_byte,
        mask,
    })
}

/// Remove protection and decrypt the Initial payload. The packet number is
/// taken as its truncated bytes: this is the client's first flight, so the
/// unobserved high bits are zero, and a datagram that disagrees fails its
/// AEAD tag and is dropped.
fn open(datagram: &[u8], parts: &Parts) -> Option<Vec<u8>> {
    let pn_len = parts.payload_offset - parts.pn_offset;
    let mut pn_bytes = [0u8; 4];
    for index in 0..pn_len {
        pn_bytes[index] = datagram[parts.pn_offset + index] ^ parts.mask[1 + index];
    }
    let truncated = u32::from_be_bytes(pn_bytes) >> ((4 - pn_len) * 8);
    let mut nonce = parts.keys.iv;
    for (index, byte) in truncated.to_be_bytes().iter().enumerate() {
        nonce[index + 8] ^= *byte;
    }
    let mut aad = datagram[..parts.pn_offset].to_vec();
    aad[0] = parts.first_byte;
    aad.extend_from_slice(&pn_bytes[..pn_len]);
    let ciphertext = datagram.get(parts.payload_offset..parts.payload_end)?;
    Aes128Gcm::new_from_slice(&parts.keys.key)
        .ok()?
        .decrypt(
            &nonce.into(),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .ok()
}

/// The first CRYPTO frame's data when it starts at offset zero: the
/// ClientHello. Frames the sniff does not need end the scan rather than
/// guess.
fn first_crypto(payload: &[u8]) -> Option<&[u8]> {
    let mut at = 0;
    while at < payload.len() {
        let (kind, next) = varint(payload, at)?;
        at = next;
        match kind {
            // Padding is a run of zero bytes; PING carries nothing.
            0 | 1 => continue,
            6 => {
                let (offset, at) = varint(payload, at)?;
                let (length, at) = varint(payload, at)?;
                if offset != 0 {
                    return None;
                }
                let length = usize::try_from(length).ok()?;
                return payload.get(at..at.checked_add(length)?);
            }
            _ => return None,
        }
    }
    None
}

/// A client Initial datagram carrying `host` as its SNI, exactly as a QUIC
/// client would send on loopback. Test-only: it exists so the runtime's UDP
/// path can be driven with a real Initial packet instead of a fake one that
/// would not survive the decryption it is meant to exercise.
#[cfg(test)]
pub(crate) fn test_initial(host: &str) -> Vec<u8> {
    tests::initial_with(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9001 A.1: the secrets the client derives from that connection ID
    /// are published, so the derivation can be checked without a packet.
    #[test]
    fn initial_secrets_match_the_rfc_vector() {
        let dcid = hex::decode("8394c8f03e515708").unwrap();
        let keys = initial_keys(&SALT_V1, &dcid, VERSION_1);
        assert_eq!(hex::encode(keys.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex::encode(keys.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex::encode(keys.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    fn client_hello(host: &str) -> Vec<u8> {
        let name = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[7; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]);
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        let mut message = vec![
            1,
            (hello.len() >> 16) as u8,
            (hello.len() >> 8) as u8,
            hello.len() as u8,
        ];
        message.extend_from_slice(&hello);
        message
    }

    /// Protect a payload the way a client does: it is the inverse of `open`,
    /// so a change to one side breaks this test unless both change. The key
    /// derivation above is what keeps the pair honest.
    fn protect(dcid: &[u8], payload: &[u8], pn_len: usize) -> Vec<u8> {
        let keys = initial_keys(&SALT_V1, dcid, VERSION_1);
        let pn = 2u32;
        let mut nonce = keys.iv;
        for (index, byte) in pn.to_be_bytes().iter().enumerate() {
            nonce[index + 8] ^= *byte;
        }
        let mut header = vec![0xc0 | (pn_len as u8 - 1)];
        header.extend_from_slice(&VERSION_1.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0);
        header.push(0);
        let length = pn_len + payload.len() + 16;
        header.extend_from_slice(&(0x4000u16 | length as u16).to_be_bytes());
        let pn_offset = header.len();
        header.extend_from_slice(&pn.to_be_bytes()[4 - pn_len..]);
        let ciphertext = Aes128Gcm::new_from_slice(&keys.key)
            .unwrap()
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: payload,
                    aad: &header,
                },
            )
            .unwrap();
        let mut protected = header.clone();
        protected.extend_from_slice(&ciphertext);
        let mut block = [0u8; 16];
        block.copy_from_slice(&protected[pn_offset + 4..pn_offset + 20]);
        let cipher = aes::Aes128::new_from_slice(&keys.hp).unwrap();
        cipher.encrypt_block((&mut block).into());
        protected[0] ^= block[0] & 0x0f;
        for index in 0..pn_len {
            protected[pn_offset + index] ^= block[1 + index];
        }
        protected
    }

    pub(super) fn initial_with(host: &str) -> Vec<u8> {
        initial_with_pn(host, 2)
    }

    /// The same Initial, with a packet number of `pn_len` bytes (1 to 4): the
    /// client picks the length, and real clients use all four.
    fn initial_with_pn(host: &str, pn_len: usize) -> Vec<u8> {
        let hello = client_hello(host);
        let mut frame = vec![6];
        frame.extend_from_slice(&[0]); // offset
        let mut length = Vec::new();
        let value = hello.len() as u64;
        // A one- or two-byte varint; SNI hello always fits two bytes.
        if value < 64 {
            length.push(value as u8);
        } else {
            length.push(0x40 | ((value >> 8) as u8));
            length.push((value & 0xff) as u8);
        }
        frame.extend_from_slice(&length);
        frame.extend_from_slice(&hello);
        frame.extend_from_slice(&vec![0; 1200 - frame.len()]);
        protect(&hex::decode("8394c8f03e515708").unwrap(), &frame, pn_len)
    }

    #[test]
    fn sniff_an_initial_datagram() {
        let datagram = initial_with("example.com");
        let sniffed = inspect(&datagram).expect("an Initial with a ClientHello");
        assert_eq!(sniffed.protocol, Some("quic"));
        assert_eq!(sniffed.domain.as_deref(), Some("example.com"));
    }

    /// Every packet number length a client may choose is read, not just the
    /// short ones. A four-byte number needs the fifth byte of the
    /// header-protection mask (one for the first byte, four for the number).
    #[test]
    fn an_initial_is_sniffed_whatever_its_packet_number_length() {
        for pn_len in 1..=4 {
            let datagram = initial_with_pn("example.com", pn_len);
            let sniffed = inspect(&datagram)
                .unwrap_or_else(|| panic!("a {pn_len}-byte packet number was not read"));
            assert_eq!(sniffed.domain.as_deref(), Some("example.com"), "{pn_len}");
        }
    }

    /// Anything a network can deliver on UDP/443 goes through `inspect`, so no
    /// input may panic it: it would end the task that serves the tunnel.
    /// Valid Initials with a byte damaged, and noise dressed as an Initial.
    #[test]
    fn no_datagram_makes_the_sniffer_panic() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let valid: Vec<Vec<u8>> = (1..=4).map(|n| initial_with_pn("example.com", n)).collect();
        for round in 0..20_000usize {
            let mut datagram = valid[round % valid.len()].clone();
            // Damage the header region hardest: that is where the lengths are.
            for _ in 0..(1 + next() % 4) {
                let at = if next() % 3 == 0 {
                    (next() as usize) % datagram.len()
                } else {
                    (next() as usize) % 40
                };
                datagram[at] = next() as u8;
            }
            let _ = inspect(&datagram);
            let mut noise = vec![0u8; 1200 + (next() % 200) as usize];
            for byte in noise.iter_mut() {
                *byte = next() as u8;
            }
            noise[0] |= 0xc0;
            let _ = inspect(&noise);
        }
    }

    #[test]
    fn leaves_anything_else_alone() {
        // Too short to be a client Initial datagram.
        assert!(inspect(&[0xc0; 30]).is_none());
        assert!(!looks_like_long_header(&[0xc0; 30]));
        // A short header is not an Initial.
        let short = [0x40u8; 1300];
        assert!(inspect(&short).is_none());
        assert!(!looks_like_long_header(&short));
        // A long header for an unknown version is refused rather than
        // guessed at with the wrong salt.
        let mut unknown = initial_with("example.com");
        unknown[1..5].copy_from_slice(&0xfaceb00cu32.to_be_bytes());
        assert!(inspect(&unknown).is_none());
        assert!(looks_like_long_header(&unknown));
    }

    /// Initial packets are always padded to 1200 bytes by the client, which
    /// is what lets the callers skip the decrypt for everything else.
    #[test]
    fn an_initial_looks_like_a_long_header() {
        assert!(looks_like_long_header(&initial_with("example.com")));
    }
}
