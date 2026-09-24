//! The TLS 1.3 key schedule (RFC 8446 §7.1), hand-rolled over HMAC-SHA256/384.
//!
//! Everything here is byte-exact by construction and unit-tested against
//! RFC 5869 test vectors; the label set matches `reference/REALITY/tls13`
//! (what Xray REALITY servers run) — see docs/specs/tls13-core.md §2.

use hmac::{Hmac, Mac};

use super::{CipherSuite, HashAlg};

type HmacSha256 = Hmac<sha2::Sha256>;
type HmacSha384 = Hmac<sha2::Sha384>;

/// `HMAC(hash, key, data)`.
pub fn hmac(hash: HashAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    match hash {
        HashAlg::Sha256 => {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        HashAlg::Sha384 => {
            let mut mac = <HmacSha384 as Mac>::new_from_slice(key).expect("hmac accepts any key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// `HKDF-Extract(salt, ikm) = HMAC(salt, ikm)`.
pub fn hkdf_extract(hash: HashAlg, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    hmac(hash, salt, ikm)
}

/// `HKDF-Expand(prk, info, len)` — RFC 5869, one round per hash output.
pub fn hkdf_expand(hash: HashAlg, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let rounds = len.div_ceil(hash.len());
    assert!(rounds <= 255, "hkdf_expand length out of range");
    let mut out = Vec::with_capacity(rounds * hash.len());
    let mut prev: Vec<u8> = Vec::new();
    for i in 1u8..=rounds as u8 {
        let mut block = std::mem::take(&mut prev);
        block.extend_from_slice(info);
        block.push(i);
        prev = hmac(hash, prk, &block);
        out.extend_from_slice(&prev);
    }
    out.truncate(len);
    out
}

/// `HKDF-Expand-Label(secret, label, context, length)` — RFC 8446 §7.1.
///
/// info = `u16be(length) || "tls13 " ++ label (len-prefixed) || context (len-prefixed)`
pub fn hkdf_expand_label(
    hash: HashAlg,
    secret: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(hash, secret, &info, len)
}

/// `Derive-Secret(secret, label, transcriptHash)`.
pub fn derive_secret(hash: HashAlg, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
    hkdf_expand_label(hash, secret, label, transcript_hash, hash.len())
}

/// The running transcript: handshake message bytes (4-byte headers included,
/// record headers excluded), in order.
///
/// Handshake messages total a few kilobytes, so keeping the raw bytes and
/// hashing on demand is simple and provably matches every definition of the
/// schedule — no incremental-hash bookkeeping to get wrong.
#[derive(Clone)]
pub struct Transcript {
    bytes: Vec<u8>,
    hash: HashAlg,
}

impl Transcript {
    pub fn new(hash: HashAlg) -> Self {
        Self {
            bytes: Vec::with_capacity(4096),
            hash,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.bytes.extend_from_slice(data);
    }

    /// The hash of everything fed so far.
    pub fn snapshot(&self) -> Vec<u8> {
        self.hash_bytes(&self.bytes)
    }

    pub fn hash_bytes(&self, data: &[u8]) -> Vec<u8> {
        match self.hash {
            HashAlg::Sha256 => {
                use sha2::{Digest, Sha256};
                Sha256::digest(data).to_vec()
            }
            HashAlg::Sha384 => {
                use sha2::{Digest, Sha384};
                Sha384::digest(data).to_vec()
            }
        }
    }

    pub fn hash_alg(&self) -> HashAlg {
        self.hash
    }
}

/// The secrets a handshake needs to carry between its phases.
#[derive(Clone)]
pub struct Schedule {
    pub hash: HashAlg,
    pub client_hs_traffic: Vec<u8>,
    pub server_hs_traffic: Vec<u8>,
    /// Carried until the server Finished lands, then expanded into the
    /// application secrets.
    master_secret: Vec<u8>,
}

/// Early → handshake secrets, from the ECDHE shared secret at
/// `Hash(ClientHello || ServerHello)`.
pub fn establish_handshake_secrets(
    suite: CipherSuite,
    shared_secret: &[u8],
    ch_sh_hash: &[u8],
) -> Schedule {
    let h = suite.hash;
    let zero = vec![0u8; h.len()];

    let early = hkdf_extract(h, &zero, &zero);
    let derived = derive_secret(h, &early, "derived", &h.empty_hash());
    let handshake = hkdf_extract(h, &derived, shared_secret);

    let client = derive_secret(h, &handshake, "c hs traffic", ch_sh_hash);
    let server = derive_secret(h, &handshake, "s hs traffic", ch_sh_hash);

    let derived2 = derive_secret(h, &handshake, "derived", &h.empty_hash());
    let master = hkdf_extract(h, &derived2, &zero);

    Schedule {
        hash: h,
        client_hs_traffic: client,
        server_hs_traffic: server,
        master_secret: master,
    }
}

/// Master → application secrets, once the transcript covers
/// `ClientHello .. server Finished`.
pub fn establish_application_secrets(
    schedule: &Schedule,
    ch_to_server_finished_hash: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let h = schedule.hash;
    (
        derive_secret(
            h,
            &schedule.master_secret,
            "c ap traffic",
            ch_to_server_finished_hash,
        ),
        derive_secret(
            h,
            &schedule.master_secret,
            "s ap traffic",
            ch_to_server_finished_hash,
        ),
    )
}

/// The AEAD key and static IV for a traffic secret.
pub fn traffic_keys(suite: CipherSuite, secret: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let key = hkdf_expand_label(suite.hash, secret, "key", &[], suite.aead.key_len());
    let iv = hkdf_expand_label(suite.hash, secret, "iv", &[], 12);
    let mut iv_arr = [0u8; 12];
    iv_arr.copy_from_slice(&iv);
    (key, iv_arr)
}

/// `verify_data` for a Finished message (RFC 8446 §4.4.4).
pub fn finished_verify_data(hash: HashAlg, base_key: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    let finished_key = hkdf_expand_label(hash, base_key, "finished", &[], hash.len());
    hmac(hash, &finished_key, transcript_hash)
}

/// The traffic secret after a KeyUpdate roll (RFC 8446 §4.6.3).
pub fn next_traffic_secret(hash: HashAlg, secret: &[u8]) -> Vec<u8> {
    hkdf_expand_label(hash, secret, "traffic upd", &[], hash.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    /// RFC 5869 Appendix A, test case 1 (HKDF-SHA256, basic).
    #[test]
    fn rfc5869_case_a1() {
        let ikm = [0x0bu8; 22];
        let salt = Vec::from_hex("000102030405060708090a0b0c").unwrap();
        let info = Vec::from_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let prk = hkdf_extract(HashAlg::Sha256, &salt, &ikm);
        assert_eq!(
            prk,
            Vec::from_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                .unwrap()
        );

        let okm = hkdf_expand(HashAlg::Sha256, &prk, &info, 42);
        assert_eq!(
            okm,
            Vec::from_hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
            .unwrap()
        );
    }

    /// RFC 5869 Appendix A, test case 3 (zero salt and info).
    #[test]
    fn rfc5869_case_a3() {
        let ikm = [0x0bu8; 22];
        let prk = hkdf_extract(HashAlg::Sha256, &[], &ikm);
        assert_eq!(
            prk,
            Vec::from_hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
                .unwrap()
        );
        let okm = hkdf_expand(HashAlg::Sha256, &prk, &[], 42);
        assert_eq!(
            okm,
            Vec::from_hex(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
            )
            .unwrap()
        );
    }

    /// The expand-label encoding is pinned: a wrong prefix or length field
    /// silently derives working-but-different keys, which only shows up as an
    /// opaque handshake failure against a live server.
    #[test]
    fn expand_label_encoding_matches_rfc8446() {
        // HKDF-Expand-Label(SHA256, secret = 0^32, "c hs traffic", "", 32);
        // info wire form u16be(32) || 0x12 "tls13 c hs traffic" || 0x00.
        // Reference value computed independently with an RFC 5869
        // implementation and cross-checked against RFC 8446 §7.1.
        let out = hkdf_expand_label(HashAlg::Sha256, &[0u8; 32], "c hs traffic", &[], 32);
        assert_eq!(
            out,
            Vec::from_hex("36f420efca38dc14c0b6d9434533c2aeb323468679940877bf5baf168794c2b1")
                .unwrap()
        );
    }

    #[test]
    fn transcript_hashes_in_order() {
        let mut t = Transcript::new(HashAlg::Sha256);
        t.update(b"ab");
        t.update(b"c");
        assert_eq!(t.snapshot(), t.hash_bytes(b"abc"));
    }
}
