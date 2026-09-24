//! The TLS 1.3 record layer: framing, AEAD protection, sequence numbers.
//!
//! See docs/specs/tls13-core.md §3. Notable TLS 1.3 specifics this must get
//! right: the real content type rides *inside* the ciphertext, the nonce is
//! the static IV XOR the big-endian sequence number, and the AAD is exactly
//! the five-byte record header.
//!
//! Sealing and opening run in place: the data plane seals straight into the
//! stream's outgoing buffer and opens straight inside its wire buffer, so a
//! record costs no heap allocation in either direction.

use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit, Nonce as GcmNonce, Tag};
use bytes::{BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroize;

use super::{malformed, AeadAlg, CipherSuite, HashAlg, MAX_CIPHERTEXT, MAX_PLAINTEXT};

pub const CONTENT_ALERT: u8 = 0x15;
pub const CONTENT_HANDSHAKE: u8 = 0x16;
pub const CONTENT_APPDATA: u8 = 0x17;
pub const CONTENT_CCS: u8 = 0x14;

/// AEAD tag length shared by all three TLS 1.3 suites.
const TAG_LEN: usize = 16;

/// The AES key schedules are several hundred bytes each; boxing them keeps
/// the enum (and every `Tls13Stream`, which holds two) small enough to move
/// cheaply through futures.
enum CrypterCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(ChaCha20Poly1305),
}

/// One sealed record, header included.
pub struct SealedRecord {
    pub bytes: Vec<u8>,
    /// Offset where the ciphertext body begins (always 5).
    pub body_at: usize,
}

/// Build the five-byte record header for a cleartext or protected record.
pub fn record_header(content_type: u8, len: usize) -> [u8; 5] {
    let mut h = [0u8; 5];
    h[0] = content_type;
    h[1] = 0x03;
    h[2] = 0x03;
    h[3..].copy_from_slice(&(len as u16).to_be_bytes());
    h
}

/// Parse one record header. Returns (content_type, body_len).
pub fn parse_header(header: &[u8]) -> Result<(u8, usize), super::Failure> {
    let h: [u8; 5] = header
        .try_into()
        .map_err(|_| super::truncated("record header"))?;
    let len = u16::from_be_bytes([h[3], h[4]]) as usize;
    if len > MAX_CIPHERTEXT {
        return Err(malformed(format!(
            "record of {len} bytes exceeds the TLS limit"
        )));
    }
    Ok((h[0], len))
}

/// AEAD protection for one direction, one key epoch.
pub struct RecordCrypter {
    suite: CipherSuite,
    cipher: CrypterCipher,
    static_iv: [u8; 12],
    seq: u64,
}

impl Drop for RecordCrypter {
    fn drop(&mut self) {
        // The AEAD types zeroize their own key schedules; the IV is ours.
        self.static_iv.zeroize();
    }
}

impl RecordCrypter {
    /// Fresh crypter for a traffic secret; sequence starts at zero.
    pub fn new(suite: CipherSuite, secret: &[u8]) -> Self {
        let (mut key, iv) = super::kdf::traffic_keys(suite, secret);
        let cipher = match suite.aead {
            AeadAlg::Aes128Gcm => CrypterCipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(&key).expect("key length checked"),
            )),
            AeadAlg::Aes256Gcm => CrypterCipher::Aes256(Box::new(
                Aes256Gcm::new_from_slice(&key).expect("key length checked"),
            )),
            AeadAlg::ChaCha20Poly1305 => CrypterCipher::ChaCha(
                ChaCha20Poly1305::new_from_slice(&key).expect("key length checked"),
            ),
        };
        key.zeroize();
        Self {
            suite,
            cipher,
            static_iv: iv,
            seq: 0,
        }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.static_iv;
        let seq = self.seq.to_be_bytes();
        for (i, b) in seq.iter().enumerate() {
            n[4 + i] ^= b;
        }
        n
    }

    /// The nonce for the next record, refusing to reuse one. RFC 8446 §5.3
    /// forbids wrapping the sequence number; a key must be rolled first.
    fn next_nonce(&self) -> Result<[u8; 12], super::Failure> {
        if self.seq == u64::MAX {
            return Err(malformed("record sequence number exhausted"));
        }
        Ok(self.nonce())
    }

    fn seal_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], aes_gcm::Error> {
        let tag = match &self.cipher {
            CrypterCipher::Aes128(c) => {
                c.encrypt_in_place_detached(GcmNonce::from_slice(nonce), aad, buffer)?
            }
            CrypterCipher::Aes256(c) => {
                c.encrypt_in_place_detached(GcmNonce::from_slice(nonce), aad, buffer)?
            }
            CrypterCipher::ChaCha(c) => c.encrypt_in_place_detached(
                chacha20poly1305::Nonce::from_slice(nonce),
                aad,
                buffer,
            )?,
        };
        Ok(tag.into())
    }

    fn open_in_place_raw(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), aes_gcm::Error> {
        let tag = Tag::from_slice(tag);
        match &self.cipher {
            CrypterCipher::Aes128(c) => {
                c.decrypt_in_place_detached(GcmNonce::from_slice(nonce), aad, buffer, tag)
            }
            CrypterCipher::Aes256(c) => {
                c.decrypt_in_place_detached(GcmNonce::from_slice(nonce), aad, buffer, tag)
            }
            CrypterCipher::ChaCha(c) => c.decrypt_in_place_detached(
                chacha20poly1305::Nonce::from_slice(nonce),
                aad,
                buffer,
                tag,
            ),
        }
    }

    /// Protect one record and append it, header included, to `out`.
    ///
    /// `content` is the plaintext payload; `inner_type` is appended before
    /// sealing, per RFC 8446 §5.2. On error `out` is left as it was.
    pub fn seal_into<B: SealBuffer>(
        &mut self,
        content: &[u8],
        inner_type: u8,
        out: &mut B,
    ) -> Result<(), super::Failure> {
        if content.len() > MAX_PLAINTEXT {
            return Err(malformed(format!(
                "payload of {} bytes does not fit one record",
                content.len()
            )));
        }
        let nonce = self.next_nonce()?;

        let body_len = content.len() + 1 + TAG_LEN;
        let header = record_header(CONTENT_APPDATA, body_len);
        let start = out.filled_len();
        out.reserve_more(5 + body_len);
        out.append(&header);
        out.append(content);
        out.append(&[inner_type]);

        let sealed = {
            let body = &mut out.as_mut_slice()[start + 5..];
            self.seal_in_place(&nonce, &header, body)
        };
        match sealed {
            Ok(tag) => out.append(&tag),
            Err(_) => {
                out.truncate_to(start);
                return Err(malformed("seal failed"));
            }
        }

        self.seq += 1;
        Ok(())
    }

    /// Protect one record. `content` is the plaintext payload; `inner_type`
    /// is appended before sealing, per RFC 8446 §5.2.
    pub fn seal(&mut self, content: &[u8], inner_type: u8) -> Result<SealedRecord, super::Failure> {
        let mut bytes = Vec::new();
        self.seal_into(content, inner_type, &mut bytes)?;
        Ok(SealedRecord { bytes, body_at: 5 })
    }

    /// Open a protected record in place. `header` is the five-byte record
    /// header (the AAD) and `body` its ciphertext, tag included.
    ///
    /// On success returns the inner content type and the plaintext length:
    /// `body[..len]` then holds the plaintext with padding and the inner type
    /// stripped. On failure the contents of `body` are unspecified.
    pub fn open_in_place(
        &mut self,
        header: &[u8; 5],
        body: &mut [u8],
    ) -> Result<(u8, usize), super::Failure> {
        if body.len() < TAG_LEN + 1 {
            return Err(malformed("encrypted record shorter than the GCM tag"));
        }
        let nonce = self.next_nonce()?;
        let (ciphertext, tag) = body.split_at_mut(body.len() - TAG_LEN);
        self.open_in_place_raw(&nonce, header, ciphertext, tag)
            .map_err(|_| {
                // A bad tag is a real integrity failure, not a network error.
                malformed("record failed authentication")
            })?;

        // Trailing zeros are padding; the last non-zero byte is the type.
        let last = ciphertext
            .iter()
            .rposition(|b| *b != 0)
            .ok_or_else(|| malformed("record content is empty"))?;
        let inner_type = ciphertext[last];
        if !matches!(
            inner_type,
            CONTENT_APPDATA | CONTENT_HANDSHAKE | CONTENT_ALERT
        ) {
            return Err(malformed(format!(
                "record has illegal inner content type {inner_type:#04x}"
            )));
        }

        self.seq += 1;
        Ok((inner_type, last))
    }

    /// Open a protected record: `header` (5 bytes, ciphertext length included)
    /// and the ciphertext body. Returns the plaintext payload with the inner
    /// content type split off.
    pub fn open(
        &mut self,
        header: &[u8; 5],
        ciphertext: &[u8],
    ) -> Result<(u8, Vec<u8>), super::Failure> {
        let mut body = ciphertext.to_vec();
        let (inner_type, len) = self.open_in_place(header, &mut body)?;
        body.truncate(len);
        Ok((inner_type, body))
    }

    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    pub fn hash(&self) -> HashAlg {
        self.suite.hash
    }
}

/// A growable byte buffer a record can be sealed into: `Vec<u8>` for the
/// handshake, `BytesMut` for the stream's outgoing queue.
pub trait SealBuffer {
    fn filled_len(&self) -> usize;
    fn reserve_more(&mut self, additional: usize);
    fn append(&mut self, bytes: &[u8]);
    fn as_mut_slice(&mut self) -> &mut [u8];
    fn truncate_to(&mut self, len: usize);
}

impl SealBuffer for Vec<u8> {
    fn filled_len(&self) -> usize {
        Vec::len(self)
    }
    fn reserve_more(&mut self, additional: usize) {
        self.reserve(additional);
    }
    fn append(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self
    }
    fn truncate_to(&mut self, len: usize) {
        self.truncate(len);
    }
}

impl SealBuffer for BytesMut {
    fn filled_len(&self) -> usize {
        BytesMut::len(self)
    }
    fn reserve_more(&mut self, additional: usize) {
        self.reserve(additional);
    }
    fn append(&mut self, bytes: &[u8]) {
        self.put_slice(bytes);
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self
    }
    fn truncate_to(&mut self, len: usize) {
        self.truncate(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_all_suites() {
        for suite in CipherSuite::OFFERED {
            let mut w = RecordCrypter::new(suite, b"traffic secret material here");
            let mut r = RecordCrypter::new(suite, b"traffic secret material here");

            let payload: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
            let rec = w.seal(&payload, CONTENT_APPDATA).unwrap();
            assert_eq!(rec.bytes[0], CONTENT_APPDATA);

            let (ctype, pt) = {
                let mut hdr = [0u8; 5];
                hdr.copy_from_slice(&rec.bytes[..5]);
                r.open(&hdr, &rec.bytes[5..]).unwrap()
            };
            assert_eq!(ctype, CONTENT_APPDATA);
            assert_eq!(pt, payload);
        }
    }

    #[test]
    fn sequence_numbers_differ_per_record() {
        let mut w = RecordCrypter::new(CipherSuite::TLS_AES_128_GCM_SHA256, &[7u8; 32]);
        let a = w.seal(b"one", CONTENT_APPDATA).unwrap();
        let b = w.seal(b"two", CONTENT_APPDATA).unwrap();
        assert_ne!(&a.bytes[5..21], &b.bytes[5..21], "nonce must roll");
    }

    #[test]
    fn tampered_record_fails_authentication() {
        let mut w = RecordCrypter::new(CipherSuite::TLS_AES_128_GCM_SHA256, &[7u8; 32]);
        let mut r = RecordCrypter::new(CipherSuite::TLS_AES_128_GCM_SHA256, &[7u8; 32]);
        let mut rec = w.seal(b"payload", CONTENT_APPDATA).unwrap();
        let n = rec.bytes.len();
        rec.bytes[n - 1] ^= 0x01;
        let (hdr, body) = {
            let mut h = [0u8; 5];
            h.copy_from_slice(&rec.bytes[..5]);
            (h, rec.bytes[5..].to_vec())
        };
        assert!(r.open(&hdr, &body).is_err());
    }

    #[test]
    fn in_place_sealing_appends_the_same_record_and_opens_in_place() {
        let suite = CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
        let mut a = RecordCrypter::new(suite, &[3u8; 32]);
        let mut b = RecordCrypter::new(suite, &[3u8; 32]);
        let mut out = BytesMut::from(&b"prefix"[..]);
        a.seal_into(b"payload", CONTENT_APPDATA, &mut out).unwrap();
        assert_eq!(&out[..6], b"prefix", "existing bytes are preserved");
        assert_eq!(
            &out[6..],
            b.seal(b"payload", CONTENT_APPDATA).unwrap().bytes
        );

        let mut r = RecordCrypter::new(suite, &[3u8; 32]);
        let header: [u8; 5] = out[6..11].try_into().unwrap();
        let (kind, len) = r.open_in_place(&header, &mut out[11..]).unwrap();
        assert_eq!(
            (kind, &out[11..11 + len]),
            (CONTENT_APPDATA, &b"payload"[..])
        );
    }

    #[test]
    fn an_exhausted_sequence_number_refuses_to_reuse_a_nonce() {
        let mut w = RecordCrypter::new(CipherSuite::TLS_AES_128_GCM_SHA256, &[7u8; 32]);
        w.seq = u64::MAX;
        assert!(w.seal(b"x", CONTENT_APPDATA).is_err());
    }

    #[test]
    fn header_rejects_oversized_records() {
        assert!(parse_header(&[0x17, 0x03, 0x03, 0xff, 0xff]).is_err());
        let (t, len) = parse_header(&[0x17, 0x03, 0x03, 0x41, 0x00]).unwrap();
        assert_eq!((t, len), (CONTENT_APPDATA, 16640));
    }
}
