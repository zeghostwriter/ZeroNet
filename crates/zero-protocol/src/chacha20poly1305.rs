//! ChaCha20-Poly1305 AEAD (RFC 8439) on top of [`crate::chacha20`].
//!
//! Only the keystream half is hand-written. The authenticator is the
//! `poly1305` crate, which is the same one `chacha20poly1305` uses, and the
//! construction around it is nine lines of RFC 8439 §2.8.
//!
//! The API is deliberately the shape of `chacha20poly1305::ChaCha20Poly1305` --
//! `new_from_slice` plus the two detached-tag calls, with the nonce as a
//! `[u8; 12]` and the tag as a slice -- so moving a call site onto this type is
//! an import swap and a nonce expression.

use chacha20poly1305::{Error, Tag};
use poly1305::universal_hash::{KeyInit, UniversalHash};
use poly1305::Poly1305;
use zeroize::Zeroize;

use crate::chacha20::xor_keystream;

const TAG_LEN: usize = 16;

/// A `ChaCha20Poly1305` key. The key is zeroed on drop and never copied except
/// by `Clone`, which is what the per-direction cipher enums in the Shadowsocks
/// paths need.
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl Clone for ChaCha20Poly1305 {
    fn clone(&self) -> Self {
        Self { key: self.key }
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ChaCha20Poly1305 {
    /// `Err` unless `key` is exactly 32 bytes.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, Error> {
        let key: &[u8; 32] = key.try_into().map_err(|_| Error)?;
        Ok(Self { key: *key })
    }

    /// Seal `buf` in place and return the 16-byte tag.
    pub fn encrypt_in_place_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<Tag, Error> {
        let mut poly = self.authenticator(nonce);
        // Counter 0 produced the one-time Poly1305 key, so the payload starts
        // at 1 (RFC 8439 §2.6).
        xor_keystream(&self.key, nonce, 1, buf);
        mac(&mut poly, aad, buf);
        Ok(finish(poly))
    }

    /// Verify the tag over `buf` and, only then, decrypt `buf` in place.
    pub fn decrypt_in_place_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let mut poly = self.authenticator(nonce);
        mac(&mut poly, aad, buf);
        // A branch on the first differing byte would leak the tag.
        if tag.len() != TAG_LEN {
            return Err(Error);
        }
        let mut diff = 0u8;
        for (want, got) in finish(poly).iter().zip(tag) {
            diff |= want ^ got;
        }
        if diff != 0 {
            return Err(Error);
        }
        xor_keystream(&self.key, nonce, 1, buf);
        Ok(())
    }

    /// RFC 8439 §2.6: the Poly1305 key is the first 32 bytes of block 0.
    fn authenticator(&self, nonce: &[u8; 12]) -> Poly1305 {
        let mut block0 = [0u8; 64];
        xor_keystream(&self.key, nonce, 0, &mut block0);
        let poly = Poly1305::new_from_slice(&block0[..32]).expect("32 bytes is a Poly1305 key");
        block0.zeroize();
        poly
    }
}

/// RFC 8439 §2.8: `aad || pad16 || ct || pad16 || len(aad) || len(ct)`.
fn mac(poly: &mut Poly1305, aad: &[u8], ciphertext: &[u8]) {
    poly.update_padded(aad);
    poly.update_padded(ciphertext);
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly.update_padded(&lengths);
}

fn finish(poly: Poly1305) -> Tag {
    let out = poly.finalize();
    let bytes: &[u8] = out.as_ref();
    let mut raw = [0u8; TAG_LEN];
    raw.copy_from_slice(bytes);
    Tag::from(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 §2.8.2. A single known-good point for the whole construction,
    /// including the counter offset and the length block.
    #[test]
    fn rfc8439_vector() {
        let key: [u8; 32] =
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = hex::decode("070000004041424344454647")
            .unwrap()
            .try_into()
            .unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected: Vec<u8> = hex::decode(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116",
        ))
        .unwrap();
        let expected_tag: [u8; 16] = hex::decode("1ae10b594f09e26a7e902ecbd0600691")
            .unwrap()
            .try_into()
            .unwrap();

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();

        let mut sealed = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, &aad, &mut sealed)
            .unwrap();
        assert_eq!(sealed, expected);
        assert_eq!(tag.as_slice(), expected_tag.as_slice());

        let mut opened = sealed.clone();
        cipher
            .decrypt_in_place_detached(&nonce, &aad, &mut opened, &tag)
            .unwrap();
        assert_eq!(opened, plaintext);
    }

    /// The point of a hand-written AEAD half: identical bytes, tag for tag, to
    /// the crate it replaces. Every length that takes a different branch in the
    /// keystream ladder, at several block offsets, in both directions.
    #[test]
    fn matches_the_crate() {
        use aes_gcm::aead::AeadInPlace;
        use chacha20poly1305::{ChaCha20Poly1305 as Ref, Nonce};

        let mut lengths: Vec<usize> = (0..=600).collect();
        lengths.extend([767, 768, 1000, 1023, 1024, 1025, 2048, 4096, 8192]);

        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        let mut aad = [0u8; 64];
        let mut seed = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        };
        for counter in 0..6u8 {
            key.iter_mut().for_each(|b| *b = next());
            nonce.iter_mut().for_each(|b| *b = next());
            aad.iter_mut().for_each(|b| *b = next());
            nonce[0] = counter;
            let mine = ChaCha20Poly1305::new_from_slice(&key).unwrap();
            let theirs = Ref::new_from_slice(&key).unwrap();
            for len in &lengths {
                let input: Vec<u8> = (0..*len).map(|i| (i % 251) as u8).collect();
                let ad = &aad[..*len % 65];

                let mut want = input.clone();
                let want_tag = theirs
                    .encrypt_in_place_detached(Nonce::from_slice(&nonce), ad, &mut want)
                    .unwrap();

                let mut got = input.clone();
                let got_tag = mine
                    .encrypt_in_place_detached(&nonce, ad, &mut got)
                    .unwrap();
                assert_eq!(got, want, "ciphertext len {len} counter {counter}");
                assert_eq!(got_tag.as_slice(), want_tag.as_slice(), "tag len {len}");

                let mut opened = want.clone();
                mine.decrypt_in_place_detached(&nonce, ad, &mut opened, want_tag.as_slice())
                    .unwrap();
                assert_eq!(opened, input, "round trip len {len}");

                let mut rejected = want.clone();
                let mut bad_tag = want_tag.to_vec();
                bad_tag[0] ^= 1;
                assert!(mine
                    .decrypt_in_place_detached(&nonce, ad, &mut rejected, &bad_tag)
                    .is_err());
            }
        }
    }

    #[test]
    fn rejects_a_wrong_key_length() {
        assert!(ChaCha20Poly1305::new_from_slice(&[0u8; 31]).is_err());
        assert!(ChaCha20Poly1305::new_from_slice(&[0u8; 33]).is_err());
        assert!(ChaCha20Poly1305::new_from_slice(&[0u8; 32]).is_ok());
    }
}
