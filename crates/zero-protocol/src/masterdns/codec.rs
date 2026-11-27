//! The label codec: how a MasterDnsVPN packet turns into DNS-safe text and
//! back, and the encryption that wraps it on the way.
//!
//! A packet never travels as raw bytes. The client encrypts the raw packet,
//! then encodes the result into the restricted character set a DNS label
//! allows, and that string becomes one or more labels of a query name. The
//! server reverses it. This file is both halves, ported from the upstream Go
//! (`internal/basecodec` and `internal/security`) at the pinned release
//! `v2026.06.13.234407-7de2476`.
//!
//! Two independent pieces live here:
//!
//!  * The **base codec** ([`base36_encode`]/[`base36_decode`] and the base32 /
//!    base64 alternates). The active one on the wire is lower-base36; the
//!    others exist because a server can be configured to use them and some
//!    reply paths use raw base64. These are pure byte<->text and carry no key.
//!  * The **cipher** ([`Codec`]). It derives a key from the user's key string
//!    the exact way the server does, then seals each packet with AES-GCM (or
//!    XOR, or nothing). Only client->server traffic is sealed this way.
//!
//! Invariant that must never drift: the derived key, the nonce placement
//! (12 random bytes in front of the AES-GCM ciphertext+tag) and the base
//! alphabets are the protocol. If any of them change, the server stops
//! decoding us. The tests pin them against vectors generated from the Go code.

use std::fmt;

use aes::Aes192;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use md5::{Digest as _, Md5};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

use super::enums;

/// AES-192-GCM is not a named alias in `aes-gcm`, so we spell it out: the
/// 192-bit AES block cipher in GCM mode with the standard 12-byte nonce.
type Aes192Gcm = aes_gcm::AesGcm<Aes192, aes::cipher::consts::U12>;

/// The number of random bytes prepended to an AES-GCM ciphertext. Must match
/// the server; it reads the first 12 bytes as the nonce.
const AES_NONCE_LEN: usize = 12;

/// What can go wrong turning labels back into a packet. Encoding and sealing
/// never fail for the sizes a DNS packet can hold, so only the reverse
/// directions return errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// The method id in a config was outside 0..=5.
    InvalidMethod,
    /// Method 2 (ChaCha20, unauthenticated) is understood but deliberately not
    /// built: it would add a dependency to carry a cipher we never want to use.
    UnsupportedMethod,
    /// The text was not valid in the expected base alphabet, or had a length
    /// that cannot come from any input.
    InvalidEncoding,
    /// The sealed bytes were too short to hold a nonce, or the AES-GCM tag did
    /// not verify. Both mean "not a packet from someone who holds the key".
    InvalidCiphertext,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            CodecError::InvalidMethod => "invalid encryption method",
            CodecError::UnsupportedMethod => "unsupported encryption method",
            CodecError::InvalidEncoding => "invalid encoded label data",
            CodecError::InvalidCiphertext => "invalid ciphertext",
        };
        f.write_str(text)
    }
}

impl std::error::Error for CodecError {}

// ---------------------------------------------------------------------------
// Lower-base36: the active label codec.
//
// It packs input in 7-byte groups. Seven bytes fit in 56 bits, which is at
// most 36^11, so each group becomes exactly 11 base36 characters written big
// end first. A trailing group of 1..6 bytes becomes a fixed, smaller number of
// characters, looked up in `BASE36_ENC_CHARS_BY_BYTES`. Decoding inverts it,
// using `BASE36_DEC_BYTES_BY_CHARS` to turn a leftover character count back
// into a byte count. Decoding accepts upper or lower case.
// ---------------------------------------------------------------------------

const BASE36_ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
/// How many characters a trailing group of N (0..=7) bytes encodes to.
const BASE36_ENC_CHARS_BY_BYTES: [usize; 8] = [0, 2, 4, 5, 7, 8, 10, 11];
/// How many bytes a trailing group of N (0..=11) characters decodes to. A zero
/// at a non-zero index marks a character count that no valid input produces.
const BASE36_DEC_BYTES_BY_CHARS: [usize; 12] = [0, 0, 1, 0, 2, 3, 0, 4, 5, 0, 6, 7];

fn base36_encoded_len(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let blocks = n / 7;
    let rem = n % 7;
    blocks * 11 + BASE36_ENC_CHARS_BY_BYTES[rem]
}

fn write_base36_block(dst: &mut [u8], mut val: u64, count: usize) {
    for i in (0..count).rev() {
        dst[i] = BASE36_ALPHABET[(val % 36) as usize];
        val /= 36;
    }
}

/// Encode bytes to a lower-base36 string. Empty in, empty out.
pub fn base36_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut out = vec![0u8; base36_encoded_len(data.len())];
    let mut offset = 0;
    let mut src = data;
    while src.len() >= 7 {
        let val = (src[0] as u64) << 48
            | (src[1] as u64) << 40
            | (src[2] as u64) << 32
            | (src[3] as u64) << 24
            | (src[4] as u64) << 16
            | (src[5] as u64) << 8
            | (src[6] as u64);
        write_base36_block(&mut out[offset..offset + 11], val, 11);
        offset += 11;
        src = &src[7..];
    }
    if !src.is_empty() {
        let mut val = 0u64;
        for &b in src {
            val = (val << 8) | b as u64;
        }
        let char_count = BASE36_ENC_CHARS_BY_BYTES[src.len()];
        write_base36_block(&mut out[offset..offset + char_count], val, char_count);
        offset += char_count;
    }
    out.truncate(offset);
    // Every byte written came from BASE36_ALPHABET, which is ASCII.
    String::from_utf8(out).expect("base36 output is ascii")
}

fn base36_decoded_len(encoded_len: usize) -> Result<usize, CodecError> {
    if encoded_len == 0 {
        return Ok(0);
    }
    let blocks = encoded_len / 11;
    let rem = encoded_len % 11;
    let decoded_rem = BASE36_DEC_BYTES_BY_CHARS[rem];
    if rem != 0 && decoded_rem == 0 {
        return Err(CodecError::InvalidEncoding);
    }
    Ok(blocks * 7 + decoded_rem)
}

fn base36_digit(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'z' => Some(ch - b'a' + 10),
        b'A'..=b'Z' => Some(ch - b'A' + 10),
        _ => None,
    }
}

fn read_base36_block(data: &[u8]) -> Result<u64, CodecError> {
    let mut val = 0u64;
    for &ch in data {
        let digit = base36_digit(ch).ok_or(CodecError::InvalidEncoding)?;
        val = val * 36 + digit as u64;
    }
    Ok(val)
}

fn base36_next_decode_block(remaining: usize) -> (usize, usize) {
    if remaining >= 11 {
        (7, 11)
    } else {
        (BASE36_DEC_BYTES_BY_CHARS[remaining], remaining)
    }
}

/// Decode a lower-base36 byte slice back to bytes. Accepts upper or lower case.
pub fn base36_decode(data: &[u8]) -> Result<Vec<u8>, CodecError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let total = base36_decoded_len(data.len())?;
    let mut out = vec![0u8; total];
    let mut offset = 0;
    let mut src = data;
    while !src.is_empty() {
        let (block_size, char_count) = base36_next_decode_block(src.len());
        let mut val = read_base36_block(&src[..char_count])?;
        for i in (0..block_size).rev() {
            out[offset + i] = val as u8;
            val >>= 8;
        }
        offset += block_size;
        src = &src[char_count..];
    }
    Ok(out)
}

/// Decode a lower-base36 string. Convenience wrapper over [`base36_decode`].
pub fn base36_decode_str(data: &str) -> Result<Vec<u8>, CodecError> {
    base36_decode(data.as_bytes())
}

// ---------------------------------------------------------------------------
// Base32 (RFC 4648, lowercase alphabet, no padding) and raw base64 (standard
// alphabet, no padding). Alternates to base36; implemented by hand for base32
// to avoid a dependency, and over the already-present `base64` crate for the
// other.
// ---------------------------------------------------------------------------

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode bytes to lowercase base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut out = Vec::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer = 0u64;
    let mut bits = 0u32;
    for &b in data {
        buffer = (buffer << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((buffer >> bits) & 0x1f) as usize]);
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize]);
    }
    String::from_utf8(out).expect("base32 output is ascii")
}

fn base32_digit(ch: u8) -> Option<u8> {
    match ch {
        b'a'..=b'z' => Some(ch - b'a'),
        b'A'..=b'Z' => Some(ch - b'A'),
        b'2'..=b'7' => Some(ch - b'2' + 26),
        _ => None,
    }
}

/// Decode lowercase or uppercase base32 (no padding) back to bytes.
pub fn base32_decode(data: &[u8]) -> Result<Vec<u8>, CodecError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    let mut buffer = 0u64;
    let mut bits = 0u32;
    for &ch in data {
        let v = base32_digit(ch).ok_or(CodecError::InvalidEncoding)?;
        buffer = (buffer << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

/// Encode bytes to standard base64 without padding (Go `RawStdEncoding`).
pub fn raw_base64_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(data)
}

/// Decode standard base64 without padding back to bytes.
pub fn raw_base64_decode(data: &[u8]) -> Result<Vec<u8>, CodecError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(data)
        .map_err(|_| CodecError::InvalidEncoding)
}

// ---------------------------------------------------------------------------
// The cipher.
// ---------------------------------------------------------------------------

/// The AES-GCM instance behind methods 3/4/5. Boxed because an AES key
/// schedule is large and we do not want it inline in the [`Cipher`] enum.
enum AesCipher {
    Aes128(Box<Aes128Gcm>),
    Aes192(Box<Aes192Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl AesCipher {
    /// Seal `plaintext` under `nonce`, returning `ciphertext || tag` exactly as
    /// Go's `aead.Seal(nil, nonce, plaintext, nil)` does. The expect can only
    /// fire if the plaintext is larger than AES-GCM's ~64 GiB limit, which a
    /// DNS packet never is.
    fn seal(&self, nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce = Nonce::from_slice(nonce);
        match self {
            AesCipher::Aes128(c) => c.encrypt(nonce, plaintext),
            AesCipher::Aes192(c) => c.encrypt(nonce, plaintext),
            AesCipher::Aes256(c) => c.encrypt(nonce, plaintext),
        }
        .expect("aes-gcm seal within size limit")
    }

    /// Open `ciphertext || tag` under `nonce`. Returns an error if the tag does
    /// not verify.
    fn open(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CodecError> {
        let nonce = Nonce::from_slice(nonce);
        let result = match self {
            AesCipher::Aes128(c) => c.decrypt(nonce, ciphertext),
            AesCipher::Aes192(c) => c.decrypt(nonce, ciphertext),
            AesCipher::Aes256(c) => c.decrypt(nonce, ciphertext),
        };
        result.map_err(|_| CodecError::InvalidCiphertext)
    }
}

/// How a packet is sealed. One variant per supported method; built once from
/// the derived key so the AES key schedule is computed a single time.
enum Cipher {
    /// Method 0: no encryption, identity.
    None,
    /// Method 1: repeating-key XOR over a 32-byte derived key.
    Xor(Vec<u8>),
    /// Methods 3/4/5: AES-GCM.
    Aes(AesCipher),
}

/// Encrypts and encodes MasterDnsVPN packets for one session, the way the
/// server configured with the same method and key string expects.
///
/// Build it once with [`Codec::new`]; it holds the derived key and cipher
/// state. The entry points are [`Codec::encrypt_and_encode`] (packet bytes ->
/// label string) and [`Codec::decode_and_decrypt`] (label string -> packet
/// bytes). Encryption and encoding cannot fail for packet-sized data, so they
/// are infallible; the reverse directions return [`CodecError`].
///
/// Example:
/// ```ignore
/// let codec = Codec::new(enums::METHOD_AES_256_GCM, "0123456789abcdef0123456789abcdef")?;
/// let labels = codec.encrypt_and_encode(&raw_packet);
/// let back = codec.decode_and_decrypt(&labels)?;
/// assert_eq!(back, raw_packet);
/// ```
pub struct Codec {
    method: u8,
    cipher: Cipher,
}

impl Codec {
    /// Build a codec for `method` (0..=5) and the user's `raw_key` string. The
    /// key is derived from the raw string exactly as the server does, so the
    /// same method and string on both sides agree. Method 2 (ChaCha20) returns
    /// [`CodecError::UnsupportedMethod`]; anything above 5 is
    /// [`CodecError::InvalidMethod`].
    pub fn new(method: u8, raw_key: &str) -> Result<Self, CodecError> {
        let cipher = match method {
            enums::METHOD_NONE => Cipher::None,
            enums::METHOD_XOR => Cipher::Xor(derive_key(method, raw_key)),
            enums::METHOD_CHACHA20 => return Err(CodecError::UnsupportedMethod),
            enums::METHOD_AES_128_GCM => {
                let key = derive_key(method, raw_key);
                Cipher::Aes(AesCipher::Aes128(Box::new(
                    Aes128Gcm::new_from_slice(&key).expect("16-byte aes-128 key"),
                )))
            }
            enums::METHOD_AES_192_GCM => {
                let key = derive_key(method, raw_key);
                Cipher::Aes(AesCipher::Aes192(Box::new(
                    Aes192Gcm::new_from_slice(&key).expect("24-byte aes-192 key"),
                )))
            }
            enums::METHOD_AES_256_GCM => {
                let key = derive_key(method, raw_key);
                Cipher::Aes(AesCipher::Aes256(Box::new(
                    Aes256Gcm::new_from_slice(&key).expect("32-byte aes-256 key"),
                )))
            }
            _ => return Err(CodecError::InvalidMethod),
        };
        Ok(Codec { method, cipher })
    }

    /// The method id this codec was built for.
    pub fn method(&self) -> u8 {
        self.method
    }

    /// Seal packet bytes. For AES-GCM the output is `nonce || ciphertext ||
    /// tag`; empty input seals to empty output, matching the server.
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        match &self.cipher {
            Cipher::None => data.to_vec(),
            Cipher::Xor(key) => xor_apply(key, data),
            Cipher::Aes(aead) => {
                if data.is_empty() {
                    return Vec::new();
                }
                let mut out = vec![0u8; AES_NONCE_LEN];
                OsRng.fill_bytes(&mut out);
                let sealed = aead.seal(&out, data);
                out.extend_from_slice(&sealed);
                out
            }
        }
    }

    /// Open packet bytes produced by [`Codec::encrypt`] on the peer.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CodecError> {
        match &self.cipher {
            Cipher::None => Ok(data.to_vec()),
            Cipher::Xor(key) => Ok(xor_apply(key, data)),
            Cipher::Aes(aead) => {
                if data.is_empty() {
                    return Ok(Vec::new());
                }
                if data.len() <= AES_NONCE_LEN {
                    return Err(CodecError::InvalidCiphertext);
                }
                aead.open(&data[..AES_NONCE_LEN], &data[AES_NONCE_LEN..])
            }
        }
    }

    /// Seal `data` and encode the result into a lower-base36 label string.
    pub fn encrypt_and_encode(&self, data: &[u8]) -> String {
        base36_encode(&self.encrypt(data))
    }

    /// Decode a lower-base36 label string and open it back to packet bytes.
    pub fn decode_and_decrypt(&self, labels: &str) -> Result<Vec<u8>, CodecError> {
        let decoded = base36_decode_str(labels)?;
        self.decrypt(&decoded)
    }

    /// Test-only: seal with a caller-chosen nonce so a test can compare the
    /// exact sealed bytes against a vector from the Go code. Not for real use;
    /// a nonce must never be reused with the same key in production.
    #[cfg(test)]
    pub(crate) fn seal_with_nonce(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        match &self.cipher {
            Cipher::Aes(aead) => {
                let mut out = nonce.to_vec();
                out.extend_from_slice(&aead.seal(nonce, data));
                out
            }
            _ => self.encrypt(data),
        }
    }
}

/// Repeating-key XOR, matching the server: empty data copies through, and a
/// zero-length key would too (it never happens here, the key is always 32
/// bytes).
fn xor_apply(key: &[u8], data: &[u8]) -> Vec<u8> {
    if data.is_empty() || key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

/// Derive the cipher key from the raw key string, byte-identical to the Go
/// `deriveKey`:
///  * methods 2 and 5: SHA-256 of the raw bytes (32 bytes),
///  * method 3: MD5 of the raw bytes (16 bytes),
///  * everything else (0, 1, 4): the raw bytes copied into a zero-padded buffer
///    of the method's required length (32, 32, 24).
fn derive_key(method: u8, raw_key: &str) -> Vec<u8> {
    let raw = raw_key.as_bytes();
    match method {
        enums::METHOD_CHACHA20 | enums::METHOD_AES_256_GCM => Sha256::digest(raw).to_vec(),
        enums::METHOD_AES_128_GCM => Md5::digest(raw).to_vec(),
        _ => {
            let target = required_derived_key_len(method);
            let mut key = vec![0u8; target];
            let n = raw.len().min(target);
            key[..n].copy_from_slice(&raw[..n]);
            key
        }
    }
}

fn required_derived_key_len(method: u8) -> usize {
    match method {
        enums::METHOD_CHACHA20 | enums::METHOD_AES_256_GCM => 32,
        enums::METHOD_AES_128_GCM => 16,
        enums::METHOD_AES_192_GCM => 24,
        _ => 32,
    }
}
