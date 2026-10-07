//! The Tide handshake: Noise `NK` with X25519, ChaCha20-Poly1305 and SHA-256.
//!
//! How this works: `NK` is the Noise pattern for "the client knows the
//! server's long-term public key beforehand, the client itself is anonymous".
//! That is the situation of a share link: it carries the server's key. Two
//! messages are exchanged.
//!
//! ```text
//!   <- s                 (known in advance, from the link)
//!   -> e, es   + payload (the client's fresh key, encrypted to the server)
//!   <- e, ee   + payload (the server's fresh key; forward secrecy from here)
//! ```
//!
//! After them both sides hold two keys, one per direction, that depend on
//! both fresh keys. Stealing the server's long-term key later does not open
//! recorded traffic sent under them.
//!
//! This file follows the Noise specification (revision 34) step for step, and
//! its test runs the published vectors for
//! `Noise_NK_25519_ChaChaPoly_SHA256`, so it interoperates with any other
//! implementation of that name. Nothing in it is of our own design; keep it
//! that way.
//!
//! The rule it keeps: a failed check returns an error and no partial output.
//! The surprise: the first payload is encrypted but only to the server's
//! long-term key, so it has no forward secrecy and can be replayed by someone
//! who recorded it. The caller has to make replays harmless (Tide puts a
//! timestamp in it and remembers the client keys it has seen).

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const NAME: &[u8; 32] = b"Noise_NK_25519_ChaChaPoly_SHA256";
/// Bytes a sealed message is longer than its plaintext.
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub struct BadMessage;

impl std::fmt::Display for BadMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("handshake message failed authentication")
    }
}

impl std::error::Error for BadMessage {}

/// The public half of an X25519 secret.
pub fn public_key(secret: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    x25519_dalek::x25519(*secret, x25519_dalek::X25519_BASEPOINT_BYTES)
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Noise's HKDF: two or three 32-byte outputs from a chaining key and input.
fn hkdf(chaining_key: &[u8; 32], input: &[u8]) -> [[u8; 32]; 3] {
    let mut temp = hmac(chaining_key, &[input]);
    let one = hmac(&temp, &[&[1]]);
    let two = hmac(&temp, &[&one, &[2]]);
    let three = hmac(&temp, &[&two, &[3]]);
    temp.zeroize();
    [one, two, three]
}

/// One direction's transport key. The caller supplies the nonce and must
/// never use one twice with the same key; Tide uses a chunk's stream offset.
pub struct Cipher {
    key: ChaCha20Poly1305,
}

impl Cipher {
    fn new(key: &[u8; KEY_LEN]) -> Self {
        Self {
            key: ChaCha20Poly1305::new(key.into()),
        }
    }

    fn nonce(counter: u64) -> Nonce {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        nonce.into()
    }

    /// Encrypt `buffer` in place and append the tag.
    pub fn seal(&self, counter: u64, associated: &[u8], buffer: &mut Vec<u8>) {
        let tag = self
            .key
            .encrypt_in_place_detached(&Self::nonce(counter), associated, buffer)
            .expect("a message this size always encrypts");
        buffer.extend_from_slice(&tag);
    }

    /// Check and decrypt `buffer` (ciphertext then tag) in place, leaving the
    /// plaintext. On failure the contents are unspecified.
    pub fn open(
        &self,
        counter: u64,
        associated: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), BadMessage> {
        let split = buffer.len().checked_sub(TAG_LEN).ok_or(BadMessage)?;
        let tag = Tag::clone_from_slice(&buffer[split..]);
        buffer.truncate(split);
        self.key
            .decrypt_in_place_detached(&Self::nonce(counter), associated, buffer, &tag)
            .map_err(|_| BadMessage)
    }
}

/// The running state both sides keep during the handshake (Noise's
/// SymmetricState): a hash of everything said so far and a chaining key that
/// every key exchange is mixed into.
struct Symmetric {
    hash: [u8; 32],
    chaining_key: [u8; 32],
    key: Option<[u8; 32]>,
    counter: u64,
}

impl Symmetric {
    fn new(prologue: &[u8], server_public: &[u8; KEY_LEN]) -> Self {
        let mut state = Self {
            hash: *NAME,
            chaining_key: *NAME,
            key: None,
            counter: 0,
        };
        state.mix_hash(prologue);
        // The pre-message: both sides already know the server's key.
        state.mix_hash(server_public);
        state
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.hash = Sha256::new()
            .chain_update(self.hash)
            .chain_update(data)
            .finalize()
            .into();
    }

    fn mix_key(&mut self, shared: &[u8; 32]) {
        let [chaining_key, key, _] = hkdf(&self.chaining_key, shared);
        self.chaining_key = chaining_key;
        self.key = Some(key);
        self.counter = 0;
    }

    fn encrypt_and_hash(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        let key = self.key.expect("NK always has a key before a payload");
        let mut sealed = payload.to_vec();
        Cipher::new(&key).seal(self.counter, &self.hash, &mut sealed);
        self.counter += 1;
        out.extend_from_slice(&sealed);
        let hash_input = out[start..].to_vec();
        self.mix_hash(&hash_input);
    }

    fn decrypt_and_hash(&mut self, sealed: &[u8]) -> Result<Vec<u8>, BadMessage> {
        let key = self.key.expect("NK always has a key before a payload");
        let mut plain = sealed.to_vec();
        Cipher::new(&key).open(self.counter, &self.hash, &mut plain)?;
        self.counter += 1;
        self.mix_hash(sealed);
        Ok(plain)
    }

    /// The two transport keys, and a third value both sides share that Tide
    /// uses to prove later requests belong to this session.
    fn split(mut self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let [first, second, extra] = hkdf(&self.chaining_key, &[]);
        self.chaining_key.zeroize();
        if let Some(key) = self.key.as_mut() {
            key.zeroize();
        }
        (first, second, extra)
    }
}

/// X25519 that refuses the all-zero result a malicious peer can force with a
/// low-order point, which would make the session key public.
fn exchange(secret: &[u8; KEY_LEN], public: &[u8; KEY_LEN]) -> Result<[u8; 32], BadMessage> {
    let shared = x25519_dalek::x25519(*secret, *public);
    if shared == [0u8; 32] {
        return Err(BadMessage);
    }
    Ok(shared)
}

/// What a finished handshake leaves each side with.
pub struct Keys {
    pub send: Cipher,
    pub receive: Cipher,
    /// Shared and secret; never used as an encryption key.
    pub binding: [u8; 32],
}

/// The client after sending its message, waiting for the server's.
pub struct Initiator {
    state: Symmetric,
    ephemeral: [u8; KEY_LEN],
}

/// Build the client's message. `ephemeral` must be 32 fresh random bytes.
pub fn initiate(
    prologue: &[u8],
    server_public: &[u8; KEY_LEN],
    mut ephemeral: [u8; KEY_LEN],
    payload: &[u8],
) -> Result<(Vec<u8>, Initiator), BadMessage> {
    let mut state = Symmetric::new(prologue, server_public);
    let public = public_key(&ephemeral);
    let mut message = Vec::with_capacity(KEY_LEN + payload.len() + TAG_LEN);
    message.extend_from_slice(&public);
    state.mix_hash(&public);
    let mut shared = exchange(&ephemeral, server_public)?;
    state.mix_key(&shared);
    shared.zeroize();
    state.encrypt_and_hash(payload, &mut message);
    let initiator = Initiator { state, ephemeral };
    ephemeral.zeroize();
    Ok((message, initiator))
}

impl Initiator {
    /// Read the server's message; returns its payload and the session keys.
    pub fn finish(mut self, message: &[u8]) -> Result<(Vec<u8>, Keys), BadMessage> {
        if message.len() < KEY_LEN + TAG_LEN {
            return Err(BadMessage);
        }
        let (their_public, sealed) = message.split_at(KEY_LEN);
        let their_public: [u8; KEY_LEN] = their_public.try_into().expect("split at 32");
        self.state.mix_hash(&their_public);
        let mut shared = exchange(&self.ephemeral, &their_public)?;
        self.ephemeral.zeroize();
        self.state.mix_key(&shared);
        shared.zeroize();
        let payload = self.state.decrypt_and_hash(sealed)?;
        let (first, second, binding) = self.state.split();
        Ok((
            payload,
            Keys {
                send: Cipher::new(&first),
                receive: Cipher::new(&second),
                binding,
            },
        ))
    }
}

/// The server after reading the client's message, before answering.
pub struct Responder {
    state: Symmetric,
    client_public: [u8; KEY_LEN],
}

/// Read the client's message with the server's long-term secret. Returns the
/// client's payload; nothing in it is trustworthy beyond "someone who knows
/// our public key wrote it", and it may be a replay.
pub fn respond(
    prologue: &[u8],
    server_secret: &[u8; KEY_LEN],
    message: &[u8],
) -> Result<(Vec<u8>, Responder), BadMessage> {
    if message.len() < KEY_LEN + TAG_LEN {
        return Err(BadMessage);
    }
    let mut state = Symmetric::new(prologue, &public_key(server_secret));
    let (client_public, sealed) = message.split_at(KEY_LEN);
    let client_public: [u8; KEY_LEN] = client_public.try_into().expect("split at 32");
    state.mix_hash(&client_public);
    let mut shared = exchange(server_secret, &client_public)?;
    state.mix_key(&shared);
    shared.zeroize();
    let payload = state.decrypt_and_hash(sealed)?;
    Ok((
        payload,
        Responder {
            state,
            client_public,
        },
    ))
}

impl Responder {
    /// The client's fresh public key: unique per handshake, so remembering
    /// it is how a replayed first message is recognised.
    pub fn client_public(&self) -> &[u8; KEY_LEN] {
        &self.client_public
    }

    /// Build the server's message. `ephemeral` must be 32 fresh random bytes.
    pub fn reply(
        mut self,
        mut ephemeral: [u8; KEY_LEN],
        payload: &[u8],
    ) -> Result<(Vec<u8>, Keys), BadMessage> {
        let public = public_key(&ephemeral);
        let mut message = Vec::with_capacity(KEY_LEN + payload.len() + TAG_LEN);
        message.extend_from_slice(&public);
        self.state.mix_hash(&public);
        let mut shared = exchange(&ephemeral, &self.client_public)?;
        ephemeral.zeroize();
        self.state.mix_key(&shared);
        shared.zeroize();
        self.state.encrypt_and_hash(payload, &mut message);
        let (first, second, binding) = self.state.split();
        Ok((
            message,
            Keys {
                // The first key is the client's sending key.
                send: Cipher::new(&second),
                receive: Cipher::new(&first),
                binding,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        hex::decode(text).unwrap().try_into().unwrap()
    }

    /// The published vector for this exact Noise name (from the `snow`
    /// project's vector file): handshake messages and the first transport
    /// message each way must match byte for byte.
    #[test]
    fn matches_the_published_test_vector() {
        let prologue = hex::decode("5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e").unwrap();
        let init_ephemeral: [u8; 32] =
            unhex("1b0c2affa2a0ba57c3d96a2b5def1671aa00f66a46d306618a2546a6757f5f65");
        let server_public: [u8; 32] =
            unhex("a1685fa10096ad890ba2427ef08d85c44ffe7b1990ebb6ed7555f57b248b9319");
        let server_secret: [u8; 32] =
            unhex("eb80faf5ebe8437d8edacb3bd95d0718a4eb3e5de6f835bca4d7e161301a563e");
        let resp_ephemeral: [u8; 32] =
            unhex("908f7161432df9036325367c1592ca275fea9a44cdf70d4f3135e16d0034dedc");
        assert_eq!(public_key(&server_secret), server_public);

        let payload1 =
            hex::decode("6b2da7554f3d4b8a27f371a0b2fb0d1b9c4830ea29e804b05d698f3f302740f4")
                .unwrap();
        let (message1, initiator) =
            initiate(&prologue, &server_public, init_ephemeral, &payload1).unwrap();
        assert_eq!(hex::encode(&message1), "1c83e1721fadb9fc168e67da9d25503aa286e42d7d35b80c73096d29cce503096ee5516c7bd399fb1f8b0f2affa71e262626c7eb957069a46177f86530217aac9d18bbb78c297d3de7b651995c6783cc");

        let (read1, responder) = respond(&prologue, &server_secret, &message1).unwrap();
        assert_eq!(read1, payload1);
        let payload2 =
            hex::decode("0216bdac2fb32a7c53d9c4711e3ed995c2e856d19fb1ed465cc88efd4f347e6f")
                .unwrap();
        let (message2, server) = responder.reply(resp_ephemeral, &payload2).unwrap();
        assert_eq!(hex::encode(&message2), "d514c7509ba675f32aaaaef759846609383fb36f6081a3aed84737c800a3127c66ebfa61ba8ee2a58b5074e40e3c0ce02ac02c30f3b6afd9ace9fcc4494485e7e3e545d05f5e9f1336ab5cd9f0d8eb54");

        let (read2, client) = initiator.finish(&message2).unwrap();
        assert_eq!(read2, payload2);
        assert_eq!(client.binding, server.binding);

        let mut third =
            hex::decode("0497dfc21ec4d70f04ffc7094b9467808c043d027c87d410b62e1af3dc791dce")
                .unwrap();
        let plain3 = third.clone();
        client.send.seal(0, &[], &mut third);
        assert_eq!(hex::encode(&third), "5bd6fb7c4fd75dd4d15b6600c8df4a59509709a97affb19f4e4a72e62dc8459f89361ae710a9fd58545eee4ceb37ec01");
        server.receive.open(0, &[], &mut third).unwrap();
        assert_eq!(third, plain3);

        let mut fourth =
            hex::decode("874ba1f2539061f556a212f83c7a96faf33a451aa75099ef8a9b2aeb54c48f36")
                .unwrap();
        server.send.seal(0, &[], &mut fourth);
        assert_eq!(hex::encode(&fourth), "1f7b7dd2a4992441bc91b6996b0079c3b0747e5aa8dc2443b1fe01331d57644647bbef13cda29f0abc9836739df52fff");
        client.receive.open(0, &[], &mut fourth).unwrap();
    }

    #[test]
    fn tampering_and_the_wrong_server_key_are_refused() {
        let server_secret = [7u8; 32];
        let server_public = public_key(&server_secret);
        let (mut message, _) = initiate(b"p", &server_public, [9u8; 32], b"hello").unwrap();
        assert!(respond(b"p", &[8u8; 32], &message).is_err(), "wrong key");
        assert!(
            respond(b"other", &server_secret, &message).is_err(),
            "wrong prologue"
        );
        *message.last_mut().unwrap() ^= 1;
        assert!(respond(b"p", &server_secret, &message).is_err(), "tampered");
        assert!(
            respond(b"p", &server_secret, &message[..40]).is_err(),
            "short"
        );
    }

    #[test]
    fn a_low_order_key_is_refused() {
        let server_secret = [7u8; 32];
        let mut message = vec![0u8; 32];
        message.extend_from_slice(&[0u8; 16]);
        assert!(respond(b"p", &server_secret, &message).is_err());
    }
}
