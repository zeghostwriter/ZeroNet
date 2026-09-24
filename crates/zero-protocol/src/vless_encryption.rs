//! VLESS Encryption (`mlkem768x25519plus`), client side.
//!
//! Xray's post-quantum layer under VLESS: a hybrid ML-KEM-768 + X25519
//! handshake against keys published in the share link ("NFS" keys, for the
//! non-forward-secret first flight), a fresh ML-KEM-768 + X25519 exchange for
//! forward secrecy, then TLS-1.3-shaped AEAD records. A server can hand out a
//! ticket so later connections skip the round trip (0-RTT).
//!
//! Ported from Xray-core `proxy/vless/encryption` (client.go, common.go,
//! xor.go); wire behaviour must match it byte for byte, and comments name the
//! Go function each piece mirrors.
//!
//! The link form is
//! `mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>[.<padding>...].<key>[.<key>...]`
//! where each key is base64url of an X25519 public key (32 bytes) or an
//! ML-KEM-768 encapsulation key (1184 bytes), and padding groups are
//! `probability-min-max` triples.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ml_kem::kem::{Kem, KeyExport};
use ml_kem::{Decapsulate, Encapsulate, EncapsulationKey768, MlKem768};
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zeroize::Zeroize;

use crate::io_util::{ReadBuffer, WriteBuffer};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

const X25519_LEN: usize = 32;
const MLKEM_EK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 5;
/// Largest plaintext per record; Xray splits writes at this size.
const MAX_RECORD_PLAINTEXT: usize = 8192;
/// Sealed-length bounds of a record, TLS 1.3's (RFC 8446 §5.2).
const MIN_RECORD: usize = 17;
const MAX_RECORD: usize = 16640;
const MAX_NONCE: [u8; 12] = [0xff; 12];

// --------------------------------------------------------------- configuration

/// One published server key.
#[derive(Clone)]
enum NfsKey {
    X25519([u8; 32]),
    MlKem(Box<EncapsulationKey768>),
}

impl NfsKey {
    /// Bytes this key occupies in the client hello's relay section.
    fn relay_len(&self) -> usize {
        match self {
            NfsKey::X25519(_) => X25519_LEN,
            NfsKey::MlKem(_) => MLKEM_CT_LEN,
        }
    }
}

/// A parsed `encryption` value.
#[derive(Clone)]
pub struct ClientConfig {
    keys: Vec<NfsKey>,
    key_bytes: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_len: usize,
    /// 0 native, 1 xorpub, 2 random.
    xor_mode: u8,
    zero_rtt: bool,
    padding_lens: Vec<[u32; 3]>,
    padding_gaps: Vec<[u32; 3]>,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("keys", &self.keys.len())
            .field("xor_mode", &self.xor_mode)
            .field("zero_rtt", &self.zero_rtt)
            .finish()
    }
}

/// Whether `value` is a VLESS encryption setting this client can use (Xray's
/// `VLessOutboundConfig.Build` check, plus the padding syntax).
pub fn is_valid(value: &str) -> bool {
    ClientConfig::parse(value).is_ok()
}

impl ClientConfig {
    pub fn parse(value: &str) -> Result<Self, String> {
        use base64::Engine;
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
            return Err(format!("unsupported VLESS encryption {value:?}"));
        }
        let xor_mode = match parts[1] {
            "native" => 0,
            "xorpub" => 1,
            "random" => 2,
            other => return Err(format!("unknown VLESS encryption mode {other:?}")),
        };
        let zero_rtt = match parts[2] {
            "1rtt" => false,
            "0rtt" => true,
            other => return Err(format!("unknown VLESS encryption RTT {other:?}")),
        };
        // Xray: tokens shorter than 20 characters are padding groups, and
        // they come before the keys.
        let mut padding = Vec::new();
        let mut key_bytes = Vec::new();
        for token in &parts[3..] {
            if token.len() < 20 {
                if !key_bytes.is_empty() {
                    return Err("VLESS encryption padding must come before the keys".into());
                }
                padding.push(*token);
                continue;
            }
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| "VLESS encryption key is not base64url".to_string())?;
            if bytes.len() != X25519_LEN && bytes.len() != MLKEM_EK_LEN {
                return Err(format!(
                    "VLESS encryption key is {} bytes; expected 32 or 1184",
                    bytes.len()
                ));
            }
            key_bytes.push(bytes);
        }
        if key_bytes.is_empty() {
            return Err("VLESS encryption has no key".into());
        }

        let mut keys = Vec::with_capacity(key_bytes.len());
        let mut hash32s = Vec::with_capacity(key_bytes.len());
        let mut relays_len = 0usize;
        for bytes in &key_bytes {
            if bytes.len() == X25519_LEN {
                keys.push(NfsKey::X25519(bytes.as_slice().try_into().unwrap()));
                relays_len += X25519_LEN + 32;
            } else {
                let encoded = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "ML-KEM-768 key has the wrong length".to_string())?;
                let key = EncapsulationKey768::new(&encoded)
                    .map_err(|_| "ML-KEM-768 key is invalid".to_string())?;
                keys.push(NfsKey::MlKem(Box::new(key)));
                relays_len += MLKEM_CT_LEN + 32;
            }
            hash32s.push(*blake3::hash(bytes).as_bytes());
        }
        relays_len -= 32;

        let (padding_lens, padding_gaps) = parse_padding(&padding.join("."))?;
        Ok(Self {
            keys,
            key_bytes,
            hash32s,
            relays_len,
            xor_mode,
            zero_rtt,
            padding_lens,
            padding_gaps,
        })
    }
}

/// `probability-min-max` groups for padding lengths and for the gaps
/// between the pieces.
type PaddingSpec = (Vec<[u32; 3]>, Vec<[u32; 3]>);

/// Xray's `ParsePadding`: alternating length and gap triples.
fn parse_padding(padding: &str) -> Result<PaddingSpec, String> {
    let mut lens = Vec::new();
    let mut gaps = Vec::new();
    if padding.is_empty() {
        return Ok((lens, gaps));
    }
    let mut max_len = 0u64;
    for (i, group) in padding.split('.').enumerate() {
        let fields: Vec<&str> = group.split('-').collect();
        if fields.len() < 3 || fields[..3].iter().any(|f| f.is_empty()) {
            return Err(format!("invalid VLESS padding group {group:?}"));
        }
        let mut y = [0u32; 3];
        for (slot, field) in y.iter_mut().zip(&fields[..3]) {
            *slot = field
                .parse()
                .map_err(|_| format!("invalid VLESS padding group {group:?}"))?;
        }
        if i == 0 && (y[0] < 100 || y[1] < 18 + 17 || y[2] < 18 + 17) {
            return Err("the first VLESS padding length must not be smaller than 35".into());
        }
        if i % 2 == 0 {
            max_len += u64::from(y[1].max(y[2]));
            lens.push(y);
        } else {
            gaps.push(y);
        }
    }
    if max_len > 18 + 65535 {
        return Err("total VLESS padding must not exceed 65553 bytes".into());
    }
    Ok((lens, gaps))
}

/// Xray's `crypto.RandBetween`: uniform in `[from, to)`, or `from` when equal.
fn rand_between(from: u32, to: u32) -> u32 {
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    if from == to {
        return from;
    }
    rand::thread_rng().gen_range(from..to)
}

/// Xray's `CreatPadding`: the padding length, how to split the first flight,
/// and the pauses between the pieces.
fn create_padding(config: &ClientConfig) -> (usize, Vec<usize>, Vec<Duration>) {
    let default_lens = [[100, 111, 1111], [50, 0, 3333]];
    let default_gaps = [[75, 0, 111]];
    let (lens_spec, gaps_spec): (&[[u32; 3]], &[[u32; 3]]) = if config.padding_lens.is_empty() {
        (&default_lens, &default_gaps)
    } else {
        (&config.padding_lens, &config.padding_gaps)
    };
    let mut total = 0usize;
    let mut lens = Vec::with_capacity(lens_spec.len());
    for y in lens_spec {
        let len = if y[0] >= rand_between(0, 100) {
            rand_between(y[1], y[2]) as usize
        } else {
            0
        };
        lens.push(len);
        total += len;
    }
    let gaps = gaps_spec
        .iter()
        .map(|y| {
            let ms = if y[0] >= rand_between(0, 100) {
                rand_between(y[1], y[2])
            } else {
                0
            };
            Duration::from_millis(u64::from(ms))
        })
        .collect();
    (total, lens, gaps)
}

// ------------------------------------------------------------------ primitives

/// Xray's `NewAEAD`: AES-256-GCM keyed by BLAKE3 derive-key with `ctx` as
/// the context. Xray's client uses ChaCha20-Poly1305 on machines without
/// AES instructions; its server tries AES-GCM first and falls back, so
/// always choosing AES-GCM is compatible.
struct Aead {
    cipher: Aes256Gcm,
    nonce: [u8; 12],
}

impl Aead {
    fn new(ctx: &[u8], key: &[u8]) -> Self {
        let derived = blake3_bytes::derive_key(ctx, key);
        Self {
            cipher: Aes256Gcm::new_from_slice(&derived).expect("32-byte key"),
            nonce: [0; 12],
        }
    }

    /// Xray's `IncreaseNonce`: big-endian, incremented before each use.
    fn next_nonce(&mut self) -> [u8; 12] {
        for byte in self.nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        self.nonce
    }

    /// Append `plaintext` sealed (ciphertext || tag) to `out`.
    fn seal_into(
        &mut self,
        nonce: Option<[u8; 12]>,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut Vec<u8>,
    ) {
        let nonce = nonce.unwrap_or_else(|| self.next_nonce());
        let start = out.len();
        out.extend_from_slice(plaintext);
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut out[start..])
            .expect("AES-GCM seal cannot fail for these sizes");
        out.extend_from_slice(&tag);
    }

    /// Open `sealed` (ciphertext || tag) in place; the plaintext is
    /// `sealed[..len - 16]` afterwards.
    fn open_in_place(
        &mut self,
        nonce: Option<[u8; 12]>,
        sealed: &mut [u8],
        aad: &[u8],
    ) -> io::Result<()> {
        let nonce = nonce.unwrap_or_else(|| self.next_nonce());
        if sealed.len() < TAG_LEN {
            return Err(invalid("VLESS encryption record is shorter than its tag"));
        }
        let split = sealed.len() - TAG_LEN;
        let (body, tag) = sealed.split_at_mut(split);
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                aad,
                body,
                aes_gcm::Tag::from_slice(tag),
            )
            .map_err(|_| invalid("VLESS encryption record failed authentication"))
    }
}

/// Xray's `NewCTR`: AES-256-CTR keyed by BLAKE3 derive-key("VLESS", key).
fn new_ctr(key: &[u8], iv: &[u8]) -> Aes256Ctr {
    let derived = blake3::derive_key("VLESS", key);
    Aes256Ctr::new_from_slices(&derived, &iv[..16]).expect("32-byte key, 16-byte iv")
}

fn encode_length(len: usize) -> [u8; 2] {
    [(len >> 8) as u8, len as u8]
}

fn decode_length(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 8) | usize::from(bytes[1])
}

/// Xray's `DecodeHeader`.
fn decode_header(header: &[u8]) -> Option<usize> {
    let len = (usize::from(header[3]) << 8) | usize::from(header[4]);
    if header[..3] != [23, 3, 3] || !(MIN_RECORD..=MAX_RECORD).contains(&len) {
        return None;
    }
    Some(len)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// ------------------------------------------------------------------- client

/// A saved 0-RTT ticket.
struct Ticket {
    expires: Instant,
    pfs_key: Vec<u8>,
    ticket: [u8; 16],
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.pfs_key.zeroize();
        self.ticket.zeroize();
    }
}

/// Xray's `ClientInstance`: the parsed configuration and, for `0rtt`, the
/// ticket shared by every connection to the same server.
pub struct Client {
    config: ClientConfig,
    ticket: Mutex<Option<Ticket>>,
}

impl Client {
    pub fn new(config: ClientConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            ticket: Mutex::new(None),
        })
    }

    fn valid_ticket(&self) -> Option<(Vec<u8>, [u8; 16])> {
        let guard = self.ticket.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .as_ref()
            .filter(|t| Instant::now() < t.expires)
            .map(|t| (t.pfs_key.clone(), t.ticket))
    }

    /// Forget a ticket the server no longer recognises.
    fn expire_ticket(&self, pfs_key: &[u8]) {
        let mut guard = self.ticket.lock().unwrap_or_else(|p| p.into_inner());
        if guard.as_ref().is_some_and(|t| t.pfs_key == pfs_key) {
            *guard = None;
        }
    }

    /// Xray's `ClientInstance.Handshake`.
    pub async fn handshake<S>(self: &Arc<Self>, mut inner: S) -> io::Result<EncryptedStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let config = &self.config;
        let iv_and_relays_len = 16 + config.relays_len;
        let mut hello = vec![0u8; iv_and_relays_len];
        rand::thread_rng().fill_bytes(&mut hello[..16]);
        let iv: [u8; 16] = hello[..16].try_into().unwrap();

        // The relay chain: one key agreement per published key, each hiding
        // the next key's hash so no relay can be swapped out.
        let mut nfs_key = zeroize::Zeroizing::new(Vec::new());
        let mut last_ctr: Option<Aes256Ctr> = None;
        let mut offset = 16usize;
        for (j, key) in config.keys.iter().enumerate() {
            let index = key.relay_len();
            let relay = &mut hello[offset..];
            match key {
                NfsKey::X25519(public) => {
                    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
                    relay[..32].copy_from_slice(x25519_dalek::PublicKey::from(&secret).as_bytes());
                    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*public));
                    if !shared.was_contributory() {
                        return Err(invalid("VLESS encryption X25519 key is degenerate"));
                    }
                    *nfs_key = shared.as_bytes().to_vec();
                }
                NfsKey::MlKem(public) => {
                    let (ciphertext, shared) = public.encapsulate();
                    let ciphertext: &[u8] = ciphertext.as_ref();
                    let shared: &[u8] = shared.as_ref();
                    relay[..MLKEM_CT_LEN].copy_from_slice(ciphertext);
                    *nfs_key = shared.to_vec();
                }
            }
            if config.xor_mode > 0 {
                new_ctr(&config.key_bytes[j], &iv).apply_keystream(&mut relay[..index]);
            }
            if let Some(ctr) = last_ctr.as_mut() {
                ctr.apply_keystream(&mut relay[..32]);
            }
            if j == config.keys.len() - 1 {
                break;
            }
            let mut ctr = new_ctr(&nfs_key, &iv);
            relay[index..index + 32].copy_from_slice(&config.hash32s[j + 1]);
            ctr.apply_keystream(&mut relay[index..index + 32]);
            last_ctr = Some(ctr);
            offset += index + 32;
        }
        let mut nfs_aead = Aead::new(&iv, &nfs_key);

        // 0-RTT: reuse the forward-secret key from a ticket.
        if config.zero_rtt {
            if let Some((pfs_key, ticket)) = self.valid_ticket() {
                let pfs_key = zeroize::Zeroizing::new(pfs_key);
                nfs_aead.seal_into(None, &encode_length(32), &[], &mut hello);
                nfs_aead.seal_into(None, &ticket, &[], &mut hello);
                let ticket_ctx = hello[iv_and_relays_len + 18..].to_vec();
                let mut united_key = pfs_key.to_vec();
                united_key.extend_from_slice(&nfs_key);
                let aead = Aead::new(&ticket_ctx, &united_key);
                let random_mode = config.xor_mode == 2;
                let out_ctr = random_mode.then(|| new_ctr(&united_key, &iv));
                let skip = hello.len();
                let mut stream =
                    EncryptedStream::new(inner, united_key, aead, None, ReadStage::ServerRandom);
                stream.random_mode = random_mode;
                stream.out_mask = HeaderMask::new(out_ctr, skip);
                stream.zero_rtt = Some((Arc::clone(self), pfs_key));
                stream.pre_write = hello;
                return Ok(stream);
            }
        }

        // 1-RTT: a fresh ML-KEM-768 + X25519 exchange for forward secrecy.
        let pfs_len = MLKEM_EK_LEN + X25519_LEN;
        nfs_aead.seal_into(None, &encode_length(pfs_len + TAG_LEN), &[], &mut hello);
        let decapsulation_key = MlKem768::generate_keypair().0;
        let encapsulation_key = decapsulation_key.encapsulation_key().to_bytes();
        let x25519_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let mut pfs_public = Vec::with_capacity(pfs_len);
        pfs_public.extend_from_slice(encapsulation_key.as_ref());
        pfs_public.extend_from_slice(x25519_dalek::PublicKey::from(&x25519_secret).as_bytes());
        nfs_aead.seal_into(None, &pfs_public, &[], &mut hello);

        let (padding_len, mut piece_lens, gaps) = create_padding(config);
        nfs_aead.seal_into(None, &encode_length(padding_len - 18), &[], &mut hello);
        let zeros = vec![0u8; padding_len - 18 - TAG_LEN];
        nfs_aead.seal_into(None, &zeros, &[], &mut hello);

        // Sent in pieces with pauses, as Xray does, so the first flight has
        // no fixed shape before the inner protocol takes over.
        piece_lens[0] += hello.len() - padding_len;
        let mut sent = 0usize;
        for (i, len) in piece_lens.iter().enumerate() {
            if *len > 0 {
                inner.write_all(&hello[sent..sent + len]).await?;
                inner.flush().await?;
                sent += len;
            }
            if let Some(gap) = gaps.get(i) {
                if !gap.is_zero() {
                    tokio::time::sleep(*gap).await;
                }
            }
        }

        let mut server_pfs = vec![0u8; MLKEM_CT_LEN + X25519_LEN + TAG_LEN];
        inner.read_exact(&mut server_pfs).await?;
        nfs_aead.open_in_place(Some(MAX_NONCE), &mut server_pfs, &[])?;
        let mlkem_key = decapsulation_key
            .decapsulate_slice(&server_pfs[..MLKEM_CT_LEN])
            .map_err(|_| invalid("ML-KEM-768 decapsulation failed"))?;
        let peer_x25519: [u8; 32] = server_pfs[MLKEM_CT_LEN..MLKEM_CT_LEN + 32]
            .try_into()
            .unwrap();
        let x25519_key = x25519_secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer_x25519));
        if !x25519_key.was_contributory() {
            return Err(invalid("VLESS encryption server X25519 key is degenerate"));
        }
        let mut pfs_key = zeroize::Zeroizing::new(Vec::with_capacity(64));
        pfs_key.extend_from_slice(mlkem_key.as_ref());
        pfs_key.extend_from_slice(x25519_key.as_bytes());
        let mut united_key = pfs_key.to_vec();
        united_key.extend_from_slice(&nfs_key);
        let aead = Aead::new(&pfs_public, &united_key);
        let mut peer_aead = Aead::new(&server_pfs[..MLKEM_CT_LEN + X25519_LEN], &united_key);

        let mut ticket = [0u8; 32];
        inner.read_exact(&mut ticket).await?;
        peer_aead.open_in_place(None, &mut ticket, &[])?;
        let seconds = decode_length(&ticket);
        if config.zero_rtt && seconds > 0 {
            let mut guard = self.ticket.lock().unwrap_or_else(|p| p.into_inner());
            *guard = Some(Ticket {
                expires: Instant::now() + Duration::from_secs(seconds as u64),
                pfs_key: pfs_key.to_vec(),
                ticket: ticket[..16].try_into().unwrap(),
            });
        }

        let mut length = [0u8; 18];
        inner.read_exact(&mut length).await?;
        peer_aead.open_in_place(None, &mut length, &[])?;
        let server_padding = decode_length(&length);

        let mut stream = EncryptedStream::new(
            inner,
            united_key,
            aead,
            Some(peer_aead),
            ReadStage::ServerPadding(server_padding),
        );
        if config.xor_mode == 2 {
            stream.random_mode = true;
            stream.out_mask = HeaderMask::new(Some(new_ctr(&stream.united_key, &iv)), 0);
            stream.in_mask = HeaderMask::new(
                Some(new_ctr(&stream.united_key, &ticket[..16])),
                server_padding,
            );
        }
        Ok(stream)
    }
}

// --------------------------------------------------------------- the stream

/// Xray's `XorConn` for one direction: in `random` mode the 5-byte header of
/// every record is XORed with an AES-CTR keystream so nothing on the wire
/// looks like TLS. The keystream is spent on header bytes only; `skip`
/// counts the record body (or handshake bytes) still to pass untouched.
///
/// The mask keeps parsing record boundaries after Vision switches to direct
/// mode, because the server's raw inner-TLS records pass through the same
/// `XorConn` on its side.
struct HeaderMask {
    ctr: Option<Aes256Ctr>,
    skip: usize,
    header: [u8; HEADER_LEN],
    have: usize,
}

impl HeaderMask {
    fn new(ctr: Option<Aes256Ctr>, skip: usize) -> Self {
        Self {
            ctr,
            skip,
            header: [0; HEADER_LEN],
            have: 0,
        }
    }

    /// `XorConn.Write` (outgoing = true) or `XorConn.Read`. Headers are
    /// parsed from their plaintext form either way.
    fn apply(&mut self, mut p: &mut [u8], outgoing: bool) {
        let Some(ctr) = self.ctr.as_mut() else {
            return;
        };
        loop {
            if p.len() <= self.skip {
                self.skip -= p.len();
                return;
            }
            p = &mut std::mem::take(&mut p)[self.skip..];
            self.skip = 0;
            let need = HEADER_LEN - self.have;
            let take = need.min(p.len());
            if !outgoing {
                ctr.apply_keystream(&mut p[..take]);
            }
            self.header[self.have..self.have + take].copy_from_slice(&p[..take]);
            if outgoing {
                ctr.apply_keystream(&mut p[..take]);
            }
            if take < need {
                self.have += take;
                return;
            }
            self.have = 0;
            // Xray's DecodeHeader: a record of the wrong type skips nothing,
            // an out-of-range length is still skipped.
            self.skip = if self.header[..3] == [23, 3, 3] {
                (usize::from(self.header[3]) << 8) | usize::from(self.header[4])
            } else {
                0
            };
            p = &mut std::mem::take(&mut p)[take..];
        }
    }
}

enum ReadStage {
    /// 0-RTT: the server's 16 random bytes that key its direction.
    ServerRandom,
    /// 1-RTT: server padding still to consume before the first record.
    ServerPadding(usize),
    Records,
}

/// Xray's `CommonConn`, with `XorConn` folded in as [`HeaderMask`]s.
pub struct EncryptedStream<S> {
    inner: S,
    united_key: Vec<u8>,
    aead: Aead,
    peer_aead: Option<Aead>,
    /// `random` mode: set when the 0-RTT server random arrives.
    random_mode: bool,
    out_mask: HeaderMask,
    in_mask: HeaderMask,
    read_stage: ReadStage,
    /// Set while a 0-RTT ticket is unconfirmed, to forget it if refused.
    zero_rtt: Option<(Arc<Client>, zeroize::Zeroizing<Vec<u8>>)>,
    /// The 0-RTT first flight, sent ahead of the first record.
    pre_write: Vec<u8>,
    read_buf: ReadBuffer,
    /// How many bytes at the front of `read_buf` have been unmasked.
    unmasked: usize,
    plain: Vec<u8>,
    plain_pos: usize,
    /// Vision received `PaddingDirect`: the server now writes its raw inner
    /// stream underneath this layer.
    direct_read: bool,
    write_buf: WriteBuffer,
}

impl<S> Drop for EncryptedStream<S> {
    fn drop(&mut self) {
        self.united_key.zeroize();
    }
}

impl<S> EncryptedStream<S> {
    fn new(
        inner: S,
        united_key: Vec<u8>,
        aead: Aead,
        peer_aead: Option<Aead>,
        read_stage: ReadStage,
    ) -> Self {
        Self {
            inner,
            united_key,
            aead,
            peer_aead,
            random_mode: false,
            out_mask: HeaderMask::new(None, 0),
            in_mask: HeaderMask::new(None, 0),
            read_stage,
            zero_rtt: None,
            pre_write: Vec::new(),
            read_buf: ReadBuffer::with_capacity(32 * 1024),
            unmasked: 0,
            plain: Vec::new(),
            plain_pos: 0,
            direct_read: false,
            write_buf: WriteBuffer::default(),
        }
    }

    /// Stop decrypting: everything after the Vision `PaddingDirect` frame
    /// arrives as the server's raw inner stream (Xray's `UnwrapRawConn`
    /// stops at this layer's transport). Only Vision calls this, after
    /// authenticating the frame inside a decrypted record.
    pub fn enter_direct_mode(&mut self) {
        self.direct_read = true;
    }

    /// Seal one record of `data` into the write buffer.
    fn seal_record(&mut self, data: &[u8]) {
        let out = self.write_buf.buf_mut();
        let start = out.len();
        if !self.pre_write.is_empty() {
            out.extend_from_slice(&std::mem::take(&mut self.pre_write));
        }
        let header_at = out.len();
        let len = data.len() + TAG_LEN;
        let header = [23, 3, 3, (len >> 8) as u8, len as u8];
        out.extend_from_slice(&header);
        let rekey = self.aead.nonce == MAX_NONCE;
        self.aead.seal_into(None, data, &header, out);
        if rekey {
            self.aead = Aead::new(&out[header_at..], &self.united_key);
        }
        self.out_mask.apply(&mut out[start..], true);
    }

    fn consume(&mut self, n: usize) {
        self.read_buf.consume(n);
        self.unmasked = self.unmasked.saturating_sub(n);
    }
}

impl<S: AsyncRead + Unpin> EncryptedStream<S> {
    /// Buffer at least `need` bytes, unmasking whatever arrived.
    fn poll_fill(&mut self, cx: &mut Context<'_>, need: usize) -> Poll<io::Result<bool>> {
        let result = self.read_buf.poll_fill(Pin::new(&mut self.inner), cx, need);
        let data = self.read_buf.data_mut();
        if self.unmasked < data.len() {
            self.in_mask.apply(&mut data[self.unmasked..], false);
            self.unmasked = data.len();
        }
        result
    }

    /// Advance the read side until plaintext is available or EOF.
    fn poll_fill_plain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            match self.read_stage {
                ReadStage::ServerRandom => {
                    // The mask has no keystream yet, so these bytes and any
                    // read past them stay as they arrived.
                    if !ready!(self.poll_fill(cx, 16))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let random: [u8; 16] = self.read_buf.data()[..16].try_into().unwrap();
                    self.consume(16);
                    self.peer_aead = Some(Aead::new(&random, &self.united_key));
                    if self.random_mode {
                        self.in_mask = HeaderMask::new(Some(new_ctr(&self.united_key, &random)), 0);
                        self.unmasked = 0;
                        let data = self.read_buf.data_mut();
                        self.in_mask.apply(data, false);
                        self.unmasked = data.len();
                    }
                    self.read_stage = ReadStage::Records;
                }
                ReadStage::ServerPadding(len) => {
                    if !ready!(self.poll_fill(cx, len))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let peer = self.peer_aead.as_mut().expect("1-RTT has a peer key");
                    peer.open_in_place(None, &mut self.read_buf.data_mut()[..len], &[])?;
                    self.consume(len);
                    self.read_stage = ReadStage::Records;
                }
                ReadStage::Records => {
                    if !ready!(self.poll_fill(cx, HEADER_LEN))? {
                        if self.read_buf.is_empty() {
                            return Poll::Ready(Ok(false));
                        }
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let header: [u8; 5] = self.read_buf.data()[..5].try_into().unwrap();
                    let Some(len) = decode_header(&header) else {
                        if let Some((client, pfs_key)) = self.zero_rtt.take() {
                            // The server did not accept the ticket; the
                            // next connection handshakes afresh.
                            client.expire_ticket(&pfs_key);
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                "VLESS encryption ticket expired; a new handshake is needed",
                            )));
                        }
                        return Poll::Ready(Err(invalid("invalid VLESS encryption record header")));
                    };
                    self.zero_rtt = None;
                    if !ready!(self.poll_fill(cx, HEADER_LEN + len))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let peer = self
                        .peer_aead
                        .as_mut()
                        .expect("records follow the peer key");
                    let next = (peer.nonce == MAX_NONCE).then(|| {
                        Aead::new(&self.read_buf.data()[..HEADER_LEN + len], &self.united_key)
                    });
                    let record = &mut self.read_buf.data_mut()[HEADER_LEN..HEADER_LEN + len];
                    let result = peer.open_in_place(None, record, &header);
                    if let Some(next) = next {
                        *peer = next;
                    }
                    result?;
                    self.plain.clear();
                    self.plain.extend_from_slice(&record[..len - TAG_LEN]);
                    self.plain_pos = 0;
                    self.consume(HEADER_LEN + len);
                    if !self.plain.is_empty() {
                        return Poll::Ready(Ok(true));
                    }
                }
            }
        }
    }
}

/// `std::task::ready!`, spelled out for the MSRV.
macro_rules! ready {
    ($e:expr) => {
        match $e {
            Poll::Ready(value) => value,
            Poll::Pending => return Poll::Pending,
        }
    };
}
use ready;

impl<S: AsyncRead + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.plain_pos < this.plain.len() {
            let n = buf.remaining().min(this.plain.len() - this.plain_pos);
            buf.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
            this.plain_pos += n;
            return Poll::Ready(Ok(()));
        }
        if this.direct_read {
            if !this.read_buf.is_empty() {
                let n = buf.remaining().min(this.read_buf.len());
                buf.put_slice(&this.read_buf.data()[..n]);
                this.consume(n);
                return Poll::Ready(Ok(()));
            }
            let before = buf.filled().len();
            ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
            this.in_mask.apply(&mut buf.filled_mut()[before..], false);
            return Poll::Ready(Ok(()));
        }
        if !ready!(this.poll_fill_plain(cx))? {
            return Poll::Ready(Ok(()));
        }
        let n = buf.remaining().min(this.plain.len());
        buf.put_slice(&this.plain[..n]);
        this.plain_pos = n;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Bounded buffering behind a slow transport.
        if this.write_buf.len() >= 4 * (MAX_RECORD_PLAINTEXT + HEADER_LEN + TAG_LEN) {
            ready!(this.write_buf.poll_drain(Pin::new(&mut this.inner), cx))?;
        }
        let n = data.len().min(MAX_RECORD_PLAINTEXT);
        this.seal_record(&data[..n]);
        // The record is queued either way; push it now if the transport can
        // take it.
        if let Poll::Ready(Err(error)) = this.write_buf.poll_drain(Pin::new(&mut this.inner), cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.write_buf.poll_drain(Pin::new(&mut this.inner), cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.write_buf.poll_drain(Pin::new(&mut this.inner), cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

// ------------------------------------------------------------------ BLAKE3

/// BLAKE3 derive-key with an arbitrary byte-string context.
///
/// Xray passes raw bytes (IVs, public keys, record ciphertext) as the
/// derive-key context; the `blake3` crate only takes `&str`, and handing it
/// bytes that are not UTF-8 would be unsound. The context key is therefore
/// computed here, straight from the BLAKE3 specification's reference
/// algorithm, and checked against the crate wherever the crate can express
/// the same input.
mod blake3_bytes {
    const IV: [u32; 8] = [
        0x6A09_E667,
        0xBB67_AE85,
        0x3C6E_F372,
        0xA54F_F53A,
        0x510E_527F,
        0x9B05_688C,
        0x1F83_D9AB,
        0x5BE0_CD19,
    ];
    const PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
    const CHUNK_START: u32 = 1;
    const CHUNK_END: u32 = 2;
    const PARENT: u32 = 4;
    const ROOT: u32 = 8;
    const DERIVE_KEY_CONTEXT: u32 = 32;
    const DERIVE_KEY_MATERIAL: u32 = 64;
    const BLOCK: usize = 64;
    const CHUNK: usize = 1024;

    fn g(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        s[a] = s[a].wrapping_add(s[b]).wrapping_add(x);
        s[d] = (s[d] ^ s[a]).rotate_right(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_right(12);
        s[a] = s[a].wrapping_add(s[b]).wrapping_add(y);
        s[d] = (s[d] ^ s[a]).rotate_right(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_right(7);
    }

    fn compress(cv: &[u32; 8], block: &[u32; 16], counter: u64, len: u32, flags: u32) -> [u32; 16] {
        let mut s = [
            cv[0],
            cv[1],
            cv[2],
            cv[3],
            cv[4],
            cv[5],
            cv[6],
            cv[7],
            IV[0],
            IV[1],
            IV[2],
            IV[3],
            counter as u32,
            (counter >> 32) as u32,
            len,
            flags,
        ];
        let mut m = *block;
        for round in 0..7 {
            g(&mut s, 0, 4, 8, 12, m[0], m[1]);
            g(&mut s, 1, 5, 9, 13, m[2], m[3]);
            g(&mut s, 2, 6, 10, 14, m[4], m[5]);
            g(&mut s, 3, 7, 11, 15, m[6], m[7]);
            g(&mut s, 0, 5, 10, 15, m[8], m[9]);
            g(&mut s, 1, 6, 11, 12, m[10], m[11]);
            g(&mut s, 2, 7, 8, 13, m[12], m[13]);
            g(&mut s, 3, 4, 9, 14, m[14], m[15]);
            if round < 6 {
                let mut permuted = [0u32; 16];
                for (i, p) in PERMUTATION.iter().enumerate() {
                    permuted[i] = m[*p];
                }
                m = permuted;
            }
        }
        for i in 0..8 {
            s[i] ^= s[i + 8];
            s[i + 8] ^= cv[i];
        }
        s
    }

    fn words(bytes: &[u8]) -> [u32; 16] {
        let mut padded = [0u8; BLOCK];
        padded[..bytes.len()].copy_from_slice(bytes);
        let mut out = [0u32; 16];
        for (i, w) in out.iter_mut().enumerate() {
            *w = u32::from_le_bytes(padded[i * 4..i * 4 + 4].try_into().unwrap());
        }
        out
    }

    fn first8(state: [u32; 16]) -> [u32; 8] {
        state[..8].try_into().unwrap()
    }

    /// What is still to be compressed for a node's output.
    struct Output {
        cv: [u32; 8],
        block: [u32; 16],
        counter: u64,
        len: u32,
        flags: u32,
    }

    impl Output {
        fn chaining_value(&self) -> [u32; 8] {
            first8(compress(
                &self.cv,
                &self.block,
                self.counter,
                self.len,
                self.flags,
            ))
        }
        fn root(&self) -> [u8; 32] {
            let s = compress(&self.cv, &self.block, 0, self.len, self.flags | ROOT);
            let mut out = [0u8; 32];
            for (i, w) in s[..8].iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            out
        }
    }

    fn chunk_output(key: &[u32; 8], chunk: &[u8], counter: u64, flags: u32) -> Output {
        let mut cv = *key;
        let blocks: Vec<&[u8]> = if chunk.is_empty() {
            vec![&[][..]]
        } else {
            chunk.chunks(BLOCK).collect()
        };
        let last = blocks.len() - 1;
        for (i, block) in blocks[..last].iter().enumerate() {
            let start = if i == 0 { CHUNK_START } else { 0 };
            cv = first8(compress(
                &cv,
                &words(block),
                counter,
                BLOCK as u32,
                flags | start,
            ));
        }
        Output {
            cv,
            block: words(blocks[last]),
            counter,
            len: blocks[last].len() as u32,
            flags: flags | CHUNK_END | if last == 0 { CHUNK_START } else { 0 },
        }
    }

    fn parent_output(key: &[u32; 8], left: [u32; 8], right: [u32; 8], flags: u32) -> Output {
        let mut block = [0u32; 16];
        block[..8].copy_from_slice(&left);
        block[8..].copy_from_slice(&right);
        Output {
            cv: *key,
            block,
            counter: 0,
            len: BLOCK as u32,
            flags: flags | PARENT,
        }
    }

    /// The reference implementation's tree hash, 32-byte output.
    fn hash(input: &[u8], key: &[u32; 8], flags: u32) -> [u8; 32] {
        let chunks: Vec<&[u8]> = if input.is_empty() {
            vec![&[][..]]
        } else {
            input.chunks(CHUNK).collect()
        };
        let mut stack: Vec<[u32; 8]> = Vec::new();
        let last = chunks.len() - 1;
        for (i, chunk) in chunks[..last].iter().enumerate() {
            let mut cv = chunk_output(key, chunk, i as u64, flags).chaining_value();
            let mut total = i as u64 + 1;
            while total & 1 == 0 {
                let left = stack.pop().expect("tree stack");
                cv = parent_output(key, left, cv, flags).chaining_value();
                total >>= 1;
            }
            stack.push(cv);
        }
        let mut output = chunk_output(key, chunks[last], last as u64, flags);
        while let Some(left) = stack.pop() {
            output = parent_output(key, left, output.chaining_value(), flags);
        }
        output.root()
    }

    pub(super) fn derive_key(context: &[u8], material: &[u8]) -> [u8; 32] {
        let context_key = hash(context, &IV, DERIVE_KEY_CONTEXT);
        let mut key = [0u32; 8];
        for (i, w) in key.iter_mut().enumerate() {
            *w = u32::from_le_bytes(context_key[i * 4..i * 4 + 4].try_into().unwrap());
        }
        hash(material, &key, DERIVE_KEY_MATERIAL)
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn matches_the_blake3_crate_wherever_it_can_be_compared() {
            for context_len in [0usize, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 3000, 5000] {
                let context: String = (0..context_len)
                    .map(|i| (b'a' + (i % 26) as u8) as char)
                    .collect();
                for material_len in [0usize, 1, 64, 1024, 1025, 4096, 9000] {
                    let material: Vec<u8> = (0..material_len).map(|i| (i * 7) as u8).collect();
                    assert_eq!(
                        super::derive_key(context.as_bytes(), &material),
                        blake3::derive_key(&context, &material),
                        "context {context_len}, material {material_len}"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_what_xray_accepts() {
        use base64::Engine;
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]);
        let config = ClientConfig::parse(&format!("mlkem768x25519plus.native.0rtt.{x}")).unwrap();
        assert!(config.zero_rtt && config.xor_mode == 0 && config.keys.len() == 1);
        let config = ClientConfig::parse(&format!(
            "mlkem768x25519plus.random.1rtt.100-111-1111.75-0-111.50-0-3333.{x}"
        ))
        .unwrap();
        assert_eq!(config.padding_lens.len(), 2);
        assert_eq!(config.padding_gaps.len(), 1);
        assert!(ClientConfig::parse("none").is_err());
        assert!(ClientConfig::parse(&format!("mlkem768x25519plus.native.2rtt.{x}")).is_err());
        assert!(
            ClientConfig::parse("mlkem768x25519plus.native.0rtt.c2hvcnRrZXlzaG9ydGtleQ").is_err()
        );
    }

    #[test]
    fn nonces_count_up_big_endian_from_one() {
        let mut aead = Aead::new(b"ctx", b"key");
        assert_eq!(aead.next_nonce()[11], 1);
        aead.nonce = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff];
        assert_eq!(aead.next_nonce(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    }
}
