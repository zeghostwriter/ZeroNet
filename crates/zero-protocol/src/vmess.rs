//! VMess AEAD TCP framing.
//!
//! This is the modern VMess wire contract used by Xray: an AEAD-authenticated
//! request header followed by length-prefixed data records. The module only
//! owns bytes and crypto; endpoint selection and socket setup stay in the
//! runtime layer.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::{aead::AeadInPlace, Aes128Gcm};
use md5::{Digest, Md5};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use zero_core::{Address, Destination, Network};

use crate::io_util::{ReadBuffer, ReplayFilter, WriteBuffer, DEFAULT_READ_CAPACITY};

const AUTH_ID_LEN: usize = 16;
const TAG_LEN: usize = 16;
const MAX_FRAME: usize = u16::MAX as usize;
const MAX_WRITE_PLAINTEXT: usize = 8192;
/// Plaintext framed per `poll_write` (eight Xray-sized chunks).
const MAX_WRITE_BATCH: usize = 8 * MAX_WRITE_PLAINTEXT;
/// Auth IDs accepted by this process's servers, remembered for 120-240 s.
static AUTH_IDS: ReplayFilter<AUTH_ID_LEN> =
    ReplayFilter::new(std::time::Duration::from_secs(120), 64 * 1024);
const MAGIC_AUTH_ID: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// Request bytes, data key/IV, response key/IV, the response verification
/// byte, and the negotiated framing options.
type RequestMaterial = (Vec<u8>, [u8; 16], [u8; 16], [u8; 16], [u8; 16], u8, u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}

impl Cipher {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Self::Auto,
            "aes-128-gcm" => Self::Aes128Gcm,
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Self::Chacha20Poly1305,
            "none" => Self::None,
            _ => return None,
        })
    }

    fn actual(self) -> Self {
        match self {
            // Xray's current VMess auto choice is ChaCha20-Poly1305.
            Self::Auto => Self::Chacha20Poly1305,
            other => other,
        }
    }

    fn wire_code(self) -> u8 {
        match self.actual() {
            Self::Aes128Gcm => 3,
            Self::Chacha20Poly1305 => 4,
            Self::None => 5,
            Self::Auto => unreachable!(),
        }
    }

    fn from_wire(value: u8) -> io::Result<Self> {
        match value {
            3 => Ok(Self::Aes128Gcm),
            4 => Ok(Self::Chacha20Poly1305),
            5 => Ok(Self::None),
            _ => Err(invalid("VMess requested an unknown data cipher")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct User {
    pub uuid: [u8; 16],
    pub cipher: Cipher,
}

#[derive(Debug)]
pub struct Accepted<S> {
    pub destination: Destination,
    pub stream: Stream<S>,
}

/// The per-direction data AEAD. The cipher object (with its expanded key
/// schedule) is built once per stream, not once per chunk.
enum FrameCipher {
    None {
        counter: u16,
    },
    Aes {
        cipher: Box<Aes128Gcm>,
        iv: [u8; 16],
        counter: u16,
    },
    Chacha {
        cipher: Box<chacha20poly1305::ChaCha20Poly1305>,
        iv: [u8; 16],
        counter: u16,
    },
}

impl FrameCipher {
    fn new(cipher: Cipher, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        match cipher.actual() {
            Cipher::None => Self::None { counter: 0 },
            Cipher::Aes128Gcm => Self::Aes {
                cipher: Box::new(Aes128Gcm::new_from_slice(key).expect("16-byte AES key")),
                iv: *iv,
                counter: 0,
            },
            Cipher::Chacha20Poly1305 => Self::Chacha {
                cipher: Box::new(
                    chacha20poly1305::ChaCha20Poly1305::new_from_slice(&chacha_key(key))
                        .expect("32-byte ChaCha key"),
                ),
                iv: *iv,
                counter: 0,
            },
            Cipher::Auto => unreachable!(),
        }
    }

    fn nonce(iv: &[u8; 16], counter: u16) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[2..].copy_from_slice(&iv[2..12]);
        nonce[0..2].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    fn overhead(&self) -> usize {
        match self {
            Self::None { .. } => 0,
            Self::Aes { .. } | Self::Chacha { .. } => TAG_LEN,
        }
    }

    /// Append the sealed form of `plaintext` to `out`, encrypting in place.
    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let start = out.len();
        out.extend_from_slice(plaintext);
        match self {
            Self::None { counter } => {
                *counter = counter.wrapping_add(1);
            }
            Self::Aes {
                cipher,
                iv,
                counter,
            } => {
                let nonce = Self::nonce(iv, *counter);
                let tag = cipher
                    .encrypt_in_place_detached(
                        aes_gcm::Nonce::from_slice(&nonce),
                        b"",
                        &mut out[start..],
                    )
                    .map_err(|_| invalid("VMess data encryption failed"))?;
                out.extend_from_slice(&tag);
                *counter = counter.wrapping_add(1);
            }
            Self::Chacha {
                cipher,
                iv,
                counter,
            } => {
                let nonce = Self::nonce(iv, *counter);
                let tag = cipher
                    .encrypt_in_place_detached(
                        chacha20poly1305::Nonce::from_slice(&nonce),
                        b"",
                        &mut out[start..],
                    )
                    .map_err(|_| invalid("VMess data encryption failed"))?;
                out.extend_from_slice(&tag);
                *counter = counter.wrapping_add(1);
            }
        }
        Ok(())
    }

    /// Authenticate and decrypt `chunk` in place, returning the plaintext
    /// length (the plaintext is `chunk[..len]`).
    fn open_in_place(&mut self, chunk: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::None { counter } => {
                *counter = counter.wrapping_add(1);
                Ok(chunk.len())
            }
            Self::Aes {
                cipher,
                iv,
                counter,
            } => {
                if chunk.len() < TAG_LEN {
                    return Err(invalid("VMess data frame is shorter than its AEAD tag"));
                }
                let nonce = Self::nonce(iv, *counter);
                let split = chunk.len() - TAG_LEN;
                let (body, tag) = chunk.split_at_mut(split);
                let tag: &[u8] = tag;
                cipher
                    .decrypt_in_place_detached(
                        aes_gcm::Nonce::from_slice(&nonce),
                        b"",
                        body,
                        tag.into(),
                    )
                    .map_err(|_| invalid("VMess data authentication failed"))?;
                *counter = counter.wrapping_add(1);
                Ok(split)
            }
            Self::Chacha {
                cipher,
                iv,
                counter,
            } => {
                if chunk.len() < TAG_LEN {
                    return Err(invalid("VMess data frame is shorter than its AEAD tag"));
                }
                let nonce = Self::nonce(iv, *counter);
                let split = chunk.len() - TAG_LEN;
                let (body, tag) = chunk.split_at_mut(split);
                let tag: &[u8] = tag;
                cipher
                    .decrypt_in_place_detached(
                        chacha20poly1305::Nonce::from_slice(&nonce),
                        b"",
                        body,
                        tag.into(),
                    )
                    .map_err(|_| invalid("VMess data authentication failed"))?;
                *counter = counter.wrapping_add(1);
                Ok(split)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadStage {
    ResponseLength,
    ResponseBody(usize),
    DataLength,
    DataBody(usize),
    Eof,
}

/// Plaintext of the frame at the head of the read buffer not yet delivered.
#[derive(Debug, Clone, Copy, Default)]
struct PlainWindow {
    pos: usize,
    end: usize,
    frame_len: usize,
}

/// A VMess data stream. The client consumes the encrypted response header on
/// its first read; the server starts directly at data frames and emits its
/// response header lazily with its first write.
///
/// Writes are buffered: `poll_write` frames the caller's bytes into an
/// internal buffer and reports them accepted; `poll_flush` and
/// `poll_shutdown` drain it.
pub struct Stream<S> {
    inner: S,
    send: FrameCipher,
    recv: FrameCipher,
    read_stage: ReadStage,
    read_buf: ReadBuffer,
    plain: PlainWindow,
    write_buf: WriteBuffer,
    shutdown_sent: bool,
    response_key: Option<[u8; 16]>,
    response_iv: Option<[u8; 16]>,
    /// The client's random response-authentication byte, which the server
    /// must echo as the first byte of its response header.
    response_auth: u8,
    /// Chunk-length masking and padding for each direction, when the peer
    /// negotiated them. `None` is the plain `0x01` framing.
    send_sizes: Option<ShakeSizeParser>,
    recv_sizes: Option<ShakeSizeParser>,
    /// Padding for the chunk currently being read, drawn when its length was.
    recv_padding: usize,
}

impl<S> std::fmt::Debug for Stream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessStream")
            .field("read_stage", &self.read_stage)
            .field("pending_write", &self.write_buf.len())
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream<S> {
    #[allow(clippy::too_many_arguments)]
    fn new_client(
        inner: S,
        cipher: Cipher,
        data_key: [u8; 16],
        data_iv: [u8; 16],
        response_key: [u8; 16],
        response_iv: [u8; 16],
        response_auth: u8,
        options: u8,
    ) -> Self {
        // Each direction has its own SHAKE stream, seeded with that
        // direction's IV.
        let masking = options & OPTION_CHUNK_MASKING != 0;
        let padding = options & OPTION_GLOBAL_PADDING != 0;
        Self {
            inner,
            send: FrameCipher::new(cipher, &data_key, &data_iv),
            recv: FrameCipher::new(cipher, &response_key, &response_iv),
            read_stage: ReadStage::ResponseLength,
            read_buf: ReadBuffer::with_capacity(DEFAULT_READ_CAPACITY),
            plain: PlainWindow::default(),
            write_buf: WriteBuffer::default(),
            shutdown_sent: false,
            response_key: Some(response_key),
            response_iv: Some(response_iv),
            response_auth,
            send_sizes: masking.then(|| ShakeSizeParser::new(&data_iv, padding)),
            recv_sizes: masking.then(|| ShakeSizeParser::new(&response_iv, padding)),
            recv_padding: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new_server(
        inner: S,
        cipher: Cipher,
        data_key: [u8; 16],
        data_iv: [u8; 16],
        response_key: [u8; 16],
        response_iv: [u8; 16],
        response_prefix: Vec<u8>,
        options: u8,
    ) -> Self {
        // The server mirrors whatever the client asked for: the options live
        // in the request header and are not the server's to choose.
        let masking = options & OPTION_CHUNK_MASKING != 0;
        let padding = options & OPTION_GLOBAL_PADDING != 0;
        let mut write_buf = WriteBuffer::default();
        write_buf.buf_mut().extend_from_slice(&response_prefix);
        Self {
            inner,
            send: FrameCipher::new(cipher, &response_key, &response_iv),
            recv: FrameCipher::new(cipher, &data_key, &data_iv),
            read_stage: ReadStage::DataLength,
            read_buf: ReadBuffer::with_capacity(DEFAULT_READ_CAPACITY),
            plain: PlainWindow::default(),
            write_buf,
            shutdown_sent: false,
            response_key: None,
            response_iv: None,
            response_auth: 0,
            send_sizes: masking.then(|| ShakeSizeParser::new(&response_iv, padding)),
            recv_sizes: masking.then(|| ShakeSizeParser::new(&data_iv, padding)),
            recv_padding: 0,
        }
    }

    /// Append one complete data frame carrying `plaintext` (empty for the
    /// end-of-stream marker) to the write buffer.
    fn frame_into(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let out = self.write_buf.buf_mut();
        let at = out.len();
        out.extend_from_slice(&[0, 0]);
        if let Err(error) = self.send.seal_into(plaintext, out) {
            out.truncate(at);
            return Err(error);
        }
        let encrypted = out.len() - at - 2;
        let Some(sizes) = self.send_sizes.as_mut() else {
            if encrypted > MAX_FRAME {
                out.truncate(at);
                return Err(invalid("VMess frame exceeds the u16 length field"));
            }
            out[at..at + 2].copy_from_slice(&(encrypted as u16).to_be_bytes());
            return Ok(());
        };

        // The declared length covers the ciphertext *and* the padding; the
        // padding itself goes out in clear after the ciphertext.
        let padding = sizes.next_padding() as usize;
        let total = encrypted + padding;
        if total > MAX_FRAME {
            out.truncate(at);
            return Err(invalid("VMess frame exceeds the u16 length field"));
        }
        let masked = sizes.mask(total as u16);
        out[at..at + 2].copy_from_slice(&masked.to_be_bytes());
        if padding > 0 {
            let noise_at = out.len();
            out.resize(noise_at + padding, 0);
            rand::thread_rng().fill_bytes(&mut out[noise_at..]);
        }
        Ok(())
    }

    fn consume_response_length(&mut self) -> io::Result<()> {
        let key = self
            .response_key
            .ok_or_else(|| invalid("VMess response keys are missing"))?;
        let iv = self
            .response_iv
            .ok_or_else(|| invalid("VMess response IV is missing"))?;
        let len_key: [u8; 16] = kdf(&key, &[b"AEAD Resp Header Len Key"])[..16]
            .try_into()
            .unwrap();
        let len_nonce: [u8; 12] = kdf(&iv, &[b"AEAD Resp Header Len IV"])[..12]
            .try_into()
            .unwrap();
        let clear = open_header(
            &len_key,
            &len_nonce,
            &self.read_buf.data()[..2 + TAG_LEN],
            &[],
        )?;
        self.read_buf.consume(2 + TAG_LEN);
        if clear.len() != 2 {
            return Err(invalid("VMess response length is malformed"));
        }
        let len = u16::from_be_bytes([clear[0], clear[1]]) as usize;
        if len > 4096 {
            return Err(invalid("VMess response header is too large"));
        }
        self.read_stage = ReadStage::ResponseBody(len + TAG_LEN);
        Ok(())
    }

    fn consume_response_body(&mut self, len: usize) -> io::Result<()> {
        let key = self
            .response_key
            .ok_or_else(|| invalid("VMess response keys are missing"))?;
        let iv = self
            .response_iv
            .ok_or_else(|| invalid("VMess response IV is missing"))?;
        let body_key: [u8; 16] = kdf(&key, &[b"AEAD Resp Header Key"])[..16]
            .try_into()
            .unwrap();
        let body_nonce: [u8; 12] = kdf(&iv, &[b"AEAD Resp Header IV"])[..12]
            .try_into()
            .unwrap();
        let clear = open_header(&body_key, &body_nonce, &self.read_buf.data()[..len], &[])?;
        self.read_buf.consume(len);
        if clear.len() != 4 {
            return Err(invalid("VMess response header is malformed"));
        }
        // Xray rejects a response whose first byte is not the random value it
        // put in the request; so must we, or the check it provides is lost.
        if clear[0] != self.response_auth {
            return Err(invalid("VMess response header does not match the request"));
        }
        self.response_key = None;
        self.response_iv = None;
        self.read_stage = ReadStage::DataLength;
        Ok(())
    }
}

/// VMess request options that change the *data* framing.
///
/// These are not cosmetic. When a peer sets them, every chunk length on the
/// wire is XOR-masked with a SHAKE128 stream and each chunk carries trailing
/// cleartext padding whose length comes from the same stream. A reader that
/// ignores them does not fail — it silently misreads the first length and then
/// waits forever for bytes that will never come, which is exactly how this was
/// found. Xray's client sets both by default.
pub const OPTION_CHUNK_STREAM: u8 = 0x01;
pub const OPTION_CHUNK_MASKING: u8 = 0x04;
pub const OPTION_GLOBAL_PADDING: u8 = 0x08;

/// The SHAKE128 stream that drives chunk-length masking and global padding.
///
/// Both draws come from one stream, and the *order* is part of the protocol:
/// the padding length is drawn before the length mask for every chunk. Drawing
/// them in the other order desynchronises the stream permanently.
#[derive(Clone)]
struct ShakeSizeParser {
    shake: sha3::Shake128Reader,
    padding: bool,
}

impl ShakeSizeParser {
    fn new(nonce: &[u8], padding: bool) -> Self {
        use sha3::digest::{ExtendableOutput, Update};
        let mut shake = sha3::Shake128::default();
        shake.update(nonce);
        Self {
            shake: shake.finalize_xof(),
            padding,
        }
    }

    fn next(&mut self) -> u16 {
        use sha3::digest::XofReader;
        let mut buffer = [0u8; 2];
        self.shake.read(&mut buffer);
        u16::from_be_bytes(buffer)
    }

    /// Padding first, then the mask — the order Xray's reader and writer both
    /// use.
    fn next_padding(&mut self) -> u16 {
        if self.padding {
            self.next() % 64
        } else {
            0
        }
    }

    fn mask(&mut self, size: u16) -> u16 {
        self.next() ^ size
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut node = VmKdfNode::base(b"VMess AEAD KDF");
    for layer in path {
        node = VmKdfNode::wrap(node, layer);
    }
    node.write(key);
    node.sum()
}

/// The Go VMess KDF builds an HMAC whose inner and outer hash constructors
/// intentionally alias the previous HMAC object. This small state machine is
/// the direct equivalent: `sum` resets the previous layer, writes the outer
/// pad and the inner digest, then sums it again.
enum VmKdfNode {
    Base(Box<VmKdfBase>),
    Wrap {
        previous: Box<VmKdfNode>,
        ipad: [u8; 64],
        opad: [u8; 64],
    },
}

struct VmKdfBase {
    inner: Sha256,
    outer: Sha256,
    initial_inner: Sha256,
    initial_outer: Sha256,
}

impl VmKdfNode {
    fn base(key: &[u8]) -> Self {
        let (ipad, opad) = hmac_pads(key);
        let mut inner = Sha256::new();
        let mut outer = Sha256::new();
        inner.update(ipad);
        outer.update(opad);
        Self::Base(Box::new(VmKdfBase {
            initial_inner: inner.clone(),
            initial_outer: outer.clone(),
            inner,
            outer,
        }))
    }

    fn wrap(previous: Self, key: &[u8]) -> Self {
        let (ipad, opad) = hmac_pads(key);
        let mut node = Self::Wrap {
            previous: Box::new(previous),
            ipad,
            opad,
        };
        if let Self::Wrap { previous, ipad, .. } = &mut node {
            previous.write(ipad);
        }
        node
    }

    fn write(&mut self, data: &[u8]) {
        match self {
            Self::Base(base) => base.inner.update(data),
            Self::Wrap { previous, .. } => previous.write(data),
        }
    }

    fn reset(&mut self) {
        match self {
            Self::Base(base) => {
                base.inner = base.initial_inner.clone();
                base.outer = base.initial_outer.clone();
            }
            Self::Wrap { previous, ipad, .. } => {
                previous.reset();
                previous.write(ipad);
            }
        }
    }

    fn sum(&mut self) -> [u8; 32] {
        match self {
            Self::Base(base) => {
                let digest = base.inner.clone().finalize();
                let mut result = base.outer.clone();
                result.update(digest);
                result.finalize().into()
            }
            Self::Wrap { previous, opad, .. } => {
                let inner_digest = previous.sum();
                previous.reset();
                previous.write(opad);
                previous.write(&inner_digest);
                previous.sum()
            }
        }
    }
}

fn hmac_pads(key: &[u8]) -> ([u8; 64], [u8; 64]) {
    let mut normalized = [0u8; 64];
    if key.len() > normalized.len() {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for index in 0..64 {
        ipad[index] ^= normalized[index];
        opad[index] ^= normalized[index];
    }
    (ipad, opad)
}

fn instruction_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut input = Vec::with_capacity(uuid.len() + MAGIC_AUTH_ID.len());
    input.extend_from_slice(uuid);
    input.extend_from_slice(MAGIC_AUTH_ID);
    Md5::digest(input).into()
}

fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first: [u8; 16] = Md5::digest(key).into();
    let second: [u8; 16] = Md5::digest(first).into();
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

fn aes_ecb(key: &[u8; 16], block: &mut [u8; 16], encrypt: bool) -> io::Result<()> {
    let cipher = Aes128::new_from_slice(key).map_err(|_| invalid("bad VMess auth key"))?;
    let block = GenericArray::from_mut_slice(block);
    if encrypt {
        cipher.encrypt_block(block);
    } else {
        cipher.decrypt_block(block);
    }
    Ok(())
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in data {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

fn seal_header(
    key: &[u8; 16],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| invalid("bad VMess header key"))?;
    let mut body = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, &mut body)
        .map_err(|_| invalid("VMess header encryption failed"))?;
    body.extend_from_slice(&tag);
    Ok(body)
}

fn open_header(
    key: &[u8; 16],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    if ciphertext.len() < TAG_LEN {
        return Err(invalid("VMess header AEAD block is truncated"));
    }
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| invalid("bad VMess header key"))?;
    let split = ciphertext.len() - TAG_LEN;
    let mut body = ciphertext[..split].to_vec();
    cipher
        .decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(nonce),
            aad,
            &mut body,
            (&ciphertext[split..]).into(),
        )
        .map_err(|_| invalid("VMess header authentication failed"))?;
    Ok(body)
}

fn response_material(data_iv: &[u8; 16], data_key: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let response_iv: [u8; 16] = Sha256::digest(data_iv).as_slice()[..16].try_into().unwrap();
    let response_key: [u8; 16] = Sha256::digest(data_key).as_slice()[..16]
        .try_into()
        .unwrap();
    (response_key, response_iv)
}

fn response_prefix(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    auth: u8,
) -> io::Result<Vec<u8>> {
    let len_key: [u8; 16] = kdf(response_key, &[b"AEAD Resp Header Len Key"])[..16]
        .try_into()
        .unwrap();
    let len_nonce: [u8; 12] = kdf(response_iv, &[b"AEAD Resp Header Len IV"])[..12]
        .try_into()
        .unwrap();
    let mut out = seal_header(&len_key, &len_nonce, &[0, 4], &[])?;
    let body_key: [u8; 16] = kdf(response_key, &[b"AEAD Resp Header Key"])[..16]
        .try_into()
        .unwrap();
    let body_nonce: [u8; 12] = kdf(response_iv, &[b"AEAD Resp Header IV"])[..12]
        .try_into()
        .unwrap();
    out.extend_from_slice(&seal_header(&body_key, &body_nonce, &[auth, 0, 0, 0], &[])?);
    Ok(out)
}

fn make_auth_id(uuid: &[u8; 16]) -> io::Result<[u8; 16]> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before UNIX epoch"))?
        .as_secs();
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&now.saturating_sub(60).to_be_bytes());
    rand::thread_rng().fill_bytes(&mut plain[8..12]);
    let checksum = crc32(&plain[..12]).to_be_bytes();
    plain[12..].copy_from_slice(&checksum);
    let key: [u8; 16] = kdf(&instruction_key(uuid), &[b"AES Auth ID Encryption"])[..16]
        .try_into()
        .unwrap();
    aes_ecb(&key, &mut plain, true)?;
    Ok(plain)
}

fn valid_auth_id(uuid: &[u8; 16], auth_id: &[u8; 16]) -> io::Result<bool> {
    let key: [u8; 16] = kdf(&instruction_key(uuid), &[b"AES Auth ID Encryption"])[..16]
        .try_into()
        .unwrap();
    let mut plain = *auth_id;
    aes_ecb(&key, &mut plain, false)?;
    if crc32(&plain[..12]) != u32::from_be_bytes(plain[12..].try_into().unwrap()) {
        return Ok(false);
    }
    let timestamp = u64::from_be_bytes(plain[..8].try_into().unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before UNIX epoch"))?
        .as_secs();
    Ok(timestamp.abs_diff(now) <= 120)
}

fn encode_destination(out: &mut Vec<u8>, destination: &Destination) -> io::Result<()> {
    out.extend_from_slice(&destination.port.to_be_bytes());
    match &destination.address {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            if domain.len() > u8::MAX as usize {
                return Err(invalid("VMess destination hostname is too long"));
            }
            out.push(2);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(3);
            out.extend_from_slice(&ip.octets());
        }
    }
    Ok(())
}

fn decode_destination(
    header: &[u8],
    cursor: &mut usize,
    network: Network,
) -> io::Result<Destination> {
    if *cursor + 3 > header.len() {
        return Err(invalid("VMess destination is truncated"));
    }
    let port = u16::from_be_bytes([header[*cursor], header[*cursor + 1]]);
    *cursor += 2;
    let address = match header[*cursor] {
        1 => {
            *cursor += 1;
            if *cursor + 4 > header.len() {
                return Err(invalid("VMess IPv4 destination is truncated"));
            }
            let ip = std::net::Ipv4Addr::new(
                header[*cursor],
                header[*cursor + 1],
                header[*cursor + 2],
                header[*cursor + 3],
            );
            *cursor += 4;
            Address::from(ip)
        }
        2 => {
            *cursor += 1;
            let len = *header
                .get(*cursor)
                .ok_or_else(|| invalid("VMess domain length is missing"))?
                as usize;
            *cursor += 1;
            if *cursor + len > header.len() {
                return Err(invalid("VMess domain destination is truncated"));
            }
            let domain = std::str::from_utf8(&header[*cursor..*cursor + len])
                .map_err(|_| invalid("VMess destination hostname is not UTF-8"))?;
            *cursor += len;
            Address::domain(domain)
        }
        3 => {
            *cursor += 1;
            if *cursor + 16 > header.len() {
                return Err(invalid("VMess IPv6 destination is truncated"));
            }
            let ip = std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&header[*cursor..*cursor + 16]).unwrap(),
            );
            *cursor += 16;
            Address::from(ip)
        }
        _ => return Err(invalid("VMess destination has an unknown address type")),
    };
    Ok(Destination::new(address, port, network))
}

fn request_header(
    uuid: &[u8; 16],
    cipher: Cipher,
    destination: &Destination,
) -> io::Result<RequestMaterial> {
    let auth_id = make_auth_id(uuid)?;
    let mut clear = Vec::with_capacity(320);
    clear.push(1);
    let mut data_iv = [0u8; 16];
    let mut data_key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut data_iv);
    rand::thread_rng().fill_bytes(&mut data_key);
    clear.extend_from_slice(&data_iv);
    clear.extend_from_slice(&data_key);
    let mut response_auth = [0u8; 1];
    rand::thread_rng().fill_bytes(&mut response_auth);
    clear.push(response_auth[0]);
    // The same options Xray's client sets by default. Matching it is not
    // optional politeness: a VMess client that negotiates a different framing
    // than every other VMess client is distinguishable on the wire, and a
    // server that only speaks the simplified framing cannot talk to Xray at
    // all.
    let options = OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING;
    clear.push(options);
    // Xray randomises the request header padding in 0..16; a constant zero is
    // a fingerprint of its own.
    let header_padding = (rand::random::<u8>() % 16) as usize;
    clear.push(((header_padding as u8) << 4) | cipher.actual().wire_code());
    clear.push(0); // reserved
    clear.push(match destination.network {
        Network::Tcp => 1,
        Network::Udp => 2,
    });
    encode_destination(&mut clear, destination)?;
    if header_padding > 0 {
        let mut noise = vec![0u8; header_padding];
        rand::thread_rng().fill_bytes(&mut noise);
        clear.extend_from_slice(&noise);
    }
    let checksum = fnv1a(&clear);
    clear.extend_from_slice(&checksum.to_be_bytes());

    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let header_len_key: [u8; 16] = kdf(
        &instruction_key(uuid),
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    )[..16]
        .try_into()
        .unwrap();
    let header_len_nonce: [u8; 12] = kdf(
        &instruction_key(uuid),
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    )[..12]
        .try_into()
        .unwrap();
    let encrypted_len = seal_header(
        &header_len_key,
        &header_len_nonce,
        &(clear.len() as u16).to_be_bytes(),
        &auth_id,
    )?;
    let header_key: [u8; 16] = kdf(
        &instruction_key(uuid),
        &[b"VMess Header AEAD Key", &auth_id, &nonce],
    )[..16]
        .try_into()
        .unwrap();
    let header_nonce: [u8; 12] = kdf(
        &instruction_key(uuid),
        &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
    )[..12]
        .try_into()
        .unwrap();
    let encrypted_header = seal_header(&header_key, &header_nonce, &clear, &auth_id)?;

    let (response_key, response_iv) = response_material(&data_iv, &data_key);
    let mut request = Vec::with_capacity(AUTH_ID_LEN + 18 + 8 + encrypted_header.len());
    request.extend_from_slice(&auth_id);
    request.extend_from_slice(&encrypted_len);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&encrypted_header);
    Ok((
        request,
        data_key,
        data_iv,
        response_key,
        response_iv,
        response_auth[0],
        options,
    ))
}

/// Write a VMess client request and return the framed stream.
pub async fn client_handshake<S>(
    mut inner: S,
    uuid: [u8; 16],
    cipher: Cipher,
    destination: &Destination,
) -> io::Result<Stream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (request, data_key, data_iv, response_key, response_iv, response_auth, options) =
        request_header(&uuid, cipher, destination)?;
    tokio::io::AsyncWriteExt::write_all(&mut inner, &request).await?;
    tokio::io::AsyncWriteExt::flush(&mut inner).await?;
    Ok(Stream::new_client(
        inner,
        cipher.actual(),
        data_key,
        data_iv,
        response_key,
        response_iv,
        response_auth,
        options,
    ))
}

/// Read and authenticate a VMess request, returning the target and a server
/// stream. The response header is emitted lazily with the first server write.
pub async fn server_handshake<S>(mut inner: S, users: &[User]) -> io::Result<Accepted<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut auth_id = [0u8; AUTH_ID_LEN];
    tokio::io::AsyncReadExt::read_exact(&mut inner, &mut auth_id).await?;
    let user = users
        .iter()
        .find(|user| valid_auth_id(&user.uuid, &auth_id).unwrap_or(false))
        .ok_or_else(|| invalid("VMess authentication id is invalid or expired"))?;
    // Xray keeps every accepted auth ID for its 120-second validity window
    // and rejects repeats; without that, a captured request replays verbatim.
    if !AUTH_IDS.check_and_insert(&auth_id) {
        return Err(invalid("VMess authentication id was replayed"));
    }

    let mut encrypted_len = [0u8; 2 + TAG_LEN];
    tokio::io::AsyncReadExt::read_exact(&mut inner, &mut encrypted_len).await?;
    let mut nonce = [0u8; 8];
    tokio::io::AsyncReadExt::read_exact(&mut inner, &mut nonce).await?;
    let instruction = instruction_key(&user.uuid);
    let len_key: [u8; 16] = kdf(
        &instruction,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    )[..16]
        .try_into()
        .unwrap();
    let len_nonce: [u8; 12] = kdf(
        &instruction,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    )[..12]
        .try_into()
        .unwrap();
    let clear_len = open_header(&len_key, &len_nonce, &encrypted_len, &auth_id)?;
    let header_len = u16::from_be_bytes([clear_len[0], clear_len[1]]) as usize;
    if !(38..=4096).contains(&header_len) {
        return Err(invalid("VMess request header length is outside bounds"));
    }
    let mut encrypted_header = vec![0u8; header_len + TAG_LEN];
    tokio::io::AsyncReadExt::read_exact(&mut inner, &mut encrypted_header).await?;
    let header_key: [u8; 16] = kdf(&instruction, &[b"VMess Header AEAD Key", &auth_id, &nonce])
        [..16]
        .try_into()
        .unwrap();
    let header_nonce: [u8; 12] = kdf(
        &instruction,
        &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
    )[..12]
        .try_into()
        .unwrap();
    let header = open_header(&header_key, &header_nonce, &encrypted_header, &auth_id)?;
    if header.len() < 38 || header[0] != 1 || header[34] & 0x01 == 0 {
        return Err(invalid("VMess request header has an unsupported format"));
    }
    let command = header[37];
    let network = match command {
        1 => Network::Tcp,
        2 => Network::Udp,
        _ => return Err(invalid("VMess request command is unsupported")),
    };
    let options = header[34];
    let cipher = Cipher::from_wire(header[35] & 0x0f)?;
    if !matches!(user.cipher, Cipher::Auto) && user.cipher.actual() != cipher.actual() {
        return Err(invalid(
            "VMess user does not permit the requested data cipher",
        ));
    }
    let mut cursor = 38;
    let destination = decode_destination(&header, &mut cursor, network)?;
    let margin_len = (header[35] >> 4) as usize;
    if cursor + margin_len + 4 > header.len() {
        return Err(invalid("VMess request margin/checksum is truncated"));
    }
    cursor += margin_len;
    let expected = u32::from_be_bytes(header[cursor..cursor + 4].try_into().unwrap());
    if fnv1a(&header[..cursor]) != expected {
        return Err(invalid("VMess request checksum is invalid"));
    }
    let data_iv: [u8; 16] = header[1..17].try_into().unwrap();
    let data_key: [u8; 16] = header[17..33].try_into().unwrap();
    let response_auth = header[33];
    let (response_key, response_iv) = response_material(&data_iv, &data_key);
    let prefix = response_prefix(&response_key, &response_iv, response_auth)?;
    Ok(Accepted {
        destination,
        stream: Stream::new_server(
            inner,
            cipher,
            data_key,
            data_iv,
            response_key,
            response_iv,
            prefix,
            options,
        ),
    })
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream<S> {
    /// Make at least `need` bytes available. `Ready(Ok(false))` means the
    /// caller should return what it already delivered, or a clean EOF.
    fn poll_need(
        &mut self,
        cx: &mut Context<'_>,
        need: usize,
        delivered: bool,
        at_boundary: bool,
    ) -> Poll<io::Result<bool>> {
        if self.read_buf.len() >= need {
            return Poll::Ready(Ok(true));
        }
        match self.read_buf.poll_fill(Pin::new(&mut self.inner), cx, need) {
            Poll::Ready(Ok(true)) => Poll::Ready(Ok(true)),
            Poll::Ready(Ok(false)) => {
                if delivered || (at_boundary && self.read_buf.is_empty()) {
                    Poll::Ready(Ok(false))
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "VMess peer closed mid-frame",
                    )))
                }
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending if delivered => Poll::Ready(Ok(false)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let initial = buf.filled().len();
        loop {
            if this.plain.pos < this.plain.end {
                let window = &this.read_buf.data()[this.plain.pos..this.plain.end];
                let count = window.len().min(buf.remaining());
                buf.put_slice(&window[..count]);
                this.plain.pos += count;
                if this.plain.pos < this.plain.end {
                    return Poll::Ready(Ok(()));
                }
                this.read_buf.consume(this.plain.frame_len);
                this.plain = PlainWindow::default();
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            let delivered = buf.filled().len() > initial;

            let (need, at_boundary) = match this.read_stage {
                ReadStage::ResponseLength => (2 + TAG_LEN, true),
                ReadStage::ResponseBody(len) => (len, false),
                ReadStage::DataLength => (2, true),
                ReadStage::DataBody(len) => (len, false),
                ReadStage::Eof => return Poll::Ready(Ok(())),
            };
            match this.poll_need(cx, need, delivered, at_boundary) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(false)) => {
                    if !delivered {
                        this.read_stage = ReadStage::Eof;
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(true)) => {}
            }

            match this.read_stage {
                ReadStage::ResponseLength => this.consume_response_length()?,
                ReadStage::ResponseBody(len) => this.consume_response_body(len)?,
                ReadStage::DataLength => {
                    let data = this.read_buf.data();
                    let wire = u16::from_be_bytes([data[0], data[1]]);
                    this.read_buf.consume(2);
                    // Padding is drawn before the mask, for every chunk, in
                    // both directions. Getting that order wrong desynchronises
                    // the SHAKE stream and every later length is garbage.
                    let (len, padding) = match this.recv_sizes.as_mut() {
                        None => (wire as usize, 0usize),
                        Some(sizes) => {
                            let padding = sizes.next_padding() as usize;
                            (sizes.mask(wire) as usize, padding)
                        }
                    };
                    this.recv_padding = padding;
                    if len <= padding {
                        // A chunk carrying only padding is the end marker.
                        this.read_stage = ReadStage::Eof;
                    } else if len - padding < this.recv.overhead() {
                        return Poll::Ready(Err(invalid("VMess frame length is invalid")));
                    } else {
                        this.read_stage = ReadStage::DataBody(len);
                    }
                }
                ReadStage::DataBody(len) => {
                    let payload_len = len - this.recv_padding;
                    let plain_len = this
                        .recv
                        .open_in_place(&mut this.read_buf.data_mut()[..payload_len])?;
                    this.read_stage = ReadStage::DataLength;
                    if plain_len == 0 {
                        this.read_buf.consume(len);
                        this.read_stage = ReadStage::Eof;
                    } else {
                        this.plain = PlainWindow {
                            pos: 0,
                            end: plain_len,
                            frame_len: len,
                        };
                    }
                }
                ReadStage::Eof => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.write_buf.is_empty() {
            match this.write_buf.poll_drain(Pin::new(&mut this.inner), cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.shutdown_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "VMess stream was shut down",
            )));
        }
        // Chunks keep Xray's 8 KiB plaintext size; several are framed per
        // call so a large write becomes one transport write, not many.
        let accepted = buf.len().min(MAX_WRITE_BATCH);
        for chunk in buf[..accepted].chunks(MAX_WRITE_PLAINTEXT) {
            this.frame_into(chunk)?;
        }
        if let Poll::Ready(Err(error)) = this.write_buf.poll_drain(Pin::new(&mut this.inner), cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.write_buf.poll_drain(Pin::new(&mut this.inner), cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.shutdown_sent {
            // Append, never replace: buffered data (or the server's pending
            // response header) must go out before the end marker.
            this.frame_into(&[])?;
            this.shutdown_sent = true;
        }
        match this.write_buf.poll_drain(Pin::new(&mut this.inner), cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn uuid() -> [u8; 16] {
        [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ]
    }

    #[tokio::test]
    async fn client_and_server_roundtrip_aead_stream() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let destination = Destination::tcp(Address::domain("example.com"), 443);
        let user = User {
            uuid: uuid(),
            cipher: Cipher::Auto,
        };
        let server = tokio::spawn(async move { server_handshake(server_io, &[user]).await });
        let mut client = client_handshake(client_io, uuid(), Cipher::Aes128Gcm, &destination)
            .await
            .unwrap();
        let accepted = server.await.unwrap().unwrap();
        assert_eq!(accepted.destination, destination);
        let mut server_stream = accepted.stream;

        client.write_all(b"hello from client").await.unwrap();
        client.flush().await.unwrap();
        let mut received = vec![0u8; 17];
        server_stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"hello from client");

        server_stream.write_all(b"hello from server").await.unwrap();
        server_stream.flush().await.unwrap();
        let mut response = vec![0u8; 17];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"hello from server");
    }

    #[tokio::test]
    async fn client_and_server_roundtrip_single_target_udp_command() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let destination = Destination::udp(Address::domain("dns.example"), 53);
        let user = User {
            uuid: uuid(),
            cipher: Cipher::Auto,
        };
        let server = tokio::spawn(async move { server_handshake(server_io, &[user]).await });
        let mut client = client_handshake(client_io, uuid(), Cipher::Aes128Gcm, &destination)
            .await
            .unwrap();
        let accepted = server.await.unwrap().unwrap();
        assert_eq!(accepted.destination, destination);
        let mut server_stream = accepted.stream;

        client.write_all(b"dns-query").await.unwrap();
        client.flush().await.unwrap();
        let mut received = [0u8; 9];
        server_stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"dns-query");

        server_stream.write_all(b"dns-reply").await.unwrap();
        server_stream.flush().await.unwrap();
        let mut response = [0u8; 9];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"dns-reply");
    }

    /// Regression: `poll_shutdown` replaced the pending write buffer with the
    /// end marker, so a server that shut down before its first write threw
    /// away its own response header and the client failed authentication.
    #[tokio::test]
    async fn a_server_that_closes_without_data_still_sends_its_header() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let destination = Destination::tcp(Address::domain("example.com"), 443);
        let user = User {
            uuid: uuid(),
            cipher: Cipher::Auto,
        };
        let server = tokio::spawn(async move {
            let mut stream = server_handshake(server_io, &[user]).await.unwrap().stream;
            stream.shutdown().await.unwrap();
        });
        let mut client =
            client_handshake(client_io, uuid(), Cipher::Chacha20Poly1305, &destination)
                .await
                .unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn bulk_transfer_with_small_reads_and_half_close() {
        for cipher in [Cipher::Aes128Gcm, Cipher::Chacha20Poly1305, Cipher::None] {
            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            let destination = Destination::tcp(Address::domain("example.com"), 443);
            let user = User {
                uuid: uuid(),
                cipher: Cipher::Auto,
            };
            let payload: Vec<u8> = (0..150_000u32).map(|i| (i % 249) as u8).collect();
            let expected = payload.clone();
            let server = tokio::spawn(async move {
                let mut stream = server_handshake(server_io, &[user]).await.unwrap().stream;
                let mut got = Vec::new();
                let mut chunk = [0u8; 777];
                loop {
                    let n = stream.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&chunk[..n]);
                }
                stream.write_all(&got).await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let mut client = client_handshake(client_io, uuid(), cipher, &destination)
                .await
                .unwrap();
            let (mut reader, mut writer) = tokio::io::split(&mut client);
            let send = async {
                writer.write_all(&payload).await.unwrap();
                writer.shutdown().await.unwrap();
            };
            let mut echoed = Vec::new();
            let ((), received) = tokio::join!(send, reader.read_to_end(&mut echoed));
            received.unwrap();
            assert_eq!(echoed, expected);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_replayed_request_is_rejected() {
        let destination = Destination::tcp(Address::domain("example.com"), 443);
        let (request, ..) = request_header(&uuid(), Cipher::Aes128Gcm, &destination).unwrap();
        let user = User {
            uuid: uuid(),
            cipher: Cipher::Auto,
        };
        let (mut first, server_io) = tokio::io::duplex(64 * 1024);
        first.write_all(&request).await.unwrap();
        assert!(server_handshake(server_io, &[user]).await.is_ok());
        let (mut replay, server_io) = tokio::io::duplex(64 * 1024);
        replay.write_all(&request).await.unwrap();
        let error = server_handshake(server_io, &[user]).await.unwrap_err();
        assert!(error.to_string().contains("replayed"));
    }

    #[tokio::test]
    async fn a_response_with_the_wrong_auth_byte_is_rejected() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let destination = Destination::tcp(Address::domain("example.com"), 443);
        let mut client = client_handshake(client_io, uuid(), Cipher::Aes128Gcm, &destination)
            .await
            .unwrap();
        let mut request = vec![0u8; 4096];
        let _ = server_io.read(&mut request).await.unwrap();
        let wrong = client.response_auth.wrapping_add(1);
        let prefix = response_prefix(
            &client.response_key.unwrap(),
            &client.response_iv.unwrap(),
            wrong,
        )
        .unwrap();
        server_io.write_all(&prefix).await.unwrap();
        let mut buf = [0u8; 8];
        assert!(client.read(&mut buf).await.is_err());
    }

    #[test]
    fn kdf_and_auth_checksum_are_deterministic() {
        let key = [7u8; 16];
        assert_eq!(kdf(&key, &[b"one"]), kdf(&key, &[b"one"]));
        assert_ne!(kdf(&key, &[b"one"]), kdf(&key, &[b"two"]));
        assert_ne!(crc32(b"hello"), 0);
    }
}
