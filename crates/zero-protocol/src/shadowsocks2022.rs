//! Shadowsocks 2022 TCP (`2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`).
//!
//! SIP022 wire format, single-PSK (no EIH multi-user). The session subkey is
//! `BLAKE3::derive_key("shadowsocks 2022 session subkey", PSK || salt)` and
//! every AEAD chunk uses a 12-byte little-endian counter nonce starting at 0,
//! matching the reference implementations.
//!
//! Request (client -> server): `salt || AEAD(fixed) || AEAD(variable) || data*`
//!   fixed    = type(0) || timestamp(8) || variable_len(2)
//!   variable = address || padding_len(2) || padding
//! Response (server -> client): `salt || AEAD(fixed) || data*`
//!   fixed    = type(1) || timestamp(8) || request_salt(salt_len) || first_len(2)
//! Data chunks are the standard `AEAD(len(2)) || AEAD(payload)` pair.
//!
//! Interop note: verified end-to-end against this crate's own client/server in
//! the module tests. It has not been tested against an external Xray/sing-box
//! peer in this environment.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use zero_core::{Address, Destination, Network};

use crate::io_util::{ReadBuffer, ReplayFilter, WriteBuffer, DEFAULT_READ_CAPACITY};

const TAG_LEN: usize = 16;
const LENGTH_LEN: usize = 2;
const MAX_CHUNK: usize = 0xffff;
const HEADER_TYPE_CLIENT: u8 = 0;
const HEADER_TYPE_SERVER: u8 = 1;
const TIMESTAMP_SKEW: u64 = 30;
/// SIP022's upper bound on request-header padding.
const MAX_PADDING: usize = 900;
/// Salts per replay-pool generation (two generations are kept). Bounds the
/// pool at a few MiB no matter how many handshakes arrive in a window.
const SALT_POOL_GENERATION_LIMIT: usize = 64 * 1024;
const SESSION_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    /// `2022-blake3-chacha20-poly1305`: same framing and key derivation, a
    /// 32-byte key, and ChaCha20-Poly1305 as the chunk AEAD.
    Chacha20Poly1305,
}

impl Method {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "2022-blake3-aes-128-gcm" => Self::Aes128Gcm,
            "2022-blake3-aes-256-gcm" => Self::Aes256Gcm,
            "2022-blake3-chacha20-poly1305" => Self::Chacha20Poly1305,
            _ => return None,
        })
    }

    /// Both the PSK length and the salt length equal the key length.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 => 32,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidFrame(&'static str),
    Crypto,
    UnsupportedDestination,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::InvalidFrame(reason) => write!(f, "invalid Shadowsocks 2022 frame: {reason}"),
            Self::Crypto => write!(f, "Shadowsocks 2022 crypto failed"),
            Self::UnsupportedDestination => write!(f, "unsupported Shadowsocks 2022 destination"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Io(inner) => inner,
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}

pub fn decode_user_key(password: &str, method: Method) -> Result<Vec<u8>, Error> {
    let raw = password.trim();
    let bytes = base64_decode(raw).unwrap_or_else(|_| raw.as_bytes().to_vec());
    if bytes.len() != method.key_len() {
        return Err(Error::Crypto);
    }
    Ok(bytes)
}

fn base64_decode(value: &str) -> Result<Vec<u8>, ()> {
    const TABLE: &[u8; 128] = &{
        let mut table = [0xffu8; 128];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < alphabet.len() {
            table[alphabet[i] as usize] = i as u8;
            i += 1;
        }
        table
    };
    let value = value.trim_end_matches('=');
    if value.is_empty() || value.bytes().any(|b| b > 127 || TABLE[b as usize] == 0xff) {
        return Err(());
    }
    let mut out = Vec::with_capacity(value.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for byte in value.bytes() {
        buf = (buf << 6) | TABLE[byte as usize] as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

fn session_subkey(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let mut hasher = blake3::Hasher::new_derive_key(SESSION_SUBKEY_CONTEXT);
    hasher.update(&material);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; key_len];
    reader.fill(&mut out);
    out
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn encode_address(destination: &Destination) -> Result<Vec<u8>, Error> {
    if destination.network != Network::Tcp {
        return Err(Error::UnsupportedDestination);
    }
    let mut out = Vec::new();
    match &destination.address {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            if domain.is_empty() || domain.len() > 255 {
                return Err(Error::UnsupportedDestination);
            }
            out.push(3);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(out)
}

fn decode_address(buf: &[u8]) -> Result<(Destination, usize), Error> {
    if buf.is_empty() {
        return Err(Error::InvalidFrame("empty address"));
    }
    let (address, used) = match buf[0] {
        1 if buf.len() >= 1 + 4 + 2 => {
            let ip = std::net::Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            (Address::Ip(ip.into()), 5)
        }
        3 if buf.len() >= 2 => {
            let len = buf[1] as usize;
            if len == 0 {
                return Err(Error::InvalidFrame("empty domain"));
            }
            if buf.len() < 2 + len + 2 {
                return Err(Error::InvalidFrame("short domain"));
            }
            let domain = std::str::from_utf8(&buf[2..2 + len])
                .map_err(|_| Error::InvalidFrame("domain is not utf-8"))?
                .into();
            (Address::Domain(domain), 2 + len)
        }
        4 if buf.len() >= 1 + 16 + 2 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            (Address::Ip(std::net::Ipv6Addr::from(octets).into()), 17)
        }
        _ => return Err(Error::InvalidFrame("bad address")),
    };
    let port = u16::from_be_bytes([buf[used], buf[used + 1]]);
    Ok((
        Destination {
            network: Network::Tcp,
            address,
            port,
        },
        used + 2,
    ))
}

/// A counter-nonce AEAD chunk cipher. The nonce is a 12-byte little-endian
/// counter that increments once per sealed or opened chunk. Both variants are
/// boxed: the AES key schedules are ~1 KiB and are built once per direction.
enum ChunkCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    Chacha(Box<chacha20poly1305::ChaCha20Poly1305>),
}

struct ChunkState {
    cipher: ChunkCipher,
    counter: u64,
}

impl ChunkState {
    fn new(method: Method, subkey: &[u8]) -> Self {
        let cipher = match method {
            Method::Aes128Gcm => ChunkCipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(subkey).expect("subkey length checked"),
            )),
            Method::Aes256Gcm => ChunkCipher::Aes256(Box::new(
                Aes256Gcm::new_from_slice(subkey).expect("subkey length checked"),
            )),
            Method::Chacha20Poly1305 => ChunkCipher::Chacha(Box::new(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(subkey)
                    .expect("subkey length checked"),
            )),
        };
        Self { cipher, counter: 0 }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        nonce
    }

    /// Append `plaintext` to `out` as `ciphertext || tag`, encrypting in place.
    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let nonce = self.nonce();
        let nonce = Nonce::from_slice(&nonce);
        let start = out.len();
        out.extend_from_slice(plaintext);
        let body = &mut out[start..];
        let tag = match &self.cipher {
            ChunkCipher::Aes128(c) => c.encrypt_in_place_detached(nonce, &[], body),
            ChunkCipher::Aes256(c) => c.encrypt_in_place_detached(nonce, &[], body),
            ChunkCipher::Chacha(c) => c.encrypt_in_place_detached(nonce, &[], body),
        }
        .map_err(|_| Error::Crypto)?;
        out.extend_from_slice(tag.as_slice());
        self.counter = self.counter.wrapping_add(1);
        Ok(())
    }

    /// Decrypt a `ciphertext || tag` chunk in place; the plaintext is
    /// `chunk[..chunk.len() - TAG_LEN]` afterwards.
    fn open_in_place(&mut self, chunk: &mut [u8]) -> Result<(), Error> {
        if chunk.len() < TAG_LEN {
            return Err(Error::InvalidFrame("chunk shorter than tag"));
        }
        let nonce = self.nonce();
        let nonce = Nonce::from_slice(&nonce);
        let split = chunk.len() - TAG_LEN;
        let (body, tag) = chunk.split_at_mut(split);
        let tag = aes_gcm::Tag::from_slice(tag);
        match &self.cipher {
            ChunkCipher::Aes128(c) => c.decrypt_in_place_detached(nonce, &[], body, tag),
            ChunkCipher::Aes256(c) => c.decrypt_in_place_detached(nonce, &[], body, tag),
            ChunkCipher::Chacha(c) => c.decrypt_in_place_detached(nonce, &[], body, tag),
        }
        .map_err(|_| Error::Crypto)?;
        self.counter = self.counter.wrapping_add(1);
        Ok(())
    }
}

/// Salts seen by this process's servers. SIP022 requires a server to keep
/// every salt for at least 60 seconds (twice the timestamp tolerance) and
/// reject repeats; without it a captured request can be replayed verbatim to
/// make the server re-open the connection, which active probers use.
static SERVER_SALTS: ReplayFilter<32> = ReplayFilter::new(
    Duration::from_secs(2 * TIMESTAMP_SKEW),
    SALT_POOL_GENERATION_LIMIT,
);

fn salt_key(salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..salt.len()].copy_from_slice(salt);
    key
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadStage {
    /// Client only: read the server salt before anything else.
    ServerSalt,
    /// Client only: read the server's fixed response header.
    FixedHeader,
    /// Read a length chunk (2 + tag).
    Length,
    /// Read a data chunk of the given plaintext length.
    Data(usize),
}

/// Plaintext of the chunk at the head of the read buffer not yet delivered.
#[derive(Debug, Clone, Copy, Default)]
struct PlainWindow {
    pos: usize,
    end: usize,
    chunk_len: usize,
}

/// A Shadowsocks 2022 stream.
///
/// Writes are buffered: `poll_write` seals the caller's bytes, starts sending
/// them and reports them accepted; `poll_flush`/`poll_shutdown` drain the rest.
pub struct Stream<S> {
    inner: S,
    method: Method,
    role: Role,
    psk: Vec<u8>,
    /// The client's request salt. On the client it is our own salt; on the
    /// server it is the salt we read from the request and must echo back.
    request_salt: Vec<u8>,
    send: Option<ChunkState>,
    recv: Option<ChunkState>,
    write_header_done: bool,
    read_stage: ReadStage,
    read_buf: ReadBuffer,
    plain: PlainWindow,
    /// Server only: payload that arrived inside the request's variable header.
    initial: Vec<u8>,
    initial_pos: usize,
    write_buf: WriteBuffer,
}

impl<S> Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Open a client session: derive the request subkey, then write
    /// `salt || AEAD(fixed) || AEAD(variable)` carrying the destination.
    pub async fn client(
        mut inner: S,
        method: Method,
        password: &str,
        destination: &Destination,
    ) -> Result<Self, Error> {
        let psk = decode_user_key(password, method)?;
        let salt = random_salt(method);
        let subkey = session_subkey(&psk, &salt, method.key_len());
        let mut send = ChunkState::new(method, &subkey);

        // SIP022: a request header that carries no payload MUST carry random
        // padding, or its length alone identifies the destination length.
        let padding = rand::thread_rng().gen_range(1..=MAX_PADDING);
        let mut variable = encode_address(destination)?;
        variable.extend_from_slice(&(padding as u16).to_be_bytes());
        let padding_at = variable.len();
        variable.resize(padding_at + padding, 0);
        rand::thread_rng().fill_bytes(&mut variable[padding_at..]);

        let mut fixed = Vec::with_capacity(1 + 8 + 2);
        fixed.push(HEADER_TYPE_CLIENT);
        fixed.extend_from_slice(&now().to_be_bytes());
        fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());

        let mut out = Vec::with_capacity(salt.len() + fixed.len() + variable.len() + 2 * TAG_LEN);
        out.extend_from_slice(&salt);
        send.seal_into(&fixed, &mut out)?;
        send.seal_into(&variable, &mut out)?;
        inner.write_all(&out).await?;
        inner.flush().await?;

        Ok(Self::assemble(
            inner,
            method,
            Role::Client,
            psk,
            salt,
            Some(send),
            None,
            ReadStage::ServerSalt,
            Vec::new(),
        ))
    }

    /// Accept a server session: read `salt || AEAD(fixed) || AEAD(variable)`,
    /// returning the requested destination. The response header is emitted
    /// lazily on the first write so it can fold the first payload length.
    pub async fn server(
        mut inner: S,
        method: Method,
        password: &str,
    ) -> Result<(Self, Destination), Error> {
        let psk = decode_user_key(password, method)?;
        let salt_len = method.key_len();

        let mut salt = vec![0u8; salt_len];
        inner.read_exact(&mut salt).await?;
        let subkey = session_subkey(&psk, &salt, salt_len);
        let mut recv = ChunkState::new(method, &subkey);

        let fixed_len = 1 + 8 + LENGTH_LEN + TAG_LEN;
        let mut fixed_chunk = [0u8; 1 + 8 + LENGTH_LEN + TAG_LEN];
        inner.read_exact(&mut fixed_chunk[..fixed_len]).await?;
        recv.open_in_place(&mut fixed_chunk)?;
        let fixed = &fixed_chunk[..fixed_len - TAG_LEN];
        if fixed[0] != HEADER_TYPE_CLIENT {
            return Err(Error::InvalidFrame("not a client header"));
        }
        let stamp = u64::from_be_bytes(fixed[1..9].try_into().expect("eight bytes"));
        if now().abs_diff(stamp) > TIMESTAMP_SKEW {
            return Err(Error::InvalidFrame("timestamp skew"));
        }
        // Only an authenticated, fresh header may enter the salt pool, so a
        // prober cannot fill it with garbage salts.
        if !SERVER_SALTS.check_and_insert(&salt_key(&salt)) {
            return Err(Error::InvalidFrame("replayed salt"));
        }
        let variable_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        if variable_len == 0 {
            return Err(Error::InvalidFrame("bad variable header length"));
        }

        let mut variable = vec![0u8; variable_len + TAG_LEN];
        inner.read_exact(&mut variable).await?;
        recv.open_in_place(&mut variable)?;
        variable.truncate(variable_len);
        let (destination, used) = decode_address(&variable)?;
        if variable.len() < used + LENGTH_LEN {
            return Err(Error::InvalidFrame("missing padding length"));
        }
        let padding = u16::from_be_bytes([variable[used], variable[used + 1]]) as usize;
        let payload_at = used + LENGTH_LEN + padding;
        if payload_at > variable.len() {
            return Err(Error::InvalidFrame("padding length exceeds the header"));
        }
        if padding == 0 && payload_at == variable.len() {
            return Err(Error::InvalidFrame(
                "header has neither padding nor payload",
            ));
        }
        // Whatever follows the padding is the client's initial payload, which
        // SIP022 clients (shadowsocks-rust, sing-box, Xray) send with the header.
        variable.drain(..payload_at);

        let stream = Self::assemble(
            inner,
            method,
            Role::Server,
            psk,
            salt,
            None,
            Some(recv),
            ReadStage::Length,
            variable,
        );
        Ok((stream, destination))
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        inner: S,
        method: Method,
        role: Role,
        psk: Vec<u8>,
        request_salt: Vec<u8>,
        send: Option<ChunkState>,
        recv: Option<ChunkState>,
        read_stage: ReadStage,
        initial: Vec<u8>,
    ) -> Self {
        Self {
            inner,
            method,
            role,
            psk,
            request_salt,
            write_header_done: role == Role::Client,
            send,
            recv,
            read_stage,
            read_buf: ReadBuffer::with_capacity(DEFAULT_READ_CAPACITY),
            plain: PlainWindow::default(),
            initial,
            initial_pos: 0,
            write_buf: WriteBuffer::default(),
        }
    }
}

fn random_salt(method: Method) -> Vec<u8> {
    let mut salt = vec![0u8; method.key_len()];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

impl<S> Stream<S> {
    /// Seal up to one maximum chunk of `src` into the write buffer, emitting
    /// the lazy server response header first when it is still owed.
    fn seal_batch(&mut self, src: &[u8]) -> Result<usize, Error> {
        let n = src.len().min(MAX_CHUNK);
        let out = self.write_buf.buf_mut();
        if !self.write_header_done && self.role == Role::Server {
            // The server emits its response header lazily, folding the first
            // payload length into the fixed header.
            let salt = random_salt(self.method);
            let subkey = session_subkey(&self.psk, &salt, self.method.key_len());
            let mut send = ChunkState::new(self.method, &subkey);
            let mut fixed = Vec::with_capacity(1 + 8 + self.request_salt.len() + 2);
            fixed.push(HEADER_TYPE_SERVER);
            fixed.extend_from_slice(&now().to_be_bytes());
            fixed.extend_from_slice(&self.request_salt);
            fixed.extend_from_slice(&(n as u16).to_be_bytes());
            out.extend_from_slice(&salt);
            send.seal_into(&fixed, out)?;
            send.seal_into(&src[..n], out)?;
            self.send = Some(send);
            self.write_header_done = true;
            return Ok(n);
        }
        let send = self
            .send
            .as_mut()
            .ok_or(Error::InvalidFrame("send cipher is missing"))?;
        send.seal_into(&(n as u16).to_be_bytes(), out)?;
        send.seal_into(&src[..n], out)?;
        Ok(n)
    }
}

impl<S: AsyncRead + Unpin> Stream<S> {
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
                        "Shadowsocks 2022 peer closed mid-frame",
                    )))
                }
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending if delivered => Poll::Ready(Ok(false)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Advance the read state machine by one step.
    fn step(&mut self) -> Result<(), Error> {
        match self.read_stage {
            ReadStage::ServerSalt => {
                let salt_len = self.method.key_len();
                let salt = self.read_buf.data()[..salt_len].to_vec();
                let subkey = session_subkey(&self.psk, &salt, salt_len);
                self.recv = Some(ChunkState::new(self.method, &subkey));
                self.read_buf.consume(salt_len);
                self.read_stage = ReadStage::FixedHeader;
            }
            ReadStage::FixedHeader => {
                let salt_len = self.method.key_len();
                let fixed_len = 1 + 8 + salt_len + LENGTH_LEN + TAG_LEN;
                let recv = self.recv.as_mut().ok_or(Error::Crypto)?;
                let fixed = &mut self.read_buf.data_mut()[..fixed_len];
                recv.open_in_place(fixed)?;
                if fixed[0] != HEADER_TYPE_SERVER {
                    return Err(Error::InvalidFrame("not a server header"));
                }
                let stamp = u64::from_be_bytes(fixed[1..9].try_into().expect("eight bytes"));
                if now().abs_diff(stamp) > TIMESTAMP_SKEW {
                    return Err(Error::InvalidFrame("timestamp skew"));
                }
                if fixed[9..9 + salt_len] != *self.request_salt.as_slice() {
                    return Err(Error::InvalidFrame("response request-salt mismatch"));
                }
                let length =
                    u16::from_be_bytes([fixed[9 + salt_len], fixed[10 + salt_len]]) as usize;
                self.read_buf.consume(fixed_len);
                if length == 0 {
                    return Err(Error::InvalidFrame("bad payload length"));
                }
                self.read_stage = ReadStage::Data(length);
            }
            ReadStage::Length => {
                let recv = self.recv.as_mut().ok_or(Error::Crypto)?;
                let chunk = &mut self.read_buf.data_mut()[..LENGTH_LEN + TAG_LEN];
                recv.open_in_place(chunk)?;
                let length = u16::from_be_bytes([chunk[0], chunk[1]]) as usize;
                self.read_buf.consume(LENGTH_LEN + TAG_LEN);
                if length == 0 {
                    return Err(Error::InvalidFrame("bad chunk length"));
                }
                self.read_stage = ReadStage::Data(length);
            }
            ReadStage::Data(length) => {
                let recv = self.recv.as_mut().ok_or(Error::Crypto)?;
                recv.open_in_place(&mut self.read_buf.data_mut()[..length + TAG_LEN])?;
                self.plain = PlainWindow {
                    pos: 0,
                    end: length,
                    chunk_len: length + TAG_LEN,
                };
                self.read_stage = ReadStage::Length;
            }
        }
        Ok(())
    }

    fn stage_need(&self) -> (usize, bool) {
        let salt_len = self.method.key_len();
        match self.read_stage {
            ReadStage::ServerSalt => (salt_len, true),
            ReadStage::FixedHeader => (1 + 8 + salt_len + LENGTH_LEN + TAG_LEN, false),
            ReadStage::Length => (LENGTH_LEN + TAG_LEN, true),
            ReadStage::Data(length) => (length + TAG_LEN, false),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.initial_pos < this.initial.len() {
            let remaining = &this.initial[this.initial_pos..];
            let n = remaining.len().min(dst.remaining());
            dst.put_slice(&remaining[..n]);
            this.initial_pos += n;
            if this.initial_pos == this.initial.len() {
                this.initial = Vec::new();
                this.initial_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        let initial = dst.filled().len();
        loop {
            if this.plain.pos < this.plain.end {
                let window = &this.read_buf.data()[this.plain.pos..this.plain.end];
                let n = window.len().min(dst.remaining());
                dst.put_slice(&window[..n]);
                this.plain.pos += n;
                if this.plain.pos < this.plain.end {
                    return Poll::Ready(Ok(()));
                }
                this.read_buf.consume(this.plain.chunk_len);
                this.plain = PlainWindow::default();
                if dst.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            let delivered = dst.filled().len() > initial;
            let (need, at_boundary) = this.stage_need();
            match this.poll_need(cx, need, delivered, at_boundary) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(true)) => {}
            }
            if let Err(error) = this.step() {
                return Poll::Ready(Err(error.into()));
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.write_buf.is_empty() {
            match this.write_buf.poll_drain(Pin::new(&mut this.inner), cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if src.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let accepted = match this.seal_batch(src) {
            Ok(accepted) => accepted,
            Err(error) => return Poll::Ready(Err(error.into())),
        };
        if let Poll::Ready(Err(error)) = this.write_buf.poll_drain(Pin::new(&mut this.inner), cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.write_buf.poll_drain(Pin::new(&mut this.inner), cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn accepts_base64_and_raw_keys_of_the_right_length() {
        let key = decode_user_key("MDEyMzQ1Njc4OWFiY2RlZg==", Method::Aes128Gcm).unwrap();
        assert_eq!(key.len(), 16);
        assert!(decode_user_key("short", Method::Aes128Gcm).is_err());
    }

    #[test]
    fn address_round_trips() {
        let destination = Destination::tcp(Address::domain("example.com"), 443);
        let encoded = encode_address(&destination).unwrap();
        let (decoded, used) = decode_address(&encoded).unwrap();
        assert_eq!(used, encoded.len());
        assert_eq!(decoded.port, 443);
    }

    #[tokio::test]
    async fn the_chacha20_method_round_trips() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let password = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        let destination = Destination::tcp(Address::domain("example.com"), 443);
        let server = tokio::spawn(async move {
            let (mut stream, _) = Stream::server(server_io, Method::Chacha20Poly1305, password)
                .await
                .unwrap();
            let mut got = vec![0u8; 5];
            stream.read_exact(&mut got).await.unwrap();
            stream.write_all(&got).await.unwrap();
            stream.flush().await.unwrap();
        });
        let mut client =
            Stream::client(client_io, Method::Chacha20Poly1305, password, &destination)
                .await
                .unwrap();
        client.write_all(b"chach").await.unwrap();
        client.flush().await.unwrap();
        let mut got = vec![0u8; 5];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"chach");
        server.await.unwrap();
        assert_eq!(
            Method::parse("2022-blake3-chacha20-poly1305"),
            Some(Method::Chacha20Poly1305)
        );
    }

    #[tokio::test]
    async fn client_and_server_agree_both_directions() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let password = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="; // 32 bytes b64
        let destination = Destination::tcp(Address::domain("example.com"), 443);

        let server = tokio::spawn(async move {
            let (mut stream, dest) = Stream::server(server_io, Method::Aes256Gcm, password)
                .await
                .unwrap();
            assert_eq!(dest.port, 443);
            let mut got = vec![0u8; 5];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hello");
            stream.write_all(b"world!!").await.unwrap();
            stream.flush().await.unwrap();
        });

        let mut client = Stream::client(client_io, Method::Aes256Gcm, password, &destination)
            .await
            .unwrap();
        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();
        let mut got = vec![0u8; 7];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"world!!");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_wrong_password_is_rejected() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let good = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        let bad = "ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY=";
        let destination = Destination::tcp(Address::domain("example.com"), 443);

        let server = tokio::spawn(async move {
            Stream::server(server_io, Method::Aes256Gcm, bad)
                .await
                .map(|_| ())
        });
        let client = Stream::client(client_io, Method::Aes256Gcm, good, &destination).await;
        // The client write succeeds locally; the server must fail to open it.
        drop(client);
        assert!(server.await.unwrap().is_err());
    }

    const PSK: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    /// Build a raw SIP022 request the way external clients do: the initial
    /// payload rides in the variable header after the padding.
    fn raw_request(payload: &[u8], padding: usize) -> Vec<u8> {
        let psk = decode_user_key(PSK, Method::Aes256Gcm).unwrap();
        let salt = random_salt(Method::Aes256Gcm);
        let mut send = ChunkState::new(
            Method::Aes256Gcm,
            &session_subkey(&psk, &salt, Method::Aes256Gcm.key_len()),
        );
        let mut variable =
            encode_address(&Destination::tcp(Address::domain("example.com"), 80)).unwrap();
        variable.extend_from_slice(&(padding as u16).to_be_bytes());
        variable.resize(variable.len() + padding, 0x55);
        variable.extend_from_slice(payload);
        let mut fixed = vec![HEADER_TYPE_CLIENT];
        fixed.extend_from_slice(&now().to_be_bytes());
        fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());
        let mut out = salt;
        send.seal_into(&fixed, &mut out).unwrap();
        send.seal_into(&variable, &mut out).unwrap();
        out
    }

    /// Regression: the server rejected any request whose variable header
    /// carried the initial payload ("padding length mismatch"), which is how
    /// shadowsocks-rust, sing-box and Xray clients send their first bytes.
    #[tokio::test]
    async fn server_delivers_payload_carried_in_the_request_header() {
        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        client_io
            .write_all(&raw_request(b"GET / HTTP/1.1\r\n\r\n", 0))
            .await
            .unwrap();
        let (mut stream, destination) = Stream::server(server_io, Method::Aes256Gcm, PSK)
            .await
            .unwrap();
        assert_eq!(destination.port, 80);
        let mut got = [0u8; 18];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"GET / HTTP/1.1\r\n\r\n");
    }

    /// Regression: there was no salt pool, so a captured request could be
    /// replayed and the server would dial the destination again.
    #[tokio::test]
    async fn a_replayed_request_is_rejected() {
        let request = raw_request(b"", 16);
        let (mut first_io, server_io) = tokio::io::duplex(64 * 1024);
        first_io.write_all(&request).await.unwrap();
        assert!(Stream::server(server_io, Method::Aes256Gcm, PSK)
            .await
            .is_ok());
        let (mut replay_io, server_io) = tokio::io::duplex(64 * 1024);
        replay_io.write_all(&request).await.unwrap();
        let error = Stream::server(server_io, Method::Aes256Gcm, PSK)
            .await
            .err()
            .expect("replay must fail");
        assert!(error.to_string().contains("replayed salt"));
    }

    #[tokio::test]
    async fn half_close_is_a_clean_eof_and_bulk_data_round_trips() {
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let destination = Destination::tcp(Address::domain("example.com"), 443);
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
        let expected = payload.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = Stream::server(server_io, Method::Aes256Gcm, PSK)
                .await
                .unwrap();
            let mut got = Vec::new();
            stream.read_to_end(&mut got).await.unwrap();
            stream.write_all(&got).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut client = Stream::client(client_io, Method::Aes256Gcm, PSK, &destination)
            .await
            .unwrap();
        let (mut reader, mut writer) = tokio::io::split(&mut client);
        let send = async {
            writer.write_all(&payload).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let mut echoed = Vec::new();
        let receive = reader.read_to_end(&mut echoed);
        let ((), received) = tokio::join!(send, receive);
        received.unwrap();
        assert_eq!(echoed, expected);
        server.await.unwrap();
    }
}
