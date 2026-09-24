//! Legacy Shadowsocks AEAD TCP framing.
//!
//! This module implements the RFC 8439-style chunk transport used by the
//! `aes-*-gcm` and `chacha20-ietf-poly1305` Shadowsocks methods. It is a
//! stream wrapper: names remain inside the first encrypted address chunk and
//! are never resolved by this protocol layer.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use rand::RngCore;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use zero_core::{Address, BoxStream, Destination, Network};

use crate::io_util::{ReadBuffer, WriteBuffer, DEFAULT_READ_CAPACITY};

const SALT_LEN: usize = 32;
const TAG_LEN: usize = 16;
const MAX_CHUNK: usize = 0x3fff;
const LENGTH_LEN: usize = 2;
/// Plaintext sealed per `poll_write`: four maximum chunks. Batching turns a
/// large relay write into one transport write instead of one per 16 KiB.
const MAX_WRITE_BATCH: usize = 4 * MAX_CHUNK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Method {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Self::Aes128Gcm,
            "aes-256-gcm" => Self::Aes256Gcm,
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Self::Chacha20Poly1305,
            _ => return None,
        })
    }

    fn key_len(self) -> usize {
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
            Self::InvalidFrame(detail) => f.write_str(detail),
            Self::Crypto => f.write_str("Shadowsocks AEAD authentication failed"),
            Self::UnsupportedDestination => f.write_str("unsupported Shadowsocks destination"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// The per-direction AEAD. The AES variants are boxed: their expanded key
/// schedules are ~1 KiB, and the enum is built once per direction per session.
#[derive(Clone)]
enum SsCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(ChaCha20Poly1305),
}

#[derive(Clone)]
struct CipherState {
    cipher: SsCipher,
    counter: u64,
}

impl CipherState {
    fn new(method: Method, master_key: &[u8], salt: &[u8; SALT_LEN]) -> Self {
        let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
        let mut key = [0u8; 32];
        let key = &mut key[..method.key_len()];
        hk.expand(b"ss-subkey", key)
            .expect("method key length is valid");
        let cipher = match method {
            Method::Aes128Gcm => {
                SsCipher::Aes128(Box::new(Aes128Gcm::new_from_slice(key).expect("valid key")))
            }
            Method::Aes256Gcm => {
                SsCipher::Aes256(Box::new(Aes256Gcm::new_from_slice(key).expect("valid key")))
            }
            Method::Chacha20Poly1305 => {
                SsCipher::ChaCha(ChaCha20Poly1305::new_from_slice(key).expect("valid key"))
            }
        };
        Self { cipher, counter: 0 }
    }

    /// The AEAD nonce: a 12-byte **little-endian** counter starting at zero.
    ///
    /// SIP004 states the byte order, and Xray implements it by starting at
    /// all-`0xFF` and incrementing byte-wise from the low end, which is the
    /// same sequence. Writing the counter big-endian agrees with that only at
    /// zero, so a stream built that way completes its first chunk and then
    /// fails every one after it — which reads like a framing bug rather than
    /// the byte-order bug it is.
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        nonce
    }

    fn advance(&mut self) -> Result<(), Error> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(Error::InvalidFrame("Shadowsocks nonce counter exhausted"))?;
        Ok(())
    }

    /// Append `plaintext` to `out` as one sealed chunk (`ciphertext || tag`),
    /// encrypting in place inside `out` — no intermediate allocation.
    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let nonce = self.nonce();
        let start = out.len();
        out.extend_from_slice(plaintext);
        let body = &mut out[start..];
        let tag = match &self.cipher {
            SsCipher::Aes128(cipher) => cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", body)
                .map_err(|_| Error::Crypto)?,
            SsCipher::Aes256(cipher) => cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", body)
                .map_err(|_| Error::Crypto)?,
            SsCipher::ChaCha(cipher) => cipher
                .encrypt_in_place_detached(chacha20poly1305::Nonce::from_slice(&nonce), b"", body)
                .map_err(|_| Error::Crypto)?,
        };
        out.extend_from_slice(&tag);
        self.advance()
    }

    /// Authenticate and decrypt `chunk = ciphertext || tag` in place; the
    /// plaintext is `chunk[..chunk.len() - TAG_LEN]` afterwards.
    fn open_in_place(&mut self, chunk: &mut [u8]) -> Result<(), Error> {
        if chunk.len() < TAG_LEN {
            return Err(Error::InvalidFrame("Shadowsocks AEAD chunk is truncated"));
        }
        let nonce = self.nonce();
        let split = chunk.len() - TAG_LEN;
        let (body, tag) = chunk.split_at_mut(split);
        let tag: &[u8] = tag;
        match &self.cipher {
            SsCipher::Aes128(cipher) => cipher
                .decrypt_in_place_detached(Nonce::from_slice(&nonce), b"", body, tag.into())
                .map_err(|_| Error::Crypto)?,
            SsCipher::Aes256(cipher) => cipher
                .decrypt_in_place_detached(Nonce::from_slice(&nonce), b"", body, tag.into())
                .map_err(|_| Error::Crypto)?,
            SsCipher::ChaCha(cipher) => cipher
                .decrypt_in_place_detached(
                    chacha20poly1305::Nonce::from_slice(&nonce),
                    b"",
                    body,
                    tag.into(),
                )
                .map_err(|_| Error::Crypto)?,
        }
        self.advance()
    }
}

/// Plaintext bytes of the chunk at the head of the read buffer that have not
/// been handed to the caller yet.
#[derive(Debug, Clone, Copy, Default)]
struct PlainWindow {
    pos: usize,
    end: usize,
    /// Wire bytes the chunk occupies; consumed once the plaintext is drained.
    chunk_len: usize,
}

/// An AEAD-framed Shadowsocks stream. The first write emits the per-session
/// salt; the first read consumes the peer's salt.
///
/// Writes are buffered: `poll_write` seals the caller's bytes into an internal
/// buffer, starts sending it, and reports the bytes as accepted. The buffer is
/// drained by the next `poll_write`, `poll_flush` or `poll_shutdown`, so
/// callers must flush (as with any buffered writer) before waiting on a reply.
pub struct Stream<S> {
    inner: S,
    method: Method,
    master_key: Box<[u8]>,
    send: Option<CipherState>,
    recv: Option<CipherState>,
    read_buf: ReadBuffer,
    /// The decoded length of the payload chunk being waited for.
    payload_len: Option<usize>,
    plain: PlainWindow,
    write_buf: WriteBuffer,
}

impl<S> Stream<S> {
    pub fn new_client(inner: S, method: Method, password: impl AsRef<[u8]>) -> Self {
        Self::new(inner, method, password.as_ref())
    }

    pub fn new_server(inner: S, method: Method, password: impl AsRef<[u8]>) -> Self {
        Self::new(inner, method, password.as_ref())
    }

    fn new(inner: S, method: Method, password: &[u8]) -> Self {
        Self {
            inner,
            method,
            master_key: evp_bytes_to_key(password, method.key_len()).into_boxed_slice(),
            send: None,
            recv: None,
            read_buf: ReadBuffer::with_capacity(DEFAULT_READ_CAPACITY),
            payload_len: None,
            plain: PlainWindow::default(),
            write_buf: WriteBuffer::default(),
        }
    }

    pub async fn write_destination(&mut self, destination: &Destination) -> Result<(), Error>
    where
        S: AsyncWrite + Unpin,
    {
        let address = encode_address(destination)?;
        tokio::io::AsyncWriteExt::write_all(self, &address).await?;
        tokio::io::AsyncWriteExt::flush(self).await?;
        Ok(())
    }

    pub async fn read_destination(&mut self) -> Result<(Destination, Vec<u8>), Error>
    where
        S: AsyncRead + Unpin,
    {
        let mut first = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(self, &mut first).await?;
        let (address, consumed) = decode_address(first[0], self).await?;
        let destination = Destination::tcp(address.0, address.1);
        Ok((destination, consumed))
    }

    /// Seal up to [`MAX_WRITE_BATCH`] bytes of `src` into the write buffer.
    fn seal_batch(&mut self, src: &[u8]) -> Result<usize, Error> {
        let out = self.write_buf.buf_mut();
        if self.send.is_none() {
            let mut salt = [0u8; SALT_LEN];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            self.send = Some(CipherState::new(self.method, &self.master_key, &salt));
            out.extend_from_slice(&salt);
        }
        let send = self.send.as_mut().expect("send cipher initialised above");
        let accepted = src.len().min(MAX_WRITE_BATCH);
        out.reserve(accepted + accepted.div_ceil(MAX_CHUNK) * (LENGTH_LEN + 2 * TAG_LEN));
        for chunk in src[..accepted].chunks(MAX_CHUNK) {
            send.seal_into(&(chunk.len() as u16).to_be_bytes(), out)?;
            send.seal_into(chunk, out)?;
        }
        Ok(accepted)
    }
}

impl<S: AsyncRead + Unpin> Stream<S> {
    /// Make at least `need` bytes available. `Ready(Ok(false))` means the
    /// caller should return what it already delivered (or a clean EOF).
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
                        "Shadowsocks peer closed mid-frame",
                    )))
                }
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            // Bytes already handed out must be reported now, not after the
            // next network read.
            Poll::Pending if delivered => Poll::Ready(Ok(false)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
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

            if this.recv.is_none() {
                match this.poll_need(cx, SALT_LEN, delivered, true) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                    Poll::Ready(Ok(true)) => {}
                }
                let salt: [u8; SALT_LEN] = this.read_buf.data()[..SALT_LEN]
                    .try_into()
                    .expect("salt length checked");
                this.recv = Some(CipherState::new(this.method, &this.master_key, &salt));
                this.read_buf.consume(SALT_LEN);
                continue;
            }

            match this.payload_len {
                None => {
                    match this.poll_need(cx, LENGTH_LEN + TAG_LEN, delivered, true) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                        Poll::Ready(Ok(true)) => {}
                    }
                    let recv = this.recv.as_mut().expect("receive cipher initialised");
                    let chunk = &mut this.read_buf.data_mut()[..LENGTH_LEN + TAG_LEN];
                    if let Err(error) = recv.open_in_place(chunk) {
                        return Poll::Ready(Err(io::Error::other(error)));
                    }
                    let length = u16::from_be_bytes([chunk[0], chunk[1]]) as usize;
                    this.read_buf.consume(LENGTH_LEN + TAG_LEN);
                    if length == 0 || length > MAX_CHUNK {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid Shadowsocks payload length",
                        )));
                    }
                    this.payload_len = Some(length);
                }
                Some(length) => {
                    match this.poll_need(cx, length + TAG_LEN, delivered, false) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                        Poll::Ready(Ok(true)) => {}
                    }
                    let recv = this.recv.as_mut().expect("receive cipher initialised");
                    if let Err(error) =
                        recv.open_in_place(&mut this.read_buf.data_mut()[..length + TAG_LEN])
                    {
                        return Poll::Ready(Err(io::Error::other(error)));
                    }
                    this.payload_len = None;
                    this.plain = PlainWindow {
                        pos: 0,
                        end: length,
                        chunk_len: length + TAG_LEN,
                    };
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // Earlier output must reach the transport before more is accepted;
        // this is the backpressure point.
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
            Err(error) => return Poll::Ready(Err(io::Error::other(error))),
        };
        // Start sending right away; whatever the transport cannot take now
        // stays buffered for the next write or flush.
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

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream<S> {
    pub fn boxed_client(inner: S, method: Method, password: impl AsRef<[u8]>) -> BoxStream {
        Box::pin(Self::new_client(inner, method, password))
    }
}

fn evp_bytes_to_key(password: &[u8], length: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(length);
    let mut previous = Vec::new();
    while key.len() < length {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password);
        previous = hasher.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(length);
    key
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
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            if domain.is_empty() || domain.len() > u8::MAX as usize {
                return Err(Error::UnsupportedDestination);
            }
            out.push(3);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(out)
}

async fn decode_address<S: AsyncRead + Unpin>(
    kind: u8,
    stream: &mut Stream<S>,
) -> Result<((Address, u16), Vec<u8>), Error> {
    let mut consumed = vec![kind];
    let address = match kind {
        1 => {
            let mut bytes = [0u8; 4];
            tokio::io::AsyncReadExt::read_exact(stream, &mut bytes).await?;
            consumed.extend_from_slice(&bytes);
            Address::Ip(std::net::IpAddr::V4(bytes.into()))
        }
        4 => {
            let mut bytes = [0u8; 16];
            tokio::io::AsyncReadExt::read_exact(stream, &mut bytes).await?;
            consumed.extend_from_slice(&bytes);
            Address::Ip(std::net::IpAddr::V6(bytes.into()))
        }
        3 => {
            let mut len = [0u8; 1];
            tokio::io::AsyncReadExt::read_exact(stream, &mut len).await?;
            if len[0] == 0 {
                return Err(Error::InvalidFrame("empty Shadowsocks domain"));
            }
            let mut bytes = vec![0u8; len[0] as usize];
            tokio::io::AsyncReadExt::read_exact(stream, &mut bytes).await?;
            consumed.push(len[0]);
            consumed.extend_from_slice(&bytes);
            let domain = String::from_utf8(bytes)
                .map_err(|_| Error::InvalidFrame("invalid Shadowsocks domain"))?;
            Address::Domain(domain.into())
        }
        _ => return Err(Error::InvalidFrame("invalid Shadowsocks address type")),
    };
    let mut port = [0u8; 2];
    tokio::io::AsyncReadExt::read_exact(stream, &mut port).await?;
    consumed.extend_from_slice(&port);
    Ok(((address, u16::from_be_bytes(port)), consumed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn the_nonce_is_a_little_endian_counter() {
        let master = evp_bytes_to_key(b"password", Method::Aes256Gcm.key_len());
        let mut state = CipherState::new(Method::Aes256Gcm, &master, &[0u8; SALT_LEN]);
        assert_eq!(state.nonce(), [0u8; 12]);
        state.counter = 1;
        assert_eq!(state.nonce(), [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        state.counter = 258;
        assert_eq!(state.nonce(), [2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // The distinguishing case: a big-endian counter agrees at zero and
        // nowhere else, which is exactly why this went unnoticed.
        state.counter = 1;
        assert_ne!(state.nonce()[4..], 1u64.to_be_bytes());
    }

    #[test]
    fn password_derivation_is_stable_and_method_sized() {
        assert_eq!(evp_bytes_to_key(b"password", 16).len(), 16);
        assert_eq!(evp_bytes_to_key(b"password", 32).len(), 32);
        assert_eq!(
            evp_bytes_to_key(b"password", 32),
            evp_bytes_to_key(b"password", 32)
        );
    }

    #[tokio::test]
    async fn client_and_server_stream_roundtrip() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let (client, server) = tokio::io::duplex(128 * 1024);
            let mut client = Stream::new_client(client, method, "secret");
            let mut server = Stream::new_server(server, method, "secret");
            let destination = Destination::tcp(Address::parse_host("example.com"), 443);
            let expected = destination.clone();
            let writer = tokio::spawn(async move {
                client.write_destination(&destination).await.unwrap();
                client.write_all(b"payload").await.unwrap();
                client.flush().await.unwrap();
            });
            let (decoded, _) = server.read_destination().await.unwrap();
            assert_eq!(decoded, expected);
            let mut payload = [0u8; 7];
            server.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"payload");
            writer.await.unwrap();
        }
    }

    /// Regression: the old reader reported every EOF — even a clean one at a
    /// chunk boundary — as "peer closed mid-frame", so a client half-close
    /// tore down the relay instead of letting the response flow back.
    #[tokio::test]
    async fn a_clean_close_is_eof_and_a_truncated_chunk_is_an_error() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mut client = Stream::new_client(client, Method::Aes128Gcm, "secret");
        let mut server = Stream::new_server(server, Method::Aes128Gcm, "secret");
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"request");

        let (mut raw, server) = tokio::io::duplex(64 * 1024);
        let mut server = Stream::new_server(server, Method::Aes128Gcm, "secret");
        raw.write_all(&[7u8; SALT_LEN + 5]).await.unwrap();
        drop(raw);
        let mut got = Vec::new();
        let error = server.read_to_end(&mut got).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn large_transfers_span_many_chunks_and_small_reads() {
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let (client, server) = tokio::io::duplex(16 * 1024);
        let mut client = Stream::new_client(client, Method::Chacha20Poly1305, "secret");
        let mut server = Stream::new_server(server, Method::Chacha20Poly1305, "secret");
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        let mut chunk = [0u8; 1000];
        loop {
            let n = server.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
        }
        writer.await.unwrap();
        assert_eq!(got, expected);
    }
}
