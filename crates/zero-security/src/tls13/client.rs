//! The TLS 1.3 client handshake and the post-handshake stream.
//!
//! State machine per docs/specs/tls13-core.md §1: ServerHello in the clear,
//! then EncryptedExtensions → Certificate → CertificateVerify → Finished
//! under handshake keys (possibly straddling records), then exactly one
//! client Finished, then application data both ways.
//!
//! Tolerance rules that are load-bearing against real Xray REALITY servers
//! (docs/specs/REALITY-client.md §9): dummy ChangeCipherSpec records are
//! skipped, and after the handshake the server may send validly-encrypted
//! *empty* application-data records replicating the fallback site's ticket
//! flow — they must be consumed silently. Session tickets and KeyUpdate
//! arriving post-handshake are processed or ignored, never fatal.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use ml_kem::Decapsulate;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zero_core::{Confidence, Failure, FailureKind, Stage};
use zeroize::Zeroize;

use super::hello::{build as build_hello, ClientKeypair, HelloParams};
use super::kdf::{
    establish_application_secrets, establish_handshake_secrets, finished_verify_data,
    next_traffic_secret, Transcript,
};
use super::record::{
    parse_header, record_header, RecordCrypter, CONTENT_ALERT, CONTENT_APPDATA, CONTENT_CCS,
    CONTENT_HANDSHAKE,
};
use super::{malformed, CipherSuite, MAX_PLAINTEXT};

/// Handshake message types we handle.
mod msg {
    pub const SERVER_HELLO: u8 = 2;
    pub const NEW_SESSION_TICKET: u8 = 4;
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    pub const CERTIFICATE: u8 = 11;
    pub const CERTIFICATE_VERIFY: u8 = 15;
    pub const FINISHED: u8 = 20;
    pub const KEY_UPDATE: u8 = 24;
}

/// The HelloRetryRequest sentinel random (RFC 8446 §4.1.3). We do not follow
/// retries; seeing it means the server refused our key share.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Certificate authentication policy.
///
/// The minimal stack does no X.509 chain validation; the policy owns the
/// decision. REALITY replaces it entirely with the temporary-certificate
/// HMAC (see `crate::reality`), which also returns the leaf's Ed25519 public
/// key so the CertificateVerify signature can be checked.
pub trait ServerAuth: Send + Sync {
    /// Inspect the leaf certificate DER. Returns the raw public key bytes
    /// from its SubjectPublicKeyInfo (32 bytes for Ed25519).
    fn verify_certificate(&self, cert_der: &[u8]) -> Result<Vec<u8>, Failure>;

    /// Verify a certificate with the handshake bytes available. REALITY's
    /// optional ML-DSA-65 binding signs an HMAC over both hellos; ordinary
    /// certificate policies can use the default implementation.
    fn verify_certificate_with_context(
        &self,
        cert_der: &[u8],
        _client_hello: &[u8],
        _server_hello: &[u8],
    ) -> Result<Vec<u8>, Failure> {
        self.verify_certificate(cert_der)
    }
}

/// A hello prepared for sending. `msg` is public so REALITY can patch its
/// sealed tag into bytes 39..71 before the record goes on the wire.
pub struct PendingHello {
    pub msg: Vec<u8>,
    keypair: ClientKeypair,
}

impl PendingHello {
    /// Build with `params`; `params.session_id` lands verbatim at msg[39..71].
    pub fn new(params: &HelloParams) -> Self {
        let (msg, keypair) = build_hello(params);
        Self { msg, keypair }
    }

    /// The 32-byte session-id field as currently in the message.
    pub fn session_id(&self) -> &[u8] {
        &self.msg[39..71]
    }

    /// The ephemeral keypair behind the key share. REALITY derives its auth
    /// key from this secret without consuming it; the handshake later uses
    /// the same secret for the TLS ECDHE.
    pub fn keypair(&self) -> &ClientKeypair {
        &self.keypair
    }

    /// The hello random (salt and nonce source for the REALITY seal).
    pub fn random(&self) -> &[u8] {
        &self.msg[6..38]
    }
}

/// Everything a completed handshake hands to the caller.
pub struct HandshakeResult<S> {
    pub stream: Tls13Stream<S>,
    pub suite: CipherSuite,
}

/// Run the full handshake over `io` and return a usable stream.
pub async fn handshake<S>(
    mut io: S,
    hello: PendingHello,
    auth: &dyn ServerAuth,
) -> Result<HandshakeResult<S>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stage = Stage::TlsStarted;

    // ── ClientHello ──────────────────────────────────────────────────────
    let mut record = Vec::with_capacity(5 + hello.msg.len());
    // TLS 1.3 keeps the legacy ClientHello record version at 0x0301 for
    // middlebox compatibility. Subsequent protected records use 0x0303.
    let mut hello_header = record_header(CONTENT_HANDSHAKE, hello.msg.len());
    hello_header[2] = 0x01;
    record.extend_from_slice(&hello_header);
    record.extend_from_slice(&hello.msg);
    io.write_all(&record)
        .await
        .map_err(|e| Failure::from_io(&e, stage))?;
    io.flush().await.map_err(|e| Failure::from_io(&e, stage))?;

    // ── ServerHello ──────────────────────────────────────────────────────
    let sh = read_server_hello(&mut io).await?;
    let suite = parse_server_hello(&sh, hello.session_id())?;
    let server_share = extract_server_key_share(&sh)?;

    let mut transcript = Transcript::new(suite.hash);
    transcript.update(&hello.msg);
    transcript.update(&sh);

    // ── Key schedule, phase one ──────────────────────────────────────────
    let mut shared = match server_share.group {
        0x001d if server_share.data.len() == 32 => x25519_dalek::x25519(
            hello.keypair.secret,
            server_share.data[..].try_into().unwrap(),
        )
        .to_vec(),
        0x11ec if server_share.data.len() == 1088 + 32 => {
            // X25519MLKEM768 puts the ML-KEM ciphertext first and the
            // X25519 server share last. Go's TLS implementation concatenates
            // the KEM secret before the ECDH secret for this group.
            let decapsulation_key = hello.keypair.mlkem.as_ref().ok_or_else(|| {
                malformed("server selected X25519MLKEM768, which the hello did not offer")
            })?;
            let mlkem = decapsulation_key
                .decapsulate_slice(&server_share.data[..1088])
                .map_err(|_| malformed("invalid ML-KEM-768 server ciphertext"))?;
            let x25519 = x25519_dalek::x25519(
                hello.keypair.secret,
                server_share.data[1088..].try_into().unwrap(),
            );
            let mut shared = Vec::with_capacity(64);
            shared.extend_from_slice(mlkem.as_ref());
            shared.extend_from_slice(&x25519);
            shared
        }
        _ => return Err(malformed("unsupported or malformed server key share")),
    };
    if shared.iter().all(|b| *b == 0) {
        return Err(malformed("ECDH produced a degenerate shared secret"));
    }
    let ch_sh_hash = transcript.snapshot();
    let schedule = establish_handshake_secrets(suite, &shared, &ch_sh_hash);
    shared.zeroize();

    let mut read_crypter = RecordCrypter::new(suite, &schedule.server_hs_traffic);

    // ── Encrypted flight: EE, Certificate, CertificateVerify, Finished ──
    let mut acc: Vec<u8> = Vec::new();
    let mut got_ee = false;
    // The public key the certificate policy authenticated; CertificateVerify
    // must be checked against exactly this key.
    let mut leaf_key: Option<Vec<u8>> = None;
    let mut got_cv = false;
    let mut got_finished = false;

    while !got_finished {
        let (inner_type, payload) = read_encrypted_record(&mut io, &mut read_crypter).await?;
        if inner_type != CONTENT_HANDSHAKE {
            return Err(malformed(format!(
                "expected handshake content inside encrypted records, got {inner_type:#04x}"
            )));
        }
        acc.extend_from_slice(&payload);
        if acc.len() > 4 * MAX_PLAINTEXT {
            return Err(malformed(
                "encrypted handshake flight exceeds the size limit",
            ));
        }

        // Parse every complete message currently buffered.
        let mut at = 0usize;
        while !got_finished && at + 4 <= acc.len() {
            let mtype = acc[at];
            let mlen = read_u24(&acc, at + 1)?;
            let total = 4 + mlen;
            if at + total > acc.len() {
                break; // message straddles records; wait for the next one
            }
            let body = &acc[at + 4..at + total];

            match mtype {
                msg::ENCRYPTED_EXTENSIONS if !got_ee && leaf_key.is_none() => got_ee = true,
                msg::CERTIFICATE if leaf_key.is_none() => {
                    let leaf = certificate_leaf_der(body)?;
                    leaf_key = Some(auth.verify_certificate_with_context(leaf, &hello.msg, &sh)?);
                }
                msg::CERTIFICATE_VERIFY if !got_cv => {
                    let Some(key) = leaf_key.as_deref() else {
                        return Err(malformed("CertificateVerify before Certificate"));
                    };
                    verify_certificate_verify(body, key, &transcript)?;
                    got_cv = true;
                }
                msg::FINISHED if got_cv => {
                    // verify_data covers CH..CertificateVerify, i.e. the
                    // transcript as it stands before this message.
                    let th = transcript.snapshot();
                    let expect = finished_verify_data(suite.hash, &schedule.server_hs_traffic, &th);
                    if !bool::from(body.ct_eq(expect.as_slice())) {
                        return Err(malformed("server Finished verify_data mismatch"));
                    }
                    got_finished = true;
                }
                msg::NEW_SESSION_TICKET => { /* tickets never join the transcript */ }
                other => {
                    return Err(malformed(format!(
                        "unexpected handshake message type {other} in the encrypted flight"
                    )))
                }
            }
            if mtype != msg::NEW_SESSION_TICKET {
                transcript.update(&acc[at..at + total]);
            }
            at += total;
        }
        acc.drain(..at);
    }

    // ── Key schedule, phase two ──────────────────────────────────────────
    let full_hash = transcript.snapshot();
    let (client_app, server_app) = establish_application_secrets(&schedule, &full_hash);

    // ── Client Finished ──────────────────────────────────────────────────
    let vd = finished_verify_data(suite.hash, &schedule.client_hs_traffic, &full_hash);
    let mut finished_msg = Vec::with_capacity(4 + vd.len());
    finished_msg.push(msg::FINISHED);
    finished_msg.extend_from_slice(&(vd.len() as u32).to_be_bytes()[1..]);
    finished_msg.extend_from_slice(&vd);

    let mut write_hs = RecordCrypter::new(suite, &schedule.client_hs_traffic);
    let sealed = write_hs.seal(&finished_msg, CONTENT_HANDSHAKE)?;
    io.write_all(&sealed.bytes)
        .await
        .map_err(|e| Failure::from_io(&e, stage))?;
    io.flush().await.map_err(|e| Failure::from_io(&e, stage))?;

    Ok(HandshakeResult {
        stream: Tls13Stream::new(io, suite, server_app, client_app),
        suite,
    })
}

/// CertificateVerify: parse, and verify against the authenticated leaf key
/// over `Hash(CH .. Certificate)` with the RFC 8446 §4.4.3 framing.
///
/// `leaf_key` is the key the `ServerAuth` policy returned. When it is an
/// Ed25519 key (every REALITY certificate) the signature *must* be Ed25519
/// and must verify: the certificate HMAC alone is replayable by an on-path
/// attacker who relays our hello to the real server, and CertificateVerify is
/// the proof that the peer we derived keys with owns the certificate.
fn verify_certificate_verify(
    cv_body: &[u8],
    leaf_key: &[u8],
    transcript: &Transcript,
) -> Result<(), Failure> {
    if cv_body.len() < 4 {
        return Err(super::truncated("CertificateVerify"));
    }
    let alg = u16::from_be_bytes([cv_body[0], cv_body[1]]);
    let sig_len = u16::from_be_bytes([cv_body[2], cv_body[3]]) as usize;
    if cv_body.len() != 4 + sig_len {
        return Err(malformed("CertificateVerify length mismatch"));
    }
    let Ok(pubkey) = <[u8; 32]>::try_from(leaf_key) else {
        // Only Ed25519 is verifiable here; that is what REALITY servers use.
        // A policy authenticating some other key type owns that decision.
        return Ok(());
    };
    if alg != 0x0807 {
        return Err(malformed(format!(
            "CertificateVerify algorithm {alg:#06x} does not match the Ed25519 leaf key"
        )));
    }
    if sig_len != 64 {
        return Err(malformed("Ed25519 CertificateVerify is not 64 bytes"));
    }

    let th = transcript.snapshot();
    let mut signed = Vec::with_capacity(64 + 34 + th.len());
    signed.extend_from_slice(&[0x20u8; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0x00);
    signed.extend_from_slice(&th);

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let key = VerifyingKey::from_bytes(&pubkey)
        .map_err(|e| malformed(format!("bad Ed25519 leaf key: {e}")))?;
    let sig_arr: [u8; 64] = cv_body[4..4 + 64]
        .try_into()
        .map_err(|_| malformed("CertificateVerify signature is not 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);
    key.verify(&signed, &sig)
        .map_err(|_| malformed("CertificateVerify signature did not verify"))?;
    Ok(())
}

/// Read the ServerHello handshake message from cleartext records, skipping
/// dummy CCS/mimicry records.
///
/// Returns exactly the one handshake message (4-byte header included), which
/// is what the transcript must hash. A server may legally fragment the
/// ServerHello across several records; nothing may follow it in cleartext,
/// because every later handshake message is encrypted.
async fn read_server_hello<S>(io: &mut S) -> Result<Vec<u8>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut message: Vec<u8> = Vec::new();
    let mut guard = 0u64;
    loop {
        let mut header = [0u8; 5];
        io.read_exact(&mut header)
            .await
            .map_err(|e| classify_eof(e, "waiting for ServerHello"))?;
        let (ctype, len) = parse_header(&header)?;

        let mut body = vec![0u8; len];
        match ctype {
            CONTENT_HANDSHAKE => {
                io.read_exact(&mut body)
                    .await
                    .map_err(|e| classify_eof(e, "reading ServerHello"))?;
                if body.is_empty() {
                    // RFC 8446 §5.1: zero-length handshake fragments are illegal.
                    return Err(malformed("empty handshake record before ServerHello"));
                }
                message.extend_from_slice(&body);
                if message.len() >= 4 {
                    let need = 4 + read_u24(&message, 1)?;
                    if need > MAX_PLAINTEXT {
                        return Err(malformed("ServerHello exceeds the size limit"));
                    }
                    match message.len().cmp(&need) {
                        std::cmp::Ordering::Equal => return Ok(message),
                        std::cmp::Ordering::Greater => {
                            return Err(malformed(
                                "unexpected cleartext handshake data after ServerHello",
                            ))
                        }
                        std::cmp::Ordering::Less => {} // fragmented; keep reading
                    }
                }
            }
            CONTENT_CCS | CONTENT_APPDATA if message.is_empty() => {
                io.read_exact(&mut body)
                    .await
                    .map_err(|e| classify_eof(e, "reading pre-handshake record"))?;
                // dummy CCS or mimicry: skip
            }
            CONTENT_ALERT => {
                io.read_exact(&mut body)
                    .await
                    .map_err(|e| classify_eof(e, "reading alert"))?;
                return Err(alert_failure(&body));
            }
            _ if !message.is_empty() => {
                return Err(malformed(format!(
                    "record type {ctype:#04x} interleaved with a fragmented ServerHello"
                )))
            }
            _ => return Err(malformed(format!("unexpected record type {ctype:#04x}"))),
        }
        guard += 1;
        if guard > 64 {
            return Err(malformed(
                "too many non-handshake records before ServerHello",
            ));
        }
    }
}

/// Read and decrypt one protected record after the ServerHello.
async fn read_encrypted_record<S>(
    io: &mut S,
    crypter: &mut RecordCrypter,
) -> Result<(u8, Vec<u8>), Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut guard = 0u64;
    loop {
        let mut header = [0u8; 5];
        io.read_exact(&mut header)
            .await
            .map_err(|e| classify_eof(e, "waiting for encrypted flight"))?;
        let (ctype, len) = parse_header(&header)?;

        let mut body = vec![0u8; len];
        io.read_exact(&mut body)
            .await
            .map_err(|e| classify_eof(e, "reading encrypted flight"))?;

        match ctype {
            CONTENT_APPDATA => {
                let (inner_type, len) = crypter.open_in_place(&header, &mut body)?;
                body.truncate(len);
                return Ok((inner_type, body));
            }
            CONTENT_CCS => { /* middlebox-compat dummy */ }
            CONTENT_ALERT => return Err(alert_failure(&body)),
            CONTENT_HANDSHAKE => {
                return Err(malformed(
                    "cleartext handshake record inside the encrypted flight",
                ))
            }
            _ => return Err(malformed(format!("unexpected record type {ctype:#04x}"))),
        }
        guard += 1;
        if guard > 64 {
            return Err(malformed(
                "too many useless records in the encrypted flight",
            ));
        }
    }
}

fn classify_eof(e: std::io::Error, ctx: &'static str) -> Failure {
    let mut f = Failure::from_io(&e, Stage::TlsStarted);
    f.detail = Some(format!("{ctx}: {e}"));
    f
}

fn alert_failure(body: &[u8]) -> Failure {
    let desc = body.get(1).copied().unwrap_or(0xff);
    let kind = if desc == 0 {
        FailureKind::Cancelled // close_notify
    } else {
        FailureKind::TlsAlert
    };
    Failure::new(kind, Stage::TlsStarted)
        .with_confidence(Confidence::Confirmed)
        .with_detail(format!("alert description {desc}"))
}

/// Validate a ServerHello against what we sent. Returns the negotiated suite.
fn parse_server_hello(sh: &[u8], our_session_id: &[u8]) -> Result<CipherSuite, Failure> {
    if sh.first() != Some(&msg::SERVER_HELLO) {
        return Err(malformed(
            "first server handshake message is not ServerHello",
        ));
    }
    let mut at = 4usize;

    at += 2; // legacy_version

    let random = super::take(sh, at, 32, "server random")?;
    if random == HRR_RANDOM {
        return Err(malformed(
            "server sent HelloRetryRequest; the hello's key share was not acceptable",
        ));
    }
    at += 32;

    let sid_len = byte_at(sh, at, "session id length")? as usize;
    at += 1;
    let sid = super::take(sh, at, sid_len, "session id")?;
    if sid != our_session_id {
        return Err(malformed("server did not echo our session id"));
    }
    at += sid_len;

    let suite_id = u16::from_be_bytes(super::take(sh, at, 2, "cipher suite")?.try_into().unwrap());
    at += 2;
    let suite = CipherSuite::by_id(suite_id)
        .ok_or_else(|| malformed(format!("server selected unknown suite {suite_id:#06x}")))?;

    let compression = byte_at(sh, at, "compression")?;
    at += 1;
    if compression != 0 {
        return Err(malformed("server selected non-null compression"));
    }

    // Extensions: supported_versions must confirm 1.3.
    let ext_total = u16::from_be_bytes(
        super::take(sh, at, 2, "extensions length")?
            .try_into()
            .unwrap(),
    ) as usize;
    at += 2;
    let end = at + ext_total;
    if end > sh.len() {
        return Err(super::truncated("server extensions"));
    }

    let mut saw_tls13 = false;
    while at + 4 <= end {
        let etype = u16::from_be_bytes(sh[at..at + 2].try_into().unwrap());
        let elen = u16::from_be_bytes(sh[at + 2..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let body = super::take(sh, at, elen, "extension body")?;
        at += elen;
        // ClientHello carries a length-prefixed list here, but ServerHello
        // carries the single selected version directly (RFC 8446 §4.2.1).
        if etype == 43 && body == [0x03, 0x04] {
            saw_tls13 = true;
        }
    }
    if !saw_tls13 {
        // A fallback target on TLS 1.2 shows up exactly here.
        return Err(malformed("server did not negotiate TLS 1.3"));
    }
    Ok(suite)
}

struct ServerKeyShare {
    group: u16,
    data: Vec<u8>,
}

/// Extract the selected X25519 or X25519MLKEM768 share from ServerHello.
fn extract_server_key_share(sh: &[u8]) -> Result<ServerKeyShare, Failure> {
    let mut at = 4 + 2 + 32;
    let sid_len = byte_at(sh, at, "session id length")? as usize;
    at += 1 + sid_len + 2 + 1;
    let ext_total = u16::from_be_bytes(
        super::take(sh, at, 2, "extensions length")?
            .try_into()
            .unwrap(),
    ) as usize;
    at += 2;
    let end = at + ext_total;
    if end > sh.len() {
        return Err(super::truncated("server extensions"));
    }

    while at + 4 <= end {
        let etype = u16::from_be_bytes(sh[at..at + 2].try_into().unwrap());
        let elen = u16::from_be_bytes(sh[at + 2..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let body = super::take(sh, at, elen, "key_share body")?;
        at += elen;
        if etype == 51 {
            // ServerHello carries one selected share directly; the
            // two-byte vector length exists only in ClientHello.
            if body.len() < 4 {
                return Err(super::truncated("server key_share"));
            }
            let group = u16::from_be_bytes(body[..2].try_into().unwrap());
            let klen = u16::from_be_bytes(body[2..4].try_into().unwrap()) as usize;
            let data = super::take(body, 4, klen, "server key_share entry")?;
            if body.len() != 4 + klen {
                return Err(malformed("trailing bytes in server key_share"));
            }
            if (group == 0x001d && klen == 32) || (group == 0x11ec && klen == 1088 + 32) {
                return Ok(ServerKeyShare {
                    group,
                    data: data.to_vec(),
                });
            }
        }
    }
    Err(malformed("no X25519 key share in ServerHello"))
}

/// Pull the leaf certificate DER out of a Certificate handshake message.
fn certificate_leaf_der(body: &[u8]) -> Result<&[u8], Failure> {
    let ctx_len = byte_at(body, 0, "cert request context length")? as usize;
    let mut at = 1 + ctx_len;
    let list_len = read_u24(body, at)?;
    at += 3;
    if list_len == 0 {
        return Err(malformed("empty certificate list"));
    }
    let cert_len = read_u24(body, at)?;
    at += 3;
    super::take(body, at, cert_len, "certificate DER")
}

fn byte_at(buf: &[u8], at: usize, what: &'static str) -> Result<u8, Failure> {
    Ok(super::take(buf, at, 1, what)?[0])
}

fn read_u24(buf: &[u8], at: usize) -> Result<usize, Failure> {
    let b = super::take(buf, at, 3, "u24 length")?;
    Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
}

// ── The post-handshake stream ────────────────────────────────────────────

/// Sealed-but-unsent ciphertext at which `poll_write` stops accepting new
/// plaintext until the socket drains: four full records.
const OUTGOING_HIGH_WATER: usize = 4 * (MAX_PLAINTEXT + 5 + 1 + 16);

/// A completed TLS 1.3 connection: decrypts inbound records, encrypts
/// outbound ones, and tolerates everything a REALITY server emits around
/// the data plane.
pub struct Tls13Stream<S> {
    inner: S,
    suite: CipherSuite,
    read: RecordCrypter,
    write: RecordCrypter,
    read_secret: Vec<u8>,
    write_secret: Vec<u8>,
    /// Raw bytes off the socket, not yet reassembled into records.
    wire: BytesMut,
    /// Decrypted application bytes awaiting delivery.
    plaintext: BytesMut,
    /// Sealed records awaiting transmission.
    outgoing: BytesMut,
    eof: bool,
    close_sent: bool,
    /// XTLS Vision transitions are directional. A peer's authenticated
    /// `PaddingDirect` response authorizes raw bytes on the read path, but
    /// this client emits `PaddingEnd`, so its write path must remain inside
    /// the outer TLS carrier. Keeping the states separate prevents a fast
    /// response from exposing request bytes that are still being written.
    direct_read: bool,
    direct_write: bool,
    /// Consecutive empty app-data records consumed — bounds ticket mimicry.
    empty_records: u64,
}

impl<S> Tls13Stream<S> {
    pub(crate) fn new(
        inner: S,
        suite: CipherSuite,
        server_app: Vec<u8>,
        client_app: Vec<u8>,
    ) -> Self {
        Self {
            inner,
            suite,
            read: RecordCrypter::new(suite, &server_app),
            write: RecordCrypter::new(suite, &client_app),
            read_secret: server_app,
            write_secret: client_app,
            wire: BytesMut::with_capacity(16 * 1024),
            plaintext: BytesMut::new(),
            outgoing: BytesMut::new(),
            eof: false,
            close_sent: false,
            direct_read: false,
            direct_write: false,
            empty_records: 0,
        }
    }

    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Enter Vision's authenticated direct-read mode. The protocol layer
    /// calls this only after consuming a valid `PaddingDirect` frame; an
    /// unauthenticated record-shaped prefix must never bypass the outer
    /// record authenticator.
    pub fn enter_direct_mode(&mut self) {
        self.direct_read = true;
    }
}

impl<S> Drop for Tls13Stream<S> {
    fn drop(&mut self) {
        self.read_secret.zeroize();
        self.write_secret.zeroize();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Tls13Stream<S> {
    /// Turn buffered wire bytes into plaintext. Ok(false) means clean EOF.
    fn pump_records(&mut self) -> Result<bool, Failure> {
        loop {
            if self.wire.len() < 5 {
                return Ok(true);
            }
            let (ctype, len) = {
                let hdr = [
                    self.wire[0],
                    self.wire[1],
                    self.wire[2],
                    self.wire[3],
                    self.wire[4],
                ];
                parse_header(&hdr)?
            };
            if self.wire.len() < 5 + len {
                return Ok(true);
            }
            let mut header = [0u8; 5];
            header.copy_from_slice(&self.wire[..5]);

            match ctype {
                CONTENT_CCS => self.wire.advance(5 + len), // dummy: ignore, any time
                CONTENT_ALERT => {
                    let close_notify = self.wire.get(5 + 1) == Some(&0) && len >= 2;
                    if close_notify {
                        self.wire.advance(5 + len);
                        self.eof = true;
                        return Ok(false);
                    }
                    return Err(alert_failure(&self.wire[5..5 + len]));
                }
                CONTENT_HANDSHAKE => {
                    return Err(malformed(
                        "cleartext handshake record after the handshake completed",
                    ));
                }
                CONTENT_APPDATA => {
                    // Decrypt inside the wire buffer: no per-record allocation,
                    // and the only copy is the one into `plaintext`.
                    let (inner_type, pt_len) = self
                        .read
                        .open_in_place(&header, &mut self.wire[5..5 + len])?;
                    let payload_range = 5..5 + pt_len;
                    match inner_type {
                        CONTENT_APPDATA => {
                            if pt_len == 0 {
                                // REALITY ticket-mimicry: validly encrypted
                                // empty records. Bounded tolerance.
                                self.empty_records += 1;
                                if self.empty_records > 256 {
                                    return Err(malformed(
                                        "peer sent an implausible run of empty records",
                                    ));
                                }
                            } else {
                                self.empty_records = 0;
                                self.plaintext.extend_from_slice(&self.wire[payload_range]);
                            }
                        }
                        CONTENT_ALERT => {
                            let payload = &self.wire[payload_range];
                            if payload.get(1) == Some(&0) {
                                self.wire.advance(5 + len);
                                self.eof = true;
                                return Ok(false);
                            }
                            return Err(alert_failure(payload));
                        }
                        CONTENT_HANDSHAKE => {
                            let payload = self.wire[payload_range].to_vec();
                            self.handle_post_handshake_messages(&payload)?;
                        }
                        _ => unreachable!("open validated the inner type"),
                    }
                    self.wire.advance(5 + len);

                    // Return after one authenticated plaintext record. Vision
                    // may need to inspect that record and authorize a direct
                    // carrier transition before the next raw bytes already
                    // buffered in `wire` are parsed. Draining the whole wire
                    // buffer here races that protocol-level state change and
                    // can mistake raw inner TLS for a failed outer record.
                    if !self.plaintext.is_empty() {
                        return Ok(true);
                    }
                }
                _ => return Err(malformed(format!("unexpected record type {ctype:#04x}"))),
            }
        }
    }

    /// Post-handshake handshake messages: session tickets are ignored,
    /// KeyUpdate rolls the traffic secrets (RFC 8446 §4.6.3).
    fn handle_post_handshake_messages(&mut self, payload: &[u8]) -> Result<(), Failure> {
        let mut at = 0usize;
        while at + 4 <= payload.len() {
            let mtype = payload[at];
            let mlen = match read_u24(payload, at + 1) {
                Ok(n) => n,
                Err(_) => return Ok(()), // fragment/mimicry: stop here
            };
            let body_at = at + 4;
            if body_at + mlen > payload.len() {
                return Ok(()); // incomplete trailing message: mimicry, not an error
            }
            if mtype == msg::KEY_UPDATE && mlen >= 1 {
                let next = next_traffic_secret(self.suite.hash, &self.read_secret);
                self.read_secret.zeroize();
                self.read_secret = next;
                self.read = RecordCrypter::new(self.suite, &self.read_secret);
                if payload[body_at] == 1 && !self.close_sent {
                    // Peer requests our update: answer with a not-requesting
                    // KeyUpdate, then roll the write side. RFC 8446 §4.6.3:
                    // the KeyUpdate itself is protected under the *old* key,
                    // and only the records after it use the new one — the
                    // peer switches its read key when it processes it.
                    let reply = [msg::KEY_UPDATE, 0, 0, 1, 0];
                    self.write
                        .seal_into(&reply, CONTENT_HANDSHAKE, &mut self.outgoing)?;
                    let next = next_traffic_secret(self.suite.hash, &self.write_secret);
                    self.write_secret.zeroize();
                    self.write_secret = next;
                    self.write = RecordCrypter::new(self.suite, &self.write_secret);
                }
            }
            // NewSessionTicket and unknown types: no resumption, ignored.
            at = body_at + mlen;
        }
        Ok(())
    }

    fn poll_flush_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.outgoing.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.outgoing) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tls13 write returned 0",
                    )))
                }
                Poll::Ready(Ok(n)) => self.outgoing.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// A zero-length application-data record is the one no-op TLS 1.3 actually
/// permits: RFC 8446 §5.1 forbids empty fragments of handshake and alert
/// types, but explicitly allows them for application data. Servers in this
/// ecosystem already emit them as session-ticket mimicry, and this stream's
/// own read path already tolerates and bounds them — so a keepalive here is
/// indistinguishable from traffic the peer was going to send anyway.
///
/// Owning the TLS stack is what makes this possible at all: a stock TLS
/// library gives no way to emit a record with no payload, which is why
/// keepalive shaping is absent from proxies built on one.
impl<S: AsyncRead + AsyncWrite + Unpin> zero_evasion::KeepaliveCarrier for Tls13Stream<S> {
    fn poll_keepalive(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let this = self.get_mut();
        // After a Vision direct-write transition there is no record layer left
        // to put a no-op into; the bytes would land in the peer's payload.
        if this.close_sent || this.direct_write {
            return Poll::Ready(Ok(false));
        }
        match this
            .write
            .seal_into(&[], CONTENT_APPDATA, &mut this.outgoing)
        {
            Ok(()) => {}
            Err(failure) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    failure.to_string(),
                )))
            }
        }
        match this.poll_flush_outgoing(cx) {
            // The record is buffered either way, so it is on its way out even
            // if the socket did not take it all this poll.
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(true)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Tls13Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if !this.plaintext.is_empty() {
                let n = this.plaintext.len().min(buf.remaining());
                let data = this.plaintext.split_to(n);
                buf.put_slice(&data);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(())); // clean EOF: zero-byte read
            }
            if this.direct_read {
                if !this.wire.is_empty() {
                    let n = this.wire.len().min(buf.remaining());
                    let data = this.wire.split_to(n);
                    buf.put_slice(&data);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            match this.pump_records() {
                Ok(true) => {}
                Ok(false) => {
                    // A peer may put application data and close_notify in
                    // the same socket read. `pump_records` has already
                    // queued that plaintext before reporting EOF; drain it
                    // before exposing the clean end of stream.
                    if !this.plaintext.is_empty() {
                        continue;
                    }
                    return Poll::Ready(Ok(()));
                }
                Err(f) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        f.to_string(),
                    )))
                }
            }
            if !this.plaintext.is_empty() || this.eof {
                continue; // something to deliver or EOF was reached
            }

            // Need more wire bytes.
            this.wire.reserve(16 * 1024);
            let (ptr, len) = {
                let chunk = this.wire.chunk_mut();
                (chunk.as_mut_ptr().cast(), chunk.len())
            };
            // SAFETY: `chunk_mut` just handed out this spare capacity.
            let mut sub = unsafe { ReadBuf::uninit(std::slice::from_raw_parts_mut(ptr, len)) };
            match Pin::new(&mut this.inner).poll_read(cx, &mut sub) {
                Poll::Ready(Ok(())) => {
                    let n = sub.filled().len();
                    if n == 0 {
                        // TCP EOF without a goodbye.
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    // SAFETY: n bytes were just filled into the spare
                    // capacity of wire.
                    unsafe { this.wire.advance_mut(n) };
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Tls13Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.close_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tls13 stream already closed",
            )));
        }

        if this.direct_write {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            // An empty write must not put an (empty) record on the wire.
            return Poll::Ready(Ok(0));
        }

        // Backpressure: sealed-but-unsent bytes are bounded. Without this a
        // fast producer on a slow socket would have every write accepted and
        // queued, growing `outgoing` without limit.
        while this.outgoing.len() >= OUTGOING_HIGH_WATER {
            match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tls13 write returned 0",
                    )))
                }
                Poll::Ready(Ok(n)) => this.outgoing.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Seal one record's worth; the rest is delivered by further
        // poll_write calls from `write_all`. Buffering the sealed bytes
        // here means we own them even if the flush below pends.
        let take = buf.len().min(MAX_PLAINTEXT);
        match this
            .write
            .seal_into(&buf[..take], CONTENT_APPDATA, &mut this.outgoing)
        {
            Ok(()) => {}
            Err(f) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    f.to_string(),
                )))
            }
        }

        // Flush as far as the socket accepts. A pending flush is fine: the
        // bytes are already buffered above, so report them as written.
        match this.poll_flush_outgoing(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(take)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Ready(Ok(take)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.direct_write {
            return Pin::new(&mut this.inner).poll_flush(cx);
        }
        this.poll_flush_outgoing(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.direct_write {
            return Pin::new(&mut this.inner).poll_shutdown(cx);
        }
        if !this.close_sent {
            this.close_sent = true;
            // close_notify: warning level 1, description 0.
            match this
                .write
                .seal_into(&[0x01, 0x00], CONTENT_ALERT, &mut this.outgoing)
            {
                Ok(()) => {}
                Err(f) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        f.to_string(),
                    )))
                }
            }
        }
        match this.poll_flush_outgoing(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn unauthenticated_record_shaped_bytes_fail_closed() {
        let (mut peer, io) = tokio::io::duplex(4096);
        let mut stream = Tls13Stream::new(
            io,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            vec![1; 32],
            vec![2; 32],
        );
        let raw = {
            let mut record = vec![CONTENT_APPDATA, 0x03, 0x03, 0, 17];
            record.extend_from_slice(&[0xa5; 17]);
            record
        };
        peer.write_all(&raw).await.unwrap();

        let mut received = vec![0u8; raw.len()];
        let error = stream.read_exact(&mut received).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    async fn read_record<R: AsyncRead + Unpin>(
        peer: &mut R,
        crypter: &mut RecordCrypter,
    ) -> (u8, Vec<u8>) {
        let mut header = [0u8; 5];
        peer.read_exact(&mut header).await.unwrap();
        let mut body = vec![0u8; u16::from_be_bytes([header[3], header[4]]) as usize];
        peer.read_exact(&mut body).await.unwrap();
        crypter.open(&header, &body).unwrap()
    }

    /// RFC 8446 §4.6.3: the KeyUpdate answer is sealed under the old write
    /// key and only the records after it use the new one. Sealing it under
    /// the new key makes the peer fail authentication on the answer itself.
    #[tokio::test]
    async fn requested_key_update_is_answered_under_the_old_key() {
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let (server_app, client_app) = (vec![1u8; 32], vec![2u8; 32]);
        let (mut peer, io) = tokio::io::duplex(64 * 1024);
        let mut stream = Tls13Stream::new(io, suite, server_app.clone(), client_app.clone());

        let mut peer_write = RecordCrypter::new(suite, &server_app);
        let mut wire = peer_write
            .seal(&[msg::KEY_UPDATE, 0, 0, 1, 1], CONTENT_HANDSHAKE)
            .unwrap()
            .bytes;
        let mut peer_write =
            RecordCrypter::new(suite, &next_traffic_secret(suite.hash, &server_app));
        wire.extend_from_slice(&peer_write.seal(b"hi", CONTENT_APPDATA).unwrap().bytes);
        peer.write_all(&wire).await.unwrap();

        let mut got = [0u8; 2];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hi");
        stream.write_all(b"x").await.unwrap();
        stream.flush().await.unwrap();

        let mut old_read = RecordCrypter::new(suite, &client_app);
        let (kind, answer) = read_record(&mut peer, &mut old_read).await;
        assert_eq!(
            (kind, answer.as_slice()),
            (CONTENT_HANDSHAKE, &[24, 0, 0, 1, 0][..])
        );
        let mut new_read = RecordCrypter::new(suite, &next_traffic_secret(suite.hash, &client_app));
        let (kind, data) = read_record(&mut peer, &mut new_read).await;
        assert_eq!((kind, data.as_slice()), (CONTENT_APPDATA, &b"x"[..]));
    }

    /// Writes must apply backpressure. Previously every `poll_write` sealed
    /// and queued its record and reported success even when the socket was
    /// full, so a stalled peer let `outgoing` grow without bound.
    #[tokio::test]
    async fn writes_block_instead_of_buffering_without_bound() {
        let (_peer, io) = tokio::io::duplex(4096);
        let mut stream = Tls13Stream::new(
            io,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            vec![1; 32],
            vec![2; 32],
        );
        let payload = vec![0x5a; 4 * 1024 * 1024];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            stream.write_all(&payload),
        )
        .await;
        assert!(result.is_err(), "write_all finished against a stalled peer");
        assert!(stream.outgoing.len() < OUTGOING_HIGH_WATER + MAX_PLAINTEXT + 64);
    }

    #[tokio::test]
    async fn empty_writes_put_nothing_on_the_wire() {
        let (mut peer, io) = tokio::io::duplex(4096);
        let mut stream = Tls13Stream::new(
            io,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            vec![1; 32],
            vec![2; 32],
        );
        assert_eq!(stream.write(&[]).await.unwrap(), 0);
        stream.write_all(b"a").await.unwrap();
        stream.flush().await.unwrap();
        let mut read = RecordCrypter::new(CipherSuite::TLS_AES_128_GCM_SHA256, &[2; 32]);
        let (_, data) = read_record(&mut peer, &mut read).await;
        assert_eq!(data, b"a", "the first record must carry the first byte");
    }

    /// An on-path relay can forward the genuine REALITY certificate (its HMAC
    /// is valid for our hello) but cannot sign with its key. Skipping the
    /// CertificateVerify check for a non-Ed25519 algorithm let exactly that
    /// relay complete the handshake.
    #[test]
    fn certificate_verify_must_use_the_ed25519_leaf_key() {
        let transcript = Transcript::new(super::super::HashAlg::Sha256);
        let mut body = vec![0x04, 0x03, 0x00, 0x40];
        body.extend_from_slice(&[0u8; 64]);
        assert!(verify_certificate_verify(&body, &[9u8; 32], &transcript).is_err());

        let mut ed = vec![0x08, 0x07, 0x00, 0x40];
        ed.extend_from_slice(&[0u8; 64]);
        assert!(
            verify_certificate_verify(&ed, &[9u8; 32], &transcript).is_err(),
            "a forged Ed25519 signature must not verify"
        );
    }

    #[tokio::test]
    async fn fragmented_server_hello_is_reassembled_exactly() {
        let message: Vec<u8> = {
            let mut m = vec![msg::SERVER_HELLO, 0, 0, 6];
            m.extend_from_slice(b"abcdef");
            m
        };
        let (mut peer, mut io) = tokio::io::duplex(4096);
        let mut wire = Vec::new();
        wire.extend_from_slice(&[CONTENT_CCS, 3, 3, 0, 1, 1]);
        wire.extend_from_slice(&record_header(CONTENT_HANDSHAKE, 3));
        wire.extend_from_slice(&message[..3]);
        wire.extend_from_slice(&record_header(CONTENT_HANDSHAKE, 7));
        wire.extend_from_slice(&message[3..]);
        peer.write_all(&wire).await.unwrap();
        assert_eq!(read_server_hello(&mut io).await.unwrap(), message);

        // Trailing cleartext after a complete ServerHello is a violation.
        let mut extra = record_header(CONTENT_HANDSHAKE, message.len() + 1).to_vec();
        extra.extend_from_slice(&message);
        extra.push(0);
        peer.write_all(&extra).await.unwrap();
        assert!(read_server_hello(&mut io).await.is_err());
    }

    #[tokio::test]
    async fn direct_read_transition_does_not_bypass_outer_tls_writes() {
        let (mut peer, io) = tokio::io::duplex(4096);
        let mut stream = Tls13Stream::new(
            io,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            vec![1; 32],
            vec![2; 32],
        );
        stream.enter_direct_mode();
        stream.write_all(b"request-tail").await.unwrap();

        let mut header = [0u8; 5];
        peer.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..3], &[CONTENT_APPDATA, 0x03, 0x03]);
    }
}
