//! Minimal TLS 1.3 server handshake used by REALITY.
//!
//! This is deliberately the mirror image of `client.rs`, not a general
//! certificate TLS implementation. It accepts a byte-controlled ClientHello,
//! validates the REALITY session seal, and then exposes the same record stream
//! type used by the client implementation.

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use ml_kem::{Encapsulate, EncapsulationKey768};
use rand::RngCore;
use sha2::Sha512;
use subtle::{Choice, ConstantTimeEq};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

use super::kdf::{
    establish_application_secrets, establish_handshake_secrets, finished_verify_data, Transcript,
};
use super::record::{
    parse_header, record_header, RecordCrypter, CONTENT_APPDATA, CONTENT_CCS, CONTENT_HANDSHAKE,
};
use super::{CipherSuite, Tls13Stream};
use zero_core::{Confidence, Failure, FailureKind, Stage};

#[derive(Debug, Clone)]
pub struct RealityServerParams {
    pub private_key: [u8; 32],
    pub server_names: Box<[Box<str>]>,
    pub short_ids: Box<[Box<[u8]>]>,
}

struct ClientHelloInfo {
    message: Vec<u8>,
    random: [u8; 32],
    session_id: [u8; 32],
    /// The X25519 public key the REALITY *tag* is authenticated against.
    ///
    /// The standalone `x25519` share when the hello carries one, otherwise the
    /// X25519 half of the hybrid share — the order REALITY's own server scan
    /// uses ("secondary choice: X25519 in X25519MLKEM768").
    auth_key_share: [u8; 32],
    /// The hybrid share, split into its two halves.
    ///
    /// These are kept apart from `auth_key_share` because they are genuinely
    /// different keys. Go's TLS client generates an independent ECDHE key for
    /// every group it offers, so the X25519 inside `X25519MLKEM768` is *not*
    /// the standalone `x25519` share. Deriving the TLS handshake secret from
    /// the wrong one produces a valid-looking hello, a completed ServerHello,
    /// and then a peer that cannot open a single record.
    hybrid: Option<HybridShare>,
    sni: String,
    suite: CipherSuite,
}

/// A client `X25519MLKEM768` key share.
struct HybridShare {
    /// ML-KEM-768 encapsulation key (1184 bytes).
    mlkem_key: Vec<u8>,
    /// The X25519 public key that follows it, used for this group's ECDH.
    x25519: [u8; 32],
}

/// Result of the first REALITY inspection. The fallback arm preserves the
/// socket and the exact record bytes already consumed from it.
///
/// `Accepted` is deliberately unboxed even though it dwarfs the other arms:
/// the outcome is produced once per connection and destructured immediately,
/// so the size costs one move, while boxing would add a heap allocation to
/// every accepted connection and change the type callers match on.
#[allow(clippy::large_enum_variant)]
pub enum HandshakeOutcome<S> {
    Accepted(Tls13Stream<S>),
    Fallback {
        stream: S,
        client_hello: Vec<u8>,
        failure: Failure,
    },
    Rejected(Failure),
}

pub async fn handshake<S>(io: S, params: &RealityServerParams) -> Result<Tls13Stream<S>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match handshake_or_fallback(io, params).await {
        HandshakeOutcome::Accepted(stream) => Ok(stream),
        HandshakeOutcome::Fallback { failure, .. } | HandshakeOutcome::Rejected(failure) => {
            Err(failure)
        }
    }
}

/// Perform the REALITY handshake while preserving a valid first record for a
/// fallback site when the connection is ordinary TLS or has the wrong REALITY
/// credentials.
pub async fn handshake_or_fallback<S>(
    mut io: S,
    params: &RealityServerParams,
) -> HandshakeOutcome<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (client_hello, message) = match read_client_hello_record(&mut io).await {
        Ok(ClientHelloRead::Complete { record, message }) => (record, message),
        Ok(ClientHelloRead::NotTls { consumed, failure }) => {
            // Not a ClientHello at all: exactly what REALITY forwards to the
            // target untouched. Dropping it instead would answer an active
            // probe differently from the decoy site.
            return HandshakeOutcome::Fallback {
                stream: io,
                client_hello: consumed,
                failure,
            };
        }
        Err(failure) => return HandshakeOutcome::Rejected(failure),
    };
    let hello = match parse_client_hello(message) {
        Ok(hello) => hello,
        Err(failure) => {
            return HandshakeOutcome::Fallback {
                stream: io,
                client_hello,
                failure,
            }
        }
    };
    if !params
        .server_names
        .iter()
        .any(|name| name.eq_ignore_ascii_case(&hello.sni))
    {
        return HandshakeOutcome::Fallback {
            stream: io,
            client_hello,
            failure: reality_error("ClientHello SNI is not allowed"),
        };
    }

    let shared = x25519_dalek::x25519(params.private_key, hello.auth_key_share);
    if shared.iter().all(|byte| *byte == 0) {
        return HandshakeOutcome::Fallback {
            stream: io,
            client_hello,
            failure: reality_error("REALITY X25519 shared secret is degenerate"),
        };
    }
    let auth_key = derive_auth_key(&shared, &hello.random[..20]);
    let aad = match zero_session_id(&hello.message) {
        Ok(aad) => aad,
        Err(failure) => {
            return HandshakeOutcome::Fallback {
                stream: io,
                client_hello,
                failure,
            }
        }
    };
    let plaintext =
        match decrypt_session_id(&auth_key, &hello.random[20..], &hello.session_id, &aad) {
            Ok(plaintext) => plaintext,
            Err(failure) => {
                return HandshakeOutcome::Fallback {
                    stream: io,
                    client_hello,
                    failure,
                }
            }
        };
    // Fold over every configured id without short-circuiting: the shortId is
    // the actual secret gate (anyone with the public key can produce a valid
    // seal), so its comparison must not leak through timing.
    let authorised = params.short_ids.iter().fold(Choice::from(0), |acc, short| {
        acc | short_id_matches(&plaintext[8..16], short)
    });
    if !bool::from(authorised) {
        return HandshakeOutcome::Fallback {
            stream: io,
            client_hello,
            failure: reality_error("REALITY shortId is not authorised"),
        };
    }

    match complete_handshake(io, hello, auth_key).await {
        Ok(stream) => HandshakeOutcome::Accepted(stream),
        Err(failure) => HandshakeOutcome::Rejected(failure),
    }
}

async fn complete_handshake<S>(
    mut io: S,
    hello: ClientHelloInfo,
    auth_key: [u8; 32],
) -> Result<Tls13Stream<S>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut server_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut server_seed);
    let server_seed = zeroize::Zeroizing::new(server_seed);
    let server_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*server_seed)).to_bytes();
    let (server_share, mut handshake_shared) = if let Some(hybrid) = hello.hybrid {
        // The hybrid group's ECDH uses the X25519 key carried *inside* that
        // share, not the standalone one the REALITY tag was checked against.
        let x25519_shared = x25519_dalek::x25519(*server_seed, hybrid.x25519);
        let key_bytes = hybrid
            .mlkem_key
            .as_slice()
            .try_into()
            .map_err(|_| reality_error("ML-KEM-768 public key has the wrong length"))?;
        let key = EncapsulationKey768::new(&key_bytes)
            .map_err(|_| reality_error("ML-KEM-768 public key is invalid"))?;
        let (ciphertext, mlkem_shared) = key.encapsulate();
        let ciphertext_bytes: &[u8] = ciphertext.as_ref();
        let mlkem_shared_bytes: &[u8] = mlkem_shared.as_ref();
        let mut share = Vec::with_capacity(ciphertext_bytes.len() + server_public.len());
        share.extend_from_slice(ciphertext_bytes);
        share.extend_from_slice(&server_public);
        let mut shared = Vec::with_capacity(mlkem_shared_bytes.len() + x25519_shared.len());
        shared.extend_from_slice(mlkem_shared_bytes);
        shared.extend_from_slice(&x25519_shared);
        (share, shared)
    } else {
        let x25519_shared = x25519_dalek::x25519(*server_seed, hello.auth_key_share);
        (server_public.to_vec(), x25519_shared.to_vec())
    };

    let group = if server_share.len() == 1088 + 32 {
        0x11ec
    } else {
        0x001d
    };
    let server_hello = build_server_hello(&hello.session_id, hello.suite, group, &server_share);
    write_clear_record(&mut io, &server_hello).await?;

    let mut transcript = Transcript::new(hello.suite.hash);
    transcript.update(&hello.message);
    transcript.update(&server_hello);
    let schedule =
        establish_handshake_secrets(hello.suite, &handshake_shared, &transcript.snapshot());
    handshake_shared.zeroize();

    let mut signing_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut signing_seed);
    let signing = SigningKey::from_bytes(&signing_seed);
    signing_seed.zeroize();
    let certificate = reality_certificate(&signing, &auth_key, &hello.sni);
    let encrypted_flight = build_encrypted_flight(
        hello.suite,
        &schedule.server_hs_traffic,
        &mut transcript,
        &certificate,
        &signing,
    )?;
    io.write_all(&encrypted_flight)
        .await
        .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
    io.flush()
        .await
        .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;

    let client_finished =
        read_encrypted_handshake(&mut io, hello.suite, &schedule.client_hs_traffic).await?;
    let expected = finished_verify_data(
        hello.suite.hash,
        &schedule.client_hs_traffic,
        &transcript.snapshot(),
    );
    if !bool::from(client_finished.ct_eq(expected.as_slice())) {
        return Err(reality_error("client Finished verification failed"));
    }
    // Application traffic secrets are derived from the transcript through
    // the server Finished.  The client Finished is sent under the handshake
    // traffic secret but is not part of the transcript input to the
    // application traffic key schedule (RFC 8446 §7.1).
    let (client_app, server_app) = establish_application_secrets(&schedule, &transcript.snapshot());
    Ok(Tls13Stream::new(io, hello.suite, client_app, server_app))
}

fn derive_auth_key(shared: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), shared);
    let mut key = [0u8; 32];
    hk.expand(b"REALITY", &mut key).expect("fixed HKDF output");
    key
}

fn decrypt_session_id(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8; 32],
    aad: &[u8],
) -> Result<[u8; 16], Failure> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("fixed AES key");
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| reality_error("REALITY session seal did not verify"))?;
    plain
        .try_into()
        .map_err(|_| reality_error("REALITY session plaintext has the wrong length"))
}

/// Constant-time check that `sealed` equals `configured` left-aligned and
/// zero-padded to eight bytes.
fn short_id_matches(sealed: &[u8], configured: &[u8]) -> Choice {
    if sealed.len() != 8 || configured.len() > 8 {
        // Lengths are public configuration, not secrets.
        return Choice::from(0);
    }
    let mut padded = [0u8; 8];
    padded[..configured.len()].copy_from_slice(configured);
    sealed.ct_eq(&padded)
}

fn zero_session_id(message: &[u8]) -> Result<Vec<u8>, Failure> {
    if message.len() < 71 || message[0] != 1 || message[38] != 32 {
        return Err(reality_error("malformed REALITY ClientHello session id"));
    }
    let mut zeroed = message.to_vec();
    zeroed[39..71].fill(0);
    Ok(zeroed)
}

/// Go's limit on one handshake message (crypto/tls `maxHandshake`).
const MAX_CLIENT_HELLO: usize = 65536;

enum ClientHelloRead {
    /// The complete ClientHello message and every record byte consumed.
    Complete { record: Vec<u8>, message: Vec<u8> },
    /// The peer is not speaking TLS; `consumed` must be replayed verbatim.
    NotTls { consumed: Vec<u8>, failure: Failure },
}

/// Read one ClientHello handshake message, reassembling it if the client
/// fragmented it across several records — which a client using TLS-hello
/// fragmentation against DPI does, and which Go's REALITY server accepts.
async fn read_client_hello_record<S>(io: &mut S) -> Result<ClientHelloRead, Failure>
where
    S: AsyncRead + Unpin,
{
    let mut record = Vec::new();
    let mut message = Vec::new();
    loop {
        let mut header = [0u8; 5];
        io.read_exact(&mut header)
            .await
            .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
        record.extend_from_slice(&header);
        let length = match parse_header(&header) {
            Ok((super::record::CONTENT_HANDSHAKE, length)) => length,
            Ok(_) => {
                return Ok(ClientHelloRead::NotTls {
                    consumed: record,
                    failure: reality_error("REALITY expected a cleartext ClientHello"),
                })
            }
            Err(failure) => {
                return Ok(ClientHelloRead::NotTls {
                    consumed: record,
                    failure,
                })
            }
        };
        let body_at = record.len();
        record.resize(body_at + length, 0);
        io.read_exact(&mut record[body_at..])
            .await
            .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
        message.extend_from_slice(&record[body_at..]);
        if length == 0 {
            // RFC 8446 §5.1 forbids empty handshake fragments.
            return Ok(ClientHelloRead::NotTls {
                consumed: record,
                failure: reality_error("empty handshake record"),
            });
        }
        if message.len() < 4 {
            continue;
        }
        let need = 4
            + (((message[1] as usize) << 16) | ((message[2] as usize) << 8) | message[3] as usize);
        if need > MAX_CLIENT_HELLO {
            return Ok(ClientHelloRead::NotTls {
                consumed: record,
                failure: reality_error("ClientHello exceeds the handshake size limit"),
            });
        }
        if message.len() >= need {
            // Anything past `need` is caught by `parse_client_hello`'s
            // length-consistency check and falls back.
            return Ok(ClientHelloRead::Complete { record, message });
        }
    }
}

fn parse_client_hello(message: Vec<u8>) -> Result<ClientHelloInfo, Failure> {
    if message.len() < 4 || message[0] != 1 {
        return Err(reality_error("first handshake message is not ClientHello"));
    }
    let body_len =
        ((message[1] as usize) << 16) | ((message[2] as usize) << 8) | message[3] as usize;
    if body_len + 4 != message.len() {
        return Err(reality_error("ClientHello length is inconsistent"));
    }
    let mut at = 4 + 2;
    let random: [u8; 32] = message
        .get(at..at + 32)
        .ok_or_else(|| reality_error("ClientHello random is truncated"))?
        .try_into()
        .unwrap();
    at += 32;
    let sid_len = *message
        .get(at)
        .ok_or_else(|| reality_error("ClientHello session id is truncated"))?
        as usize;
    at += 1;
    if sid_len != 32 || at + sid_len > message.len() {
        return Err(reality_error("REALITY requires a 32-byte session id"));
    }
    let session_id = message[at..at + 32].try_into().unwrap();
    at += 32;
    let suites_len = u16::from_be_bytes(take2(&message, at, "cipher suites")?) as usize;
    at += 2;
    let suites_end = at + suites_len;
    if suites_end > message.len() || !suites_len.is_multiple_of(2) {
        return Err(reality_error("ClientHello cipher suites are truncated"));
    }
    let mut suite = None;
    let (pairs, remainder) = message[at..suites_end].as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for pair in pairs {
        if let Some(candidate) = CipherSuite::by_id(u16::from_be_bytes([pair[0], pair[1]])) {
            suite.get_or_insert(candidate);
        }
    }
    let suite = suite.ok_or_else(|| reality_error("ClientHello has no supported TLS 1.3 suite"))?;
    at = suites_end;
    let compression_len = *message
        .get(at)
        .ok_or_else(|| reality_error("ClientHello compression is truncated"))?
        as usize;
    at += 1 + compression_len;
    let ext_len = u16::from_be_bytes(take2(&message, at, "extensions")?) as usize;
    at += 2;
    let end = at + ext_len;
    if end > message.len() {
        return Err(reality_error("ClientHello extensions are truncated"));
    }
    let mut sni = None;
    let mut auth_key_share = None;
    let mut hybrid = None;
    while at + 4 <= end {
        let typ = u16::from_be_bytes([message[at], message[at + 1]]);
        let len = u16::from_be_bytes([message[at + 2], message[at + 3]]) as usize;
        at += 4;
        let body = message
            .get(at..at + len)
            .ok_or_else(|| reality_error("ClientHello extension body is truncated"))?;
        at += len;
        if typ == 0 {
            sni = parse_sni(body);
        } else if typ == 51 {
            let (x25519, parsed_hybrid) = parse_key_shares(body);
            auth_key_share = x25519;
            hybrid = parsed_hybrid;
        }
    }
    Ok(ClientHelloInfo {
        message,
        random,
        session_id,
        auth_key_share: auth_key_share
            .ok_or_else(|| reality_error("ClientHello has no X25519 key share"))?,
        hybrid,
        sni: sni.ok_or_else(|| reality_error("ClientHello has no SNI"))?,
        suite,
    })
}

fn take2(buf: &[u8], at: usize, what: &'static str) -> Result<[u8; 2], Failure> {
    buf.get(at..at + 2)
        .ok_or_else(|| reality_error(format!("{what} are truncated")))
        .map(|v| [v[0], v[1]])
}

fn parse_sni(body: &[u8]) -> Option<String> {
    if body.len() < 5 {
        return None;
    }
    let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if list_len + 2 > body.len() || body[2] != 0 {
        return None;
    }
    let name_len = u16::from_be_bytes([body[3], body[4]]) as usize;
    std::str::from_utf8(body.get(5..5 + name_len)?)
        .ok()
        .map(str::to_string)
}

/// Split a `key_share` extension into the standalone X25519 share and the
/// hybrid share.
///
/// Both are returned because REALITY uses them for different things: the tag
/// is authenticated against the standalone share when there is one, while the
/// TLS handshake secret comes from whichever group the server selects.
fn parse_key_shares(body: &[u8]) -> (Option<[u8; 32]>, Option<HybridShare>) {
    if body.len() < 2 {
        return (None, None);
    }
    let total = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut at = 2;
    let mut x25519 = None;
    let mut hybrid = None;
    while at + 4 <= body.len() && at - 2 < total {
        let group = u16::from_be_bytes([body[at], body[at + 1]]);
        let len = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        at += 4;
        let share = match body.get(at..at + len) {
            Some(share) => share,
            None => break,
        };
        if group == 0x001d && len == 32 {
            x25519 = share.try_into().ok();
        } else if group == 0x11ec && len == 1216 {
            if let Ok(tail) = share[1184..].try_into() {
                hybrid = Some(HybridShare {
                    mlkem_key: share[..1184].to_vec(),
                    x25519: tail,
                });
            }
        }
        at += len;
    }
    // "Secondary choice: X25519 in X25519MLKEM768" — a hello that offers only
    // the hybrid still authenticates, against the key inside it.
    if x25519.is_none() {
        if let Some(share) = hybrid.as_ref() {
            x25519 = Some(share.x25519);
        }
    }
    (x25519, hybrid)
}

fn build_server_hello(
    session_id: &[u8; 32],
    suite: CipherSuite,
    group: u16,
    key: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&suite.id.to_be_bytes());
    body.push(0);
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0, 43, 0, 2, 3, 4]);
    extensions.extend_from_slice(&[0, 51]);
    extensions.extend_from_slice(&((4 + key.len()) as u16).to_be_bytes());
    extensions.extend_from_slice(&group.to_be_bytes());
    extensions.extend_from_slice(&(key.len() as u16).to_be_bytes());
    extensions.extend_from_slice(key);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    handshake_message(2, &body)
}

async fn write_clear_record<S>(io: &mut S, message: &[u8]) -> Result<(), Failure>
where
    S: AsyncWrite + Unpin,
{
    let header = record_header(CONTENT_HANDSHAKE, message.len());
    io.write_all(&header)
        .await
        .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
    io.write_all(message)
        .await
        .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
    Ok(())
}

fn build_encrypted_flight(
    suite: CipherSuite,
    secret: &[u8],
    transcript: &mut Transcript,
    certificate: &[u8],
    signing: &SigningKey,
) -> Result<Vec<u8>, Failure> {
    // EncryptedExtensions is a vector, even when no extensions are selected.
    // The two-byte zero length is required by RFC 8446 §4.4.2 and by Go's
    // TLS parser; an empty handshake body is not a valid message.
    let ee = handshake_message(8, &[0, 0]);
    let cert = certificate_message(certificate);
    let mut out = Vec::new();
    let mut crypter = RecordCrypter::new(suite, secret);
    transcript.update(&ee);
    out.extend_from_slice(&crypter.seal(&ee, CONTENT_HANDSHAKE)?.bytes);
    transcript.update(&cert);
    out.extend_from_slice(&crypter.seal(&cert, CONTENT_HANDSHAKE)?.bytes);
    let signed = certificate_verify_input(transcript.snapshot());
    let signature = signing.sign(&signed);
    let mut cv_body = Vec::with_capacity(68);
    cv_body.extend_from_slice(&0x0807u16.to_be_bytes());
    cv_body.extend_from_slice(&64u16.to_be_bytes());
    cv_body.extend_from_slice(&signature.to_bytes());
    let cv = handshake_message(15, &cv_body);
    transcript.update(&cv);
    out.extend_from_slice(&crypter.seal(&cv, CONTENT_HANDSHAKE)?.bytes);
    let verify = finished_verify_data(suite.hash, secret, &transcript.snapshot());
    let finished = handshake_message(20, &verify);
    transcript.update(&finished);
    out.extend_from_slice(&crypter.seal(&finished, CONTENT_HANDSHAKE)?.bytes);
    Ok(out)
}

async fn read_encrypted_handshake<S>(
    io: &mut S,
    suite: CipherSuite,
    secret: &[u8],
) -> Result<Vec<u8>, Failure>
where
    S: AsyncRead + Unpin,
{
    let mut crypter = RecordCrypter::new(suite, secret);
    loop {
        let mut header = [0u8; 5];
        io.read_exact(&mut header)
            .await
            .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
        let (kind, len) = parse_header(&header)?;
        let mut body = vec![0u8; len];
        io.read_exact(&mut body)
            .await
            .map_err(|error| Failure::from_io(&error, Stage::TlsStarted))?;
        if kind == CONTENT_CCS {
            // RFC 8446 §5.1 middlebox compatibility: a client may send a
            // cleartext 0x14/0x03.03/0x0001 record between ServerHello and
            // its encrypted Finished. It carries no transcript bytes.
            continue;
        }
        if kind != CONTENT_APPDATA {
            return Err(reality_error("client Finished is not encrypted"));
        }
        let (inner_type, plaintext_len) = crypter.open_in_place(&header, &mut body)?;
        body.truncate(plaintext_len);
        let plaintext = body;
        if inner_type != CONTENT_HANDSHAKE || plaintext.len() < 4 || plaintext[0] != 20 {
            return Err(reality_error(format!(
                "client did not send Finished (inner={inner_type:#04x}, plaintext_len={}, first={:02x?})",
                plaintext.len(),
                &plaintext[..plaintext.len().min(8)]
            )));
        }
        let len = ((plaintext[1] as usize) << 16)
            | ((plaintext[2] as usize) << 8)
            | plaintext[3] as usize;
        if len + 4 != plaintext.len() {
            return Err(reality_error("client Finished length is invalid"));
        }
        let mut finished = plaintext;
        finished.drain(..4);
        return Ok(finished);
    }
}

fn reality_certificate(signing: &SigningKey, auth_key: &[u8; 32], hostname: &str) -> Vec<u8> {
    let public = signing.verifying_key().to_bytes();
    let algorithm = der_sequence(&[0x06, 0x03, 0x2b, 0x65, 0x70]);
    let spki = der_sequence(&[algorithm.as_slice(), &der_bit_string(&public)].concat());
    let version = [0xa0, 0x03, 0x02, 0x01, 0x02];
    let serial = der_tlv(0x02, &[0x01]);
    let name = der_name(hostname);
    let signature_algorithm = algorithm.clone();
    let validity = der_sequence(
        &[
            der_tlv(0x17, b"250101000000Z"),
            der_tlv(0x17, b"500101000000Z"),
        ]
        .concat(),
    );
    // Keep all mandatory RFC 5280 fields present. REALITY replaces ordinary
    // certificate-chain verification with the HMAC below, but Xray's Go
    // parser still requires a structurally valid certificate.
    let tbs = der_sequence(
        &[
            version.as_slice(),
            serial.as_slice(),
            signature_algorithm.as_slice(),
            name.as_slice(),
            validity.as_slice(),
            name.as_slice(),
            spki.as_slice(),
        ]
        .concat(),
    );
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(auth_key).expect("fixed HMAC key");
    mac.update(&public);
    let signature = mac.finalize().into_bytes();
    let signature = der_bit_string(&signature);
    der_sequence(&[tbs.as_slice(), algorithm.as_slice(), signature.as_slice()].concat())
}

fn der_name(hostname: &str) -> Vec<u8> {
    let common_name = der_sequence(
        &[
            &[0x06, 0x03, 0x55, 0x04, 0x03][..],
            der_tlv(0x0c, hostname.as_bytes()).as_slice(),
        ]
        .concat(),
    );
    let set = der_tlv(0x31, &common_name);
    der_sequence(&set)
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(body);
    out
}

fn certificate_message(certificate: &[u8]) -> Vec<u8> {
    let mut body = vec![0];
    let mut list = Vec::with_capacity(3 + certificate.len() + 2);
    put_u24(&mut list, certificate.len());
    list.extend_from_slice(certificate);
    list.extend_from_slice(&[0, 0]);
    put_u24_at(&mut body, list.len());
    body.extend_from_slice(&list);
    handshake_message(11, &body)
}

fn certificate_verify_input(transcript_hash: Vec<u8>) -> Vec<u8> {
    let mut signed = Vec::with_capacity(64 + 34 + transcript_hash.len());
    signed.extend_from_slice(&[0x20; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0);
    signed.extend_from_slice(&transcript_hash);
    signed
}

fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(kind);
    put_u24(&mut message, body.len());
    message.extend_from_slice(body);
    message
}

fn put_u24(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&[(value >> 16) as u8, (value >> 8) as u8, value as u8]);
}

fn put_u24_at(out: &mut Vec<u8>, value: usize) {
    put_u24(out, value);
}

fn der_sequence(body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(body);
    out
}

fn der_bit_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x03];
    out.extend_from_slice(&der_len(data.len() + 1));
    out.push(0);
    out.extend_from_slice(data);
    out
}

fn der_len(length: usize) -> Vec<u8> {
    if length < 128 {
        vec![length as u8]
    } else {
        let bytes = (length as u32).to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
        let body = &bytes[first..];
        let mut out = vec![0x80 | body.len() as u8];
        out.extend_from_slice(body);
        out
    }
}

fn reality_error(detail: impl Into<String>) -> Failure {
    Failure::new(FailureKind::RealityFallback, Stage::TlsStarted)
        .with_confidence(Confidence::Confirmed)
        .with_detail(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::{HelloParams, PendingHello};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn reality_server_round_trips_application_data() {
        let private_key = [7u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key))
                .to_bytes();
        let server_params = RealityServerParams {
            private_key,
            server_names: vec![Box::from("example.test")].into_boxed_slice(),
            short_ids: vec![vec![0xaa, 0xbb, 0xcc, 0xdd].into_boxed_slice()].into_boxed_slice(),
        };
        let client_params = crate::reality::RealityParams::from_config(
            std::sync::Arc::from("example.test"),
            public_key,
            &[0xaa, 0xbb, 0xcc, 0xdd],
        )
        .with_hybrid_kem(true);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut stream = handshake(server_io, &server_params).await.unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut client = crate::reality::connect(client_io, &client_params)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    fn reality_pair(
        client_short_id: &[u8],
    ) -> (RealityServerParams, crate::reality::RealityParams) {
        let private_key = [7u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key))
                .to_bytes();
        let server_params = RealityServerParams {
            private_key,
            server_names: vec![Box::from("example.test")].into_boxed_slice(),
            short_ids: vec![
                vec![0x01].into_boxed_slice(),
                vec![0xaa, 0xbb, 0xcc, 0xdd].into_boxed_slice(),
            ]
            .into_boxed_slice(),
        };
        let client_params = crate::reality::RealityParams::from_config(
            std::sync::Arc::from("example.test"),
            public_key,
            client_short_id,
        );
        (server_params, client_params)
    }

    /// A client fragmenting its ClientHello into several TLS records (the
    /// `tlshello` fragment strategy) must still authenticate: Go's REALITY
    /// server reassembles the handshake message, and so must this one.
    #[tokio::test]
    async fn fragmented_client_hello_is_reassembled_and_accepted() {
        let (server_params, client_params) = reality_pair(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut stream = match handshake_or_fallback(server_io, &server_params).await {
                HandshakeOutcome::Accepted(stream) => stream,
                HandshakeOutcome::Fallback { failure, .. }
                | HandshakeOutcome::Rejected(failure) => {
                    panic!("fragmented hello was not accepted: {failure}")
                }
            };
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
        });
        let fragmented = zero_evasion::FragmentStream::new(
            client_io,
            zero_evasion::FragmentPolicy {
                interval_min_ms: 0,
                interval_max_ms: 0,
                ..Default::default()
            },
        );
        let mut client = crate::reality::connect(fragmented, &client_params)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unknown_short_id_falls_back() {
        let (server_params, client_params) = reality_pair(&[0xaa, 0xbb]);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client = tokio::spawn(async move {
            let _ = crate::reality::connect(client_io, &client_params).await;
        });
        match handshake_or_fallback(server_io, &server_params).await {
            HandshakeOutcome::Fallback { failure, .. } => {
                assert!(failure.to_string().contains("shortId"), "{failure}")
            }
            HandshakeOutcome::Accepted(_) => panic!("a prefix of a short id must not authorise"),
            HandshakeOutcome::Rejected(error) => panic!("expected fallback: {error}"),
        }
        client.abort();
    }

    #[test]
    fn short_id_matching_is_exact_and_zero_padded() {
        let sealed = [0xaa, 0xbb, 0, 0, 0, 0, 0, 0];
        assert!(bool::from(short_id_matches(&sealed, &[0xaa, 0xbb])));
        assert!(bool::from(short_id_matches(&sealed, &[0xaa, 0xbb, 0])));
        assert!(!bool::from(short_id_matches(&sealed, &[0xaa])));
        assert!(!bool::from(short_id_matches(&sealed, &[0xaa, 0xbc])));
        assert!(!bool::from(short_id_matches(&sealed, &[0; 9])));
        assert!(bool::from(short_id_matches(&[0; 8], &[])));
    }

    /// Non-TLS first bytes are REALITY's "forward to target" case, not a
    /// drop: the consumed bytes come back for replay.
    #[tokio::test]
    async fn non_tls_first_record_falls_back_with_the_consumed_bytes() {
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let (params, _) = reality_pair(&[0xaa]);
        match handshake_or_fallback(server, &params).await {
            HandshakeOutcome::Fallback { client_hello, .. } => assert_eq!(client_hello, b"GET /"),
            HandshakeOutcome::Accepted(_) => panic!("HTTP must not authenticate"),
            HandshakeOutcome::Rejected(error) => panic!("expected fallback: {error}"),
        }
    }

    #[tokio::test]
    async fn fallback_preserves_the_exact_client_hello_record() {
        let hello = PendingHello::new(&HelloParams::new("ordinary.example"));
        let mut record = record_header(CONTENT_HANDSHAKE, hello.msg.len()).to_vec();
        record[2] = 0x01;
        record.extend_from_slice(&hello.msg);
        let expected = record.clone();
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        client.write_all(&record).await.unwrap();
        client.flush().await.unwrap();

        let params = RealityServerParams {
            private_key: [7u8; 32],
            server_names: vec![Box::from("reality.example")].into_boxed_slice(),
            short_ids: vec![vec![1, 2, 3, 4].into_boxed_slice()].into_boxed_slice(),
        };
        match handshake_or_fallback(server, &params).await {
            HandshakeOutcome::Fallback { client_hello, .. } => assert_eq!(client_hello, expected),
            HandshakeOutcome::Accepted(_) => panic!("ordinary hello must not authenticate"),
            HandshakeOutcome::Rejected(error) => panic!("hello should be replayable: {error}"),
        }
    }
}
