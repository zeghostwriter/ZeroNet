//! A minimal TLS 1.3 client substrate for REALITY.
//!
//! This is *not* a general TLS library (PLAN-01 Decision 2). It exists for one
//! purpose: emit a byte-controlled ClientHello — the session-id and the
//! key-share must be ours, not the backend's — and then complete a standard
//! TLS 1.3 handshake and record layer against whatever answers. Ordinary TLS
//! stays on rustls; this module must never be offered for it.
//!
//! Scope, deliberately narrow:
//!
//! * one full handshake, no PSK/resumption, no 0-RTT, no client auth,
//! * the three RFC 8446 cipher suites, no TLS 1.2,
//! * no HelloRetryRequest — the hello offers X25519 and a conforming server
//!   that accepts it does not need to retry,
//! * post-handshake records (session tickets, KeyUpdate, dummy CCS, empty
//!   app-data mimicry) are tolerated, never fatal.
//!
//! The wire behavior is specified in `docs/specs/tls13-core.md`, verified
//! against the Go TLS fork Xray's REALITY servers actually run.

pub mod cert;
pub mod client;
pub mod hello;
pub mod kdf;
pub mod record;
pub mod server;

pub use client::{handshake, PendingHello, ServerAuth, Tls13Stream};
pub use hello::HelloParams;

use zero_core::{Failure, FailureKind, Stage};

/// The hash a cipher suite runs its key schedule on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    /// Output length in bytes; the HKDF L for this suite.
    pub(crate) fn len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }

    fn empty_hash(self) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => {
                use sha2::{Digest, Sha256};
                Sha256::digest([]).to_vec()
            }
            HashAlg::Sha384 => {
                use sha2::{Digest, Sha384};
                Sha384::digest([]).to_vec()
            }
        }
    }
}

/// Which AEAD protects the records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlg {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadAlg {
    pub fn key_len(self) -> usize {
        match self {
            AeadAlg::Aes128Gcm => 16,
            AeadAlg::Aes256Gcm | AeadAlg::ChaCha20Poly1305 => 32,
        }
    }
}

/// A TLS 1.3 cipher suite we can complete a handshake with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuite {
    pub id: u16,
    pub hash: HashAlg,
    pub aead: AeadAlg,
}

impl CipherSuite {
    pub const TLS_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        id: 0x1301,
        hash: HashAlg::Sha256,
        aead: AeadAlg::Aes128Gcm,
    };
    pub const TLS_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        id: 0x1302,
        hash: HashAlg::Sha384,
        aead: AeadAlg::Aes256Gcm,
    };
    pub const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        id: 0x1303,
        hash: HashAlg::Sha256,
        aead: AeadAlg::ChaCha20Poly1305,
    };

    pub fn by_id(id: u16) -> Option<CipherSuite> {
        Some(match id {
            0x1301 => Self::TLS_AES_128_GCM_SHA256,
            0x1302 => Self::TLS_AES_256_GCM_SHA384,
            0x1303 => Self::TLS_CHACHA20_POLY1305_SHA256,
            _ => return None,
        })
    }

    /// Suites in offer order, matching Chrome's preference.
    pub const OFFERED: [CipherSuite; 3] = [
        Self::TLS_AES_128_GCM_SHA256,
        Self::TLS_AES_256_GCM_SHA384,
        Self::TLS_CHACHA20_POLY1305_SHA256,
    ];
}

/// Maximum plaintext carried by one TLS 1.3 record (RFC 8446 §5.2).
pub const MAX_PLAINTEXT: usize = 16384;
/// Maximum on-wire ciphertext: plaintext + inner type + worst-case padding
/// room + 16-byte tag. Records beyond this are a protocol violation.
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;

/// A `usize` window that is either fully inside the buffer or a parse error.
pub(crate) fn take<'a>(
    buf: &'a [u8],
    at: usize,
    len: usize,
    what: &'static str,
) -> Result<&'a [u8], Failure> {
    buf.get(at..at + len).ok_or_else(|| truncated(what))
}

pub(crate) fn truncated(what: &'static str) -> Failure {
    Failure::new(FailureKind::TlsHandshakeMalformed, Stage::TlsStarted)
        .with_confidence(zero_core::Confidence::Confirmed)
        .with_detail(format!("truncated while reading {what}"))
}

pub(crate) fn malformed(what: impl Into<String>) -> Failure {
    Failure::new(FailureKind::TlsHandshakeMalformed, Stage::TlsStarted)
        .with_confidence(zero_core::Confidence::Confirmed)
        .with_detail(what)
}
