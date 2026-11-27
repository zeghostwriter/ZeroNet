//! The SESSION_INIT request payload: what the client sends to open a session,
//! and the two reply-mode ids that go in its first byte.
//!
//! Ported from the Go client's `buildSessionInitPayload` at the pinned release
//! `v2026.06.13.234407-7de2476`. The reply (SESSION_ACCEPT / SESSION_BUSY)
//! lives in [`super::packet`]; this is only the request side.
//!
//! The payload is a fixed ten bytes:
//!
//! ```text
//!   [0]    reply mode    (0 = raw, 1 = base64 answers)
//!   [1]    compression   (packed upload/download pair, see super::compression)
//!   [2..4] upload MTU     (u16, big endian)
//!   [4..6] download MTU   (u16, big endian)
//!   [6..10] verify code   (4 random bytes the client picks)
//! ```
//!
//! The verify code is the whole point of the handshake's anti-spoofing: the
//! client makes up four random bytes, and only a reply that echoes them back
//! is believed. A SESSION_ACCEPT carries them in its verify field; a
//! SESSION_BUSY carries them as its first four payload bytes. Anything that
//! does not match is treated as noise, so a blind forged answer teaches an
//! attacker nothing.

use super::compression;

/// Fixed length of a SESSION_INIT payload, in bytes.
pub const SESSION_INIT_PAYLOAD_SIZE: usize = 10;

/// Length of the verify code the client picks and the server must echo.
pub const VERIFY_CODE_LEN: usize = 4;

/// Reply mode: the server answers with raw bytes in the TXT records.
pub const REPLY_MODE_RAW: u8 = 0;
/// Reply mode: the server answers with standard-base64 text in the TXT
/// records. The client asks for this when its config sets base-encoded data,
/// usually because a resolver on the path mangles non-text TXT bytes.
pub const REPLY_MODE_BASE64: u8 = 1;

/// Build the ten-byte SESSION_INIT payload.
///
/// `base64_reply` picks the reply mode byte; `upload`/`download` are the
/// requested compression codec ids (packed the way the handshake carries
/// them); `upload_mtu`/`download_mtu` are the probed MTUs; `verify` is the
/// four-byte code the client will insist the server echo.
///
/// The returned mode byte is also what the inbound path keys on to know
/// whether answers are base64, so callers keep it alongside the session.
pub fn build_session_init_payload(
    base64_reply: bool,
    upload: u8,
    download: u8,
    upload_mtu: u16,
    download_mtu: u16,
    verify: [u8; VERIFY_CODE_LEN],
) -> [u8; SESSION_INIT_PAYLOAD_SIZE] {
    let mut payload = [0u8; SESSION_INIT_PAYLOAD_SIZE];
    payload[0] = if base64_reply {
        REPLY_MODE_BASE64
    } else {
        REPLY_MODE_RAW
    };
    payload[1] = compression::pack_pair(upload, download);
    payload[2..4].copy_from_slice(&upload_mtu.to_be_bytes());
    payload[4..6].copy_from_slice(&download_mtu.to_be_bytes());
    payload[6..10].copy_from_slice(&verify);
    payload
}
