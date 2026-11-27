//! Payload preparation: the thin layer that joins packet building to the
//! optional compression codecs.
//!
//! [`zero_protocol::masterdns::packet`] builds and parses the raw wire bytes
//! but, on purpose, knows nothing about compression — it pulls in no codec
//! library so it can stay a pure, byte-exact description of the wire. The
//! codecs themselves live next door in [`crate::compress`]. This module is the
//! seam between the two: it decides whether an outbound payload is worth
//! compressing before it is framed, and it un-compresses an inbound payload
//! after it is parsed.
//!
//! Ported from the Go client's `internal/vpnproto/payload.go` at the pinned
//! release `v2026.06.13.234407-7de2476`, matching each decision exactly.
//!
//! The one subtlety worth knowing: compression is only ever attempted for the
//! packet types whose header actually carries the one compression byte (see
//! [`zero_protocol::masterdns::enums::has_compression`]). Asking to compress a
//! type that cannot record which codec it used would leave the receiver unable
//! to reverse it, so [`prepare_payload`] quietly sends those raw.

#[cfg(test)]
mod tests;

use std::borrow::Cow;

use zero_protocol::masterdns::compression::{normalize_available_type, TYPE_OFF};
use zero_protocol::masterdns::enums::has_compression;
use zero_protocol::masterdns::packet::{build_raw, BuildOptions, Packet, PacketError};

use crate::compress::{compress_payload, try_decompress_payload};

/// A compressed payload that could not be reversed. Mirrors the Go
/// `ErrInvalidCompressedPayload`: the only way an inflate fails is a codec that
/// was named in the header but whose bytes do not decode (corrupt frame, or one
/// that would expand past the decompression cap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCompressedPayload;

impl std::fmt::Display for InvalidCompressedPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid compressed vpn payload")
    }
}

impl std::error::Error for InvalidCompressedPayload {}

/// Decide whether to compress one outbound payload and with which codec, before
/// it is framed. Returns the bytes to put on the wire and the codec id to write
/// into the compression byte (so the receiver can reverse the right one).
///
/// Mirrors the Go `PreparePayload`, gate for gate: a requested codec of off or
/// unknown, a packet type that carries no compression byte, or an empty payload
/// all send the payload untouched as [`TYPE_OFF`]. Only otherwise does the
/// actual [`compress_payload`] decision run (which may still choose off if the
/// payload is too small or did not shrink).
///
/// The returned [`Cow`] borrows the input in every "send as-is" case, so an
/// incompressible payload is never copied just to be handed back.
pub fn prepare_payload(
    packet_type: u8,
    payload: &[u8],
    requested_compression: u8,
    min_size: usize,
) -> (Cow<'_, [u8]>, u8) {
    let requested = normalize_available_type(requested_compression);
    if requested == TYPE_OFF {
        return (Cow::Borrowed(payload), TYPE_OFF);
    }
    if !has_compression(packet_type) {
        return (Cow::Borrowed(payload), TYPE_OFF);
    }
    if payload.is_empty() {
        return (Cow::Borrowed(payload), TYPE_OFF);
    }
    compress_payload(payload, requested, min_size)
}

/// Build a raw packet, choosing compression automatically. This is
/// [`prepare_payload`] followed by [`build_raw`]: the payload and compression
/// byte in `opts` are the *requested* ones, and the function overrides them
/// with whatever `prepare_payload` actually decided before framing.
///
/// Mirrors the Go `BuildRawAuto`. `min_size` is the smallest payload worth
/// compressing (zero means the codec default).
pub fn build_raw_auto(opts: &BuildOptions, min_size: usize) -> Result<Vec<u8>, PacketError> {
    let (payload, compression_type) = prepare_payload(
        opts.packet_type,
        opts.payload,
        opts.compression_type,
        min_size,
    );
    let auto = BuildOptions {
        session_id: opts.session_id,
        packet_type: opts.packet_type,
        session_cookie: opts.session_cookie,
        stream_id: opts.stream_id,
        sequence_num: opts.sequence_num,
        fragment_id: opts.fragment_id,
        total_fragments: opts.total_fragments,
        compression_type,
        payload: &payload[..],
    };
    build_raw(&auto)
}

/// Reverse the compression a parsed packet recorded, returning its real
/// payload. A packet with no compression byte, or one that names [`TYPE_OFF`],
/// passes straight through (borrowing its bytes); any other codec is run and,
/// if its frame does not decode, the whole packet is rejected.
///
/// Mirrors the Go `InflatePayload`, which replaces the packet's payload in
/// place. Here the packet borrows its bytes immutably, so the inflated payload
/// is returned instead of written back; the caller uses it directly.
pub fn inflate_payload<'a>(packet: &Packet<'a>) -> Result<Cow<'a, [u8]>, InvalidCompressedPayload> {
    match packet.compression_type {
        None => Ok(Cow::Borrowed(packet.payload)),
        Some(ct) if ct == TYPE_OFF => Ok(Cow::Borrowed(packet.payload)),
        Some(ct) => try_decompress_payload(packet.payload, ct).ok_or(InvalidCompressedPayload),
    }
}
