//! The optional payload codecs the handshake can negotiate.
//!
//! The MasterDNS tunnel can compress the bytes it carries in either direction.
//! Which codec runs each way is picked once, in the handshake, and packed into
//! the single pair byte that [`zero_protocol::masterdns::compression`] knows
//! how to build and split. This module is the other half: the codecs
//! themselves, plus the two decisions the sender makes per payload —
//! [`compress_payload`] and [`try_decompress_payload`] — ported to behave
//! exactly like the Go server's `internal/compression` at the pinned release.
//!
//! Three formats, matched to the Go side byte-compatibly:
//!
//!  * **ZSTD** — a standard Zstandard frame. The Go server encodes at its
//!    fastest level; the level only changes the ratio, never whether the other
//!    end can decode it, so any valid frame interoperates.
//!  * **LZ4** — a raw LZ4 *block* (not the self-framed format) behind a
//!    4-byte little-endian length header. That header is the Go server's own
//!    convention (it mirrors Python's `lz4.block`), not part of LZ4, so it is
//!    written and read here by hand.
//!  * **ZLIB** — despite the name, raw DEFLATE with no zlib header or Adler
//!    checksum, which is what Go's `compress/flate` produces.
//!
//! The one rule that matters for safety: decompression is a place a hostile or
//! broken peer can hand you a few bytes that expand into gigabytes, so every
//! decoder here refuses to produce more than [`MAX_DECOMPRESSED_SIZE`] and the
//! DEFLATE path additionally refuses trailing garbage after the stream ends,
//! both exactly as the Go code does.

use std::borrow::Cow;

use flate2::Compression;
use zero_protocol::masterdns::compression::{
    normalize_available_type, DEFAULT_MIN_SIZE, TYPE_LZ4, TYPE_OFF, TYPE_ZLIB, TYPE_ZSTD,
};

/// Hard ceiling on any decompressed payload: 10 MiB, the same guard the Go
/// server uses. A compressed frame that would expand past this is rejected
/// rather than allocated, so a decompression bomb costs the peer nothing and
/// us nothing.
pub const MAX_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;

/// DEFLATE level for the ZLIB codec. The Go side writes at level 1 (fastest);
/// a decoder reads any level, so this is a speed choice, not a wire one.
const DEFLATE_LEVEL: u32 = 1;

/// ZSTD level for the ZSTD codec. `1` is the library's fastest positive level,
/// which is what the Go server's "fastest" setting maps to; as with DEFLATE it
/// does not affect decodability.
const ZSTD_LEVEL: i32 = 1;

/// Decide whether and how to compress one outbound payload, returning the
/// bytes to send and the codec id that was actually used (which the receiver
/// is told so it can reverse the right one).
///
/// This is the Go `CompressPayload`, decision for decision:
///
///  1. empty input is sent as-is, off;
///  2. a codec id that is off or unknown means send as-is, off;
///  3. a payload at or below `min_size` is not worth compressing (a zero
///     `min_size` means [`DEFAULT_MIN_SIZE`]);
///  4. if compression errors, or does not actually make the payload smaller,
///     the original is sent, off.
///
/// Only when a codec genuinely shrank the payload do we send the compressed
/// bytes and report that codec. The borrow in the common "send as-is" cases
/// means an incompressible payload is never copied just to be handed back.
pub fn compress_payload(data: &[u8], comp_type: u8, min_size: usize) -> (Cow<'_, [u8]>, u8) {
    if data.is_empty() {
        return (Cow::Borrowed(data), TYPE_OFF);
    }
    let comp_type = normalize_available_type(comp_type);
    if comp_type == TYPE_OFF {
        return (Cow::Borrowed(data), TYPE_OFF);
    }
    let min_size = if min_size == 0 {
        DEFAULT_MIN_SIZE
    } else {
        min_size
    };
    if data.len() <= min_size {
        return (Cow::Borrowed(data), TYPE_OFF);
    }

    let compressed = match comp_type {
        TYPE_ZLIB => deflate(data),
        TYPE_ZSTD => zstd_compress(data),
        TYPE_LZ4 => Some(lz4_compress(data)),
        _ => None,
    };

    match compressed {
        // A codec that did not beat the original is not worth the receiver's
        // decode cost, so fall back to sending it raw.
        Some(out) if out.len() < data.len() => (Cow::Owned(out), comp_type),
        _ => (Cow::Borrowed(data), TYPE_OFF),
    }
}

/// Reverse [`compress_payload`] on the receiving side: given the bytes and the
/// codec id the sender reported, return the original payload, or `None` if the
/// frame is corrupt or would decompress past [`MAX_DECOMPRESSED_SIZE`].
///
/// Mirrors the Go `TryDecompressPayload`: empty input and the off/unknown
/// codec both pass through untouched, so the only way to get `None` is a codec
/// that was named but could not decode its bytes.
pub fn try_decompress_payload(data: &[u8], comp_type: u8) -> Option<Cow<'_, [u8]>> {
    if data.is_empty() {
        return Some(Cow::Borrowed(data));
    }
    let comp_type = normalize_available_type(comp_type);
    if comp_type == TYPE_OFF {
        return Some(Cow::Borrowed(data));
    }
    let out = match comp_type {
        TYPE_ZLIB => inflate(data)?,
        TYPE_ZSTD => zstd_decompress(data)?,
        TYPE_LZ4 => lz4_decompress(data)?,
        _ => return Some(Cow::Borrowed(data)),
    };
    Some(Cow::Owned(out))
}

// --- ZLIB (raw DEFLATE) ----------------------------------------------------

/// Compress with raw DEFLATE (no zlib wrapper), matching Go's `compress/flate`.
/// Returns `None` only if the encoder itself fails, which for an in-memory
/// buffer does not happen in practice but is handled rather than panicked on.
fn deflate(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    let mut encoder = flate2::write::DeflateEncoder::new(
        Vec::with_capacity(data.len() / 2),
        Compression::new(DEFLATE_LEVEL),
    );
    encoder.write_all(data).ok()?;
    encoder.finish().ok()
}

/// Decompress raw DEFLATE with the two guards the Go side keeps: the output is
/// capped at [`MAX_DECOMPRESSED_SIZE`], and every input byte must belong to the
/// stream — trailing bytes after the end marker are an error, not ignored.
///
/// The reader's `total_in` reports exactly how many compressed bytes the
/// decoder consumed to reach the end of the stream; comparing it against the
/// input length is how trailing garbage is caught without a hand-rolled loop.
fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    let mut out = Vec::new();
    // Read one byte past the cap so an over-large payload is detected rather
    // than silently truncated to exactly the cap. A truncated or corrupt
    // stream surfaces as a read error here and becomes `None`.
    decoder
        .by_ref()
        .take(MAX_DECOMPRESSED_SIZE as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    if out.len() > MAX_DECOMPRESSED_SIZE {
        return None;
    }
    // Trailing bytes after the DEFLATE stream are rejected, as in Go.
    if decoder.total_in() as usize != data.len() {
        return None;
    }
    Some(out)
}

// --- ZSTD ------------------------------------------------------------------

/// Compress into a standard Zstandard frame. `None` on encoder error.
fn zstd_compress(data: &[u8]) -> Option<Vec<u8>> {
    zstd::bulk::compress(data, ZSTD_LEVEL).ok()
}

/// Decompress a Zstandard frame, capped at [`MAX_DECOMPRESSED_SIZE`]. Unlike
/// the DEFLATE path, the Go side does not reject trailing bytes here, so this
/// does not either.
fn zstd_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let decoder = zstd::stream::read::Decoder::new(data).ok()?;
    let mut out = Vec::new();
    // Read one byte past the cap so an over-large payload is detected rather
    // than silently truncated to exactly the cap.
    decoder
        .take(MAX_DECOMPRESSED_SIZE as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    if out.len() > MAX_DECOMPRESSED_SIZE {
        return None;
    }
    Some(out)
}

// --- LZ4 (raw block + 4-byte little-endian length header) ------------------

/// Compress to a raw LZ4 block prefixed with the uncompressed length as a
/// 4-byte little-endian integer, matching the Go server's `compressLZ4`. The
/// header lets the decoder size its output buffer exactly, the way Go's
/// `lz4.UncompressBlock` needs.
fn lz4_compress(data: &[u8]) -> Vec<u8> {
    let block = lz4_flex::block::compress(data);
    let mut out = Vec::with_capacity(4 + block.len());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&block);
    out
}

/// Reverse [`lz4_compress`]: read the 4-byte length header, refuse anything
/// over [`MAX_DECOMPRESSED_SIZE`], decode the block into a buffer of exactly
/// that size, and insist the decoder produced exactly that many bytes.
fn lz4_decompress(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 4 {
        return None;
    }
    let orig_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if orig_size > MAX_DECOMPRESSED_SIZE {
        return None;
    }
    let out = lz4_flex::block::decompress(&data[4..], orig_size).ok()?;
    if out.len() != orig_size {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests;
