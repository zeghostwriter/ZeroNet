//! Compression vocabulary: the type ids the two ends agree on, and the single
//! byte that carries both directions' choices through the handshake.
//!
//! Ported from the pure part of the Go `internal/compression` at the pinned
//! release `v2026.06.13.234407-7de2476`. Only the classification and the
//! upload/download pairing live here, because those are what the wire format
//! needs and they carry no dependency. The actual deflate/zstd/lz4 codecs are
//! a separate concern that belongs with the live transport, where pulling in
//! those crates is paid for once.
//!
//! The pairing rule: a SESSION_INIT asks for an upload codec and a download
//! codec, and a SESSION_ACCEPT answers with the pair the server settled on,
//! both squeezed into one byte — upload in the high nibble, download in the
//! low. [`pack_pair`] builds that byte and [`split_pair`] takes it apart, and
//! both fold anything they do not recognise down to [`TYPE_OFF`] so a bad or
//! future id can never be mistaken for a real codec.

/// No compression: the payload is sent verbatim.
pub const TYPE_OFF: u8 = 0;
/// Zstandard.
pub const TYPE_ZSTD: u8 = 1;
/// LZ4 block format, with a 4-byte little-endian size prefix.
pub const TYPE_LZ4: u8 = 2;
/// Raw DEFLATE (what the Go side calls ZLIB; no zlib header or checksum).
pub const TYPE_ZLIB: u8 = 3;

/// Default smallest payload the server will bother compressing, in bytes.
pub const DEFAULT_MIN_SIZE: usize = 100;

/// The highest id that names a real codec. Everything above folds to off.
const MAX_TYPE: u8 = TYPE_ZLIB;

/// Fold a type id to a known codec, or [`TYPE_OFF`] if it names nothing. This
/// is the mask check the Go `NormalizeAvailableType` does: ids 0..=3 are the
/// four built in codecs and pass through, everything else becomes off.
pub fn normalize_available_type(value: u8) -> u8 {
    // The available set is exactly {off, zstd, lz4, zlib} = ids 0..=3, so the
    // mask test and the range test agree; the range test is cheaper.
    if value <= MAX_TYPE {
        value
    } else {
        TYPE_OFF
    }
}

/// Human name for a codec id, for logs. Unknown ids read as `OFF`.
pub fn type_name(value: u8) -> &'static str {
    match normalize_available_type(value) {
        TYPE_ZSTD => "ZSTD",
        TYPE_LZ4 => "LZ4",
        TYPE_ZLIB => "ZLIB",
        _ => "OFF",
    }
}

/// Pack an upload and a download codec id into the one byte the handshake
/// carries: upload in the high nibble, download in the low. Either id that is
/// not a real codec is sent as [`TYPE_OFF`]. Mirrors the Go `PackPair`.
pub fn pack_pair(upload: u8, download: u8) -> u8 {
    let upload = if upload > MAX_TYPE { TYPE_OFF } else { upload };
    let download = if download > MAX_TYPE {
        TYPE_OFF
    } else {
        download
    };
    (upload << 4) | download
}

/// Split a packed byte back into `(upload, download)`, folding each nibble to a
/// known codec. Mirrors the Go `SplitPair`, including that an unknown nibble
/// reads as [`TYPE_OFF`] rather than erroring.
pub fn split_pair(value: u8) -> (u8, u8) {
    (
        normalize_nibble((value >> 4) & 0x0F),
        normalize_nibble(value & 0x0F),
    )
}

/// A single nibble (0..=15) folded to a known codec id. The Go side keeps a
/// 16-entry table for this; the first four entries are the identity and the
/// rest are off, which is exactly [`normalize_available_type`] on a nibble.
fn normalize_nibble(nibble: u8) -> u8 {
    normalize_available_type(nibble)
}
