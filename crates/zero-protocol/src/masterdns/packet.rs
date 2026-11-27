//! Building and parsing the raw MasterDnsVPN packet: the bytes that exist
//! after decryption and before encoding, or before encryption and after
//! decoding.
//!
//! Ported from the Go `internal/vpnproto` at the pinned release
//! `v2026.06.13.234407-7de2476`.
//!
//! A raw packet is a small header followed by an optional payload:
//!
//! ```text
//!   [0] session id      (1)
//!   [1] packet type     (1)
//!   -- optional, in this order, only the ones the type carries (see enums) --
//!   stream id           (2, big endian)
//!   sequence number     (2, big endian)
//!   fragment id, total  (1 + 1)
//!   compression type    (1)
//!   -- integrity footer --
//!   session cookie      (1)
//!   header check        (1)
//!   -- payload follows immediately --
//! ```
//!
//! The header check is a one-byte running mix over every header byte up to and
//! including the cookie (see [`header_check_byte`]). It is cheap and not a MAC;
//! its only job is to reject a label string that decoded to something that was
//! never one of our packets, before we hand the payload on. Authenticity comes
//! from the AES-GCM tag in [`super::codec`], not from this byte.
//!
//! This module also carries the two small packed structures the protocol
//! defines: the SESSION_ACCEPT payload and the packed-control-block list.

use super::codec::Codec;
use super::enums;

const INTEGRITY_LEN: usize = 2;
const MIN_HEADER_LEN: usize = 4;

/// What can go wrong turning bytes into a [`Packet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    /// Fewer bytes than the smallest possible header, or than this type needs.
    TooShort,
    /// The type byte is not one the protocol defines.
    InvalidType,
    /// The header-check byte did not match: these bytes were not one of ours.
    BadCheck,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            PacketError::TooShort => "vpn packet too short",
            PacketError::InvalidType => "invalid vpn packet type",
            PacketError::BadCheck => "invalid vpn header check",
        };
        f.write_str(text)
    }
}

impl std::error::Error for PacketError {}

/// The fields a caller sets to build one packet. Only the fields the packet
/// type actually carries are written; the rest are ignored. Build with struct
/// syntax over [`BuildOptions::default`] so new fields never silently change a
/// call site.
#[derive(Default)]
pub struct BuildOptions<'a> {
    pub session_id: u8,
    pub packet_type: u8,
    pub session_cookie: u8,
    pub stream_id: u16,
    pub sequence_num: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
    pub compression_type: u8,
    pub payload: &'a [u8],
}

/// A fragment extension: which fragment this is and how many there are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    pub id: u8,
    pub total: u8,
}

/// A parsed packet. The optional fields are present exactly when the type
/// carries them. `payload` borrows the input, so it costs nothing to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub session_id: u8,
    pub packet_type: u8,
    pub session_cookie: u8,
    pub stream_id: Option<u16>,
    pub sequence_num: Option<u16>,
    pub fragment: Option<Fragment>,
    pub compression_type: Option<u8>,
    pub header_length: usize,
    pub payload: &'a [u8],
}

/// The raw header length for a packet type, or `None` if the type is invalid.
fn header_len(flags: u8) -> usize {
    let mut len = 2 + INTEGRITY_LEN;
    if flags & enums::F_STREAM != 0 {
        len += 2;
    }
    if flags & enums::F_SEQUENCE != 0 {
        len += 2;
    }
    if flags & enums::F_FRAGMENT != 0 {
        len += 2;
    }
    if flags & enums::F_COMPRESSION != 0 {
        len += 1;
    }
    len
}

/// The raw header length for a packet type, or `0` if the type is not valid.
/// Mirrors Go `vpnproto.HeaderRawSize`: the number of bytes a packet of this
/// type spends on its header (base + the extensions it carries + the integrity
/// footer), before any payload. The MTU probe uses it to size the slack it can
/// ask the server to echo back.
pub fn header_raw_size(packet_type: u8) -> usize {
    let flags = enums::FLAGS[packet_type as usize];
    if flags & enums::F_VALID == 0 {
        return 0;
    }
    header_len(flags)
}

/// The largest header any valid packet type carries. Mirrors Go
/// `vpnproto.MaxHeaderRawSize`: a packet with all four extensions (stream,
/// sequence, fragment, compression) plus the base header and integrity footer,
/// which works out to 11 bytes. It is the upper bound the download-probe reserve
/// is measured against.
pub fn max_header_raw_size() -> usize {
    (0u16..=255)
        .map(|t| header_raw_size(t as u8))
        .max()
        .unwrap_or(0)
}

/// Serialize a packet to raw bytes (before encryption). Fails only if the
/// packet type is not valid.
pub fn build_raw(opts: &BuildOptions) -> Result<Vec<u8>, PacketError> {
    let flags = enums::FLAGS[opts.packet_type as usize];
    if flags & enums::F_VALID == 0 {
        return Err(PacketError::InvalidType);
    }

    let header = header_len(flags);
    let mut raw = vec![0u8; header + opts.payload.len()];
    raw[0] = opts.session_id;
    raw[1] = opts.packet_type;
    let mut offset = 2;

    if flags & enums::F_STREAM != 0 {
        raw[offset] = (opts.stream_id >> 8) as u8;
        raw[offset + 1] = opts.stream_id as u8;
        offset += 2;
    }
    if flags & enums::F_SEQUENCE != 0 {
        raw[offset] = (opts.sequence_num >> 8) as u8;
        raw[offset + 1] = opts.sequence_num as u8;
        offset += 2;
    }
    if flags & enums::F_FRAGMENT != 0 {
        raw[offset] = opts.fragment_id;
        raw[offset + 1] = opts.total_fragments;
        offset += 2;
    }
    if flags & enums::F_COMPRESSION != 0 {
        raw[offset] = opts.compression_type;
        offset += 1;
    }

    raw[offset] = opts.session_cookie;
    offset += 1;
    raw[offset] = header_check_byte(&raw[..offset]);
    offset += 1;
    raw[offset..].copy_from_slice(opts.payload);
    Ok(raw)
}

/// Build a packet and seal+encode it into a label string in one step.
pub fn build_encoded(opts: &BuildOptions, codec: &Codec) -> Result<String, PacketError> {
    Ok(codec.encrypt_and_encode(&build_raw(opts)?))
}

/// Parse raw bytes into a [`Packet`]. The borrow in the result keeps `data`
/// alive for as long as the packet is held.
pub fn parse(data: &[u8]) -> Result<Packet<'_>, PacketError> {
    if data.len() < MIN_HEADER_LEN {
        return Err(PacketError::TooShort);
    }

    let packet_type = data[1];
    let flags = enums::FLAGS[packet_type as usize];
    if flags & enums::F_VALID == 0 {
        return Err(PacketError::InvalidType);
    }

    let min_len = header_len(flags);
    if data.len() < min_len {
        return Err(PacketError::TooShort);
    }

    let mut offset = 2;
    let stream_id = if flags & enums::F_STREAM != 0 {
        let v = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        Some(v)
    } else {
        None
    };
    let sequence_num = if flags & enums::F_SEQUENCE != 0 {
        let v = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        Some(v)
    } else {
        None
    };
    let fragment = if flags & enums::F_FRAGMENT != 0 {
        let f = Fragment {
            id: data[offset],
            total: data[offset + 1],
        };
        offset += 2;
        Some(f)
    } else {
        None
    };
    let compression_type = if flags & enums::F_COMPRESSION != 0 {
        let v = data[offset];
        offset += 1;
        Some(v)
    } else {
        None
    };

    let session_cookie = data[offset];
    let check = data[offset + 1];
    let expected = header_check_byte(&data[..offset + 1]);
    if check != expected {
        return Err(PacketError::BadCheck);
    }

    let header_length = offset + INTEGRITY_LEN;
    Ok(Packet {
        session_id: data[0],
        packet_type,
        session_cookie,
        stream_id,
        sequence_num,
        fragment,
        compression_type,
        header_length,
        payload: &data[header_length..],
    })
}

/// The running one-byte header check over `header` (everything up to and
/// including the session cookie, never the check byte itself). Every step
/// wraps within a byte, exactly like the Go `computeHeaderCheckByte`.
pub fn header_check_byte(header: &[u8]) -> u8 {
    let mut acc = (header.len() as u8).wrapping_mul(17).wrapping_add(0x5D);
    for (idx, &value) in header.iter().enumerate() {
        acc = acc.wrapping_add(value).wrapping_add(idx as u8);
        acc ^= value << (idx & 0x03);
    }
    acc
}

// ---------------------------------------------------------------------------
// SESSION_ACCEPT payload.
// ---------------------------------------------------------------------------

/// Base payload size: id, cookie, compression pair, 4-byte verify code.
pub const SESSION_ACCEPT_BASE_SIZE: usize = 7;
/// Size of the optional policy block appended after the base payload.
pub const SESSION_ACCEPT_POLICY_SIZE: usize = 13;
/// Full payload size when the policy block is present.
pub const SESSION_ACCEPT_SIZE: usize = SESSION_ACCEPT_BASE_SIZE + SESSION_ACCEPT_POLICY_SIZE;

const SCALED_MIN: f64 = 0.05;
const SCALED_MAX: f64 = 1.0;

/// The server's SESSION_ACCEPT answer. The policy block is optional; when the
/// server does not send one, `client_policy` is `None` and only the first 7
/// bytes are on the wire.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SessionAcceptPayload {
    pub session_id: u8,
    pub session_cookie: u8,
    pub compression_pair: u8,
    pub verify_code: [u8; 4],
    pub client_policy: Option<SessionAcceptClientPolicy>,
}

/// Server-chosen limits the client must respect, carried in the optional
/// policy block. The two interval fields are seconds, stored on the wire as a
/// single byte scaled over `0.05..=1.00` (see [`encode_session_scaled_byte`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SessionAcceptClientPolicy {
    pub max_packet_duplication_count: i64,
    pub max_setup_duplication_count: i64,
    pub max_upload_mtu: i64,
    pub max_download_mtu: i64,
    pub max_rx_tx_workers: i64,
    pub min_ping_aggressive_interval: f64,
    pub max_packets_per_batch: i64,
    pub max_arq_window_size: i64,
    pub max_arq_data_nack_max_gap: i64,
    pub min_compression_min_size: i64,
    pub min_arq_initial_rto_seconds: f64,
}

/// Serialize a SESSION_ACCEPT payload. 7 bytes without a policy block, 20 with.
pub fn encode_session_accept_payload(p: &SessionAcceptPayload) -> Vec<u8> {
    let size = if p.client_policy.is_some() {
        SESSION_ACCEPT_SIZE
    } else {
        SESSION_ACCEPT_BASE_SIZE
    };
    let mut buf = vec![0u8; size];
    buf[0] = p.session_id;
    buf[1] = p.session_cookie;
    buf[2] = p.compression_pair;
    buf[3..7].copy_from_slice(&p.verify_code);
    if let Some(policy) = &p.client_policy {
        buf[SESSION_ACCEPT_BASE_SIZE..]
            .copy_from_slice(&encode_session_accept_client_policy(policy));
    }
    buf
}

/// Parse a SESSION_ACCEPT payload. The policy block is read only when the input
/// is long enough to hold it.
pub fn decode_session_accept_payload(payload: &[u8]) -> Result<SessionAcceptPayload, PacketError> {
    if payload.len() < SESSION_ACCEPT_BASE_SIZE {
        return Err(PacketError::TooShort);
    }
    let client_policy = if payload.len() >= SESSION_ACCEPT_SIZE {
        Some(decode_session_accept_client_policy(
            &payload[SESSION_ACCEPT_BASE_SIZE..SESSION_ACCEPT_SIZE],
        ))
    } else {
        None
    };
    Ok(SessionAcceptPayload {
        session_id: payload[0],
        session_cookie: payload[1],
        compression_pair: payload[2],
        verify_code: [payload[3], payload[4], payload[5], payload[6]],
        client_policy,
    })
}

fn encode_session_accept_client_policy(
    p: &SessionAcceptClientPolicy,
) -> [u8; SESSION_ACCEPT_POLICY_SIZE] {
    let mut out = [0u8; SESSION_ACCEPT_POLICY_SIZE];
    out[0] = ((clamp_i64(p.max_setup_duplication_count, 0, 15) << 4)
        | clamp_i64(p.max_packet_duplication_count, 0, 15)) as u8;
    out[1] = clamp_i64(p.max_upload_mtu, 0, 0xFF) as u8;
    out[2..4].copy_from_slice(&(clamp_i64(p.max_download_mtu, 0, 0xFFFF) as u16).to_be_bytes());
    out[4] = clamp_i64(p.max_rx_tx_workers, 0, 0xFF) as u8;
    out[5] = encode_session_scaled_byte(p.min_ping_aggressive_interval);
    out[6] = clamp_i64(p.max_packets_per_batch, 0, 0xFF) as u8;
    out[7..9].copy_from_slice(&(clamp_i64(p.max_arq_window_size, 0, 0xFFFF) as u16).to_be_bytes());
    out[9] = clamp_i64(p.max_arq_data_nack_max_gap, 0, 0xFF) as u8;
    out[10..12]
        .copy_from_slice(&(clamp_i64(p.min_compression_min_size, 0, 0xFFFF) as u16).to_be_bytes());
    out[12] = encode_session_scaled_byte(p.min_arq_initial_rto_seconds);
    out
}

fn decode_session_accept_client_policy(p: &[u8]) -> SessionAcceptClientPolicy {
    SessionAcceptClientPolicy {
        max_packet_duplication_count: (p[0] & 0x0F) as i64,
        max_setup_duplication_count: ((p[0] >> 4) & 0x0F) as i64,
        max_upload_mtu: p[1] as i64,
        max_download_mtu: u16::from_be_bytes([p[2], p[3]]) as i64,
        max_rx_tx_workers: p[4] as i64,
        min_ping_aggressive_interval: decode_session_scaled_byte(p[5]),
        max_packets_per_batch: p[6] as i64,
        max_arq_window_size: u16::from_be_bytes([p[7], p[8]]) as i64,
        max_arq_data_nack_max_gap: p[9] as i64,
        min_compression_min_size: u16::from_be_bytes([p[10], p[11]]) as i64,
        min_arq_initial_rto_seconds: decode_session_scaled_byte(p[12]),
    }
}

/// Encode a seconds value into one byte, mapping `0.05..=1.00` linearly onto
/// `0..=255` (values outside the range clamp to the ends). The inverse is
/// [`decode_session_scaled_byte`].
pub fn encode_session_scaled_byte(value: f64) -> u8 {
    let clamped = clamp_f64(value, SCALED_MIN, SCALED_MAX);
    let normalized = (clamped - SCALED_MIN) / (SCALED_MAX - SCALED_MIN);
    (normalized * 255.0).round() as u8
}

/// Decode a scaled byte back to seconds in `0.05..=1.00`.
pub fn decode_session_scaled_byte(value: u8) -> f64 {
    let normalized = value as f64 / 255.0;
    SCALED_MIN + normalized * (SCALED_MAX - SCALED_MIN)
}

fn clamp_i64(v: i64, lo: i64, hi: i64) -> i64 {
    v.clamp(lo, hi)
}

fn clamp_f64(v: f64, lo: f64, hi: f64) -> f64 {
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

// ---------------------------------------------------------------------------
// Packed control blocks (packet type PACKED_CONTROL_BLOCKS).
// ---------------------------------------------------------------------------

/// Each packed control block is a fixed 7 bytes.
pub const PACKED_CONTROL_BLOCK_SIZE: usize = 7;

/// One decoded control block from a PACKED_CONTROL_BLOCKS payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedControlBlock {
    pub packet_type: u8,
    pub stream_id: u16,
    pub sequence_num: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
}

/// Append one 7-byte control block to `dst`.
pub fn append_packed_control_block(
    dst: &mut Vec<u8>,
    packet_type: u8,
    stream_id: u16,
    sequence_num: u16,
    fragment_id: u8,
    total_fragments: u8,
) {
    dst.push(packet_type);
    dst.push((stream_id >> 8) as u8);
    dst.push(stream_id as u8);
    dst.push((sequence_num >> 8) as u8);
    dst.push(sequence_num as u8);
    dst.push(fragment_id);
    dst.push(total_fragments);
}

/// Walk a PACKED_CONTROL_BLOCKS payload block by block. A trailing partial
/// block (fewer than 7 bytes) is ignored, matching the server.
pub fn iter_packed_control_blocks(payload: &[u8]) -> impl Iterator<Item = PackedControlBlock> + '_ {
    payload
        .as_chunks::<PACKED_CONTROL_BLOCK_SIZE>()
        .0
        .iter()
        .map(|b| PackedControlBlock {
            packet_type: b[0],
            stream_id: u16::from_be_bytes([b[1], b[2]]),
            sequence_num: u16::from_be_bytes([b[3], b[4]]),
            fragment_id: b[5],
            total_fragments: b[6],
        })
}

/// True when a control packet may be packed: it must be one of the allowed
/// control types and carry no payload of its own.
pub fn is_packable_control_packet(packet_type: u8, payload_len: usize) -> bool {
    if payload_len != 0 {
        return false;
    }
    matches!(
        packet_type,
        enums::PACKET_STREAM_DATA_ACK
            | enums::PACKET_STREAM_DATA_NACK
            | enums::PACKET_STREAM_SYN_ACK
            | enums::PACKET_STREAM_CLOSE_WRITE_ACK
            | enums::PACKET_STREAM_CLOSE_READ_ACK
            | enums::PACKET_STREAM_RST_ACK
            | enums::PACKET_SOCKS5_SYN_ACK
            | enums::PACKET_STREAM_CONNECTED
            | enums::PACKET_STREAM_CONNECTED_ACK
            | enums::PACKET_STREAM_CONNECT_FAIL
            | enums::PACKET_STREAM_CONNECT_FAIL_ACK
            | enums::PACKET_SOCKS5_CONNECT_FAIL
            | enums::PACKET_SOCKS5_RULESET_DENIED
            | enums::PACKET_SOCKS5_NETWORK_UNREACHABLE
            | enums::PACKET_SOCKS5_HOST_UNREACHABLE
            | enums::PACKET_SOCKS5_CONNECTION_REFUSED
            | enums::PACKET_SOCKS5_TTL_EXPIRED
            | enums::PACKET_SOCKS5_COMMAND_UNSUPPORTED
            | enums::PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED
            | enums::PACKET_SOCKS5_AUTH_FAILED
            | enums::PACKET_SOCKS5_UPSTREAM_UNAVAILABLE
            | enums::PACKET_SOCKS5_CONNECTED
            | enums::PACKET_SOCKS5_CONNECTED_ACK
            | enums::PACKET_SOCKS5_CONNECT_FAIL_ACK
            | enums::PACKET_SOCKS5_RULESET_DENIED_ACK
            | enums::PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK
            | enums::PACKET_SOCKS5_HOST_UNREACHABLE_ACK
            | enums::PACKET_SOCKS5_CONNECTION_REFUSED_ACK
            | enums::PACKET_SOCKS5_TTL_EXPIRED_ACK
            | enums::PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK
            | enums::PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK
            | enums::PACKET_SOCKS5_AUTH_FAILED_ACK
            | enums::PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK
            | enums::PACKET_DNS_QUERY_REQ_ACK
            | enums::PACKET_DNS_QUERY_RES_ACK
    )
}
