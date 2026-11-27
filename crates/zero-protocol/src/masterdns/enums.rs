//! Packet-type and flag tables for the MasterDnsVPN wire format.
//!
//! These are copied verbatim from the upstream Go project
//! (`masterking32/MasterDnsVPN`, `internal/enums` and `internal/vpnproto`) at
//! the pinned server release `v2026.06.13.234407-7de2476`. The numbers are the
//! protocol; they must stay byte-identical to the server or nothing decodes.
//!
//! A packet type decides which optional header fields a packet carries. The
//! [`FLAGS`] table maps every one of the 256 possible type bytes to a bitmask
//! of the extensions it uses, exactly the way the Go `buildPacketFlags()` does.
//! [`packet`](super::packet) reads this table to know how long a header is and
//! which fields to write or expect.

#![allow(dead_code)]

// MTU discovery.
pub const PACKET_MTU_UP_REQ: u8 = 0x01;
pub const PACKET_MTU_UP_RES: u8 = 0x02;
pub const PACKET_MTU_DOWN_REQ: u8 = 0x03;
pub const PACKET_MTU_DOWN_RES: u8 = 0x04;

// Session management.
pub const PACKET_SESSION_INIT: u8 = 0x05;
pub const PACKET_SESSION_ACCEPT: u8 = 0x06;
pub const PACKET_PING: u8 = 0x07;
pub const PACKET_PONG: u8 = 0x08;

// Stream transport.
pub const PACKET_STREAM_SYN: u8 = 0x09;
pub const PACKET_STREAM_SYN_ACK: u8 = 0x0A;
pub const PACKET_STREAM_CONNECTED: u8 = 0x0B;
pub const PACKET_STREAM_CONNECTED_ACK: u8 = 0x0C;
pub const PACKET_STREAM_CONNECT_FAIL: u8 = 0x0D;
pub const PACKET_STREAM_CONNECT_FAIL_ACK: u8 = 0x0E;
pub const PACKET_STREAM_DATA: u8 = 0x0F;
pub const PACKET_STREAM_DATA_ACK: u8 = 0x10;
pub const PACKET_STREAM_DATA_NACK: u8 = 0x11;
pub const PACKET_STREAM_RESEND: u8 = 0x12;
pub const PACKET_PACKED_CONTROL_BLOCKS: u8 = 0x13;
pub const PACKET_STREAM_CLOSE_WRITE: u8 = 0x14;
pub const PACKET_STREAM_CLOSE_WRITE_ACK: u8 = 0x15;
pub const PACKET_STREAM_CLOSE_READ: u8 = 0x16;
pub const PACKET_STREAM_CLOSE_READ_ACK: u8 = 0x17;
pub const PACKET_STREAM_RST: u8 = 0x18;
pub const PACKET_STREAM_RST_ACK: u8 = 0x19;

// SOCKS5 stream setup.
pub const PACKET_SOCKS5_SYN: u8 = 0x1A;
pub const PACKET_SOCKS5_SYN_ACK: u8 = 0x1B;

// SOCKS5 results.
pub const PACKET_SOCKS5_CONNECT_FAIL: u8 = 0x1C;
pub const PACKET_SOCKS5_CONNECT_FAIL_ACK: u8 = 0x1D;
pub const PACKET_SOCKS5_RULESET_DENIED: u8 = 0x1E;
pub const PACKET_SOCKS5_RULESET_DENIED_ACK: u8 = 0x1F;
pub const PACKET_SOCKS5_NETWORK_UNREACHABLE: u8 = 0x20;
pub const PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK: u8 = 0x21;
pub const PACKET_SOCKS5_HOST_UNREACHABLE: u8 = 0x22;
pub const PACKET_SOCKS5_HOST_UNREACHABLE_ACK: u8 = 0x23;
pub const PACKET_SOCKS5_CONNECTION_REFUSED: u8 = 0x24;
pub const PACKET_SOCKS5_CONNECTION_REFUSED_ACK: u8 = 0x25;
pub const PACKET_SOCKS5_TTL_EXPIRED: u8 = 0x26;
pub const PACKET_SOCKS5_TTL_EXPIRED_ACK: u8 = 0x27;
pub const PACKET_SOCKS5_COMMAND_UNSUPPORTED: u8 = 0x28;
pub const PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK: u8 = 0x29;
pub const PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED: u8 = 0x2A;
pub const PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK: u8 = 0x2B;
pub const PACKET_SOCKS5_AUTH_FAILED: u8 = 0x2C;
pub const PACKET_SOCKS5_AUTH_FAILED_ACK: u8 = 0x2D;
pub const PACKET_SOCKS5_UPSTREAM_UNAVAILABLE: u8 = 0x2E;
pub const PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK: u8 = 0x2F;
pub const PACKET_SOCKS5_CONNECTED: u8 = 0x30;
pub const PACKET_SOCKS5_CONNECTED_ACK: u8 = 0x31;

// DNS tunnel.
pub const PACKET_DNS_QUERY_REQ: u8 = 0x32;
pub const PACKET_DNS_QUERY_RES: u8 = 0x33;
pub const PACKET_DNS_QUERY_REQ_ACK: u8 = 0x34;
pub const PACKET_DNS_QUERY_RES_ACK: u8 = 0x35;

// Session control.
pub const PACKET_SESSION_CLOSE: u8 = 0x36;
pub const PACKET_SESSION_BUSY: u8 = 0x37;

// Generic error.
pub const PACKET_ERROR_DROP: u8 = 0xFF;

// Header extension flags. A type's entry in [`FLAGS`] is the OR of the ones it
// uses. `VALID` just marks a byte as a real packet type; an unknown type has a
// zero entry and is rejected.
pub const F_VALID: u8 = 1 << 0;
pub const F_STREAM: u8 = 1 << 1;
pub const F_SEQUENCE: u8 = 1 << 2;
pub const F_FRAGMENT: u8 = 1 << 3;
pub const F_COMPRESSION: u8 = 1 << 4;

// Types that carry no optional fields: just the two-byte base header, the
// cookie and the check byte.
const VALID_ONLY: [u8; 11] = [
    PACKET_MTU_UP_RES,
    PACKET_MTU_DOWN_REQ,
    PACKET_SESSION_INIT,
    PACKET_SESSION_ACCEPT,
    PACKET_SESSION_BUSY,
    PACKET_SESSION_CLOSE,
    PACKET_PING,
    PACKET_PONG,
    PACKET_ERROR_DROP,
    PACKET_MTU_UP_REQ,
    PACKET_MTU_DOWN_RES,
];

// Types that carry a stream id and a sequence number.
const STREAM_SEQ: [u8; 44] = [
    PACKET_STREAM_SYN,
    PACKET_STREAM_SYN_ACK,
    PACKET_STREAM_DATA,
    PACKET_STREAM_DATA_ACK,
    PACKET_STREAM_DATA_NACK,
    PACKET_STREAM_RESEND,
    PACKET_STREAM_CLOSE_WRITE,
    PACKET_STREAM_CLOSE_WRITE_ACK,
    PACKET_STREAM_CLOSE_READ,
    PACKET_STREAM_CLOSE_READ_ACK,
    PACKET_STREAM_RST,
    PACKET_STREAM_RST_ACK,
    PACKET_MTU_UP_REQ,
    PACKET_MTU_DOWN_RES,
    PACKET_SOCKS5_SYN,
    PACKET_SOCKS5_SYN_ACK,
    PACKET_STREAM_CONNECTED,
    PACKET_STREAM_CONNECTED_ACK,
    PACKET_STREAM_CONNECT_FAIL,
    PACKET_STREAM_CONNECT_FAIL_ACK,
    PACKET_SOCKS5_CONNECT_FAIL,
    PACKET_SOCKS5_CONNECT_FAIL_ACK,
    PACKET_SOCKS5_RULESET_DENIED,
    PACKET_SOCKS5_RULESET_DENIED_ACK,
    PACKET_SOCKS5_NETWORK_UNREACHABLE,
    PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
    PACKET_SOCKS5_HOST_UNREACHABLE,
    PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
    PACKET_SOCKS5_CONNECTION_REFUSED,
    PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
    PACKET_SOCKS5_TTL_EXPIRED,
    PACKET_SOCKS5_TTL_EXPIRED_ACK,
    PACKET_SOCKS5_COMMAND_UNSUPPORTED,
    PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
    PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
    PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
    PACKET_SOCKS5_AUTH_FAILED,
    PACKET_SOCKS5_AUTH_FAILED_ACK,
    PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
    PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
    PACKET_SOCKS5_CONNECTED,
    PACKET_SOCKS5_CONNECTED_ACK,
    PACKET_DNS_QUERY_REQ,
    PACKET_DNS_QUERY_RES,
];

// A second stream+seq group kept apart only because the Go source lists these
// four separately; the effect is the same OR of flags.
const STREAM_SEQ_DNS_ACK: [u8; 2] = [PACKET_DNS_QUERY_REQ_ACK, PACKET_DNS_QUERY_RES_ACK];

// Types that add the two fragment bytes (fragment id, total fragments).
const FRAGMENT: [u8; 9] = [
    PACKET_STREAM_DATA,
    PACKET_STREAM_RESEND,
    PACKET_SOCKS5_SYN,
    PACKET_DNS_QUERY_REQ,
    PACKET_DNS_QUERY_RES,
    PACKET_DNS_QUERY_REQ_ACK,
    PACKET_DNS_QUERY_RES_ACK,
    PACKET_MTU_UP_REQ,
    PACKET_MTU_DOWN_RES,
];

// Types that add the one compression byte.
const COMPRESSION: [u8; 7] = [
    PACKET_STREAM_DATA,
    PACKET_STREAM_RESEND,
    PACKET_PACKED_CONTROL_BLOCKS,
    PACKET_DNS_QUERY_REQ,
    PACKET_DNS_QUERY_RES,
    PACKET_MTU_UP_REQ,
    PACKET_MTU_DOWN_RES,
];

const fn mark(flags: &mut [u8; 256], list: &[u8], bits: u8) {
    let mut i = 0;
    while i < list.len() {
        flags[list[i] as usize] |= bits;
        i += 1;
    }
}

const fn build_flags() -> [u8; 256] {
    let mut flags = [0u8; 256];
    mark(&mut flags, &VALID_ONLY, F_VALID);
    mark(&mut flags, &STREAM_SEQ, F_VALID | F_STREAM | F_SEQUENCE);
    mark(
        &mut flags,
        &STREAM_SEQ_DNS_ACK,
        F_VALID | F_STREAM | F_SEQUENCE,
    );
    mark(&mut flags, &FRAGMENT, F_FRAGMENT);
    mark(&mut flags, &COMPRESSION, F_VALID | F_COMPRESSION);
    flags
}

/// Extension bitmask for every possible packet-type byte. Index by the type
/// byte; a zero entry means "not a valid type".
pub static FLAGS: [u8; 256] = build_flags();

/// Does this type carry a stream id?
#[inline]
pub fn has_stream(packet_type: u8) -> bool {
    FLAGS[packet_type as usize] & F_STREAM != 0
}

/// Does this type carry a sequence number?
#[inline]
pub fn has_sequence(packet_type: u8) -> bool {
    FLAGS[packet_type as usize] & F_SEQUENCE != 0
}

/// Does this type carry the two fragment bytes?
#[inline]
pub fn has_fragment(packet_type: u8) -> bool {
    FLAGS[packet_type as usize] & F_FRAGMENT != 0
}

/// Does this type carry the compression byte?
#[inline]
pub fn has_compression(packet_type: u8) -> bool {
    FLAGS[packet_type as usize] & F_COMPRESSION != 0
}

/// Is this a known, valid packet type?
#[inline]
pub fn is_valid(packet_type: u8) -> bool {
    FLAGS[packet_type as usize] & F_VALID != 0
}

/// Encryption method ids, matching `internal/security`. Only [`METHOD_AES_256_GCM`]
/// is authenticated and the one ZeroNet uses; the rest exist so the codec can
/// interoperate with a server configured differently.
pub const METHOD_NONE: u8 = 0;
pub const METHOD_XOR: u8 = 1;
pub const METHOD_CHACHA20: u8 = 2;
pub const METHOD_AES_128_GCM: u8 = 3;
pub const METHOD_AES_192_GCM: u8 = 4;
pub const METHOD_AES_256_GCM: u8 = 5;

/// Human name for an encryption method id, as the server logs it.
pub fn method_name(method: u8) -> &'static str {
    match method {
        METHOD_NONE => "NONE",
        METHOD_XOR => "XOR",
        METHOD_CHACHA20 => "ChaCha20",
        METHOD_AES_128_GCM => "AES-128-GCM",
        METHOD_AES_192_GCM => "AES-192-GCM",
        METHOD_AES_256_GCM => "AES-256-GCM",
        _ => "UNKNOWN",
    }
}

/// Queue priority levels for the multi-level send queue, matching
/// `internal/enums/packet_priority.go`. Lower numbers are served first; the
/// queue has exactly these six levels and no aging, so a steady supply of a
/// higher level starves the ones below it (the server relies on that order).
pub const PACKET_PRIORITY_CRITICAL: usize = 0;
pub const PACKET_PRIORITY_RETRY: usize = 1;
pub const PACKET_PRIORITY_HIGH: usize = 2;
pub const PACKET_PRIORITY_NORMAL: usize = 3;
pub const PACKET_PRIORITY_LOW: usize = 4;
pub const PACKET_PRIORITY_IDLE: usize = 5;

/// The default send-queue priority for a packet type, matching Go
/// `DefaultPacketPriority`. ACKs, stream setup and every SOCKS result ride at
/// the top so a reply is never stuck behind bulk data; retransmits and tunneled
/// DNS sit just under them; ordinary stream data is `Normal`; the lazy
/// housekeeping (`CLOSE_WRITE`, `SESSION_CLOSE`) is `Low`; keep-alives are
/// `Idle`. Anything unlisted falls back to `Normal`, exactly as the Go `default`.
pub fn default_packet_priority(packet_type: u8) -> usize {
    match packet_type {
        PACKET_STREAM_DATA_ACK
        | PACKET_STREAM_DATA_NACK
        | PACKET_STREAM_SYN
        | PACKET_STREAM_SYN_ACK
        | PACKET_STREAM_CONNECTED
        | PACKET_STREAM_CONNECTED_ACK
        | PACKET_STREAM_CONNECT_FAIL
        | PACKET_STREAM_CONNECT_FAIL_ACK
        | PACKET_STREAM_CLOSE_WRITE_ACK
        | PACKET_STREAM_CLOSE_READ
        | PACKET_STREAM_CLOSE_READ_ACK
        | PACKET_STREAM_RST
        | PACKET_STREAM_RST_ACK
        | PACKET_SOCKS5_SYN
        | PACKET_SOCKS5_SYN_ACK
        | PACKET_SOCKS5_CONNECT_FAIL
        | PACKET_SOCKS5_CONNECT_FAIL_ACK
        | PACKET_SOCKS5_RULESET_DENIED
        | PACKET_SOCKS5_RULESET_DENIED_ACK
        | PACKET_SOCKS5_NETWORK_UNREACHABLE
        | PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK
        | PACKET_SOCKS5_HOST_UNREACHABLE
        | PACKET_SOCKS5_HOST_UNREACHABLE_ACK
        | PACKET_SOCKS5_CONNECTION_REFUSED
        | PACKET_SOCKS5_CONNECTION_REFUSED_ACK
        | PACKET_SOCKS5_TTL_EXPIRED
        | PACKET_SOCKS5_TTL_EXPIRED_ACK
        | PACKET_SOCKS5_COMMAND_UNSUPPORTED
        | PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK
        | PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED
        | PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK
        | PACKET_SOCKS5_AUTH_FAILED
        | PACKET_SOCKS5_AUTH_FAILED_ACK
        | PACKET_SOCKS5_UPSTREAM_UNAVAILABLE
        | PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK
        | PACKET_SOCKS5_CONNECTED
        | PACKET_SOCKS5_CONNECTED_ACK
        | PACKET_DNS_QUERY_REQ_ACK
        | PACKET_DNS_QUERY_RES_ACK => PACKET_PRIORITY_CRITICAL,

        PACKET_STREAM_RESEND | PACKET_DNS_QUERY_RES | PACKET_DNS_QUERY_REQ => PACKET_PRIORITY_RETRY,

        PACKET_STREAM_DATA => PACKET_PRIORITY_NORMAL,

        PACKET_STREAM_CLOSE_WRITE | PACKET_SESSION_CLOSE => PACKET_PRIORITY_LOW,

        PACKET_PING | PACKET_PONG => PACKET_PRIORITY_IDLE,

        _ => PACKET_PRIORITY_NORMAL,
    }
}

/// Keep a caller-supplied priority if it names a real level, otherwise fall
/// back to [`default_packet_priority`]. Mirrors Go `NormalizePacketPriority`.
pub fn normalize_packet_priority(packet_type: u8, priority: usize) -> usize {
    if priority <= PACKET_PRIORITY_IDLE {
        priority
    } else {
        default_packet_priority(packet_type)
    }
}

/// The deterministic ACK type a tracked control/setup packet expects back,
/// matching Go `ControlAckFor` (the `ControlAckPairs` map). Data ACKs are
/// deliberately absent — those stay inside the ARQ data path, not the control
/// reliability table. Returns `None` for a type that is not ack-tracked.
pub fn control_ack_for(packet_type: u8) -> Option<u8> {
    let ack = match packet_type {
        PACKET_DNS_QUERY_REQ => PACKET_DNS_QUERY_REQ_ACK,
        PACKET_DNS_QUERY_RES => PACKET_DNS_QUERY_RES_ACK,
        PACKET_STREAM_SYN => PACKET_STREAM_SYN_ACK,
        PACKET_STREAM_CONNECTED => PACKET_STREAM_CONNECTED_ACK,
        PACKET_STREAM_CONNECT_FAIL => PACKET_STREAM_CONNECT_FAIL_ACK,
        PACKET_STREAM_CLOSE_WRITE => PACKET_STREAM_CLOSE_WRITE_ACK,
        PACKET_STREAM_CLOSE_READ => PACKET_STREAM_CLOSE_READ_ACK,
        PACKET_STREAM_RST => PACKET_STREAM_RST_ACK,
        PACKET_SOCKS5_SYN => PACKET_SOCKS5_SYN_ACK,
        PACKET_SOCKS5_CONNECT_FAIL => PACKET_SOCKS5_CONNECT_FAIL_ACK,
        PACKET_SOCKS5_RULESET_DENIED => PACKET_SOCKS5_RULESET_DENIED_ACK,
        PACKET_SOCKS5_NETWORK_UNREACHABLE => PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
        PACKET_SOCKS5_HOST_UNREACHABLE => PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
        PACKET_SOCKS5_CONNECTION_REFUSED => PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
        PACKET_SOCKS5_TTL_EXPIRED => PACKET_SOCKS5_TTL_EXPIRED_ACK,
        PACKET_SOCKS5_COMMAND_UNSUPPORTED => PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
        PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED => PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
        PACKET_SOCKS5_AUTH_FAILED => PACKET_SOCKS5_AUTH_FAILED_ACK,
        PACKET_SOCKS5_UPSTREAM_UNAVAILABLE => PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
        PACKET_SOCKS5_CONNECTED => PACKET_SOCKS5_CONNECTED_ACK,
        _ => return None,
    };
    Some(ack)
}

/// The originating control type for an ACK type: the inverse of
/// [`control_ack_for`], matching Go `ReverseControlAckFor`. Returns `None` if
/// `ack_type` is not the ack of any tracked control packet.
pub fn reverse_control_ack_for(ack_type: u8) -> Option<u8> {
    let origin = match ack_type {
        PACKET_DNS_QUERY_REQ_ACK => PACKET_DNS_QUERY_REQ,
        PACKET_DNS_QUERY_RES_ACK => PACKET_DNS_QUERY_RES,
        PACKET_STREAM_SYN_ACK => PACKET_STREAM_SYN,
        PACKET_STREAM_CONNECTED_ACK => PACKET_STREAM_CONNECTED,
        PACKET_STREAM_CONNECT_FAIL_ACK => PACKET_STREAM_CONNECT_FAIL,
        PACKET_STREAM_CLOSE_WRITE_ACK => PACKET_STREAM_CLOSE_WRITE,
        PACKET_STREAM_CLOSE_READ_ACK => PACKET_STREAM_CLOSE_READ,
        PACKET_STREAM_RST_ACK => PACKET_STREAM_RST,
        PACKET_SOCKS5_SYN_ACK => PACKET_SOCKS5_SYN,
        PACKET_SOCKS5_CONNECT_FAIL_ACK => PACKET_SOCKS5_CONNECT_FAIL,
        PACKET_SOCKS5_RULESET_DENIED_ACK => PACKET_SOCKS5_RULESET_DENIED,
        PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK => PACKET_SOCKS5_NETWORK_UNREACHABLE,
        PACKET_SOCKS5_HOST_UNREACHABLE_ACK => PACKET_SOCKS5_HOST_UNREACHABLE,
        PACKET_SOCKS5_CONNECTION_REFUSED_ACK => PACKET_SOCKS5_CONNECTION_REFUSED,
        PACKET_SOCKS5_TTL_EXPIRED_ACK => PACKET_SOCKS5_TTL_EXPIRED,
        PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK => PACKET_SOCKS5_COMMAND_UNSUPPORTED,
        PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK => PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
        PACKET_SOCKS5_AUTH_FAILED_ACK => PACKET_SOCKS5_AUTH_FAILED,
        PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK => PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
        PACKET_SOCKS5_CONNECTED_ACK => PACKET_SOCKS5_CONNECTED,
        _ => return None,
    };
    Some(origin)
}

/// Whether this control type, when acknowledged, tears the stream down — the
/// `PacketsCloseStream` set in Go `GetPacketCloseStream`. The ARQ matches the
/// acks of these sequence-agnostically (any tracked packet of the type counts)
/// because a resend may have changed the sequence the peer echoes back.
pub fn is_close_stream_packet(packet_type: u8) -> bool {
    matches!(
        packet_type,
        PACKET_STREAM_RST
            | PACKET_STREAM_CLOSE_WRITE
            | PACKET_STREAM_CLOSE_READ
            | PACKET_SOCKS5_RULESET_DENIED
            | PACKET_SOCKS5_NETWORK_UNREACHABLE
            | PACKET_SOCKS5_HOST_UNREACHABLE
            | PACKET_SOCKS5_CONNECTION_REFUSED
            | PACKET_SOCKS5_TTL_EXPIRED
            | PACKET_SOCKS5_COMMAND_UNSUPPORTED
            | PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED
            | PACKET_SOCKS5_AUTH_FAILED
            | PACKET_SOCKS5_UPSTREAM_UNAVAILABLE
            | PACKET_STREAM_CONNECT_FAIL
            | PACKET_SOCKS5_CONNECT_FAIL
    )
}

/// The two "setup" control packets — the ones that open a stream — which the
/// control reliability treats specially: a tighter initial RTO (capped at
/// 350ms), a gentler growth factor, and far more generous retry/TTL limits,
/// matching Go `setupControlPacketTypes`.
pub fn is_setup_control_packet(packet_type: u8) -> bool {
    matches!(packet_type, PACKET_STREAM_SYN | PACKET_SOCKS5_SYN)
}

/// Build the 64-bit dedup/queue identity for a stream-owned packet, matching
/// `enums.PacketIdentityKey`. The runtime uses this later to avoid queuing two
/// copies of the same logical packet; it is defined here with the rest of the
/// per-type behavior so the two never drift apart.
pub fn packet_identity_key(
    stream_id: u16,
    packet_type: u8,
    sequence_num: u16,
    fragment_id: u8,
) -> u64 {
    match packet_type {
        PACKET_STREAM_DATA
        | PACKET_STREAM_RESEND
        | PACKET_STREAM_DATA_ACK
        | PACKET_STREAM_DATA_NACK
        | PACKET_STREAM_SYN
        | PACKET_STREAM_SYN_ACK
        | PACKET_SOCKS5_SYN
        | PACKET_SOCKS5_SYN_ACK
        | PACKET_DNS_QUERY_REQ
        | PACKET_DNS_QUERY_REQ_ACK
        | PACKET_DNS_QUERY_RES
        | PACKET_DNS_QUERY_RES_ACK => {
            identity_seq_frag(stream_id, packet_type, sequence_num, fragment_id)
        }

        PACKET_STREAM_CLOSE_WRITE
        | PACKET_STREAM_CLOSE_WRITE_ACK
        | PACKET_STREAM_CLOSE_READ
        | PACKET_STREAM_CLOSE_READ_ACK
        | PACKET_STREAM_RST
        | PACKET_STREAM_RST_ACK
        | PACKET_STREAM_CONNECTED
        | PACKET_STREAM_CONNECTED_ACK
        | PACKET_STREAM_CONNECT_FAIL
        | PACKET_STREAM_CONNECT_FAIL_ACK
        | PACKET_SOCKS5_CONNECT_FAIL
        | PACKET_SOCKS5_CONNECT_FAIL_ACK
        | PACKET_SOCKS5_RULESET_DENIED
        | PACKET_SOCKS5_RULESET_DENIED_ACK
        | PACKET_SOCKS5_NETWORK_UNREACHABLE
        | PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK
        | PACKET_SOCKS5_HOST_UNREACHABLE
        | PACKET_SOCKS5_HOST_UNREACHABLE_ACK
        | PACKET_SOCKS5_CONNECTION_REFUSED
        | PACKET_SOCKS5_CONNECTION_REFUSED_ACK
        | PACKET_SOCKS5_TTL_EXPIRED
        | PACKET_SOCKS5_TTL_EXPIRED_ACK
        | PACKET_SOCKS5_COMMAND_UNSUPPORTED
        | PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK
        | PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED
        | PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK
        | PACKET_SOCKS5_AUTH_FAILED
        | PACKET_SOCKS5_AUTH_FAILED_ACK
        | PACKET_SOCKS5_UPSTREAM_UNAVAILABLE
        | PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK
        | PACKET_SOCKS5_CONNECTED
        | PACKET_SOCKS5_CONNECTED_ACK
        | PACKET_PACKED_CONTROL_BLOCKS
        | PACKET_ERROR_DROP
        | PACKET_PING
        | PACKET_PONG => identity_seq(stream_id, packet_type, sequence_num),

        PACKET_SESSION_CLOSE | PACKET_SESSION_BUSY => type_stream_key(stream_id, packet_type),

        _ => identity_seq_frag(stream_id, packet_type, sequence_num, fragment_id),
    }
}

#[inline]
fn type_stream_key(stream_id: u16, packet_type: u8) -> u64 {
    (stream_id as u64) << 40 | (packet_type as u64) << 32
}

#[inline]
fn identity_seq(stream_id: u16, packet_type: u8, sequence_num: u16) -> u64 {
    (stream_id as u64) << 40 | (packet_type as u64) << 32 | (sequence_num as u64) << 8
}

#[inline]
fn identity_seq_frag(stream_id: u16, packet_type: u8, sequence_num: u16, fragment_id: u8) -> u64 {
    (stream_id as u64) << 40
        | (packet_type as u64) << 32
        | (sequence_num as u64) << 8
        | fragment_id as u64
}
