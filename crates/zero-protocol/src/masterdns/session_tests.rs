//! Byte-exact tests for the session, compression, and SOCKS target wire
//! pieces.
//!
//! Every table and payload here was emitted by a small Go harness
//! (`cmd/sessvec`) that calls the upstream `internal/compression` and
//! `internal/socksproto` packages directly at the pinned release, plus the
//! documented ten-byte SESSION_INIT layout. A passing run means this Rust
//! code and that Go server agree byte for byte.

use super::compression::{normalize_available_type, pack_pair, split_pair};
use super::enums::{
    default_packet_priority, normalize_packet_priority, PACKET_DNS_QUERY_REQ,
    PACKET_DNS_QUERY_REQ_ACK, PACKET_PING, PACKET_PRIORITY_CRITICAL, PACKET_PRIORITY_IDLE,
    PACKET_PRIORITY_LOW, PACKET_PRIORITY_NORMAL, PACKET_PRIORITY_RETRY, PACKET_SESSION_CLOSE,
    PACKET_SOCKS5_CONNECTED_ACK, PACKET_SOCKS5_SYN, PACKET_STREAM_CLOSE_WRITE, PACKET_STREAM_DATA,
    PACKET_STREAM_DATA_ACK, PACKET_STREAM_DATA_NACK, PACKET_STREAM_RESEND, PACKET_STREAM_RST,
};
use super::session::{build_session_init_payload, REPLY_MODE_BASE64, REPLY_MODE_RAW};
use super::socks::{
    build_target_payload, build_udp_datagram, parse_target_payload, parse_udp_datagram, Target,
    TargetError, ADDRESS_TYPE_DOMAIN, ADDRESS_TYPE_IPV4, ADDRESS_TYPE_IPV6,
};

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in test vector")
}

// normalize_available_type over the whole 0..=255 range, from Go.
#[rustfmt::skip]
const NORMALIZE: [u8; 256] = [
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

// split_pair over 0..=255, each result re-packed as (upload << 4) | download,
// from Go's SplitPair.
#[rustfmt::skip]
const SPLIT_PACKED: [u8; 256] = [
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    16, 17, 18, 19, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    32, 33, 34, 35, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    48, 49, 50, 51, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

// pack_pair over the input ids used by the Go grid, in this order.
const PACK_INPUTS: [u8; 8] = [0, 1, 2, 3, 4, 7, 15, 255];
#[rustfmt::skip]
const PACK_GRID: [[u8; 8]; 8] = [
    [0, 1, 2, 3, 0, 0, 0, 0],
    [16, 17, 18, 19, 16, 16, 16, 16],
    [32, 33, 34, 35, 32, 32, 32, 32],
    [48, 49, 50, 51, 48, 48, 48, 48],
    [0, 1, 2, 3, 0, 0, 0, 0],
    [0, 1, 2, 3, 0, 0, 0, 0],
    [0, 1, 2, 3, 0, 0, 0, 0],
    [0, 1, 2, 3, 0, 0, 0, 0],
];

#[test]
fn normalize_available_type_matches_go() {
    for (value, expected) in NORMALIZE.iter().enumerate() {
        assert_eq!(
            normalize_available_type(value as u8),
            *expected,
            "normalize({value})"
        );
    }
}

#[test]
fn split_pair_matches_go() {
    for (value, expected) in SPLIT_PACKED.iter().enumerate() {
        let (up, down) = split_pair(value as u8);
        assert_eq!((up << 4) | down, *expected, "split({value})");
    }
}

#[test]
fn pack_pair_matches_go() {
    for (ui, up) in PACK_INPUTS.iter().enumerate() {
        for (di, down) in PACK_INPUTS.iter().enumerate() {
            assert_eq!(
                pack_pair(*up, *down),
                PACK_GRID[ui][di],
                "pack({up}, {down})"
            );
        }
    }
}

// (base64 reply?, upload, download, upload mtu, download mtu, verify hex,
//  expected 10-byte payload hex)
const SESSION_INIT: &[(bool, u8, u8, u16, u16, &str, &str)] = &[
    (false, 0, 0, 1232, 1232, "deadbeef", "000004d004d0deadbeef"),
    (true, 1, 3, 512, 1400, "01020304", "01130200057801020304"),
    (false, 3, 1, 1200, 65535, "ffffffff", "003104b0ffffffffffff"),
    (true, 2, 2, 100, 100, "00000000", "01220064006400000000"),
    (false, 5, 9, 1232, 576, "a1b2c3d4", "000004d00240a1b2c3d4"),
];

#[test]
fn build_session_init_payload_matches_go() {
    for (base64, up, down, up_mtu, down_mtu, verify_hex, expected) in SESSION_INIT {
        let verify_bytes = hx(verify_hex);
        let mut verify = [0u8; 4];
        verify.copy_from_slice(&verify_bytes);
        let got = build_session_init_payload(*base64, *up, *down, *up_mtu, *down_mtu, verify);
        assert_eq!(
            hex::encode(got),
            *expected,
            "session init base64={base64} up={up} down={down} up_mtu={up_mtu} down_mtu={down_mtu}"
        );
    }
}

#[test]
fn session_init_reply_mode_byte_is_the_first_byte() {
    let raw = build_session_init_payload(false, 0, 0, 1232, 1232, [0; 4]);
    assert_eq!(raw[0], REPLY_MODE_RAW);
    let b64 = build_session_init_payload(true, 0, 0, 1232, 1232, [0; 4]);
    assert_eq!(b64[0], REPLY_MODE_BASE64);
}

// (address type, host, port, expected payload hex)
const SOCKS_TARGETS: &[(u8, &str, u16, &str)] = &[
    (ADDRESS_TYPE_IPV4, "1.2.3.4", 80, "01010203040050"),
    (ADDRESS_TYPE_IPV4, "0.0.0.0", 0, "01000000000000"),
    (
        ADDRESS_TYPE_IPV4,
        "255.255.255.255",
        65535,
        "01ffffffffffff",
    ),
    (
        ADDRESS_TYPE_DOMAIN,
        "example.com",
        443,
        "030b6578616d706c652e636f6d01bb",
    ),
    (ADDRESS_TYPE_DOMAIN, "a", 1, "0301610001"),
    (
        ADDRESS_TYPE_IPV6,
        "::1",
        8080,
        "04000000000000000000000000000000011f90",
    ),
    (
        ADDRESS_TYPE_IPV6,
        "2001:db8::1",
        443,
        "0420010db800000000000000000000000101bb",
    ),
    (
        ADDRESS_TYPE_IPV6,
        "fe80::abcd:1234:5678:9abc",
        51820,
        "04fe80000000000000abcd123456789abcca6c",
    ),
];

#[test]
fn build_target_payload_matches_go() {
    for (atyp, host, port, expected) in SOCKS_TARGETS {
        let target = Target {
            address_type: *atyp,
            host: (*host).to_string(),
            port: *port,
        };
        assert_eq!(
            hex::encode(build_target_payload(&target)),
            *expected,
            "target {atyp} {host}:{port}"
        );
    }
}

#[test]
fn target_payloads_round_trip_to_the_same_host() {
    for (atyp, host, port, expected) in SOCKS_TARGETS {
        let bytes = hx(expected);
        let parsed = parse_target_payload(&bytes).unwrap();
        assert_eq!(parsed.address_type, *atyp);
        assert_eq!(parsed.port, *port);
        // Go renders the host back canonically; for these inputs that equals
        // the input text (dotted-quad, compressed v6, or the raw name).
        assert_eq!(parsed.host, *host, "parsed host for {expected}");
    }
}

#[test]
fn parse_target_rejects_short_and_bad_payloads() {
    assert_eq!(parse_target_payload(&[1, 2]), Err(TargetError::TooShort));
    // IPv4 claimed but only two trailing bytes present.
    assert_eq!(
        parse_target_payload(&[ADDRESS_TYPE_IPV4, 1, 2]),
        Err(TargetError::TooShort)
    );
    // Domain with a zero length byte.
    assert_eq!(
        parse_target_payload(&[ADDRESS_TYPE_DOMAIN, 0, 0, 0]),
        Err(TargetError::InvalidDomainLength)
    );
    // Unknown address type.
    assert_eq!(
        parse_target_payload(&[0x09, 1, 2, 3]),
        Err(TargetError::UnsupportedAddressType)
    );
}

#[test]
fn an_ipv4_host_in_an_ipv6_target_falls_back_to_the_zero_address() {
    // The Go BuildTargetPayload uses ParseIPv6, which returns :: for a v4
    // literal; a target that mislabels a v4 host as v6 must encode as ::.
    let target = Target {
        address_type: ADDRESS_TYPE_IPV6,
        host: "1.2.3.4".to_string(),
        port: 443,
    };
    assert_eq!(
        hex::encode(build_target_payload(&target)),
        "040000000000000000000000000000000001bb"
    );
}

#[test]
fn udp_datagram_round_trips_target_and_payload() {
    // Mirrors the Go socksproto TestParseAndBuildUDPDatagram.
    let target = Target {
        address_type: ADDRESS_TYPE_DOMAIN,
        host: "example.com".to_string(),
        port: 53,
    };
    let packet = build_udp_datagram(&target, &[0x01, 0x02, 0x03]);
    let parsed = parse_udp_datagram(&packet).unwrap();
    assert_eq!(parsed.target, target);
    assert_eq!(parsed.payload, &[0x01, 0x02, 0x03]);
}

#[test]
fn udp_datagram_rejects_fragments_and_short_input() {
    // A non-zero FRAG byte (packet[2]) is refused rather than reassembled.
    let fragged = [0x00, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0x00, 0x35, 0xAA];
    assert_eq!(
        parse_udp_datagram(&fragged),
        Err(TargetError::UdpFragmented)
    );
    assert_eq!(
        parse_udp_datagram(&[0, 0, 0]),
        Err(TargetError::UdpDatagramTooShort)
    );
}

#[test]
fn udp_datagram_ipv4_target_with_empty_payload() {
    // offset == len(packet) is allowed and yields an empty payload.
    let packet = [0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x35];
    let parsed = parse_udp_datagram(&packet).unwrap();
    assert_eq!(parsed.target.host, "127.0.0.1");
    assert_eq!(parsed.target.port, 53);
    assert!(parsed.payload.is_empty());
}

#[test]
fn packet_priority_matches_go_table() {
    // The cases from the Go packet_priority_test.go, plus the level buckets.
    assert_eq!(
        default_packet_priority(PACKET_STREAM_DATA_ACK),
        PACKET_PRIORITY_CRITICAL
    );
    assert_eq!(
        default_packet_priority(PACKET_STREAM_DATA_NACK),
        PACKET_PRIORITY_CRITICAL
    );
    assert_eq!(
        default_packet_priority(PACKET_SOCKS5_SYN),
        PACKET_PRIORITY_CRITICAL
    );
    assert_eq!(
        default_packet_priority(PACKET_STREAM_RST),
        PACKET_PRIORITY_CRITICAL
    );
    assert_eq!(
        default_packet_priority(PACKET_SOCKS5_CONNECTED_ACK),
        PACKET_PRIORITY_CRITICAL
    );
    assert_eq!(
        default_packet_priority(PACKET_DNS_QUERY_REQ_ACK),
        PACKET_PRIORITY_CRITICAL
    );
    assert_eq!(
        default_packet_priority(PACKET_STREAM_RESEND),
        PACKET_PRIORITY_RETRY
    );
    assert_eq!(
        default_packet_priority(PACKET_DNS_QUERY_REQ),
        PACKET_PRIORITY_RETRY
    );
    assert_eq!(
        default_packet_priority(PACKET_STREAM_DATA),
        PACKET_PRIORITY_NORMAL
    );
    assert_eq!(
        default_packet_priority(PACKET_STREAM_CLOSE_WRITE),
        PACKET_PRIORITY_LOW
    );
    assert_eq!(
        default_packet_priority(PACKET_SESSION_CLOSE),
        PACKET_PRIORITY_LOW
    );
    assert_eq!(default_packet_priority(PACKET_PING), PACKET_PRIORITY_IDLE);
    // Unlisted type -> Normal (the Go default arm). 0x00 is not in any list.
    assert_eq!(default_packet_priority(0x00), PACKET_PRIORITY_NORMAL);
}

#[test]
fn normalize_priority_keeps_valid_and_falls_back_otherwise() {
    // An in-range priority is kept as-is regardless of the type.
    assert_eq!(
        normalize_packet_priority(PACKET_STREAM_DATA, PACKET_PRIORITY_CRITICAL),
        PACKET_PRIORITY_CRITICAL
    );
    // Out of range falls back to the type default (DATA -> Normal).
    assert_eq!(
        normalize_packet_priority(PACKET_STREAM_DATA, 99),
        PACKET_PRIORITY_NORMAL
    );
}
