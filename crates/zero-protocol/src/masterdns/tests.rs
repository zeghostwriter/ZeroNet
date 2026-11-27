//! Byte-exact tests for the MasterDnsVPN wire port.
//!
//! Every expected value here was produced by a small Go harness that calls the
//! upstream packages directly (base codec, packet builder, security codec) at
//! the pinned release, so a passing run means this Rust code and that Go server
//! agree byte for byte. If one of these fails after a change, the change moved
//! the wire format, not the test.

use super::codec::{
    base32_decode, base32_encode, base36_decode, base36_encode, raw_base64_decode,
    raw_base64_encode, Codec, CodecError,
};
use super::enums;
use super::packet::{
    self, append_packed_control_block, build_raw, decode_session_accept_payload,
    decode_session_scaled_byte, encode_session_accept_payload, encode_session_scaled_byte,
    header_check_byte, is_packable_control_packet, iter_packed_control_blocks, parse, BuildOptions,
    PackedControlBlock, SessionAcceptClientPolicy, SessionAcceptPayload,
};

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in test vector")
}

// (input hex, base36, base32, raw base64)
const ENCODINGS: &[(&str, &str, &str, &str)] = &[
    ("", "", "", ""),
    ("00", "00", "aa", "AA"),
    ("ff", "73", "74", "/w"),
    ("010203", "01eyr", "aebag", "AQID"),
    (
        "31323334353637",
        "3scinlpjsxj",
        "gezdgnbvgy3q",
        "MTIzNDU2Nw",
    ),
    (
        "3132333435363738",
        "3scinlpjsxj1k",
        "gezdgnbvgy3tq",
        "MTIzNDU2Nzg",
    ),
    (
        "68656c6c6f20776f726c642121",
        "81c2z3kqlpz17fotu6881",
        "nbswy3dpeb3w64tmmqqsc",
        "aGVsbG8gd29ybGQhIQ",
    ),
    (
        "0000000000000000",
        "0000000000000",
        "aaaaaaaaaaaaa",
        "AAAAAAAAAAA",
    ),
    (
        "deadbeef00112233445566778899aabbccddeeff",
        "h55o0dwq59e3y34uo3r8ux1ujj0ob3lr",
        "32w353yacerdgrcvmz3yrgnkxpgn33x7",
        "3q2+7wARIjNEVWZ3iJmqu8zd7v8",
    ),
];

#[test]
fn base_codecs_match_and_round_trip() {
    for (input_hex, b36, b32, b64) in ENCODINGS {
        let input = hx(input_hex);
        assert_eq!(&base36_encode(&input), b36, "base36 encode {input_hex}");
        assert_eq!(&base32_encode(&input), b32, "base32 encode {input_hex}");
        assert_eq!(&raw_base64_encode(&input), b64, "base64 encode {input_hex}");

        assert_eq!(
            base36_decode(b36.as_bytes()).unwrap(),
            input,
            "base36 {b36}"
        );
        assert_eq!(
            base32_decode(b32.as_bytes()).unwrap(),
            input,
            "base32 {b32}"
        );
        assert_eq!(
            raw_base64_decode(b64.as_bytes()).unwrap(),
            input,
            "b64 {b64}"
        );
    }
}

#[test]
fn base36_decode_is_case_insensitive() {
    // "01eyr" is 010203; its upper form must decode the same.
    assert_eq!(base36_decode(b"01EYR").unwrap(), hx("010203"));
}

#[test]
fn base36_rejects_impossible_lengths() {
    // A single leftover character can never come from any input (the decode
    // table maps count 1 to zero bytes).
    assert_eq!(base36_decode(b"0"), Err(CodecError::InvalidEncoding));
    // A character outside the alphabet.
    assert_eq!(base36_decode(b"01ey!"), Err(CodecError::InvalidEncoding));
}

// (name, raw hex, base36 of raw)
fn built_packet(name: &str) -> BuildOptions<'static> {
    match name {
        "session_init" => BuildOptions {
            session_id: 7,
            packet_type: enums::PACKET_SESSION_INIT,
            session_cookie: 9,
            payload: b"hello",
            ..Default::default()
        },
        "ping_empty" => BuildOptions {
            session_id: 1,
            packet_type: enums::PACKET_PING,
            session_cookie: 2,
            ..Default::default()
        },
        "stream_data" => BuildOptions {
            session_id: 4,
            packet_type: enums::PACKET_STREAM_DATA,
            stream_id: 0x1122,
            sequence_num: 0x3344,
            fragment_id: 5,
            total_fragments: 9,
            compression_type: 2,
            session_cookie: 7,
            payload: b"vpn-data",
        },
        "dns_query_req" => BuildOptions {
            session_id: 3,
            packet_type: enums::PACKET_DNS_QUERY_REQ,
            stream_id: 100,
            sequence_num: 200,
            fragment_id: 1,
            total_fragments: 2,
            compression_type: 1,
            session_cookie: 4,
            payload: b"tunnel-payload",
        },
        "socks5_syn" => BuildOptions {
            session_id: 0,
            packet_type: enums::PACKET_SOCKS5_SYN,
            stream_id: 0xABCD,
            sequence_num: 1,
            fragment_id: 0,
            total_fragments: 1,
            session_cookie: 200,
            payload: b"example.com:443",
            ..Default::default()
        },
        "stream_syn_ack" => BuildOptions {
            session_id: 255,
            packet_type: enums::PACKET_STREAM_SYN_ACK,
            stream_id: 1,
            sequence_num: 2,
            session_cookie: 0,
            ..Default::default()
        },
        other => panic!("unknown packet vector {other}"),
    }
}

const PACKET_VECTORS: &[(&str, &str, &str)] = &[
    ("session_init", "0705098368656c6c6f", "0jgdv1qfr700lf3"),
    ("ping_empty", "01070292", "00a9fv6"),
    (
        "stream_data",
        "040f11223344050902075d76706e2d64617461",
        "0b8yxpnplhh0oyrf4e0jfy2hk8qr8h",
    ),
    (
        "dns_query_req",
        "0332006400c8010201043374756e6e656c2d7061796c6f6164",
        "08ut7ntmn7l05jy11al0tq8hyq9j1hkzd0u34llw",
    ),
    (
        "socks5_syn",
        "001aabcd00010001c8d06578616d706c652e636f6d3a343433",
        "00ae7svnd3404y1gqhkrjh8nkzv4gctbh0g5ds1f",
    ),
    ("stream_syn_ack", "ff0a00010002002e", "jmueoziwohs1a"),
];

#[test]
fn build_raw_matches_and_round_trips() {
    for (name, raw_hex, b36) in PACKET_VECTORS {
        let opts = built_packet(name);
        let raw = build_raw(&opts).unwrap();
        assert_eq!(raw, hx(raw_hex), "raw bytes for {name}");
        assert_eq!(&base36_encode(&raw), b36, "base36 for {name}");

        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed.session_id, opts.session_id, "{name} sid");
        assert_eq!(parsed.packet_type, opts.packet_type, "{name} type");
        assert_eq!(parsed.session_cookie, opts.session_cookie, "{name} cookie");
        assert_eq!(parsed.payload, opts.payload, "{name} payload");
        if enums::has_stream(opts.packet_type) {
            assert_eq!(parsed.stream_id, Some(opts.stream_id), "{name} stream");
        }
        if enums::has_sequence(opts.packet_type) {
            assert_eq!(parsed.sequence_num, Some(opts.sequence_num), "{name} seq");
        }
        if enums::has_fragment(opts.packet_type) {
            let f = parsed.fragment.expect("fragment present");
            assert_eq!((f.id, f.total), (opts.fragment_id, opts.total_fragments));
        }
        if enums::has_compression(opts.packet_type) {
            assert_eq!(parsed.compression_type, Some(opts.compression_type));
        }
    }
}

#[test]
fn packed_control_block_vector() {
    let mut payload = Vec::new();
    append_packed_control_block(
        &mut payload,
        enums::PACKET_STREAM_DATA_ACK,
        0x1122,
        0x3344,
        5,
        9,
    );
    append_packed_control_block(&mut payload, enums::PACKET_STREAM_DATA_NACK, 1, 2, 0, 0);
    let opts = BuildOptions {
        session_id: 10,
        packet_type: enums::PACKET_PACKED_CONTROL_BLOCKS,
        compression_type: 0,
        session_cookie: 11,
        payload: &payload,
        ..Default::default()
    };
    let raw = build_raw(&opts).unwrap();
    assert_eq!(raw, hx("0a13000bfb1011223344050911000100020000"));
    assert_eq!(base36_encode(&raw), "0rx5fck6h3l2msbclp4rgg01z16v40");

    let parsed = parse(&raw).unwrap();
    let blocks: Vec<PackedControlBlock> = iter_packed_control_blocks(parsed.payload).collect();
    assert_eq!(
        blocks,
        vec![
            PackedControlBlock {
                packet_type: enums::PACKET_STREAM_DATA_ACK,
                stream_id: 0x1122,
                sequence_num: 0x3344,
                fragment_id: 5,
                total_fragments: 9,
            },
            PackedControlBlock {
                packet_type: enums::PACKET_STREAM_DATA_NACK,
                stream_id: 1,
                sequence_num: 2,
                fragment_id: 0,
                total_fragments: 0,
            },
        ]
    );
}

#[test]
fn is_packable_follows_the_rules() {
    assert!(is_packable_control_packet(enums::PACKET_STREAM_DATA_ACK, 0));
    // A data packet is never packable, and a nonzero payload disqualifies.
    assert!(!is_packable_control_packet(enums::PACKET_STREAM_DATA, 0));
    assert!(!is_packable_control_packet(
        enums::PACKET_STREAM_DATA_ACK,
        3
    ));
}

#[test]
fn header_check_rejects_a_flipped_byte() {
    let raw = build_raw(&built_packet("session_init")).unwrap();
    assert_eq!(parse(&raw).unwrap().packet_type, enums::PACKET_SESSION_INIT);
    let mut broken = raw.clone();
    broken[0] ^= 0xFF; // change the session id, check byte no longer matches
    assert_eq!(parse(&broken), Err(packet::PacketError::BadCheck));
}

#[test]
fn header_check_byte_is_stable() {
    // Independent of build_raw, pin the function on a known header.
    assert_eq!(header_check_byte(&[0x0a, 0x13, 0x00, 0x0b]), 0xfb);
    assert_eq!(header_check_byte(&[0x01, 0x07, 0x02]), 0x92);
}

#[test]
fn invalid_and_short_packets_are_rejected() {
    assert_eq!(parse(&[0, 0]), Err(packet::PacketError::TooShort));
    // Type 0x00 is not a valid packet type.
    assert_eq!(parse(&[0, 0, 0, 0]), Err(packet::PacketError::InvalidType));
}

// (method, raw key, nonce hex, plaintext hex, sealed hex)
const AEAD_VECTORS: &[(u8, &str, &str, &str, &str)] = &[
    (
        5,
        "0123456789abcdef0123456789abcdef",
        "000102030405060708090a0b",
        "6d6173746572646e7376706e2d726f756e64747269702d74657374",
        "000102030405060708090a0b2c8f2835d957c39a25876e0ec2ec87705c328766951a85def5489792b5c2ede3b088bd41c97f89a866fb77",
    ),
    (
        5,
        "0123456789abcdef0123456789abcdef",
        "ffeeddccbbaa998877665544",
        "",
        "ffeeddccbbaa998877665544ef26c2b3937de76ff74936439dde4b37",
    ),
    (
        3,
        "0123456789abcdef",
        "0b0a09080706050403020100",
        "616573313238",
        "0b0a090807060504030201002e126ca019041c9c6c903f156128f737408b5159cfe2",
    ),
    (
        4,
        "0123456789abcdef01234567",
        "112233445566778899aabbcc",
        "6165733139322d67636d207061796c6f6164",
        "112233445566778899aabbcc22b96e129e386fbb99fae3063b173c8fa790d8282cd54524e0d1ef3093a423b732fd",
    ),
];

#[test]
fn aes_gcm_matches_go_and_round_trips() {
    for (method, raw_key, nonce_hex, pt_hex, sealed_hex) in AEAD_VECTORS {
        let codec = Codec::new(*method, raw_key).unwrap();
        let nonce = hx(nonce_hex);
        let pt = hx(pt_hex);
        let sealed = hx(sealed_hex);

        // The exact sealed bytes must match the Go output under the same nonce.
        assert_eq!(
            codec.seal_with_nonce(&nonce, &pt),
            sealed,
            "seal method {method}"
        );
        // Opening the Go-sealed blob returns the plaintext.
        assert_eq!(codec.decrypt(&sealed).unwrap(), pt, "open method {method}");
        // And a fresh random-nonce round trip returns the plaintext too.
        let fresh = codec.encrypt(&pt);
        assert_eq!(codec.decrypt(&fresh).unwrap(), pt, "round trip {method}");
    }
}

#[test]
fn a_tampered_tag_fails_to_open() {
    let codec = Codec::new(5, "0123456789abcdef0123456789abcdef").unwrap();
    let mut sealed = codec.encrypt(b"secret payload");
    let last = sealed.len() - 1;
    sealed[last] ^= 0x01;
    assert_eq!(codec.decrypt(&sealed), Err(CodecError::InvalidCiphertext));
}

#[test]
fn chacha20_is_unsupported_and_bad_methods_are_rejected() {
    // Codec holds cipher state and is not comparable, so match on the error.
    assert_eq!(
        Codec::new(2, "key").err(),
        Some(CodecError::UnsupportedMethod)
    );
    assert_eq!(Codec::new(6, "key").err(), Some(CodecError::InvalidMethod));
}

// (raw key, plaintext hex, ciphertext hex)
const XOR_VECTORS: &[(&str, &str, &str)] = &[
    ("key-material", "786f722d64617461", "130a0b0009000004"),
    (
        "key-material",
        "61206c6f6e67657220706c61696e746578742074686174206578636565647320746865207468697274792d74776f2062797465206b6579206c656e6774682062792061206c6f74",
        "0a4515420306111752190d0d696e7465787420746861742065786365656473201f0d1c0d19091d1706104c18776f2062797465206b6579206c656e67746820621245180d010e00",
    ),
];

#[test]
fn xor_matches_go_and_round_trips() {
    for (raw_key, pt_hex, ct_hex) in XOR_VECTORS {
        let codec = Codec::new(1, raw_key).unwrap();
        let pt = hx(pt_hex);
        let ct = hx(ct_hex);
        assert_eq!(codec.encrypt(&pt), ct, "xor encrypt");
        assert_eq!(codec.decrypt(&ct).unwrap(), pt, "xor decrypt");
    }
}

#[test]
fn method_none_is_identity_through_the_label_codec() {
    let codec = Codec::new(0, "").unwrap();
    let raw = build_raw(&built_packet("session_init")).unwrap();
    let labels = codec.encrypt_and_encode(&raw);
    // With no encryption the labels are just base36 of the raw packet.
    assert_eq!(labels, base36_encode(&raw));
    assert_eq!(codec.decode_and_decrypt(&labels).unwrap(), raw);
}

#[test]
fn session_accept_payload_vectors() {
    let base = SessionAcceptPayload {
        session_id: 0x11,
        session_cookie: 0x22,
        compression_pair: 0x33,
        verify_code: [0xde, 0xad, 0xbe, 0xef],
        client_policy: None,
    };
    assert_eq!(encode_session_accept_payload(&base), hx("112233deadbeef"));

    let full = SessionAcceptPayload {
        client_policy: Some(SessionAcceptClientPolicy {
            max_packet_duplication_count: 3,
            max_setup_duplication_count: 5,
            max_upload_mtu: 180,
            max_download_mtu: 1200,
            max_rx_tx_workers: 4,
            min_ping_aggressive_interval: 0.2,
            max_packets_per_batch: 32,
            max_arq_window_size: 256,
            max_arq_data_nack_max_gap: 7,
            min_compression_min_size: 64,
            min_arq_initial_rto_seconds: 0.3,
        }),
        ..base
    };
    let encoded = encode_session_accept_payload(&full);
    assert_eq!(encoded, hx("112233deadbeef53b404b0042820010007004043"));

    // Round-trip the base fields; scaled fields come back within one step.
    let decoded = decode_session_accept_payload(&encoded).unwrap();
    assert_eq!(decoded.session_id, 0x11);
    assert_eq!(decoded.verify_code, [0xde, 0xad, 0xbe, 0xef]);
    let policy = decoded.client_policy.expect("policy present");
    assert_eq!(policy.max_download_mtu, 1200);
    assert_eq!(policy.max_arq_window_size, 256);
}

#[test]
fn scaled_byte_vectors() {
    assert_eq!(encode_session_scaled_byte(0.0), 0);
    assert_eq!(encode_session_scaled_byte(0.05), 0);
    assert_eq!(encode_session_scaled_byte(0.2), 40);
    assert_eq!(encode_session_scaled_byte(0.5), 121);
    assert_eq!(encode_session_scaled_byte(1.0), 255);
    assert_eq!(encode_session_scaled_byte(2.0), 255);
    // Decode is the rough inverse; 40 -> about 0.20.
    assert!((decode_session_scaled_byte(40) - 0.2).abs() < 0.01);
}

// (stream id, packet type, sequence, fragment, expected key)
const IDENTITY_KEYS: &[(u16, u8, u16, u8, u64)] = &[
    (
        0x1122,
        enums::PACKET_STREAM_DATA,
        0x3344,
        5,
        4822522427294725,
    ),
    (1, enums::PACKET_STREAM_CLOSE_WRITE, 2, 9, 1185410974208),
    (7, enums::PACKET_SESSION_CLOSE, 3, 1, 7928509628416),
    (0xffff, enums::PACKET_PING, 0xffff, 0xff, 72056524607848192),
];

#[test]
fn packet_identity_keys_match() {
    for (sid, ptype, seq, frag, key) in IDENTITY_KEYS {
        assert_eq!(
            enums::packet_identity_key(*sid, *ptype, *seq, *frag),
            *key,
            "identity key for type {ptype}"
        );
    }
}
