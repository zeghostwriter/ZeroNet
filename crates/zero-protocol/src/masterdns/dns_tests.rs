//! Byte-exact tests for the DNS carrier framing.
//!
//! Every expected value here was produced by a small Go harness
//! (`cmd/dnsvec`) that calls the upstream `internal/dnsparser` and
//! `internal/vpnproto` packages directly at the pinned release. A passing run
//! means this Rust framing and that Go server agree byte for byte: the same
//! question bytes go out, and the same raw frame comes back from a response.
//! The DNS transaction id is fixed at zero in the vectors so the bytes are
//! deterministic.

use super::dns::{
    build_tunnel_txt_question, encode_dns_name_strict, extract_txt_bytes, extract_vpn_frame,
    max_encoded_qname_chars, parse_dns_packet, reassemble_vpn_frame, DnsError, DNS_RECORD_TYPE_TXT,
    EDNS_SAFE_UDP_SIZE,
};
use super::packet;

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in test vector")
}

// (domain, frame hex, edns udp size, expected question packet hex with id=0)
const QUESTIONS: &[(&str, &str, u16, &str)] = &[
    (
        "vpn.example.com",
        "",
        4096,
        "0000010000010000000000010376706e076578616d706c6503636f6d00001000010000291000000000000000",
    ),
    (
        "vpn.example.com",
        "616263",
        4096,
        "000001000001000000000001036162630376706e076578616d706c6503636f6d00001000010000291000000000000000",
    ),
    (
        "t.io",
        "303132333435363738396162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738396162636465666768696a6b6c6d6e6f",
        4096,
        "0000010000010000000000013d303132333435363738396162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738396162636465666768696a6b6c6d6e6f017402696f00001000010000291000000000000000",
    ),
    (
        "t.io",
        "303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132",
        4096,
        "0000010000010000000000013f303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132017402696f00001000010000291000000000000000",
    ),
    (
        "t.io",
        "30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839",
        4096,
        "0000010000010000000000013f3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031320733343536373839017402696f00001000010000291000000000000000",
    ),
    (
        "vpn.example.com",
        "68656c6c6f",
        0,
        "0000010000010000000000000568656c6c6f0376706e076578616d706c6503636f6d0000100001",
    ),
];

#[test]
fn build_tunnel_txt_question_matches_go() {
    for (domain, frame_hex, edns, expected) in QUESTIONS {
        let frame = hx(frame_hex);
        let got = build_tunnel_txt_question(domain, &frame, 0, DNS_RECORD_TYPE_TXT, *edns).unwrap();
        assert_eq!(
            hex::encode(&got),
            *expected,
            "question for {domain:?} frame={frame_hex:?} edns={edns}"
        );
    }
}

#[test]
fn a_name_longer_than_the_limit_is_refused() {
    // 300 label chars under a short domain blows past 253 bytes on the wire.
    let frame = vec![b'a'; 300];
    assert_eq!(
        build_tunnel_txt_question("t.io", &frame, 0, DNS_RECORD_TYPE_TXT, 4096),
        Err(DnsError::InvalidName)
    );
}

// (base64-encoded answers?, response packet hex with id=0, expected raw frame hex)
const RESPONSES: &[(bool, &str, &str)] = &[
    (
        false,
        "000081800001000100000001036162630376706e076578616d706c6503636f6d00001000010376706e076578616d706c6503636f6d000010000100000000003433110f2233445500000000ab000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526270000291000000000000000",
        "110f2233445500000000ab000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
    ),
    (
        true,
        "000081800001000100000001036162630376706e076578616d706c6503636f6d00001000010376706e076578616d706c6503636f6d000010000100000000004544455138694d30525641414141414b734141514944424155474277674a4367734d4451345045424553457851564668635947526f62484230654879416849694d6b4a53596e0000291000000000000000",
        "110f2233445500000000ab000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
    ),
    (
        false,
        "000081800001000200000001036162630376706e076578616d706c6503636f6d00001000010376706e076578616d706c6503636f6d0000100001000000000100ff0002110f2233445500000000ab000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1c0250010000100000000003c3b01f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b0000291000000000000000",
        "110f2233445500000000ab000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b",
    ),
    (
        true,
        "000081800001000200000001036162630376706e076578616d706c6503636f6d00001000010376706e076578616d706c6503636f6d0000100001000000000100ff414149524479497a52465541414141417177414241674d454251594843416b4b4377774e4467385145524954464255574678675a4768736348523466494345694979516c4a69636f4b536f724c4330754c7a41784d6a4d304e5459334f446b364f7a7739506a394151554a44524556475230684a536b744d545535505546465355315256566c6459575670625846316558324268596d4e6b5a575a6e61476c7161327874626d397763584a7a6448563264336835656e74386658352f6749474367345346686f65496959714c6a49324f6a3543526b704f556c5a61586d4a6d616d3579646e702b676f614b6a704b576d703669707171757372613676734c45c025001000010000000000a5a441624b7a744c573274376935757275387662362f774d484377385446787366497963724c7a4d334f7a3944523074505531646258324e6e6132397a6433742f6734654c6a354f586d352b6a70367576733765377638504879382f5431397666342b6672372f50332b2f77414241674d454251594843416b4b4377774e4467385145524954464255574678675a4768736348523466494345694979516c4a69636f4b536f720000291000000000000000",
        "110f2233445500000000ab000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b",
    ),
    (
        false,
        "000081800001000100000001036162630376706e076578616d706c6503636f6d00001000010376706e076578616d706c6503636f6d0000100001000000000005040708008b0000291000000000000000",
        "0708008b",
    ),
];

#[test]
fn extract_vpn_frame_matches_go() {
    for (base_encoded, resp_hex, expected_raw) in RESPONSES {
        let resp = hx(resp_hex);
        let got = extract_vpn_frame(&resp, *base_encoded).unwrap();
        assert_eq!(
            hex::encode(&got),
            *expected_raw,
            "extract (base64={base_encoded}) from {resp_hex}"
        );
        // The recovered frame must be a packet our own parser accepts.
        packet::parse(&got).expect("reassembled frame parses");
    }
}

#[test]
fn the_recovered_frame_carries_the_servers_fields() {
    // The short STREAM_DATA response: session 0x11, stream 0x2233, seq 0x4455.
    let resp = hx(RESPONSES[0].1);
    let raw = extract_vpn_frame(&resp, false).unwrap();
    let parsed = packet::parse(&raw).unwrap();
    assert_eq!(parsed.session_id, 0x11);
    assert_eq!(parsed.packet_type, super::enums::PACKET_STREAM_DATA);
    assert_eq!(parsed.stream_id, Some(0x2233));
    assert_eq!(parsed.sequence_num, Some(0x4455));
    assert_eq!(parsed.payload.len(), 40);
    assert_eq!(parsed.payload[0], 0x00);
    assert_eq!(parsed.payload[39], 0x27);
}

#[test]
fn parse_reads_the_header_question_and_answers() {
    // The two-answer chunked response: one real name plus one compression
    // pointer, both TXT.
    let resp = hx(RESPONSES[2].1);
    let parsed = parse_dns_packet(&resp).unwrap();
    assert!(parsed.header.is_response());
    assert_eq!(parsed.header.rcode(), 0);
    assert_eq!(parsed.header.qd_count, 1);
    assert_eq!(parsed.header.an_count, 2);
    assert_eq!(parsed.questions.len(), 1);
    assert_eq!(parsed.questions[0].name, "abc.vpn.example.com");
    assert_eq!(parsed.questions[0].qtype, DNS_RECORD_TYPE_TXT);
    assert_eq!(parsed.answers.len(), 2);
    for answer in &parsed.answers {
        assert_eq!(answer.rtype, DNS_RECORD_TYPE_TXT);
        // The compression pointer must resolve to the same answer name.
        assert_eq!(answer.name, "vpn.example.com");
    }
}

#[test]
fn names_round_trip_through_the_wire_form() {
    let wire = encode_dns_name_strict("vpn.example.com").unwrap();
    assert_eq!(hex::encode(&wire), "0376706e076578616d706c6503636f6d00");
    assert_eq!(encode_dns_name_strict("").unwrap(), vec![0u8]);
    // A single label over 63 bytes is rejected.
    assert_eq!(
        encode_dns_name_strict(&"a".repeat(64)),
        Err(DnsError::InvalidName)
    );
}

#[test]
fn txt_rdata_with_several_strings_is_joined() {
    // Two strings, 0x02 "hi" and 0x03 "bye", concatenate to "hibye".
    let rdata = [0x02, b'h', b'i', 0x03, b'b', b'y', b'e'];
    assert_eq!(extract_txt_bytes(&rdata), b"hibye");
    // A single full string takes the fast path.
    let single = [0x03, b'a', b'b', b'c'];
    assert_eq!(extract_txt_bytes(&single), b"abc");
}

#[test]
fn a_response_with_no_txt_answer_is_flagged() {
    // Header says one answer, but it is an A record, not TXT.
    let mut resp = Vec::new();
    resp.extend_from_slice(&[0, 0, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0]);
    resp.extend_from_slice(&encode_dns_name_strict("a.b").unwrap());
    resp.extend_from_slice(&1u16.to_be_bytes()); // type A
    resp.extend_from_slice(&1u16.to_be_bytes()); // class IN
    resp.extend_from_slice(&0u32.to_be_bytes()); // ttl
    resp.extend_from_slice(&4u16.to_be_bytes()); // rdlen
    resp.extend_from_slice(&[1, 2, 3, 4]);
    assert_eq!(
        extract_vpn_frame(&resp, false),
        Err(DnsError::TxtAnswerMissing)
    );
}

#[test]
fn a_chunk_set_missing_a_piece_is_malformed() {
    // chunk0 claims a total of 3 but only chunk0 and chunk1 arrive.
    let chunk0 = vec![0x00, 0x03, b'h', b'd', b'r'];
    let chunk1 = vec![0x01, b'x', b'y'];
    assert_eq!(
        reassemble_vpn_frame(&[chunk0, chunk1], false),
        Err(DnsError::TxtAnswerMalformed)
    );
}

#[test]
fn max_encoded_chars_stays_under_the_name_limit() {
    // For a short domain almost the whole 253 bytes is available to labels.
    let chars = max_encoded_qname_chars("t.io");
    assert!(chars > 180 && chars <= 253, "got {chars}");
    // Building at exactly the computed budget must succeed.
    let frame = vec![b'a'; chars];
    assert!(build_tunnel_txt_question("t.io", &frame, 0, DNS_RECORD_TYPE_TXT, 0).is_ok());
    // One more character must fail.
    let frame = vec![b'a'; chars + 1];
    assert_eq!(
        build_tunnel_txt_question("t.io", &frame, 0, DNS_RECORD_TYPE_TXT, 0),
        Err(DnsError::InvalidName)
    );
}

#[test]
fn edns_constant_matches_the_go_client() {
    assert_eq!(EDNS_SAFE_UDP_SIZE, 4096);
}
