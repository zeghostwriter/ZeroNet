//! Tests for the payload-preparation seam. These check the gates that decide
//! whether an outbound payload is compressed, the automatic build path, and the
//! inbound inflate — including the round trip through a real codec and the
//! corrupt-frame rejection, against the Go `payload.go` behaviour.

use super::*;

use zero_protocol::masterdns::compression::{TYPE_LZ4, TYPE_ZLIB, TYPE_ZSTD};
use zero_protocol::masterdns::enums::{PACKET_PING, PACKET_STREAM_DATA};
use zero_protocol::masterdns::packet::parse;

/// A payload large and repetitive enough that every codec shrinks it well past
/// the 100-byte default threshold.
fn squishy() -> Vec<u8> {
    vec![42u8; 1000]
}

#[test]
fn prepare_sends_raw_when_codec_is_off() {
    let data = squishy();
    let (out, codec) = prepare_payload(PACKET_STREAM_DATA, &data, TYPE_OFF, 0);
    assert_eq!(codec, TYPE_OFF);
    assert!(matches!(out, Cow::Borrowed(_)));
    assert_eq!(out.as_ref(), &data[..]);
}

#[test]
fn prepare_sends_raw_for_a_type_without_a_compression_byte() {
    // PING carries no compression field, so even a very squishy payload and an
    // explicit codec request must go out uncompressed.
    let data = squishy();
    let (out, codec) = prepare_payload(PACKET_PING, &data, TYPE_ZSTD, 0);
    assert_eq!(codec, TYPE_OFF);
    assert!(matches!(out, Cow::Borrowed(_)));
}

#[test]
fn prepare_sends_raw_for_an_empty_payload() {
    let (out, codec) = prepare_payload(PACKET_STREAM_DATA, &[], TYPE_ZSTD, 0);
    assert_eq!(codec, TYPE_OFF);
    assert!(out.as_ref().is_empty());
}

#[test]
fn prepare_sends_raw_for_an_unknown_codec_id() {
    // 0x7F normalizes to off, so the request is treated as "no compression".
    let data = squishy();
    let (_out, codec) = prepare_payload(PACKET_STREAM_DATA, &data, 0x7F, 0);
    assert_eq!(codec, TYPE_OFF);
}

#[test]
fn prepare_compresses_a_large_payload_on_a_capable_type() {
    let data = squishy();
    let (out, codec) = prepare_payload(PACKET_STREAM_DATA, &data, TYPE_ZSTD, 0);
    assert_eq!(codec, TYPE_ZSTD);
    assert!(matches!(out, Cow::Owned(_)));
    assert!(out.len() < data.len());
}

#[test]
fn prepare_sends_raw_when_payload_is_below_the_min_size() {
    // Under the 100-byte default the payload is not worth compressing.
    let data = vec![42u8; 50];
    let (_out, codec) = prepare_payload(PACKET_STREAM_DATA, &data, TYPE_ZSTD, 0);
    assert_eq!(codec, TYPE_OFF);
}

#[test]
fn build_raw_auto_records_the_chosen_codec_and_round_trips() {
    let data = squishy();
    let opts = BuildOptions {
        packet_type: PACKET_STREAM_DATA,
        stream_id: 7,
        sequence_num: 3,
        compression_type: TYPE_ZSTD,
        payload: &data,
        ..Default::default()
    };
    let raw = build_raw_auto(&opts, 0).expect("build");

    let packet = parse(&raw).expect("parse");
    // The compression byte on the wire is the codec that actually ran, not the
    // one originally requested (here they match, because the payload shrank).
    assert_eq!(packet.compression_type, Some(TYPE_ZSTD));
    assert!(packet.payload.len() < data.len());

    let inflated = inflate_payload(&packet).expect("inflate");
    assert_eq!(inflated.as_ref(), &data[..]);
}

#[test]
fn build_raw_auto_falls_back_to_raw_when_nothing_shrinks() {
    // A tiny payload cannot beat the threshold, so the wire records off and the
    // bytes are carried verbatim.
    let data = vec![1u8, 2, 3, 4, 5];
    let opts = BuildOptions {
        packet_type: PACKET_STREAM_DATA,
        stream_id: 1,
        sequence_num: 1,
        compression_type: TYPE_ZSTD,
        payload: &data,
        ..Default::default()
    };
    let raw = build_raw_auto(&opts, 0).expect("build");
    let packet = parse(&raw).expect("parse");
    assert_eq!(packet.compression_type, Some(TYPE_OFF));
    assert_eq!(packet.payload, &data[..]);
}

#[test]
fn inflate_passes_through_uncompressed_payloads() {
    let data = squishy();
    let opts = BuildOptions {
        packet_type: PACKET_STREAM_DATA,
        stream_id: 1,
        sequence_num: 1,
        compression_type: TYPE_OFF,
        payload: &data,
        ..Default::default()
    };
    let raw = build_raw_auto(&opts, 0).expect("build");
    let packet = parse(&raw).expect("parse");
    assert_eq!(packet.compression_type, Some(TYPE_OFF));
    let inflated = inflate_payload(&packet).expect("inflate");
    assert!(matches!(inflated, Cow::Borrowed(_)));
    assert_eq!(inflated.as_ref(), &data[..]);
}

#[test]
fn inflate_rejects_a_corrupt_compressed_frame() {
    // Build a genuinely compressed packet, then overwrite the payload region
    // with bytes that are not a valid DEFLATE stream (a leading 0xFF selects a
    // reserved block type), leaving the header — and so the parse — intact.
    let data = squishy();
    let opts = BuildOptions {
        packet_type: PACKET_STREAM_DATA,
        stream_id: 1,
        sequence_num: 1,
        compression_type: TYPE_ZLIB,
        payload: &data,
        ..Default::default()
    };
    let raw = build_raw_auto(&opts, 0).expect("build");
    let header_len = parse(&raw).expect("parse").header_length;
    let mut corrupt = raw.clone();
    for b in &mut corrupt[header_len..] {
        *b = 0xFF;
    }
    let packet = parse(&corrupt).expect("parse");
    assert_eq!(packet.compression_type, Some(TYPE_ZLIB));
    assert_eq!(inflate_payload(&packet), Err(InvalidCompressedPayload));
}

#[test]
fn every_codec_round_trips_through_auto_build() {
    let data = squishy();
    for codec in [TYPE_ZSTD, TYPE_LZ4, TYPE_ZLIB] {
        let opts = BuildOptions {
            packet_type: PACKET_STREAM_DATA,
            stream_id: 1,
            sequence_num: 1,
            compression_type: codec,
            payload: &data,
            ..Default::default()
        };
        let raw = build_raw_auto(&opts, 0).expect("build");
        let packet = parse(&raw).expect("parse");
        assert_eq!(packet.compression_type, Some(codec));
        assert_eq!(
            inflate_payload(&packet).expect("inflate").as_ref(),
            &data[..]
        );
    }
}
