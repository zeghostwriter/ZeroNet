//! Tests for the sans-IO MTU probe logic. These check the exact byte offsets,
//! the echo-validation rules, and the binary search against synthetic probes,
//! so the module can be trusted without a live resolver.

use std::time::Duration;

use super::*;
use zero_protocol::masterdns::enums::{PACKET_MTU_DOWN_RES, PACKET_MTU_UP_RES, PACKET_STREAM_DATA};

#[test]
fn reserve_is_zero_with_current_table() {
    // Both MaxHeaderRawSize and the DOWN_RES header are 11 bytes, so the
    // download probe reserves nothing: requested size == answer length.
    assert_eq!(mtu_down_response_reserve(), 0);
    assert_eq!(effective_download_mtu_probe_size(100), 100);
    assert_eq!(effective_download_mtu_probe_size(0), 0);
    assert_eq!(effective_download_mtu_probe_size(-5), 0);
}

#[test]
fn download_floor_is_session_accept_size() {
    assert_eq!(MIN_DOWNLOAD_MTU_FLOOR, 20);
}

#[test]
fn upload_payload_layout() {
    let p = build_upload_probe_payload(40, false, 0x01020304).unwrap();
    assert_eq!(p.len(), 40);
    assert_eq!(p[0], MTU_PROBE_RAW_RESPONSE);
    assert_eq!(&p[1..5], &[0x01, 0x02, 0x03, 0x04]);
    // Everything past the code is left zero.
    assert!(p[5..].iter().all(|&b| b == 0));

    let b = build_upload_probe_payload(10, true, 0xDEADBEEF).unwrap();
    assert_eq!(b[0], MTU_PROBE_BASE64_REPLY);
    assert_eq!(&b[1..5], &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn upload_payload_rejects_too_small() {
    assert!(build_upload_probe_payload(4, false, 1).is_none());
    assert!(build_upload_probe_payload(0, false, 1).is_none());
    assert!(build_upload_probe_payload(5, false, 1).is_some());
}

#[test]
fn download_payload_layout_and_request_len() {
    // request_len = max(7, upload_mtu); with a tiny upload it is the 7 floor.
    let probe = build_download_probe_payload(100, 5, false, 0xAABBCCDD).unwrap();
    assert_eq!(probe.effective_size, 100);
    assert_eq!(probe.payload.len(), 7);
    assert_eq!(probe.payload[0], MTU_PROBE_RAW_RESPONSE);
    assert_eq!(&probe.payload[1..5], &[0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(&probe.payload[5..7], &100u16.to_be_bytes());

    // A larger upload grows the request to carry it.
    let probe = build_download_probe_payload(300, 120, true, 1).unwrap();
    assert_eq!(probe.effective_size, 300);
    assert_eq!(probe.payload.len(), 120);
    assert_eq!(probe.payload[0], MTU_PROBE_BASE64_REPLY);
    assert_eq!(&probe.payload[5..7], &300u16.to_be_bytes());
}

#[test]
fn download_payload_rejects_below_floor() {
    // effective < 20 cannot be probed.
    assert!(build_download_probe_payload(19, 50, false, 1).is_none());
    assert!(build_download_probe_payload(20, 50, false, 1).is_some());
}

#[test]
fn upload_validation() {
    let mut good = Vec::new();
    good.extend_from_slice(&0x11223344u32.to_be_bytes());
    good.extend_from_slice(&150u16.to_be_bytes());
    assert!(validate_upload_response(
        PACKET_MTU_UP_RES,
        &good,
        0x11223344,
        150
    ));
    // Wrong type.
    assert!(!validate_upload_response(
        PACKET_STREAM_DATA,
        &good,
        0x11223344,
        150
    ));
    // Wrong length.
    assert!(!validate_upload_response(
        PACKET_MTU_UP_RES,
        &good[..5],
        0x11223344,
        150
    ));
    // Wrong code.
    assert!(!validate_upload_response(
        PACKET_MTU_UP_RES,
        &good,
        0x11223345,
        150
    ));
    // Wrong echoed size.
    assert!(!validate_upload_response(
        PACKET_MTU_UP_RES,
        &good,
        0x11223344,
        151
    ));
}

#[test]
fn download_validation() {
    let effective = 24;
    let mut good = vec![0u8; effective as usize];
    good[0..4].copy_from_slice(&0x55667788u32.to_be_bytes());
    good[4..6].copy_from_slice(&(effective as u16).to_be_bytes());
    assert!(validate_download_response(
        PACKET_MTU_DOWN_RES,
        &good,
        0x55667788,
        effective
    ));
    // Wrong type.
    assert!(!validate_download_response(
        PACKET_MTU_UP_RES,
        &good,
        0x55667788,
        effective
    ));
    // Length must equal the effective size exactly.
    assert!(!validate_download_response(
        PACKET_MTU_DOWN_RES,
        &good[..(effective as usize - 1)],
        0x55667788,
        effective
    ));
    // Wrong code.
    assert!(!validate_download_response(
        PACKET_MTU_DOWN_RES,
        &good,
        1,
        effective
    ));
    // Wrong echoed size.
    let mut bad = good.clone();
    bad[4..6].copy_from_slice(&(effective as u16 + 1).to_be_bytes());
    assert!(!validate_download_response(
        PACKET_MTU_DOWN_RES,
        &bad,
        0x55667788,
        effective
    ));
}

// --- binary search ---------------------------------------------------------

/// A probe that passes for any candidate at or below `limit`, with a fixed RTT.
fn monotone(limit: i32) -> impl FnMut(i32, bool) -> ProbeOutcome {
    move |value, _retry| {
        if value <= limit {
            ProbeOutcome::Pass(Duration::from_millis(5))
        } else {
            ProbeOutcome::Fail
        }
    }
}

#[test]
fn search_ceiling_accepts_immediately() {
    // limit above the ceiling: the first probe (high) passes.
    let mut calls = 0;
    let res = binary_search_mtu(38, 150, MIN_UPLOAD_MTU_FLOOR, 2, |v, r| {
        calls += 1;
        monotone(500)(v, r)
    });
    assert_eq!(res, Some((150, Duration::from_millis(5))));
    assert_eq!(calls, 1);
}

#[test]
fn search_finds_largest_passing() {
    let res = binary_search_mtu(38, 150, MIN_UPLOAD_MTU_FLOOR, 2, monotone(97));
    assert_eq!(res.map(|(v, _)| v), Some(97));
}

#[test]
fn search_floor_fails_returns_none() {
    // Even the floor (max(38,10)=38) fails.
    let res = binary_search_mtu(38, 150, MIN_UPLOAD_MTU_FLOOR, 2, monotone(10));
    assert_eq!(res, None);
}

#[test]
fn search_rejects_invalid_range() {
    assert_eq!(binary_search_mtu(38, 0, 10, 2, monotone(100)), None);
    // high < low after flooring.
    assert_eq!(binary_search_mtu(200, 150, 10, 2, monotone(500)), None);
}

#[test]
fn search_low_equals_high() {
    // Range collapses to a single value; passes.
    assert_eq!(
        binary_search_mtu(100, 100, 10, 2, monotone(100)).map(|(v, _)| v),
        Some(100)
    );
    // Single value fails.
    assert_eq!(binary_search_mtu(100, 100, 10, 2, monotone(50)), None);
}

#[test]
fn search_uses_retries() {
    // Fail the first attempt at the winning size, pass on the retry. With
    // retries=2 the candidate still counts as passing.
    let mut first_seen = std::collections::HashSet::new();
    let res = binary_search_mtu(38, 150, 10, 2, move |value, is_retry| {
        if value > 97 {
            return ProbeOutcome::Fail;
        }
        // First attempt at a value fails; the retry passes.
        if !is_retry && first_seen.insert(value) {
            ProbeOutcome::Fail
        } else {
            ProbeOutcome::Pass(Duration::from_millis(3))
        }
    });
    assert_eq!(res.map(|(v, _)| v), Some(97));
}

#[test]
fn search_cancel_aborts() {
    let res = binary_search_mtu(38, 150, 10, 2, |_v, _r| ProbeOutcome::Cancelled);
    assert_eq!(res, None);
}

// --- derived helpers --------------------------------------------------------

#[test]
fn upload_caps_and_floors() {
    assert_eq!(upload_max_limit(0), DEFAULT_UPLOAD_MAX_CAP);
    assert_eq!(upload_max_limit(-1), DEFAULT_UPLOAD_MAX_CAP);
    assert_eq!(upload_max_limit(1000), DEFAULT_UPLOAD_MAX_CAP);
    assert_eq!(upload_max_limit(150), 150);
    assert_eq!(upload_accept_floor(38), 38);
    assert_eq!(upload_accept_floor(5), MIN_UPLOAD_MTU_FLOOR);
    assert_eq!(download_accept_floor(100), 100);
    assert_eq!(download_accept_floor(5), MIN_DOWNLOAD_MTU_FLOOR);
}

#[test]
fn crypto_overhead_by_method() {
    assert_eq!(mtu_crypto_overhead(0), 0);
    assert_eq!(mtu_crypto_overhead(1), 0);
    assert_eq!(mtu_crypto_overhead(2), 16);
    assert_eq!(mtu_crypto_overhead(3), 28);
    assert_eq!(mtu_crypto_overhead(4), 28);
    assert_eq!(mtu_crypto_overhead(5), 28);
    assert_eq!(mtu_crypto_overhead(9), 0);
}

#[test]
fn safe_upload_mtu() {
    // Normal AEAD case: 150 - 28 = 122.
    assert_eq!(compute_safe_upload_mtu(150, 28), 122);
    // Floor at 64 then clamp back down to upload for a small mtu.
    assert_eq!(compute_safe_upload_mtu(50, 28), 50);
    // Exactly at the floor edge.
    assert_eq!(compute_safe_upload_mtu(90, 28), 64);
    assert_eq!(compute_safe_upload_mtu(0, 28), 0);
    assert_eq!(compute_safe_upload_mtu(-1, 0), 0);
}

#[test]
fn packed_blocks() {
    // floor(floor(1200*80/100)/7) = floor(960/7) = 137, clamped to 8.
    assert_eq!(max_packed_blocks(1200, 80, 8), 8);
    // Small mtu: floor(floor(40*80/100)/7) = floor(32/7) = 4.
    assert_eq!(max_packed_blocks(40, 80, 8), 4);
    // percent floored at 30.
    assert_eq!(max_packed_blocks(100, 10, 8), max_packed_blocks(100, 30, 8));
    // Always at least 1.
    assert_eq!(max_packed_blocks(1, 80, 8), 1);
    assert_eq!(max_packed_blocks(1000, 80, 0), 1);
}

#[test]
fn average_rtt_ignores_zero() {
    assert_eq!(average_mtu_probe_rtt(&[]), Duration::ZERO);
    assert_eq!(
        average_mtu_probe_rtt(&[Duration::ZERO, Duration::ZERO]),
        Duration::ZERO
    );
    assert_eq!(
        average_mtu_probe_rtt(&[Duration::from_millis(10), Duration::ZERO]),
        Duration::from_millis(10)
    );
    assert_eq!(
        average_mtu_probe_rtt(&[Duration::from_millis(10), Duration::from_millis(30)]),
        Duration::from_millis(20)
    );
}

#[test]
fn confirm_down_timeout_clamps() {
    // Default when window is zero or >= 1s.
    assert_eq!(
        confirm_resolver_down_timeout(Duration::ZERO),
        Duration::from_millis(350)
    );
    assert_eq!(
        confirm_resolver_down_timeout(Duration::from_secs(5)),
        Duration::from_millis(350)
    );
    // Sub-second window divided by three, then clamped low to 200ms.
    assert_eq!(
        confirm_resolver_down_timeout(Duration::from_millis(900)),
        Duration::from_millis(300)
    );
    assert_eq!(
        confirm_resolver_down_timeout(Duration::from_millis(300)),
        Duration::from_millis(200)
    );
}

#[test]
fn confirm_down_probe_size_clamps() {
    assert_eq!(confirm_resolver_down_probe_size(10), 32);
    assert_eq!(confirm_resolver_down_probe_size(64), 64);
    assert_eq!(confirm_resolver_down_probe_size(200), 96);
}
