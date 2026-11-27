//! Tests for the sans-IO session handshake. Each one drives the state machine
//! with explicit resolver sets, reply packets built from the real wire
//! encoders, and explicit `Instant`s, then checks the outcome and the state it
//! lands in. There is no Go handshake vector harness, so the expected values
//! are hand-computed against the Go `session.go` /
//! `session_accept.go` logic. Being a child module, the tests reach into the
//! private fields directly.

use super::*;
use zero_protocol::masterdns::compression::{pack_pair, TYPE_LZ4, TYPE_ZSTD};
use zero_protocol::masterdns::packet::encode_session_accept_payload;
use zero_protocol::masterdns::{SessionAcceptClientPolicy, SessionAcceptPayload};

/// A client-settings snapshot with the shipped defaults, for policy-apply tests.
fn default_settings() -> SessionAcceptClientSettings {
    SessionAcceptClientSettings {
        packet_duplication_count: 2,
        setup_packet_duplication_count: 2,
        max_upload_mtu: 150,
        max_download_mtu: 500,
        rx_tx_workers: 4,
        ping_aggressive_interval: 0.1,
        max_packets_per_batch: 8,
        arq_window_size: 600,
        arq_data_nack_max_gap: 16,
        compression_min_size: 100,
        arq_initial_rto_seconds: 1.0,
        arq_control_initial_rto_seconds: 0.5,
        arq_max_rto_seconds: 5.0,
        arq_control_max_rto_seconds: 3.0,
    }
}

/// Build a `SESSION_ACCEPT` payload on the wire the way the server would.
fn accept_bytes(
    session_id: u8,
    session_cookie: u8,
    compression_pair: u8,
    verify: [u8; 4],
    policy: Option<SessionAcceptClientPolicy>,
) -> Vec<u8> {
    encode_session_accept_payload(&SessionAcceptPayload {
        session_id,
        session_cookie,
        compression_pair,
        verify_code: verify,
        client_policy: policy,
    })
}

const V: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

#[test]
fn fresh_handshake_is_not_ready() {
    let now = Instant::now();
    let s = SessionHandshake::new(SessionConfig::client_defaults());
    assert!(!s.is_ready());
    assert_eq!(s.failures(), 0);
    assert!(!s.is_busy(now));
    assert_eq!(s.busy_until(), None);
    assert_eq!(s.session_id(), 0);
}

#[test]
fn begin_attempt_builds_and_caches_payload() {
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    let attempt = s.begin_attempt(&[true], V).expect("one valid resolver");
    assert_eq!(attempt.resolver_index, 0);
    assert_eq!(attempt.packet_type, PACKET_SESSION_INIT);
    // Default config: raw reply mode, codecs off, zero MTUs, verify in [6..10].
    assert_eq!(attempt.payload[0], 0);
    assert_eq!(&attempt.payload[6..10], &V);

    // A second begin with a *different* verify keeps the cached payload: every
    // racing copy of one attempt must carry the same code.
    let other = [1, 2, 3, 4];
    let again = s.begin_attempt(&[true], other).expect("still valid");
    assert_eq!(&again.payload[6..10], &V);
}

#[test]
fn begin_attempt_round_robin() {
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    let a = &[true, true, true];
    assert_eq!(s.begin_attempt(a, V).unwrap().resolver_index, 0);
    assert_eq!(s.begin_attempt(a, V).unwrap().resolver_index, 1);
    assert_eq!(s.begin_attempt(a, V).unwrap().resolver_index, 2);
    assert_eq!(s.begin_attempt(a, V).unwrap().resolver_index, 0);
}

#[test]
fn round_robin_skips_invalid() {
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    let a = &[true, false, true];
    // 0 (cursor->1), then from 1 skip the invalid middle to 2 (cursor->0),
    // then from 0 again.
    assert_eq!(s.begin_attempt(a, V).unwrap().resolver_index, 0);
    assert_eq!(s.begin_attempt(a, V).unwrap().resolver_index, 2);
    assert_eq!(s.begin_attempt(a, V).unwrap().resolver_index, 0);
}

#[test]
fn begin_attempt_no_valid_connections() {
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    assert_eq!(
        s.begin_attempt(&[], V),
        Err(SessionError::NoValidConnections)
    );
    assert_eq!(
        s.begin_attempt(&[false, false], V),
        Err(SessionError::NoValidConnections)
    );
}

#[test]
fn accept_with_matching_verify_is_accepted() {
    let now = Instant::now();
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    s.begin_attempt(&[true], V).unwrap();

    let pair = pack_pair(TYPE_ZSTD, TYPE_LZ4);
    let payload = accept_bytes(7, 9, pair, V, None);
    let outcome = s.apply_reply(PACKET_SESSION_ACCEPT, &payload, default_settings(), now);
    assert_eq!(
        outcome,
        SessionReplyOutcome::Accepted {
            session_id: 7,
            session_cookie: 9,
            response_mode: 0,
            upload_compression: TYPE_ZSTD,
            download_compression: TYPE_LZ4,
            applied_settings: None,
        }
    );
    assert!(s.is_ready());
    assert_eq!(s.session_id(), 7);
    assert_eq!(s.session_cookie(), 9);
    assert_eq!(s.upload_compression(), TYPE_ZSTD);
    assert_eq!(s.download_compression(), TYPE_LZ4);
    // The accept cleared the cached init state.
    assert!(s.init_payload.is_none());
}

#[test]
fn accept_with_wrong_verify_ignored() {
    let now = Instant::now();
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    s.begin_attempt(&[true], V).unwrap();
    let payload = accept_bytes(7, 9, 0, [9, 9, 9, 9], None);
    assert_eq!(
        s.apply_reply(PACKET_SESSION_ACCEPT, &payload, default_settings(), now),
        SessionReplyOutcome::Ignored
    );
    assert!(!s.is_ready());
}

#[test]
fn accept_malformed_ignored() {
    let now = Instant::now();
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    s.begin_attempt(&[true], V).unwrap();
    // Fewer than the 7-byte base payload cannot decode.
    assert_eq!(
        s.apply_reply(PACKET_SESSION_ACCEPT, &[0, 1, 2], default_settings(), now),
        SessionReplyOutcome::Ignored
    );
    assert!(!s.is_ready());
}

#[test]
fn accept_with_policy_clamps_window() {
    let now = Instant::now();
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    s.begin_attempt(&[true], V).unwrap();

    // Only the ARQ window max is tight (300 < the client's 600); every other
    // ceiling is loose, so the window is the single field that moves.
    let policy = SessionAcceptClientPolicy {
        max_packet_duplication_count: 15,
        max_setup_duplication_count: 15,
        max_upload_mtu: 255,
        max_download_mtu: 500,
        max_rx_tx_workers: 255,
        min_ping_aggressive_interval: 0.05,
        max_packets_per_batch: 255,
        max_arq_window_size: 300,
        max_arq_data_nack_max_gap: 255,
        min_compression_min_size: 1,
        min_arq_initial_rto_seconds: 0.05,
    };
    let payload = accept_bytes(3, 4, 0, V, Some(policy));
    let outcome = s.apply_reply(PACKET_SESSION_ACCEPT, &payload, default_settings(), now);
    match outcome {
        SessionReplyOutcome::Accepted {
            applied_settings: Some(settings),
            ..
        } => {
            assert_eq!(settings.arq_window_size, 300);
            // Everything else is untouched by the loose ceilings.
            assert_eq!(settings.packet_duplication_count, 2);
            assert_eq!(settings.setup_packet_duplication_count, 2);
            assert_eq!(settings.max_upload_mtu, 150);
            assert_eq!(settings.max_download_mtu, 500);
            assert_eq!(settings.rx_tx_workers, 4);
            assert_eq!(settings.max_packets_per_batch, 8);
            assert_eq!(settings.arq_data_nack_max_gap, 16);
            assert_eq!(settings.compression_min_size, 100);
        }
        other => panic!("expected Accepted with policy, got {other:?}"),
    }
    assert!(s.is_ready());
}

#[test]
fn busy_with_matching_verify_arms_cooldown() {
    let now = Instant::now();
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    s.begin_attempt(&[true], V).unwrap();
    let outcome = s.apply_reply(PACKET_SESSION_BUSY, &V, default_settings(), now);
    let retry_at = now + Duration::from_secs(60);
    assert_eq!(outcome, SessionReplyOutcome::Busy { retry_at });
    assert_eq!(s.busy_until(), Some(retry_at));
    assert!(s.is_busy(now));
    assert!(s.is_busy(now + Duration::from_secs(59)));
    // The cooldown edge is exclusive: at exactly retry_at it is over.
    assert!(!s.is_busy(retry_at));
    assert!(!s.is_ready());
}

#[test]
fn busy_with_wrong_verify_ignored() {
    let now = Instant::now();
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    s.begin_attempt(&[true], V).unwrap();
    assert_eq!(
        s.apply_reply(PACKET_SESSION_BUSY, &[0, 0, 0, 0], default_settings(), now),
        SessionReplyOutcome::Ignored
    );
    assert_eq!(s.busy_until(), None);
}

#[test]
fn busy_too_short_ignored() {
    let now = Instant::now();
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    s.begin_attempt(&[true], V).unwrap();
    assert_eq!(
        s.apply_reply(PACKET_SESSION_BUSY, &[0xDE, 0xAD], default_settings(), now),
        SessionReplyOutcome::Ignored
    );
    assert_eq!(s.busy_until(), None);
}

#[test]
fn reply_ignored_once_ready() {
    let now = Instant::now();
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    s.begin_attempt(&[true], V).unwrap();
    s.apply_reply(
        PACKET_SESSION_ACCEPT,
        &accept_bytes(1, 1, 0, V, None),
        default_settings(),
        now,
    );
    assert!(s.is_ready());
    // A late second accept (even a valid one) changes nothing.
    let late = s.apply_reply(
        PACKET_SESSION_ACCEPT,
        &accept_bytes(2, 2, 0, V, None),
        default_settings(),
        now,
    );
    assert_eq!(late, SessionReplyOutcome::Ignored);
    assert_eq!(s.session_id(), 1);
}

#[test]
fn unknown_packet_type_ignored() {
    let now = Instant::now();
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    s.begin_attempt(&[true], V).unwrap();
    assert_eq!(
        s.apply_reply(0x09, &V, default_settings(), now),
        SessionReplyOutcome::Ignored
    );
    assert!(!s.is_ready());
}

#[test]
fn retry_backoff_schedule() {
    let s = SessionHandshake::new(SessionConfig::client_defaults());
    // No failures: no wait.
    assert_eq!(s.retry_delay(0), Duration::ZERO);
    // Linear region (first five failures) all wait the 1 s base.
    for f in 1..=5 {
        assert_eq!(s.retry_delay(f), Duration::from_secs(1));
    }
    // Past the linear-after point the delay grows one step per failure.
    assert_eq!(s.retry_delay(6), Duration::from_secs(2));
    assert_eq!(s.retry_delay(7), Duration::from_secs(3));
    // ...up to the 60 s cap: 1 + (65-5) = 61 s would exceed it.
    assert_eq!(s.retry_delay(65), Duration::from_secs(60));
    assert_eq!(s.retry_delay(1000), Duration::from_secs(60));
}

#[test]
fn note_attempt_failed_tracks_and_resets() {
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    assert_eq!(s.note_attempt_failed(), Duration::from_secs(1));
    assert_eq!(s.failures(), 1);
    for _ in 2..=5 {
        assert_eq!(s.note_attempt_failed(), Duration::from_secs(1));
    }
    // Sixth failure crosses into the growing region.
    assert_eq!(s.note_attempt_failed(), Duration::from_secs(2));
    assert_eq!(s.failures(), 6);

    s.note_session_established();
    assert_eq!(s.failures(), 0);
}

#[test]
fn reset_session_clears_ready_and_cache() {
    let now = Instant::now();
    let mut s = SessionHandshake::new(SessionConfig::client_defaults());
    s.begin_attempt(&[true], V).unwrap();
    s.apply_reply(
        PACKET_SESSION_ACCEPT,
        &accept_bytes(5, 6, 0, V, None),
        default_settings(),
        now,
    );
    assert!(s.is_ready());

    s.reset_session();
    assert!(!s.is_ready());
    assert_eq!(s.session_id(), 0);
    assert_eq!(s.upload_compression(), TYPE_OFF);
    assert!(s.init_payload.is_none());

    // The next attempt builds a fresh payload with a new verify code.
    let fresh = [0x11, 0x22, 0x33, 0x44];
    let attempt = s.begin_attempt(&[true], fresh).unwrap();
    assert_eq!(&attempt.payload[6..10], &fresh);
}

#[test]
fn config_new_floors_the_schedule() {
    let cfg = SessionConfig::new(SessionConfig {
        retry_base: Duration::from_millis(10),
        retry_step: Duration::from_secs(100),
        retry_linear_after: 5000,
        retry_max: Duration::from_millis(1),
        busy_retry_interval: Duration::ZERO,
        ..SessionConfig::client_defaults()
    });
    assert_eq!(cfg.retry_base, Duration::from_millis(100));
    assert_eq!(cfg.retry_step, Duration::from_secs(60));
    assert_eq!(cfg.retry_linear_after, 1000);
    // max clamps up to base since 1 ms < the floored 100 ms base.
    assert_eq!(cfg.retry_max, Duration::from_millis(100));
    assert_eq!(cfg.busy_retry_interval, Duration::from_secs(1));
}

#[test]
fn effective_compression_disables_under_low_mtu() {
    // Upload MTU below the 100-byte warning threshold forces upload off; the
    // download MTU is comfortable so its codec stays.
    let (up, down) = effective_session_compression(TYPE_ZSTD, TYPE_ZSTD, 50, 200, 100);
    assert_eq!(up, TYPE_OFF);
    assert_eq!(down, TYPE_ZSTD);

    // MTU equal to the min-size (but above the warning threshold) also disables.
    let (_, down2) = effective_session_compression(TYPE_ZSTD, TYPE_ZSTD, 300, 100, 100);
    assert_eq!(down2, TYPE_OFF);

    // A zero (unknown) MTU leaves the codec untouched.
    let (up3, down3) = effective_session_compression(TYPE_LZ4, TYPE_LZ4, 0, 0, 100);
    assert_eq!(up3, TYPE_LZ4);
    assert_eq!(down3, TYPE_LZ4);
}

#[test]
fn effective_compression_folds_unknown_codec_off() {
    // An unknown codec id normalizes to off even with a healthy MTU.
    let (up, down) = effective_session_compression(99, 200, 400, 400, 100);
    assert_eq!(up, TYPE_OFF);
    assert_eq!(down, TYPE_OFF);
}

#[test]
fn apply_policy_clamps_like_go() {
    let mut current = default_settings();
    current.packet_duplication_count = 10;
    current.setup_packet_duplication_count = 1;

    let policy = SessionAcceptClientPolicy {
        max_packet_duplication_count: 3,
        max_setup_duplication_count: 0,
        max_upload_mtu: 255,
        max_download_mtu: 500,
        max_rx_tx_workers: 255,
        min_ping_aggressive_interval: 0.05,
        max_packets_per_batch: 255,
        max_arq_window_size: 65535,
        max_arq_data_nack_max_gap: 255,
        min_compression_min_size: 1,
        min_arq_initial_rto_seconds: 0.05,
    };
    let out = apply_session_accept_client_policy(current, &policy);
    // packet dup clamps down to the ceiling of 3.
    assert_eq!(out.packet_duplication_count, 3);
    // setup dup is then raised to the new packet-dup floor of 3 even though its
    // own policy max is 0, because that max is lifted to packet_dup first.
    assert_eq!(out.setup_packet_duplication_count, 3);
}

#[test]
fn apply_policy_raises_compression_min_size() {
    let mut current = default_settings();
    current.compression_min_size = 100;
    let mut policy = SessionAcceptClientPolicy {
        max_packet_duplication_count: 15,
        max_setup_duplication_count: 15,
        max_upload_mtu: 255,
        max_download_mtu: 500,
        max_rx_tx_workers: 255,
        min_ping_aggressive_interval: 0.05,
        max_packets_per_batch: 255,
        max_arq_window_size: 65535,
        max_arq_data_nack_max_gap: 255,
        min_compression_min_size: 250,
        min_arq_initial_rto_seconds: 0.05,
    };
    // The server demands a larger minimum than the client picked: it wins.
    let out = apply_session_accept_client_policy(current, &policy);
    assert_eq!(out.compression_min_size, 250);

    // A zero policy minimum floors at 1, never below the client's own value.
    policy.min_compression_min_size = 0;
    let out2 = apply_session_accept_client_policy(current, &policy);
    assert_eq!(out2.compression_min_size, 100);
}
