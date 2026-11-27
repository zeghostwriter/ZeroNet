//! Tests for the sans-IO SOCKS handshake parser. Each test drives the state
//! machine with the exact bytes a SOCKS4/4a/5 client would send and checks the
//! ordered actions it emits, plus — for the success paths — that the parsed
//! [`Target`] re-encodes to the same stream-setup bytes the Go client builds.
//! Expected values are hand-computed against `socks_manager.go`.

use super::*;
use zero_protocol::masterdns::socks::build_target_payload;

/// Auth-off config: SOCKS5 offers "no auth", SOCKS4 is accepted.
fn open_cfg() -> SocksConfig {
    SocksConfig::default()
}

/// Auth-on config with a username and password.
fn auth_cfg() -> SocksConfig {
    SocksConfig {
        auth_required: true,
        user: b"u".to_vec(),
        pass: b"p".to_vec(),
    }
}

#[test]
fn supports_socks4_rules() {
    assert!(open_cfg().supports_socks4());
    // Username + password set: SOCKS4 cannot carry a password, so it is refused.
    assert!(!auth_cfg().supports_socks4());
    // Username only, empty password: SOCKS4 can still check the user id.
    let user_only = SocksConfig {
        auth_required: true,
        user: b"bob".to_vec(),
        pass: Vec::new(),
    };
    assert!(user_only.supports_socks4());
}

#[test]
fn socks5_connect_ipv4() {
    let mut h = SocksHandshake::new(open_cfg());
    let mut acts = h.push(&[0x05, 0x01, 0x00]);
    acts.extend(h.push(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB]));
    assert_eq!(
        acts,
        vec![
            SocksAction::Write(vec![0x05, 0x00]),
            SocksAction::Connect {
                target: Target {
                    address_type: ADDRESS_TYPE_IPV4,
                    host: "1.2.3.4".to_string(),
                    port: 443,
                },
                socks_version: 0x05,
            },
        ]
    );
    assert!(h.succeeded());
    // The target re-encodes to the exact SOCKS5_SYN payload Go would send.
    if let SocksAction::Connect { target, .. } = &acts[1] {
        assert_eq!(
            build_target_payload(target),
            vec![0x01, 1, 2, 3, 4, 0x01, 0xBB]
        );
    }
}

#[test]
fn socks5_connect_domain() {
    let mut h = SocksHandshake::new(open_cfg());
    let mut bytes = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 11];
    bytes.extend_from_slice(b"example.com");
    bytes.extend_from_slice(&[0x01, 0xBB]);
    let acts = h.push(&bytes);
    assert_eq!(acts[0], SocksAction::Write(vec![0x05, 0x00]));
    match &acts[1] {
        SocksAction::Connect {
            target,
            socks_version,
        } => {
            assert_eq!(*socks_version, 0x05);
            assert_eq!(target.address_type, ADDRESS_TYPE_DOMAIN);
            assert_eq!(target.host, "example.com");
            assert_eq!(target.port, 443);
            let mut want = vec![0x03, 11];
            want.extend_from_slice(b"example.com");
            want.extend_from_slice(&[0x01, 0xBB]);
            assert_eq!(build_target_payload(target), want);
        }
        other => panic!("expected Connect, got {other:?}"),
    }
}

#[test]
fn socks5_connect_ipv6() {
    let mut h = SocksHandshake::new(open_cfg());
    let mut bytes = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x04];
    let ip = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // ::1
    bytes.extend_from_slice(&ip);
    bytes.extend_from_slice(&[0x01, 0xBB]);
    let acts = h.push(&bytes);
    match &acts[1] {
        SocksAction::Connect { target, .. } => {
            assert_eq!(target.address_type, ADDRESS_TYPE_IPV6);
            assert_eq!(target.host, "::1");
            assert_eq!(target.port, 443);
            let mut want = vec![0x04];
            want.extend_from_slice(&ip);
            want.extend_from_slice(&[0x01, 0xBB]);
            assert_eq!(build_target_payload(target), want);
        }
        other => panic!("expected Connect, got {other:?}"),
    }
}

#[test]
fn socks5_udp_associate() {
    let mut h = SocksHandshake::new(open_cfg());
    let acts = h.push(&[
        0x05, 0x01, 0x00, 0x05, 0x03, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35,
    ]);
    assert_eq!(acts[0], SocksAction::Write(vec![0x05, 0x00]));
    assert_eq!(
        acts[1],
        SocksAction::UdpAssociate {
            target: Target {
                address_type: ADDRESS_TYPE_IPV4,
                host: "1.2.3.4".to_string(),
                port: 53,
            },
        }
    );
    assert!(h.succeeded());
}

#[test]
fn socks5_unsupported_command_replies_and_closes() {
    let mut h = SocksHandshake::new(open_cfg());
    // Command 0x02 (BIND) is not supported.
    let acts = h.push(&[0x05, 0x01, 0x00, 0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80]);
    assert_eq!(
        acts,
        vec![
            SocksAction::Write(vec![0x05, 0x00]),
            SocksAction::Write(vec![0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
            SocksAction::Close,
        ]
    );
    assert!(h.is_finished());
    assert!(!h.succeeded());
}

#[test]
fn socks5_bad_reserved_byte_closes() {
    let mut h = SocksHandshake::new(open_cfg());
    let acts = h.push(&[0x05, 0x01, 0x00, 0x05, 0x01, 0x01, 0x01, 1, 2, 3, 4, 0, 80]);
    assert_eq!(
        acts,
        vec![SocksAction::Write(vec![0x05, 0x00]), SocksAction::Close]
    );
}

#[test]
fn socks5_no_acceptable_methods_when_auth_off() {
    // Auth is off but the client offers only user/pass (0x02), not no-auth.
    let mut h = SocksHandshake::new(open_cfg());
    let acts = h.push(&[0x05, 0x01, 0x02]);
    assert_eq!(
        acts,
        vec![SocksAction::Write(vec![0x05, 0xFF]), SocksAction::Close]
    );
}

#[test]
fn socks5_auth_success_then_connect() {
    let mut h = SocksHandshake::new(auth_cfg());
    let mut acts = h.push(&[0x05, 0x01, 0x02]);
    acts.extend(h.push(&[0x01, 1, b'u', 1, b'p']));
    acts.extend(h.push(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]));
    assert_eq!(
        acts,
        vec![
            SocksAction::Write(vec![0x05, 0x02]),
            SocksAction::AuthSucceeded,
            SocksAction::Write(vec![0x01, 0x00]),
            SocksAction::Connect {
                target: Target {
                    address_type: ADDRESS_TYPE_IPV4,
                    host: "1.2.3.4".to_string(),
                    port: 80,
                },
                socks_version: 0x05,
            },
        ]
    );
}

#[test]
fn socks5_auth_failure_writes_closes() {
    let mut h = SocksHandshake::new(auth_cfg());
    let mut acts = h.push(&[0x05, 0x01, 0x02]);
    acts.extend(h.push(&[0x01, 1, b'u', 1, b'x'])); // wrong password
    assert_eq!(
        acts,
        vec![
            SocksAction::Write(vec![0x05, 0x02]),
            SocksAction::Write(vec![0x01, 0x01]),
            SocksAction::AuthFailed,
            SocksAction::Close,
        ]
    );
    assert!(!h.succeeded());
}

#[test]
fn socks5_auth_required_but_not_offered() {
    let mut h = SocksHandshake::new(auth_cfg());
    // Client offers only no-auth; auth is required, so no acceptable method.
    let acts = h.push(&[0x05, 0x01, 0x00]);
    assert_eq!(
        acts,
        vec![SocksAction::Write(vec![0x05, 0xFF]), SocksAction::Close]
    );
}

#[test]
fn socks5_auth_header_wrong_version_closes() {
    let mut h = SocksHandshake::new(auth_cfg());
    let mut acts = h.push(&[0x05, 0x01, 0x02]);
    acts.extend(h.push(&[0x02, 1, b'u', 1, b'p'])); // auth version must be 0x01
    assert_eq!(
        acts,
        vec![SocksAction::Write(vec![0x05, 0x02]), SocksAction::Close]
    );
}

#[test]
fn socks4_connect_ip() {
    let mut h = SocksHandshake::new(open_cfg());
    // ver, CONNECT, port 443, 1.2.3.4, empty user id.
    let acts = h.push(&[0x04, 0x01, 0x01, 0xBB, 1, 2, 3, 4, 0x00]);
    assert_eq!(
        acts,
        vec![SocksAction::Connect {
            target: Target {
                address_type: ADDRESS_TYPE_IPV4,
                host: "1.2.3.4".to_string(),
                port: 443,
            },
            socks_version: 0x04,
        }]
    );
}

#[test]
fn socks4a_connect_domain() {
    let mut h = SocksHandshake::new(open_cfg());
    let mut bytes = vec![0x04, 0x01, 0x01, 0xBB, 0, 0, 0, 1, 0x00]; // IP 0.0.0.1 => 4a
    bytes.extend_from_slice(b"example.com\x00");
    let acts = h.push(&bytes);
    assert_eq!(
        acts,
        vec![SocksAction::Connect {
            target: Target {
                address_type: ADDRESS_TYPE_DOMAIN,
                host: "example.com".to_string(),
                port: 443,
            },
            socks_version: 0x04,
        }]
    );
}

#[test]
fn socks4_non_connect_command_rejected() {
    let mut h = SocksHandshake::new(open_cfg());
    let acts = h.push(&[0x04, 0x02, 0, 80, 1, 2, 3, 4]); // BIND, not CONNECT
    assert_eq!(
        acts,
        vec![
            SocksAction::Write(vec![0x00, 0x5B, 0, 0, 0, 0, 0, 0]),
            SocksAction::Close,
        ]
    );
}

#[test]
fn socks4_auth_success() {
    let cfg = SocksConfig {
        auth_required: true,
        user: b"bob".to_vec(),
        pass: Vec::new(),
    };
    let mut h = SocksHandshake::new(cfg);
    let mut bytes = vec![0x04, 0x01, 0x01, 0xBB, 1, 2, 3, 4];
    bytes.extend_from_slice(b"bob\x00");
    let acts = h.push(&bytes);
    assert_eq!(
        acts,
        vec![
            SocksAction::AuthSucceeded,
            SocksAction::Connect {
                target: Target {
                    address_type: ADDRESS_TYPE_IPV4,
                    host: "1.2.3.4".to_string(),
                    port: 443,
                },
                socks_version: 0x04,
            },
        ]
    );
}

#[test]
fn socks4_auth_failure() {
    let cfg = SocksConfig {
        auth_required: true,
        user: b"bob".to_vec(),
        pass: Vec::new(),
    };
    let mut h = SocksHandshake::new(cfg);
    let mut bytes = vec![0x04, 0x01, 0x01, 0xBB, 1, 2, 3, 4];
    bytes.extend_from_slice(b"eve\x00"); // wrong user id
    let acts = h.push(&bytes);
    assert_eq!(
        acts,
        vec![
            SocksAction::AuthFailed,
            SocksAction::Write(vec![0x00, 0x5B, 0, 0, 0, 0, 0, 0]),
            SocksAction::Close,
        ]
    );
}

#[test]
fn socks4_refused_when_password_required() {
    // auth with a password set => SOCKS4 is not supported at all.
    let mut h = SocksHandshake::new(auth_cfg());
    let acts = h.push(&[0x04, 0x01, 0x01, 0xBB, 1, 2, 3, 4, 0x00]);
    assert_eq!(acts, vec![SocksAction::Close]);
}

#[test]
fn socks4a_empty_domain_rejected() {
    let mut h = SocksHandshake::new(open_cfg());
    // userID empty, then domain empty.
    let acts = h.push(&[0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, 0x00, 0x00]);
    assert_eq!(
        acts,
        vec![
            SocksAction::Write(vec![0x00, 0x5B, 0, 0, 0, 0, 0, 0]),
            SocksAction::Close,
        ]
    );
}

#[test]
fn unknown_version_closes() {
    let mut h = SocksHandshake::new(open_cfg());
    assert_eq!(h.push(&[0x06]), vec![SocksAction::Close]);
    assert!(h.is_finished());
}

#[test]
fn null_terminated_field_too_long_closes() {
    let mut h = SocksHandshake::new(open_cfg());
    let mut bytes = vec![0x04, 0x01, 0, 80, 1, 2, 3, 4];
    bytes.extend(std::iter::repeat_n(b'A', 256)); // 256 non-null, no terminator
    let acts = h.push(&bytes);
    assert_eq!(acts, vec![SocksAction::Close]);
}

#[test]
fn null_terminated_field_max_length_ok() {
    let mut h = SocksHandshake::new(open_cfg());
    let mut bytes = vec![0x04, 0x01, 0x01, 0xBB, 1, 2, 3, 4];
    bytes.extend(std::iter::repeat_n(b'A', 255)); // exactly 255 then terminator
    bytes.push(0x00);
    let acts = h.push(&bytes);
    // A 255-byte user id is accepted; the connect goes through.
    assert_eq!(acts.len(), 1);
    assert!(matches!(acts[0], SocksAction::Connect { .. }));
}

#[test]
fn byte_at_a_time_matches_batch() {
    let full = vec![
        0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB,
    ];

    let mut batch = SocksHandshake::new(open_cfg());
    let batch_acts = batch.push(&full);

    let mut drip = SocksHandshake::new(open_cfg());
    let mut drip_acts = Vec::new();
    for b in &full {
        drip_acts.extend(drip.push(&[*b]));
    }
    assert_eq!(batch_acts, drip_acts);
}

#[test]
fn take_remaining_returns_trailing_stream_bytes() {
    let mut h = SocksHandshake::new(open_cfg());
    let mut bytes = vec![
        0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB,
    ];
    // The client pipelined the first stream bytes right after the request.
    bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    let acts = h.push(&bytes);
    assert!(matches!(acts.last(), Some(SocksAction::Connect { .. })));
    assert_eq!(h.take_remaining(), vec![0xAA, 0xBB, 0xCC]);
    // Draining it twice yields nothing the second time.
    assert!(h.take_remaining().is_empty());
}

#[test]
fn finished_handshake_ignores_more_input() {
    let mut h = SocksHandshake::new(open_cfg());
    h.push(&[0x06]); // unknown version => Close
    assert!(h.is_finished());
    assert!(h.push(&[0x05, 0x01, 0x00]).is_empty());
}

// --- connect-result replies ------------------------------------------------

use zero_protocol::masterdns::enums::{
    PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED, PACKET_SOCKS5_AUTH_FAILED,
    PACKET_SOCKS5_COMMAND_UNSUPPORTED, PACKET_SOCKS5_CONNECTION_REFUSED,
    PACKET_SOCKS5_CONNECT_FAIL, PACKET_SOCKS5_HOST_UNREACHABLE, PACKET_SOCKS5_NETWORK_UNREACHABLE,
    PACKET_SOCKS5_RULESET_DENIED, PACKET_SOCKS5_TTL_EXPIRED, PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
    PACKET_STREAM_DATA,
};

#[test]
fn socks4_reply_bytes_match_go() {
    assert_eq!(socks4_reply(true), vec![0x00, 0x5A, 0, 0, 0, 0, 0, 0]);
    assert_eq!(socks4_reply(false), vec![0x00, 0x5B, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn socks5_connect_reply_is_ten_bytes_bound_to_zero() {
    // Success: [VER, REP, RSV, ATYP=IPv4, 0.0.0.0, port 0].
    assert_eq!(
        socks5_connect_reply(SOCKS5_SUCCESS),
        vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    );
    // A failure code just changes the second byte.
    assert_eq!(
        socks5_connect_reply(socks_reply_for_packet_type(PACKET_SOCKS5_HOST_UNREACHABLE)),
        vec![0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn socks_reply_code_for_each_failure_type() {
    assert_eq!(
        socks_reply_for_packet_type(PACKET_SOCKS5_RULESET_DENIED),
        0x02
    );
    assert_eq!(
        socks_reply_for_packet_type(PACKET_SOCKS5_NETWORK_UNREACHABLE),
        0x03
    );
    assert_eq!(
        socks_reply_for_packet_type(PACKET_SOCKS5_HOST_UNREACHABLE),
        0x04
    );
    assert_eq!(
        socks_reply_for_packet_type(PACKET_SOCKS5_CONNECTION_REFUSED),
        0x05
    );
    assert_eq!(socks_reply_for_packet_type(PACKET_SOCKS5_TTL_EXPIRED), 0x06);
    assert_eq!(
        socks_reply_for_packet_type(PACKET_SOCKS5_COMMAND_UNSUPPORTED),
        0x07
    );
    assert_eq!(
        socks_reply_for_packet_type(PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED),
        0x08
    );
}

#[test]
fn socks_reply_code_folds_the_rest_to_general_failure() {
    for t in [
        PACKET_SOCKS5_AUTH_FAILED,
        PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
        PACKET_SOCKS5_CONNECT_FAIL,
        // Anything unrecognised also folds to general failure.
        PACKET_STREAM_DATA,
    ] {
        assert_eq!(socks_reply_for_packet_type(t), 0x01);
    }
}
