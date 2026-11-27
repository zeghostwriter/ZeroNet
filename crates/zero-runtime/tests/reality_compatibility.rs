//! The config compiler and the TLS stack must agree about REALITY.
//!
//! `zero-config` deliberately does not depend on `zero-security`: a config has
//! to be checkable without dragging in the whole TLS stack, and RESEARCH-01
//! §19 wants impossible combinations refused at compile time rather than at
//! connect time. The price of that independence is a second copy of the
//! "which fingerprints can carry REALITY" rule.
//!
//! A duplicated rule that nobody compares is a rule that silently drifts, and
//! the failure mode here is the worst kind: a config the compiler accepts, a
//! handshake the server answers by piping the client to the decoy site, and no
//! error anywhere. So this test compares the two copies across every entry in
//! the shipped uTLS corpus — not a sample, and not the handful someone
//! remembered to list.

use zero_config::Fingerprint;
use zero_security::{
    family_supports_reality, named_profile_supports_reality, FingerprintProfile,
    RealityCompatibility, RealityGeneration, RealityIncompatibility, DEFAULT_MIN_CLIENT_VERSION,
};

/// Every fingerprint family `zero-config` can parse, paired with the
/// `zero-security` profile it compiles to.
const FAMILIES: &[(&str, FingerprintProfile)] = &[
    ("chrome", FingerprintProfile::Chrome),
    ("firefox", FingerprintProfile::Firefox),
    ("safari", FingerprintProfile::Safari),
    ("edge", FingerprintProfile::Edge),
    ("ios", FingerprintProfile::Ios),
    ("android", FingerprintProfile::Android),
    ("unshaped", FingerprintProfile::Unshaped),
];

#[test]
fn the_config_compiler_agrees_with_the_wire_corpus_on_every_named_profile() {
    let mut checked = 0usize;
    for name in zero_security::reality_compat::corpus_profile_names() {
        let Some(parsed) = Fingerprint::parse(name) else {
            // Families are covered by their own test below; anything else that
            // the corpus knows and the config rejects is a parity bug.
            assert!(
                FAMILIES.iter().any(|(family, _)| family == name),
                "{name} is in the uTLS corpus but zero-config will not parse it"
            );
            continue;
        };
        let from_config = parsed.supports_reality();
        let from_corpus = named_profile_supports_reality(name)
            .unwrap_or_else(|| panic!("{name} is listed in the corpus but has no shape"));
        assert_eq!(
            from_config, from_corpus,
            "zero-config says supports_reality={from_config} for {name}, \
             but its ClientHello shape says {from_corpus}"
        );
        checked += 1;
    }
    // A parity test that silently checks nothing is worse than no test.
    assert!(checked >= 50, "only {checked} profiles compared");
}

#[test]
fn the_config_compiler_agrees_with_the_wire_corpus_on_every_family() {
    for (name, profile) in FAMILIES {
        let parsed = Fingerprint::parse(name).expect("family parses");
        assert_eq!(
            parsed.supports_reality(),
            family_supports_reality(*profile),
            "family {name} disagrees between zero-config and zero-security"
        );
    }
}

#[test]
fn the_refusal_is_not_vacuous_at_least_one_shipped_profile_cannot_carry_reality() {
    let refused: Vec<&str> = zero_security::reality_compat::corpus_profile_names()
        .iter()
        .copied()
        .filter(|name| named_profile_supports_reality(name) == Some(false))
        .collect();
    assert!(
        !refused.is_empty(),
        "no shipped profile lacks an X25519 key share, so the REALITY \
         capability check can never fire and is not testing anything"
    );
    // And the compiler must refuse each of them by name, not just in aggregate.
    for name in refused {
        let parsed = Fingerprint::parse(name).expect("refused profile still parses");
        assert!(
            !parsed.supports_reality(),
            "{name} has no X25519 key share but zero-config accepts it for REALITY"
        );
    }
}

#[test]
fn a_reality_outbound_naming_an_unsuitable_profile_fails_at_compile_time() {
    let config = serde_json::json!({
        "inbounds": [{
            "tag": "socks",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": 0,
            "settings": {"udp": false}
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "203.0.113.10",
                "port": 443,
                "users": [{"id": "8c1b8a2e-0e1f-4a7d-9a2b-3c4d5e6f7081", "encryption": "none"}]
            }]},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": "www.googletagmanager.com",
                    "publicKey": "hK8vN2pQ4rS6tU8wY0aB2cD4eF6gH8iJ0kL2mN4oP6Q",
                    "shortId": "0123456789abcdef",
                    // No X25519 key share in this shape.
                    "fingerprint": "helloandroid_11_okhttp"
                }
            }
        }]
    });
    let text = zero_config::parse_config(&config)
        .expect_err("a REALITY outbound with no X25519 key share must not compile")
        .to_string();
    assert!(
        text.contains("X25519") && text.contains("REALITY"),
        "the error should name the actual constraint, got: {text}"
    );
}

#[test]
fn the_compatibility_record_reports_a_version_gate_it_cannot_satisfy() {
    let compat = RealityCompatibility::new(FingerprintProfile::Chrome);
    assert!(compat.validate_against(DEFAULT_MIN_CLIENT_VERSION).is_ok());
    assert!(matches!(
        compat.validate_against([99, 0, 0]),
        Err(RealityIncompatibility::ClientVersionTooOld { .. })
    ));
}

#[test]
fn the_hybrid_key_share_is_offered_by_default() {
    // Not a preference: current REALITY servers scan the ClientHello for an
    // X25519MLKEM768 share and abandon the tag check when there is none. The
    // connection is then relayed to the decoy site, so a classic-only client
    // believes it succeeded while tunnelling to a host it never chose.
    let compat = RealityCompatibility::new(FingerprintProfile::Chrome);
    assert_eq!(compat.protocol_generation, RealityGeneration::HybridKem);
    assert!(compat.protocol_generation.offers_hybrid_kem());
}

#[test]
fn a_random_fingerprint_is_only_allowed_with_reality_if_every_draw_can_carry_it() {
    // `random` commits the connection to whichever name the process drew, so
    // accepting it is a claim about the whole draw set rather than about one
    // profile. If a future corpus update adds a candidate with no X25519 key
    // share, this is where that shows up.
    let every_draw_works = zero_security::reality_compat::random_draw_supports_reality();
    for name in [Fingerprint::Random, Fingerprint::Randomized] {
        assert_eq!(
            name.supports_reality(),
            every_draw_works,
            "zero-config accepts {} for REALITY, but at least one name it can \
             draw has no X25519 key share",
            name.name()
        );
    }
}
