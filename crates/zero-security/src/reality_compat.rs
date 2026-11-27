//! REALITY compatibility, modelled in one place.
//!
//! PLAN-01 §7 is explicit about the shape of this: version-dependent REALITY
//! behaviour belongs in a single record, "never `if xray_version >=` scattered
//! through the tree". Two separate things drift between Xray releases and both
//! land here:
//!
//! 1. **A version gate.** Xray set a default `minClientVer` of 26.3.27 in
//!    July 2026. A server that enforces it drops any client reporting less,
//!    and the symptom is indistinguishable from a wrong public key — the
//!    server simply pipes the connection to the decoy site.
//! 2. **A capability gate.** REALITY derives its authentication key from the
//!    *same* ephemeral X25519 secret the ClientHello's key share carries. A
//!    fingerprint profile that does not offer the X25519 group therefore
//!    cannot carry a REALITY tag at all, no matter how good a disguise it is
//!    otherwise. RESEARCH-01 §19 wants that rejected when the config is
//!    compiled, not when the user's first connection silently falls back.

use crate::fingerprint::FingerprintProfile;
use crate::utls_profiles::profile_offers_x25519_key_share;

/// The Xray-core client version this build reports inside the sealed session
/// id. It is the newest gate value known to be deployed, so claiming it passes
/// every `minClientVer` currently in the wild while never claiming a version
/// whose behaviour we do not actually implement.
pub const REPORTED_CLIENT_VERSION: [u8; 3] = [26, 3, 27];

/// Xray's default `minClientVer` since July 2026.
pub const DEFAULT_MIN_CLIENT_VERSION: [u8; 3] = [26, 3, 27];

/// Which REALITY key-exchange generation a connection speaks.
///
/// Ordered, and `HybridKem` is the default, because current REALITY does not
/// treat the hybrid share as an enhancement — it *requires* it. The server
/// walks the ClientHello's key shares and gives up outright on one that has no
/// X25519MLKEM768 entry:
///
/// ```text
/// if peerPub2 == nil {
///     break // reject outdated/strange Client Hello that doesn't have
///           // X25519MLKEM768 before optional X25519
/// }
/// ```
///
/// (`REALITY/tls.go`, the server-side tag check.)
///
/// What makes this worth spelling out is how it fails. A rejected hello is not
/// answered with an error — REALITY's whole design is that an unrecognised
/// client is relayed to the decoy site, indistinguishably from real browsing.
/// So a classic-only client does not see "unsupported"; it sees a valid TLS
/// session with the decoy's real certificate, and any tunnel traffic it sends
/// goes to a host the censor chose. That is why this defaults on, and why the
/// differential oracle rather than a self-consistent test is what caught it.
///
/// `Classic` remains expressible for a genuinely old deployment, since an
/// extra key share is ignored by servers that predate the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RealityGeneration {
    /// Classic X25519-only key share. Refused by current REALITY servers.
    Classic,
    /// Offers X25519MLKEM768 before the classic X25519 share, which is the
    /// order the server's "ensure order" scan requires.
    #[default]
    HybridKem,
}

impl RealityGeneration {
    pub fn offers_hybrid_kem(self) -> bool {
        matches!(self, Self::HybridKem)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::HybridKem => "hybrid-kem",
        }
    }
}

/// Why a REALITY configuration cannot work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RealityIncompatibility {
    /// The named fingerprint profile carries no X25519 key share.
    FingerprintLacksX25519 { fingerprint: Box<str> },
    /// The name is not in the shipped uTLS corpus at all.
    UnknownFingerprint { fingerprint: Box<str> },
    /// The server's advertised gate is newer than the version we report.
    ClientVersionTooOld {
        reported: [u8; 3],
        required: [u8; 3],
    },
}

impl std::fmt::Display for RealityIncompatibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FingerprintLacksX25519 { fingerprint } => write!(
                f,
                "fingerprint {fingerprint:?} has no X25519 key share and cannot be used with REALITY"
            ),
            Self::UnknownFingerprint { fingerprint } => {
                write!(f, "fingerprint {fingerprint:?} is not in the uTLS corpus")
            }
            Self::ClientVersionTooOld { reported, required } => write!(
                f,
                "REALITY server requires client version {}.{}.{} but this build reports {}.{}.{}",
                required[0], required[1], required[2], reported[0], reported[1], reported[2]
            ),
        }
    }
}

impl std::error::Error for RealityIncompatibility {}

/// Everything version- or capability-dependent about one REALITY connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityCompatibility {
    /// Which key-exchange generation to offer.
    pub protocol_generation: RealityGeneration,
    /// The version placed in the sealed session id.
    pub reported_client_version: [u8; 3],
    /// The ClientHello family this connection wears.
    pub fingerprint_profile: FingerprintProfile,
    /// Whether the peer supplied an ML-DSA-65 verification key, enabling
    /// Xray's second certificate-binding check.
    pub supports_mldsa65: bool,
    /// The concrete corpus entry, when the config named one rather than a
    /// family. This is what the X25519 constraint is actually checked against.
    fingerprint_name: Option<Box<str>>,
}

impl Default for RealityCompatibility {
    fn default() -> Self {
        Self::new(FingerprintProfile::default())
    }
}

impl RealityCompatibility {
    pub fn new(fingerprint_profile: FingerprintProfile) -> Self {
        Self {
            protocol_generation: RealityGeneration::default(),
            reported_client_version: REPORTED_CLIENT_VERSION,
            fingerprint_profile,
            supports_mldsa65: false,
            fingerprint_name: None,
        }
    }

    /// Name the concrete corpus entry, when the config selected one.
    pub fn with_fingerprint_name(mut self, name: Option<impl Into<Box<str>>>) -> Self {
        self.fingerprint_name = name.map(Into::into);
        self
    }

    pub fn with_generation(mut self, generation: RealityGeneration) -> Self {
        self.protocol_generation = generation;
        self
    }

    pub fn with_hybrid_kem(mut self, enabled: bool) -> Self {
        self.protocol_generation = if enabled {
            RealityGeneration::HybridKem
        } else {
            RealityGeneration::Classic
        };
        self
    }

    pub fn with_mldsa65(mut self, enabled: bool) -> Self {
        self.supports_mldsa65 = enabled;
        self
    }

    pub fn fingerprint_name(&self) -> Option<&str> {
        self.fingerprint_name.as_deref()
    }

    /// Whether this build's reported version satisfies a server's gate.
    pub fn satisfies_min_client_version(&self, required: [u8; 3]) -> bool {
        self.reported_client_version >= required
    }

    /// Reject a combination that cannot complete a REALITY handshake.
    ///
    /// Checked against the concrete corpus entry when one was named, and
    /// against the family otherwise. `Unshaped` is refused outright: without a
    /// shaped hello there is no controlled key share to hide the tag in.
    pub fn validate(&self) -> Result<(), RealityIncompatibility> {
        if let Some(name) = self.fingerprint_name.as_deref() {
            return match profile_offers_x25519_key_share(name) {
                Some(true) => Ok(()),
                Some(false) => Err(RealityIncompatibility::FingerprintLacksX25519 {
                    fingerprint: name.into(),
                }),
                None => Err(RealityIncompatibility::UnknownFingerprint {
                    fingerprint: name.into(),
                }),
            };
        }
        if !family_supports_reality(self.fingerprint_profile) {
            return Err(RealityIncompatibility::FingerprintLacksX25519 {
                fingerprint: self.fingerprint_profile.as_str().into(),
            });
        }
        Ok(())
    }

    /// Validate both gates at once, given a server's advertised `minClientVer`.
    pub fn validate_against(&self, required: [u8; 3]) -> Result<(), RealityIncompatibility> {
        self.validate()?;
        if !self.satisfies_min_client_version(required) {
            return Err(RealityIncompatibility::ClientVersionTooOld {
                reported: self.reported_client_version,
                required,
            });
        }
        Ok(())
    }
}

/// Whether a fingerprint *family* can carry REALITY.
///
/// Resolved through the same corpus the shaped hello is built from, so this
/// cannot drift away from what actually goes on the wire.
pub fn family_supports_reality(profile: FingerprintProfile) -> bool {
    match profile {
        // No shaping means no controlled key share to seal the tag into.
        FingerprintProfile::Unshaped => false,
        other => profile_offers_x25519_key_share(other.as_str()).unwrap_or(false),
    }
}

/// Whether a named corpus profile can carry REALITY. `None` for a name the
/// corpus does not know.
pub fn named_profile_supports_reality(name: &str) -> Option<bool> {
    profile_offers_x25519_key_share(name)
}

/// Every fingerprint name the shipped corpus resolves to a concrete shape for.
///
/// Exposed so a parity test can prove the config compiler's independent copy
/// of the REALITY constraint agrees with the wire corpus for every one of
/// them, rather than for the handful someone remembered to list.
pub fn corpus_profile_names() -> &'static [&'static str] {
    crate::utls_profiles::CORPUS_PROFILE_NAMES
}

/// The names a `random`/`randomized` fingerprint can draw.
///
/// A config naming either commits to *all* of these, so REALITY can only be
/// allowed with a random fingerprint if every candidate can carry it.
pub fn modern_fingerprint_names() -> &'static [&'static str] {
    crate::utls_profiles::MODERN_FINGERPRINT_NAMES
}

/// Whether a `random`/`randomized` draw is safe to combine with REALITY.
pub fn random_draw_supports_reality() -> bool {
    modern_fingerprint_names()
        .iter()
        .all(|name| named_profile_supports_reality(name) == Some(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reported_version_clears_xrays_current_default_gate() {
        let compat = RealityCompatibility::new(FingerprintProfile::Chrome);
        assert!(compat.satisfies_min_client_version(DEFAULT_MIN_CLIENT_VERSION));
        assert!(compat.validate_against(DEFAULT_MIN_CLIENT_VERSION).is_ok());
    }

    #[test]
    fn a_newer_gate_than_we_implement_is_reported_rather_than_guessed_at() {
        let compat = RealityCompatibility::new(FingerprintProfile::Chrome);
        assert_eq!(
            compat.validate_against([27, 0, 0]),
            Err(RealityIncompatibility::ClientVersionTooOld {
                reported: REPORTED_CLIENT_VERSION,
                required: [27, 0, 0],
            })
        );
    }

    #[test]
    fn version_comparison_orders_by_component_not_lexically() {
        let mut compat = RealityCompatibility::new(FingerprintProfile::Chrome);
        compat.reported_client_version = [26, 10, 0];
        // 26.10.0 is newer than 26.9.9 even though "10" sorts before "9".
        assert!(compat.satisfies_min_client_version([26, 9, 9]));
        assert!(!compat.satisfies_min_client_version([26, 10, 1]));
    }

    #[test]
    fn a_profile_without_an_x25519_share_is_refused() {
        // The shipped Android/okhttp shape carries no key share at all.
        assert_eq!(
            named_profile_supports_reality("helloandroid_11_okhttp"),
            Some(false)
        );
        let compat = RealityCompatibility::new(FingerprintProfile::Android)
            .with_fingerprint_name(Some("helloandroid_11_okhttp"));
        assert_eq!(
            compat.validate(),
            Err(RealityIncompatibility::FingerprintLacksX25519 {
                fingerprint: "helloandroid_11_okhttp".into(),
            })
        );
    }

    #[test]
    fn an_unshaped_hello_cannot_carry_a_reality_tag() {
        assert!(!family_supports_reality(FingerprintProfile::Unshaped));
        assert!(RealityCompatibility::new(FingerprintProfile::Unshaped)
            .validate()
            .is_err());
    }

    #[test]
    fn an_unknown_corpus_name_is_distinguished_from_an_unsuitable_one() {
        let compat = RealityCompatibility::new(FingerprintProfile::Chrome)
            .with_fingerprint_name(Some("hellonetscape_3"));
        assert_eq!(
            compat.validate(),
            Err(RealityIncompatibility::UnknownFingerprint {
                fingerprint: "hellonetscape_3".into(),
            })
        );
    }

    #[test]
    fn the_modern_browser_families_all_carry_reality() {
        for profile in [
            FingerprintProfile::Chrome,
            FingerprintProfile::Firefox,
            FingerprintProfile::Safari,
            FingerprintProfile::Edge,
            FingerprintProfile::Ios,
        ] {
            assert!(
                family_supports_reality(profile),
                "{} should carry REALITY",
                profile.as_str()
            );
        }
    }

    #[test]
    fn generations_are_ordered_and_only_the_newer_one_offers_the_hybrid_share() {
        assert!(RealityGeneration::HybridKem > RealityGeneration::Classic);
        assert!(!RealityGeneration::Classic.offers_hybrid_kem());
        assert!(RealityGeneration::HybridKem.offers_hybrid_kem());
        let compat = RealityCompatibility::new(FingerprintProfile::Chrome).with_hybrid_kem(true);
        assert_eq!(compat.protocol_generation, RealityGeneration::HybridKem);
        assert!(!compat
            .with_hybrid_kem(false)
            .protocol_generation
            .offers_hybrid_kem());
    }

    #[test]
    fn the_hybrid_share_is_offered_by_default() {
        // Current REALITY rejects a hello without it, and a rejected hello is
        // relayed to the decoy site rather than refused — so defaulting this
        // off means silently tunnelling through a host the censor picked.
        let compat = RealityCompatibility::new(FingerprintProfile::Chrome);
        assert!(compat.protocol_generation.offers_hybrid_kem());
    }

    #[test]
    fn every_corpus_name_resolves_to_a_definite_answer() {
        for name in corpus_profile_names() {
            assert!(
                named_profile_supports_reality(name).is_some(),
                "{name} is listed in the corpus but has no shape"
            );
        }
    }
}
