//! TLS ClientHello shaping.
//!
//! A stock Rust TLS hello is itself a fingerprint: it matches no browser, so
//! on a network that classifies by hello shape it stands out precisely because
//! it is unusual. This module biases the backend toward a named browser
//! profile.
//!
//! ## What this does and does not achieve
//!
//! The workspace uses the pinned shaped-rustls backend for the wire-visible
//! controls ordinary Rustls does not expose: extension ordering, GREASE,
//! padding, advertised suites/groups, key shares, ALPN, and the profile's
//! optional raw extensions. The profile registry remains outside the TLS
//! backend so a backend upgrade cannot silently replace the selected shape.

use std::sync::Arc;

use crate::utls_profiles::{profile_for_fingerprint, profile_shuffles_extensions};
use crate::utls_shaping::{
    apply_alpn_override, apply_utls_profile, profile_has_usable_cipher_suite,
};
use rustls::client::{
    ClientHelloAdvertisedSupportedVersions, ClientHelloPlan, ClientHelloSupportedVersions,
    WantsClientCert,
};
#[cfg(test)]
use rustls::SupportedCipherSuite;
use rustls::{ClientConfig, ConfigBuilder, Error as RustlsError, RootCertStore};

/// A named browser hello shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FingerprintProfile {
    #[default]
    Chrome,
    Firefox,
    Safari,
    Edge,
    Ios,
    Android,
    /// Do not shape; use the backend's native hello.
    Unshaped,
}

impl FingerprintProfile {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "chrome" => Self::Chrome,
            "firefox" => Self::Firefox,
            "safari" => Self::Safari,
            "edge" => Self::Edge,
            "ios" => Self::Ios,
            "android" => Self::Android,
            "" | "none" | "unshaped" => Self::Unshaped,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Edge => "edge",
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Unshaped => "unshaped",
        }
    }

    /// Whether this profile offers an X25519 key share, which REALITY needs.
    pub fn supports_reality(self) -> bool {
        !matches!(self, Self::Unshaped)
    }

    /// Cipher suites in the order this profile advertises them.
    ///
    /// Order is part of the fingerprint, so these lists are explicit rather
    /// than filtered from a default set whose order could shift under us.
    #[cfg(test)]
    fn cipher_suites(self) -> Vec<SupportedCipherSuite> {
        use rustls::crypto::ring::cipher_suite as cs;

        match self {
            // Chrome and Edge share Chromium's ordering.
            Self::Chrome | Self::Edge | Self::Android => vec![
                cs::TLS13_AES_128_GCM_SHA256,
                cs::TLS13_AES_256_GCM_SHA384,
                cs::TLS13_CHACHA20_POLY1305_SHA256,
                cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            // Firefox puts ChaCha20 ahead of AES-256.
            Self::Firefox => vec![
                cs::TLS13_AES_128_GCM_SHA256,
                cs::TLS13_CHACHA20_POLY1305_SHA256,
                cs::TLS13_AES_256_GCM_SHA384,
                cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ],
            Self::Safari | Self::Ios => vec![
                cs::TLS13_AES_128_GCM_SHA256,
                cs::TLS13_AES_256_GCM_SHA384,
                cs::TLS13_CHACHA20_POLY1305_SHA256,
                cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            Self::Unshaped => rustls::crypto::ring::default_provider()
                .cipher_suites
                .clone(),
        }
    }

    /// Key-exchange groups, X25519 first for every modern browser.
    #[cfg(test)]
    fn kx_groups(self) -> Vec<&'static dyn rustls::crypto::SupportedKxGroup> {
        use rustls::crypto::ring::kx_group;
        match self {
            Self::Unshaped => rustls::crypto::ring::default_provider().kx_groups.clone(),
            _ => vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1],
        }
    }

    /// The same profile ordering, backed by aws-lc-rs for ECH. Rustls keeps
    /// provider-specific suite values, so ECH cannot reuse the ring-backed
    /// vector above even though the wire suite IDs are identical.
    pub(crate) fn aws_provider(self) -> rustls::crypto::CryptoProvider {
        use rustls::crypto::aws_lc_rs;

        let mut provider = aws_lc_rs::default_provider();
        let suite_order: &[rustls::CipherSuite] = match self {
            Self::Chrome | Self::Edge | Self::Android => &[
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            Self::Firefox => &[
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ],
            Self::Safari | Self::Ios => &[
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            Self::Unshaped => &[],
        };
        if !suite_order.is_empty() {
            let available = provider.cipher_suites.clone();
            provider.cipher_suites = suite_order
                .iter()
                .filter_map(|wanted| {
                    available
                        .iter()
                        .find(|candidate| candidate.suite() == *wanted)
                })
                .copied()
                .collect();
        }
        provider.kx_groups = match self {
            Self::Unshaped => provider.kx_groups.clone(),
            _ => vec![
                aws_lc_rs::kx_group::X25519MLKEM768,
                aws_lc_rs::kx_group::X25519,
                aws_lc_rs::kx_group::SECP256R1,
                aws_lc_rs::kx_group::SECP384R1,
            ],
        };
        provider
    }

    /// The ALPN list a browser would send when the config does not pin one.
    pub fn default_alpn(self) -> Vec<Vec<u8>> {
        match self {
            Self::Unshaped => Vec::new(),
            _ => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    }

    /// Install this profile's AWS-LC crypto provider into a config builder.
    pub fn apply_to_builder(
        self,
        roots: RootCertStore,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        rustls::ClientConfig::builder_with_provider(self.aws_provider().into())
            .with_safe_default_protocol_versions()
            .expect("AWS-LC provider supports the default protocol versions")
            .with_root_certificates(roots)
    }

    /// Final adjustments that are only reachable on the built config.
    pub fn apply_to_config(self, cfg: &mut ClientConfig) {
        // Browsers send session tickets; suppressing resumption would itself
        // be distinguishing on a repeat connection.
        cfg.resumption = rustls::client::Resumption::in_memory_sessions(256);

        if self != Self::Unshaped {
            // Chromium-family clients do not advertise early data by default.
            cfg.enable_early_data = false;
        }
    }

    /// Install the wire-level uTLS controls available through shaped-rustls.
    ///
    /// The crypto provider still owns the handshake implementation; this
    /// customizer only changes the advertised ClientHello shape. That keeps
    /// certificate verification, ECH, and session resumption on the normal
    /// Rustls path while making the browser profile visible on the wire.
    /// Install a concrete Xray/uTLS profile while retaining the generic
    /// browser family for provider and compatibility decisions.
    pub(crate) fn apply_client_hello_shape_named(
        self,
        cfg: &mut ClientConfig,
        alpn: &[Vec<u8>],
        managed_ech: bool,
        profile_name: &str,
    ) -> Result<(), String> {
        if self == Self::Unshaped {
            return Ok(());
        }

        let Some(profile) = profile_for_fingerprint(profile_name) else {
            return Err(format!("missing uTLS profile data for {profile_name}"));
        };
        if !profile_has_usable_cipher_suite(profile, &self.aws_provider()) {
            return Err(format!(
                "uTLS profile {profile_name} has no cipher suite supported by rustls"
            ));
        }

        cfg.client_hello_customizer = Some(Arc::new(BrowserClientHelloCustomizer {
            profile_name: profile_name.to_owned(),
            alpn: (!alpn.is_empty()).then(|| alpn.to_vec()),
            managed_ech,
        }));
        Ok(())
    }
}

#[derive(Debug)]
struct BrowserClientHelloCustomizer {
    profile_name: String,
    alpn: Option<Vec<Vec<u8>>>,
    managed_ech: bool,
}

impl rustls::client::ClientHelloCustomizer for BrowserClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        context: rustls::client::ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        if context.is_quic {
            return Ok(None);
        }

        let profile = profile_for_fingerprint(&self.profile_name).ok_or_else(|| {
            RustlsError::General(format!(
                "missing uTLS profile data for {}",
                self.profile_name
            ))
        })?;
        // Resolved per hello, not per config: for a shuffling profile the
        // order has to be redrawn on every connection or the "shuffle" is a
        // single fixed permutation, which is no better than none.
        let shuffle = profile_shuffles_extensions(&self.profile_name);
        let mut plan = apply_utls_profile(
            ClientHelloPlan::new(),
            profile,
            context,
            self.managed_ech,
            shuffle,
        )?;
        // ECH is TLS 1.3-only in rustls. Keep the profile's browser shape when
        // both versions are enabled, but never ask the handshake planner to
        // advertise a version the selected config cannot negotiate.
        if context.versions.len() < 2 {
            let enabled = context
                .versions
                .iter()
                .map(|version| version.version)
                .collect::<Vec<_>>();
            plan = plan
                .with_supported_versions(ClientHelloSupportedVersions::try_from(enabled.clone())?)
                .with_advertised_supported_versions(
                    ClientHelloAdvertisedSupportedVersions::try_from(enabled)?,
                );
        }
        if let Some(alpn) = &self.alpn {
            plan = apply_alpn_override(plan, profile, alpn, shuffle)?;
        }

        Ok(Some(plan))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_names_case_insensitively() {
        assert_eq!(
            FingerprintProfile::parse("Chrome"),
            Some(FingerprintProfile::Chrome)
        );
        assert_eq!(
            FingerprintProfile::parse("firefox"),
            Some(FingerprintProfile::Firefox)
        );
        assert_eq!(FingerprintProfile::parse("bogus"), None);
    }

    #[test]
    fn chrome_offers_x25519_first() {
        let groups = FingerprintProfile::Chrome.kx_groups();
        assert_eq!(groups[0].name(), rustls::NamedGroup::X25519);
    }

    #[test]
    fn firefox_prefers_chacha_over_aes256() {
        let suites = FingerprintProfile::Firefox.cipher_suites();
        let names: Vec<_> = suites.iter().map(|s| s.suite()).collect();
        let chacha = names
            .iter()
            .position(|s| *s == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
            .unwrap();
        let aes256 = names
            .iter()
            .position(|s| *s == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)
            .unwrap();
        assert!(chacha < aes256, "firefox orders chacha before aes256");
    }

    #[test]
    fn chrome_prefers_aes256_over_chacha() {
        let suites = FingerprintProfile::Chrome.cipher_suites();
        let names: Vec<_> = suites.iter().map(|s| s.suite()).collect();
        let chacha = names
            .iter()
            .position(|s| *s == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
            .unwrap();
        let aes256 = names
            .iter()
            .position(|s| *s == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)
            .unwrap();
        assert!(aes256 < chacha, "chrome orders aes256 before chacha");
    }

    #[test]
    fn profiles_differ_on_the_wire() {
        // If two profiles produced the same suite order they would be the
        // same fingerprint, which would make selecting between them pointless.
        let c: Vec<_> = FingerprintProfile::Chrome
            .cipher_suites()
            .iter()
            .map(|s| s.suite())
            .collect();
        let f: Vec<_> = FingerprintProfile::Firefox
            .cipher_suites()
            .iter()
            .map(|s| s.suite())
            .collect();
        assert_ne!(c, f);
    }

    #[test]
    fn builds_a_usable_config_for_every_profile() {
        for p in [
            FingerprintProfile::Chrome,
            FingerprintProfile::Firefox,
            FingerprintProfile::Safari,
            FingerprintProfile::Edge,
            FingerprintProfile::Ios,
            FingerprintProfile::Android,
            FingerprintProfile::Unshaped,
        ] {
            let roots = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let _ = p.apply_to_builder(roots).with_no_client_auth();
        }
    }

    #[test]
    fn unshaped_cannot_be_used_with_reality() {
        assert!(!FingerprintProfile::Unshaped.supports_reality());
        assert!(FingerprintProfile::Chrome.supports_reality());
    }
}
