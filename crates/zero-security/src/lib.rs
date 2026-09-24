//! `zero-security` — TLS, ClientHello shaping, REALITY and Vision.
//!
//! Each of these is a separate module on purpose: a rustls upgrade must not
//! require touching VLESS, and a REALITY protocol change must not destabilise
//! ordinary TLS (RESEARCH-01 §13).

pub mod fingerprint;
pub mod reality;
pub mod reality_compat;
pub mod server;
pub mod tls;
pub mod tls13;

mod utls_profiles;
mod utls_shaping;

pub use fingerprint::FingerprintProfile;
pub use reality::{connect as reality_connect, RealityParams};
pub use reality_compat::{
    family_supports_reality, named_profile_supports_reality, RealityCompatibility,
    RealityGeneration, RealityIncompatibility, DEFAULT_MIN_CLIENT_VERSION, REPORTED_CLIENT_VERSION,
};
pub use tls::{client_config, connect, connect_with, try_client_config, TlsParams};
