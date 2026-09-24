//! `zero-router` — routing decisions.

pub mod assets;
pub mod matcher;
pub mod router;

pub use assets::{AssetKind, AssetPolicy, AssetSpec, AssetStore, RefreshOutcome};
pub use matcher::{is_private_ip, DomainMatcher, GeoData, IpMatcher};
pub use router::{Decision, Router};
