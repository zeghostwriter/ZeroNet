//! `zero-evasion` — active DPI countermeasures.
//!
//! These are *strategies*, not global switches. The connection planner selects
//! among them from measured evidence; each one costs latency, syscalls or
//! privileges, so none is applied unconditionally (PLAN-02 §4.2).

pub mod fragment;
pub mod keepalive;
pub mod noise;
pub mod rand_between;
pub mod sni_desync;

pub use fragment::{FragmentPolicy, FragmentStream, Packets};
pub use keepalive::{
    KeepaliveAction, KeepaliveCarrier, KeepalivePolicy, KeepaliveState, KeepaliveStream,
    NoKeepalive,
};
pub use noise::{NoiseEntry, NoisePacket, NoisePolicy};
pub use rand_between::rand_between;
pub use sni_desync::{
    build_fake_client_hello, has_raw_socket_capability, inject_fake_client_hello, SniDesyncConfig,
};
