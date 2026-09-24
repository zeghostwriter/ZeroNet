//! `zero-protocol` — proxy protocol encodings.
//!
//! These modules encode and decode wire formats. They never open sockets,
//! never resolve names and never choose a route; they are handed a stream and
//! a destination (RESEARCH-01 §2).

pub mod amnezia;
pub mod anytls;
mod io_util;
pub mod mux;
pub mod shadowsocks;
pub mod shadowsocks2022;
pub mod socks;
pub mod trojan;
pub mod vision;
pub mod vless;
pub mod vless_encryption;
pub mod vmess;
