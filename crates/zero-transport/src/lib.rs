//! `zero-transport` — stream carriers.
//!
//! A carrier turns a connected socket into the byte stream a protocol expects.
//! Carriers do not know which protocol rides on them, and protocols do not
//! know which carrier they are on.

pub mod grpc;
pub mod httpupgrade;
pub mod hysteria2;
mod relay;
pub mod tcp_header;
pub mod tuic;
pub mod ws;
pub mod xhttp;
pub mod xhttp_request;

pub use ws::{WebSocketStream, WsConfig};
