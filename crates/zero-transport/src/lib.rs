//! `zero-transport` — stream carriers.
//!
//! A carrier turns a connected socket into the byte stream a protocol expects.
//! Carriers do not know which protocol rides on them, and protocols do not
//! know which carrier they are on.

pub mod grpc;
pub mod hop;
pub mod httpupgrade;
mod huffman;
pub mod hysteria2;
pub mod juicity;
pub mod masque;
pub mod masquerade;
pub mod quic_cc;
pub mod quic_pool;
pub mod quic_shape;
mod relay;
pub mod salamander;
pub mod shadowtls;
pub mod tcp_header;
pub mod tide;
pub mod tide_http1;
pub mod tide_relay;
pub mod tuic;
pub mod ws;
pub mod xhttp;
pub mod xhttp_request;

pub use ws::{WebSocketStream, WsConfig};
