//! WebSocket carrier.
//!
//! This is the transport the CDN-fronted config class rides on: a VLESS or
//! Trojan stream inside an ordinary-looking WebSocket upgrade to a CDN edge
//! (PLAN-02 §1, class B).

pub mod frame;
mod handshake;
mod stream;

pub use handshake::{accept_server, build_request, verify_response, WsConfig};
pub use stream::{connect, WebSocketStream};
