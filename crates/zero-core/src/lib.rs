//! `zero-core` — foundational types for the Zray runtime.
//!
//! This crate holds the vocabulary every other crate speaks: addresses,
//! sessions, streams, and the structured failure taxonomy. It deliberately
//! contains no networking, no protocol logic and no configuration parsing, so
//! that protocol code can never reach around it to touch I/O directly
//! (RESEARCH-01 §2).

pub mod address;
pub mod error;
pub mod node_control;
pub mod platform;
pub mod session;
pub mod sniff;
pub mod stream;

pub use address::{Address, Destination, Network};
pub use error::{Confidence, Error, Failure, FailureKind, Result, Stage};
pub use node_control::{ActiveNodeState, ActiveProfileSelector, NodeControlEvent};
pub use platform::{
    bind_protected_udp, connect_protected, has_socket_protector, protect_fd, protect_socket,
    set_socket_protector, SocketProtector,
};
pub use session::{
    GenerationId, InboundId, OutboundId, RouteId, SessionContext, SessionId, Sniffed,
};
pub use stream::{boxed, BoxStream, Stream};
