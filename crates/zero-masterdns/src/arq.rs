//! The reliable (ARQ) layer: turning the lossy DNS tunnel into ordered,
//! retransmitted byte streams.
//!
//! One ARQ instance drives one bidirectional stream. The deterministic
//! arithmetic that the whole layer rests on lives in two small, heavily tested
//! submodules, kept apart from the socket-and-timer machinery so it can be
//! checked against the Go server byte for byte:
//!
//!  * [`seq`] — the 16-bit sequence-number space: how far ahead a packet is,
//!    whether it is a stale repeat, and which of the three receive buckets it
//!    falls into (old / in-window / beyond the window).
//!  * [`rto`] — the adaptive retransmit timeout, computed in whole nanoseconds
//!    with the same truncating integer math the Go side uses, plus the fixed
//!    growth factors a retransmit multiplies the timeout by.
//!
//! The surrounding state machine builds on these:
//!
//!  * [`data`] — the reliable data path for one stream as a pure, sans-IO state
//!    machine: the send and receive buffers, acks, gap NACKs, and the adaptive
//!    retransmit timer, all driven by explicit timestamps so the whole thing is
//!    unit-testable without a socket.
//!  * [`control`] — the control-plane reliability for one stream, also sans-IO:
//!    the handshake and teardown packets tracked until their matching ack,
//!    resent on an adaptive control RTO, and expired (closing the stream) once
//!    they run out of retries or outlive their TTL.
//!  * [`close`] — the close/teardown state machine that sits above both: it owns
//!    a [`control`] plane, decides which terminal packet (`CLOSE_READ` /
//!    `CLOSE_WRITE` / `RST`) to send, runs the drain and ack-wait watchdogs, and
//!    emits the actions that tear a stream down.

pub mod close;
pub mod control;
pub mod data;
pub mod rto;
pub mod seq;
