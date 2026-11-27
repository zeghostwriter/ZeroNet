//! The live, socket-and-timing half of the MasterDnsVPN client.
//!
//! [`zero_protocol::masterdns`] holds the pure wire format — the packet
//! layout, the base/encryption codec, the DNS framing, and the deterministic
//! handshake payloads. That part has to be byte-for-byte identical to the
//! server, so it is tested against vectors the Go server itself emits and it
//! pulls in no sockets. This crate is everything that part cannot be: the UDP
//! resolver carrier that actually sends the DNS queries and waits for replies,
//! the optional payload compression, the reliable (ARQ) layer, the session
//! handshake orchestration, and the SOCKS stream management on top.
//!
//! The split is the same one the `tide` protocol uses (`zero-protocol` for the
//! wire, `zero-transport`/`zero-runtime` for the live layers); MasterDNS is
//! large enough — its own ARQ, session, SOCKS and carrier — that it earns a
//! crate rather than more files inside `zero-transport`, the way the embedded
//! Tor client (`zero-tor`) does.
//!
//! Only AES-256-GCM (method 5) is the shipping choice: it is the one
//! authenticated option, and the request direction (client to server) is the
//! only one that is encrypted. Replies come back raw or base64 in TXT records.

pub mod arq;
pub mod balancer;
pub mod carrier;
pub mod client;
pub mod compress;
pub mod dispatch;
pub mod fragment;
pub mod inbound;
pub mod mlq;
pub mod mtu;
pub mod payload;
pub mod ping;
pub mod ratelimit;
pub mod session;
pub mod socks;
pub mod streamid;
