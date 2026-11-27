//! MasterDnsVPN client wire format.
//!
//! This is a Rust port of the deterministic core of `masterking32/MasterDnsVPN`
//! (MIT), pinned to the server release `v2026.06.13.234407-7de2476`. It is the
//! part of the protocol that has to be byte-for-byte identical to the server or
//! nothing decodes: the packet layout, the base codec that turns packets into
//! DNS labels, and the encryption that wraps them.
//!
//! How the pieces fit, bottom up:
//!
//!  * [`enums`] is the vocabulary: every packet-type byte and which optional
//!    header fields it carries, plus the encryption-method ids.
//!  * [`packet`] builds and parses the raw packet, and holds the two small
//!    packed structures (SESSION_ACCEPT and packed control blocks).
//!  * [`codec`] seals a raw packet and encodes it into DNS-label text, and
//!    reverses that. [`codec::Codec`] is what a session holds.
//!  * [`dns`] frames an encoded packet as the question name of a DNS `TXT`
//!    query, and recovers the raw frame from the server's `TXT` answers.
//!  * [`compression`] is the codec vocabulary: the type ids and the packed
//!    upload/download pair the handshake carries.
//!  * [`session`] builds the SESSION_INIT request payload (its reply is read
//!    by [`packet`]).
//!  * [`socks`] encodes and parses the SOCKS target address a stream-setup
//!    packet carries.
//!
//! What is deliberately *not* here yet: the sockets that send these DNS
//! queries and wait for replies, the reliable (ARQ) layer, the session
//! handshake *orchestration*, SOCKS stream management, and the from-the-phone
//! server installer. Those need sockets and timing and belong in
//! `zero-transport`/`zero-runtime`; this crate stays pure wire, the same
//! split the `tide` protocol uses.
//!
//! Only AES-256-GCM (method 5) is the shipping choice: it is the one
//! authenticated option. The other methods are implemented so the codec can
//! talk to a differently configured server, except method 2 (ChaCha20, which
//! upstream runs unauthenticated) which returns an error rather than pull in a
//! cipher we never want to select.

pub mod codec;
pub mod compression;
pub mod dns;
pub mod enums;
pub mod packet;
pub mod session;
pub mod socks;

pub use codec::{Codec, CodecError};
pub use dns::{
    build_tunnel_txt_question, extract_vpn_frame, parse_dns_packet, DnsError, DnsHeader, DnsPacket,
    DnsQuestion, DnsResourceRecord,
};
pub use packet::{
    build_encoded, build_raw, decode_session_accept_payload, encode_session_accept_payload,
    header_check_byte, header_raw_size, max_header_raw_size, parse, BuildOptions, Fragment,
    PackedControlBlock, Packet, PacketError, SessionAcceptClientPolicy, SessionAcceptPayload,
};
pub use session::{build_session_init_payload, SESSION_INIT_PAYLOAD_SIZE, VERIFY_CODE_LEN};
pub use socks::{
    build_target_payload, build_udp_datagram, parse_target_payload, parse_udp_datagram, Target,
    TargetError, UdpDatagram,
};

#[cfg(test)]
mod dns_tests;
#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod tests;
