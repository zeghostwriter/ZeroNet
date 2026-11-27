//! The SOCKS target address codec: the few bytes that say where a stream
//! should connect, as the tunnel carries them inside a stream-setup packet.
//!
//! Ported from the Go `internal/socksproto` (`BuildTargetPayload` and
//! `ParseTargetPayload`) at the pinned release `v2026.06.13.234407-7de2476`.
//! The layout is the classic SOCKS5 address shape, so it reads the same as the
//! address field of a SOCKS5 request:
//!
//! ```text
//!   [0] address type   (1 = IPv4, 3 = domain, 4 = IPv6)
//!   then, by type:
//!     IPv4   : 4 raw bytes
//!     domain : 1 length byte, then that many name bytes
//!     IPv6   : 16 raw bytes
//!   [..] port          (u16, big endian)
//! ```
//!
//! The client builds this inline when a browser asks it to CONNECT somewhere;
//! the server parses it to know where to dial. Keeping both halves here means
//! the encode and the decode are read side by side and cannot drift apart.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Address type: a four-byte IPv4 address follows.
pub const ADDRESS_TYPE_IPV4: u8 = 0x01;
/// Address type: a length-prefixed domain name follows.
pub const ADDRESS_TYPE_DOMAIN: u8 = 0x03;
/// Address type: a sixteen-byte IPv6 address follows.
pub const ADDRESS_TYPE_IPV6: u8 = 0x04;

/// Where a stream is headed: an address kind, the host (as text, exactly how
/// SOCKS gave it), and the port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub address_type: u8,
    pub host: String,
    pub port: u16,
}

/// What can go wrong reading a target payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetError {
    /// Fewer bytes than the smallest possible target.
    TooShort,
    /// The address-type byte names nothing we handle.
    UnsupportedAddressType,
    /// A domain target claimed a zero or over-running name length.
    InvalidDomainLength,
    /// A SOCKS UDP datagram header was shorter than the fixed 4-byte preamble
    /// (or ran out before its declared target/payload).
    UdpDatagramTooShort,
    /// A SOCKS UDP datagram set a non-zero FRAG byte; this tunnel never
    /// reassembles SOCKS-level UDP fragments.
    UdpFragmented,
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            TargetError::TooShort => "socks target payload too short",
            TargetError::UnsupportedAddressType => "unsupported socks address type",
            TargetError::InvalidDomainLength => "invalid socks domain length",
            TargetError::UdpDatagramTooShort => "socks udp datagram too short",
            TargetError::UdpFragmented => "socks udp fragmentation unsupported",
        };
        f.write_str(text)
    }
}

impl std::error::Error for TargetError {}

/// Encode a target to its on-the-wire bytes. Mirrors the Go
/// `BuildTargetPayload`, including its tolerance for a host string that does
/// not parse: an IPv4 target whose host is not a v4 literal encodes as
/// `0.0.0.0`, and an IPv6 target whose host is not a v6 literal encodes as
/// `::`, the same zero-address fallbacks `net.ParseIP` gives the Go side.
pub fn build_target_payload(target: &Target) -> Vec<u8> {
    match target.address_type {
        ADDRESS_TYPE_IPV4 => {
            let ip = target
                .host
                .parse::<Ipv4Addr>()
                .unwrap_or(Ipv4Addr::UNSPECIFIED);
            let mut out = Vec::with_capacity(1 + 4 + 2);
            out.push(ADDRESS_TYPE_IPV4);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&target.port.to_be_bytes());
            out
        }
        ADDRESS_TYPE_IPV6 => {
            let ip = parse_ipv6_or_zero(&target.host);
            let mut out = Vec::with_capacity(1 + 16 + 2);
            out.push(ADDRESS_TYPE_IPV6);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&target.port.to_be_bytes());
            out
        }
        // Everything else is treated as a domain, matching the Go default arm.
        _ => {
            let host = target.host.as_bytes();
            let mut out = Vec::with_capacity(1 + 1 + host.len() + 2);
            out.push(ADDRESS_TYPE_DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host);
            out.extend_from_slice(&target.port.to_be_bytes());
            out
        }
    }
}

/// Parse a target payload back into a [`Target`]. Mirrors the Go
/// `ParseTargetPayload`: the host comes back as text (dotted-quad for IPv4,
/// the canonical compressed form for IPv6, the raw name for a domain).
pub fn parse_target_payload(payload: &[u8]) -> Result<Target, TargetError> {
    if payload.len() < 3 {
        return Err(TargetError::TooShort);
    }
    let address_type = payload[0];
    let mut offset = 1usize;

    let host = match address_type {
        ADDRESS_TYPE_IPV4 => {
            if payload.len() < offset + 4 + 2 {
                return Err(TargetError::TooShort);
            }
            let ip = Ipv4Addr::new(
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            );
            offset += 4;
            ip.to_string()
        }
        ADDRESS_TYPE_DOMAIN => {
            if payload.len() < offset + 1 {
                return Err(TargetError::TooShort);
            }
            let domain_len = payload[offset] as usize;
            offset += 1;
            if domain_len < 1 || payload.len() < offset + domain_len + 2 {
                return Err(TargetError::InvalidDomainLength);
            }
            let host = String::from_utf8_lossy(&payload[offset..offset + domain_len]).into_owned();
            offset += domain_len;
            host
        }
        ADDRESS_TYPE_IPV6 => {
            if payload.len() < offset + 16 + 2 {
                return Err(TargetError::TooShort);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload[offset..offset + 16]);
            offset += 16;
            Ipv6Addr::from(octets).to_string()
        }
        _ => return Err(TargetError::UnsupportedAddressType),
    };

    let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    Ok(Target {
        address_type,
        host,
        port,
    })
}

/// Parse an IPv6 literal, falling back to the all-zero address the way the Go
/// `ParseIPv6` does: a non-address or a v4-mapped address both become `::`,
/// because a genuine IPv6 target never carries one of those.
fn parse_ipv6_or_zero(host: &str) -> Ipv6Addr {
    match host.parse::<Ipv6Addr>() {
        Ok(ip) if ip.to_ipv4_mapped().is_none() => ip,
        _ => Ipv6Addr::UNSPECIFIED,
    }
}

/// A SOCKS5 UDP ASSOCIATE datagram: a target address and the application
/// payload that rides to it. Mirrors Go `socksproto.UDPDatagram`. The payload
/// borrows the input buffer, exactly as the Go code returns a sub-slice, so a
/// forwarded DNS query is never copied on the way through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub target: Target,
    pub payload: &'a [u8],
}

/// Parse a SOCKS5 UDP ASSOCIATE datagram. The three-byte preamble is two
/// reserved bytes and a fragment byte; this tunnel only forwards whole
/// datagrams, so a non-zero fragment byte is rejected the way Go does rather
/// than attempt reassembly. The returned payload is the remainder after the
/// target and may legitimately be empty.
pub fn parse_udp_datagram(packet: &[u8]) -> Result<UdpDatagram<'_>, TargetError> {
    if packet.len() < 4 {
        return Err(TargetError::UdpDatagramTooShort);
    }
    if packet[2] != 0 {
        return Err(TargetError::UdpFragmented);
    }

    let (target, consumed) = parse_target_with_offset(&packet[3..])?;
    let offset = consumed + 3;
    if packet.len() < offset {
        return Err(TargetError::UdpDatagramTooShort);
    }
    Ok(UdpDatagram {
        target,
        payload: &packet[offset..],
    })
}

/// Build a SOCKS5 UDP ASSOCIATE datagram: the zeroed three-byte preamble, then
/// the target in [`build_target_payload`] shape, then the payload. Mirrors Go
/// `BuildUDPDatagram`.
pub fn build_udp_datagram(target: &Target, payload: &[u8]) -> Vec<u8> {
    let head = build_target_payload(target);
    let mut out = Vec::with_capacity(3 + head.len() + payload.len());
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&head);
    out.extend_from_slice(payload);
    out
}

/// Parse a target and report how many bytes it consumed, mirroring Go
/// `parseTargetWithOffset`. The consumed length is read from the raw bytes (the
/// domain-length byte, not the decoded host string) so a non-UTF-8 name cannot
/// shift the offset.
fn parse_target_with_offset(payload: &[u8]) -> Result<(Target, usize), TargetError> {
    let target = parse_target_payload(payload)?;
    let offset = match target.address_type {
        ADDRESS_TYPE_IPV4 => 1 + 4 + 2,
        ADDRESS_TYPE_IPV6 => 1 + 16 + 2,
        ADDRESS_TYPE_DOMAIN => {
            if payload.len() < 2 {
                return Err(TargetError::TooShort);
            }
            1 + 1 + payload[1] as usize + 2
        }
        _ => return Err(TargetError::UnsupportedAddressType),
    };
    Ok((target, offset))
}
