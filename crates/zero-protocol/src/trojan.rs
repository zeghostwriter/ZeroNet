//! Trojan.
//!
//! Trojan authenticates with the hex SHA-224 of the password and then uses
//! SOCKS5-shaped addressing. Note the address encoding differs from VLESS in
//! both field order (address before port) and type codes — a detail worth
//! keeping explicit, since sharing one encoder between them would be wrong.
//!
//! ```text
//! 56 hex(sha224(password))
//! 2  CRLF
//! 1  command (1=CONNECT, 3=UDP ASSOCIATE)
//! 1  address type (1=IPv4, 3=domain, 4=IPv6)
//! N  address
//! 2  port, big endian
//! 2  CRLF
//! .. payload
//! ```

use bytes::{BufMut, BytesMut};
use zero_core::{Address, Destination, Network};

pub const CMD_CONNECT: u8 = 1;
pub const CMD_UDP_ASSOCIATE: u8 = 3;

pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAIN: u8 = 3;
pub const ATYP_IPV6: u8 = 4;

const CRLF: [u8; 2] = [0x0D, 0x0A];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub password_hash: [u8; 56],
    pub destination: Destination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestParse {
    Incomplete,
    Complete { request: Request, consumed: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpPacketParse {
    Incomplete,
    Complete {
        destination: Destination,
        payload: Vec<u8>,
        consumed: usize,
    },
}

/// Parse one Trojan request header without consuming payload bytes.
pub fn parse_request(buf: &[u8]) -> Result<RequestParse, String> {
    if buf.len() < 59 {
        return Ok(RequestParse::Incomplete);
    }
    if buf[56..58] != CRLF {
        return Err("invalid Trojan password separator".into());
    }
    let network = match buf[58] {
        CMD_CONNECT => Network::Tcp,
        CMD_UDP_ASSOCIATE => Network::Udp,
        other => return Err(format!("unsupported Trojan command {other}")),
    };
    let (address, mut offset) = match decode_address(buf, 59) {
        Ok(value) => value,
        Err(error) if error.starts_with("truncated") || error.starts_with("missing") => {
            return Ok(RequestParse::Incomplete)
        }
        Err(error) => return Err(error),
    };
    if offset + 4 > buf.len() {
        return Ok(RequestParse::Incomplete);
    }
    let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    offset += 2;
    if buf[offset..offset + 2] != CRLF {
        return Err("invalid Trojan request separator".into());
    }
    offset += 2;
    let mut password_hash = [0u8; 56];
    password_hash.copy_from_slice(&buf[..56]);
    Ok(RequestParse::Complete {
        request: Request {
            password_hash,
            destination: Destination::new(address, port, network),
        },
        consumed: offset,
    })
}

/// Encode one Trojan UDP packet after the connection header.
pub fn encode_udp_packet(dst: &Destination, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return Err("Trojan UDP payload must contain 1..=65535 bytes".into());
    }
    let mut out = BytesMut::with_capacity(32 + payload.len());
    encode_address(dst, &mut out);
    out.put_u16(payload.len() as u16);
    out.put_slice(&CRLF);
    out.put_slice(payload);
    Ok(out.to_vec())
}

/// Decode one complete Trojan UDP packet, returning the consumed byte count.
pub fn decode_udp_packet(buf: &[u8]) -> Result<(Destination, Vec<u8>, usize), String> {
    let (address, mut offset) = decode_address(buf, 0)?;
    if offset + 4 > buf.len() {
        return Err("incomplete Trojan UDP packet header".into());
    }
    let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    offset += 2;
    let payload_len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
    offset += 2;
    if offset + 2 > buf.len() {
        return Err("incomplete Trojan UDP packet separator".into());
    }
    if buf.get(offset..offset + 2) != Some(&CRLF) {
        return Err("invalid Trojan UDP packet separator".into());
    }
    offset += 2;
    if offset + payload_len > buf.len() {
        return Err("incomplete Trojan UDP packet payload".into());
    }
    Ok((
        Destination::udp(address, port),
        buf[offset..offset + payload_len].to_vec(),
        offset + payload_len,
    ))
}

/// Parse one Trojan UDP packet without consuming bytes from a stream buffer.
///
/// `decode_udp_packet` is intentionally strict for callers that already have
/// a datagram. Stream transports need the tri-state form because a header or
/// payload may be split across reads.
pub fn parse_udp_packet(buf: &[u8]) -> Result<UdpPacketParse, String> {
    let (address, mut offset) = match decode_address(buf, 0) {
        Ok(value) => value,
        Err(error) if error.starts_with("truncated") || error.starts_with("missing") => {
            return Ok(UdpPacketParse::Incomplete)
        }
        Err(error) => return Err(error),
    };
    if offset + 4 > buf.len() {
        return Ok(UdpPacketParse::Incomplete);
    }
    let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    offset += 2;
    let payload_len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
    offset += 2;
    if offset + 2 > buf.len() {
        return Ok(UdpPacketParse::Incomplete);
    }
    if buf.get(offset..offset + 2) != Some(&CRLF) {
        return Err("invalid Trojan UDP packet separator".into());
    }
    offset += 2;
    if offset + payload_len > buf.len() {
        return Ok(UdpPacketParse::Incomplete);
    }
    Ok(UdpPacketParse::Complete {
        destination: Destination::udp(address, port),
        payload: buf[offset..offset + payload_len].to_vec(),
        consumed: offset + payload_len,
    })
}

fn decode_address(buf: &[u8], mut offset: usize) -> Result<(Address, usize), String> {
    let atyp = *buf
        .get(offset)
        .ok_or_else(|| "missing Trojan UDP address type".to_string())?;
    offset += 1;
    let address = match atyp {
        ATYP_IPV4 => {
            if offset + 4 > buf.len() {
                return Err("truncated Trojan UDP IPv4 address".into());
            }
            let ip = std::net::Ipv4Addr::new(
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            );
            offset += 4;
            Address::from(ip)
        }
        ATYP_IPV6 => {
            if offset + 16 > buf.len() {
                return Err("truncated Trojan UDP IPv6 address".into());
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&buf[offset..offset + 16]);
            offset += 16;
            Address::from(std::net::Ipv6Addr::from(bytes))
        }
        ATYP_DOMAIN => {
            let len = *buf
                .get(offset)
                .ok_or_else(|| "truncated Trojan UDP domain length".to_string())?
                as usize;
            offset += 1;
            if offset + len > buf.len() {
                return Err("truncated Trojan UDP domain".into());
            }
            let name = std::str::from_utf8(&buf[offset..offset + len])
                .map_err(|_| "Trojan UDP domain is not UTF-8")?;
            offset += len;
            Address::parse_host(name)
        }
        other => return Err(format!("unsupported Trojan UDP address type {other}")),
    };
    Ok((address, offset))
}

/// Write a SOCKS5-style address, which is address-first.
pub fn encode_address(dst: &Destination, out: &mut BytesMut) {
    match &dst.address {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.put_u8(ATYP_IPV4);
            out.put_slice(&ip.octets());
        }
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.put_u8(ATYP_IPV6);
            out.put_slice(&ip.octets());
        }
        Address::Domain(d) => {
            out.put_u8(ATYP_DOMAIN);
            let bytes = d.as_bytes();
            debug_assert!(bytes.len() <= 255, "domain too long for Trojan");
            out.put_u8(bytes.len() as u8);
            out.put_slice(bytes);
        }
    }
    out.put_u16(dst.port);
}

/// Build the Trojan request header.
pub fn encode_request(password_hash: &[u8; 56], dst: &Destination) -> BytesMut {
    let mut out = BytesMut::with_capacity(128);
    out.put_slice(password_hash);
    out.put_slice(&CRLF);
    out.put_u8(match dst.network {
        Network::Tcp => CMD_CONNECT,
        Network::Udp => CMD_UDP_ASSOCIATE,
    });
    encode_address(dst, &mut out);
    out.put_slice(&CRLF);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash() -> [u8; 56] {
        let mut h = [b'a'; 56];
        h[0] = b'f';
        h
    }

    #[test]
    fn request_layout_for_domain() {
        let d = Destination::tcp(Address::domain("example.com"), 443);
        let req = encode_request(&hash(), &d);

        assert_eq!(&req[..56], &hash());
        assert_eq!(&req[56..58], &CRLF);
        assert_eq!(req[58], CMD_CONNECT);
        assert_eq!(req[59], ATYP_DOMAIN);
        assert_eq!(req[60], 11);
        assert_eq!(&req[61..72], b"example.com");
        assert_eq!(u16::from_be_bytes([req[72], req[73]]), 443);
        assert_eq!(&req[74..76], &CRLF);
        assert_eq!(req.len(), 76);
    }

    #[test]
    fn request_layout_for_ipv4() {
        let d = Destination::tcp(Address::parse_host("8.8.8.8"), 53);
        let req = encode_request(&hash(), &d);
        assert_eq!(req[59], ATYP_IPV4);
        assert_eq!(&req[60..64], &[8, 8, 8, 8]);
        assert_eq!(u16::from_be_bytes([req[64], req[65]]), 53);
    }

    #[test]
    fn udp_uses_associate_command() {
        let d = Destination::udp(Address::domain("a.io"), 53);
        let req = encode_request(&hash(), &d);
        assert_eq!(req[58], CMD_UDP_ASSOCIATE);
    }

    #[test]
    fn ipv6_type_code_differs_from_vless() {
        let d = Destination::tcp(Address::parse_host("[::1]"), 443);
        let req = encode_request(&hash(), &d);
        // Trojan uses 4 for IPv6 where VLESS uses 3.
        assert_eq!(req[59], ATYP_IPV6);
        assert_eq!(ATYP_IPV6, 4);
        assert_eq!(crate::vless::ADDR_IPV6, 3);
    }

    #[test]
    fn address_is_written_before_port() {
        // The opposite of VLESS, which is port-first.
        let d = Destination::tcp(Address::parse_host("1.2.3.4"), 0x1234);
        let mut out = BytesMut::new();
        encode_address(&d, &mut out);
        assert_eq!(out[0], ATYP_IPV4);
        assert_eq!(&out[1..5], &[1, 2, 3, 4]);
        assert_eq!(&out[5..7], &[0x12, 0x34]);
    }

    #[test]
    fn udp_packet_roundtrips() {
        let destination = Destination::udp(Address::domain("example.com"), 53);
        let encoded = encode_udp_packet(&destination, b"dns").unwrap();
        let (decoded, payload, consumed) = decode_udp_packet(&encoded).unwrap();
        assert_eq!(decoded, destination);
        assert_eq!(payload, b"dns");
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn udp_stream_parser_distinguishes_partial_input() {
        let destination = Destination::udp(Address::domain("example.com"), 53);
        let encoded = encode_udp_packet(&destination, b"dns").unwrap();
        for end in 0..encoded.len() {
            assert_eq!(
                parse_udp_packet(&encoded[..end]).unwrap(),
                UdpPacketParse::Incomplete
            );
        }
        assert_eq!(
            parse_udp_packet(&encoded).unwrap(),
            UdpPacketParse::Complete {
                destination,
                payload: b"dns".to_vec(),
                consumed: encoded.len()
            }
        );
    }

    #[test]
    fn parses_request_and_preserves_payload_boundary() {
        let destination = Destination::tcp(Address::domain("origin.example"), 443);
        let mut wire = encode_request(&hash(), &destination).to_vec();
        wire.extend_from_slice(b"payload");
        let RequestParse::Complete { request, consumed } = parse_request(&wire).unwrap() else {
            panic!("request should be complete");
        };
        assert_eq!(request.password_hash, hash());
        assert_eq!(request.destination, destination);
        assert_eq!(&wire[consumed..], b"payload");
    }

    #[test]
    fn request_parser_rejects_bad_separator_and_reports_partial_headers() {
        assert_eq!(parse_request(&[0; 58]).unwrap(), RequestParse::Incomplete);
        let mut request = encode_request(
            &hash(),
            &Destination::tcp(Address::parse_host("1.2.3.4"), 80),
        )
        .to_vec();
        request[57] = 0;
        assert!(parse_request(&request).is_err());
    }
}
