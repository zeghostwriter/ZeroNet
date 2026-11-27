//! The PROXY protocol (HAProxy), versions 1 and 2: a header a proxy puts in
//! front of a connection so the server behind it learns who really connected.
//!
//! How this works. [`encode`] makes the header for a connection from `source`
//! to `destination`; [`parse`] reads one off the front of a buffer. Both
//! versions are handled: version 1 is a text line (`PROXY TCP4 1.2.3.4
//! 5.6.7.8 1111 2222`), version 2 is a 12-byte signature, a version and
//! command byte, an address family byte and a length, then the addresses.
//!
//! The rule it keeps: a header never claims what it cannot say. Addresses of
//! two different families, or none, are sent as `UNKNOWN` (version 1) or the
//! `LOCAL` command (version 2), which a receiver reads as "use the socket's
//! own addresses".

use std::net::{IpAddr, SocketAddr};

/// The 12 bytes that begin every version 2 header.
pub const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// The longest version 1 header: the specification's 107 bytes.
const V1_MAX: usize = 107;

/// What a header said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The connecting client; `None` when the sender said it did not know
    /// (`UNKNOWN`, or a `LOCAL` connection).
    pub source: Option<SocketAddr>,
    pub destination: Option<SocketAddr>,
}

/// The header for a TCP connection, in `version` 1 or 2.
pub fn encode(version: u8, source: Option<SocketAddr>, destination: Option<SocketAddr>) -> Vec<u8> {
    let pair = match (source, destination) {
        (Some(s), Some(d)) if s.is_ipv4() == d.is_ipv4() => Some((s, d)),
        _ => None,
    };
    if version == 1 {
        return match pair {
            Some((s, d)) => format!(
                "PROXY {} {} {} {} {}\r\n",
                if s.is_ipv4() { "TCP4" } else { "TCP6" },
                s.ip(),
                d.ip(),
                s.port(),
                d.port()
            )
            .into_bytes(),
            None => b"PROXY UNKNOWN\r\n".to_vec(),
        };
    }
    let mut out = V2_SIGNATURE.to_vec();
    match pair {
        None => {
            out.extend_from_slice(&[0x20, 0x00, 0, 0]);
        }
        Some((s, d)) => {
            let (family, mut addresses) = match (s.ip(), d.ip()) {
                (IpAddr::V4(s), IpAddr::V4(d)) => (0x11u8, [s.octets(), d.octets()].concat()),
                (IpAddr::V6(s), IpAddr::V6(d)) => (0x21u8, [s.octets(), d.octets()].concat()),
                _ => unreachable!("the pair has one family"),
            };
            addresses.extend_from_slice(&s.port().to_be_bytes());
            addresses.extend_from_slice(&d.port().to_be_bytes());
            out.extend_from_slice(&[0x21, family]);
            out.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
            out.extend_from_slice(&addresses);
        }
    }
    out
}

/// The result of looking at the start of a connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// A header, and how many bytes it took.
    Header(Header, usize),
    /// The bytes so far could still become a header; read more.
    Incomplete,
    /// Not a PROXY protocol header.
    NotProxy,
}

/// Look for a header at the start of `buf`.
pub fn parse(buf: &[u8]) -> Parsed {
    if buf.starts_with(&V2_SIGNATURE) {
        return parse_v2(buf);
    }
    if buf.starts_with(b"PROXY ") {
        return parse_v1(buf);
    }
    // A prefix of either signature: wait for the rest before deciding.
    if V2_SIGNATURE.starts_with(buf) || b"PROXY ".starts_with(buf) {
        return Parsed::Incomplete;
    }
    Parsed::NotProxy
}

fn parse_v1(buf: &[u8]) -> Parsed {
    let Some(end) = buf.windows(2).position(|pair| pair == b"\r\n") else {
        return if buf.len() >= V1_MAX {
            Parsed::NotProxy
        } else {
            Parsed::Incomplete
        };
    };
    let consumed = end + 2;
    let Ok(line) = std::str::from_utf8(&buf[..end]) else {
        return Parsed::NotProxy;
    };
    let fields: Vec<&str> = line.split(' ').collect();
    match fields.as_slice() {
        ["PROXY", "UNKNOWN", ..] => Parsed::Header(
            Header {
                source: None,
                destination: None,
            },
            consumed,
        ),
        ["PROXY", family @ ("TCP4" | "TCP6"), src, dst, sport, dport] => {
            let parse = |ip: &str, port: &str| -> Option<SocketAddr> {
                let ip: IpAddr = ip.parse().ok()?;
                let port: u16 = port.parse().ok()?;
                (ip.is_ipv4() == (*family == "TCP4")).then(|| SocketAddr::new(ip, port))
            };
            match (parse(src, sport), parse(dst, dport)) {
                (Some(source), Some(destination)) => Parsed::Header(
                    Header {
                        source: Some(source),
                        destination: Some(destination),
                    },
                    consumed,
                ),
                _ => Parsed::NotProxy,
            }
        }
        _ => Parsed::NotProxy,
    }
}

fn parse_v2(buf: &[u8]) -> Parsed {
    if buf.len() < 16 {
        return Parsed::Incomplete;
    }
    let (version_command, family, length) = (
        buf[12],
        buf[13],
        usize::from(u16::from_be_bytes([buf[14], buf[15]])),
    );
    if version_command >> 4 != 2 {
        return Parsed::NotProxy;
    }
    let total = 16 + length;
    if buf.len() < total {
        return Parsed::Incomplete;
    }
    let body = &buf[16..total];
    let address = |len: usize, v6: bool| -> Option<Header> {
        let half = len / 2 - 2;
        let ip = |bytes: &[u8]| -> IpAddr {
            if v6 {
                IpAddr::from(<[u8; 16]>::try_from(bytes).expect("sized by the family"))
            } else {
                IpAddr::from(<[u8; 4]>::try_from(bytes).expect("sized by the family"))
            }
        };
        let body = body.get(..len)?;
        Some(Header {
            source: Some(SocketAddr::new(
                ip(&body[..half]),
                u16::from_be_bytes([body[2 * half], body[2 * half + 1]]),
            )),
            destination: Some(SocketAddr::new(
                ip(&body[half..2 * half]),
                u16::from_be_bytes([body[2 * half + 2], body[2 * half + 3]]),
            )),
        })
    };
    let header = match (version_command & 0x0f, family >> 4) {
        // LOCAL: the sender's own connection (a health check), no addresses.
        (0, _) => Some(Header {
            source: None,
            destination: None,
        }),
        (1, 1) if length >= 12 => address(12, false),
        (1, 2) if length >= 36 => address(36, true),
        // PROXY for a family we do not carry (UNIX, UNSPEC): skipped, with
        // the connection's own addresses standing.
        (1, _) => Some(Header {
            source: None,
            destination: None,
        }),
        _ => None,
    };
    match header {
        Some(header) => Parsed::Header(header, total),
        None => Parsed::NotProxy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn version_one_matches_the_specification_text() {
        let header = encode(
            1,
            Some(addr("192.0.2.1:56324")),
            Some(addr("198.51.100.7:443")),
        );
        assert_eq!(header, b"PROXY TCP4 192.0.2.1 198.51.100.7 56324 443\r\n");
        let header = encode(
            1,
            Some(addr("[2001:db8::1]:1000")),
            Some(addr("[2001:db8::2]:2000")),
        );
        assert_eq!(header, b"PROXY TCP6 2001:db8::1 2001:db8::2 1000 2000\r\n");
        assert_eq!(encode(1, None, None), b"PROXY UNKNOWN\r\n");
        // Two families cannot be one connection's addresses.
        assert_eq!(
            encode(1, Some(addr("192.0.2.1:1")), Some(addr("[2001:db8::2]:2"))),
            b"PROXY UNKNOWN\r\n"
        );
    }

    #[test]
    fn version_two_has_the_signature_and_the_documented_layout() {
        let header = encode(
            2,
            Some(addr("192.0.2.1:56324")),
            Some(addr("198.51.100.7:443")),
        );
        assert_eq!(&header[..12], &V2_SIGNATURE);
        assert_eq!(&header[12..16], &[0x21, 0x11, 0, 12]);
        assert_eq!(&header[16..20], &[192, 0, 2, 1]);
        assert_eq!(&header[20..24], &[198, 51, 100, 7]);
        assert_eq!(&header[24..26], &56324u16.to_be_bytes());
        assert_eq!(&header[26..28], &443u16.to_be_bytes());
        assert_eq!(header.len(), 28);
        let local = encode(2, None, None);
        assert_eq!(&local[12..16], &[0x20, 0, 0, 0]);
    }

    #[test]
    fn every_header_reads_back_as_it_was_written() {
        for version in [1u8, 2] {
            for (s, d) in [
                ("192.0.2.1:56324", "198.51.100.7:443"),
                ("[2001:db8::1]:1000", "[2001:db8::2]:2000"),
            ] {
                let mut bytes = encode(version, Some(addr(s)), Some(addr(d)));
                let length = bytes.len();
                bytes.extend_from_slice(b"GET / HTTP/1.1");
                match parse(&bytes) {
                    Parsed::Header(header, consumed) => {
                        assert_eq!(consumed, length, "v{version} {s}");
                        assert_eq!(header.source, Some(addr(s)));
                        assert_eq!(header.destination, Some(addr(d)));
                    }
                    other => panic!("v{version} {s}: {other:?}"),
                }
            }
            match parse(&encode(version, None, None)) {
                Parsed::Header(header, _) => assert_eq!(header.source, None),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn a_header_still_arriving_is_told_from_a_connection_that_is_not_one() {
        let full = encode(2, Some(addr("192.0.2.1:1")), Some(addr("198.51.100.7:2")));
        for cut in [1, 5, 12, 15, full.len() - 1] {
            assert_eq!(parse(&full[..cut]), Parsed::Incomplete, "cut at {cut}");
        }
        assert_eq!(parse(b"PRO"), Parsed::Incomplete);
        assert_eq!(parse(b"PROXY TCP4 1.2.3.4 5.6"), Parsed::Incomplete);
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), Parsed::NotProxy);
        assert_eq!(parse(b"\x16\x03\x01"), Parsed::NotProxy);
        assert_eq!(
            parse(b"PROXY TCP4 not-an-ip 5.6.7.8 1 2\r\n"),
            Parsed::NotProxy
        );
        // The wrong family for the declared one.
        assert_eq!(
            parse(b"PROXY TCP4 2001:db8::1 5.6.7.8 1 2\r\n"),
            Parsed::NotProxy
        );
    }

    #[test]
    fn no_bytes_make_the_parser_panic() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let seed = encode(2, Some(addr("192.0.2.1:1")), Some(addr("198.51.100.7:2")));
        for _ in 0..20_000 {
            let mut bytes = seed.clone();
            for _ in 0..(next() % 6) {
                let at = (next() as usize) % bytes.len();
                bytes[at] = next() as u8;
            }
            bytes.truncate((next() as usize) % (bytes.len() + 1));
            let _ = parse(&bytes);
        }
    }
}
