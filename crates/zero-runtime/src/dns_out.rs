//! The `dns` outbound: answer an application's DNS query from the runtime's
//! own resolver instead of forwarding the datagram.
//!
//! In TUN mode every application resolves names itself, over plain UDP/53 to
//! whatever server the platform handed it. Forwarding those datagrams has two
//! bad outcomes on a censored network:
//!
//! * **Direct**, they are answered by the censor. Foreign resolvers on port 53
//!   are transparently hijacked, and a blocked name comes back as a private
//!   sinkhole address the tunnel can do nothing with.
//! * **Through the proxy**, they need a UDP-capable outbound. Shadowsocks and
//!   AnyTLS carry none here, so a VPN built on one of those would have no DNS
//!   at all.
//!
//! Routing UDP/53 to an outbound of protocol `dns` instead hands the question
//! to [`zero_dns::Resolver`], which applies the configured tiers (encrypted
//! remote resolver, domestic resolver for domestic names, anti-sanction
//! resolver for sanctioned ones) and answers locally. The application sees an
//! ordinary DNS response from the server it asked.
//!
//! Only `A` and `AAAA` are resolved. Every other question type gets an empty
//! `NOERROR` answer, which clients treat as "no such record" and move on from
//! (`HTTPS`/`SVCB` lookups by browsers are the common case). The answer TTL is
//! short and fixed: the resolver keeps its own cache with the real TTLs, so a
//! long client-side TTL would only pin an answer past a network change.

use std::net::IpAddr;

use zero_config::dns::QueryStrategy;
use zero_dns::{ResolveError, Resolver};

/// TTL written into synthesised answers.
const ANSWER_TTL_SECONDS: u32 = 60;
/// Largest query accepted; a legitimate single-question query is far smaller.
const MAX_QUERY_BYTES: usize = 4096;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

const RCODE_NOERROR: u8 = 0;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_NOTIMP: u8 = 4;

/// One parsed question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Query {
    pub id: u16,
    /// The request's flags word; opcode and RD are echoed back.
    pub flags: u16,
    /// Lower-cased, dot-joined, without a trailing dot.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// The question section exactly as sent, echoed in the answer.
    question: Vec<u8>,
}

/// Parse a standard single-question query. Anything else — responses,
/// multi-question packets, compression inside a question — is refused rather
/// than guessed at.
pub(crate) fn parse_query(packet: &[u8]) -> Option<Query> {
    if packet.len() < 12 || packet.len() > MAX_QUERY_BYTES {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    // QR set means this is a response, not a question.
    if flags & 0x8000 != 0 || qdcount != 1 {
        return None;
    }
    let mut at = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let length = *packet.get(at)? as usize;
        at += 1;
        if length == 0 {
            break;
        }
        // Compression pointers (and the reserved 0x40/0x80 forms) have no
        // business in a question.
        if length & 0xC0 != 0 {
            return None;
        }
        let label = packet.get(at..at + length)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        at += length;
        if at > 12 + 255 {
            return None;
        }
    }
    let fixed = packet.get(at..at + 4)?;
    let qtype = u16::from_be_bytes([fixed[0], fixed[1]]);
    let qclass = u16::from_be_bytes([fixed[2], fixed[3]]);
    at += 4;
    Some(Query {
        id,
        flags,
        name: labels.join("."),
        qtype,
        qclass,
        question: packet[12..at].to_vec(),
    })
}

/// Build the response to `query` carrying `addresses` (only those matching
/// the question's family are written).
pub(crate) fn build_response(query: &Query, rcode: u8, addresses: &[IpAddr]) -> Vec<u8> {
    let answers: Vec<&IpAddr> = addresses
        .iter()
        .filter(|address| match query.qtype {
            TYPE_A => address.is_ipv4(),
            TYPE_AAAA => address.is_ipv6(),
            _ => false,
        })
        .take(16)
        .collect();
    let mut out = Vec::with_capacity(12 + query.question.len() + answers.len() * 28);
    out.extend_from_slice(&query.id.to_be_bytes());
    // QR=1, the request's opcode and RD, RA=1, and the result code.
    let flags = 0x8000 | (query.flags & 0x7900) | 0x0080 | u16::from(rcode & 0x0F);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query.question);
    for address in answers {
        // A pointer to the question's name at offset 12.
        out.extend_from_slice(&0xC00Cu16.to_be_bytes());
        out.extend_from_slice(&query.qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ANSWER_TTL_SECONDS.to_be_bytes());
        match address {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

/// Answer one query packet through `resolver`. `None` means the packet was
/// not a query this outbound answers and should be dropped.
pub(crate) async fn answer(resolver: &Resolver, packet: &[u8]) -> Option<Vec<u8>> {
    let query = parse_query(packet)?;
    if query.qclass != CLASS_IN {
        return Some(build_response(&query, RCODE_NOTIMP, &[]));
    }
    let strategy = match query.qtype {
        TYPE_A => QueryStrategy::UseIpv4,
        TYPE_AAAA => QueryStrategy::UseIpv6,
        _ => return Some(build_response(&query, RCODE_NOERROR, &[])),
    };
    // A configuration restricted to one family answers the other with
    // nothing, so applications never try a family the tunnel cannot carry.
    let configured = resolver.settings().query_strategy;
    let family_allowed = !matches!(
        (configured, strategy),
        (QueryStrategy::UseIpv4, QueryStrategy::UseIpv6)
            | (QueryStrategy::UseIpv6, QueryStrategy::UseIpv4)
    );
    if !family_allowed || query.name.is_empty() {
        return Some(build_response(&query, RCODE_NOERROR, &[]));
    }
    Some(match resolver.lookup(&query.name, strategy).await {
        Ok(addresses) => build_response(&query, RCODE_NOERROR, &addresses),
        Err(ResolveError::NoData(_)) => build_response(&query, RCODE_NOERROR, &[]),
        Err(ResolveError::Blocked) => build_response(&query, RCODE_NXDOMAIN, &[]),
        Err(error) => {
            tracing::debug!(name = %query.name, %error, "dns outbound could not resolve");
            build_response(&query, RCODE_SERVFAIL, &[])
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet
    }

    #[test]
    fn a_question_round_trips_into_an_answer_with_matching_id_and_question() {
        let packet = query("Example.COM", TYPE_A);
        let parsed = parse_query(&packet).unwrap();
        assert_eq!(parsed.name, "example.com");
        assert_eq!(parsed.qtype, TYPE_A);

        let response = build_response(
            &parsed,
            RCODE_NOERROR,
            &[
                "93.184.216.34".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
        );
        assert_eq!(&response[..2], &[0x12, 0x34]);
        // QR, RD echoed, RA, NOERROR.
        assert_eq!(u16::from_be_bytes([response[2], response[3]]), 0x8180);
        // One answer: the IPv6 address does not belong in an A response.
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(&response[12..12 + parsed.question.len()], &packet[12..]);
        assert_eq!(&response[response.len() - 4..], &[93, 184, 216, 34]);
    }

    #[test]
    fn responses_and_compressed_questions_are_not_answered() {
        let mut response = query("example.com", TYPE_A);
        response[2] |= 0x80;
        assert!(parse_query(&response).is_none());

        let mut compressed = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C];
        compressed.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse_query(&compressed).is_none());
        assert!(parse_query(&[0u8; 5]).is_none());
    }

    #[tokio::test]
    async fn other_types_get_an_empty_noerror_and_hosts_entries_are_served() {
        let mut settings = zero_config::dns::DnsSettings::default();
        settings.hosts.insert(
            "pinned.example".into(),
            zero_config::dns::HostValue::Addresses(vec![zero_core::Address::parse_host(
                "192.0.2.7",
            )]),
        );
        settings.query_strategy = QueryStrategy::UseIpv4;
        let resolver = Resolver::new(settings);

        let https = answer(&resolver, &query("pinned.example", 65))
            .await
            .unwrap();
        assert_eq!(https[3] & 0x0F, RCODE_NOERROR);
        assert_eq!(u16::from_be_bytes([https[6], https[7]]), 0);

        let a = answer(&resolver, &query("pinned.example", TYPE_A))
            .await
            .unwrap();
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1);
        assert_eq!(&a[a.len() - 4..], &[192, 0, 2, 7]);

        // IPv4-only configuration: AAAA is answered empty, not resolved.
        let aaaa = answer(&resolver, &query("pinned.example", TYPE_AAAA))
            .await
            .unwrap();
        assert_eq!(aaaa[3] & 0x0F, RCODE_NOERROR);
        assert_eq!(u16::from_be_bytes([aaaa[6], aaaa[7]]), 0);
    }
}
