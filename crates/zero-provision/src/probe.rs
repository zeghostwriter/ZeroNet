//! Checking from the person's own network that a MasterDNS server answers.
//!
//! A DNS tunnel only works when the whole chain does: the name server record
//! at the registrar, the `A` record of that host, the server's port 53, and a
//! resolver that is willing to pass the queries on. This module asks the same
//! question the tunnel itself will: it sends the tunnel's own MTU probe, under
//! the tunnel domain, through each resolver given, and sees whether the
//! server answers. A resolver that returns the answer proves every link of the
//! chain at once.
//!
//! [`ns_host_points_here`] covers the part people most often get wrong, the
//! `A` record, and can run before anything is installed.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use zero_masterdns::carrier::{exchange, DnsRequestIds, Exchange, TunnelSocket};
use zero_masterdns::mtu::{
    build_upload_probe_payload, validate_upload_response, PROBE_FRAGMENT_ID,
    PROBE_SENTINEL_SESSION_ID, PROBE_SEQUENCE_NUM, PROBE_STREAM_ID, PROBE_TOTAL_FRAGMENTS,
};
use zero_protocol::masterdns::codec::Codec;
use zero_protocol::masterdns::dns::{
    build_tunnel_txt_question, extract_vpn_frame, parse_dns_packet,
};
use zero_protocol::masterdns::enums::PACKET_MTU_UP_REQ;
use zero_protocol::masterdns::packet::{build_raw, parse, BuildOptions};

use crate::record::MasterDns;

const TIMEOUT: Duration = Duration::from_secs(4);
const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
/// Size of the probe payload: small enough for any resolver path.
const PROBE_SIZE: i32 = 40;

/// Public resolvers the checks go through when the person's own resolver may
/// be the thing in the way: Google, Quad9 and Cloudflare. Any one answering is
/// enough to prove the record has spread.
pub fn public_resolvers() -> Vec<SocketAddr> {
    [[8, 8, 8, 8], [9, 9, 9, 9], [1, 1, 1, 1]]
        .into_iter()
        .map(|ip| SocketAddr::from((ip, 53)))
        .collect()
}

/// How one resolver fared.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProbeResult {
    pub resolver: SocketAddr,
    pub answered: bool,
    /// Round trip of the answered probe, in milliseconds.
    pub millis: Option<u64>,
}

/// Send the tunnel's probe to `server_name` (the tunnel domain) through each
/// of `resolvers` and report which of them delivered it. Pass the server
/// itself as the only "resolver" to test the server without DNS in the way.
pub async fn probe_masterdns(service: &MasterDns, resolvers: &[SocketAddr]) -> Vec<ProbeResult> {
    let Ok(codec) = Codec::new(service.method, &service.key) else {
        return Vec::new();
    };
    let ids = DnsRequestIds::random();
    let code: u32 = rand::random();
    let payload = build_upload_probe_payload(PROBE_SIZE, false, code).expect("a size that fits");
    let raw = build_raw(&BuildOptions {
        session_id: PROBE_SENTINEL_SESSION_ID,
        packet_type: PACKET_MTU_UP_REQ,
        stream_id: PROBE_STREAM_ID,
        sequence_num: PROBE_SEQUENCE_NUM,
        fragment_id: PROBE_FRAGMENT_ID,
        total_fragments: PROBE_TOTAL_FRAGMENTS,
        payload: &payload,
        ..Default::default()
    })
    .expect("a well-formed probe");
    let labels = codec.encrypt_and_encode(&raw);
    let mut results = Vec::new();
    for resolver in resolvers {
        let Ok(socket) = TunnelSocket::bind().await else {
            continue;
        };
        let Ok(question) = build_tunnel_txt_question(
            &service.domain,
            labels.as_bytes(),
            ids.next(),
            TYPE_TXT,
            4096,
        ) else {
            continue;
        };
        let mut buffer = vec![0u8; 65535];
        let started = Instant::now();
        let reply = exchange(&socket, &question, *resolver, TIMEOUT, &mut buffer).await;
        let answered = match reply {
            Ok(Exchange::Response { len, .. }) => extract_vpn_frame(&buffer[..len], false)
                .ok()
                .and_then(|frame| {
                    let packet = parse(&frame).ok()?;
                    Some(validate_upload_response(
                        packet.packet_type,
                        packet.payload,
                        code,
                        PROBE_SIZE,
                    ))
                })
                .unwrap_or(false),
            _ => false,
        };
        results.push(ProbeResult {
            resolver: *resolver,
            answered,
            millis: answered.then(|| started.elapsed().as_millis() as u64),
        });
    }
    results
}

/// Whether `host` resolves, through any of `resolvers`, to `expected`: the
/// check for the `A` record that names the server. `None` when no resolver
/// answered at all (so nothing can be said).
pub async fn ns_host_points_here(
    host: &str,
    expected: IpAddr,
    resolvers: &[SocketAddr],
) -> Option<bool> {
    let ids = DnsRequestIds::random();
    let mut heard = false;
    for resolver in resolvers {
        let Ok(socket) = TunnelSocket::bind().await else {
            continue;
        };
        let Ok(question) = build_tunnel_txt_question(host, b"", ids.next(), TYPE_A, 0) else {
            continue;
        };
        let mut buffer = vec![0u8; 4096];
        let Ok(Exchange::Response { len, .. }) =
            exchange(&socket, &question, *resolver, TIMEOUT, &mut buffer).await
        else {
            continue;
        };
        let Ok(packet) = parse_dns_packet(&buffer[..len]) else {
            continue;
        };
        heard = true;
        let found: Vec<IpAddr> = packet
            .answers
            .iter()
            .filter(|r| r.rtype == TYPE_A && r.rdata.len() == 4)
            .map(|r| IpAddr::from([r.rdata[0], r.rdata[1], r.rdata[2], r.rdata[3]]))
            .collect();
        if found.contains(&expected) {
            return Some(true);
        }
    }
    heard.then_some(false)
}
