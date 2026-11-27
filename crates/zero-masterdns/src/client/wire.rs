//! The client half of the wire: turn a packet into a DNS question, and an
//! answer back into packets.
//!
//! How it works: a packet is built (and compressed if the session negotiated
//! it), sealed and encoded into DNS-label text by the [`Codec`], and placed as
//! the leading labels of a `TXT` question under the tunnel domain. The server
//! answers with the reply packet in the TXT record: raw bytes, or base64 text
//! when the session asked for it. Only the request direction is encrypted.
//!
//! One answer carries one packet, except `PACKED_CONTROL_BLOCKS`, which carries
//! several payload-free control packets (acks) at once; [`Wire::replies`]
//! expands that into one [`Reply`] each, so callers never see the packing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use zero_protocol::masterdns::codec::Codec;
use zero_protocol::masterdns::dns::{
    build_tunnel_txt_question, extract_vpn_frame, max_encoded_qname_chars,
};
use zero_protocol::masterdns::enums::PACKET_PACKED_CONTROL_BLOCKS;
use zero_protocol::masterdns::packet::{iter_packed_control_blocks, parse, BuildOptions};

use super::Error;
use crate::carrier::DnsRequestIds;
use crate::payload::{build_raw_auto, inflate_payload};

/// One packet the server sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reply {
    pub packet_type: u8,
    pub stream_id: u16,
    pub seq: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
    pub payload: Vec<u8>,
}

/// Builds questions and reads answers for one tunnel domain and key.
pub(crate) struct Wire {
    domain: String,
    codec: Codec,
    ids: DnsRequestIds,
    base64: AtomicBool,
}

/// The `TXT` record type, and the EDNS buffer size the questions advertise.
const QTYPE_TXT: u16 = 16;
const EDNS_UDP_SIZE: u16 = 4096;

impl Wire {
    pub fn new(domain: &str, key: &str, method: u8, base64: bool) -> Result<Self, Error> {
        let codec = Codec::new(method, key).map_err(|e| Error::Config(format!("key: {e:?}")))?;
        Ok(Wire {
            domain: domain.trim().trim_end_matches('.').to_ascii_lowercase(),
            codec,
            ids: DnsRequestIds::random(),
            base64: AtomicBool::new(base64),
        })
    }

    /// Whether answers come back as base64 text (decided in the handshake).
    pub fn set_base64(&self, base64: bool) {
        self.base64.store(base64, Ordering::Relaxed);
    }

    /// The DNS question that carries `opts`. Fails when the sealed packet
    /// would not fit in a name (the caller sized the payload from
    /// [`Wire::max_payload`], so this is an internal error, not a path one).
    pub fn question(&self, opts: &BuildOptions) -> Result<Vec<u8>, Error> {
        let raw = build_raw_auto(opts, 0).map_err(|e| Error::Protocol(format!("packet: {e:?}")))?;
        let labels = self.codec.encrypt_and_encode(&raw);
        build_tunnel_txt_question(
            &self.domain,
            labels.as_bytes(),
            self.ids.next(),
            QTYPE_TXT,
            EDNS_UDP_SIZE,
        )
        .map_err(|e| Error::Protocol(format!("question: {e:?}")))
    }

    /// The packets in one DNS answer (none when it carries no tunnel data).
    pub fn replies(&self, datagram: &[u8]) -> Vec<Reply> {
        let Ok(frame) = extract_vpn_frame(datagram, self.base64.load(Ordering::Relaxed)) else {
            return Vec::new();
        };
        let Ok(packet) = parse(&frame) else {
            return Vec::new();
        };
        if packet.packet_type == PACKET_PACKED_CONTROL_BLOCKS {
            return iter_packed_control_blocks(packet.payload)
                .map(|b| Reply {
                    packet_type: b.packet_type,
                    stream_id: b.stream_id,
                    seq: b.sequence_num,
                    fragment_id: b.fragment_id,
                    total_fragments: b.total_fragments,
                    payload: Vec::new(),
                })
                .collect();
        }
        let Ok(payload) = inflate_payload(&packet) else {
            return Vec::new();
        };
        vec![Reply {
            packet_type: packet.packet_type,
            stream_id: packet.stream_id.unwrap_or(0),
            seq: packet.sequence_num.unwrap_or(0),
            fragment_id: packet.fragment.map_or(0, |f| f.id),
            total_fragments: packet.fragment.map_or(0, |f| f.total),
            payload: payload.into_owned(),
        }]
    }

    /// The most payload bytes a packet of `packet_type` can carry in one
    /// question under this domain, assuming every optional header field is
    /// present (the worst case). Found by building and checking, so it tracks
    /// the real header and encoding sizes instead of a formula.
    pub fn max_payload(&self, packet_type: u8) -> usize {
        let fits = |len: usize| {
            let payload = vec![0u8; len];
            self.question(&BuildOptions {
                session_id: 255,
                packet_type,
                session_cookie: 255,
                stream_id: 0xFFFF,
                sequence_num: 0xFFFF,
                fragment_id: 0xFF,
                total_fragments: 0xFF,
                compression_type: 0xFF,
                payload: &payload,
            })
            .is_ok()
        };
        let (mut low, mut high, mut best) = (0usize, max_encoded_qname_chars(&self.domain), 0);
        while low <= high {
            let mid = (low + high) / 2;
            if fits(mid) {
                best = mid;
                low = mid + 1;
            } else if mid == 0 {
                break;
            } else {
                high = mid - 1;
            }
        }
        best
    }
}

/// How long a query may go unanswered before its slot is given up. The packet
/// itself is left to the ARQ layer to resend.
pub(crate) const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
