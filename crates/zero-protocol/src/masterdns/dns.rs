//! The DNS carrier framing: how a sealed, label-encoded packet becomes the
//! question name of a DNS `TXT` query, and how the server's `TXT` answers
//! become raw packet bytes again.
//!
//! Ported from the Go `internal/dnsparser` at the pinned release
//! `v2026.06.13.234407-7de2476`. This is pure bytes-in, bytes-out: the sockets
//! that actually send a query and wait for a reply live in `zero-transport`,
//! the same split the rest of this crate keeps.
//!
//! Two directions, and they are deliberately not symmetric:
//!
//!  * **Request** — the client has already sealed a packet and encoded it to a
//!    base-N label string (see [`super::codec`]). [`build_tunnel_txt_question`]
//!    chops that string into DNS labels of at most 63 bytes, appends the base
//!    domain, and writes a standard `TXT` question. Local resolvers see an
//!    ordinary name query and forward it to the server's authoritative side.
//!  * **Response** — the server answers with one or more `TXT` records whose
//!    strings carry the raw reply frame, either verbatim or standard-base64.
//!    [`extract_vpn_frame`] parses the message, pulls the `TXT` strings, and
//!    (when the reply was split) reassembles the chunks back into one frame.
//!
//! The reassembly rule the chunk format keeps: chunk zero starts with a
//! `0x00` marker and a total count and carries the packet header; every later
//! chunk starts with its own 1-based index. Concatenating chunk zero's bytes
//! after the two marker bytes, then each later chunk's bytes after its index
//! byte, in index order, reproduces the original frame exactly — no need to
//! know where the header ends.

use super::codec::{self, CodecError};

/// Longest a full DNS name may be on the wire, in bytes (RFC 1035).
pub const MAX_DNS_NAME_LEN: usize = 253;
/// Longest a single DNS label may be, in bytes.
pub const MAX_DNS_LABEL_LEN: usize = 63;
/// The EDNS0 UDP payload size the client advertises, matching the Go client's
/// `EDnsSafeUDPSize`. Pass `0` to omit the OPT record entirely.
pub const EDNS_SAFE_UDP_SIZE: u16 = 4096;

const DNS_HEADER_SIZE: usize = 12;
const MAX_NAME_JUMPS: usize = 10;

/// DNS record type for a text record: the carrier for both the question and
/// the answers.
pub const DNS_RECORD_TYPE_TXT: u16 = 16;
/// DNS record type for the EDNS0 pseudo-record.
pub const DNS_RECORD_TYPE_OPT: u16 = 41;
/// DNS `IN` (internet) class.
pub const DNS_CLASS_IN: u16 = 1;

/// What can go wrong building or reading a carrier message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    /// A name or label was empty, over length, or otherwise unencodable.
    InvalidName,
    /// Fewer bytes than a DNS header, or a section ran off the end.
    PacketTooShort,
    /// The question section could not be parsed.
    InvalidQuestion,
    /// A resource record section could not be parsed.
    InvalidAnswer,
    /// The response held no usable `TXT` answer.
    TxtAnswerMissing,
    /// The chunked answer set was inconsistent: a missing or extra chunk, a
    /// bad total, or a malformed marker.
    TxtAnswerMalformed,
    /// A base64 answer string did not decode.
    BadEncoding,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            DnsError::InvalidName => "invalid dns name",
            DnsError::PacketTooShort => "dns packet too short",
            DnsError::InvalidQuestion => "invalid dns question section",
            DnsError::InvalidAnswer => "invalid dns resource record section",
            DnsError::TxtAnswerMissing => "dns txt answer missing",
            DnsError::TxtAnswerMalformed => "dns txt answer malformed",
            DnsError::BadEncoding => "dns txt answer not valid base64",
        };
        f.write_str(text)
    }
}

impl std::error::Error for DnsError {}

impl From<CodecError> for DnsError {
    fn from(_: CodecError) -> Self {
        DnsError::BadEncoding
    }
}

// ---------------------------------------------------------------------------
// Request path.
// ---------------------------------------------------------------------------

/// Encode a dotted DNS name into the length-prefixed wire form, lowercasing
/// nothing (the caller controls case). An empty name encodes to the single
/// root byte `0x00`. Mirrors the Go `encodeDNSNameStrict`.
pub fn encode_dns_name_strict(name: &str) -> Result<Vec<u8>, DnsError> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() {
        return Ok(vec![0]);
    }
    if name.len() > MAX_DNS_NAME_LEN {
        return Err(DnsError::InvalidName);
    }

    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() + 2);
    let mut label_start = 0;
    for i in 0..=bytes.len() {
        if i < bytes.len() && bytes[i] != b'.' {
            continue;
        }
        let label_len = i - label_start;
        if label_len == 0 || label_len > MAX_DNS_LABEL_LEN {
            return Err(DnsError::InvalidName);
        }
        out.push(label_len as u8);
        out.extend_from_slice(&bytes[label_start..i]);
        label_start = i + 1;
    }
    out.push(0);
    Ok(out)
}

/// The wire length a question name would occupy for `encoded_chars` label
/// characters plus a base domain of `domain_len` characters. Mirrors the Go
/// `encodedQNameLen`, which measures against the raw domain string length.
fn encoded_qname_len(encoded_chars: usize, domain_len: usize) -> usize {
    if encoded_chars == 0 {
        return domain_len;
    }
    let label_splits = (encoded_chars - 1) / MAX_DNS_LABEL_LEN;
    encoded_chars + label_splits + 1 + domain_len
}

/// The most label characters that will still fit in a question name under the
/// 253-byte limit, for the given base domain. Mirrors the Go
/// `CalculateMaxEncodedQNameChars` (a binary search).
pub fn max_encoded_qname_chars(domain: &str) -> usize {
    let domain_len = domain.trim().trim_end_matches('.').len();
    if domain_len == 0 {
        return MAX_DNS_NAME_LEN;
    }
    let (mut low, mut high, mut best) = (0usize, MAX_DNS_NAME_LEN, 0usize);
    while low <= high {
        let mid = (low + high) / 2;
        if encoded_qname_len(mid, domain_len) <= MAX_DNS_NAME_LEN {
            best = mid;
            low = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }
    best
}

/// Build a `TXT` question carrying `encoded_frame` as the leading labels of the
/// name, under `domain`. `request_id` is the DNS transaction id (the transport
/// layer picks it); `qtype` is normally [`DNS_RECORD_TYPE_TXT`]; a non-zero
/// `edns_udp_size` appends an EDNS0 OPT record advertising that buffer size.
///
/// With an empty `encoded_frame` this is just a plain question for `domain`.
/// Fails with [`DnsError::InvalidName`] if the name would exceed 253 bytes.
pub fn build_tunnel_txt_question(
    domain: &str,
    encoded_frame: &[u8],
    request_id: u16,
    qtype: u16,
    edns_udp_size: u16,
) -> Result<Vec<u8>, DnsError> {
    let normalized = domain.trim().to_ascii_lowercase();
    let normalized = normalized.trim_end_matches('.');
    if normalized.is_empty() {
        return Err(DnsError::InvalidName);
    }
    let domain_qname = encode_dns_name_strict(normalized)?;

    if encoded_frame.is_empty() {
        return Ok(build_question_prepared(
            &domain_qname,
            request_id,
            qtype,
            edns_udp_size,
        ));
    }

    if encoded_qname_len(encoded_frame.len(), normalized.len()) > MAX_DNS_NAME_LEN {
        return Err(DnsError::InvalidName);
    }

    let label_count = encoded_frame.len().div_ceil(MAX_DNS_LABEL_LEN);
    let qname_len = encoded_frame.len() + label_count + domain_qname.len();

    let (ar_count, opt_len) = edns_section(edns_udp_size);
    let mut packet = vec![0u8; DNS_HEADER_SIZE + qname_len + 4 + opt_len];
    write_question_header(&mut packet, request_id, ar_count);

    let mut offset = DNS_HEADER_SIZE;
    let mut start = 0;
    while start < encoded_frame.len() {
        let end = (start + MAX_DNS_LABEL_LEN).min(encoded_frame.len());
        packet[offset] = (end - start) as u8;
        offset += 1;
        packet[offset..offset + (end - start)].copy_from_slice(&encoded_frame[start..end]);
        offset += end - start;
        start = end;
    }
    offset += copy_into(&mut packet[offset..], &domain_qname);
    offset = write_question_tail(&mut packet, offset, qtype);
    write_opt_record(&mut packet, offset, edns_udp_size);

    Ok(packet)
}

/// Build a plain `TXT` question for an already-encoded name (no tunnel labels).
fn build_question_prepared(
    qname: &[u8],
    request_id: u16,
    qtype: u16,
    edns_udp_size: u16,
) -> Vec<u8> {
    let (ar_count, opt_len) = edns_section(edns_udp_size);
    let mut packet = vec![0u8; DNS_HEADER_SIZE + qname.len() + 4 + opt_len];
    write_question_header(&mut packet, request_id, ar_count);

    let mut offset = DNS_HEADER_SIZE;
    offset += copy_into(&mut packet[offset..], qname);
    offset = write_question_tail(&mut packet, offset, qtype);
    write_opt_record(&mut packet, offset, edns_udp_size);
    packet
}

/// `(arcount, opt-record-length)` for an optional EDNS0 size. `0` means none.
fn edns_section(edns_udp_size: u16) -> (u16, usize) {
    if edns_udp_size > 0 {
        (1, 11)
    } else {
        (0, 0)
    }
}

fn write_question_header(packet: &mut [u8], request_id: u16, ar_count: u16) {
    packet[0..2].copy_from_slice(&request_id.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    packet[4..6].copy_from_slice(&1u16.to_be_bytes());
    packet[10..12].copy_from_slice(&ar_count.to_be_bytes());
}

fn write_question_tail(packet: &mut [u8], offset: usize, qtype: u16) -> usize {
    packet[offset..offset + 2].copy_from_slice(&qtype.to_be_bytes());
    packet[offset + 2..offset + 4].copy_from_slice(&DNS_CLASS_IN.to_be_bytes());
    offset + 4
}

fn write_opt_record(packet: &mut [u8], offset: usize, edns_udp_size: u16) {
    if edns_udp_size == 0 {
        return;
    }
    packet[offset] = 0x00;
    packet[offset + 1..offset + 3].copy_from_slice(&DNS_RECORD_TYPE_OPT.to_be_bytes());
    packet[offset + 3..offset + 5].copy_from_slice(&edns_udp_size.to_be_bytes());
    // ttl (4 bytes) and rdlen (2 bytes) are already zero.
}

fn copy_into(dst: &mut [u8], src: &[u8]) -> usize {
    dst[..src.len()].copy_from_slice(src);
    src.len()
}

// ---------------------------------------------------------------------------
// Response path: parsing.
// ---------------------------------------------------------------------------

/// A DNS header, the fields a client cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl DnsHeader {
    /// The 4-bit response code from the flags word.
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }
    /// True when the response bit (QR) is set.
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
}

/// One question record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub class: u16,
}

/// One resource record. `rdata` is owned so the parsed packet can outlive the
/// input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

/// A fully parsed DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub authorities: Vec<DnsResourceRecord>,
    pub additional: Vec<DnsResourceRecord>,
}

fn parse_header(data: &[u8]) -> DnsHeader {
    DnsHeader {
        id: u16::from_be_bytes([data[0], data[1]]),
        flags: u16::from_be_bytes([data[2], data[3]]),
        qd_count: u16::from_be_bytes([data[4], data[5]]),
        an_count: u16::from_be_bytes([data[6], data[7]]),
        ns_count: u16::from_be_bytes([data[8], data[9]]),
        ar_count: u16::from_be_bytes([data[10], data[11]]),
    }
}

/// Parse a whole DNS message. Mirrors the Go `ParsePacket`.
pub fn parse_dns_packet(data: &[u8]) -> Result<DnsPacket, DnsError> {
    if data.len() < DNS_HEADER_SIZE {
        return Err(DnsError::PacketTooShort);
    }
    let header = parse_header(data);
    let mut offset = DNS_HEADER_SIZE;

    let (questions, next) = parse_questions(data, offset, header.qd_count as usize)?;
    offset = next;
    let (answers, next) = parse_records(data, offset, header.an_count as usize)?;
    offset = next;
    let (authorities, next) = parse_records(data, offset, header.ns_count as usize)?;
    offset = next;
    let (additional, _) = parse_records(data, offset, header.ar_count as usize)?;

    Ok(DnsPacket {
        header,
        questions,
        answers,
        authorities,
        additional,
    })
}

fn parse_questions(
    data: &[u8],
    mut offset: usize,
    count: usize,
) -> Result<(Vec<DnsQuestion>, usize), DnsError> {
    let mut questions = Vec::with_capacity(count);
    for _ in 0..count {
        let (name, next) = parse_name(data, offset).map_err(|_| DnsError::InvalidQuestion)?;
        offset = next;
        if offset + 4 > data.len() {
            return Err(DnsError::InvalidQuestion);
        }
        questions.push(DnsQuestion {
            name,
            qtype: u16::from_be_bytes([data[offset], data[offset + 1]]),
            class: u16::from_be_bytes([data[offset + 2], data[offset + 3]]),
        });
        offset += 4;
    }
    Ok((questions, offset))
}

fn parse_records(
    data: &[u8],
    mut offset: usize,
    count: usize,
) -> Result<(Vec<DnsResourceRecord>, usize), DnsError> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let (name, next) = parse_name(data, offset).map_err(|_| DnsError::InvalidAnswer)?;
        offset = next;
        if offset + 10 > data.len() {
            return Err(DnsError::InvalidAnswer);
        }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let class = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rd_len = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;
        let end = offset + rd_len;
        if end > data.len() {
            return Err(DnsError::InvalidAnswer);
        }
        records.push(DnsResourceRecord {
            name,
            rtype,
            class,
            ttl,
            rdata: data[offset..end].to_vec(),
        });
        offset = end;
    }
    Ok((records, offset))
}

/// Parse a DNS name, following compression pointers. Returns the lowercased
/// dotted name and the offset of the byte after the name in its original
/// position (not the pointer target). Mirrors the Go `parseName`.
fn parse_name(data: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let data_len = data.len();
    if start >= data_len {
        return Err(DnsError::InvalidName);
    }
    let mut offset = start;
    let mut jumped = false;
    let mut jumps = 0usize;
    let mut orig_next = start;
    let mut name = String::new();
    let mut has_label = false;

    loop {
        if offset >= data_len {
            return Err(DnsError::InvalidName);
        }
        let length = data[offset] as usize;
        if length == 0 {
            offset += 1;
            if !jumped {
                orig_next = offset;
            }
            break;
        }
        if length >= 0xC0 {
            if offset + 1 >= data_len || jumps >= MAX_NAME_JUMPS {
                return Err(DnsError::InvalidName);
            }
            let ptr = (u16::from_be_bytes([data[offset], data[offset + 1]]) & 0x3FFF) as usize;
            if ptr >= data_len {
                return Err(DnsError::InvalidName);
            }
            if !jumped {
                orig_next = offset + 2;
                jumped = true;
            }
            offset = ptr;
            jumps += 1;
            continue;
        }
        if length > MAX_DNS_LABEL_LEN {
            return Err(DnsError::InvalidName);
        }
        offset += 1;
        let end = offset + length;
        if end > data_len {
            return Err(DnsError::InvalidName);
        }
        if !name.is_empty() {
            name.push('.');
        }
        for &b in &data[offset..end] {
            name.push(b.to_ascii_lowercase() as char);
        }
        has_label = true;
        offset = end;
        if !jumped {
            orig_next = offset;
        }
    }

    if !has_label {
        return Ok((".".to_string(), orig_next));
    }
    Ok((name, orig_next))
}

// ---------------------------------------------------------------------------
// Response path: TXT extraction and reassembly.
// ---------------------------------------------------------------------------

/// Pull the concatenated bytes of one `TXT` record's rdata. A `TXT` rdata is
/// one or more `<len><bytes>` strings; this joins them. Mirrors the Go
/// `extractTXTBytes`, including its tolerance for a final truncated string.
pub fn extract_txt_bytes(rdata: &[u8]) -> Vec<u8> {
    if rdata.is_empty() {
        return Vec::new();
    }
    // Fast path: a single string that fills the whole rdata.
    if rdata[0] as usize + 1 == rdata.len() {
        return rdata[1..].to_vec();
    }

    let mut out = Vec::new();
    let mut offset = 0;
    while offset < rdata.len() {
        let size = rdata[offset] as usize;
        offset += 1;
        if size == 0 {
            continue;
        }
        if offset + size > rdata.len() {
            out.extend_from_slice(&rdata[offset..]);
            break;
        }
        out.extend_from_slice(&rdata[offset..offset + size]);
        offset += size;
    }
    out
}

/// Every `TXT` answer's bytes, in answer order, skipping empties. Mirrors the
/// Go `extractTXTAnswerPayloads`.
pub fn extract_txt_answer_payloads(packet: &DnsPacket) -> Vec<Vec<u8>> {
    let mut payloads = Vec::with_capacity(packet.answers.len());
    for answer in &packet.answers {
        if answer.rtype != DNS_RECORD_TYPE_TXT {
            continue;
        }
        let raw = extract_txt_bytes(&answer.rdata);
        if raw.is_empty() {
            continue;
        }
        payloads.push(raw);
    }
    payloads
}

/// Turn the `TXT` answer strings back into one raw packet frame (still
/// compressed if the server compressed it). `base_encoded` says whether the
/// strings are standard-base64 rather than verbatim bytes. Mirrors the Go
/// `assembleVPNResponse` up to the point before inflation; the caller runs
/// [`super::packet::parse`] and any decompression on the result.
pub fn reassemble_vpn_frame(
    raw_answers: &[Vec<u8>],
    base_encoded: bool,
) -> Result<Vec<u8>, DnsError> {
    if raw_answers.is_empty() {
        return Err(DnsError::TxtAnswerMissing);
    }
    if raw_answers.len() == 1 {
        return decode_answer(&raw_answers[0], base_encoded);
    }

    const MAX_CHUNKS: usize = 256;
    let mut chunks: Vec<Option<Vec<u8>>> = (0..MAX_CHUNKS).map(|_| None).collect();
    let mut total_expected = 0usize;
    let mut seen = 0usize;
    let mut header_seen = false;

    for raw in raw_answers {
        let raw = decode_answer(raw, base_encoded)?;
        if raw.is_empty() {
            continue;
        }
        if raw[0] == 0x00 {
            if raw.len() < 3 {
                return Err(DnsError::TxtAnswerMalformed);
            }
            total_expected = raw[1] as usize;
            if total_expected == 0 || total_expected > MAX_CHUNKS {
                return Err(DnsError::TxtAnswerMalformed);
            }
            header_seen = true;
            if chunks[0].is_none() {
                seen += 1;
            }
            chunks[0] = Some(raw[2..].to_vec());
            continue;
        }
        let chunk_id = raw[0] as usize;
        if chunk_id >= MAX_CHUNKS {
            return Err(DnsError::TxtAnswerMalformed);
        }
        if chunks[chunk_id].is_none() {
            seen += 1;
        }
        chunks[chunk_id] = Some(raw[1..].to_vec());
    }

    if !header_seen || total_expected == 0 || seen != total_expected {
        return Err(DnsError::TxtAnswerMalformed);
    }
    for chunk in chunks.iter().take(total_expected) {
        if chunk.is_none() {
            return Err(DnsError::TxtAnswerMalformed);
        }
    }
    for chunk in chunks.iter().skip(total_expected) {
        if chunk.is_some() {
            return Err(DnsError::TxtAnswerMalformed);
        }
    }

    let mut frame = Vec::new();
    for chunk in chunks.into_iter().take(total_expected) {
        frame.extend_from_slice(&chunk.expect("checked present"));
    }
    Ok(frame)
}

fn decode_answer(raw: &[u8], base_encoded: bool) -> Result<Vec<u8>, DnsError> {
    if base_encoded {
        Ok(codec::raw_base64_decode(raw)?)
    } else {
        Ok(raw.to_vec())
    }
}

/// Parse a DNS response and recover the raw packet frame it carries. This is
/// the client's whole inbound path short of decryption/decompression. Mirrors
/// the Go `ExtractVPNResponse`.
pub fn extract_vpn_frame(packet: &[u8], base_encoded: bool) -> Result<Vec<u8>, DnsError> {
    let parsed = parse_dns_packet(packet)?;
    let answers = extract_txt_answer_payloads(&parsed);
    if answers.is_empty() {
        return Err(DnsError::TxtAnswerMissing);
    }
    reassemble_vpn_frame(&answers, base_encoded)
}
