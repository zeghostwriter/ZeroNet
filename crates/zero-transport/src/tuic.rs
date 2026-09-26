//! TUIC v5 QUIC carrier.
//!
//! The implementation follows the public TUIC v5 wire contract used by the
//! MIT-licensed `shoes` reference: an authenticated unidirectional stream,
//! bidirectional CONNECT streams, and PACKET datagrams. The runtime owns
//! routing; this module only turns a QUIC connection into a byte stream or one
//! request/response datagram exchange.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{BufMut, BytesMut};
use tokio::io::duplex;
use tokio::time::{timeout, Duration, Instant};
use zero_core::{boxed, BoxStream, Destination};

const VERSION: u8 = 5;
const AUTH: u8 = 0;
const CONNECT: u8 = 1;
const PACKET: u8 = 2;
const HEARTBEAT: u8 = 4;
const MAX_ADDRESS: usize = 255;

fn tls_client_config(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
) -> Result<(h3_quinn::quinn::Endpoint, zero_security::TlsParams), String> {
    if addrs.is_empty() {
        return Err("TUIC has no resolved endpoint".into());
    }
    let mut tls = tls.clone();
    tls.alpn = vec![b"h3".to_vec()];
    let rustls = zero_security::try_client_config(&tls)
        .map_err(|error| format!("TUIC TLS configuration: {error}"))?;
    let crypto = h3_quinn::quinn::crypto::rustls::QuicClientConfig::try_from((*rustls).clone())
        .map_err(|error| format!("TUIC TLS configuration: {error}"))?;
    let mut client_config = h3_quinn::quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = crate::relay::quic_transport(CLIENT_IDLE_TIMEOUT, Some(CLIENT_KEEP_ALIVE));
    transport.max_concurrent_bidi_streams(1024u32.into());
    transport.max_concurrent_uni_streams(1024u32.into());
    client_config.transport_config(Arc::new(transport));
    let bind: SocketAddr = if addrs[0].is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = crate::relay::protected_client_endpoint(bind)
        .map_err(|error| format!("TUIC endpoint: {error}"))?;
    endpoint.set_default_client_config(client_config);
    Ok((endpoint, tls))
}

async fn connect_quic(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
) -> Result<(h3_quinn::quinn::Endpoint, h3_quinn::quinn::Connection), String> {
    let (endpoint, tls) = tls_client_config(addrs, tls)?;
    let mut last_error = None;
    for address in addrs {
        match endpoint.connect(*address, &tls.server_name) {
            Ok(connecting) => match connecting.await {
                Ok(connection) => return Ok((endpoint, connection)),
                Err(error) => last_error = Some(error.to_string()),
            },
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    Err(format!(
        "TUIC QUIC connect failed: {}",
        last_error.unwrap_or_else(|| "no candidate succeeded".into())
    ))
}

async fn authenticate(
    connection: &h3_quinn::quinn::Connection,
    uuid: &[u8; 16],
    password: &str,
) -> Result<(), String> {
    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|error| format!("TUIC key export: {error:?}"))?;
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|error| format!("TUIC auth stream: {error}"))?;
    stream
        .write_all(&[VERSION, AUTH])
        .await
        .map_err(|error| format!("TUIC auth header: {error}"))?;
    stream
        .write_all(uuid)
        .await
        .map_err(|error| format!("TUIC auth UUID: {error}"))?;
    stream
        .write_all(&token)
        .await
        .map_err(|error| format!("TUIC auth token: {error}"))?;
    stream
        .finish()
        .map_err(|error| format!("TUIC auth finish: {error}"))?;
    Ok(())
}

async fn authenticate_server(
    connection: &h3_quinn::quinn::Connection,
    uuid: &[u8; 16],
    password: &str,
) -> Result<(), String> {
    let mut expected = [0u8; 32];
    connection
        .export_keying_material(&mut expected, uuid, password.as_bytes())
        .map_err(|error| format!("TUIC key export: {error:?}"))?;
    let mut stream = connection
        .accept_uni()
        .await
        .map_err(|error| format!("TUIC auth accept: {error}"))?;
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|error| format!("TUIC auth header: {error}"))?;
    if header != [VERSION, AUTH] {
        return Err("TUIC authentication command is invalid".into());
    }
    let mut specified_uuid = [0u8; 16];
    stream
        .read_exact(&mut specified_uuid)
        .await
        .map_err(|error| format!("TUIC auth UUID: {error}"))?;
    if &specified_uuid != uuid {
        return Err("TUIC UUID authentication failed".into());
    }
    let mut token = [0u8; 32];
    stream
        .read_exact(&mut token)
        .await
        .map_err(|error| format!("TUIC auth token: {error}"))?;
    if token != expected {
        return Err("TUIC token authentication failed".into());
    }
    Ok(())
}

fn encode_address(destination: &Destination) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(MAX_ADDRESS + 3);
    match &destination.address {
        zero_core::Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        zero_core::Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(2);
            out.extend_from_slice(&ip.octets());
        }
        zero_core::Address::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > MAX_ADDRESS {
                return Err("TUIC hostname is outside the one-byte length limit".into());
            }
            out.push(0);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(out)
}

fn decode_address(data: &[u8], offset: &mut usize) -> Result<Destination, String> {
    let kind = *data
        .get(*offset)
        .ok_or_else(|| "TUIC address type is missing".to_string())?;
    *offset += 1;
    let address = match kind {
        0 => {
            let len = *data
                .get(*offset)
                .ok_or_else(|| "TUIC hostname length is missing".to_string())?
                as usize;
            *offset += 1;
            let end = offset
                .checked_add(len)
                .ok_or_else(|| "TUIC hostname length overflow".to_string())?;
            let bytes = data
                .get(*offset..end)
                .ok_or_else(|| "TUIC hostname is truncated".to_string())?;
            *offset = end;
            let host =
                std::str::from_utf8(bytes).map_err(|_| "TUIC hostname is not UTF-8".to_string())?;
            zero_core::Address::parse_host(host)
        }
        1 => {
            let bytes = data
                .get(*offset..*offset + 4)
                .ok_or_else(|| "TUIC IPv4 address is truncated".to_string())?;
            *offset += 4;
            zero_core::Address::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        }
        2 => {
            let bytes = data
                .get(*offset..*offset + 16)
                .ok_or_else(|| "TUIC IPv6 address is truncated".to_string())?;
            *offset += 16;
            let bytes: [u8; 16] = bytes.try_into().unwrap();
            zero_core::Address::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
        }
        other => return Err(format!("TUIC address type {other} is invalid")),
    };
    let port = u16::from_be_bytes(
        data.get(*offset..*offset + 2)
            .ok_or_else(|| "TUIC port is truncated".to_string())?
            .try_into()
            .unwrap(),
    );
    *offset += 2;
    Ok(Destination {
        address,
        port,
        network: zero_core::Network::Udp,
    })
}

async fn read_address_stream(
    stream: &mut h3_quinn::quinn::RecvStream,
) -> Result<Destination, String> {
    let mut kind = [0u8; 1];
    stream
        .read_exact(&mut kind)
        .await
        .map_err(|error| format!("TUIC address type: {error}"))?;
    let address = match kind[0] {
        0 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|error| format!("TUIC hostname length: {error}"))?;
            let mut bytes = vec![0u8; len[0] as usize];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("TUIC hostname: {error}"))?;
            let host = std::str::from_utf8(&bytes)
                .map_err(|_| "TUIC hostname is not UTF-8".to_string())?;
            zero_core::Address::parse_host(host)
        }
        1 => {
            let mut bytes = [0u8; 4];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("TUIC IPv4 address: {error}"))?;
            zero_core::Address::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(bytes)))
        }
        2 => {
            let mut bytes = [0u8; 16];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("TUIC IPv6 address: {error}"))?;
            zero_core::Address::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
        }
        other => return Err(format!("TUIC address type {other} is invalid")),
    };
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .map_err(|error| format!("TUIC port: {error}"))?;
    Ok(Destination::tcp(address, u16::from_be_bytes(port)))
}

struct PacketFragment {
    association: u16,
    packet: u16,
    fragment_total: u8,
    fragment_id: u8,
    destination: Option<Destination>,
    payload: Vec<u8>,
}

type ReassembledPacket = (u16, u16, Destination, Vec<u8>);

fn decode_packet_fragment(data: &[u8]) -> Result<PacketFragment, String> {
    if data.len() < 10 || data[0] != VERSION || data[1] != PACKET {
        return Err("TUIC packet header is invalid".into());
    }
    let association = u16::from_be_bytes([data[2], data[3]]);
    let packet = u16::from_be_bytes([data[4], data[5]]);
    let fragment_total = data[6];
    let fragment_id = data[7];
    if fragment_total == 0 || fragment_id >= fragment_total {
        return Err("TUIC packet fragment index is invalid".into());
    }
    let payload_len = u16::from_be_bytes([data[8], data[9]]) as usize;
    let mut offset = 10;
    let destination = if fragment_id == 0 {
        let mut destination = decode_address(data, &mut offset)?;
        destination.network = zero_core::Network::Udp;
        Some(destination)
    } else {
        if data.get(offset) != Some(&0xff) {
            return Err("TUIC continuation fragment is missing its address marker".into());
        }
        offset += 1;
        None
    };
    let end = offset
        .checked_add(payload_len)
        .ok_or_else(|| "TUIC packet length overflow".to_string())?;
    let payload = data
        .get(offset..end)
        .ok_or_else(|| "TUIC packet payload is truncated".to_string())?
        .to_vec();
    if end != data.len() {
        return Err("TUIC packet has trailing bytes".into());
    }
    Ok(PacketFragment {
        association,
        packet,
        fragment_total,
        fragment_id,
        destination,
        payload,
    })
}

struct PacketReassembler {
    association: u16,
    packet: u16,
    fragment_total: u8,
    destination: Option<Destination>,
    received: Vec<Option<Vec<u8>>>,
    received_count: u8,
    payload_len: usize,
}

impl PacketReassembler {
    fn new(fragment: &PacketFragment) -> Self {
        Self {
            association: fragment.association,
            packet: fragment.packet,
            fragment_total: fragment.fragment_total,
            destination: None,
            received: vec![None; fragment.fragment_total as usize],
            received_count: 0,
            payload_len: 0,
        }
    }

    fn push(&mut self, fragment: PacketFragment) -> Result<Option<ReassembledPacket>, String> {
        if fragment.association != self.association || fragment.packet != self.packet {
            return Err("TUIC fragment identity changed during reassembly".into());
        }
        if fragment.fragment_total != self.fragment_total {
            return Err("TUIC fragment count changed during reassembly".into());
        }
        if fragment.fragment_id == 0 {
            if self.destination.is_some() {
                return Err("duplicate TUIC first fragment".into());
            }
            self.destination = fragment.destination;
        } else if fragment.destination.is_some() {
            return Err("TUIC continuation fragment contained an address".into());
        }
        let slot = &mut self.received[fragment.fragment_id as usize];
        if slot.is_some() {
            return Err("duplicate TUIC packet fragment".into());
        }
        self.payload_len = self
            .payload_len
            .checked_add(fragment.payload.len())
            .ok_or_else(|| "TUIC reassembled payload length overflow".to_string())?;
        if self.payload_len > u16::MAX as usize {
            return Err("TUIC reassembled payload is too large".into());
        }
        *slot = Some(fragment.payload);
        self.received_count += 1;
        if self.received_count != self.fragment_total {
            return Ok(None);
        }
        let destination = self
            .destination
            .take()
            .ok_or_else(|| "TUIC packet completed without a destination".to_string())?;
        let mut payload = Vec::with_capacity(self.payload_len);
        for fragment in &mut self.received {
            payload.extend_from_slice(
                fragment
                    .take()
                    .ok_or_else(|| "TUIC packet has a missing fragment".to_string())?
                    .as_slice(),
            );
        }
        Ok(Some((self.association, self.packet, destination, payload)))
    }
}

pub enum Accepted {
    Tcp {
        stream: BoxStream,
        destination: Destination,
        peer: SocketAddr,
    },
    Udp {
        connection: h3_quinn::quinn::Connection,
        association: u16,
        packet: u16,
        destination: Destination,
        payload: Vec<u8>,
        peer: SocketAddr,
    },
}

pub fn encode_packet(
    association: u16,
    packet: u16,
    destination: &Destination,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if destination.network != zero_core::Network::Udp {
        return Err("TUIC packet response requires a UDP destination".into());
    }
    if payload.len() > u16::MAX as usize {
        return Err("TUIC packet payload is too large".into());
    }
    let address = encode_address(destination)?;
    let mut output = BytesMut::with_capacity(10 + address.len() + payload.len());
    output.put_u8(VERSION);
    output.put_u8(PACKET);
    output.put_u16(association);
    output.put_u16(packet);
    output.put_u8(1);
    output.put_u8(0);
    output.put_u16(payload.len() as u16);
    output.extend_from_slice(&address);
    output.extend_from_slice(payload);
    Ok(output.to_vec())
}

/// Encode one TUIC PACKET message, splitting it at the negotiated QUIC
/// datagram size when necessary. Only the first fragment carries the address;
/// continuation fragments carry the protocol's 0xff address marker.
pub fn encode_packet_fragments(
    max_datagram: usize,
    association: u16,
    packet: u16,
    destination: &Destination,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    if destination.network != zero_core::Network::Udp {
        return Err("TUIC packet requires a UDP destination".into());
    }
    if payload.len() > u16::MAX as usize {
        return Err("TUIC packet payload is too large".into());
    }
    let address = encode_address(destination)?;
    let first_overhead = 10usize
        .checked_add(address.len())
        .ok_or_else(|| "TUIC packet header length overflow".to_string())?;
    let continuation_overhead = 11usize;
    if max_datagram < first_overhead || max_datagram < continuation_overhead {
        return Err("TUIC negotiated datagram size is too small for a packet".into());
    }
    let first_capacity = max_datagram - first_overhead;
    let continuation_capacity = max_datagram - continuation_overhead;
    let fragment_total = if payload.len() <= first_capacity {
        1usize
    } else {
        1 + (payload.len() - first_capacity).div_ceil(continuation_capacity)
    };
    if fragment_total > u8::MAX as usize {
        return Err("TUIC packet needs too many fragments".into());
    }
    let fragment_total = fragment_total as u8;
    let mut output = Vec::with_capacity(fragment_total as usize);
    let mut offset = 0usize;
    for fragment_id in 0..fragment_total {
        let capacity = if fragment_id == 0 {
            first_capacity
        } else {
            continuation_capacity
        };
        let fragment_len = (payload.len() - offset).min(capacity);
        let mut frame = BytesMut::with_capacity(
            if fragment_id == 0 {
                first_overhead
            } else {
                continuation_overhead
            } + fragment_len,
        );
        frame.put_u8(VERSION);
        frame.put_u8(PACKET);
        frame.put_u16(association);
        frame.put_u16(packet);
        frame.put_u8(fragment_total);
        frame.put_u8(fragment_id);
        frame.put_u16(fragment_len as u16);
        if fragment_id == 0 {
            frame.extend_from_slice(&address);
        } else {
            frame.put_u8(0xff);
        }
        frame.extend_from_slice(&payload[offset..offset + fragment_len]);
        output.push(frame.to_vec());
        offset += fragment_len;
    }
    Ok(output)
}

/// The pooled, authenticated connection to a TUIC server (see
/// [`crate::quic_pool`]). Authentication is a one-way command, sent once per
/// connection; every stream and packet after it rides the same connection.
async fn pooled(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    uuid: &[u8; 16],
    password: &str,
) -> Result<(String, std::sync::Arc<crate::quic_pool::Pooled>), String> {
    let mut secret = uuid.to_vec();
    secret.extend_from_slice(password.as_bytes());
    let key = crate::quic_pool::key("tuic", addrs, tls, &secret);
    let pooled = crate::quic_pool::get(&key, || async {
        let (endpoint, connection) = connect_quic(addrs, tls).await?;
        authenticate(&connection, uuid, password).await?;
        Ok((endpoint, connection))
    })
    .await?;
    Ok((key, pooled))
}

/// Open an authenticated TUIC TCP stream.
pub async fn connect(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    uuid: &[u8; 16],
    password: &str,
    destination: &Destination,
) -> Result<BoxStream, String> {
    if destination.network != zero_core::Network::Tcp {
        return Err("TUIC stream connect requires a TCP destination".into());
    }
    let mut opened = None;
    for attempt in 0..2 {
        let (key, pooled) = pooled(addrs, tls, uuid, password).await?;
        match pooled.connection.open_bi().await {
            Ok(pair) => {
                opened = Some((pooled.stream_guard(), pair));
                break;
            }
            Err(error) if attempt == 0 => {
                tracing::debug!(%error, "TUIC pooled connection is gone; dialling anew");
                crate::quic_pool::evict(&key, &pooled);
            }
            Err(error) => return Err(format!("TUIC CONNECT stream: {error}")),
        }
    }
    let (guard, (mut send, recv)) = opened.ok_or("TUIC CONNECT stream: no connection")?;
    let mut header = vec![VERSION, CONNECT];
    header.extend_from_slice(&encode_address(destination)?);
    send.write_all(&header)
        .await
        .map_err(|error| format!("TUIC CONNECT header: {error}"))?;
    let (app, worker) = duplex(128 * 1024);
    tokio::spawn(async move {
        crate::relay::bridge_quic_stream(worker, send, recv, "TUIC").await;
        // The connection stays in the pool for the next stream.
        drop(guard);
    });
    Ok(boxed(app))
}

/// Exchange one TUIC PACKET message, including protocol-level fragmentation
/// when the negotiated QUIC datagram size requires it.
pub async fn exchange_udp(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    uuid: &[u8; 16],
    password: &str,
    destination: &Destination,
    payload: &[u8],
) -> Result<(Destination, Vec<u8>), String> {
    if destination.network != zero_core::Network::Udp {
        return Err("TUIC packet exchange requires a UDP destination".into());
    }
    if payload.len() > u16::MAX as usize {
        return Err("TUIC packet payload is too large".into());
    }
    let mut last = String::new();
    for attempt in 0..2 {
        let (key, pooled) = pooled(addrs, tls, uuid, password).await?;
        match packet_on(&pooled, destination, payload).await {
            Ok(response) => return Ok(response),
            Err((error, retry)) => {
                if retry && attempt == 0 {
                    crate::quic_pool::evict(&key, &pooled);
                    last = error;
                    continue;
                }
                return Err(error);
            }
        }
    }
    Err(last)
}

/// The association a TUIC PACKET datagram belongs to.
fn packet_association(datagram: &[u8]) -> Option<u32> {
    if datagram.len() < 10 || datagram[0] != VERSION || datagram[1] != PACKET {
        return None;
    }
    Some(u32::from(u16::from_be_bytes([datagram[2], datagram[3]])))
}

/// One PACKET exchange on a pooled connection. The error says whether a
/// fresh connection is worth trying (the connection itself failed).
async fn packet_on(
    pooled: &std::sync::Arc<crate::quic_pool::Pooled>,
    destination: &Destination,
    payload: &[u8],
) -> Result<(Destination, Vec<u8>), (String, bool)> {
    let connection = &pooled.connection;
    let max_datagram = connection
        .max_datagram_size()
        .ok_or_else(|| ("TUIC peer does not support QUIC datagrams".to_string(), false))?;
    let association_id: u16 = rand::random();
    let packet_id = rand::random();
    let packets = encode_packet_fragments(max_datagram, association_id, packet_id, destination, payload)
        .map_err(|error| (error, false))?;
    let mut registration = pooled.register(u32::from(association_id), packet_association);
    for packet in packets {
        connection
            .send_datagram(bytes::Bytes::from(packet))
            .map_err(|error| (format!("TUIC PACKET send: {error}"), true))?;
    }
    timeout(Duration::from_secs(5), async {
        let mut reassembler: Option<PacketReassembler> = None;
        while let Some(data) = registration.receiver.recv().await {
            let Ok(fragment) = decode_packet_fragment(&data) else { continue };
            if fragment.association != association_id {
                continue;
            }
            let assembler = match &mut reassembler {
                // Fragments of one response share its packet id; a fragment
                // of another response to this association waits its turn.
                Some(existing) if existing.packet != fragment.packet => continue,
                Some(existing) => existing,
                None => reassembler.insert(PacketReassembler::new(&fragment)),
            };
            match assembler.push(fragment) {
                Ok(Some((_, _, address, payload))) => return Ok((address, payload)),
                Ok(None) => {}
                Err(error) => return Err((error, false)),
            }
        }
        Err(("TUIC connection closed before the PACKET response".to_string(), true))
    })
    .await
    .map_err(|_| ("TUIC PACKET response timed out".to_string(), false))?
}

/// Client keep-alive, as in the TUIC reference client's default heartbeat.
const CLIENT_KEEP_ALIVE: Duration = Duration::from_secs(10);
/// Client idle timeout.
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Bound on the QUIC handshake plus the TUIC authentication of a connection.
const SERVER_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on reading one CONNECT header once its stream is open.
const SERVER_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Accepted streams and datagrams queued for the runtime.
const ACCEPT_QUEUE: usize = 64;
/// How long a partly received fragmented PACKET is kept.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);
/// Fragmented PACKETs reassembled concurrently per connection.
const MAX_REASSEMBLIES: usize = 64;
/// Largest command accepted on a unidirectional stream after authentication.
const MAX_UNI_COMMAND: usize = 64 * 1024;

/// Accepts TUIC connections and yields every CONNECT stream and PACKET they
/// carry.
///
/// Each QUIC connection is handshaken, authenticated and served on its own
/// task. The previous free `accept` function did all of that inline and only
/// ever took the *first* request of a connection: one client that completed
/// the handshake and then went quiet stalled the whole inbound, and a TUIC
/// client multiplexing requests over one connection (the protocol's normal
/// mode) had all but the first ignored.
pub struct Acceptor {
    endpoint: h3_quinn::quinn::Endpoint,
    accepted: tokio::sync::mpsc::Receiver<Result<Accepted, String>>,
    sender: tokio::sync::mpsc::Sender<Result<Accepted, String>>,
}

impl Acceptor {
    pub fn new(endpoint: h3_quinn::quinn::Endpoint) -> Self {
        let (sender, accepted) = tokio::sync::mpsc::channel(ACCEPT_QUEUE);
        Self {
            endpoint,
            accepted,
            sender,
        }
    }

    /// Wait for the next CONNECT stream or PACKET. `Err` reports one rejected
    /// connection or request and is not fatal; `Ok(None)` means the endpoint
    /// closed. The credentials apply to connections accepted from this call
    /// on.
    pub async fn accept(
        &mut self,
        uuid: &[u8; 16],
        password: &str,
    ) -> Result<Option<Accepted>, String> {
        let credentials: Arc<([u8; 16], Box<str>)> = Arc::new((*uuid, password.into()));
        loop {
            tokio::select! {
                biased;
                item = self.accepted.recv() => {
                    return match item {
                        Some(item) => item.map(Some),
                        None => Ok(None),
                    };
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return Ok(None);
                    };
                    tokio::spawn(serve_connection(
                        incoming,
                        Arc::clone(&credentials),
                        self.sender.clone(),
                    ));
                }
            }
        }
    }
}

async fn serve_connection(
    incoming: h3_quinn::quinn::Incoming,
    credentials: Arc<([u8; 16], Box<str>)>,
    out: tokio::sync::mpsc::Sender<Result<Accepted, String>>,
) {
    let authenticated = timeout(SERVER_AUTH_TIMEOUT, async {
        let connection = incoming
            .await
            .map_err(|error| format!("TUIC QUIC handshake: {error}"))?;
        authenticate_server(&connection, &credentials.0, &credentials.1).await?;
        Ok::<_, String>(connection)
    })
    .await
    .unwrap_or_else(|_| Err("TUIC handshake or authentication timed out".into()));
    let connection = match authenticated {
        Ok(connection) => connection,
        Err(error) => {
            let _ = out.send(Err(error)).await;
            return;
        }
    };
    let peer = connection.remote_address();
    let mut reassembly: std::collections::HashMap<(u16, u16), (PacketReassembler, Instant)> =
        std::collections::HashMap::new();
    loop {
        tokio::select! {
            result = connection.accept_bi() => {
                let Ok((send, recv)) = result else {
                    return;
                };
                let out = out.clone();
                tokio::spawn(async move {
                    let accepted =
                        timeout(SERVER_REQUEST_TIMEOUT, accept_connect_stream(send, recv, peer))
                            .await
                            .unwrap_or_else(|_| Err("TUIC CONNECT header timed out".into()));
                    let _ = out.send(accepted).await;
                });
            }
            result = connection.accept_uni() => {
                let Ok(mut stream) = result else {
                    return;
                };
                // Post-authentication uni streams carry commands this carrier
                // does not act on (DISSOCIATE, QUIC-mode packets). They must
                // still be consumed, or the client's stream credit runs out.
                tokio::spawn(async move {
                    let _ = timeout(SERVER_REQUEST_TIMEOUT, stream.read_to_end(MAX_UNI_COMMAND)).await;
                });
            }
            result = connection.read_datagram() => {
                let Ok(data) = result else {
                    return;
                };
                let packet = match receive_packet(&data, &mut reassembly) {
                    Ok(Some(packet)) => packet,
                    Ok(None) => continue,
                    Err(error) => {
                        tracing::debug!(%error, "TUIC datagram discarded");
                        continue;
                    }
                };
                let (association, packet, destination, payload) = packet;
                let accepted = Accepted::Udp {
                    connection: connection.clone(),
                    association,
                    packet,
                    destination,
                    payload,
                    peer,
                };
                if out.send(Ok(accepted)).await.is_err() {
                    return;
                }
            }
            () = out.closed() => {
                connection.close(0u32.into(), b"server stopped");
                return;
            }
        }
    }
}

/// Feed one datagram into the connection's reassembly state. Returns a
/// complete packet when this datagram finished one; heartbeats are consumed.
fn receive_packet(
    data: &[u8],
    reassembly: &mut std::collections::HashMap<(u16, u16), (PacketReassembler, Instant)>,
) -> Result<Option<ReassembledPacket>, String> {
    if data.len() >= 2 && data[0] == VERSION && data[1] == HEARTBEAT {
        return Ok(None);
    }
    let fragment = decode_packet_fragment(data)?;
    let key = (fragment.association, fragment.packet);
    if fragment.fragment_total == 1 {
        let mut single = PacketReassembler::new(&fragment);
        return single.push(fragment);
    }
    let now = Instant::now();
    reassembly.retain(|_, (_, started)| now.duration_since(*started) < REASSEMBLY_TIMEOUT);
    if !reassembly.contains_key(&key) && reassembly.len() >= MAX_REASSEMBLIES {
        return Err("too many TUIC packets are being reassembled".into());
    }
    let (reassembler, _) = reassembly
        .entry(key)
        .or_insert_with(|| (PacketReassembler::new(&fragment), now));
    match reassembler.push(fragment) {
        Ok(Some(packet)) => {
            reassembly.remove(&key);
            Ok(Some(packet))
        }
        Ok(None) => Ok(None),
        Err(error) => {
            reassembly.remove(&key);
            Err(error)
        }
    }
}

/// Read one CONNECT header from a freshly accepted stream.
async fn accept_connect_stream(
    send: h3_quinn::quinn::SendStream,
    mut recv: h3_quinn::quinn::RecvStream,
    peer: SocketAddr,
) -> Result<Accepted, String> {
    let mut command = [0u8; 2];
    recv.read_exact(&mut command)
        .await
        .map_err(|error| format!("TUIC CONNECT command: {error}"))?;
    if command != [VERSION, CONNECT] {
        return Err("TUIC CONNECT command is invalid".into());
    }
    let destination = read_address_stream(&mut recv).await?;
    let (app, worker) = duplex(128 * 1024);
    // Other requests share this connection; the bridge must not close it.
    tokio::spawn(crate::relay::bridge_quic_stream(
        worker,
        send,
        recv,
        "TUIC server",
    ));
    Ok(Accepted::Tcp {
        stream: boxed(app),
        destination,
        peer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_framing_roundtrips_domain_and_ipv6() {
        let destination = Destination::udp(zero_core::Address::domain("dns.example"), 53);
        let encoded = encode_address(&destination).unwrap();
        let mut offset = 0;
        assert_eq!(decode_address(&encoded, &mut offset).unwrap(), destination);

        let destination =
            Destination::udp(zero_core::Address::Ip("2001:db8::1".parse().unwrap()), 443);
        let encoded = encode_address(&destination).unwrap();
        let mut offset = 0;
        assert_eq!(decode_address(&encoded, &mut offset).unwrap(), destination);
    }

    #[test]
    fn address_framing_rejects_truncation() {
        let mut offset = 0;
        assert!(decode_address(&[0, 3, b'a'], &mut offset).is_err());
    }

    #[test]
    fn packet_framing_roundtrips_identity_and_payload() {
        let destination = Destination::udp(zero_core::Address::domain("dns.example"), 53);
        let encoded = encode_packet(7, 9, &destination, b"query").unwrap();
        let fragment = decode_packet_fragment(&encoded).unwrap();
        assert_eq!((fragment.association, fragment.packet), (7, 9));
        assert_eq!(fragment.destination, Some(destination));
        assert_eq!(fragment.payload, b"query");
    }

    #[test]
    fn fragmented_packets_reassemble_out_of_order() {
        let destination = Destination::udp(zero_core::Address::domain("dns.example"), 53);
        let payload = b"a deliberately fragmented TUIC datagram";
        let frames = encode_packet_fragments(28, 7, 9, &destination, payload).unwrap();
        assert!(frames.len() > 1);
        assert_eq!(frames[0][6] as usize, frames.len());
        assert_eq!(frames[0][7], 0);
        assert_eq!(frames[1][10], 0xff);

        let first = decode_packet_fragment(&frames[0]).unwrap();
        let mut reassembler = PacketReassembler::new(&first);
        assert!(reassembler.push(first).unwrap().is_none());
        for frame in frames.iter().skip(1).rev() {
            let fragment = decode_packet_fragment(frame).unwrap();
            if let Some((association, packet, decoded, actual)) =
                reassembler.push(fragment).unwrap()
            {
                assert_eq!((association, packet), (7, 9));
                assert_eq!(decoded, destination);
                assert_eq!(actual, payload);
            }
        }
        assert_eq!(reassembler.received_count, reassembler.fragment_total);
    }

    #[test]
    fn server_reassembly_is_keyed_bounded_and_skips_heartbeats() {
        let destination = Destination::udp(zero_core::Address::domain("dns.example"), 53);
        let payload = b"a deliberately fragmented TUIC datagram";
        let frames = encode_packet_fragments(28, 7, 9, &destination, payload).unwrap();
        let other =
            encode_packet_fragments(28, 7, 10, &destination, b"second packet here").unwrap();
        let mut state = std::collections::HashMap::new();
        assert!(receive_packet(&[VERSION, HEARTBEAT, 0, 1], &mut state)
            .unwrap()
            .is_none());
        // Interleave two packets; each completes independently.
        let mut done = Vec::new();
        for (a, b) in frames.iter().zip(other.iter()) {
            done.extend(receive_packet(a, &mut state).unwrap());
            done.extend(receive_packet(b, &mut state).unwrap());
        }
        for frame in frames.iter().skip(other.len()) {
            done.extend(receive_packet(frame, &mut state).unwrap());
        }
        for frame in other.iter().skip(frames.len()) {
            done.extend(receive_packet(frame, &mut state).unwrap());
        }
        assert_eq!(done.len(), 2);
        assert!(state.is_empty(), "completed packets must be released");
        let first = done.iter().find(|p| p.1 == 9).unwrap();
        assert_eq!(first.3, payload);

        // Starting fragments of many packets cannot grow the state unbounded.
        for id in 0..(MAX_REASSEMBLIES as u16 + 10) {
            let frames = encode_packet_fragments(28, 1, id, &destination, payload).unwrap();
            let _ = receive_packet(&frames[0], &mut state);
        }
        assert!(state.len() <= MAX_REASSEMBLIES);
    }

    #[test]
    fn continuation_fragment_requires_address_marker() {
        let destination = Destination::udp(zero_core::Address::domain("dns.example"), 53);
        let mut frames = encode_packet_fragments(28, 7, 9, &destination, b"fragment me").unwrap();
        assert!(frames.len() > 1);
        frames[1][10] = 0;
        assert!(decode_packet_fragment(&frames[1]).is_err());
    }
}
