//! AmneziaWG 2.x packet obfuscation.
//!
//! This module owns the wire transformation around a normal WireGuard packet:
//! bounded junk datagrams before a handshake, an S-prefix before each packet
//! type, and H-magic values replacing WireGuard's four-byte little-endian
//! type. The cryptographic WireGuard engine remains a separate carrier
//! boundary; this layer never treats random junk as an authenticated packet.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use rand::{Rng, SeedableRng};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const HANDSHAKE_INIT: u32 = 1;
const HANDSHAKE_RESPONSE: u32 = 2;
const COOKIE_REPLY: u32 = 3;
const TRANSPORT_DATA: u32 = 4;
const MAX_JUNK_COUNT: u16 = 64;
const MAX_PADDING: u16 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeU16 {
    pub min: u16,
    pub max: u16,
}

impl RangeU16 {
    pub const fn fixed(value: u16) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    fn validate(self, name: &str) -> Result<(), String> {
        if self.min > self.max {
            return Err(format!("AmneziaWG {name} range is inverted"));
        }
        Ok(())
    }

    fn choose(self, rng: &mut impl Rng) -> u16 {
        if self.min == self.max {
            self.min
        } else {
            rng.gen_range(self.min..=self.max)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderRange {
    pub min: u32,
    pub max: u32,
}

impl HeaderRange {
    pub const fn fixed(value: u32) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    fn contains(self, value: u32) -> bool {
        self.min <= value && value <= self.max
    }

    fn validate(self, name: &str) -> Result<(), String> {
        if self.min > self.max {
            return Err(format!("AmneziaWG {name} range is inverted"));
        }
        Ok(())
    }

    fn choose(self, rng: &mut impl Rng) -> u32 {
        if self.min == self.max {
            self.min
        } else {
            rng.gen_range(self.min..=self.max)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmneziaParams {
    pub junk_count: u16,
    pub junk_size: RangeU16,
    pub init_padding: RangeU16,
    pub response_padding: RangeU16,
    pub cookie_padding: RangeU16,
    pub transport_padding: RangeU16,
    pub init_header: HeaderRange,
    pub response_header: HeaderRange,
    pub cookie_header: HeaderRange,
    pub transport_header: HeaderRange,
}

impl Default for AmneziaParams {
    fn default() -> Self {
        Self {
            junk_count: 0,
            junk_size: RangeU16::fixed(0),
            init_padding: RangeU16::fixed(0),
            response_padding: RangeU16::fixed(0),
            cookie_padding: RangeU16::fixed(0),
            transport_padding: RangeU16::fixed(0),
            init_header: HeaderRange::fixed(HANDSHAKE_INIT),
            response_header: HeaderRange::fixed(HANDSHAKE_RESPONSE),
            cookie_header: HeaderRange::fixed(COOKIE_REPLY),
            transport_header: HeaderRange::fixed(TRANSPORT_DATA),
        }
    }
}

impl AmneziaParams {
    pub fn validate(self) -> Result<(), String> {
        if self.junk_count > MAX_JUNK_COUNT {
            return Err(format!("AmneziaWG junk count exceeds {MAX_JUNK_COUNT}"));
        }
        self.junk_size.validate("junk size")?;
        if self.junk_size.max > MAX_PADDING {
            return Err(format!("AmneziaWG junk size exceeds {MAX_PADDING} bytes"));
        }
        for (name, range) in [
            ("S1", self.init_padding),
            ("S2", self.response_padding),
            ("S3", self.cookie_padding),
            ("S4", self.transport_padding),
        ] {
            range.validate(name)?;
            if range.max > MAX_PADDING {
                return Err(format!("AmneziaWG {name} exceeds {MAX_PADDING} bytes"));
            }
        }
        for (name, range) in [
            ("H1", self.init_header),
            ("H2", self.response_header),
            ("H3", self.cookie_header),
            ("H4", self.transport_header),
        ] {
            range.validate(name)?;
        }
        let headers = [
            ("H1", self.init_header),
            ("H2", self.response_header),
            ("H3", self.cookie_header),
            ("H4", self.transport_header),
        ];
        for (index, (left_name, left)) in headers.iter().enumerate() {
            for (right_name, right) in headers.iter().skip(index + 1) {
                if left.min <= right.max && right.min <= left.max {
                    return Err(format!(
                        "AmneziaWG header ranges {left_name} and {right_name} overlap"
                    ));
                }
            }
        }
        Ok(())
    }

    fn packet_shape(self, kind: PacketKind) -> (RangeU16, HeaderRange) {
        match kind {
            PacketKind::HandshakeInit => (self.init_padding, self.init_header),
            PacketKind::HandshakeResponse => (self.response_padding, self.response_header),
            PacketKind::CookieReply => (self.cookie_padding, self.cookie_header),
            PacketKind::TransportData => (self.transport_padding, self.transport_header),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    HandshakeInit,
    HandshakeResponse,
    CookieReply,
    TransportData,
}

impl PacketKind {
    fn standard_type(self) -> u32 {
        match self {
            Self::HandshakeInit => HANDSHAKE_INIT,
            Self::HandshakeResponse => HANDSHAKE_RESPONSE,
            Self::CookieReply => COOKIE_REPLY,
            Self::TransportData => TRANSPORT_DATA,
        }
    }

    fn from_standard_type(value: u32) -> Option<Self> {
        Some(match value {
            HANDSHAKE_INIT => Self::HandshakeInit,
            HANDSHAKE_RESPONSE => Self::HandshakeResponse,
            COOKIE_REPLY => Self::CookieReply,
            TRANSPORT_DATA => Self::TransportData,
            _ => return None,
        })
    }
}

/// Return the standard WireGuard packet kind from its unmodified type word.
pub fn packet_kind(packet: &[u8]) -> Option<PacketKind> {
    let header = packet.get(..4)?.try_into().ok().map(u32::from_le_bytes)?;
    PacketKind::from_standard_type(header)
}

/// Generate the bounded junk datagrams sent before a handshake initiation.
pub fn junk_packets(params: AmneziaParams, rng: &mut impl Rng) -> Result<Vec<Vec<u8>>, String> {
    params.validate()?;
    let mut packets = Vec::with_capacity(params.junk_count as usize);
    for _ in 0..params.junk_count {
        let length = params.junk_size.choose(rng) as usize;
        let mut packet = vec![0u8; length];
        rng.fill(packet.as_mut_slice());
        packets.push(packet);
    }
    Ok(packets)
}

/// Apply the AmneziaWG prefix and dynamic header to one authenticated
/// WireGuard packet produced by the underlying tunnel engine.
pub fn encode_packet(
    params: AmneziaParams,
    packet: &[u8],
    rng: &mut impl Rng,
) -> Result<Vec<u8>, String> {
    params.validate()?;
    let kind = packet_kind(packet).ok_or_else(|| "unknown WireGuard packet type".to_string())?;
    let (padding, header) = params.packet_shape(kind);
    let padding = padding.choose(rng) as usize;
    let mut output = vec![0u8; padding + packet.len()];
    rng.fill(&mut output[..padding]);
    output[padding..padding + 4].copy_from_slice(&header.choose(rng).to_le_bytes());
    output[padding + 4..].copy_from_slice(&packet[4..]);
    Ok(output)
}

/// Remove an AmneziaWG prefix and restore the standard WireGuard type word.
/// Random junk returns `Ok(None)` so callers can ignore it without feeding it
/// into the authenticated tunnel engine.
pub fn decode_packet(params: AmneziaParams, packet: &[u8]) -> Result<Option<Vec<u8>>, String> {
    params.validate()?;
    for (kind, (padding, header)) in [
        (
            PacketKind::HandshakeInit,
            params.packet_shape(PacketKind::HandshakeInit),
        ),
        (
            PacketKind::HandshakeResponse,
            params.packet_shape(PacketKind::HandshakeResponse),
        ),
        (
            PacketKind::CookieReply,
            params.packet_shape(PacketKind::CookieReply),
        ),
        (
            PacketKind::TransportData,
            params.packet_shape(PacketKind::TransportData),
        ),
    ] {
        for padding in padding.min as usize..=padding.max as usize {
            if padding > packet.len().saturating_sub(4) {
                continue;
            }
            let value = u32::from_le_bytes(
                packet[padding..padding + 4]
                    .try_into()
                    .expect("four-byte header checked above"),
            );
            if header.contains(value) {
                let mut output = Vec::with_capacity(packet.len() - padding);
                output.extend_from_slice(&kind.standard_type().to_le_bytes());
                output.extend_from_slice(&packet[padding + 4..]);
                return Ok(Some(output));
            }
        }
    }
    Ok(None)
}

/// The minimum client-side parameters needed to carry one IP UDP exchange
/// through a WireGuard peer. The caller supplies the resolved peer endpoint;
/// this keeps DNS and route policy outside the protocol layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireGuardParams {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub tunnel_address: IpAddr,
    pub persistent_keepalive: Option<u16>,
    pub obfuscation: AmneziaParams,
}

/// A persistent userspace WireGuard session.
///
/// The session owns the outer UDP socket and boringtun state, so multiple
/// logical UDP datagrams reuse the authenticated peer session instead of
/// performing a new handshake for every packet. Calls must be serialized by
/// the caller; the runtime does that with one async mutex per outbound.
pub struct AmneziaSession {
    socket: UdpSocket,
    tunnel: Tunn,
    endpoint: SocketAddr,
    params: WireGuardParams,
    rng: rand::rngs::StdRng,
    network_buffer: Vec<u8>,
    datagram_buffer: Vec<u8>,
    clear_buffer: Vec<u8>,
    handshaken: bool,
}

impl AmneziaSession {
    pub async fn connect(
        peer_endpoints: &[SocketAddr],
        params: WireGuardParams,
    ) -> Result<Self, String> {
        if peer_endpoints.is_empty() {
            return Err("AmneziaWG has no peer endpoint".into());
        }
        params.obfuscation.validate()?;
        let endpoint = peer_endpoints[0];
        if endpoint.is_ipv4() != params.tunnel_address.is_ipv4() {
            return Err("AmneziaWG peer and tunnel address families differ".into());
        }
        let bind_address: std::net::SocketAddr = if endpoint.is_ipv4() {
            "0.0.0.0:0".parse().expect("a literal bind address")
        } else {
            "[::]:0".parse().expect("a literal bind address")
        };
        // The last-resort transport is the one that most needs to reach the
        // real network rather than the tunnel it is replacing.
        let std_socket = zero_core::platform::bind_protected_udp(bind_address)
            .map_err(|error| format!("AmneziaWG UDP bind: {error}"))?;
        std_socket
            .set_nonblocking(true)
            .map_err(|error| format!("AmneziaWG UDP bind: {error}"))?;
        let socket = UdpSocket::from_std(std_socket)
            .map_err(|error| format!("AmneziaWG UDP bind: {error}"))?;
        let private = boringtun::x25519::StaticSecret::from(params.private_key);
        let peer = boringtun::x25519::PublicKey::from(params.peer_public_key);
        let tunnel = Tunn::new(
            private,
            peer,
            params.preshared_key,
            params.persistent_keepalive,
            rand::random(),
            None,
        );
        Ok(Self {
            socket,
            tunnel,
            endpoint,
            params,
            rng: rand::rngs::StdRng::from_entropy(),
            network_buffer: vec![0u8; 65_535],
            datagram_buffer: vec![0u8; 65_535],
            clear_buffer: vec![0u8; 65_535],
            handshaken: false,
        })
    }

    pub async fn exchange(
        &mut self,
        destination: SocketAddr,
        payload: &[u8],
    ) -> Result<(SocketAddr, Vec<u8>), String> {
        if destination.is_ipv4() != self.params.tunnel_address.is_ipv4() {
            return Err("AmneziaWG tunnel and destination address families differ".into());
        }
        if payload.len() > u16::MAX as usize - 48 {
            return Err("AmneziaWG UDP payload is too large".into());
        }
        let source_port = self
            .socket
            .local_addr()
            .map_err(|error| format!("AmneziaWG local address: {error}"))?
            .port();
        let inner = build_udp_packet(
            self.params.tunnel_address,
            destination.ip(),
            source_port,
            destination.port(),
            payload,
        )?;
        match self.tunnel.encapsulate(&inner, &mut self.network_buffer) {
            TunnResult::WriteToNetwork(packet) => {
                send_wireguard_packet(
                    &self.socket,
                    self.endpoint,
                    self.params.obfuscation,
                    packet,
                    &mut self.rng,
                )
                .await?;
            }
            TunnResult::Err(error) => return Err(format!("AmneziaWG handshake: {error:?}")),
            TunnResult::Done => return Err("AmneziaWG did not produce a packet".into()),
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                return Err("AmneziaWG produced tunnel data before network output".into())
            }
        }

        let result = timeout(Duration::from_secs(8), async {
            loop {
                let (length, source) = self
                    .socket
                    .recv_from(&mut self.datagram_buffer)
                    .await
                    .map_err(|error| format!("AmneziaWG receive: {error}"))?;
                if source != self.endpoint {
                    continue;
                }
                let Some(normalized) =
                    decode_packet(self.params.obfuscation, &self.datagram_buffer[..length])?
                else {
                    continue;
                };
                let mut state =
                    self.tunnel
                        .decapsulate(Some(source.ip()), &normalized, &mut self.clear_buffer);
                loop {
                    match state {
                        TunnResult::WriteToNetwork(packet) => {
                            send_wireguard_packet(
                                &self.socket,
                                self.endpoint,
                                self.params.obfuscation,
                                packet,
                                &mut self.rng,
                            )
                            .await?;
                            state = self.tunnel.decapsulate(None, &[], &mut self.clear_buffer);
                        }
                        TunnResult::WriteToTunnelV4(packet, _) => {
                            return parse_ipv4_udp_packet(packet);
                        }
                        TunnResult::WriteToTunnelV6(packet, _) => {
                            return parse_ipv6_udp_packet(packet);
                        }
                        TunnResult::Done => break,
                        TunnResult::Err(error) => {
                            return Err(format!("AmneziaWG datagram authentication: {error:?}"));
                        }
                    }
                }
            }
        })
        .await
        .map_err(|_| "AmneziaWG UDP response timed out".to_string())??;
        self.handshaken = true;
        Ok(result)
    }

    pub fn is_handshaken(&self) -> bool {
        self.handshaken
    }
}

/// Carry one UDP datagram through a temporary WireGuard/AmneziaWG session.
/// Callers handling multiple datagrams should keep an [`AmneziaSession`] and
/// use its `exchange` method instead.
pub async fn exchange_udp(
    peer_endpoints: &[SocketAddr],
    params: &WireGuardParams,
    destination: SocketAddr,
    payload: &[u8],
) -> Result<(SocketAddr, Vec<u8>), String> {
    let mut session = AmneziaSession::connect(peer_endpoints, *params).await?;
    session.exchange(destination, payload).await
}

async fn send_wireguard_packet(
    socket: &UdpSocket,
    endpoint: SocketAddr,
    params: AmneziaParams,
    packet: &[u8],
    rng: &mut impl Rng,
) -> Result<(), String> {
    if packet_kind(packet) == Some(PacketKind::HandshakeInit) {
        for junk in junk_packets(params, rng)? {
            socket
                .send_to(&junk, endpoint)
                .await
                .map_err(|error| format!("AmneziaWG junk packet: {error}"))?;
        }
    }
    let encoded = encode_packet(params, packet, rng)?;
    socket
        .send_to(&encoded, endpoint)
        .await
        .map_err(|error| format!("AmneziaWG packet: {error}"))?;
    Ok(())
}

fn build_udp_packet(
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let udp_len = 8usize
        .checked_add(payload.len())
        .ok_or_else(|| "AmneziaWG UDP length overflow".to_string())?;
    if udp_len > u16::MAX as usize {
        return Err("AmneziaWG UDP packet is too large".into());
    }
    let mut udp = vec![0u8; udp_len];
    udp[..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let checksum = udp_checksum(source, destination, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let total_len = 20usize + udp_len;
            if total_len > u16::MAX as usize {
                return Err("AmneziaWG IPv4 packet is too large".into());
            }
            let mut packet = vec![0u8; total_len];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&destination.octets());
            let checksum = internet_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            packet[20..].copy_from_slice(&udp);
            Ok(packet)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let mut packet = vec![0u8; 40 + udp_len];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            packet[6] = 17;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&destination.octets());
            packet[40..].copy_from_slice(&udp);
            Ok(packet)
        }
        _ => Err("AmneziaWG tunnel and destination address families differ".into()),
    }
}

fn parse_ipv4_udp_packet(packet: &[u8]) -> Result<(SocketAddr, Vec<u8>), String> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return Err("AmneziaWG returned a non-UDP IPv4 packet".into());
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if ihl < 20 || total < ihl + 8 || total > packet.len() {
        return Err("AmneziaWG returned a truncated IPv4 UDP packet".into());
    }
    let udp = &packet[ihl..total];
    let length = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if length < 8 || length > udp.len() {
        return Err("AmneziaWG returned an invalid UDP length".into());
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let port = u16::from_be_bytes([udp[0], udp[1]]);
    Ok((
        SocketAddr::new(IpAddr::V4(source), port),
        udp[8..length].to_vec(),
    ))
}

fn parse_ipv6_udp_packet(packet: &[u8]) -> Result<(SocketAddr, Vec<u8>), String> {
    if packet.len() < 48 || packet[0] >> 4 != 6 || packet[6] != 17 {
        return Err("AmneziaWG returned a non-UDP IPv6 packet".into());
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if payload_len < 8 || 40 + payload_len > packet.len() {
        return Err("AmneziaWG returned a truncated IPv6 UDP packet".into());
    }
    let udp = &packet[40..40 + payload_len];
    let length = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if length < 8 || length > udp.len() {
        return Err("AmneziaWG returned an invalid IPv6 UDP length".into());
    }
    let mut source = [0u8; 16];
    source.copy_from_slice(&packet[8..24]);
    let port = u16::from_be_bytes([udp[0], udp[1]]);
    Ok((
        SocketAddr::new(IpAddr::V6(source.into()), port),
        udp[8..length].to_vec(),
    ))
}

fn udp_checksum(source: IpAddr, destination: IpAddr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(match (source, destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => 12 + udp.len(),
        (IpAddr::V6(_), IpAddr::V6(_)) => 40 + udp.len(),
        _ => return 0,
    });
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&(udp.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 17]);
        }
        _ => unreachable!(),
    }
    pseudo.extend_from_slice(udp);
    let checksum = internet_checksum(&pseudo);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
        while sum > u16::MAX as u32 {
            sum = (sum & u16::MAX as u32) + (sum >> 16);
        }
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> AmneziaParams {
        AmneziaParams {
            junk_count: 5,
            junk_size: RangeU16 { min: 50, max: 100 },
            init_padding: RangeU16::fixed(7),
            response_padding: RangeU16::fixed(8),
            cookie_padding: RangeU16::fixed(9),
            transport_padding: RangeU16::fixed(10),
            init_header: HeaderRange::fixed(101),
            response_header: HeaderRange::fixed(202),
            cookie_header: HeaderRange::fixed(303),
            transport_header: HeaderRange::fixed(404),
        }
    }

    #[test]
    fn every_packet_kind_roundtrips_with_prefix_and_magic() {
        let params = params();
        let mut rng = rand::thread_rng();
        for kind in [
            PacketKind::HandshakeInit,
            PacketKind::HandshakeResponse,
            PacketKind::CookieReply,
            PacketKind::TransportData,
        ] {
            let mut packet = kind.standard_type().to_le_bytes().to_vec();
            packet.extend_from_slice(b"authenticated payload");
            let encoded = encode_packet(params, &packet, &mut rng).unwrap();
            assert_eq!(
                u32::from_le_bytes(
                    encoded[params.packet_shape(kind).0.min as usize..][..4]
                        .try_into()
                        .unwrap()
                ),
                params.packet_shape(kind).1.min
            );
            assert_eq!(decode_packet(params, &encoded).unwrap(), Some(packet));
        }
    }

    #[test]
    fn junk_packets_are_bounded_and_randomly_filled() {
        let mut rng = rand::thread_rng();
        let packets = junk_packets(params(), &mut rng).unwrap();
        assert_eq!(packets.len(), 5);
        assert!(packets
            .iter()
            .all(|packet| (50..=100).contains(&packet.len())));
    }

    #[test]
    fn invalid_or_ambiguous_parameters_fail_closed() {
        let mut invalid = params();
        invalid.response_header = HeaderRange::fixed(101);
        assert!(invalid.validate().is_err());
        let mut invalid = params();
        invalid.junk_size = RangeU16 { min: 101, max: 50 };
        assert!(junk_packets(invalid, &mut rand::thread_rng()).is_err());
        assert_eq!(decode_packet(params(), &[1, 2, 3, 4, 5]).unwrap(), None);
    }

    #[test]
    fn ipv6_udp_inner_packet_roundtrips() {
        let source = "fd00::2".parse::<IpAddr>().unwrap();
        let destination = "2001:db8::53".parse::<IpAddr>().unwrap();
        let packet = build_udp_packet(source, destination, 40123, 53, b"hello").unwrap();
        let (returned, payload) = parse_ipv6_udp_packet(&packet).unwrap();
        assert_eq!(returned, SocketAddr::new(source, 40123));
        assert_eq!(payload, b"hello");
    }
}
