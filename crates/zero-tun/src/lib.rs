//! Platform-isolated TUN packet I/O.
//!
//! This crate owns only the device boundary and packet framing. TCP/UDP
//! translation belongs above it, so the same packet pump can later be driven
//! by Android/iOS file descriptors without importing Linux ioctls into the
//! runtime.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use netcmd::NetCommand;
pub use netstack_smoltcp::UdpSocket;
use thiserror::Error;
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
use zero_core::Network;

pub mod inherited;
pub mod netcmd;
mod platform;
pub mod privilege;
mod wintun;

pub use privilege::{check_tun_permissions, PrivilegeStatus};

const MAX_PACKET: usize = 65_535;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("TUN device name is invalid")]
    InvalidName,
    #[error("opening TUN device: {0}")]
    Open(#[source] io::Error),
    #[error("configuring TUN device: {0}")]
    Configure(#[source] io::Error),
    #[error("configuring TUN network: {0}")]
    Network(#[source] io::Error),
    #[error("invalid TUN CIDR: {0}")]
    InvalidCidr(String),
    #[error("TUN I/O: {0}")]
    Io(#[source] io::Error),
    #[error("malformed or unsupported IP packet: {0}")]
    MalformedPacket(&'static str),
}

/// Transport metadata extracted from one IP packet read from the TUN device.
/// The payload is the transport payload, excluding the IP and TCP/UDP headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPacket {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub network: Network,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: Vec<u8>,
}

/// Parse an IPv4 or IPv6 TCP/UDP packet without resolving or rewriting it.
/// Fragmented packets are rejected until a reassembly layer is present;
/// supported IPv6 extension headers are walked so ordinary packets carrying
/// hop-by-hop, routing, destination-options, or AH headers are not discarded.
pub fn parse_ip_packet(packet: &[u8]) -> Result<IpPacket, TunError> {
    let version = packet.first().map(|byte| byte >> 4);
    let (source, destination, protocol, transport) = match version {
        Some(4) => {
            if packet.len() < 20 {
                return Err(TunError::MalformedPacket("truncated IPv4 header"));
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            let fragments = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff;
            if ihl < 20 || ihl > packet.len() || total < ihl || total > packet.len() {
                return Err(TunError::MalformedPacket("invalid IPv4 length"));
            }
            if fragments != 0 || packet[6] & 0x20 != 0 {
                return Err(TunError::MalformedPacket("fragmented IPv4 packet"));
            }
            (
                IpAddr::V4(Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    packet[16], packet[17], packet[18], packet[19],
                )),
                packet[9],
                &packet[ihl..total],
            )
        }
        Some(6) => {
            if packet.len() < 40 {
                return Err(TunError::MalformedPacket("truncated IPv6 header"));
            }
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            let total = 40 + payload_len;
            if total > packet.len() {
                return Err(TunError::MalformedPacket("invalid IPv6 length"));
            }
            let mut protocol = packet[6];
            let mut offset = 40usize;
            let mut extensions = 0usize;
            loop {
                match protocol {
                    0 | 43 | 60 => {
                        if offset + 2 > total {
                            return Err(TunError::MalformedPacket(
                                "truncated IPv6 extension header",
                            ));
                        }
                        let length = (packet[offset + 1] as usize + 1) * 8;
                        if length < 8 || offset + length > total {
                            return Err(TunError::MalformedPacket(
                                "invalid IPv6 extension header length",
                            ));
                        }
                        protocol = packet[offset];
                        offset += length;
                    }
                    44 => {
                        return Err(TunError::MalformedPacket("fragmented IPv6 packet"));
                    }
                    51 => {
                        if offset + 2 > total {
                            return Err(TunError::MalformedPacket(
                                "truncated IPv6 authentication header",
                            ));
                        }
                        let length = (packet[offset + 1] as usize + 2) * 4;
                        if length < 12 || offset + length > total {
                            return Err(TunError::MalformedPacket(
                                "invalid IPv6 authentication header length",
                            ));
                        }
                        protocol = packet[offset];
                        offset += length;
                    }
                    50 => {
                        return Err(TunError::MalformedPacket(
                            "encrypted IPv6 payload is unsupported",
                        ));
                    }
                    6 | 17 => break,
                    59 => {
                        return Err(TunError::MalformedPacket("IPv6 packet has no next header"));
                    }
                    _ => {
                        return Err(TunError::MalformedPacket(
                            "unsupported IPv6 next-header protocol",
                        ));
                    }
                }
                extensions += 1;
                if extensions > 16 {
                    return Err(TunError::MalformedPacket(
                        "IPv6 extension header chain is too long",
                    ));
                }
            }
            (
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&packet[8..24]).unwrap(),
                )),
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&packet[24..40]).unwrap(),
                )),
                protocol,
                &packet[offset..total],
            )
        }
        _ => return Err(TunError::MalformedPacket("unknown IP version")),
    };
    let payload = match protocol {
        6 => {
            if transport.len() < 20 {
                return Err(TunError::MalformedPacket("truncated TCP header"));
            }
            let length = (transport[12] >> 4) as usize * 4;
            if !(20..=transport.len()).contains(&length) {
                return Err(TunError::MalformedPacket("invalid TCP header length"));
            }
            &transport[length..]
        }
        17 => {
            if transport.len() < 8 {
                return Err(TunError::MalformedPacket("truncated UDP header"));
            }
            let length = u16::from_be_bytes([transport[4], transport[5]]) as usize;
            if length < 8 || length > transport.len() {
                return Err(TunError::MalformedPacket("invalid UDP length"));
            }
            // The UDP length, not the end of the IP payload, bounds the
            // datagram: anything after it is padding and must not reach the
            // application as data.
            &transport[8..length]
        }
        _ => return Err(TunError::MalformedPacket("unsupported transport protocol")),
    };
    Ok(IpPacket {
        source,
        destination,
        network: if protocol == 6 {
            Network::Tcp
        } else {
            Network::Udp
        },
        source_port: u16::from_be_bytes([transport[0], transport[1]]),
        destination_port: u16::from_be_bytes([transport[2], transport[3]]),
        payload: payload.to_vec(),
    })
}

/// Build the IP/UDP response packet for a parsed TUN datagram.
///
/// This is intentionally limited to UDP: a TCP reply requires sequence-space,
/// retransmission, FIN/RST and window state, which belongs to a netstack rather
/// than a stateless packet helper. The returned packet swaps the original
/// endpoints and computes both the UDP checksum and the IP header checksum.
pub fn build_udp_reply(packet: &IpPacket, payload: &[u8]) -> Result<Vec<u8>, TunError> {
    if packet.network != Network::Udp || payload.len() > u16::MAX as usize - 8 {
        return Err(TunError::MalformedPacket(
            "UDP reply is outside the size limit",
        ));
    }
    let udp_len = 8 + payload.len();
    match (packet.source, packet.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let total_len = 20 + udp_len;
            if total_len > u16::MAX as usize {
                return Err(TunError::MalformedPacket("IPv4 reply is too large"));
            }
            let mut out = vec![0u8; total_len];
            out[0] = 0x45;
            out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            out[4..6].copy_from_slice(&0u16.to_be_bytes());
            out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
            out[8] = 64;
            out[9] = 17;
            out[12..16].copy_from_slice(&destination.octets());
            out[16..20].copy_from_slice(&source.octets());
            let header_checksum = internet_checksum(&out[..20]);
            out[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            write_udp(
                &mut out[20..],
                packet.destination_port,
                packet.source_port,
                payload,
            );
            let checksum = udp_checksum_v4(destination, source, &out[20..]);
            out[26..28].copy_from_slice(&checksum.to_be_bytes());
            Ok(out)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            if udp_len > u16::MAX as usize {
                return Err(TunError::MalformedPacket("IPv6 reply is too large"));
            }
            let mut out = vec![0u8; 40 + udp_len];
            out[0] = 0x60;
            out[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            out[6] = 17;
            out[7] = 64;
            out[8..24].copy_from_slice(&destination.octets());
            out[24..40].copy_from_slice(&source.octets());
            write_udp(
                &mut out[40..],
                packet.destination_port,
                packet.source_port,
                payload,
            );
            let checksum = udp_checksum_v6(destination, source, &out[40..]);
            out[46..48].copy_from_slice(&checksum.to_be_bytes());
            Ok(out)
        }
        _ => Err(TunError::MalformedPacket("address families do not match")),
    }
}

fn write_udp(packet: &mut [u8], source_port: u16, destination_port: u16, payload: &[u8]) {
    packet[0..2].copy_from_slice(&source_port.to_be_bytes());
    packet[2..4].copy_from_slice(&destination_port.to_be_bytes());
    packet[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[6..8].fill(0);
    packet[8..].copy_from_slice(payload);
}

// The pseudo-header is summed in place rather than assembled into a buffer
// in front of a copy of the datagram: every piece is an even number of bytes,
// so summing the parts separately gives exactly the sum of their
// concatenation, without an allocation and a payload copy per reply.

fn udp_checksum_v4(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut sum = checksum_add(0, &source.octets());
    sum = checksum_add(sum, &destination.octets());
    sum = checksum_add(sum, &[0, 17]);
    sum = checksum_add(sum, &(udp.len() as u16).to_be_bytes());
    sum = checksum_add(sum, udp);
    nonzero_checksum(checksum_finish(sum))
}

fn udp_checksum_v6(source: Ipv6Addr, destination: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut sum = checksum_add(0, &source.octets());
    sum = checksum_add(sum, &destination.octets());
    sum = checksum_add(sum, &(udp.len() as u32).to_be_bytes());
    sum = checksum_add(sum, &[0, 0, 0, 17]);
    sum = checksum_add(sum, udp);
    nonzero_checksum(checksum_finish(sum))
}

fn nonzero_checksum(checksum: u16) -> u16 {
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    checksum_finish(checksum_add(0, bytes))
}

/// Add `bytes` to a running one's-complement sum. Words are accumulated in a
/// `u64`, which cannot overflow for any input shorter than 2^48 bytes, and
/// folded once at the end instead of after every word.
fn checksum_add(mut sum: u64, bytes: &[u8]) -> u64 {
    let (words, remainder) = bytes.as_chunks::<2>();
    for word in words {
        sum += u16::from_be_bytes(*word) as u64;
    }
    if let [last] = remainder {
        sum += u16::from_be_bytes([*last, 0]) as u64;
    }
    sum
}

fn checksum_finish(mut sum: u64) -> u16 {
    while sum > u16::MAX as u64 {
        sum = (sum & u16::MAX as u64) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub no_packet_info: bool,
    pub max_packet_size: usize,
    pub mtu: usize,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "zray0".into(),
            no_packet_info: true,
            max_packet_size: MAX_PACKET,
            mtu: 1500,
        }
    }
}

/// The kernel interface-name limit. POSIX systems expose it as `IFNAMSIZ`;
/// it is stated here too so the configuration model validates identically on a
/// platform that has no TUN device at all.
const INTERFACE_NAME_LIMIT: usize = 16;

/// Whether `name` is safe to hand to the kernel and to `ip`/`ifconfig`/`netsh`
/// as a single argument.
///
/// The link commands are run without a shell, so there is no shell injection
/// to fear — but a name is still an *argument*, and one that starts with `-`
/// is read as an option (`ifconfig -a`), while `/`, `:`, whitespace, quotes
/// and control characters are rejected by the kernel or change how the tools
/// split their input. Windows adapter names may contain spaces; nothing else
/// here may.
fn interface_name_is_valid(name: &str) -> bool {
    if name.is_empty()
        || name.len() >= INTERFACE_NAME_LIMIT
        || name == "."
        || name == ".."
        || name.starts_with('-')
    {
        return false;
    }
    name.chars().all(|character| {
        !character.is_control()
            && !matches!(character, '/' | '\\' | ':' | '"' | '\'' | '=')
            && ((cfg!(windows) && character == ' ') || !character.is_whitespace())
    })
}

impl TunConfig {
    fn validate(&self) -> Result<(), TunError> {
        if !interface_name_is_valid(&self.name) {
            return Err(TunError::InvalidName);
        }
        if !(1..=MAX_PACKET).contains(&self.max_packet_size) {
            return Err(TunError::Configure(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_packet_size is outside the IP packet limit",
            )));
        }
        if !(576..=MAX_PACKET).contains(&self.mtu) {
            return Err(TunError::Configure(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mtu is outside the IP packet limit",
            )));
        }
        Ok(())
    }
}

/// An address assigned to the virtual interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunAddress {
    pub address: IpAddr,
    pub prefix: u8,
}

impl TunAddress {
    pub fn parse(value: &str) -> Result<Self, TunError> {
        let (address, prefix) = value
            .trim()
            .split_once('/')
            .ok_or_else(|| TunError::InvalidCidr(value.into()))?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| TunError::InvalidCidr(value.into()))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| TunError::InvalidCidr(value.into()))?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(TunError::InvalidCidr(value.into()));
        }
        Ok(Self { address, prefix })
    }

    /// The address in CIDR form, as every platform's tooling wants it.
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.address, self.prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunRoute {
    pub network: IpAddr,
    pub prefix: u8,
}

impl TunRoute {
    /// Parse a route in CIDR form. Host bits below the prefix are cleared, so
    /// `198.18.0.1/15` names the network `198.18.0.0/15`: `ip route` refuses a
    /// destination with host bits set, and a user who wrote the interface
    /// address where the network belongs meant the network.
    pub fn parse(value: &str) -> Result<Self, TunError> {
        let address = TunAddress::parse(value)?;
        let network = match address.address {
            IpAddr::V4(v4) => {
                let mask = u32::MAX
                    .checked_shl(32 - address.prefix as u32)
                    .unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) => {
                let mask = u128::MAX
                    .checked_shl(128 - address.prefix as u32)
                    .unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
        };
        Ok(Self {
            network,
            prefix: address.prefix,
        })
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network, self.prefix)
    }
}

#[derive(Debug, Clone, Default)]
pub struct TunNetworkConfig {
    pub addresses: Vec<TunAddress>,
    pub routes: Vec<TunRoute>,
    /// Outbound proxy server IPs that must bypass the tunnel to prevent routing loops.
    pub bypass_ips: Vec<IpAddr>,
    /// Installing routes is process-wide and privileged, so it is explicit.
    pub auto_route: bool,
    /// Strict routing requires an explicit route list and never guesses a
    /// default route that could strand the proxy's own control connection.
    pub strict_route: bool,
}

/// Owns addresses and routes installed for one TUN instance. Dropping it
/// removes only state created by this guard.
///
/// The undo commands are computed once, when the configuration succeeds, so
/// the same list serves both `Drop` and the abort-time panic hook below.
pub struct TunNetworkGuard {
    name: String,
    state: std::sync::Mutex<GuardState>,
}

/// What a guard installed, and the undo list registered for it.
struct GuardState {
    installed: Installed,
    teardown: Arc<[NetCommand]>,
    registration: u64,
    /// The physical path to the internet per address family, captured
    /// before the tunnel routes existed. Once they do, asking the system for
    /// the route to a new server answers "the tunnel", so bypass routes added
    /// later have to be pinned to what the path was.
    uplink_v4: Option<platform::Via>,
    uplink_v6: Option<platform::Via>,
    auto_route: bool,
}

impl std::fmt::Debug for TunNetworkGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunNetworkGuard")
            .field("name", &self.name)
            .field("teardown", &self.teardown_commands())
            .finish()
    }
}

impl TunNetworkGuard {
    fn state(&self) -> std::sync::MutexGuard<'_, GuardState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The commands this guard runs when it is dropped, in order.
    pub fn teardown_commands(&self) -> Vec<NetCommand> {
        self.state().teardown.to_vec()
    }

    /// The physical interface traffic left by before the tunnel took over:
    /// the one to keep the proxy's own sockets on (see
    /// `zero_core::platform::set_bound_interface`). IPv4's when both
    /// families have one.
    pub fn uplink_interface(&self) -> Option<String> {
        let state = self.state();
        state
            .uplink_v4
            .as_ref()
            .or(state.uplink_v6.as_ref())
            .map(|via| via.interface.clone())
    }

    /// The proxy servers currently kept off the tunnel.
    pub fn bypassed(&self) -> Vec<IpAddr> {
        self.state()
            .installed
            .bypass
            .iter()
            .map(|(ip, _)| *ip)
            .collect()
    }

    /// Keep exactly `ips` off the tunnel, for switching servers without
    /// tearing the interface down.
    ///
    /// New routes go in before stale ones come out, so there is no moment
    /// in which the new server's traffic would loop into the tunnel. Routes
    /// this guard did not create are never removed. A no-op when the guard
    /// installed no default routes, since then nothing needs bypassing.
    pub fn set_bypass(&self, ips: &[IpAddr]) -> Result<(), TunError> {
        let mut state = self.state();
        if !state.auto_route {
            return Ok(());
        }
        for ip in ips {
            if state.installed.bypass.iter().any(|(have, _)| have == ip) {
                continue;
            }
            let uplink = if ip.is_ipv4() {
                state.uplink_v4.clone()
            } else {
                state.uplink_v6.clone()
            };
            // No uplink for this family: the server is unreachable without
            // the tunnel too, so there is no path to pin it to.
            let Some(via) = uplink else { continue };
            match platform::run_applied(&platform::current::add_bypass_route(*ip, &via)) {
                Ok(true) => state
                    .installed
                    .bypass
                    .push((*ip, platform::current::del_bypass_route(*ip, &via))),
                Ok(false) => {}
                Err(error) => {
                    state.refresh_registration(&self.name);
                    return Err(TunError::Network(error));
                }
            }
        }
        let stale: Vec<(IpAddr, NetCommand)> = state
            .installed
            .bypass
            .iter()
            .filter(|(have, _)| !ips.contains(have))
            .cloned()
            .collect();
        for (ip, undo) in stale {
            platform::run_best_effort(&undo);
            state.installed.bypass.retain(|(have, _)| *have != ip);
        }
        state.refresh_registration(&self.name);
        Ok(())
    }
}

impl GuardState {
    /// Recompute the undo list after a change and swap it into the
    /// abort-time registry, so a crash never leaves a route behind.
    fn refresh_registration(&mut self, name: &str) {
        let teardown: Arc<[NetCommand]> = self.installed.teardown(name).into();
        let registration = teardown_registry::register(Arc::clone(&teardown));
        teardown_registry::unregister(self.registration);
        self.teardown = teardown;
        self.registration = registration;
    }
}

impl Drop for TunNetworkGuard {
    fn drop(&mut self) {
        let state = self.state();
        teardown_registry::unregister(state.registration);
        for command in state.teardown.iter() {
            platform::run_best_effort(command);
        }
    }
}

/// Everything one configuration attempt has changed so far.
///
/// Both the rollback of a half-finished attempt and the guard of a finished
/// one undo exactly this, in exactly the reverse order it was applied.
#[derive(Default)]
struct Installed {
    changed_mtu: Option<usize>,
    addresses: Vec<TunAddress>,
    raised_link: bool,
    /// Each bypassed server and the command that removes its route.
    bypass: Vec<(IpAddr, NetCommand)>,
    routes: Vec<TunRoute>,
}

impl Installed {
    /// The undo list. Routes into the tunnel go first, so traffic stops
    /// entering it before the bypass routes that keep the proxy's own
    /// connections out of it are removed — the other order briefly loops the
    /// proxy's traffic back into itself.
    fn teardown(&self, name: &str) -> Vec<NetCommand> {
        let mut commands = Vec::new();
        for route in self.routes.iter().rev() {
            commands.push(platform::current::del_route(name, route));
        }
        commands.extend(self.bypass.iter().rev().map(|(_, undo)| undo.clone()));
        for address in self.addresses.iter().rev() {
            commands.push(platform::current::del_address(name, address));
        }
        if self.raised_link {
            commands.extend(platform::current::link_down(name));
        }
        if let Some(mtu) = self.changed_mtu {
            commands.extend(platform::current::set_mtu(name, mtu));
        }
        commands
    }

    fn roll_back(&self, name: &str) {
        for command in self.teardown(name) {
            platform::run_best_effort(&command);
        }
    }
}

/// Undo lists of every live guard in the process.
///
/// With `panic = "abort"` — which the release profile uses — a panic never
/// unwinds, so no `Drop` runs and every route a guard installed would outlive
/// the process. A panic hook still runs before the abort, though, so each
/// guard registers its undo list here and a hook installed on first use runs
/// them. Under `panic = "unwind"` the hook is not installed: tokio catches a
/// panicking task and the process carries on, and tearing the network down
/// underneath a process that is still running would be worse than the panic.
mod teardown_registry {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, TryLockError};

    use crate::netcmd::NetCommand;
    use crate::platform;

    type Entry = (u64, Arc<[NetCommand]>);

    static LIVE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
    static NEXT: AtomicU64 = AtomicU64::new(1);

    pub(super) fn register(commands: Arc<[NetCommand]>) -> u64 {
        install_hook();
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        LIVE.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((id, commands));
        id
    }

    pub(super) fn unregister(id: u64) {
        LIVE.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|(entry, _)| *entry != id);
    }

    #[cfg(test)]
    pub(super) fn is_registered(id: u64) -> bool {
        LIVE.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .any(|(entry, _)| *entry == id)
    }

    /// Run and forget every registered undo list, newest first.
    ///
    /// `try_lock`, because the panicking thread may be the one holding the
    /// lock; blocking on it inside the hook would turn a crash into a hang.
    #[cfg_attr(not(panic = "abort"), allow(dead_code))]
    pub(super) fn run_all() {
        let entries = match LIVE.try_lock() {
            Ok(mut live) => std::mem::take(&mut *live),
            Err(TryLockError::Poisoned(poisoned)) => std::mem::take(&mut *poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => return,
        };
        for (_, commands) in entries.iter().rev() {
            for command in commands.iter() {
                platform::run_best_effort(command);
            }
        }
    }

    fn install_hook() {
        #[cfg(panic = "abort")]
        {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                let previous = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |info| {
                    // Report first: the panic message is what the operator
                    // needs, and it must not wait behind the teardown.
                    previous(info);
                    run_all();
                }));
            });
        }
    }
}

/// An opened non-blocking packet device.
pub struct TunDevice {
    #[cfg(unix)]
    io: AsyncFd<std::fs::File>,
    /// Windows has no descriptor to poll: Wintun owns a shared ring and a
    /// Win32 event, so the device is a session rather than a file. The read
    /// half is behind a mutex because receiving drains a channel, which needs
    /// `&mut`, while the rest of the API is shared.
    #[cfg(windows)]
    io: tokio::sync::Mutex<wintun::Session>,
    #[cfg(windows)]
    writer: std::sync::Arc<wintun::SessionWriter>,
    max_packet_size: usize,
    mtu: usize,
    name: String,
    /// Bytes of platform framing in front of each IP packet.
    ///
    /// Linux with `IFF_NO_PI` and an adopted Android descriptor deliver bare IP
    /// packets. Darwin's `utun` always prepends a four-byte address family, and
    /// expects one back — handing those four bytes to an IP parser, or omitting
    /// them on write, silently breaks every packet on exactly one platform.
    header_len: usize,
    /// Whether the descriptor came from someone else (`from_raw_fd`). Such an
    /// interface is never reconfigured from here.
    adopted: bool,
    /// Packets the netstack bridge discarded because the device refused them
    /// (a full ring, `ENOBUFS`, a malformed frame) rather than tearing the
    /// whole tunnel down over one packet.
    bridge_dropped: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for TunDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunDevice")
            .field("max_packet_size", &self.max_packet_size)
            .finish_non_exhaustive()
    }
}

impl TunDevice {
    /// Open or create a TUN device for this platform.
    ///
    /// Linux opens `/dev/net/tun`; macOS opens a `utun` control socket. On
    /// Windows and on mobile this returns [`TunError::UnsupportedPlatform`] —
    /// mobile platforms hand the application a descriptor instead, which is
    /// what [`Self::from_raw_fd`] is for.
    pub fn open(config: TunConfig) -> Result<Self, TunError> {
        config.validate()?;
        #[cfg(target_os = "linux")]
        {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true);
            let file = options
                .open(Path::new("/dev/net/tun"))
                .map_err(TunError::Open)?;
            set_nonblocking(&file).map_err(TunError::Open)?;
            configure_linux(&file, &config).map_err(TunError::Configure)?;
            let io = AsyncFd::new(file).map_err(TunError::Open)?;
            Ok(Self {
                io,
                max_packet_size: config.max_packet_size,
                mtu: config.mtu,
                name: config.name,
                // `IFF_NO_PI` removes the framing; without it the kernel
                // prepends four bytes of packet information.
                header_len: if config.no_packet_info { 0 } else { 4 },
                adopted: false,
                bridge_dropped: Default::default(),
            })
        }
        #[cfg(target_os = "macos")]
        {
            let (file, name) = open_utun(&config)?;
            set_nonblocking(&file).map_err(TunError::Open)?;
            let io = AsyncFd::new(file).map_err(TunError::Open)?;
            Ok(Self {
                io,
                max_packet_size: config.max_packet_size,
                mtu: config.mtu,
                name,
                // utun is unconditionally framed; there is no `NO_PI` for it.
                header_len: UTUN_HEADER,
                adopted: false,
                bridge_dropped: Default::default(),
            })
        }
        #[cfg(target_os = "windows")]
        {
            let session = wintun::Session::open(&config.name).map_err(TunError::Open)?;
            let writer = session.writer();
            Ok(Self {
                io: tokio::sync::Mutex::new(session),
                writer,
                max_packet_size: config.max_packet_size,
                mtu: config.mtu,
                name: config.name,
                // Wintun exchanges bare IP packets; there is no framing.
                header_len: 0,
                adopted: false,
                bridge_dropped: Default::default(),
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = config;
            Err(TunError::UnsupportedPlatform)
        }
    }

    /// Adopt a TUN descriptor the platform already opened.
    ///
    /// This is the only workable entry point on Android and iOS: `VpnService`
    /// and `NEPacketTunnelProvider` create the interface themselves and hand
    /// the process a descriptor, and neither permits opening the device
    /// directly. The descriptor is **taken over**, not borrowed — the caller
    /// must stop using it, and must not close it.
    ///
    /// `header_len` is the platform framing in front of each packet: zero for
    /// Android's `VpnService`, four for iOS `NEPacketTunnelProvider` and for
    /// Darwin `utun` descriptors.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid, open file descriptor for a TUN device that no
    /// other object owns.
    #[cfg(unix)]
    pub unsafe fn from_raw_fd(
        fd: std::os::fd::RawFd,
        config: TunConfig,
        header_len: usize,
    ) -> Result<Self, TunError> {
        use std::os::fd::FromRawFd;
        config.validate()?;
        if fd < 0 {
            return Err(TunError::Open(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN descriptor is not valid",
            )));
        }
        if header_len > 4 {
            return Err(TunError::Open(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN header length must be 0..=4 bytes",
            )));
        }
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        set_nonblocking(&file).map_err(TunError::Open)?;
        // A descriptor received over a unix socket or from a JNI call is
        // usually inheritable. Once it is ours, a child process holding a
        // copy would keep the interface alive after this device closes it.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(TunError::Open(io::Error::last_os_error()));
        }
        let io = AsyncFd::new(file).map_err(TunError::Open)?;
        Ok(Self {
            io,
            max_packet_size: config.max_packet_size,
            mtu: config.mtu,
            name: config.name,
            header_len,
            adopted: true,
            bridge_dropped: Default::default(),
        })
    }

    /// Bytes of platform framing this device puts in front of each packet.
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// The underlying descriptor, borrowed.
    ///
    /// Exposed so a privileged helper process can hand the open device to an
    /// unprivileged one over a unix socket: opening a TUN needs
    /// `CAP_NET_ADMIN`, but *using* an already-open descriptor needs nothing,
    /// which is the whole reason the handover in `inherited` exists. The
    /// descriptor stays owned by this device — a caller that wants to keep it
    /// past the device's lifetime must duplicate it.
    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.io.get_ref().as_raw_fd()
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Configure the kernel-side link and return a guard that cleans it up.
    ///
    /// This is deliberately separate from `open`: creating a TUN fd is a
    /// device operation, while changing routes is a process-wide policy
    /// operation that must be explicitly requested by the compiled config.
    ///
    /// The sequence is the same on every desktop platform — MTU, addresses,
    /// link up, routes — and so is the rollback. What differs is the spelling
    /// of each step, which lives in `netcmd`, and what a tool says when the
    /// state it was asked for already holds, which lives in `platform`.
    ///
    /// On Android and iOS this is not called at all: the host application's
    /// `VpnService` or `NEPacketTunnelProvider` has already built the
    /// interface, and a proxy reaching around it to run `ip` would be both
    /// impossible and wrong.
    pub fn configure_network(&self, config: TunNetworkConfig) -> Result<TunNetworkGuard, TunError> {
        validate_network_config(&config)?;
        if self.adopted {
            // An adopted descriptor's interface was built by the host — the
            // platform's VPN service or a privileged helper — with settings
            // the user approved. Reconfiguring it from here would change
            // something this process does not own.
            return Err(TunError::Network(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "an adopted TUN interface is configured by the host that created it",
            )));
        }
        if !platform::SUPPORTED {
            return Err(TunError::UnsupportedPlatform);
        }

        let name = self.name.clone();
        let previous = platform::current::probe(&name).map_err(TunError::Network)?;

        // Everything installed so far, so a failure at any step can be undone
        // in reverse rather than left half-applied.
        let mut installed = Installed::default();
        let fail = |installed: &Installed, error: io::Error| {
            installed.roll_back(&name);
            TunError::Network(error)
        };

        if previous.mtu != Some(self.mtu) {
            for command in platform::current::set_mtu(&name, self.mtu) {
                if let Err(error) = platform::run(&command) {
                    return Err(fail(&installed, error));
                }
                // Restoring needs the old value; when it could not be read
                // there is nothing to restore to.
                installed.changed_mtu = previous.mtu;
            }
        }

        for address in &config.addresses {
            if let Err(error) = platform::run(&platform::current::add_address(&name, address)) {
                return Err(fail(&installed, error));
            }
            installed.addresses.push(address.clone());
        }

        if !previous.up {
            for command in platform::current::link_up(&name) {
                if let Err(error) = platform::run(&command) {
                    return Err(fail(&installed, error));
                }
                installed.raised_link = true;
            }
        }

        // The uplinks, looked up while the host's own routes are still the
        // only ones, for servers bypassed after the tunnel is up.
        let uplink = |probe: IpAddr| {
            platform::current::route_to(probe)
                .ok()
                .filter(|via| via.interface != name)
        };
        let (uplink_v4, uplink_v6) = if config.auto_route {
            (
                uplink(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))),
                uplink(IpAddr::V6(std::net::Ipv6Addr::new(
                    0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
                ))),
            )
        } else {
            (None, None)
        };

        if config.auto_route {
            // Pin each proxy server to the path it uses *now*, before the
            // tunnel routes capture it. Looked up per address rather than
            // from one "default gateway": an IPv6 server needs the IPv6
            // route, and a policy-routed or multi-homed host may reach
            // different servers through different interfaces.
            for ip in &config.bypass_ips {
                let via = match platform::current::route_to(*ip) {
                    Ok(via) => via,
                    // No route today means the server is unreachable without
                    // the tunnel as well; there is no path to preserve.
                    Err(_) => continue,
                };
                if via.interface == name {
                    return Err(fail(
                        &installed,
                        io::Error::other(format!(
                            "the route to proxy server {ip} already goes through {name}; \
                             a stale tunnel route would loop the proxy into itself"
                        )),
                    ));
                }
                match platform::run_applied(&platform::current::add_bypass_route(*ip, &via)) {
                    // Only a route this call created is removed later. One that
                    // already existed belongs to whoever added it.
                    Ok(true) => installed
                        .bypass
                        .push((*ip, platform::current::del_bypass_route(*ip, &via))),
                    Ok(false) => {}
                    Err(error) => return Err(fail(&installed, error)),
                }
            }

            for route in &config.routes {
                if let Err(error) = platform::run(&platform::current::add_route(&name, route)) {
                    return Err(fail(&installed, error));
                }
                installed.routes.push(route.clone());
            }
        }

        let teardown: Arc<[NetCommand]> = installed.teardown(&name).into();
        let registration = teardown_registry::register(Arc::clone(&teardown));
        Ok(TunNetworkGuard {
            name,
            state: std::sync::Mutex::new(GuardState {
                installed,
                teardown,
                registration,
                uplink_v4,
                uplink_v6,
                auto_route: config.auto_route,
            }),
        })
    }

    /// Read one IP packet, stripping any platform framing.
    ///
    /// Callers always see a bare IP packet, whatever the platform puts in
    /// front of it. Leaving that framing in place would make `parse_ip_packet`
    /// reject every packet on Darwin while working perfectly on Linux.
    ///
    /// Framed descriptors are read with one `readv` that scatters the framing
    /// into a small stack buffer and the packet straight into the caller's
    /// buffer — no per-packet allocation, no copy, and no zeroing of a
    /// 64 KiB scratch buffer for every packet on Darwin and iOS.
    #[cfg(unix)]
    pub async fn recv(&self, packet: &mut [u8]) -> Result<usize, TunError> {
        use std::os::fd::AsRawFd;

        let limit = packet.len().min(self.max_packet_size);
        let packet = &mut packet[..limit];
        let mut header = [0u8; 4];
        let header_len = self.header_len;
        let read = loop {
            let mut guard = self.io.readable().await.map_err(TunError::Io)?;
            let attempt = guard.try_io(|inner| {
                if header_len == 0 {
                    use std::io::Read;
                    return inner.get_ref().read(packet);
                }
                let vectors = [
                    libc::iovec {
                        iov_base: header.as_mut_ptr().cast(),
                        iov_len: header_len,
                    },
                    libc::iovec {
                        iov_base: packet.as_mut_ptr().cast(),
                        iov_len: packet.len(),
                    },
                ];
                // SAFETY: both vectors point into buffers that are live and
                // exclusively borrowed for the duration of the call, with the
                // lengths given.
                let read = unsafe { libc::readv(inner.get_ref().as_raw_fd(), vectors.as_ptr(), 2) };
                if read < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(read as usize)
            });
            match attempt {
                Ok(Ok(read)) => break read,
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(TunError::Io(error)),
                Err(_would_block) => continue,
            }
        };
        if header_len == 0 {
            return Ok(read);
        }
        if read == 0 {
            // End of file, reported the same way as an unframed device.
            return Ok(0);
        }
        if read < header_len {
            return Err(TunError::MalformedPacket("TUN frame has no IP payload"));
        }
        Ok(read - header_len)
    }

    /// Write one IP packet, adding any platform framing.
    ///
    /// Framing is gathered with `writev` from a stack buffer, so a framed
    /// write costs no allocation or copy of the packet either.
    #[cfg(unix)]
    pub async fn send(&self, packet: &[u8]) -> Result<usize, TunError> {
        use std::os::fd::AsRawFd;

        if packet.is_empty() || packet.len() > self.max_packet_size {
            return Err(TunError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet is outside the configured TUN size",
            )));
        }
        let header_len = self.header_len;
        let mut header = [0u8; 4];
        if header_len > 0 {
            header[..header_len].copy_from_slice(&address_family_header(packet, header_len)?);
        }
        loop {
            let mut guard = self.io.writable().await.map_err(TunError::Io)?;
            let attempt = guard.try_io(|inner| {
                if header_len == 0 {
                    use std::io::Write;
                    return inner.get_ref().write(packet);
                }
                let vectors = [
                    libc::iovec {
                        iov_base: header.as_ptr() as *mut libc::c_void,
                        iov_len: header_len,
                    },
                    libc::iovec {
                        iov_base: packet.as_ptr() as *mut libc::c_void,
                        iov_len: packet.len(),
                    },
                ];
                // SAFETY: both vectors point into live buffers of the given
                // lengths; `writev` only reads through them.
                let written =
                    unsafe { libc::writev(inner.get_ref().as_raw_fd(), vectors.as_ptr(), 2) };
                if written < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok((written as usize).saturating_sub(header_len))
            });
            match attempt {
                Ok(Ok(written)) => return Ok(written),
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(TunError::Io(error)),
                Err(_would_block) => continue,
            }
        }
    }

    /// Read one IP packet from the Wintun ring.
    #[cfg(windows)]
    pub async fn recv(&self, packet: &mut [u8]) -> Result<usize, TunError> {
        let limit = packet.len().min(self.max_packet_size);
        let mut session = self.io.lock().await;
        session
            .recv(&mut packet[..limit])
            .await
            .map_err(TunError::Io)
    }

    /// Write one IP packet into the Wintun ring.
    ///
    /// A full ring is reported rather than queued: this is a network device,
    /// and the honest response to congestion is a dropped packet, not an
    /// unbounded buffer in front of one.
    #[cfg(windows)]
    pub async fn send(&self, packet: &[u8]) -> Result<usize, TunError> {
        if packet.is_empty() || packet.len() > self.max_packet_size {
            return Err(TunError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet is outside the configured TUN size",
            )));
        }
        self.writer.send(packet).map_err(TunError::Io)
    }

    /// Packets discarded instead of delivered: by the device because the
    /// reader fell behind (Wintun), and by the netstack bridge because the
    /// device refused a single packet.
    #[cfg(windows)]
    pub async fn dropped(&self) -> u64 {
        self.io.lock().await.dropped()
            + self
                .bridge_dropped
                .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(not(windows))]
    pub async fn dropped(&self) -> u64 {
        self.bridge_dropped
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// No packet device on this platform.
    #[cfg(not(any(unix, windows)))]
    pub async fn recv(&self, packet: &mut [u8]) -> Result<usize, TunError> {
        let _ = packet;
        Err(TunError::UnsupportedPlatform)
    }

    #[cfg(not(any(unix, windows)))]
    pub async fn send(&self, packet: &[u8]) -> Result<usize, TunError> {
        let _ = packet;
        Err(TunError::UnsupportedPlatform)
    }
}

/// Darwin's `utun` framing: the four-byte address family, in host byte order
/// on read and network byte order on write, per `if_utun`.
pub fn address_family_header(packet: &[u8], header_len: usize) -> Result<Vec<u8>, TunError> {
    if header_len == 0 {
        return Ok(Vec::new());
    }
    let version = packet.first().map(|byte| byte >> 4);
    let family: u32 = match version {
        Some(4) => 2,  // AF_INET
        Some(6) => 30, // AF_INET6 on Darwin
        _ => return Err(TunError::MalformedPacket("packet is neither IPv4 nor IPv6")),
    };
    let mut header = family.to_be_bytes().to_vec();
    header.truncate(header_len);
    Ok(header)
}

fn validate_network_config(config: &TunNetworkConfig) -> Result<(), TunError> {
    if config.addresses.is_empty() {
        return Err(TunError::Network(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one TUN address is required",
        )));
    }
    if config.auto_route && config.routes.is_empty() {
        return Err(TunError::Network(io::Error::new(
            io::ErrorKind::InvalidInput,
            "auto_route requires an explicit route list",
        )));
    }
    if config.strict_route && !config.auto_route {
        return Err(TunError::Network(io::Error::new(
            io::ErrorKind::InvalidInput,
            "strict_route requires auto_route",
        )));
    }
    Ok(())
}

/// The userspace IP stack attached to a TUN device. The stack itself is an
/// MIT/Apache dependency; this crate owns the device bridge and keeps the
/// runtime's router/relay policy above it.
pub struct NetstackParts {
    pub stack: netstack_smoltcp::Stack,
    pub runner: Option<netstack_smoltcp::Runner>,
    pub tcp: Option<netstack_smoltcp::TcpListener>,
    pub udp: Option<netstack_smoltcp::UdpSocket>,
}

#[derive(Debug, Clone, Copy)]
pub struct NetstackConfig {
    pub mtu: usize,
    pub enable_tcp: bool,
    pub enable_udp: bool,
    pub enable_icmp: bool,
}

/// Per-direction TCP buffer for each connection in the userspace stack.
pub const TCP_WINDOW: u32 = 64 * 1024;

/// Build the TCP/UDP/ICMP userspace stack without opening a platform device.
/// This separation lets Android/iOS provide their own file descriptor while
/// retaining identical stream semantics.
pub fn build_netstack(config: NetstackConfig) -> Result<NetstackParts, TunError> {
    // netstack-smoltcp owns the IP interface inside its TCP runner. UDP and
    // ICMP therefore need that runner even when no TCP listener is exposed.
    let needs_interface = config.enable_tcp || config.enable_udp || config.enable_icmp;
    let (stack, runner, udp, tcp) = netstack_smoltcp::StackBuilder::default()
        // The library default is ~320 KB per buffer, four buffers per
        // connection: 1.3 MB for every TCP flow through the tunnel, which a
        // browser multiplies into hundreds of megabytes. The window here only
        // has to cover the hop between local apps and this process, a few
        // hundred microseconds, so 64 KiB still carries well over 500 Mbit/s
        // per connection. The real network leg has its own kernel buffers.
        .tcp_recv_buffer_size(TCP_WINDOW)
        .tcp_send_buffer_size(TCP_WINDOW)
        .enable_tcp(needs_interface)
        .enable_udp(config.enable_udp)
        .enable_icmp(config.enable_icmp)
        .mtu(config.mtu)
        .build()
        .map_err(TunError::Configure)?;
    Ok(NetstackParts {
        stack,
        runner,
        tcp: tcp.filter(|_| config.enable_tcp),
        udp,
    })
}

/// Bridge raw IP packets between the platform TUN device and the userspace
/// stack. The returned task owns neither routing nor proxy policy; it only
/// preserves packet ordering and applies the configured device limit.
///
/// The bridge ends when either side does: the device reaching end of file
/// (the host closed the interface), the stack closing, or an error that means
/// the device itself is gone. A single packet that the device or the stack
/// refuses is dropped and counted in [`TunDevice::dropped`] — a network device
/// loses packets under congestion, and one `ENOBUFS`, full Wintun ring or
/// malformed frame must not take every connection down with it.
pub fn spawn_netstack_bridge(
    device: Arc<TunDevice>,
    stack: netstack_smoltcp::Stack,
) -> tokio::task::JoinHandle<Result<(), TunError>> {
    tokio::spawn(async move {
        let (mut sink, mut stream) = stack.split();
        let device_tx = Arc::clone(&device);

        let rx_fut = async {
            let mut packet = vec![0u8; MAX_PACKET];
            loop {
                let length = match device.recv(&mut packet).await {
                    // A zero-length read is end of file: no IP packet is
                    // empty. Retrying it would spin a core forever.
                    Ok(0) => return Ok(()),
                    Ok(length) => length,
                    // A runt frame has been consumed by the read that found
                    // it. Any other read error would recur on the next read,
                    // so retrying it would only spin.
                    Err(TunError::MalformedPacket(_)) => {
                        device.count_bridge_drop();
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                match sink.send(packet[..length].to_vec()).await {
                    Ok(()) => {}
                    // The stack rejects a packet it cannot parse with
                    // `InvalidInput`; only a closed stack is terminal.
                    Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                        device.count_bridge_drop();
                    }
                    Err(error) => return Err(TunError::Io(error)),
                }
            }
        };

        let tx_fut = async {
            while let Some(result) = stream.next().await {
                let packet = result.map_err(TunError::Io)?;
                match device_tx.send(&packet).await {
                    Ok(_) => {}
                    Err(error) if is_per_packet(&error) => device_tx.count_bridge_drop(),
                    Err(error) => return Err(error),
                }
            }
            Ok::<(), TunError>(())
        };

        tokio::select! {
            result = rx_fut => result,
            result = tx_fut => result,
        }
    })
}

impl TunDevice {
    fn count_bridge_drop(&self) {
        self.bridge_dropped
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Whether a device error concerns one packet rather than the device.
///
/// Everything is per-packet except errors that say the descriptor or the
/// interface is gone, which no amount of retrying fixes.
fn is_per_packet(error: &TunError) -> bool {
    let error = match error {
        TunError::MalformedPacket(_) => return true,
        TunError::Io(error) => error,
        _ => return false,
    };
    if matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::PermissionDenied
    ) {
        return false;
    }
    #[cfg(unix)]
    if let Some(code) = error.raw_os_error() {
        // Not `EIO`: Linux returns it for a write while the link is
        // administratively down, which is a state the link comes back from.
        let device_gone = [libc::EBADF, libc::ENODEV, libc::ENXIO];
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let device_gone_linux = code == libc::EBADFD;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let device_gone_linux = false;
        if device_gone.contains(&code) || device_gone_linux {
            return false;
        }
    }
    true
}

/// Darwin `utun` control name and the four-byte address-family framing it uses.
#[cfg(target_os = "macos")]
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
#[cfg(target_os = "macos")]
const UTUN_HEADER: usize = 4;

/// Open a `utun` interface on macOS.
///
/// macOS has no `/dev/net/tun`. A utun interface is created by connecting a
/// `PF_SYSTEM` control socket; the unit number selects `utunN`, and unit 0 asks
/// the kernel for the first free one — which is why the interface name is read
/// back from the socket rather than taken from the configuration.
#[cfg(target_os = "macos")]
fn open_utun(config: &TunConfig) -> Result<(std::fs::File, String), TunError> {
    use std::os::fd::FromRawFd;

    let requested_unit: u32 = config
        .name
        .strip_prefix("utun")
        .and_then(|digits| digits.parse::<u32>().ok())
        // `utun4294967295` would overflow the unit; let the kernel choose.
        .and_then(|unit| unit.checked_add(1))
        .unwrap_or(0);

    let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(TunError::Open(io::Error::last_os_error()));
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    // Darwin has no `SOCK_CLOEXEC`. Without this every `ifconfig` and `route`
    // this process spawns to configure the link inherits the tunnel.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(TunError::Open(io::Error::last_os_error()));
    }

    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (slot, byte) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
        *slot = *byte as libc::c_char;
    }
    if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) } < 0 {
        return Err(TunError::Open(io::Error::last_os_error()));
    }

    let mut address: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
    address.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
    address.sc_family = libc::AF_SYSTEM as u8;
    address.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
    address.sc_id = info.ctl_id;
    address.sc_unit = requested_unit;
    let result = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_ctl).cast(),
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(TunError::Open(io::Error::last_os_error()));
    }

    // Read the assigned name back: with unit 0 the kernel chose it.
    let mut name = [0u8; libc::IFNAMSIZ];
    let mut length = name.len() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(TunError::Open(io::Error::last_os_error()));
    }
    let written = (length as usize).min(name.len());
    let end = name[..written]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(written);
    let name = String::from_utf8_lossy(&name[..end]).into_owned();
    Ok((file, name))
}

#[cfg(unix)]
fn set_nonblocking(file: &std::fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_linux(file: &std::fs::File, config: &TunConfig) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut request = Ifreq::default();
    request.name[..config.name.len()].copy_from_slice(config.name.as_bytes());
    request.flags = libc::IFF_TUN as i16;
    if config.no_packet_info {
        request.flags |= libc::IFF_NO_PI as i16;
    }
    let result = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &request) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Ifreq {
    name: [u8; libc::IFNAMSIZ],
    flags: i16,
    padding: [u8; 22],
}

#[cfg(target_os = "linux")]
impl Default for Ifreq {
    fn default() -> Self {
        Self {
            name: [0; libc::IFNAMSIZ],
            flags: 0,
            padding: [0; 22],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal IPv4/UDP packet, used where only the framing matters.
    #[cfg(unix)]
    fn sample_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        packet
    }

    /// A connected pair of descriptors standing in for a TUN device, so the
    /// framing behaviour can be tested without the privileges a real device
    /// needs.
    #[cfg(unix)]
    fn socket_pair() -> (std::os::fd::RawFd, std::fs::File) {
        use std::os::fd::FromRawFd;
        let mut fds = [0 as libc::c_int; 2];
        let result =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(result, 0, "socketpair: {}", io::Error::last_os_error());
        (fds[0], unsafe { std::fs::File::from_raw_fd(fds[1]) })
    }

    #[test]
    fn the_address_family_header_matches_darwins_utun_framing() {
        // AF_INET is 2 and Darwin's AF_INET6 is 30; the field is four bytes,
        // network byte order.
        let ipv4 = address_family_header(&[0x45, 0, 0, 0], 4).unwrap();
        assert_eq!(ipv4, vec![0, 0, 0, 2]);
        let ipv6 = address_family_header(&[0x60, 0, 0, 0], 4).unwrap();
        assert_eq!(ipv6, vec![0, 0, 0, 30]);
        // No framing means no header at all, not a zeroed one.
        assert!(address_family_header(&[0x45], 0).unwrap().is_empty());
        // Anything that is not IP has no address family to declare.
        assert!(address_family_header(&[0x00], 4).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_adopted_descriptor_carries_bare_packets_when_unframed() {
        let (theirs, mut ours) = socket_pair();
        let device = unsafe {
            TunDevice::from_raw_fd(theirs, TunConfig::default(), 0).expect("adopt the descriptor")
        };
        assert_eq!(device.header_len(), 0);

        let packet = sample_packet();
        device.send(&packet).await.unwrap();
        let mut received = vec![0u8; 128];
        let read = {
            use std::io::Read;
            ours.read(&mut received).unwrap()
        };
        // Android's VpnService hands over an unframed descriptor: what goes in
        // is exactly what comes out.
        assert_eq!(&received[..read], &packet[..]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_framed_descriptor_adds_and_strips_the_address_family() {
        let (theirs, mut ours) = socket_pair();
        let device = unsafe {
            TunDevice::from_raw_fd(theirs, TunConfig::default(), 4).expect("adopt the descriptor")
        };
        assert_eq!(device.header_len(), 4);

        let packet = sample_packet();
        device.send(&packet).await.unwrap();
        let mut received = vec![0u8; 128];
        let read = {
            use std::io::Read;
            ours.read(&mut received).unwrap()
        };
        assert_eq!(&received[..4], &[0, 0, 0, 2], "AF_INET header is missing");
        assert_eq!(&received[4..read], &packet[..]);

        // And the reverse: a framed packet arrives as a bare IP packet, so the
        // parser above sees the same bytes on every platform.
        let mut framed = vec![0, 0, 0, 2];
        framed.extend_from_slice(&packet);
        {
            use std::io::Write;
            ours.write_all(&framed).unwrap();
        }
        let mut buffer = vec![0u8; 128];
        let read = device.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..read], &packet[..]);
        let parsed = parse_ip_packet(&buffer[..read]).expect("a stripped packet must parse");
        assert_eq!(parsed.destination_port, 53);
    }

    #[cfg(unix)]
    #[test]
    fn adopting_a_descriptor_rejects_impossible_arguments() {
        let error = unsafe { TunDevice::from_raw_fd(-1, TunConfig::default(), 0) };
        assert!(matches!(error, Err(TunError::Open(_))));

        let (fd, _keep) = socket_pair();
        // More than four bytes of framing is not a shape any platform uses.
        let error = unsafe { TunDevice::from_raw_fd(fd, TunConfig::default(), 8) };
        assert!(matches!(error, Err(TunError::Open(_))));
    }

    #[test]
    fn config_rejects_names_that_cannot_fit_the_kernel_request() {
        // `INTERFACE_NAME_LIMIT` rather than `libc::IFNAMSIZ`: the limit is
        // restated in this crate so a name is validated identically on a
        // platform whose libc has no such constant, and the test has to run
        // there too.
        let config = TunConfig {
            name: "a".repeat(INTERFACE_NAME_LIMIT),
            ..TunConfig::default()
        };
        assert!(matches!(config.validate(), Err(TunError::InvalidName)));
    }

    #[cfg(unix)]
    #[test]
    fn the_restated_name_limit_matches_the_kernels() {
        // A restated constant that drifts from the real one is worse than no
        // constant: names would be accepted here and rejected by the ioctl.
        assert_eq!(INTERFACE_NAME_LIMIT, libc::IFNAMSIZ);
    }

    #[test]
    fn config_accepts_a_normal_device_name() {
        TunConfig::default().validate().unwrap();
    }

    #[test]
    fn parses_and_validates_tun_cidrs() {
        assert_eq!(TunAddress::parse("198.18.0.1/15").unwrap().prefix, 15);
        assert_eq!(
            TunRoute::parse("2001:db8::/32").unwrap().network,
            "2001:db8::".parse::<IpAddr>().unwrap()
        );
        assert!(TunAddress::parse("198.18.0.1/33").is_err());
        assert!(TunRoute::parse("198.18.0.1").is_err());
    }

    #[test]
    fn network_configuration_requires_explicit_routes() {
        let config = TunNetworkConfig {
            addresses: vec![TunAddress::parse("198.18.0.1/15").unwrap()],
            auto_route: true,
            ..TunNetworkConfig::default()
        };
        // This check happens before any platform command, so it is safe in
        // unprivileged CI and on platforms without a Linux TUN backend.
        assert!(validate_network_config(&config).is_err());
    }

    #[test]
    fn parses_ipv4_udp_into_session_metadata() {
        let mut packet = vec![0u8; 20 + 8 + 3];
        let packet_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&11u16.to_be_bytes());
        packet[28..31].copy_from_slice(b"dns");
        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.network, Network::Udp);
        assert_eq!(parsed.destination_port, 53);
        assert_eq!(parsed.payload, b"dns");
    }

    #[test]
    fn rejects_fragmented_ipv4_before_session_creation() {
        let mut packet = vec![0u8; 20 + 8];
        let packet_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[6] = 0x20;
        assert!(matches!(
            parse_ip_packet(&packet),
            Err(TunError::MalformedPacket("fragmented IPv4 packet"))
        ));
    }

    #[test]
    fn builds_a_udp_only_stack_with_an_internal_interface_runner() {
        let parts = build_netstack(NetstackConfig {
            mtu: 1500,
            enable_tcp: false,
            enable_udp: true,
            enable_icmp: false,
        })
        .unwrap();
        assert!(parts.runner.is_some());
        assert!(parts.tcp.is_none());
        assert!(parts.udp.is_some());
    }

    #[test]
    fn builds_a_checksummed_ipv4_udp_reply() {
        let packet = IpPacket {
            source: "10.0.0.2".parse().unwrap(),
            destination: "1.1.1.1".parse().unwrap(),
            network: Network::Udp,
            source_port: 40000,
            destination_port: 53,
            payload: b"query".to_vec(),
        };
        let reply = build_udp_reply(&packet, b"answer").unwrap();
        let parsed = parse_ip_packet(&reply).unwrap();
        assert_eq!(parsed.source, packet.destination);
        assert_eq!(parsed.destination, packet.source);
        assert_eq!(parsed.source_port, packet.destination_port);
        assert_eq!(parsed.destination_port, packet.source_port);
        assert_eq!(parsed.payload, b"answer");
        assert_ne!(&reply[10..12], &[0, 0]);
        assert_ne!(&reply[26..28], &[0, 0]);
    }

    #[test]
    fn walks_an_ipv6_hop_by_hop_header_before_udp() {
        let mut packet = vec![0u8; 40 + 8 + 8 + 3];
        packet[0] = 0x60;
        let payload_len = (packet.len() - 40) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet[6] = 0; // Hop-by-Hop Options.
        packet[7] = 64;
        packet[8] = 0x20;
        packet[24] = 0x20;
        packet[40] = 17; // UDP follows the extension header.
        packet[41] = 0; // Eight-byte extension header.
        packet[48..50].copy_from_slice(&1234u16.to_be_bytes());
        packet[50..52].copy_from_slice(&53u16.to_be_bytes());
        packet[52..54].copy_from_slice(&11u16.to_be_bytes());
        packet[56..59].copy_from_slice(b"dns");
        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.network, Network::Udp);
        assert_eq!(parsed.destination_port, 53);
        assert_eq!(parsed.payload, b"dns");
    }

    #[test]
    fn rejects_an_ipv6_fragment_header_before_session_creation() {
        let mut packet = vec![0u8; 40 + 8 + 8];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16u16.to_be_bytes());
        packet[6] = 44; // Fragment header.
        packet[40] = 17;
        assert!(matches!(
            parse_ip_packet(&packet),
            Err(TunError::MalformedPacket("fragmented IPv6 packet"))
        ));
    }

    #[test]
    fn udp_padding_after_the_datagram_is_not_payload() {
        // IP says 34 bytes, UDP says 11: the three trailing bytes are padding
        // (Ethernet minimum frames, some middleboxes) and must not be handed
        // to the application as if the peer had sent them.
        let mut packet = vec![0u8; 20 + 8 + 3 + 3];
        let packet_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[9] = 17;
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&11u16.to_be_bytes());
        packet[28..31].copy_from_slice(b"dns");
        packet[31..34].copy_from_slice(b"PAD");
        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.payload, b"dns");
    }

    #[test]
    fn the_in_place_checksum_matches_a_reference_implementation() {
        // RFC 1071's straightforward form, over an assembled pseudo-header.
        fn reference(bytes: &[u8]) -> u16 {
            let mut sum = 0u32;
            for chunk in bytes.chunks(2) {
                sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
                while sum > 0xffff {
                    sum = (sum & 0xffff) + (sum >> 16);
                }
            }
            !(sum as u16)
        }
        let source: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let destination: Ipv4Addr = "1.1.1.1".parse().unwrap();
        for length in [8usize, 9, 64, 1473] {
            let udp: Vec<u8> = (0..length).map(|index| (index * 7 + 3) as u8).collect();
            let mut pseudo = Vec::new();
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
            pseudo.extend_from_slice(&udp);
            assert_eq!(
                udp_checksum_v4(source, destination, &udp),
                nonzero_checksum(reference(&pseudo)),
                "length {length}"
            );
        }
    }

    #[test]
    fn interface_names_that_would_be_read_as_options_are_rejected() {
        for name in [
            "-a", "--help", "zray 0", "zr/ay", "zr:ay", "a\nb", ".", "..", "x\"y",
        ] {
            let config = TunConfig {
                name: name.into(),
                ..TunConfig::default()
            };
            assert!(
                matches!(config.validate(), Err(TunError::InvalidName)),
                "{name:?} must not reach ip/ifconfig/netsh as an argument"
            );
        }
        for name in ["zray0", "utun7", "tun-zray", "zray_1.2"] {
            let config = TunConfig {
                name: name.into(),
                ..TunConfig::default()
            };
            assert!(config.validate().is_ok(), "{name:?} is an ordinary name");
        }
    }

    #[test]
    fn a_route_with_host_bits_names_its_network() {
        let route = TunRoute::parse("198.18.0.1/15").unwrap();
        assert_eq!(route.cidr(), "198.18.0.0/15");
        let route = TunRoute::parse("2001:db8::1/32").unwrap();
        assert_eq!(route.cidr(), "2001:db8::/32");
        assert_eq!(TunRoute::parse("1.2.3.4/0").unwrap().cidr(), "0.0.0.0/0");
        assert_eq!(TunRoute::parse("1.2.3.4/32").unwrap().cidr(), "1.2.3.4/32");
        assert_eq!(TunRoute::parse("::1/0").unwrap().cidr(), "::/0");
    }

    #[test]
    fn teardown_removes_tunnel_routes_before_the_bypass_that_protects_the_proxy() {
        let installed = Installed {
            changed_mtu: Some(1500),
            addresses: vec![TunAddress::parse("10.0.0.1/24").unwrap()],
            raised_link: true,
            bypass: vec![(
                "203.0.113.7".parse().unwrap(),
                NetCommand::new("bypass-del", ["203.0.113.7"]),
            )],
            routes: vec![
                TunRoute::parse("0.0.0.0/1").unwrap(),
                TunRoute::parse("128.0.0.0/1").unwrap(),
            ],
        };
        let commands = installed.teardown("zray0");
        let bypass = commands
            .iter()
            .position(|command| command.program == "bypass-del")
            .expect("the bypass route is undone");
        let routes = platform::current::del_route("zray0", &installed.routes[0]);
        let last_route = commands
            .iter()
            .position(|command| *command == routes)
            .expect("the tunnel route is undone");
        assert!(
            last_route < bypass,
            "removing the bypass first loops the proxy into the tunnel"
        );
        // Newest route first.
        assert_eq!(
            commands[0],
            platform::current::del_route("zray0", &installed.routes[1])
        );
    }

    #[test]
    fn a_guard_is_registered_for_abort_time_teardown_until_it_drops() {
        let teardown: Arc<[NetCommand]> = Vec::new().into();
        let registration = teardown_registry::register(Arc::clone(&teardown));
        assert!(teardown_registry::is_registered(registration));
        let guard = TunNetworkGuard {
            name: "zray-test".into(),
            state: std::sync::Mutex::new(GuardState {
                installed: Installed::default(),
                teardown,
                registration,
                uplink_v4: None,
                uplink_v6: None,
                auto_route: false,
            }),
        };
        drop(guard);
        assert!(
            !teardown_registry::is_registered(registration),
            "a dropped guard must not be torn down a second time by the panic hook"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_adopted_interface_is_never_reconfigured() {
        let (theirs, _ours) = socket_pair();
        let device = unsafe {
            TunDevice::from_raw_fd(theirs, TunConfig::default(), 0).expect("adopt the descriptor")
        };
        let result = device.configure_network(TunNetworkConfig {
            addresses: vec![TunAddress::parse("10.79.0.1/24").unwrap()],
            ..TunNetworkConfig::default()
        });
        assert!(matches!(result, Err(TunError::Network(_))));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_framed_read_at_end_of_file_reports_zero_rather_than_a_malformed_frame() {
        let (theirs, ours) = stream_pair();
        let device = unsafe {
            TunDevice::from_raw_fd(theirs, TunConfig::default(), 4).expect("adopt the descriptor")
        };
        drop(ours);
        let mut buffer = vec![0u8; 128];
        assert_eq!(device.recv(&mut buffer).await.unwrap(), 0);
    }

    /// A stream socket pair: unlike a datagram pair, closing one end gives the
    /// other a real end of file.
    #[cfg(unix)]
    fn stream_pair() -> (std::os::fd::RawFd, std::fs::File) {
        use std::os::fd::FromRawFd;
        let mut fds = [0 as libc::c_int; 2];
        let result =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
        assert_eq!(result, 0, "socketpair: {}", io::Error::last_os_error());
        (fds[0], unsafe { std::fs::File::from_raw_fd(fds[1]) })
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_bridge_survives_a_malformed_packet_and_ends_when_the_device_closes() {
        use std::io::Write;

        let (theirs, mut ours) = stream_pair();
        let device = Arc::new(unsafe {
            TunDevice::from_raw_fd(theirs, TunConfig::default(), 0).expect("adopt the descriptor")
        });
        let parts = build_netstack(NetstackConfig {
            mtu: 1500,
            enable_tcp: true,
            enable_udp: true,
            enable_icmp: false,
        })
        .unwrap();
        let runner = tokio::spawn(parts.runner.unwrap());
        let (mut udp, _udp_writer) = parts.udp.unwrap().split();
        let bridge = spawn_netstack_bridge(Arc::clone(&device), parts.stack);

        // Garbage that the stack refuses to parse. Before, this ended the
        // bridge and with it every connection on the tunnel.
        ours.write_all(&[0x45, 0, 0, 0xff]).unwrap();

        // A well-formed datagram after it must still arrive.
        let mut packet = vec![0u8; 31];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&31u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&11u16.to_be_bytes());
        packet[28..31].copy_from_slice(b"dns");
        let udp_checksum = udp_checksum_v4(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            &packet[20..],
        );
        packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
        ours.write_all(&packet).unwrap();

        let (payload, source, destination) =
            tokio::time::timeout(std::time::Duration::from_secs(5), udp.next())
                .await
                .expect("the datagram after the garbage was delivered")
                .expect("the stack is still running");
        assert_eq!(payload, b"dns");
        assert_eq!(source.port(), 40000);
        assert_eq!(destination.port(), 53);
        assert!(device.dropped().await >= 1, "the refused packet is counted");

        // Closing the device ends the bridge instead of spinning on EOF.
        drop(ours);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), bridge)
            .await
            .expect("the bridge ended at end of file")
            .expect("the bridge task did not panic");
        assert!(outcome.is_ok(), "end of file is not an error: {outcome:?}");
        runner.abort();
    }
}
