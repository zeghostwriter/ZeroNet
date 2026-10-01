//! Capability-gated fake-SNI injection.
//!
//! The packet is deliberately outside the established TCP sequence window, so
//! the real peer discards it while a passive DPI parser can still observe the
//! allow-listed SNI. Linux requires `CAP_NET_RAW`; callers must treat a lack
//! of that capability as a normal fallback to ClientHello fragmentation.

use std::sync::OnceLock;

#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::net::{IpAddr, SocketAddr};

use rand::RngCore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniDesyncConfig {
    pub fake_sni: String,
    /// The injected segment starts at this sequence number. Zero is safely
    /// outside a normal established connection window on modern TCP stacks.
    pub sequence: u32,
}

impl Default for SniDesyncConfig {
    fn default() -> Self {
        Self {
            fake_sni: "www.microsoft.com".into(),
            sequence: 0,
        }
    }
}

/// Build the fixed-size TLS ClientHello used by the raw injector.
///
/// The shape is the public MIT-licensed template used by the reference
/// `sni-spoofing-rust` implementation. Only the SNI, random, session ID and
/// X25519 key share are varied; the padding keeps the packet at 517 bytes.
pub fn build_fake_client_hello(sni: &str) -> Result<Vec<u8>, String> {
    let sni = sni.as_bytes();
    if sni.is_empty() || sni.len() > 219 || !sni.iter().all(|byte| *byte > 0x20) {
        return Err("fake SNI must be 1..=219 visible bytes".into());
    }
    let template = template_bytes();
    let template_sni = b"mci.ir";
    let mut random = [0u8; 32];
    let mut session = [0u8; 32];
    let mut key_share = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    rand::rngs::OsRng.fill_bytes(&mut session);
    rand::rngs::OsRng.fill_bytes(&mut key_share);

    let mut out = Vec::with_capacity(517);
    out.extend_from_slice(&template[..11]);
    out.extend_from_slice(&random);
    out.push(0x20);
    out.extend_from_slice(&session);
    out.extend_from_slice(&template[76..120]);

    let extension_len = (sni.len() + 5) as u16;
    let list_len = (sni.len() + 3) as u16;
    out.extend_from_slice(&extension_len.to_be_bytes());
    out.extend_from_slice(&list_len.to_be_bytes());
    out.push(0);
    out.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    out.extend_from_slice(sni);

    out.extend_from_slice(&template[127 + template_sni.len()..262 + template_sni.len()]);
    out.extend_from_slice(&key_share);
    out.extend_from_slice(&[0, 0x15]);
    out.extend_from_slice(&((219 - sni.len()) as u16).to_be_bytes());
    out.resize(517, 0);
    Ok(out)
}

/// Whether this process can open the raw socket required by SNI desync.
pub fn has_raw_socket_capability() -> bool {
    #[cfg(target_os = "linux")]
    {
        match raw_socket() {
            Ok(fd) => {
                unsafe { libc::close(fd) };
                true
            }
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Inject one fake ClientHello. `Ok(false)` means the platform or privilege
/// boundary is unavailable and the caller should use its safe fallback.
pub fn inject_fake_client_hello(
    stream: &tokio::net::TcpStream,
    config: &SniDesyncConfig,
) -> Result<bool, String> {
    let payload = build_fake_client_hello(&config.fake_sni)?;
    let local = stream
        .local_addr()
        .map_err(|error| format!("SNI desync local address: {error}"))?;
    let peer = stream
        .peer_addr()
        .map_err(|error| format!("SNI desync peer address: {error}"))?;
    #[cfg(target_os = "linux")]
    {
        if !matches!((local.ip(), peer.ip()), (IpAddr::V4(_), IpAddr::V4(_))) {
            return Ok(false);
        }
        // Build first: an early return after the socket is open would leak it.
        let packet = build_ipv4_packet(local, peer, config.sequence, &payload)?;
        let raw = match raw_socket() {
            Ok(raw) => raw,
            Err(error) if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => {
                return Ok(false)
            }
            Err(error) => return Err(format!("SNI desync raw socket: {error}")),
        };
        // The decoy must leave the way the real hello does: copy any routing
        // mark and interface binding the real connection carries.
        {
            use std::os::fd::AsRawFd;
            copy_route_binding(stream.as_raw_fd(), raw);
        }
        let destination = sockaddr_in(peer);
        let sent = unsafe {
            libc::sendto(
                raw,
                packet.as_ptr().cast(),
                packet.len(),
                0,
                (&destination as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        let result = if sent == packet.len() as isize {
            Ok(true)
        } else if sent >= 0 {
            Err("SNI desync raw socket sent a partial packet".into())
        } else {
            Err(format!(
                "SNI desync packet injection: {}",
                io::Error::last_os_error()
            ))
        };
        unsafe { libc::close(raw) };
        result
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (stream, local, peer, payload);
        Ok(false)
    }
}

/// Copy `SO_MARK` and `SO_BINDTODEVICE` from `from` onto `to`, best effort: a
/// connection that routes by mark or interface (to stay out of a TUN) keeps
/// its decoy on the same path. Nothing to copy is the common case.
#[cfg(target_os = "linux")]
fn copy_route_binding(from: libc::c_int, to: libc::c_int) {
    unsafe {
        let mut mark: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&mark) as libc::socklen_t;
        if libc::getsockopt(
            from,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mut mark as *mut libc::c_int).cast(),
            &mut len,
        ) == 0
            && mark != 0
        {
            libc::setsockopt(
                to,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&mark as *const libc::c_int).cast(),
                std::mem::size_of_val(&mark) as libc::socklen_t,
            );
        }
        let mut device = [0u8; libc::IFNAMSIZ];
        let mut len = device.len() as libc::socklen_t;
        if libc::getsockopt(
            from,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device.as_mut_ptr().cast(),
            &mut len,
        ) == 0
            && len > 0
            && device[0] != 0
        {
            libc::setsockopt(
                to,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                device.as_ptr().cast(),
                len,
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn raw_socket() -> io::Result<libc::c_int> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        let enabled: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            Err(error)
        } else {
            Ok(fd)
        }
    }
}

#[cfg(target_os = "linux")]
fn sockaddr_in(address: SocketAddr) -> libc::sockaddr_in {
    let IpAddr::V4(ip) = address.ip() else {
        unreachable!("IPv6 was rejected before raw packet construction")
    };
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    }
}

#[cfg(target_os = "linux")]
fn build_ipv4_packet(
    local: SocketAddr,
    peer: SocketAddr,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let total = 20usize
        .checked_add(20)
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or_else(|| "SNI desync packet length overflow".to_string())?;
    if total > u16::MAX as usize {
        return Err("SNI desync ClientHello is too large".into());
    }
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = libc::IPPROTO_TCP as u8;
    let IpAddr::V4(local_ip) = local.ip() else {
        unreachable!()
    };
    let IpAddr::V4(peer_ip) = peer.ip() else {
        unreachable!()
    };
    packet[12..16].copy_from_slice(&local_ip.octets());
    packet[16..20].copy_from_slice(&peer_ip.octets());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    {
        let tcp = &mut packet[20..40];
        tcp[..2].copy_from_slice(&local.port().to_be_bytes());
        tcp[2..4].copy_from_slice(&peer.port().to_be_bytes());
        tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&0u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x18; // ACK + PSH
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
    }
    packet[40..].copy_from_slice(payload);
    let checksum = tcp_checksum(local_ip, peer_ip, &packet[20..40], payload);
    packet[36..38].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

// Pure arithmetic, so it is built wherever the tests run and only *used* by
// the Linux sender; gating it to Linux too would leave the summation untested
// off that one platform.
#[cfg(any(target_os = "linux", test))]
fn tcp_checksum(
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    header: &[u8],
    payload: &[u8],
) -> u16 {
    // Summed in place rather than concatenated in front of a copy of the
    // ClientHello: twelve bytes of pseudo-header and a whole number of 16-bit
    // words of TCP header, so every join is a word boundary of the
    // concatenation and the partial sums add up to the whole. Only the payload
    // can end on an odd byte, and there the padded tail applies either way.
    let mut sum = checksum_add(0, &source.octets());
    sum = checksum_add(sum, &destination.octets());
    sum = checksum_add(sum, &[0, libc::IPPROTO_TCP as u8]);
    sum = checksum_add(sum, &((header.len() + payload.len()) as u16).to_be_bytes());
    sum = checksum_add(sum, header);
    checksum_finish(checksum_add(sum, payload))
}

#[cfg(any(target_os = "linux", test))]
fn internet_checksum(bytes: &[u8]) -> u16 {
    checksum_finish(checksum_add(0, bytes))
}

/// Add `bytes` to a running one's-complement sum of 16-bit big-endian words,
/// accumulated in the machine's own byte order and rotated back once by
/// [`checksum_finish`].
///
/// Folding a carry is reduction modulo 2^16 - 1, and in that modulus 2^16 == 1,
/// so 2^32 - 1 = (2^16 - 1)(2^16 + 1) means a 32-bit word read straight out of
/// the buffer already carries the residue of the two 16-bit words inside it:
/// one load and one add per four bytes, over eight accumulators.
///
/// Byte order falls out of the same argument. Swapping a word's halves is
/// multiplication by 2^8, which is its own inverse mod 2^16 - 1 and distributes
/// over a sum, so the native-order total is the native-order image of the sum
/// asked for and one swap on the 16-bit residue settles it: `rev` per word
/// becomes `rev` per packet.
///
/// Zero is the one value a residue class cannot decide, but a sum of
/// non-negative words is zero only if every byte was, and a swap preserves both
/// 0x0000 and 0xffff. Four bytes contribute at most 2^32, so 64 bits cannot
/// wrap for any segment that exists.
#[cfg(any(target_os = "linux", test))]
fn checksum_add(mut sum: u64, bytes: &[u8]) -> u64 {
    let (groups, rest) = bytes.as_chunks::<32>();
    let (mut a, mut b, mut c, mut d) = (0u64, 0u64, 0u64, 0u64);
    let (mut e, mut f, mut g, mut h) = (0u64, 0u64, 0u64, 0u64);
    for word in groups {
        a += u32::from_le_bytes([word[0], word[1], word[2], word[3]]) as u64;
        b += u32::from_le_bytes([word[4], word[5], word[6], word[7]]) as u64;
        c += u32::from_le_bytes([word[8], word[9], word[10], word[11]]) as u64;
        d += u32::from_le_bytes([word[12], word[13], word[14], word[15]]) as u64;
        e += u32::from_le_bytes([word[16], word[17], word[18], word[19]]) as u64;
        f += u32::from_le_bytes([word[20], word[21], word[22], word[23]]) as u64;
        g += u32::from_le_bytes([word[24], word[25], word[26], word[27]]) as u64;
        h += u32::from_le_bytes([word[28], word[29], word[30], word[31]]) as u64;
    }
    sum += ((a + b) + (c + d)) + ((e + f) + (g + h));
    let (words, tail) = rest.as_chunks::<4>();
    for word in words {
        sum += u32::from_le_bytes(*word) as u64;
    }
    let (pairs, odd) = tail.as_chunks::<2>();
    for pair in pairs {
        sum += u16::from_le_bytes(*pair) as u64;
    }
    if let [last] = odd {
        // A trailing odd byte is the high half of a zero-padded word, worth
        // `last << 8` big-endian and therefore `last` in this order.
        sum += *last as u64;
    }
    sum
}

#[cfg(any(target_os = "linux", test))]
fn checksum_finish(mut sum: u64) -> u16 {
    while sum > u16::MAX as u64 {
        sum = (sum & u16::MAX as u64) + (sum >> 16);
    }
    !((sum as u16).swap_bytes())
}

fn template_bytes() -> &'static [u8] {
    static TEMPLATE: OnceLock<Vec<u8>> = OnceLock::new();
    TEMPLATE.get_or_init(|| {
        let encoded = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5";
        (0..encoded.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&encoded[index..index + 2], 16).unwrap())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_hello_is_fixed_size_and_contains_the_requested_sni() {
        let hello = build_fake_client_hello("example.com").unwrap();
        assert_eq!(hello.len(), 517);
        let bytes = String::from_utf8_lossy(&hello);
        assert!(bytes.contains("example.com"));
    }

    #[test]
    fn fake_sni_is_bounded_and_rejects_controls() {
        assert!(build_fake_client_hello("").is_err());
        assert!(build_fake_client_hello(&"a".repeat(220)).is_err());
        assert!(build_fake_client_hello("bad\nname").is_err());
    }
}

#[cfg(test)]
mod checksum_equivalence {
    use super::{internet_checksum, tcp_checksum};

    /// What shipped: a buffer holding the pseudo-header and copies of the
    /// header and payload, summed with the carry folded after every word.
    fn reference_internet_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in bytes.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
            while sum > u16::MAX as u32 {
                sum = (sum & u16::MAX as u32) + (sum >> 16);
            }
        }
        !(sum as u16)
    }

    fn reference_tcp_checksum(
        source: std::net::Ipv4Addr,
        destination: std::net::Ipv4Addr,
        header: &[u8],
        payload: &[u8],
    ) -> u16 {
        let mut pseudo = Vec::with_capacity(12 + header.len() + payload.len());
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.extend_from_slice(&[0, libc::IPPROTO_TCP as u8]);
        pseudo.extend_from_slice(&((header.len() + payload.len()) as u16).to_be_bytes());
        pseudo.extend_from_slice(header);
        pseudo.extend_from_slice(payload);
        reference_internet_checksum(&pseudo)
    }

    #[test]
    fn the_sum_matches_the_per_word_fold_at_every_length() {
        for length in 0..=300usize {
            for mode in 0..5u8 {
                let bytes: Vec<u8> = (0..length)
                    .map(|index| match mode {
                        0 => 0xff,
                        1 => 0x00,
                        2 => index as u8,
                        3 => (index * 37 + 11) as u8,
                        _ => 0x80,
                    })
                    .collect();
                assert_eq!(
                    internet_checksum(&bytes),
                    reference_internet_checksum(&bytes),
                    "length {length} mode {mode}"
                );
            }
        }
        for length in [1000usize, 1472, 8127, 65_535] {
            for fill in [0u8, 0xff, 0x5a] {
                let bytes = vec![fill; length];
                assert_eq!(
                    internet_checksum(&bytes),
                    reference_internet_checksum(&bytes),
                    "{length}/{fill:#04x}"
                );
            }
        }
    }

    /// The split sum is only the concatenation's sum while every boundary is a
    /// word boundary, so this walks payloads of both parities over the TCP
    /// header shapes a socket can produce, with addresses that carry the
    /// pseudo-header sum out of the low word.
    #[test]
    fn the_tcp_checksum_matches_the_buffered_pseudo_header() {
        let sources = [
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            std::net::Ipv4Addr::new(255, 255, 255, 255),
            std::net::Ipv4Addr::new(0, 0, 0, 0),
        ];
        let destinations = [
            std::net::Ipv4Addr::new(203, 0, 113, 6),
            std::net::Ipv4Addr::new(255, 255, 255, 255),
        ];
        for source in sources {
            for destination in destinations {
                for header_len in [20usize, 24, 40] {
                    for payload_len in 0..=40usize {
                        let header: Vec<u8> =
                            (0..header_len).map(|index| (index * 7 + 3) as u8).collect();
                        let payload: Vec<u8> = (0..payload_len)
                            .map(|index| (index * 13 + 5) as u8)
                            .collect();
                        assert_eq!(
                            tcp_checksum(source, destination, &header, &payload),
                            reference_tcp_checksum(source, destination, &header, &payload),
                            "{source} -> {destination} {header_len}/{payload_len}"
                        );
                        let filled = vec![0xffu8; payload_len];
                        assert_eq!(
                            tcp_checksum(source, destination, &header, &filled),
                            reference_tcp_checksum(source, destination, &header, &filled),
                            "filled {header_len}/{payload_len}"
                        );
                    }
                }
            }
        }
    }
}
