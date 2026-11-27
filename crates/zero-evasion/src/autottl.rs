//! Learning how far away a server is, without root, so the TTL decoy knows
//! where to die.
//!
//! The TTL decoy ([`crate::decoy`], its `Fooling::Ttl`) hides a name by
//! sending a fake ClientHello with a hop limit low enough that it expires
//! between the filter and the server: the filter reads it, the server never
//! does. That only works at the right distance. Too low and the filter never
//! sees the decoy; too high and the server answers it and the real handshake
//! breaks. [`crate::decoy::DEFAULT_TTL`] is a blind guess at that distance,
//! the number the other userspace tools ship. This module measures it instead.
//!
//! # Measuring the distance without privileges
//!
//! A connected TCP socket does not hand userspace the TTL of the packets it
//! receives: the stream abstraction drops it (`IP_RECVTTL` on a TCP socket
//! delivers no such ancillary data — this was checked before the module was
//! built). An ICMP "ping" socket does. One echo request to the server, one
//! reply, and the reply's own TTL says how far it travelled: the initial TTL
//! is one of the well-known {64, 128, 255}, and `hops = initial - received`.
//! That is the whole of [`hop_count_guess`], and [`fake_from_hops`] turns the
//! distance into the hop limit the decoy is sent with. Both match zapret's
//! `hop_count_guess`/`autottl_eval` arithmetic.
//!
//! Such a socket needs no root where the caller's group id falls inside
//! `net.ipv4.ping_group_range`, which Android opens to every app and most
//! Linux ships open. [`supported`] checks it once.
//!
//! # What it assumes, and what happens when the assumption breaks
//!
//! The reply travels the *return* path, so this reads the distance back from
//! the server and takes the forward path to be about as long. Where the two
//! differ, or the server does not answer ICMP at all, no hop count is learned
//! and the decoy is simply not sent: [`crate::choice`] keeps the connection on
//! the urgent byte, as it would for any decoy that did not get through. A
//! wrong guess that *reached* the server would be worse, so [`fake_from_hops`]
//! refuses any value that is not strictly short of the measured distance.
//!
//! # How it is used
//!
//! [`fake_ttl`] is a cheap synchronous lookup against a small per-server
//! cache. On a miss it starts one background probe and returns `None` for now;
//! a later connection to the same server (there is always one, since the decoy
//! is only reached after the urgent byte has struck out twice —
//! [`crate::choice`]) finds the answer waiting. Measurements are kept for
//! [`FRESH`]; servers that did not answer are retried after [`RETRY`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The step the fake TTL sits from the hop count, zapret's
/// `--dpi-desync-autottl` default. Negative: the decoy has to die *before* the
/// server, so its hop limit is set one short of the server's distance.
const DELTA: i32 = -1;
/// The fake TTL is clamped between these. The floor keeps it above the handful
/// of hops to the filter, so the filter still reads the decoy; the ceiling
/// keeps a mismeasured faraway server from being handed a hop limit that could
/// reach it.
const MIN_TTL: u8 = 3;
const MAX_TTL: u8 = 20;

/// How long a measured distance is trusted before a new probe is started.
/// Routing to a given server barely moves, so this is generous.
const FRESH: Duration = Duration::from_secs(30 * 60);
/// A server that did not answer is retried sooner: it may answer later, or the
/// path may have changed, and the cost of asking again is one small packet.
const RETRY: Duration = Duration::from_secs(2 * 60);
/// Most servers remembered at once, as in [`crate::choice`]. The oldest are
/// forgotten first.
const MAX_SERVERS: usize = 256;

/// How far away a host is, from the TTL of a packet it sent: the initial TTL
/// is one of the well-known {64, 128, 255} and the distance is how far below
/// it the packet arrived. `None` for a TTL that matches none of them — a path
/// longer than 32 hops, or an initial value we do not know — where no guess is
/// safe. The exact ranges are zapret's `hop_count_guess`.
///
/// ```ignore
/// hop_count_guess(250) == Some(5)   // 255 - 250
/// hop_count_guess(50)  == Some(14)  // 64 - 50
/// hop_count_guess(10)  == None      // too far to tell
/// ```
///
/// Only the platforms that can read an echo reply's TTL call it; the tests
/// check the arithmetic everywhere.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn hop_count_guess(received: u8) -> Option<u8> {
    let initial: u8 = if received > 223 {
        255
    } else if received > 96 && received < 128 {
        128
    } else if received > 32 && received < 64 {
        64
    } else {
        return None;
    };
    Some(initial - received)
}

/// The hop limit a decoy is sent with to a server `hops` away, or `None` when
/// no safe value exists. It is the distance plus [`DELTA`] (one short of the
/// server), clamped to \[[`MIN_TTL`], [`MAX_TTL`]\]; `None` when the clamp
/// pulls it back up to the server's own distance, where the decoy would reach
/// the server and break the handshake. zapret's `autottl_eval`.
fn fake_from_hops(hops: u8) -> Option<u8> {
    let stepped = i32::from(hops) + DELTA;
    let fake = stepped.clamp(i32::from(MIN_TTL), i32::from(MAX_TTL)) as u8;
    // DELTA is negative: the fake TTL must stay strictly below the distance,
    // or the decoy reaches the server.
    (fake < hops).then_some(fake)
}

/// Whether this device can open an unprivileged ICMP ping socket, the one
/// thing the probe needs. False off Linux and Android, and where
/// `net.ipv4.ping_group_range` shuts the caller out.
pub fn supported() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        sys::ping_supported()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        false
    }
}

/// The hop limit to send a TTL decoy to `server` with, learned from the path,
/// or `None` when nothing is known yet. Cheap and synchronous: it reads a
/// cache and, on a miss or a stale entry, starts one background probe so the
/// next connection to `server` has the answer. A `None` now is not a failure,
/// only "ask again next time"; the caller falls back to the urgent byte.
pub fn fake_ttl(server: IpAddr) -> Option<u8> {
    let now = Instant::now();
    let (best, start_probe) = with_table(|table| match table.get_mut(&server) {
        Some(entry) => {
            entry.touched = now;
            let best = entry.best();
            // Stale and not already being refreshed: start one probe, but keep
            // handing out the old value until it lands (stale-while-revalidate).
            let start_probe = now >= entry.fresh_until && !entry.probing;
            if start_probe {
                entry.probing = true;
            }
            (best, start_probe)
        }
        None => {
            forget_oldest_if_full(table);
            table.insert(server, Entry::pending(now));
            (None, true)
        }
    });
    if start_probe {
        spawn_probe(server);
    }
    best
}

/// A learned distance to one server, kept with when it stops being trusted.
#[derive(Clone, Copy)]
enum Known {
    /// The server is this many hops away (measured).
    Hops(u8),
    /// The server did not answer an echo, or its reply's TTL fit no known
    /// initial value. Kept so it is not probed again at once.
    Unreachable,
}

struct Entry {
    /// The last measurement, or `None` while the first probe is still out.
    known: Option<Known>,
    /// After this the entry is stale: still returned, but a fresh probe is
    /// started to replace it.
    fresh_until: Instant,
    /// Last time this server was asked about; the oldest is forgotten first.
    touched: Instant,
    /// A probe for this server is in flight; do not start another.
    probing: bool,
}

impl Entry {
    /// A freshly inserted entry whose probe is about to be spawned.
    fn pending(now: Instant) -> Self {
        Self {
            known: None,
            fresh_until: now,
            touched: now,
            probing: true,
        }
    }

    /// The fake TTL this entry stands for right now, if any.
    fn best(&self) -> Option<u8> {
        match self.known {
            Some(Known::Hops(hops)) => fake_from_hops(hops),
            _ => None,
        }
    }
}

fn with_table<T>(f: impl FnOnce(&mut HashMap<IpAddr, Entry>) -> T) -> T {
    static SERVERS: Mutex<Option<HashMap<IpAddr, Entry>>> = Mutex::new(None);
    let mut guard = SERVERS.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(HashMap::new))
}

/// Drop the server heard of longest ago when the table is full, so a new one
/// has room. A no-op below the limit.
fn forget_oldest_if_full(table: &mut HashMap<IpAddr, Entry>) {
    if table.len() < MAX_SERVERS {
        return;
    }
    if let Some(oldest) = table
        .iter()
        .min_by_key(|(_, entry)| entry.touched)
        .map(|(ip, _)| *ip)
    {
        table.remove(&oldest);
    }
}

/// Write a completed probe's result back into the cache and clear the in-flight
/// flag, so the value is served and the server may be probed again when stale.
fn store(server: IpAddr, known: Known) {
    let now = Instant::now();
    let fresh_until = now
        + match known {
            Known::Hops(_) => FRESH,
            Known::Unreachable => RETRY,
        };
    with_table(|table| {
        let entry = table.entry(server).or_insert_with(|| Entry::pending(now));
        entry.known = Some(known);
        entry.fresh_until = fresh_until;
        entry.touched = now;
        entry.probing = false;
    });
}

/// Run one probe to `server` off the hot path and store what it learns. The
/// probe blocks (a short `recvmsg` wait), so it goes on the blocking pool.
/// Where there is no runtime to offload onto — only in tests of the cache —
/// the entry is left un-probed for a later call to retry.
fn spawn_probe(server: IpAddr) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn_blocking(move || {
                let known = match probe_hops(server) {
                    Some(hops) => Known::Hops(hops),
                    None => Known::Unreachable,
                };
                store(server, known);
            });
        }
        Err(_) => with_table(|table| {
            if let Some(entry) = table.get_mut(&server) {
                entry.probing = false;
            }
        }),
    }
}

/// One ICMP echo to `server`, turned into a hop count. `None` when nothing
/// answered or the reply's TTL fit no known initial value.
fn probe_hops(server: IpAddr) -> Option<u8> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        sys::echo_ttl(server).and_then(hop_count_guess)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = server;
        None
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod sys {
    //! The ICMP ping socket and its system calls. Everything unsafe in the
    //! module is here.

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::RawFd;
    use std::time::Duration;

    /// ICMP echo request types, not carried by `libc` for every target.
    const ICMP_ECHO: u8 = 8;
    const ICMPV6_ECHO_REQUEST: u8 = 128;
    /// How long to wait for the one reply before giving up. Generous for a
    /// lossy mobile line; a lost echo just means "unreachable for now".
    const REPLY_TIMEOUT: Duration = Duration::from_secs(2);

    /// A control buffer aligned the way the `CMSG_*` macros require. A plain
    /// `[u8; N]` is only byte-aligned, which is undefined to parse through them.
    #[repr(align(8))]
    struct Ctrl([u8; 64]);

    /// The handful of constants that differ between IPv4 and IPv6.
    struct Spec {
        family: libc::c_int,
        proto: libc::c_int,
        recv_level: libc::c_int,
        recv_opt: libc::c_int,
        cmsg_level: libc::c_int,
        cmsg_type: libc::c_int,
    }

    /// Whether an unprivileged ICMP ping socket can be opened at all. Asked
    /// once: the answer (set by `net.ipv4.ping_group_range`) cannot change
    /// while the process runs.
    pub(super) fn ping_supported() -> bool {
        static OK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *OK.get_or_init(|| {
            // SAFETY: open one ICMP datagram socket and, if it opened, close it
            // once. No pointers, no shared state.
            unsafe {
                let fd = libc::socket(
                    libc::AF_INET,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                    libc::IPPROTO_ICMP,
                );
                if fd < 0 {
                    return false;
                }
                libc::close(fd);
                true
            }
        })
    }

    /// Send one ICMP echo to `server` and return the TTL (hop limit) its reply
    /// arrived with, or `None` if nothing answered in time.
    pub(super) fn echo_ttl(server: IpAddr) -> Option<u8> {
        match server {
            IpAddr::V4(ip) => echo_ttl_v4(ip),
            IpAddr::V6(ip) => echo_ttl_v6(ip),
        }
    }

    fn echo_ttl_v4(ip: Ipv4Addr) -> Option<u8> {
        // SAFETY: a zeroed `sockaddr_storage` is a valid empty address, and it
        // is big enough for the `sockaddr_in` fields written through the cast.
        let mut dst: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = unsafe {
            let sa = std::ptr::addr_of_mut!(dst).cast::<libc::sockaddr_in>();
            (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
            (*sa).sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        };
        let mut request = [0u8; 8];
        request[0] = ICMP_ECHO;
        request[7] = 1; // sequence 1; the id is left 0 for the kernel to stamp
        let sum = checksum(&request);
        request[2..4].copy_from_slice(&sum.to_be_bytes());
        run(
            &Spec {
                family: libc::AF_INET,
                proto: libc::IPPROTO_ICMP,
                recv_level: libc::IPPROTO_IP,
                recv_opt: libc::IP_RECVTTL,
                cmsg_level: libc::IPPROTO_IP,
                cmsg_type: libc::IP_TTL,
            },
            &dst,
            len,
            &request,
        )
    }

    fn echo_ttl_v6(ip: Ipv6Addr) -> Option<u8> {
        // SAFETY: as above, for the `sockaddr_in6` fields.
        let mut dst: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = unsafe {
            let sa = std::ptr::addr_of_mut!(dst).cast::<libc::sockaddr_in6>();
            (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
            (*sa).sin6_addr = libc::in6_addr {
                s6_addr: ip.octets(),
            };
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        };
        let mut request = [0u8; 8];
        request[0] = ICMPV6_ECHO_REQUEST;
        request[7] = 1; // the kernel fills the ICMPv6 checksum for ping sockets
        run(
            &Spec {
                family: libc::AF_INET6,
                proto: libc::IPPROTO_ICMPV6,
                recv_level: libc::IPPROTO_IPV6,
                recv_opt: libc::IPV6_RECVHOPLIMIT,
                cmsg_level: libc::IPPROTO_IPV6,
                cmsg_type: libc::IPV6_HOPLIMIT,
            },
            &dst,
            len,
            &request,
        )
    }

    /// Open a ping socket of the family `spec` names, exchange one echo for one
    /// reply, and give back the reply's TTL. The socket is closed either way.
    fn run(
        spec: &Spec,
        dst: &libc::sockaddr_storage,
        dst_len: libc::socklen_t,
        request: &[u8],
    ) -> Option<u8> {
        // SAFETY: a datagram socket is opened and, on success, closed once.
        let fd = unsafe {
            libc::socket(
                spec.family,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                spec.proto,
            )
        };
        if fd < 0 {
            return None;
        }
        let ttl = exchange(fd, spec, dst, dst_len, request);
        // SAFETY: closing the socket opened just above, exactly once.
        unsafe { libc::close(fd) };
        ttl
    }

    /// On the open ping socket `fd`: ask for the reply's TTL, send the echo,
    /// then read the TTL back out of the reply's ancillary data. `None` on any
    /// refusal or when nothing answers within [`REPLY_TIMEOUT`].
    fn exchange(
        fd: RawFd,
        spec: &Spec,
        dst: &libc::sockaddr_storage,
        dst_len: libc::socklen_t,
        request: &[u8],
    ) -> Option<u8> {
        let on: libc::c_int = 1;
        let timeout = libc::timeval {
            tv_sec: REPLY_TIMEOUT.as_secs() as libc::time_t,
            tv_usec: 0,
        };
        let mut buf = [0u8; 64];
        let mut ctrl = Ctrl([0u8; 64]);
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: every pointer below refers to a local that outlives the call,
        // `fd` is open, and each size handed to the kernel matches its object.
        unsafe {
            libc::setsockopt(
                fd,
                spec.recv_level,
                spec.recv_opt,
                std::ptr::addr_of!(on).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(timeout).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
            if libc::sendto(
                fd,
                request.as_ptr().cast(),
                request.len(),
                0,
                std::ptr::addr_of!(*dst).cast(),
                dst_len,
            ) < 0
            {
                return None;
            }
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = std::ptr::addr_of_mut!(iov);
            msg.msg_iovlen = 1;
            msg.msg_control = ctrl.0.as_mut_ptr().cast();
            msg.msg_controllen = ctrl.0.len() as _;
            if libc::recvmsg(fd, std::ptr::addr_of_mut!(msg), 0) < 0 {
                return None;
            }
            let mut cmsg = libc::CMSG_FIRSTHDR(std::ptr::addr_of!(msg));
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == spec.cmsg_level && (*cmsg).cmsg_type == spec.cmsg_type {
                    let mut ttl: libc::c_int = 0;
                    std::ptr::copy_nonoverlapping(
                        libc::CMSG_DATA(cmsg),
                        std::ptr::addr_of_mut!(ttl).cast::<libc::c_uchar>(),
                        std::mem::size_of::<libc::c_int>(),
                    );
                    return u8::try_from(ttl).ok();
                }
                cmsg = libc::CMSG_NXTHDR(std::ptr::addr_of!(msg), cmsg);
            }
        }
        None
    }

    /// The 16-bit one's-complement checksum the ICMPv4 header carries, computed
    /// over the whole message with the checksum field left zero.
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        let (pairs, rest) = bytes.as_chunks::<2>();
        for pair in pairs {
            sum += u32::from(u16::from_be_bytes(*pair));
        }
        if let [odd] = rest {
            sum += u32::from(u16::from_be_bytes([*odd, 0]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// The distance is the gap below the nearest well-known initial TTL, and
    /// nothing is guessed where the TTL fits none of them.
    #[test]
    fn hop_count_from_a_well_known_initial_ttl() {
        assert_eq!(hop_count_guess(250), Some(5)); // 255 - 250
        assert_eq!(hop_count_guess(120), Some(8)); // 128 - 120
        assert_eq!(hop_count_guess(50), Some(14)); // 64 - 50
        assert_eq!(hop_count_guess(255), Some(0));
        // Boundaries and the unknowable: no guess.
        assert_eq!(hop_count_guess(64), None);
        assert_eq!(hop_count_guess(128), None);
        assert_eq!(hop_count_guess(32), None);
        assert_eq!(hop_count_guess(10), None); // a path over 32 hops
    }

    /// The fake TTL is one short of the server, clamped at both ends, and
    /// refused whenever it would not stay below the server's distance.
    #[test]
    fn the_fake_ttl_is_one_short_of_the_server_and_clamped() {
        assert_eq!(fake_from_hops(5), Some(4));
        assert_eq!(fake_from_hops(4), Some(3));
        // Clamp floor: too close to tell the filter from the server.
        assert_eq!(fake_from_hops(3), None);
        assert_eq!(fake_from_hops(2), None);
        assert_eq!(fake_from_hops(1), None);
        assert_eq!(fake_from_hops(0), None);
        // Clamp ceiling: a far server still gets a value well short of it.
        assert_eq!(fake_from_hops(25), Some(20));
        assert_eq!(fake_from_hops(21), Some(20));
        assert_eq!(fake_from_hops(20), Some(19));
    }

    /// A stored measurement is read straight back as a fake TTL, and a server
    /// known to be unreachable yields nothing.
    #[test]
    fn a_stored_measurement_is_read_back_without_probing() {
        let good = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        store(good, Known::Hops(10));
        assert_eq!(fake_ttl(good), fake_from_hops(10));
        assert_eq!(fake_ttl(good), Some(9));
        let bad = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        store(bad, Known::Unreachable);
        assert_eq!(fake_ttl(bad), None);
    }

    /// A full table forgets the server heard of longest ago to make room.
    #[test]
    fn a_full_table_forgets_its_oldest_server() {
        let mut table = HashMap::new();
        let base = Instant::now();
        for i in 0..MAX_SERVERS {
            let ip = IpAddr::V4(Ipv4Addr::new(203, 0, (i >> 8) as u8, (i & 0xff) as u8));
            table.insert(
                ip,
                Entry {
                    known: Some(Known::Hops(5)),
                    fresh_until: base,
                    touched: base + Duration::from_millis(i as u64),
                    probing: false,
                },
            );
        }
        assert_eq!(table.len(), MAX_SERVERS);
        forget_oldest_if_full(&mut table);
        assert_eq!(table.len(), MAX_SERVERS - 1);
        let oldest = IpAddr::V4(Ipv4Addr::new(203, 0, 0, 0));
        assert!(!table.contains_key(&oldest), "the oldest server is gone");
    }

    /// On a device with ICMP ping sockets, an echo to the loopback comes back
    /// carrying a TTL. Skipped where the sandbox forbids the socket, as a phone
    /// never would.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn an_echo_to_loopback_reports_a_ttl() {
        if !supported() {
            eprintln!("skipped: no unprivileged ICMP ping socket here");
            return;
        }
        let ttl = sys::echo_ttl(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(ttl.is_some(), "loopback answered an echo");
        assert!(ttl.unwrap() >= 1);
    }
}
