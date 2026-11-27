//! TCP dialing with candidate racing.
//!
//! Two rules from the research are structural here:
//!
//! * Only the raw TCP connect is raced. TLS and REALITY run exactly once, on
//!   the winning socket — racing cryptographic handshakes wastes handshakes
//!   and multiplies the server-visible fingerprint (RESEARCH-01 §26).
//! * Losing attempts are cancelled in place by dropping their futures rather
//!   than detached, so dropping the dial future cannot leak sockets.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::net::TcpStream;
use zero_core::{Failure, Stage};

/// How candidates are ordered and raced.
#[derive(Debug, Clone, Copy)]
pub struct RacePolicy {
    /// Delay before starting the next candidate.
    pub try_delay: Duration,
    pub prioritize_ipv6: bool,
    /// Address-family chunk size when interleaving; `0` exhausts the
    /// preferred family first.
    pub interleave: u32,
    pub max_concurrent: u32,
    pub connect_timeout: Duration,
}

impl Default for RacePolicy {
    fn default() -> Self {
        Self {
            try_delay: Duration::from_millis(250),
            prioritize_ipv6: false,
            interleave: 2,
            max_concurrent: 4,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Socket-level options applied before connect.
#[derive(Debug, Clone, Default)]
pub struct SocketOptions {
    pub tcp_fast_open: bool,
    pub mark: Option<u32>,
    pub bind_interface: Option<String>,
    /// Xray's `customSockopt`, applied to each socket before it connects.
    pub custom: Vec<zero_core::custom_sockopt::CustomSockopt>,
    /// The local address to connect from (Xray's `sendThrough`), used for
    /// candidates of its own IP family.
    pub bind_address: Option<std::net::IpAddr>,
    pub send_buffer: Option<usize>,
    pub recv_buffer: Option<usize>,
    /// Named TCP congestion algorithm (`TCP_CONGESTION`). A name the kernel
    /// does not know is declined at `setsockopt` time and the dial continues
    /// on the system default — the same contract Xray offers, and the only
    /// honest one for a config that can outlive the kernel it lands on.
    pub tcp_congestion: Option<String>,
    /// Seconds idle before keepalive probes begin, and between probes (Xray's
    /// `tcpKeepAliveIdle` and `tcpKeepAliveInterval`). `None` is the
    /// built-in 45 and 45; `Some((0, 0))` turns keepalive off.
    pub keepalive: Option<(u32, u32)>,
    /// `TCP_USER_TIMEOUT` in milliseconds: how long unacknowledged data may
    /// sit before the connection is given up on.
    pub user_timeout_ms: Option<u32>,
    /// `TCP_WINDOW_CLAMP`: the largest receive window advertised.
    pub window_clamp: Option<u32>,
    /// `TCP_MAXSEG`: the segment size to send.
    pub max_seg: Option<u32>,
    /// Multipath TCP, where the kernel has it (Linux 5.6 and later): the
    /// connection may use several paths at once and survives losing one. A
    /// kernel without it gets an ordinary TCP socket.
    pub mptcp: bool,
    /// Asked about each candidate before it is dialled: `true` puts the
    /// ClientHello in the SYN (TCP Fast Open, see [`crate::fastopen`]). The
    /// answer comes from the caller's memory of what worked towards that
    /// server; `None` never uses Fast Open.
    pub fast_open_if: Option<fn(SocketAddr) -> bool>,
}

/// Order candidates by address family according to the policy.
///
/// This is Happy Eyeballs generalised: rather than strictly alternating, the
/// preferred family gets `interleave` slots per alternate slot, which keeps a
/// working family dominant while still probing the other.
pub fn order_candidates(addrs: &[SocketAddr], policy: &RacePolicy) -> Vec<SocketAddr> {
    let (v6, v4): (Vec<_>, Vec<_>) = addrs.iter().partition(|a| a.is_ipv6());
    let (preferred, alternate) = if policy.prioritize_ipv6 {
        (v6, v4)
    } else {
        (v4, v6)
    };

    if policy.interleave == 0 {
        return preferred.into_iter().chain(alternate).collect();
    }

    let mut out = Vec::with_capacity(addrs.len());
    let mut p = preferred.into_iter().peekable();
    let mut a = alternate.into_iter().peekable();
    while p.peek().is_some() || a.peek().is_some() {
        for _ in 0..policy.interleave {
            match p.next() {
                Some(x) => out.push(x),
                None => break,
            }
        }
        if let Some(x) = a.next() {
            out.push(x);
        }
    }
    out
}

/// The result of a successful dial.
#[derive(Debug)]
pub struct Dialed {
    pub stream: TcpStream,
    pub addr: SocketAddr,
    pub elapsed: Duration,
    /// How many candidates were started before one succeeded.
    pub attempts: usize,
}

/// Race TCP connects across ordered candidates.
pub async fn dial_tcp(
    addrs: &[SocketAddr],
    policy: &RacePolicy,
    opts: &SocketOptions,
) -> Result<Dialed, Failure> {
    if addrs.is_empty() {
        return Err(
            Failure::new(zero_core::FailureKind::TcpUnreachable, Stage::Resolving)
                .with_detail("no candidate addresses"),
        );
    }

    let started = Instant::now();
    let ordered = order_candidates(addrs, policy);
    let max_concurrent = policy.max_concurrent.max(1) as usize;

    let mut pending = FuturesUnordered::new();
    let mut next = 0usize;
    let mut started_count = 0usize;
    // Every candidate's failure, in the order they came back.
    let mut failures: Vec<(SocketAddr, Failure)> = Vec::new();

    loop {
        // Top up in-flight attempts.
        if pending.len() < max_concurrent && next < ordered.len() {
            let addr = ordered[next];
            next += 1;
            started_count += 1;
            let timeout = policy.connect_timeout;
            // The attempt futures borrow `opts` rather than cloning it (and
            // its strings) per candidate; they never outlive this call.
            pending.push(async move {
                let r = connect_one(addr, opts, timeout).await;
                (addr, r)
            });
        }

        if pending.is_empty() {
            return Err(all_failed(failures));
        }

        // The stagger only matters while there is both a candidate left and a
        // free slot to start it in. Arming it with every slot busy made the
        // loop wake every `try_delay` for nothing — and with `tryDelayMs: 0`
        // spin at 100% CPU until an attempt finished.
        let more_to_start = next < ordered.len() && pending.len() < max_concurrent;
        let stagger = tokio::time::sleep(policy.try_delay);

        tokio::select! {
            biased;

            Some((addr, result)) = pending.next() => {
                match result {
                    Ok(stream) => {
                        return Ok(Dialed {
                            stream,
                            addr,
                            elapsed: started.elapsed(),
                            attempts: started_count,
                        });
                    }
                    Err(f) => {
                        // A fast failure frees a slot; the loop starts the next
                        // candidate immediately rather than waiting out the stagger.
                        failures.push((addr, f));
                    }
                }
            }

            _ = stagger, if more_to_start => {}
        }
    }
}

/// The one failure to report when every candidate failed, naming them all.
///
/// A server name usually has both an IPv4 and an IPv6 address, and a network
/// without IPv6 refuses the second at once with "network is unreachable";
/// reporting only the last failure would show that, and hide that the IPv4
/// attempt failed for another reason. So the failure that classifies the
/// result is the first one that is not a plain unreachable (or the first
/// at all), and its detail lists every address with what happened to it.
fn all_failed(failures: Vec<(SocketAddr, Failure)>) -> Failure {
    let Some(chosen) = failures
        .iter()
        .find(|(_, failure)| failure.kind != zero_core::FailureKind::TcpUnreachable)
        .or_else(|| failures.first())
        .map(|(_, failure)| failure.clone())
    else {
        return Failure::new(
            zero_core::FailureKind::TcpUnreachable,
            Stage::SocketConnected,
        )
        .with_detail("all candidates failed");
    };
    if failures.len() < 2 {
        return chosen;
    }
    let listed = failures
        .iter()
        .map(|(addr, failure)| {
            format!(
                "{addr}: {}",
                failure.detail.as_deref().unwrap_or("no detail")
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let own = chosen.detail.clone().unwrap_or_default();
    chosen.with_detail(format!("{own} (every address tried: {listed})"))
}

async fn connect_one(
    addr: SocketAddr,
    opts: &SocketOptions,
    timeout: Duration,
) -> Result<TcpStream, Failure> {
    let fut = async {
        let stream = connect_stream(addr, opts).await?;
        // Keepalive only after the race is won: the losers never need it.
        set_keepalive(&stream, opts.keepalive);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(ms) = opts.user_timeout_ms {
            let _ = socket2::SockRef::from(&stream)
                .set_tcp_user_timeout(Some(Duration::from_millis(ms.into())));
        }
        let _ = stream.set_nodelay(true);
        #[cfg(target_os = "linux")]
        {
            let _ = socket2::SockRef::from(&stream).set_quickack(true);
        }
        Ok(stream)
    };

    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(Failure::from_io(&e, Stage::SocketConnected)),
        Err(_) => Err(
            Failure::new(zero_core::FailureKind::TcpTimeout, Stage::SocketConnected)
                .with_confidence(zero_core::Confidence::Likely)
                .with_elapsed(timeout),
        ),
    }
}

/// One connected (or, for Fast Open, ready-to-connect) socket to `addr`.
///
/// With Fast Open wanted, the first connect to a server only fetches the
/// cookie and is an ordinary handshake, which would show the name; it is
/// dropped and the dial repeated, now with the cookie held. A server that
/// still gives no deferred connect does not do Fast Open: the plain
/// connection is kept and the caller sees it is not deferred.
async fn connect_stream(addr: SocketAddr, opts: &SocketOptions) -> io::Result<TcpStream> {
    let fast = opts.fast_open_if.is_some_and(|wanted| wanted(addr)) && crate::fastopen::supported();
    for round in 0..if fast { 2 } else { 1 } {
        let socket = new_socket(addr, opts)?;
        if fast {
            crate::fastopen::enable(&socket)?;
        }
        let stream = socket.connect(addr).await?;
        if !fast || crate::fastopen::deferred(&stream) {
            if fast {
                crate::fastopen::register(&stream, addr);
            }
            return Ok(stream);
        }
        if round == 1 {
            return Ok(stream);
        }
    }
    unreachable!("the loop returns on its last round")
}

fn new_socket(addr: SocketAddr, opts: &SocketOptions) -> io::Result<tokio::net::TcpSocket> {
    let socket = match multipath_socket(addr, opts) {
        Some(socket) => socket,
        None if addr.is_ipv4() => tokio::net::TcpSocket::new_v4()?,
        None => tokio::net::TcpSocket::new_v6()?,
    };

    // Before anything else, and before connect: on a mobile VPN an
    // unprotected socket routes back into the tunnel this process is serving.
    // A failure here fails the dial, which is correct — the alternative is a
    // connection that cannot work (zero_core::platform).
    zero_core::protect_socket(&socket)?;
    zero_core::path_mss::apply(&socket);
    zero_core::platform::bound_dead_connection(&socket);

    if let Some(sz) = opts.send_buffer {
        let _ = socket.set_send_buffer_size(u32::try_from(sz).unwrap_or(u32::MAX));
    }
    if let Some(sz) = opts.recv_buffer {
        let _ = socket.set_recv_buffer_size(u32::try_from(sz).unwrap_or(u32::MAX));
    }

    if let Some(ip) = opts
        .bind_address
        .filter(|ip| ip.is_ipv4() == addr.is_ipv4())
    {
        socket.bind(SocketAddr::new(ip, 0))?;
    }

    // SO_MARK and SO_BINDTODEVICE exist on Android too, where routing marks
    // are exactly how a VPN app keeps its own traffic out of its tunnel.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let s = socket2::SockRef::from(&socket);
        if let Some(mark) = opts.mark {
            let _ = s.set_mark(mark);
        }
        if let Some(iface) = &opts.bind_interface {
            let _ = s.bind_device(Some(iface.as_bytes()));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if !opts.custom.is_empty() {
        use std::os::fd::AsRawFd;
        let network = if addr.is_ipv4() { "tcp4" } else { "tcp6" };
        zero_core::custom_sockopt::apply(socket.as_raw_fd(), network, &opts.custom)?;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        if let Some(name) = &opts.tcp_congestion {
            set_tcp_congestion(socket.as_raw_fd(), name);
        }
        if let Some(clamp) = opts.window_clamp {
            set_int_option(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_WINDOW_CLAMP,
                clamp as libc::c_int,
            );
        }
        if let Some(segment) = opts.max_seg {
            set_int_option(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                segment as libc::c_int,
            );
        }
    }

    Ok(socket)
}

/// A Multipath TCP socket for `addr`, when the options ask for one and the
/// kernel has it; `None` otherwise, and the caller makes an ordinary one.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn multipath_socket(addr: SocketAddr, opts: &SocketOptions) -> Option<tokio::net::TcpSocket> {
    use std::os::fd::{FromRawFd, IntoRawFd};
    if !opts.mptcp {
        return None;
    }
    // IPPROTO_MPTCP is 262; socket2 has no name for it.
    let socket = socket2::Socket::new(
        if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::from(262)),
    )
    .ok()?;
    socket.set_nonblocking(true).ok()?;
    // SAFETY: the descriptor is a fresh, open TCP-type socket whose only
    // owner is handed over here.
    Some(unsafe { tokio::net::TcpSocket::from_raw_fd(socket.into_raw_fd()) })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn multipath_socket(_addr: SocketAddr, _opts: &SocketOptions) -> Option<tokio::net::TcpSocket> {
    None
}

/// An integer-valued socket option, best effort.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn set_int_option(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) {
    // SAFETY: `fd` is a live socket, the option takes an int, and the value
    // lives for the call.
    unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// TCP keepalive with Xray's defaults (Chrome's: 45 s idle, 45 s interval).
///
/// A proxied connection can sit idle for minutes — an SSH session, a
/// long-poll, a mux carrier between bursts. Without keepalive a peer that
/// vanished (or a NAT mapping that expired) is only noticed on the next
/// write, and an idle flow's NAT/conntrack entry is allowed to age out.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(45);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(45);

fn set_keepalive(stream: &TcpStream, setting: Option<(u32, u32)>) {
    let (idle, interval) = match setting {
        Some((0, 0)) => {
            let _ = socket2::SockRef::from(stream).set_keepalive(false);
            return;
        }
        Some((idle, interval)) => (
            Duration::from_secs(idle.into()),
            Duration::from_secs(interval.into()),
        ),
        None => (KEEPALIVE_IDLE, KEEPALIVE_INTERVAL),
    };
    let keepalive = socket2::TcpKeepalive::new().with_time(idle);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    let keepalive = keepalive.with_interval(interval);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    let _ = interval;
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

/// Set `TCP_CONGESTION` by name.
///
/// A rejection is not a dial failure: the kernel is the authority on which
/// algorithms exist, a config can name one this kernel was never built with,
/// and any congestion control still beats no connection. The refusal is
/// logged once per process rather than once per dial, because a retrying
/// client would otherwise print it thousands of times a minute.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_tcp_congestion(fd: std::os::fd::RawFd, name: &str) {
    use std::sync::atomic::{AtomicBool, Ordering};

    let Ok(c_name) = std::ffi::CString::new(name) else {
        static WARNED_BAD_NAME: AtomicBool = AtomicBool::new(false);
        if !WARNED_BAD_NAME.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                congestion = name,
                "TCP congestion name contains an interior NUL; leaving the system default"
            );
        }
        return;
    };

    // SAFETY: `fd` is a live socket we own, TCP_CONGESTION is a
    // string-valued TCP-level sockopt, and the buffer outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            c_name.as_ptr().cast(),
            c_name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        static WARNED: AtomicBool = AtomicBool::new(false);
        if !WARNED.swap(true, Ordering::Relaxed) {
            let err = std::io::Error::last_os_error();
            tracing::warn!(
                congestion = name,
                error = %err,
                "kernel declined the requested TCP congestion control; dials continue on the system default"
            );
        }
    }
}

/// Split resolved addresses into an ordered candidate list for a port.
pub fn candidates(ips: &[IpAddr], port: u16) -> Vec<SocketAddr> {
    ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn a_failed_dial_names_every_address_it_tried() {
        // Two ports nothing listens on: both refuse, and the report says so
        // for each, not just for the last one to come back.
        let free = || {
            let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap()
        };
        let (first, second) = (free(), free());
        let failure = dial_tcp(
            &[first, second],
            &RacePolicy::default(),
            &SocketOptions::default(),
        )
        .await
        .expect_err("nothing listens there");
        let detail = failure.detail.unwrap_or_default();
        assert!(detail.contains(&first.to_string()), "{detail}");
        assert!(detail.contains(&second.to_string()), "{detail}");
        // A single candidate keeps its own failure unchanged.
        let single = dial_tcp(&[free()], &RacePolicy::default(), &SocketOptions::default())
            .await
            .expect_err("nothing listens there");
        assert!(!single.detail.unwrap_or_default().contains("every address"));
    }

    #[test]
    fn interleaves_two_v4_per_v6_by_default() {
        let addrs = vec![
            sa("1.1.1.1:443"),
            sa("2.2.2.2:443"),
            sa("3.3.3.3:443"),
            sa("[::1]:443"),
            sa("[::2]:443"),
        ];
        let ordered = order_candidates(&addrs, &RacePolicy::default());
        assert_eq!(ordered[0], sa("1.1.1.1:443"));
        assert_eq!(ordered[1], sa("2.2.2.2:443"));
        assert_eq!(ordered[2], sa("[::1]:443"));
        assert_eq!(ordered[3], sa("3.3.3.3:443"));
    }

    #[test]
    fn interleave_zero_exhausts_preferred_family() {
        let addrs = vec![sa("1.1.1.1:443"), sa("[::1]:443"), sa("2.2.2.2:443")];
        let p = RacePolicy {
            interleave: 0,
            ..Default::default()
        };
        let ordered = order_candidates(&addrs, &p);
        assert!(ordered[0].is_ipv4() && ordered[1].is_ipv4());
        assert!(ordered[2].is_ipv6());
    }

    #[test]
    fn prioritize_ipv6_flips_preference() {
        let addrs = vec![sa("1.1.1.1:443"), sa("[::1]:443")];
        let p = RacePolicy {
            prioritize_ipv6: true,
            ..Default::default()
        };
        assert!(order_candidates(&addrs, &p)[0].is_ipv6());
    }

    #[test]
    fn ordering_preserves_all_candidates() {
        let addrs = vec![
            sa("1.1.1.1:443"),
            sa("[::1]:443"),
            sa("2.2.2.2:443"),
            sa("[::2]:443"),
            sa("3.3.3.3:443"),
        ];
        assert_eq!(
            order_candidates(&addrs, &RacePolicy::default()).len(),
            addrs.len()
        );
    }

    #[tokio::test]
    async fn empty_candidates_fail_fast() {
        let err = dial_tcp(&[], &RacePolicy::default(), &SocketOptions::default())
            .await
            .unwrap_err();
        assert_eq!(err.kind, zero_core::FailureKind::TcpUnreachable);
    }

    #[tokio::test]
    async fn connects_to_a_live_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let d = dial_tcp(&[addr], &RacePolicy::default(), &SocketOptions::default())
            .await
            .unwrap();
        assert_eq!(d.addr, addr);
        assert_eq!(d.attempts, 1);
    }

    #[tokio::test]
    async fn falls_through_dead_candidate_to_live_one() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        // Port 1 on loopback refuses immediately.
        let dead = sa("127.0.0.1:1");
        let policy = RacePolicy {
            try_delay: Duration::from_millis(20),
            ..Default::default()
        };
        let d = dial_tcp(&[dead, good], &policy, &SocketOptions::default())
            .await
            .unwrap();
        assert_eq!(d.addr, good);
    }

    /// A listener on loopback that accepts one connection and holds it.
    async fn listening() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _held = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        addr
    }

    #[tokio::test]
    async fn keepalive_can_be_set_or_turned_off() {
        let addr = listening().await;
        let options = SocketOptions {
            keepalive: Some((20, 7)),
            ..SocketOptions::default()
        };
        let d = dial_tcp(&[addr], &RacePolicy::default(), &options)
            .await
            .unwrap();
        let sock = socket2::SockRef::from(&d.stream);
        assert!(sock.keepalive().unwrap());
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            assert_eq!(sock.keepalive_time().unwrap(), Duration::from_secs(20));
            assert_eq!(sock.keepalive_interval().unwrap(), Duration::from_secs(7));
        }
        let addr = listening().await;
        let options = SocketOptions {
            keepalive: Some((0, 0)),
            ..SocketOptions::default()
        };
        let d = dial_tcp(&[addr], &RacePolicy::default(), &options)
            .await
            .unwrap();
        assert!(!socket2::SockRef::from(&d.stream).keepalive().unwrap());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn user_timeout_window_clamp_and_segment_size_reach_the_socket() {
        let addr = listening().await;
        let options = SocketOptions {
            user_timeout_ms: Some(12_000),
            window_clamp: Some(70_000),
            max_seg: Some(1200),
            ..SocketOptions::default()
        };
        let d = dial_tcp(&[addr], &RacePolicy::default(), &options)
            .await
            .unwrap();
        let sock = socket2::SockRef::from(&d.stream);
        assert_eq!(
            sock.tcp_user_timeout().unwrap(),
            Some(Duration::from_millis(12_000))
        );
        // The kernel keeps the clamp as set, or a little below it.
        let mut clamp: libc::c_int = 0;
        let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: a live socket, an int-valued option and a matching buffer.
        let rc = unsafe {
            libc::getsockopt(
                std::os::fd::AsRawFd::as_raw_fd(&d.stream),
                libc::IPPROTO_TCP,
                libc::TCP_WINDOW_CLAMP,
                std::ptr::addr_of_mut!(clamp).cast(),
                &mut size,
            )
        };
        assert_eq!(rc, 0);
        assert!((60_000..=70_000).contains(&clamp), "clamp {clamp}");
        assert!(sock.mss().unwrap() <= 1200, "mss {}", sock.mss().unwrap());
    }

    /// Multipath TCP when the kernel has it: either way the dial works, and
    /// the socket says which protocol it is.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn multipath_tcp_is_used_when_there_is_a_kernel_for_it_and_never_blocks_a_dial() {
        let addr = listening().await;
        let options = SocketOptions {
            mptcp: true,
            ..SocketOptions::default()
        };
        let d = dial_tcp(&[addr], &RacePolicy::default(), &options)
            .await
            .unwrap();
        let protocol = socket2::SockRef::from(&d.stream).protocol().unwrap();
        let supported = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::from(262)),
        )
        .is_ok();
        let expected = if supported { 262 } else { 6 };
        assert_eq!(protocol.map(i32::from), Some(expected));
    }

    #[tokio::test]
    async fn dialed_sockets_have_nodelay_and_keepalive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let d = dial_tcp(&[addr], &RacePolicy::default(), &SocketOptions::default())
            .await
            .unwrap();
        assert!(d.stream.nodelay().unwrap());
        let sock = socket2::SockRef::from(&d.stream);
        assert!(sock.keepalive().unwrap());
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(sock.keepalive_time().unwrap(), KEEPALIVE_IDLE);
    }

    /// With every slot busy the stagger timer must not be armed. Before the
    /// fix, `try_delay: 0` turned this wait into a busy loop; the observable
    /// symptom here is that a zero-delay race over more candidates than
    /// slots still completes normally once the slow attempt resolves.
    #[tokio::test]
    async fn zero_try_delay_with_full_slots_still_races_correctly() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        let policy = RacePolicy {
            try_delay: Duration::ZERO,
            max_concurrent: 1,
            ..Default::default()
        };
        let dead = sa("127.0.0.1:1");
        let d = dial_tcp(&[dead, dead, good], &policy, &SocketOptions::default())
            .await
            .unwrap();
        assert_eq!(d.addr, good);
        assert_eq!(d.attempts, 3);
    }

    /// Read back the kernel's current `TCP_CONGESTION` for a socket.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn current_congestion(socket: &tokio::net::TcpSocket) -> String {
        use std::os::fd::AsRawFd;
        let mut buf = [0u8; 64];
        let mut len = buf.len() as libc::socklen_t;
        // SAFETY: the socket is alive, and `buf`/`len` are valid out-params
        // for the string-valued sockopt the kernel writes back.
        let rc = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_CONGESTION,
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt(TCP_CONGESTION) failed");
        String::from_utf8_lossy(&buf[..len as usize])
            .trim_end_matches('\0')
            .to_string()
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_named_congestion_control_reaches_the_kernel() {
        let opts = SocketOptions {
            tcp_congestion: Some("cubic".to_string()),
            ..Default::default()
        };
        let socket = new_socket(sa("127.0.0.1:443"), &opts).expect("socket must build");
        // Only assert the swap when the kernel can express it at all: a
        // config may name an algorithm this kernel was not built with, and
        // the contract there is "declined, dial continues".
        let available =
            std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")
                .unwrap_or_default();
        if available.split_whitespace().any(|a| a == "cubic") {
            assert_eq!(current_congestion(&socket), "cubic");
        } else {
            assert!(!current_congestion(&socket).is_empty());
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn an_unknown_congestion_control_is_declined_but_not_fatal() {
        let opts = SocketOptions {
            tcp_congestion: Some("zray-no-such-congestion-control".to_string()),
            ..Default::default()
        };
        let socket = new_socket(sa("127.0.0.1:443"), &opts)
            .expect("an unknown congestion name must not fail the socket");
        assert!(!current_congestion(&socket).is_empty());
    }

    /// Towards a server that does no Fast Open the dial still ends in a
    /// connection (an ordinary one, since the cookie never comes), and the
    /// caller can see it is not deferred.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn a_server_without_fast_open_gets_an_ordinary_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let opts = SocketOptions {
            fast_open_if: Some(|_| true),
            ..Default::default()
        };
        let accepting = tokio::spawn(async move {
            // The throwaway connection and the one that is kept.
            let _first = listener.accept().await.unwrap();
            let _second = listener.accept().await.unwrap();
        });
        let dialed = dial_tcp(&[addr], &RacePolicy::default(), &opts)
            .await
            .expect("must connect");
        assert!(!crate::fastopen::deferred(&dialed.stream));
        assert_eq!(dialed.stream.peer_addr().unwrap(), addr);
        if crate::fastopen::supported() {
            accepting.await.unwrap();
        }
    }
}
