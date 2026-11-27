//! Listener socket options shared by every inbound.
//!
//! `SO_REUSEADDR` lets a new generation bind a port still in `TIME_WAIT` from
//! the old one, and `SO_REUSEPORT` (where available) lets both generations
//! hold the port at once so a reload never drops the listening socket. The
//! kernel load-balances accepted connections across the reuseport group, which
//! is the portable way to spread accept load across cores — deliberately in
//! preference to `SO_INCOMING_CPU`, which pins a socket to one fixed CPU and is
//! only correct when you open one socket per CPU.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

pub fn prepare_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    prepare_listener_with(addr, &ListenOptions::default())
}

/// What a listener asks of its socket beyond the shared defaults: Xray's
/// `sockopt` on an inbound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenOptions {
    /// `IPV6_V6ONLY` on an IPv6 wildcard listener: `Some(true)` leaves IPv4 to
    /// a listener of its own, `Some(false)` takes both, `None` the system's
    /// choice.
    pub v6_only: Option<bool>,
    /// Multipath TCP (IPPROTO_MPTCP), where the kernel has it; a kernel
    /// without it gets an ordinary TCP listener.
    pub mptcp: bool,
    /// `SO_MARK`, for policy routing of what the listener answers.
    pub mark: Option<u32>,
    /// `IP_TRANSPARENT`: accept connections addressed to other hosts, which
    /// is what TPROXY hands over.
    pub transparent: bool,
    /// Xray's `customSockopt`, applied to the listening socket.
    pub custom: Vec<zero_core::custom_sockopt::CustomSockopt>,
}

/// What to do to each connection a listener accepts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptedOptions {
    /// Seconds idle before keepalive probes start, and between probes. `None`
    /// leaves the system's; `Some((0, 0))` turns keepalive off.
    pub keepalive: Option<(u32, u32)>,
    /// `TCP_USER_TIMEOUT` in milliseconds.
    pub user_timeout_ms: Option<u32>,
    /// `TCP_WINDOW_CLAMP`: the largest receive window advertised.
    pub window_clamp: Option<u32>,
}

impl AcceptedOptions {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Apply `options` to an accepted connection. Each is best effort: a kernel
/// that refuses one does not lose the connection.
pub fn apply_accepted(stream: &tokio::net::TcpStream, options: &AcceptedOptions) {
    let socket = socket2::SockRef::from(stream);
    match options.keepalive {
        Some((0, 0)) => {
            let _ = socket.set_keepalive(false);
        }
        Some((idle, interval)) => {
            let keepalive =
                socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(idle.into()));
            #[cfg(any(
                target_os = "linux",
                target_os = "android",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "windows"
            ))]
            let keepalive =
                keepalive.with_interval(std::time::Duration::from_secs(interval.into()));
            #[cfg(not(any(
                target_os = "linux",
                target_os = "android",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "windows"
            )))]
            let _ = interval;
            let _ = socket.set_tcp_keepalive(&keepalive);
        }
        None => {}
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if let Some(ms) = options.user_timeout_ms {
            let _ = socket.set_tcp_user_timeout(Some(std::time::Duration::from_millis(ms.into())));
        }
        if let Some(clamp) = options.window_clamp {
            crate::dial::set_int_option(
                std::os::fd::AsRawFd::as_raw_fd(stream),
                libc::IPPROTO_TCP,
                libc::TCP_WINDOW_CLAMP,
                clamp as libc::c_int,
            );
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = options;
}

/// [`prepare_listener`] with `options`.
pub fn prepare_listener_with(addr: SocketAddr, options: &ListenOptions) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    // Multipath TCP is a different protocol number on the same socket type;
    // a kernel that does not know it refuses the socket, and the listener
    // is then made the ordinary way.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let mptcp = options
        .mptcp
        .then(|| Socket::new(domain, Type::STREAM, Some(Protocol::from(262))).ok())
        .flatten();
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let mptcp: Option<Socket> = None;
    let socket = match mptcp {
        Some(socket) => socket,
        None => Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?,
    };
    if addr.is_ipv6() {
        if let Some(only) = options.v6_only {
            socket.set_only_v6(only)?;
        }
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(mark) = options.mark {
        let _ = socket.set_mark(mark);
    }
    if options.transparent {
        crate::transparent::set_transparent(&socket, addr.is_ipv6())?;
    }
    if !options.custom.is_empty() {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let network = if addr.is_ipv6() { "tcp6" } else { "tcp4" };
            zero_core::custom_sockopt::apply(socket.as_raw_fd(), network, &options.custom)?;
        }
    }
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    {
        let _ = socket.set_reuse_port(true);
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wildcard IPv6 listener takes IPv4 connections too, unless it is told
    /// to be IPv6 only. (A machine with no IPv6 at all cannot run this.)
    #[tokio::test]
    async fn v6_only_decides_whether_a_wildcard_listener_takes_ipv4() {
        for (v6_only, v4_gets_in) in [(false, true), (true, false)] {
            let Ok(listener) = prepare_listener_with(
                "[::]:0".parse().unwrap(),
                &ListenOptions {
                    v6_only: Some(v6_only),
                    ..ListenOptions::default()
                },
            ) else {
                return;
            };
            let port = listener.local_addr().unwrap().port();
            let reached = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::net::TcpStream::connect(("127.0.0.1", port)),
            )
            .await;
            assert_eq!(
                matches!(reached, Ok(Ok(_))),
                v4_gets_in,
                "v6_only = {v6_only}"
            );
        }
    }

    #[tokio::test]
    async fn a_listener_that_asks_for_multipath_tcp_still_listens() {
        let listener = prepare_listener_with(
            "127.0.0.1:0".parse().unwrap(),
            &ListenOptions {
                mptcp: true,
                ..ListenOptions::default()
            },
        )
        .unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok());
    }
}
