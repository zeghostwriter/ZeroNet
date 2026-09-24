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
    let socket = Socket::new(
        if addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        },
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
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
