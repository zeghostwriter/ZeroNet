//! TCP Fast Open, used to keep the ClientHello out of the filter's sight.
//!
//! A TCP Fast Open (TFO) client that holds a cookie from the server puts its
//! first bytes in the SYN itself. A filter that reads server names out of the
//! stream after the handshake, and does not look at data riding in the SYN,
//! never sees the name: the server does, and answers as usual.
//!
//! ```text
//! plain      SYN ->  <- SYN/ACK  ACK ->  ClientHello(name) ->     the filter reads the name
//! fast open  SYN + ClientHello(name) ->  <- SYN/ACK + ServerHello  the filter reads no name
//! ```
//!
//! It costs nothing (it saves a round trip) and needs no privilege, only a
//! kernel with `TCP_FASTOPEN_CONNECT` (Linux 4.11, Android 10 kernels and
//! later) and a server that does TFO (Google's and Cloudflare's edges do).
//!
//! How it works on a socket: with `TCP_FASTOPEN_CONNECT` set and a cookie
//! cached for the destination, `connect()` returns at once and sends nothing;
//! the SYN leaves with the first `write()`. Without a cookie `connect()` is an
//! ordinary handshake that asks the server for one, so the *first* connection
//! to a server cannot hide anything: [`crate::dial`] makes that one a
//! throwaway and connects again.
//!
//! The thing that would surprise a newcomer: a socket whose connect is
//! deferred has no peer yet (`peer_addr()` fails with `ENOTCONN`) and sends
//! nothing until written to, so a protocol where the *server* speaks first
//! would wait forever. Callers therefore use it only towards ports where the client speaks first
//! ([`client_first_port`]).

#[cfg(any(target_os = "linux", target_os = "android"))]
mod sys {
    use std::collections::VecDeque;
    use std::io;
    use std::net::SocketAddr;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use tokio::net::{TcpSocket, TcpStream};

    /// `TCP_SYN_SENT` in `tcp_info.tcpi_state`.
    const SYN_SENT: u8 = 2;
    /// How long a deferred socket's peer is remembered, and how many are.
    const PEER_TTL: Duration = Duration::from_secs(60);
    const PEER_CAP: usize = 128;

    fn set_connect(fd: RawFd) -> io::Result<()> {
        let on: libc::c_int = 1;
        // SAFETY: `fd` is a live socket, the option takes an int and `on`
        // outlives the call.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN_CONNECT,
                std::ptr::from_ref(&on).cast(),
                std::mem::size_of_val(&on) as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Whether this kernel lets a client use Fast Open: asked once, by
    /// setting the option on a throwaway socket. Kernels refuse it when the
    /// client side of `net.ipv4.tcp_fastopen` is off.
    pub fn supported() -> bool {
        static STATE: AtomicU8 = AtomicU8::new(0);
        match STATE.load(Ordering::Relaxed) {
            1 => return true,
            2 => return false,
            _ => {}
        }
        // SAFETY: plain socket(2); the result is checked and closed below.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let ok = fd >= 0 && set_connect(fd).is_ok();
        if fd >= 0 {
            // SAFETY: `fd` was just opened here and is not used again.
            unsafe { libc::close(fd) };
        }
        STATE.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
        ok
    }

    pub fn enable(socket: &TcpSocket) -> io::Result<()> {
        set_connect(socket.as_raw_fd())
    }

    /// Whether `stream` is connected "later": Fast Open is on, the kernel
    /// held the SYN back for the first write, and nothing was written yet.
    pub fn deferred(stream: &TcpStream) -> bool {
        // `tcp_info` starts with `tcpi_state`, one byte; the rest is not
        // needed, and not every libc has the struct. The kernel fills as
        // much of the buffer as it has fields for.
        let mut info = [0u8; 256];
        let mut len = info.len() as libc::socklen_t;
        // SAFETY: `info` and `len` are valid out-parameters for the option.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                info.as_mut_ptr().cast(),
                &mut len,
            )
        };
        rc == 0 && len > 0 && info[0] == SYN_SENT
    }

    static PEERS: Mutex<VecDeque<(SocketAddr, SocketAddr, Instant)>> = Mutex::new(VecDeque::new());

    /// Remember that the deferred `stream` is bound for `peer`, for
    /// [`peer_addr`] (the kernel will not say until the SYN is out).
    pub fn register(stream: &TcpStream, peer: SocketAddr) {
        let Ok(local) = stream.local_addr() else {
            return;
        };
        let mut peers = PEERS.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        peers.retain(|(.., at)| now.duration_since(*at) < PEER_TTL);
        if peers.len() >= PEER_CAP {
            peers.pop_front();
        }
        peers.push_back((local, peer, now));
    }

    pub fn peer_addr(stream: &TcpStream) -> Option<SocketAddr> {
        if let Ok(peer) = stream.peer_addr() {
            return Some(peer);
        }
        let local = stream.local_addr().ok()?;
        let mut peers = PEERS.lock().unwrap_or_else(|e| e.into_inner());
        let at = peers.iter().position(|(l, ..)| *l == local)?;
        peers.remove(at).map(|(_, peer, _)| peer)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod sys {
    use std::net::SocketAddr;
    use tokio::net::{TcpSocket, TcpStream};

    pub fn supported() -> bool {
        false
    }
    pub fn enable(_: &TcpSocket) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    pub fn deferred(_: &TcpStream) -> bool {
        false
    }
    pub fn register(_: &TcpStream, _: SocketAddr) {}
    pub fn peer_addr(stream: &TcpStream) -> Option<SocketAddr> {
        stream.peer_addr().ok()
    }
}

pub use sys::{deferred, enable, peer_addr, register, supported};

/// Ports where the client speaks first (a TLS server, a web server), which is
/// where Fast Open is used: a deferred connect sends nothing until written to.
/// The filter that reads a plain HTTP `Host` header ignores the SYN as well.
pub fn client_first_port(port: u16) -> bool {
    matches!(
        port,
        80 | 443
            | 465
            | 853
            | 993
            | 995
            | 2052
            | 2053
            | 2082
            | 2083
            | 2086
            | 2087
            | 2095
            | 2096
            | 8080
            | 8443
            | 8880
    )
}
