//! The host application's hooks into socket creation.
//!
//! On a desktop the proxy owns its own process and its sockets go wherever the
//! routing table sends them. On mobile it does not. Android's `VpnService` and
//! iOS's `NEPacketTunnelProvider` put the whole process behind the tunnel the
//! proxy is itself providing, so an ordinary outbound socket is routed back
//! into the TUN device — the proxy's traffic to its own server arrives at the
//! proxy, which forwards it to its server, which arrives at the proxy. The
//! tunnel does not merely perform badly; it never carries a single byte.
//!
//! The platforms' answer is to exempt individual sockets:
//!
//! * **Android** — `VpnService.protect(fd)` binds the socket to the underlying
//!   physical network, outside the VPN's routes.
//! * **iOS/macOS** — a `NEPacketTunnelProvider`'s own sockets are exempt when
//!   bound to the correct interface, which the extension knows and this
//!   library does not.
//!
//! Both are decisions only the host application can make, and both have to
//! happen after the socket exists and before it connects. So this is a
//! process-wide hook rather than configuration: a socket created deep inside a
//! DNS resolver or a QUIC endpoint needs the same treatment as one created by
//! the dialer, and threading a handle through every one of those call paths
//! would guarantee that the one nobody remembered is the one that breaks the
//! tunnel.
//!
//! A host that installs nothing gets today's behaviour exactly: [`protect_fd`]
//! is a no-op when no protector is registered.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

/// A host-supplied exemption for one socket.
///
/// Implementations are called on whatever task or thread created the socket,
/// possibly concurrently, and must not block for long: this sits directly in
/// the connect path.
pub trait SocketProtector: Send + Sync {
    /// Exempt `fd` from the tunnel. Returning an error fails the connection
    /// that was being made, which is the right outcome — an unprotected socket
    /// on a mobile VPN does not fall back to working slowly, it loops.
    fn protect(&self, fd: i32) -> io::Result<()>;
}

static PROTECTOR: OnceLock<Arc<dyn SocketProtector>> = OnceLock::new();

/// Install the process-wide protector. Call once, before the runtime starts.
///
/// Returns `Err` if one is already installed: silently replacing it would let
/// a second host handle take over the sockets of the first, and on a platform
/// where this is load-bearing that is not something to do quietly.
pub fn set_socket_protector(protector: Arc<dyn SocketProtector>) -> Result<(), &'static str> {
    PROTECTOR
        .set(protector)
        .map_err(|_| "a socket protector is already installed")
}

/// The desktop counterpart of a host protector: while a TUN interface is
/// routing everything, the physical interface every outbound socket is pinned
/// to. See [`set_bound_interface`].
static BOUND_INTERFACE: RwLock<Option<Arc<str>>> = RwLock::new(None);
/// Fast path for the common case of no binding, checked before the lock.
static HAS_BOUND_INTERFACE: AtomicBool = AtomicBool::new(false);

/// Pin every outbound socket to `interface`, or stop doing so with `None`.
///
/// On a desktop, TUN mode sends the whole machine's traffic, this process's
/// included, into the tunnel. Only the proxy servers are given bypass
/// routes, so anything the engine connects to directly (a site routed
/// `direct`, a LAN address, a DNS server) went into the tunnel, came back
/// to the engine, was routed direct again, and looped: thousands of
/// connections a minute, each costing memory, until the tunnel was taken
/// down. Binding the engine's own sockets to the physical interface keeps
/// them out of the tunnel whatever the routing table says. This is what
/// sing-box's `auto_detect_interface` does.
///
/// A host [`SocketProtector`], when installed, takes precedence.
pub fn set_bound_interface(interface: Option<&str>) {
    let mut slot = BOUND_INTERFACE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = interface.filter(|name| !name.is_empty()).map(Arc::from);
    HAS_BOUND_INTERFACE.store(slot.is_some(), Ordering::Release);
}

/// Pins outbound sockets to an interface for as long as it lives.
#[must_use = "the binding is undone when this is dropped"]
pub struct BoundInterface(());

impl BoundInterface {
    /// Pin outbound sockets to `interface` until the returned value drops.
    pub fn set(interface: &str) -> Self {
        set_bound_interface(Some(interface));
        Self(())
    }
}

impl Drop for BoundInterface {
    fn drop(&mut self) {
        set_bound_interface(None);
    }
}

/// The interface outbound sockets are currently pinned to, if any.
pub fn bound_interface() -> Option<Arc<str>> {
    if !HAS_BOUND_INTERFACE.load(Ordering::Acquire) {
        return None;
    }
    BOUND_INTERFACE
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Whether sockets need anything done to them: a host protector, or a bound
/// interface.
pub fn has_socket_protector() -> bool {
    PROTECTOR.get().is_some() || HAS_BOUND_INTERFACE.load(Ordering::Acquire)
}

/// Apply the protector to a raw descriptor, if one is installed, or else
/// the bound interface, if one is set.
///
/// A no-op otherwise, which is every desktop build outside TUN mode and
/// every test.
pub fn protect_fd(fd: i32) -> io::Result<()> {
    if let Some(protector) = PROTECTOR.get() {
        return protector.protect(fd);
    }
    match bound_interface() {
        Some(interface) => bind_to_interface(fd, &interface),
        None => Ok(()),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_to_interface(fd: i32, interface: &str) -> io::Result<()> {
    // Allowed without privileges since Linux 5.7, as long as the socket is
    // not already bound to another device.
    // SAFETY: the name is passed with its exact length; the kernel copies it.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            interface.as_ptr().cast(),
            interface.len() as libc::socklen_t,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("keeping this connection out of the tunnel (binding to {interface}): {error}"),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn bind_to_interface(fd: i32, interface: &str) -> io::Result<()> {
    let name = std::ffi::CString::new(interface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name has a NUL"))?;
    // SAFETY: a valid C string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    // The option differs by family, so ask the socket which it is.
    // SAFETY: storage is large enough for any address; the length is updated.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let family = if unsafe {
        libc::getsockname(
            fd,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    } == 0
    {
        storage.ss_family as i32
    } else {
        libc::AF_INET
    };
    let (level, option) = if family == libc::AF_INET6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    };
    let index = index as libc::c_int;
    // SAFETY: an int option with its exact size.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&index as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn bind_to_interface(_fd: i32, _interface: &str) -> io::Result<()> {
    Ok(())
}

/// Apply the protector to anything that exposes a descriptor.
///
/// The `unix` restriction is the platform's, not ours: descriptor-level
/// exemption is what Android offers, and Windows has no equivalent because it
/// has no such routing problem.
#[cfg(unix)]
pub fn protect_socket<S: std::os::fd::AsRawFd>(socket: &S) -> io::Result<()> {
    if !has_socket_protector() {
        return Ok(());
    }
    protect_fd(socket.as_raw_fd())
}

#[cfg(not(unix))]
pub fn protect_socket<S>(_socket: &S) -> io::Result<()> {
    Ok(())
}

/// Bind a UDP socket and protect it before anything sends through it.
///
/// Exists here, in the crate that otherwise holds no networking, because the
/// ordering is the whole point: a QUIC endpoint hands its socket straight to a
/// driver that starts a handshake, so there is no later moment at which the
/// host could be asked. Callers that build an endpoint from a pre-made socket
/// — every DoQ, DoH3, Hysteria2, TUIC and XHTTP/H3 client — go through this.
pub fn bind_protected_udp(address: std::net::SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(address)?;
    protect_socket(&socket)?;
    Ok(socket)
}

/// Connect a TCP socket that the host has been allowed to protect first.
///
/// The ordering is not negotiable: `TcpStream::connect` creates and connects
/// in one step, so by the time a caller could protect the descriptor the SYN
/// has already gone out through the tunnel. Anything that opens an outbound
/// TCP connection — the dialer, the DNS resolver's DoT/DoH legs, the CDN
/// probes — goes through this.
pub async fn connect_protected(address: std::net::SocketAddr) -> io::Result<tokio::net::TcpStream> {
    let socket = if address.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    protect_socket(&socket)?;
    socket.connect(address).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting(AtomicUsize);

    /// The protector and the bound interface are process-wide; tests that
    /// assert on them take turns.
    static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    impl SocketProtector for Counting {
        fn protect(&self, _fd: i32) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_bound_interface_pins_new_sockets_and_is_undone_on_drop() {
        let _turn = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        {
            let _bound = BoundInterface::set("lo");
            assert_eq!(bound_interface().as_deref(), Some("lo"));
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            // The binding itself, independent of whether another test has
            // installed a host protector (which would take precedence).
            use std::os::fd::AsRawFd;
            bind_to_interface(socket.as_raw_fd(), "lo").expect("binding to lo needs no privileges");
            let mut name = [0u8; 16];
            let mut len = name.len() as libc::socklen_t;
            let got = unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    name.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            assert_eq!(got, 0);
            assert_eq!(&name[..2], b"lo");
        }
        assert_eq!(bound_interface(), None);
    }

    #[test]
    fn a_protected_udp_socket_is_bound_and_usable() {
        let socket = bind_protected_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        assert_ne!(socket.local_addr().unwrap().port(), 0);
    }

    /// The registry is process-wide and write-once, so its whole lifecycle has
    /// to be one test. Split across several, they would race: whichever ran
    /// first would install the protector and the others would see a state they
    /// did not set up.
    #[test]
    fn the_protector_registry_installs_once_and_applies_to_every_socket() {
        let _turn = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        // Before installation — every desktop build and every other test —
        // protection is free and infallible rather than an error to handle.
        assert!(!has_socket_protector());
        assert!(protect_fd(3).is_ok());

        let first = Arc::new(Counting(AtomicUsize::new(0)));
        set_socket_protector(first.clone()).expect("the first install succeeds");
        assert!(has_socket_protector());

        // Replacing a live protector would hand one host's sockets to another.
        let second = Arc::new(Counting(AtomicUsize::new(0)));
        assert!(set_socket_protector(second).is_err());

        // Counted as a delta, not an absolute: the registry is global, so a
        // test running in parallel can legitimately protect a socket of its
        // own between these two lines.
        let before = first.0.load(Ordering::Relaxed);
        protect_fd(7).unwrap();
        assert!(
            first.0.load(Ordering::Relaxed) > before,
            "the originally installed protector is the one that runs"
        );

        // And it reaches sockets created through the helpers, not just raw
        // descriptors — which is the whole reason the helpers exist.
        let before = first.0.load(Ordering::Relaxed);
        let _socket = bind_protected_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(
            first.0.load(Ordering::Relaxed) > before,
            "a UDP socket bound through the helper was not protected"
        );

        let before = first.0.load(Ordering::Relaxed);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let accept = tokio::spawn(async move { listener.accept().await });
            let _stream = connect_protected(address).await.unwrap();
            let _ = accept.await;
        });
        assert!(
            first.0.load(Ordering::Relaxed) > before,
            "a TCP socket connected through the helper was not protected \
             before its SYN went out"
        );
    }
}
