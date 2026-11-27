//! Transparent proxying on Linux: learning where a redirected connection was
//! really going.
//!
//! A gateway can steer traffic into a listener without the client knowing,
//! two ways:
//!
//! * **REDIRECT** (`iptables -j REDIRECT`, nft `redirect`): the packet's
//!   destination is rewritten to the listener, and the kernel's connection
//!   tracking remembers the old one. [`original_destination`] asks for it
//!   (`SO_ORIGINAL_DST`). TCP only: a UDP socket cannot ask.
//! * **TPROXY**: the packet keeps its destination and is only handed to a
//!   socket that has `IP_TRANSPARENT`. For TCP the accepted socket's own local
//!   address *is* the destination; for UDP each datagram carries it as an
//!   ancillary message ([`TransparentUdp::recv`]). Answers must leave from
//!   that destination, not from the listener, or the client drops them:
//!   [`reply_socket`] makes a socket that may bind a foreign address.
//!
//! Everything here needs `CAP_NET_ADMIN` (TPROXY) or conntrack (REDIRECT);
//! without them the calls fail with an ordinary I/O error, never a panic.

use std::io;
use std::net::SocketAddr;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use imp::*;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub use other::*;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod other {
    use super::*;

    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transparent proxying needs Linux",
        ))
    }

    pub fn original_destination(
        _stream: &tokio::net::TcpStream,
        _peer: SocketAddr,
    ) -> io::Result<SocketAddr> {
        unsupported()
    }

    pub fn set_transparent(_socket: &socket2::Socket, _v6: bool) -> io::Result<()> {
        unsupported()
    }

    pub struct TransparentUdp;

    impl TransparentUdp {
        pub fn bind(_addr: SocketAddr) -> io::Result<Self> {
            unsupported()
        }

        pub async fn recv(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
            unsupported()
        }
    }

    pub fn reply_socket(_from: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
        unsupported()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use super::*;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::mem::{size_of, zeroed};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::AsRawFd;
    use tokio::net::{TcpStream, UdpSocket};

    // Not exported by every libc version.
    const SO_ORIGINAL_DST: libc::c_int = 80;
    const IP_TRANSPARENT: libc::c_int = 19;
    const IPV6_TRANSPARENT: libc::c_int = 75;
    const IP_RECVORIGDSTADDR: libc::c_int = 20;
    const IPV6_RECVORIGDSTADDR: libc::c_int = 74;

    fn setsockopt_on(fd: i32, level: libc::c_int, name: libc::c_int) -> io::Result<()> {
        let on: libc::c_int = 1;
        // SAFETY: `on` outlives the call and the length is its size.
        let result = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                std::ptr::from_ref(&on).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Let `socket` bind and accept addresses that are not its host's own
    /// (`IP_TRANSPARENT`, or `IPV6_TRANSPARENT`). Needs `CAP_NET_ADMIN`.
    pub fn set_transparent(socket: &Socket, v6: bool) -> io::Result<()> {
        if v6 {
            setsockopt_on(socket.as_raw_fd(), libc::SOL_IPV6, IPV6_TRANSPARENT)
        } else {
            setsockopt_on(socket.as_raw_fd(), libc::SOL_IP, IP_TRANSPARENT)
        }
    }

    fn from_storage(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
        match libc::c_int::from(storage.ss_family) {
            libc::AF_INET => {
                // SAFETY: the family says the bytes are a sockaddr_in.
                let a = unsafe { &*std::ptr::from_ref(storage).cast::<libc::sockaddr_in>() };
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes())),
                    u16::from_be(a.sin_port),
                ))
            }
            libc::AF_INET6 => {
                // SAFETY: the family says the bytes are a sockaddr_in6.
                let a = unsafe { &*std::ptr::from_ref(storage).cast::<libc::sockaddr_in6>() };
                Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)),
                    u16::from_be(a.sin6_port),
                ))
            }
            _ => None,
        }
    }

    /// Where a REDIRECTed TCP connection was going before the rewrite.
    ///
    /// `peer` picks the lookup: a client that reached a dual-stack `[::]`
    /// listener over IPv4 shows up as an IPv4-mapped address, and its
    /// connection is tracked as IPv4. An error means conntrack has no entry,
    /// which is what a client that connected to the port directly looks like.
    pub fn original_destination(stream: &TcpStream, peer: SocketAddr) -> io::Result<SocketAddr> {
        let v4 = match peer.ip() {
            IpAddr::V4(_) => true,
            IpAddr::V6(ip) => ip.to_ipv4_mapped().is_some(),
        };
        // SAFETY: an all-zero sockaddr_storage is valid, and the kernel
        // writes at most `len` bytes into it.
        let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
        let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let level = if v4 { libc::SOL_IP } else { libc::SOL_IPV6 };
        // SAFETY: as above; the pointers are valid for the call.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                level,
                SO_ORIGINAL_DST,
                std::ptr::from_mut(&mut storage).cast(),
                &mut len,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        from_storage(&storage).ok_or_else(|| io::Error::other("unknown address family"))
    }

    /// A UDP socket that receives datagrams meant for other hosts (TPROXY)
    /// and says, for each, where it was going.
    pub struct TransparentUdp {
        socket: UdpSocket,
    }

    impl TransparentUdp {
        pub fn bind(addr: SocketAddr) -> io::Result<Self> {
            let v6 = addr.is_ipv6();
            let socket = Socket::new(
                if v6 { Domain::IPV6 } else { Domain::IPV4 },
                Type::DGRAM,
                Some(Protocol::UDP),
            )?;
            set_transparent(&socket, v6)?;
            if v6 {
                setsockopt_on(socket.as_raw_fd(), libc::SOL_IPV6, IPV6_RECVORIGDSTADDR)?;
            } else {
                setsockopt_on(socket.as_raw_fd(), libc::SOL_IP, IP_RECVORIGDSTADDR)?;
            }
            socket.set_reuse_address(true)?;
            socket.set_nonblocking(true)?;
            socket.bind(&addr.into())?;
            Ok(Self {
                socket: UdpSocket::from_std(socket.into())?,
            })
        }

        /// The next datagram: its length, the client it came from, and the
        /// address it was sent to.
        pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
            loop {
                self.socket.readable().await?;
                match self.socket.try_io(tokio::io::Interest::READABLE, || {
                    recv_with_destination(self.socket.as_raw_fd(), buf)
                }) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    other => return other,
                }
            }
        }
    }

    /// `recvmsg` with room for the original-destination control message.
    fn recv_with_destination(
        fd: i32,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        // SAFETY: zeroed msghdr/sockaddr_storage are valid; every pointer set
        // below points at a local that outlives the `recvmsg` call.
        unsafe {
            let mut source: libc::sockaddr_storage = zeroed();
            let mut control = [0u64; 16];
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            let mut message: libc::msghdr = zeroed();
            message.msg_name = std::ptr::from_mut(&mut source).cast();
            message.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = size_of_val(&control) as _;
            let read = libc::recvmsg(fd, &mut message, 0);
            if read < 0 {
                return Err(io::Error::last_os_error());
            }
            let client = from_storage(&source)
                .ok_or_else(|| io::Error::other("datagram from an unknown family"))?;
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                let (level, kind) = ((*header).cmsg_level, (*header).cmsg_type);
                if (level == libc::SOL_IP && kind == IP_RECVORIGDSTADDR)
                    || (level == libc::SOL_IPV6 && kind == IPV6_RECVORIGDSTADDR)
                {
                    let mut storage: libc::sockaddr_storage = zeroed();
                    let data = libc::CMSG_DATA(header);
                    let size = ((*header).cmsg_len as usize)
                        .saturating_sub(data.offset_from(header.cast::<u8>()) as usize)
                        .min(size_of::<libc::sockaddr_storage>());
                    std::ptr::copy_nonoverlapping(
                        data,
                        std::ptr::from_mut(&mut storage).cast(),
                        size,
                    );
                    if let Some(destination) = from_storage(&storage) {
                        return Ok((read as usize, client, destination));
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
            Err(io::Error::other("datagram without its destination"))
        }
    }

    /// A UDP socket bound to `from`, an address that is not this host's, so a
    /// reply to a transparently proxied client appears to come from the host
    /// the client was talking to.
    pub fn reply_socket(from: SocketAddr) -> io::Result<UdpSocket> {
        let v6 = from.is_ipv6();
        let socket = Socket::new(
            if v6 { Domain::IPV6 } else { Domain::IPV4 },
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        set_transparent(&socket, v6)?;
        socket.set_reuse_address(true)?;
        let _ = socket.set_reuse_port(true);
        socket.set_nonblocking(true)?;
        socket.bind(&from.into())?;
        UdpSocket::from_std(socket.into())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn a_direct_connection_has_no_original_destination() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let client = tokio::spawn(async move { TcpStream::connect(address).await });
            let (stream, peer) = listener.accept().await.unwrap();
            // Nothing redirected it, so conntrack knows no other destination:
            // either an error, or the address it really connected to.
            match original_destination(&stream, peer) {
                Err(_) => {}
                Ok(found) => assert_eq!(found, address),
            }
            drop(client.await);
        }

        #[test]
        fn a_stored_address_reads_back() {
            // SAFETY: zeroed sockaddr_storage is valid, and the in-place
            // sockaddr_in write fits within it.
            let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
            let v4 = unsafe { &mut *std::ptr::from_mut(&mut storage).cast::<libc::sockaddr_in>() };
            v4.sin_family = libc::AF_INET as _;
            v4.sin_port = 443u16.to_be();
            v4.sin_addr.s_addr = u32::from_ne_bytes([203, 0, 113, 7]);
            assert_eq!(
                from_storage(&storage),
                Some("203.0.113.7:443".parse().unwrap())
            );
        }
    }
}
