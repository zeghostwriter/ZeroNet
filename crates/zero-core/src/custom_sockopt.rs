//! Xray's `customSockopt`: arbitrary `setsockopt` calls on a socket.
//!
//! A config names the option by number, as the operating system does (level
//! 6 is TCP, and option 13 at that level is `TCP_CONGESTION` on Linux), and
//! gives a value that is an integer (`"type": "int"`) or a string
//! (`"type": "str"`). It is a tuning escape hatch for what Zray
//! has no named setting for, and it is Linux-only here: elsewhere the list is
//! kept and applying it does nothing.
//!
//! The rules it keeps, as Xray's do: an entry whose `system` is another
//! operating system is skipped; one whose `network` is not a prefix of the
//! socket's (`tcp` matches `tcp4` and `tcp6`; empty matches every socket) is
//! skipped; and a call the kernel refuses is an error, not a silent skip, so
//! a typo in an option number is found at the first connection.

use std::io;

/// What a custom option sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomValue {
    Int(i32),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomSockopt {
    /// Operating system this applies to (`linux`); `None` is any.
    pub system: Option<String>,
    /// Socket kind prefix: `tcp`, `udp`, `tcp4`...; empty is every socket.
    pub network: String,
    /// Protocol level (6 = TCP when the config leaves it out).
    pub level: i32,
    pub opt: i32,
    pub value: CustomValue,
}

/// Apply every entry of `options` that fits `network` (`tcp4`, `udp6`...) to
/// the socket `fd`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn apply(fd: std::os::fd::RawFd, network: &str, options: &[CustomSockopt]) -> io::Result<()> {
    for option in options {
        if option
            .system
            .as_deref()
            .is_some_and(|system| system != std::env::consts::OS)
            || !network.starts_with(&option.network)
        {
            continue;
        }
        // SAFETY: the pointer and length describe a live buffer for the call.
        let result = unsafe {
            match &option.value {
                CustomValue::Int(value) => libc::setsockopt(
                    fd,
                    option.level,
                    option.opt,
                    std::ptr::from_ref(value).cast(),
                    std::mem::size_of::<i32>() as libc::socklen_t,
                ),
                CustomValue::Bytes(bytes) => libc::setsockopt(
                    fd,
                    option.level,
                    option.opt,
                    bytes.as_ptr().cast(),
                    bytes.len() as libc::socklen_t,
                ),
            }
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "customSockopt level {} opt {} was refused: {error}",
                    option.level, option.opt
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn apply(_fd: i32, _network: &str, _options: &[CustomSockopt]) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn read_int(fd: i32, level: i32, opt: i32) -> i32 {
        let mut value = 0i32;
        let mut length = 4 as libc::socklen_t;
        // SAFETY: a live int and its length.
        let result = unsafe {
            libc::getsockopt(
                fd,
                level,
                opt,
                std::ptr::from_mut(&mut value).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0);
        value
    }

    fn option(network: &str, system: Option<&str>, opt: i32, value: i32) -> CustomSockopt {
        CustomSockopt {
            system: system.map(str::to_string),
            network: network.into(),
            level: libc::SOL_SOCKET,
            opt,
            value: CustomValue::Int(value),
        }
    }

    #[test]
    fn options_apply_by_network_prefix_and_system() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();
        let before = read_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF);
        // Another kind of socket, another system: neither applies.
        apply(fd, "udp4", &[option("tcp", None, libc::SO_RCVBUF, 200_000)]).unwrap();
        apply(
            fd,
            "udp4",
            &[option("", Some("plan9"), libc::SO_RCVBUF, 200_000)],
        )
        .unwrap();
        assert_eq!(read_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF), before);
        // A prefix and an empty network both do (the kernel doubles the value).
        apply(
            fd,
            "udp4",
            &[option("udp", Some("linux"), libc::SO_RCVBUF, 100_000)],
        )
        .unwrap();
        assert!(read_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF) >= 100_000);
        apply(fd, "udp6", &[option("", None, libc::SO_BROADCAST, 1)]).unwrap();
        assert_eq!(read_int(fd, libc::SOL_SOCKET, libc::SO_BROADCAST), 1);
        // A refused option is an error that names it.
        let error = apply(fd, "udp4", &[option("", None, 9999, 1)]).unwrap_err();
        assert!(error.to_string().contains("opt 9999"), "{error}");
    }
}
