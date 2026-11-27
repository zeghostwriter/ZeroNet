//! Which program a connection came from, for routing rules that name one
//! (`"process": [...]`, see `zero_config::routing::ProcessPattern`).
//!
//! A session only knows its source address: the address and port of the
//! socket the program opened. The system knows which program owns that
//! socket, and each platform has its own way of asking:
//!
//! * Linux: `/proc/net/{tcp,udp}{,6}` give the socket's inode for a local
//!   address, and the `/proc/<pid>/fd` entry pointing at that inode gives the
//!   program ([`linux`]).
//! * Windows: the IP Helper tables give the owning process id for a local
//!   address, and the process id gives the program's path ([`windows`]).
//! * Android: only the VPN app itself may ask, through Java
//!   (`ConnectivityManager.getConnectionOwnerUid`), so the app registers a
//!   [`ProcessFinder`] of its own with [`set_finder`]. There the "name" is the
//!   app's package name, which is what a rule names.
//!
//! A lookup reads the system's tables, so it costs a little: the router only
//! asks when it reaches a rule that names a program, and at most once per
//! session. When the owner cannot be found (another user's program, a socket
//! already closed, a platform with no way to ask) the answer is `None`, and a
//! rule that names programs then does not match: it never turns into a rule
//! that matches everything.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use zero_config::routing::ProcessPattern;
use zero_core::Network;

/// The program that owns a connection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessInfo {
    /// The process id, where the platform has one to give.
    pub pid: Option<u32>,
    /// The program's file name without `.exe`, or on Android the package
    /// name.
    pub name: String,
    /// The full path of the program with `/` between the parts; empty where
    /// there is none (Android).
    pub path: String,
}

impl ProcessInfo {
    /// The info for a program at `path`, with its name taken from the path.
    pub fn from_path(pid: Option<u32>, path: &str) -> Self {
        let path = path.replace('\\', "/");
        let file = path.rsplit('/').next().unwrap_or(&path);
        let name = file.strip_suffix(".exe").unwrap_or(file).to_string();
        Self { pid, name, path }
    }
}

/// A way of asking the system who owns a connection. `source` is the
/// program's own end of it; `destination` the far end as the program sees
/// it, which some platforms need to tell two sockets apart.
pub trait ProcessFinder: Send + Sync {
    fn find(
        &self,
        network: Network,
        source: SocketAddr,
        destination: Option<SocketAddr>,
    ) -> Option<ProcessInfo>;
}

static FINDER: RwLock<Option<Arc<dyn ProcessFinder>>> = RwLock::new(None);

/// Use `finder` for every later lookup instead of the platform's own way.
/// The Android app calls this; nothing else needs to.
pub fn set_finder(finder: Arc<dyn ProcessFinder>) {
    *FINDER.write().unwrap_or_else(|e| e.into_inner()) = Some(finder);
}

/// Who owns the connection from `source` (to `destination`), if the system
/// will say.
pub fn find(
    network: Network,
    source: SocketAddr,
    destination: Option<SocketAddr>,
) -> Option<ProcessInfo> {
    let registered = FINDER.read().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(finder) = registered {
        return finder.find(network, source, destination);
    }
    #[cfg(target_os = "linux")]
    {
        linux::find(network, source)
    }
    #[cfg(windows)]
    {
        windows::find(network, source)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (network, source, destination);
        None
    }
}

/// Whether `info` is a program any of `patterns` names.
pub fn matches(patterns: &[ProcessPattern], info: &ProcessInfo) -> bool {
    patterns.iter().any(|pattern| match pattern {
        ProcessPattern::Name(name) => info.name == name.as_ref(),
        ProcessPattern::Path(path) => !info.path.is_empty() && info.path == path.as_ref(),
        ProcessPattern::Folder(folder) => {
            !info.path.is_empty() && info.path.starts_with(folder.as_ref())
        }
        ProcessPattern::SelfProcess => info.pid == Some(std::process::id()),
    })
}

/// Whether a socket bound to `bound` is the one at `source`: the same port,
/// and the same address unless it was bound to every address (as unconnected
/// UDP sockets often are). An IPv4 address also matches its IPv6-mapped
/// form, which is how a dual-stack socket shows it.
#[cfg(any(target_os = "linux", windows, test))]
fn same_socket(bound: SocketAddr, source: SocketAddr) -> bool {
    let canonical = |ip: std::net::IpAddr| ip.to_canonical();
    bound.port() == source.port()
        && (bound.ip().is_unspecified() || canonical(bound.ip()) == canonical(source.ip()))
}

#[cfg(target_os = "linux")]
mod linux {
    //! The Linux lookup, through `/proc`.

    use super::{same_socket, ProcessInfo};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use zero_core::Network;

    pub(super) fn find(network: Network, source: SocketAddr) -> Option<ProcessInfo> {
        let (inode, uid) = socket_inode(network, source)?;
        let pid = owner_of(inode, uid)?;
        let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        let path = path.to_string_lossy();
        // A program replaced on disk while running reads as "… (deleted)".
        let path = path.strip_suffix(" (deleted)").unwrap_or(&path);
        Some(ProcessInfo::from_path(Some(pid), path))
    }

    /// The inode and owner uid of the socket bound to `source`, from the
    /// kernel's socket tables.
    fn socket_inode(network: Network, source: SocketAddr) -> Option<(u64, u32)> {
        let tables: &[&str] = match network {
            Network::Tcp => &["/proc/net/tcp", "/proc/net/tcp6"],
            Network::Udp => &["/proc/net/udp", "/proc/net/udp6"],
        };
        tables.iter().find_map(|table| {
            let text = std::fs::read_to_string(table).ok()?;
            text.lines()
                .skip(1)
                .find_map(|line| parse_line(line).filter(|(at, ..)| same_socket(*at, source)))
                .map(|(_, inode, uid)| (inode, uid))
        })
    }

    /// One line of a `/proc/net` socket table: the local address, the inode
    /// and the owner uid. `None` for a line it cannot read, or a socket with
    /// no inode (one already on its way out).
    pub(super) fn parse_line(line: &str) -> Option<(SocketAddr, u64, u32)> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (address, port) = fields.get(1)?.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let uid = fields.get(7)?.parse().ok()?;
        let inode = fields.get(9)?.parse().ok().filter(|inode| *inode != 0)?;
        Some((SocketAddr::new(parse_address(address)?, port), inode, uid))
    }

    /// The kernel prints each 32-bit word of the address in the machine's
    /// own byte order.
    fn parse_address(hex: &str) -> Option<IpAddr> {
        let word = |at: usize| {
            u32::from_str_radix(hex.get(at..at + 8)?, 16)
                .ok()
                .map(u32::to_ne_bytes)
        };
        match hex.len() {
            8 => Some(IpAddr::V4(Ipv4Addr::from(word(0)?))),
            32 => {
                let mut bytes = [0u8; 16];
                for (index, chunk) in bytes.chunks_mut(4).enumerate() {
                    chunk.copy_from_slice(&word(index * 8)?);
                }
                Some(IpAddr::V6(Ipv6Addr::from(bytes)))
            }
            _ => None,
        }
    }

    /// The process holding socket `inode`. Only processes of the socket's
    /// owner `uid` are looked at, which is both quicker and all this process
    /// may read anyway unless it runs as root.
    fn owner_of(inode: u64, uid: u32) -> Option<u32> {
        use std::os::unix::fs::MetadataExt;
        let wanted = format!("socket:[{inode}]");
        std::fs::read_dir("/proc")
            .ok()?
            .flatten()
            .find_map(|entry| {
                let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
                if entry.metadata().ok()?.uid() != uid {
                    return None;
                }
                let fds = std::fs::read_dir(entry.path().join("fd")).ok()?;
                fds.flatten()
                    .any(|fd| {
                        std::fs::read_link(fd.path())
                            .is_ok_and(|link| link.as_os_str() == wanted.as_str())
                    })
                    .then_some(pid)
            })
    }
}

#[cfg(windows)]
mod windows {
    //! The Windows lookup, through the IP Helper API.

    use super::{same_socket, ProcessInfo};
    use std::ffi::c_void;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use zero_core::Network;

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    /// `TCP_TABLE_OWNER_PID_ALL` and `UDP_TABLE_OWNER_PID`.
    const TCP_TABLE: u32 = 5;
    const UDP_TABLE: u32 = 1;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            family: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
        fn GetExtendedUdpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            family: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn QueryFullProcessImageNameW(
            process: *mut c_void,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    pub(super) fn find(network: Network, source: SocketAddr) -> Option<ProcessInfo> {
        let family = if source.is_ipv4() { AF_INET } else { AF_INET6 };
        let table = read_table(network, family)?;
        let pid = owners(&table, network, family)
            .find(|(at, _)| same_socket(*at, source))
            .map(|(_, pid)| pid)?;
        Some(ProcessInfo::from_path(Some(pid), &image_path(pid)?))
    }

    /// The whole owner table for `network` and `family`, as the API writes
    /// it: a count, then the rows.
    fn read_table(network: Network, family: u32) -> Option<Vec<u32>> {
        let call = |buffer: *mut c_void, size: &mut u32| -> u32 {
            // SAFETY: `buffer` holds at least `*size` bytes (or is null with
            // a size of zero, which only asks for the size).
            unsafe {
                match network {
                    Network::Tcp => GetExtendedTcpTable(buffer, size, 0, family, TCP_TABLE, 0),
                    Network::Udp => GetExtendedUdpTable(buffer, size, 0, family, UDP_TABLE, 0),
                }
            }
        };
        let mut size = 0u32;
        // The table can grow between the two calls; a few tries cover it.
        for _ in 0..4 {
            let mut table = vec![0u32; (size as usize).div_ceil(4)];
            match call(table.as_mut_ptr().cast(), &mut size) {
                0 => return Some(table),
                ERROR_INSUFFICIENT_BUFFER => continue,
                _ => return None,
            }
        }
        None
    }

    /// Each row's local address and owner, read from the table's 32-bit words.
    /// Row layouts (all fields 32 bits, addresses in network byte order, the
    /// port in the low 16 bits, also in network byte order):
    ///
    /// ```text
    /// TCP v4: state, local addr, local port, remote addr, remote port, pid
    /// TCP v6: local addr (4 words), scope, local port,
    ///         remote addr (4 words), scope, remote port, state, pid
    /// UDP v4: local addr, local port, pid
    /// UDP v6: local addr (4 words), scope, local port, pid
    /// ```
    fn owners<'a>(
        table: &'a [u32],
        network: Network,
        family: u32,
    ) -> impl Iterator<Item = (SocketAddr, u32)> + 'a {
        let count = table.first().copied().unwrap_or(0) as usize;
        let v6 = family == AF_INET6;
        let (width, address, port, pid) = match (network, v6) {
            (Network::Tcp, false) => (6, 1, 2, 5),
            (Network::Tcp, true) => (14, 0, 5, 13),
            (Network::Udp, false) => (3, 0, 1, 2),
            (Network::Udp, true) => (7, 0, 5, 6),
        };
        let rows = table.get(1..).unwrap_or(&[]);
        rows.chunks_exact(width).take(count).map(move |row| {
            let ip = if v6 {
                let mut bytes = [0u8; 16];
                for (index, chunk) in bytes.chunks_mut(4).enumerate() {
                    chunk.copy_from_slice(&row[address + index].to_ne_bytes());
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            } else {
                IpAddr::V4(Ipv4Addr::from(row[address].to_ne_bytes()))
            };
            let raw = row[port].to_ne_bytes();
            let at = SocketAddr::new(ip, u16::from_be_bytes([raw[0], raw[1]]));
            (at, row[pid])
        })
    }

    /// The full path of the program running as `pid`.
    fn image_path(pid: u32) -> Option<String> {
        // SAFETY: the handle is checked, used for one query and closed; the
        // buffer's length is passed with it and the result is cut to what
        // the call reports.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return None;
            }
            let mut buffer = [0u16; 1024];
            let mut size = buffer.len() as u32;
            let ok = QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut size);
            CloseHandle(process);
            (ok != 0).then(|| String::from_utf16_lossy(&buffer[..size as usize]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(pid: Option<u32>, path: &str) -> ProcessInfo {
        ProcessInfo::from_path(pid, path)
    }

    #[test]
    fn names_paths_folders_and_self_match_as_xray_has_them() {
        let pattern = |s: &str| ProcessPattern::parse(s).unwrap();
        let chrome = info(Some(7), "C:\\Program Files\\Google\\chrome.exe");
        assert_eq!(chrome.name, "chrome");
        assert_eq!(chrome.path, "C:/Program Files/Google/chrome.exe");
        assert!(matches(&[pattern("chrome.exe")], &chrome));
        assert!(matches(&[pattern("chrome")], &chrome));
        assert!(!matches(&[pattern("Chrome")], &chrome), "case-sensitive");
        assert!(matches(&[pattern("C:/Program Files/Google/")], &chrome));
        assert!(matches(
            &[pattern("C:/Program Files/Google/chrome.exe")],
            &chrome
        ));
        assert!(!matches(&[pattern("C:/Program Files/Mozilla/")], &chrome));
        assert!(!matches(&[pattern("self/")], &chrome));
        let me = info(Some(std::process::id()), "/usr/bin/zray");
        assert!(matches(&[pattern("curl"), pattern("self/")], &me));
        // An Android app: a package name and no path.
        let app = ProcessInfo {
            pid: None,
            name: "org.telegram.messenger".into(),
            path: String::new(),
        };
        assert!(matches(&[pattern("org.telegram.messenger")], &app));
        assert!(!matches(&[pattern("/")], &app), "no path, no folder match");
        assert_eq!(ProcessPattern::parse("  "), None);
    }

    #[test]
    fn a_socket_bound_to_every_address_matches_by_port() {
        let source: SocketAddr = "172.19.0.1:40000".parse().unwrap();
        assert!(same_socket("172.19.0.1:40000".parse().unwrap(), source));
        assert!(same_socket("0.0.0.0:40000".parse().unwrap(), source));
        assert!(same_socket(
            "[::ffff:172.19.0.1]:40000".parse().unwrap(),
            source
        ));
        assert!(same_socket("[::]:40000".parse().unwrap(), source));
        assert!(!same_socket("172.19.0.1:40001".parse().unwrap(), source));
        assert!(!same_socket("10.0.0.1:40000".parse().unwrap(), source));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_net_lines_are_read() {
        let v4 = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0";
        let (at, inode, uid) = linux::parse_line(v4).unwrap();
        assert_eq!(at, "127.0.0.1:8080".parse().unwrap());
        assert_eq!((inode, uid), (123456, 1000));
        let v6 = "   1: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777 1 0000000000000000 100 0 0 10 0";
        let (at, inode, _) = linux::parse_line(v6).unwrap();
        assert_eq!(at, "[::1]:53".parse().unwrap());
        assert_eq!(inode, 777);
        assert!(linux::parse_line("  sl  local_address rem_address").is_none());
    }

    /// The real thing: a socket this test opens is found, and its owner is
    /// this test program.
    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_is_found_as_the_owner_of_its_own_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let source = client.local_addr().unwrap();
        let found = find(Network::Tcp, source, None).expect("owner found");
        assert_eq!(found.pid, Some(std::process::id()));
        assert!(matches(&[ProcessPattern::SelfProcess], &found));
        let exe = std::env::current_exe().unwrap();
        assert_eq!(found.path, exe.to_string_lossy());
    }
}
