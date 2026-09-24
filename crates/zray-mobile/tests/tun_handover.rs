//! The mobile path, end to end, on a real kernel TUN device.
//!
//! On Android and iOS the proxy never opens a TUN device. The platform creates
//! the interface after the user approves a system dialog, configures its
//! addresses, routes and MTU itself, and hands the application a file
//! descriptor. The proxy then has to do two things it does not do anywhere
//! else:
//!
//! 1. **Adopt the descriptor** rather than open a device, and leave the link
//!    configuration alone.
//! 2. **Protect every outbound socket**, because the process is now behind the
//!    tunnel it is serving and an unexempted socket routes back into itself.
//!
//! Neither shares code with the desktop path, so neither is covered by any
//! other test here. This one exercises both against real kernel plumbing:
//!
//! ```text
//!   client ──connect 10.77.0.2:9000──▶ [ route: dev zray0 ]
//!                                          │
//!                                    real TUN device
//!                                          │  (descriptor created by this
//!                                          │   test, handed to the library)
//!                                     netstack ──▶ freedom outbound
//!                                                       │ socket marked by
//!                                                       │ the protector
//!                                                  [ nft: mark → DNAT ]
//!                                                       ▼
//!                                                  echo server
//! ```
//!
//! The firewall mark is what makes the exemption observable. It is the same
//! shape as the real thing — Android's `protect` binds the socket to the
//! underlying physical network, here a mark sends it down a different routing
//! path — and it means the test fails, rather than hangs, if the protector is
//! never called: an unmarked outbound socket is routed straight back into the
//! tunnel.
//!
//! Run it through the harness, which builds the namespace:
//!
//! ```bash
//! bash scripts/tun-handover-harness.sh
//! ```

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::io;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The tunnel's own subnet. Traffic to it is routed into the TUN device.
const TUN_ADDRESS: &str = "10.77.0.1/24";
/// The address the client dials. Inside the tunnel's subnet, so it routes into
/// the device; nothing is actually listening there.
const TUNNELLED_TARGET: &str = "10.77.0.2";
const TUNNELLED_PORT: u16 = 9000;
/// The mark the protector sets, and the mark the routing policy keys on.
const PROTECT_MARK: u32 = 0x5a;

// --------------------------------------------------------------- namespace

fn run(program: &str, args: &[&str]) -> io::Result<String> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn must(program: &str, args: &[&str]) {
    run(program, args).unwrap_or_else(|error| panic!("{error}"));
}

/// Refuse to run anywhere but the namespace the harness prepared.
fn require_private_namespace() {
    let links = run("ip", &["-o", "link", "show"]).expect("ip link show");
    let names: Vec<&str> = links
        .lines()
        .filter_map(|line| line.split(':').nth(1))
        .map(str::trim)
        .collect();
    assert_eq!(
        names,
        vec!["lo"],
        "refusing to create a TUN device on a network that is not a private \
         namespace (interfaces: {names:?}); run scripts/tun-handover-harness.sh"
    );
}

// ------------------------------------------------------------ the platform

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

#[repr(C)]
#[derive(Clone, Copy)]
struct Ifreq {
    name: [u8; libc::IFNAMSIZ],
    flags: i16,
    padding: [u8; 22],
}

/// Create a TUN interface and return its descriptor — what `VpnService` does.
///
/// Deliberately written here rather than called from `zero-tun`: the point is
/// that the descriptor comes from *outside* the library, exactly as it does on
/// a phone.
fn platform_creates_tun(name: &str) -> io::Result<i32> {
    let path = CString::new("/dev/net/tun").expect("a literal path");
    // SAFETY: a NUL-terminated path, opened for reading and writing.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut request = Ifreq {
        name: [0; libc::IFNAMSIZ],
        // IFF_TUN | IFF_NO_PI: bare IP packets, which is what Android's
        // VpnService descriptor also delivers.
        flags: (libc::IFF_TUN | libc::IFF_NO_PI) as i16,
        padding: [0; 22],
    };
    assert!(name.len() < libc::IFNAMSIZ);
    request.name[..name.len()].copy_from_slice(name.as_bytes());

    // SAFETY: `fd` is open and `request` is the layout the ioctl expects.
    if unsafe { libc::ioctl(fd, TUNSETIFF, &request) } < 0 {
        let error = io::Error::last_os_error();
        // SAFETY: closing the descriptor we just opened and never shared.
        unsafe { libc::close(fd) };
        return Err(error);
    }
    Ok(fd)
}

// ------------------------------------------------------------- the exemption

/// Marks every socket it is given, the way `VpnService.protect` moves a socket
/// off the tunnel.
struct MarkingProtector {
    calls: AtomicUsize,
}

impl zero_core::SocketProtector for MarkingProtector {
    fn protect(&self, fd: i32) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mark: libc::c_int = PROTECT_MARK as libc::c_int;
        // SAFETY: `fd` is a socket the runtime just created, and `mark` is a
        // correctly sized value for SO_MARK.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ fixture

/// An ordinary loopback echo server. The escape route rewrites the tunnelled
/// destination to this address, so it needs no special binding.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buffer[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    address
}

/// A loopback UDP echo server, for the datagram half of the tunnel.
async fn udp_echo_server() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 2048];
        while let Ok((n, peer)) = socket.recv_from(&mut buffer).await {
            if socket.send_to(&buffer[..n], peer).await.is_err() {
                return;
            }
        }
    });
    address
}

/// Route marked traffic away from the tunnel and deliver it locally.
///
/// This stands in for what a phone does with `protect`: the proxy's own
/// sockets leave by a path the tunnel does not own. Here that path is a
/// separate routing table, selected by the firewall mark the protector sets,
/// in which the tunnelled address is *local* — so the proxy's connection to
/// it is delivered to the echo server instead of going back into the TUN.
///
/// Without the mark — that is, if the protector were never called — the
/// proxy's socket would use the main table, be routed into the tunnel it is
/// itself serving, and the connection would never complete. That is what makes
/// this test fail rather than quietly pass when protection is missing.
fn install_escape_route(echo: SocketAddr, udp_echo: SocketAddr) {
    must("nft", &["add", "table", "ip", "zray"]);
    must(
        "nft",
        &[
            "add",
            "chain",
            "ip",
            "zray",
            "out",
            "{ type nat hook output priority -100; policy accept; }",
        ],
    );
    // Only marked packets are rewritten. The client's connection carries no
    // mark, is not matched here, and follows the main table into the tunnel.
    must(
        "nft",
        &[
            "add",
            "rule",
            "ip",
            "zray",
            "out",
            "meta",
            "mark",
            &PROTECT_MARK.to_string(),
            "ip",
            "daddr",
            TUNNELLED_TARGET,
            "tcp",
            "dport",
            &TUNNELLED_PORT.to_string(),
            "dnat",
            "to",
            &format!("127.0.0.1:{}", echo.port()),
        ],
    );
    must(
        "nft",
        &[
            "add",
            "rule",
            "ip",
            "zray",
            "out",
            "meta",
            "mark",
            &PROTECT_MARK.to_string(),
            "ip",
            "daddr",
            TUNNELLED_TARGET,
            "udp",
            "dport",
            &TUNNELLED_PORT.to_string(),
            "dnat",
            "to",
            &format!("127.0.0.1:{}", udp_echo.port()),
        ],
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the namespace from scripts/tun-handover-harness.sh"]
async fn the_runtime_adopts_a_host_descriptor_and_carries_traffic_through_it() {
    require_private_namespace();

    let protector = Arc::new(MarkingProtector {
        calls: AtomicUsize::new(0),
    });
    zero_core::set_socket_protector(protector.clone()).expect("first install in this process");

    let echo = echo_server().await;
    let udp_echo = udp_echo_server().await;
    install_escape_route(echo, udp_echo);

    // The platform creates the interface and configures it. The library does
    // neither; on a phone it could not.
    let fd = platform_creates_tun("zray0").expect("creating the TUN interface");
    must("ip", &["addr", "add", TUN_ADDRESS, "dev", "zray0"]);
    must("ip", &["link", "set", "dev", "zray0", "mtu", "1500"]);
    must("ip", &["link", "set", "dev", "zray0", "up"]);

    // Hand it over. Ownership moves with it.
    assert_eq!(
        zray_mobile::zray_set_tun_descriptor(fd, 0, 1500),
        zray_mobile::ZRAY_OK
    );

    let config = CString::new(
        serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": "tun-in",
                "protocol": "tun",
                "settings": {
                    "name": "zray0",
                    "mtu": 1500,
                    "autoRoute": false,
                    "stack": "system",
                    "enableUdp": true,
                },
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        })
        .to_string(),
    )
    .unwrap();

    // SAFETY: a valid NUL-terminated string for the duration of the call.
    let started = unsafe { zray_mobile::zray_start(config.as_ptr()) };
    assert_eq!(
        started,
        zray_mobile::ZRAY_OK,
        "the runtime refused to start: {:?}",
        last_error()
    );
    assert_eq!(zray_mobile::zray_is_running(), 1);

    // The library owns the descriptor now; the test must not touch it again.
    let target: SocketAddr = format!("{TUNNELLED_TARGET}:{TUNNELLED_PORT}")
        .parse()
        .unwrap();
    let mut stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(target))
        .await
        .expect("connecting through the tunnel timed out")
        .expect("the tunnelled connection was refused");

    stream.write_all(b"through the descriptor").await.unwrap();
    let mut echoed = [0u8; 22];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("the echo did not come back through the tunnel")
        .expect("reading the echo");
    assert_eq!(&echoed, b"through the descriptor");

    // The datagram half travels the same descriptor and a different code
    // path, and the netstack names source and destination there too.
    let datagram = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    datagram.connect(target).await.unwrap();
    datagram
        .send(b"datagram through the descriptor")
        .await
        .unwrap();
    let mut back = vec![0u8; 2048];
    let read = tokio::time::timeout(Duration::from_secs(10), datagram.recv(&mut back))
        .await
        .expect("the datagram echo did not come back through the tunnel")
        .expect("receiving the datagram echo");
    assert_eq!(&back[..read], b"datagram through the descriptor");

    assert!(
        protector.calls.load(Ordering::Relaxed) > 0,
        "the outbound socket was never offered to the protector, so it \
         cannot have escaped the tunnel — yet traffic completed, which means \
         this test is measuring something other than what it claims"
    );

    assert_eq!(zray_mobile::zray_stop(), zray_mobile::ZRAY_OK);
    assert_eq!(zray_mobile::zray_is_running(), 0);
}

fn last_error() -> Option<String> {
    let pointer = zray_mobile::zray_last_error();
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the pointer came from `zray_last_error` and is freed here.
    let message = unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned();
    unsafe { zray_mobile::zray_string_free(pointer) };
    Some(message)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the namespace from scripts/tun-handover-harness.sh"]
async fn an_adopted_descriptor_is_never_configured_by_the_library() {
    // The addresses, routes and MTU on a platform-created interface came from
    // a dialog the user agreed to. A proxy that reached around that — even
    // successfully — would be changing settings the user approved for
    // something else.
    require_private_namespace();

    let fd = platform_creates_tun("zray1").expect("creating the TUN interface");
    must("ip", &["addr", "add", "10.78.0.1/24", "dev", "zray1"]);
    must("ip", &["link", "set", "dev", "zray1", "mtu", "1400"]);
    must("ip", &["link", "set", "dev", "zray1", "up"]);

    let before = run("ip", &["-o", "addr", "show", "dev", "zray1"]).unwrap();
    let mtu_before = run("ip", &["-o", "link", "show", "dev", "zray1"]).unwrap();

    // Adopt it directly, which is the path `serve_tun` takes when a descriptor
    // is waiting.
    // SAFETY: the descriptor was just created here and is handed over once.
    let device = unsafe {
        zero_tun::TunDevice::from_raw_fd(
            fd,
            zero_tun::TunConfig {
                name: "zray1".into(),
                no_packet_info: true,
                max_packet_size: 65_535,
                mtu: 1400,
            },
            0,
        )
    }
    .expect("adopting the descriptor");

    // A configuration request names an MTU and addresses that differ from the
    // host's. Nothing about the interface may change.
    let _ = device.configure_network(zero_tun::TunNetworkConfig {
        addresses: vec![zero_tun::TunAddress::parse("10.79.0.1/24").unwrap()],
        routes: vec![],
        bypass_ips: vec![],
        auto_route: false,
        strict_route: false,
    });

    let after = run("ip", &["-o", "addr", "show", "dev", "zray1"]).unwrap();
    let mtu_after = run("ip", &["-o", "link", "show", "dev", "zray1"]).unwrap();
    assert!(
        !after.contains("10.79.0.1"),
        "the library assigned an address to an interface the host owns:\n{after}"
    );
    assert_eq!(
        before.split_whitespace().collect::<Vec<_>>(),
        after.split_whitespace().collect::<Vec<_>>(),
        "the host's addresses changed"
    );
    assert!(
        mtu_before.contains("mtu 1400") && mtu_after.contains("mtu 1400"),
        "the host's MTU changed:\n{mtu_before}\n{mtu_after}"
    );
}
