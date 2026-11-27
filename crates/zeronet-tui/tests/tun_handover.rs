//! End-to-end test of the privileged TUN handover.
//!
//! The whole point of `elevate` is that an unprivileged process ends up
//! holding a working TUN descriptor it could not have opened itself. Nothing
//! short of actually doing it proves that: the interesting failures are a
//! `sendmsg` control buffer that is the wrong size, a descriptor that arrives
//! closed, a header length that does not travel with it, and routes that are
//! never removed.
//!
//! Real privileges are obtained without touching the developer's machine by
//! re-running this test inside an unprivileged user namespace with its own
//! network namespace (`unshare -rn`). Inside it the process is root, holds
//! `CAP_NET_ADMIN`, and every interface and route it creates belongs to a
//! namespace that disappears when the test does — so a test that crashes
//! part-way through cannot leave the machine altered.
//!
//! Skipped, rather than failed, where user namespaces are unavailable: that
//! is a property of the kernel's configuration, not of this code.

use std::process::Command;

const REENTRY: &str = "ZERONET_TUN_HANDOVER_INNER";

/// Whether this process is the copy running inside the namespace.
fn inside_namespace() -> bool {
    std::env::var_os(REENTRY).is_some()
}

/// Re-run one test of this binary inside `unshare -rn`, and report what it said.
///
/// Returns `None` when a namespace could not be created at all.
fn run_inside(test_name: &str) -> Option<std::process::Output> {
    if Command::new("unshare")
        .args(["-rn", "true"])
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        return None;
    }

    let exe = std::env::current_exe().expect("test binary path");
    let output = Command::new("unshare")
        .arg("-rn")
        .arg(&exe)
        .arg(test_name)
        .args(["--exact", "--nocapture", "--test-threads=1"])
        .env(REENTRY, "1")
        // `open_privileged_tun` would otherwise re-execute *this* test
        // binary as the helper, which libtest rejects.
        .env("ZERONET_TUN_HELPER", env!("CARGO_BIN_EXE_zeronet-tui"))
        .output()
        .expect("running the test inside a namespace");
    Some(output)
}

/// Run `body` as the privileged half, either directly or by re-entering.
fn privileged(test_name: &str, body: impl FnOnce()) {
    if inside_namespace() {
        body();
        return;
    }
    match run_inside(test_name) {
        Some(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "{test_name} failed inside the namespace\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
            );
        }
        None => eprintln!(
            "skipping {test_name}: unprivileged user namespaces are unavailable on this kernel"
        ),
    }
}

fn request(name: &str, socket: &str) -> zeronet_tui::elevate::TunRequest {
    zeronet_tui::elevate::TunRequest {
        name: name.to_string(),
        mtu: 1400,
        addresses: vec!["10.254.0.1/30".into()],
        routes: vec!["0.0.0.0/1".into(), "128.0.0.0/1".into()],
        auto_route: true,
        strict_route: false,
        bypass_ips: Vec::new(),
        socket_path: socket.to_string(),
    }
}

/// Everything `ip` knows about the interfaces in this namespace.
fn interfaces() -> String {
    Command::new("ip")
        .args(["link", "show"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn routes() -> String {
    Command::new("ip")
        .args(["route", "show"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

#[test]
fn the_helper_hands_over_a_usable_descriptor_and_a_configured_link() {
    privileged(
        "the_helper_hands_over_a_usable_descriptor_and_a_configured_link",
        || {
            use std::os::fd::AsRawFd;

            let socket = zeronet_tui::elevate::handover_socket_path();
            let request = request("zrayho0", &socket);

            let (mut helper, handover) = zeronet_tui::elevate::open_privileged_tun(&request, None)
                .expect("the helper should bring up a TUN");

            // A descriptor that arrives closed, or as the wrong kind of
            // object, is the failure this whole mechanism turns on.
            assert!(handover.fd >= 0, "no descriptor came back");
            let flags = unsafe { libc::fcntl(handover.fd, libc::F_GETFD) };
            assert!(flags >= 0, "the descriptor arrived closed");
            assert_eq!(handover.mtu, 1400);
            assert_eq!(handover.device, "zrayho0");
            // Linux with IFF_NO_PI delivers bare IP packets. A wrong header
            // length mangles every packet without ever erroring.
            assert_eq!(
                handover.header_len, 0,
                "wrong framing travelled with the fd"
            );

            // The interface has to exist, carry the address and the MTU, and
            // be up — the helper's job, not the client's.
            let links = interfaces();
            assert!(
                links.contains("zrayho0"),
                "the interface was never created:\n{links}"
            );
            assert!(
                links.contains("mtu 1400"),
                "the MTU was not applied:\n{links}"
            );
            let addrs = Command::new("ip")
                .args(["addr", "show", "dev", "zrayho0"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            assert!(
                addrs.contains("10.254.0.1/30"),
                "the address was not assigned:\n{addrs}"
            );

            let table = routes();
            assert!(
                table.contains("0.0.0.0/1") && table.contains("128.0.0.0/1"),
                "the default routes were not installed:\n{table}"
            );

            assert!(helper.is_running(), "the helper exited after the handover");

            // The descriptor must be usable by this process, which never had
            // the privileges to open one. Writing a malformed packet is
            // enough: the kernel accepts the write into the device and drops
            // it, which proves the fd is a live TUN we own.
            let packet = [0u8; 20];
            let written = unsafe { libc::write(handover.fd, packet.as_ptr().cast(), packet.len()) };
            assert!(
                written > 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL),
                "the descriptor is not a writable TUN: {}",
                std::io::Error::last_os_error()
            );

            // Teardown is structural: dropping the helper closes its stdin,
            // which is the signal to undo everything it installed.
            let socket_file = std::path::PathBuf::from(&socket);
            drop(helper);
            unsafe {
                libc::close(handover.fd);
            }

            // The interface goes when the last descriptor closes, and the
            // routes go with it. A machine left routing into a dead interface
            // is the worst outcome this code can produce.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut links = interfaces();
            while links.contains("zrayho0") && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
                links = interfaces();
            }
            assert!(
                !links.contains("zrayho0"),
                "the interface outlived the helper:\n{links}"
            );
            let table = routes();
            assert!(
                !table.contains("0.0.0.0/1"),
                "the routes outlived the helper:\n{table}"
            );
            assert!(
                !socket_file.exists(),
                "the handover socket was left behind at {socket}"
            );

            // The descriptor really was the only thing keeping it alive.
            let _ = flags;
            let _ = std::io::stdout().as_raw_fd();
        },
    );
}

/// Switching servers with TUN on used to fail: a new helper tried to create
/// the interface while the running engine still held the old one open, and
/// the kernel refused the name. Now the helper stays, only the bypass route
/// moves, and the next engine gets a fresh descriptor to the same device.
#[test]
fn switching_servers_reroutes_the_bypass_without_rebuilding_the_interface() {
    privileged(
        "switching_servers_reroutes_the_bypass_without_rebuilding_the_interface",
        || {
            // A stand-in for the physical uplink the bypass routes must use.
            for args in [
                &["link", "add", "up0", "type", "dummy"][..],
                &["addr", "add", "192.0.2.2/24", "dev", "up0"],
                &["link", "set", "up0", "up"],
                &["route", "add", "default", "via", "192.0.2.1", "dev", "up0"],
            ] {
                let status = Command::new("ip").args(args).status().unwrap();
                assert!(status.success(), "ip {args:?} failed");
            }

            let socket = zeronet_tui::elevate::handover_socket_path();
            let mut first = request("zraysw0", &socket);
            first.bypass_ips = vec!["203.0.113.7".into()];
            let (mut helper, engine_one) = zeronet_tui::elevate::open_privileged_tun(&first, None)
                .expect("the helper should bring up a TUN");
            let table = routes();
            assert!(
                table.contains("203.0.113.7 via 192.0.2.1 dev up0"),
                "the first server was not kept off the tunnel:\n{table}"
            );

            // The switch, while engine one still has its descriptor open.
            let mut second = request("zraysw0", &socket);
            second.bypass_ips = vec!["198.51.100.9".into()];
            assert!(
                helper.serves(&second),
                "same interface, only the server differs"
            );
            let engine_two = helper.retarget(&second).expect("the switch should reroute");

            let table = routes();
            assert!(
                table.contains("198.51.100.9 via 192.0.2.1 dev up0"),
                "the new server is routed into the tunnel:\n{table}"
            );
            assert!(
                !table.contains("203.0.113.7"),
                "the old server's bypass was left behind:\n{table}"
            );
            assert!(
                table.contains("0.0.0.0/1"),
                "the tunnel routes went away during the switch:\n{table}"
            );
            assert_ne!(engine_two.fd, engine_one.fd);
            assert_eq!(engine_two.device, "zraysw0");
            let flags = unsafe { libc::fcntl(engine_two.fd, libc::F_GETFD) };
            assert!(flags >= 0, "the new descriptor is not open");

            // Engine one stops. The interface must survive it: the client
            // keeps its own descriptor for exactly this.
            unsafe { libc::close(engine_one.fd) };
            assert!(
                interfaces().contains("zraysw0"),
                "the interface died with engine one"
            );

            // A different interface cannot be served by this helper.
            let mut other = request("zraysw0", &socket);
            other.mtu = 1300;
            assert!(!helper.serves(&other));

            drop(helper);
            unsafe { libc::close(engine_two.fd) };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while interfaces().contains("zraysw0") && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            assert!(
                !interfaces().contains("zraysw0"),
                "the interface outlived everything"
            );
            let table = routes();
            assert!(
                !table.contains("198.51.100.9") && !table.contains("0.0.0.0/1"),
                "routes outlived the helper:\n{table}"
            );
        },
    );
}

#[test]
fn a_second_handover_replaces_the_first_without_leaking_an_interface() {
    privileged(
        "a_second_handover_replaces_the_first_without_leaking_an_interface",
        || {
            // Reconnecting asks for a new descriptor while the old engine is
            // being retired. Two live helpers for the same device name is the
            // shape of that bug.
            let first_socket = zeronet_tui::elevate::handover_socket_path();
            let (first, first_fd) = {
                let (helper, handover) = zeronet_tui::elevate::open_privileged_tun(
                    &request("zrayho1", &first_socket),
                    None,
                )
                .expect("first handover");
                (helper, handover.fd)
            };
            assert!(interfaces().contains("zrayho1"));

            drop(first);
            unsafe {
                libc::close(first_fd);
            }

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while interfaces().contains("zrayho1") && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            let second_socket = zeronet_tui::elevate::handover_socket_path();
            assert_ne!(first_socket, second_socket);
            let (second, second_handover) = zeronet_tui::elevate::open_privileged_tun(
                &request("zrayho1", &second_socket),
                None,
            )
            .expect("the same device name should be reusable after teardown");
            assert!(interfaces().contains("zrayho1"));

            drop(second);
            unsafe {
                libc::close(second_handover.fd);
            }
        },
    );
}

#[test]
fn a_request_the_kernel_refuses_is_reported_rather_than_left_half_applied() {
    privileged(
        "a_request_the_kernel_refuses_is_reported_rather_than_left_half_applied",
        || {
            // An interface name longer than IFNAMSIZ cannot be created. The
            // client has to hear about it instead of waiting for a descriptor
            // that never arrives.
            let socket = zeronet_tui::elevate::handover_socket_path();
            let mut bad = request("this-name-is-far-too-long-for-a-link", &socket);
            bad.name = "this-name-is-far-too-long-for-a-link".into();

            let outcome = zeronet_tui::elevate::open_privileged_tun(&bad, None);
            assert!(
                outcome.is_err(),
                "an impossible request appeared to succeed"
            );
            let message = outcome.err().unwrap().to_string();
            assert!(!message.is_empty(), "the failure carried no explanation");

            // Nothing was left behind for the next attempt to trip over.
            assert!(
                !std::path::Path::new(&socket).exists(),
                "the handover socket survived a failed attempt"
            );
        },
    );
}
