//! Running the link configuration, per platform.
//!
//! `netcmd` decides *what* to run; this module runs it and knows what the
//! local tooling's failures mean. The install-and-roll-back logic itself is
//! shared, because getting it wrong is the same mistake everywhere: a
//! half-configured interface left behind when one step of four fails.
//!
//! Two behaviours need per-platform knowledge and nothing else does:
//!
//! * **What "already there" looks like.** Re-running a configuration must be
//!   a no-op, and every tool reports an existing address or route with its own
//!   wording and its own exit status.
//! * **What the link looked like before.** Only the MTU and the up/down state
//!   are restored on teardown, and only when this process changed them.

use std::io;
use std::process::Command;

use crate::netcmd::NetCommand;
use crate::{TunAddress, TunRoute};

/// The parts of an interface's prior state a guard restores.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LinkState {
    pub mtu: Option<usize>,
    pub up: bool,
}

/// Whether this build can configure a link at all.
pub(crate) const SUPPORTED: bool = cfg!(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows"
));

/// Run one command, treating "it is already like that" as success.
///
/// Idempotence is not a nicety here: a reload re-applies the same
/// configuration to a live interface, and a run that failed because the
/// address it wanted was already present would tear down a working tunnel.
pub(crate) fn run(command: &NetCommand) -> io::Result<()> {
    run_applied(command).map(|_| ())
}

/// Run one install command and report whether it changed anything: `true`
/// when it did, `false` when the tool said the state was already there.
///
/// The difference matters for state outside the tunnel's own interface. A
/// host route to the proxy server that already existed belongs to whoever
/// added it, and removing it on teardown would break their setup.
pub(crate) fn run_applied(command: &NetCommand) -> io::Result<bool> {
    let output = Command::new(&command.program)
        .args(&command.args)
        .output()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("running `{}`: {error}", command.display()),
            )
        })?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    // netsh reports failures on stdout, not stderr.
    let message = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    if is_already_present(message) {
        return Ok(false);
    }
    Err(io::Error::other(format!(
        "`{}` exited with {}: {}",
        command.display(),
        output.status,
        message
    )))
}

/// Run one teardown command, ignoring any failure. Used on teardown paths,
/// where the interface may already be gone ("Cannot find device", "not in
/// table", "Element not found.") and there is nothing useful to report.
pub(crate) fn run_best_effort(command: &NetCommand) {
    let _ = run(command);
}

/// Whether an install failure means the requested state already holds.
///
/// Matched on the message rather than the exit status because none of the
/// three tools distinguishes "already done" from "refused" in its status.
///
/// Only "it exists" wording counts. "Not found" on an *install* means the
/// interface it names is missing — `netsh` answers a route for an unknown
/// interface with "Element not found." — and treating that as success would
/// report a tunnel as routed while nothing was routed at all.
fn is_already_present(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    [
        // Linux `ip` and Darwin `route`.
        "file exists",
        "already exists",
        "already in table",
        // Darwin `ifconfig` re-aliasing an address it already has.
        "address already assigned",
        // Windows `netsh`.
        "the object already exists",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

/// The path traffic to one address takes before the tunnel is up: the next
/// hop, if the destination is not on-link, and the interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Via {
    pub gateway: Option<std::net::IpAddr>,
    pub interface: String,
}

/// Parse the next hop out of `ip route get` output, e.g.
/// `203.0.113.7 via 192.168.1.1 dev wlan0 src 192.168.1.20 uid 1000`.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn parse_ip_route_get(text: &str) -> io::Result<Via> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    // Routes that do not leave through an interface have no path to pin.
    if let Some(kind) = fields.first() {
        if matches!(
            *kind,
            "unreachable"
                | "blackhole"
                | "prohibit"
                | "throw"
                | "local"
                | "broadcast"
                | "multicast"
        ) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no forwarding route ({kind})"),
            ));
        }
    }
    let after = |keyword: &str| {
        fields
            .windows(2)
            .find(|pair| pair[0] == keyword)
            .map(|pair| pair[1])
    };
    let interface = after("dev")
        .filter(|name| !name.is_empty() && !name.starts_with('-'))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "route names no interface"))?;
    Ok(Via {
        gateway: after("via").and_then(|gateway| gateway.parse().ok()),
        interface: interface.to_owned(),
    })
}

/// Parse `route -n get` output on Darwin: `gateway: …` and `interface: …`
/// lines. A link-local IPv6 gateway is printed with its `%scope`.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn parse_darwin_route_get(text: &str) -> io::Result<Via> {
    let mut gateway = None;
    let mut interface = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("gateway:") {
            let value = value.trim();
            let value = value.split('%').next().unwrap_or(value);
            gateway = value.parse::<std::net::IpAddr>().ok();
        } else if let Some(value) = line.strip_prefix("interface:") {
            let value = value.trim();
            if !value.is_empty() && !value.starts_with('-') {
                interface = Some(value.to_owned());
            }
        }
    }
    let interface = interface
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "route names no interface"))?;
    Ok(Via { gateway, interface })
}

// ------------------------------------------------------------------- Linux

#[cfg(target_os = "linux")]
pub(crate) mod current {
    use super::*;
    use crate::netcmd::linux;

    pub(crate) fn probe(name: &str) -> io::Result<LinkState> {
        let output = Command::new("ip")
            .args(["-o", "link", "show", "dev", name])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let fields = text.split_whitespace().collect::<Vec<_>>();
        let mtu = fields
            .windows(2)
            .find(|pair| pair[0] == "mtu")
            .and_then(|pair| pair[1].parse::<usize>().ok());
        let up = fields.iter().any(|field| {
            field
                .trim_matches(['<', '>'])
                .split(',')
                .any(|flag| flag == "UP")
        });
        Ok(LinkState { mtu, up })
    }

    pub(crate) fn set_mtu(name: &str, mtu: usize) -> Vec<NetCommand> {
        vec![linux::set_mtu(name, mtu)]
    }

    pub(crate) fn link_up(name: &str) -> Vec<NetCommand> {
        vec![linux::link_up(name)]
    }

    pub(crate) fn link_down(name: &str) -> Vec<NetCommand> {
        vec![linux::link_down(name)]
    }

    pub(crate) fn add_address(name: &str, address: &TunAddress) -> NetCommand {
        linux::add_address(name, address)
    }

    pub(crate) fn del_address(name: &str, address: &TunAddress) -> NetCommand {
        linux::del_address(name, address)
    }

    pub(crate) fn add_route(name: &str, route: &TunRoute) -> NetCommand {
        linux::add_route(name, route)
    }

    pub(crate) fn del_route(name: &str, route: &TunRoute) -> NetCommand {
        linux::del_route(name, route)
    }

    /// The route the kernel would pick for `ip` right now.
    pub(crate) fn route_to(ip: std::net::IpAddr) -> io::Result<Via> {
        let output = Command::new("ip")
            .args(["route", "get", &ip.to_string()])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        parse_ip_route_get(&String::from_utf8_lossy(&output.stdout))
    }

    pub(crate) fn add_bypass_route(ip: std::net::IpAddr, via: &Via) -> NetCommand {
        linux::add_bypass_route(ip, via.gateway, &via.interface)
    }

    pub(crate) fn del_bypass_route(ip: std::net::IpAddr, via: &Via) -> NetCommand {
        linux::del_bypass_route(ip, via.gateway, &via.interface)
    }
}

// ------------------------------------------------------------------ Darwin

#[cfg(target_os = "macos")]
pub(crate) mod current {
    use super::*;
    use crate::netcmd::macos;

    pub(crate) fn probe(name: &str) -> io::Result<LinkState> {
        let output = Command::new("ifconfig").arg(name).output()?;
        if !output.status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let fields = text.split_whitespace().collect::<Vec<_>>();
        let mtu = fields
            .windows(2)
            .find(|pair| pair[0] == "mtu")
            .and_then(|pair| pair[1].parse::<usize>().ok());
        // `ifconfig` prints `flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>`.
        let up = text
            .split_once('<')
            .and_then(|(_, rest)| rest.split_once('>'))
            .is_some_and(|(flags, _)| flags.split(',').any(|flag| flag == "UP"));
        Ok(LinkState { mtu, up })
    }

    pub(crate) fn set_mtu(name: &str, mtu: usize) -> Vec<NetCommand> {
        vec![macos::set_mtu(name, mtu)]
    }

    pub(crate) fn link_up(name: &str) -> Vec<NetCommand> {
        vec![macos::link_up(name)]
    }

    pub(crate) fn link_down(name: &str) -> Vec<NetCommand> {
        vec![macos::link_down(name)]
    }

    pub(crate) fn add_address(name: &str, address: &TunAddress) -> NetCommand {
        macos::add_address(name, address)
    }

    pub(crate) fn del_address(name: &str, address: &TunAddress) -> NetCommand {
        macos::del_address(name, address)
    }

    pub(crate) fn add_route(name: &str, route: &TunRoute) -> NetCommand {
        macos::add_route(name, route)
    }

    pub(crate) fn del_route(name: &str, route: &TunRoute) -> NetCommand {
        macos::del_route(name, route)
    }

    /// The route the kernel would pick for `ip` right now.
    pub(crate) fn route_to(ip: std::net::IpAddr) -> io::Result<Via> {
        let family = if ip.is_ipv6() { "-inet6" } else { "-inet" };
        let output = Command::new("route")
            .args(["-n", "get", family, &ip.to_string()])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        parse_darwin_route_get(&String::from_utf8_lossy(&output.stdout))
    }

    pub(crate) fn add_bypass_route(ip: std::net::IpAddr, via: &Via) -> NetCommand {
        macos::add_bypass_route(ip, via.gateway, &via.interface)
    }

    pub(crate) fn del_bypass_route(ip: std::net::IpAddr, via: &Via) -> NetCommand {
        macos::del_bypass_route(ip, via.gateway, &via.interface)
    }
}

// ----------------------------------------------------------------- Windows

#[cfg(target_os = "windows")]
pub(crate) mod current {
    use super::*;
    use crate::netcmd::windows;

    /// Windows keeps the MTU on the subinterface and reports it per family.
    /// There is no single "link is up" bit that means what it does on Unix —
    /// a Wintun adapter is up as soon as it exists — so the state to restore
    /// is the IPv4 MTU alone.
    pub(crate) fn probe(name: &str) -> io::Result<LinkState> {
        let output = Command::new("netsh")
            .args(["interface", "ipv4", "show", "subinterface", name])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        // The table's first numeric column is the MTU.
        let mtu = text
            .lines()
            .filter(|line| line.contains(name))
            .find_map(|line| line.split_whitespace().next()?.parse::<usize>().ok());
        Ok(LinkState { mtu, up: true })
    }

    pub(crate) fn set_mtu(name: &str, mtu: usize) -> Vec<NetCommand> {
        vec![
            windows::set_mtu(name, mtu, false),
            windows::set_mtu(name, mtu, true),
        ]
    }

    /// A Wintun adapter carries traffic as soon as it is created, so there is
    /// no separate link-up step to perform or to undo.
    pub(crate) fn link_up(_name: &str) -> Vec<NetCommand> {
        Vec::new()
    }

    pub(crate) fn link_down(_name: &str) -> Vec<NetCommand> {
        Vec::new()
    }

    pub(crate) fn add_address(name: &str, address: &TunAddress) -> NetCommand {
        windows::add_address(name, address)
    }

    pub(crate) fn del_address(name: &str, address: &TunAddress) -> NetCommand {
        windows::del_address(name, address)
    }

    pub(crate) fn add_route(name: &str, route: &TunRoute) -> NetCommand {
        windows::add_route(name, route)
    }

    pub(crate) fn del_route(name: &str, route: &TunRoute) -> NetCommand {
        windows::del_route(name, route)
    }

    /// Not implemented: `netsh` has no "which route would you use" query,
    /// and `route print` is not stable enough to parse. The bypass step is
    /// skipped, as it is for any server with no current route.
    pub(crate) fn route_to(_ip: std::net::IpAddr) -> io::Result<Via> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "per-destination route lookup is not implemented on Windows",
        ))
    }

    pub(crate) fn add_bypass_route(ip: std::net::IpAddr, via: &Via) -> NetCommand {
        windows::add_bypass_route(ip, via.gateway, &via.interface)
    }

    pub(crate) fn del_bypass_route(ip: std::net::IpAddr, via: &Via) -> NetCommand {
        windows::del_bypass_route(ip, via.gateway, &via.interface)
    }
}

// ------------------------------------------------------- unsupported hosts

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) mod current {
    use super::*;

    pub(crate) fn probe(_name: &str) -> io::Result<LinkState> {
        Err(io::Error::other("no link configuration on this platform"))
    }

    pub(crate) fn set_mtu(_name: &str, _mtu: usize) -> Vec<NetCommand> {
        Vec::new()
    }

    pub(crate) fn link_up(_name: &str) -> Vec<NetCommand> {
        Vec::new()
    }

    pub(crate) fn link_down(_name: &str) -> Vec<NetCommand> {
        Vec::new()
    }

    pub(crate) fn add_address(_name: &str, _address: &TunAddress) -> NetCommand {
        NetCommand::new::<_, [String; 0], _>("false", [])
    }

    pub(crate) fn del_address(_name: &str, _address: &TunAddress) -> NetCommand {
        NetCommand::new::<_, [String; 0], _>("false", [])
    }

    pub(crate) fn add_route(_name: &str, _route: &TunRoute) -> NetCommand {
        NetCommand::new::<_, [String; 0], _>("false", [])
    }

    pub(crate) fn del_route(_name: &str, _route: &TunRoute) -> NetCommand {
        NetCommand::new::<_, [String; 0], _>("false", [])
    }

    pub(crate) fn route_to(_ip: std::net::IpAddr) -> io::Result<Via> {
        Err(io::Error::other("unsupported platform"))
    }

    pub(crate) fn add_bypass_route(_ip: std::net::IpAddr, _via: &Via) -> NetCommand {
        NetCommand::new::<_, [String; 0], _>("false", [])
    }

    pub(crate) fn del_bypass_route(_ip: std::net::IpAddr, _via: &Via) -> NetCommand {
        NetCommand::new::<_, [String; 0], _>("false", [])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_existing_address_or_route_is_not_a_failure() {
        // Re-applying a live configuration on reload must be a no-op. Each of
        // these is what one of the three platforms actually prints.
        for message in [
            "RTNETLINK answers: File exists",
            "route: writing to routing socket: File exists",
            "add net 0.0.0.0: gateway utun5: File exists",
            "ifconfig: ioctl (SIOCAIFADDR): Address already assigned",
            "The object already exists.",
        ] {
            assert!(
                is_already_present(message),
                "{message:?} should be treated as done"
            );
        }
    }

    #[test]
    fn removing_something_already_gone_is_not_a_failure() {
        // Teardown tolerates every failure: the interface may already be gone
        // with everything on it. A command that fails outright must neither
        // panic nor report.
        run_best_effort(&NetCommand {
            program: "zray-no-such-tool".into(),
            args: vec!["route".into(), "del".into()],
        });
    }

    #[test]
    fn an_install_that_names_something_missing_is_a_failure() {
        // These are what the tools say when the *interface* an install names
        // does not exist. Treating them as "already done" reported a route as
        // installed while nothing had been routed — `netsh` answers an add
        // for an unknown interface with exactly "Element not found."
        for message in [
            "Cannot find device \"zray0\"",
            "route: delete net 0.0.0.0: not in table",
            "Element not found.",
            "RTNETLINK answers: No such process",
        ] {
            assert!(
                !is_already_present(message),
                "{message:?} must not count as an installed route"
            );
        }
    }

    #[test]
    fn the_route_to_a_server_is_read_from_ip_route_get() {
        let via = parse_ip_route_get(
            "203.0.113.7 via 192.168.1.1 dev wlan0 src 192.168.1.20 uid 1000 \n    cache",
        )
        .unwrap();
        assert_eq!(via.gateway, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(via.interface, "wlan0");

        // On-link: no gateway, only the interface.
        let via = parse_ip_route_get("192.168.1.5 dev eth0 src 192.168.1.20 uid 0").unwrap();
        assert_eq!(via.gateway, None);
        assert_eq!(via.interface, "eth0");

        // IPv6 through a link-local next hop keeps the next hop.
        let via = parse_ip_route_get(
            "2001:db8::7 from :: via fe80::1 dev wlan0 proto ra src 2001:db8::20 metric 600 pref medium",
        )
        .unwrap();
        assert_eq!(via.gateway, Some("fe80::1".parse().unwrap()));

        // Nothing to pin for addresses that are not forwarded anywhere.
        assert!(parse_ip_route_get("local 127.0.0.1 dev lo table local src 127.0.0.1").is_err());
        assert!(parse_ip_route_get("unreachable 203.0.113.9").is_err());
    }

    #[test]
    fn the_route_to_a_server_is_read_from_darwin_route_get() {
        let via = parse_darwin_route_get(
            "   route to: 203.0.113.7\ndestination: default\n       mask: default\n    \
             gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>",
        )
        .unwrap();
        assert_eq!(via.gateway, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(via.interface, "en0");

        let via = parse_darwin_route_get("    gateway: fe80::1%en0\n  interface: en0").unwrap();
        assert_eq!(via.gateway, Some("fe80::1".parse().unwrap()));

        assert!(parse_darwin_route_get("route: writing to routing socket: not in table").is_err());
    }

    #[test]
    fn a_real_failure_is_still_a_failure() {
        // The tolerance above must not swallow the errors that matter — an
        // unprivileged process quietly "succeeding" at configuring nothing is
        // exactly the outcome to avoid.
        for message in [
            "Operation not permitted",
            "RTNETLINK answers: Operation not permitted",
            "ifconfig: interface utun5 does not exist",
            "Access is denied.",
            "The requested operation requires elevation.",
        ] {
            assert!(
                !is_already_present(message),
                "{message:?} must not be swallowed"
            );
        }
    }

    #[test]
    fn a_missing_program_names_the_command_that_was_attempted() {
        let command = NetCommand {
            program: "zray-no-such-tool".into(),
            args: vec!["link".into(), "show".into()],
        };
        let error = run(&command).expect_err("the program does not exist");
        assert!(
            error.to_string().contains("zray-no-such-tool link show"),
            "the error should say what was attempted, got: {error}"
        );
    }
}
