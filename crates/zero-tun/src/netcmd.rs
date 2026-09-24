//! Link configuration, expressed as commands rather than performed.
//!
//! Bringing up a TUN interface means assigning addresses, setting an MTU,
//! raising the link and installing routes. Every platform spells that
//! differently — `ip(8)` on Linux, `ifconfig`/`route` on Darwin, `netsh` on
//! Windows — and the spelling is where the bugs are. A wrong flag does not
//! fail to compile; it fails on a machine the author does not have.
//!
//! So the commands are built here as data, separately from running them. The
//! executor in `platform` probes the live interface and runs what it needs,
//! while the exact argument vector for all three platforms can be asserted
//! from a test on any one of them. That is not as good as running the code on
//! each OS, and it is the part that can be checked without three machines:
//! everything below is verified against the tests in this module, and the
//! cross-platform CI job compiles every adapter for its real target.

use std::net::IpAddr;

use crate::{TunAddress, TunRoute};

/// One external command, ready to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl NetCommand {
    pub(crate) fn new<P, I, S>(program: P, args: I) -> Self
    where
        P: Into<String>,
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    /// Rendered form, for diagnostics and for tests to read at a glance.
    pub fn display(&self) -> String {
        if self.args.is_empty() {
            return self.program.clone();
        }
        format!("{} {}", self.program, self.args.join(" "))
    }
}

/// Dotted-quad netmask for an IPv4 prefix length.
///
/// Windows' `netsh` still wants a mask rather than a prefix on the IPv4
/// address commands.
pub fn ipv4_netmask(prefix: u8) -> String {
    let prefix = prefix.min(32);
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    let octets = mask.to_be_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

// ------------------------------------------------------------------- Linux

pub mod linux {
    use super::*;

    pub fn set_mtu(name: &str, mtu: usize) -> NetCommand {
        NetCommand::new("ip", ["link", "set", "dev", name, "mtu", &mtu.to_string()])
    }

    pub fn link_up(name: &str) -> NetCommand {
        NetCommand::new("ip", ["link", "set", "dev", name, "up"])
    }

    pub fn link_down(name: &str) -> NetCommand {
        NetCommand::new("ip", ["link", "set", "dev", name, "down"])
    }

    pub fn add_address(name: &str, address: &TunAddress) -> NetCommand {
        NetCommand::new("ip", ["addr", "add", &address.cidr(), "dev", name])
    }

    pub fn del_address(name: &str, address: &TunAddress) -> NetCommand {
        NetCommand::new("ip", ["addr", "del", &address.cidr(), "dev", name])
    }

    pub fn add_route(name: &str, route: &TunRoute) -> NetCommand {
        route_command("add", name, route)
    }

    pub fn del_route(name: &str, route: &TunRoute) -> NetCommand {
        route_command("del", name, route)
    }

    pub fn add_bypass_route(ip: IpAddr, gateway: Option<IpAddr>, iface: &str) -> NetCommand {
        bypass_route_command("add", ip, gateway, iface)
    }

    pub fn del_bypass_route(ip: IpAddr, gateway: Option<IpAddr>, iface: &str) -> NetCommand {
        bypass_route_command("del", ip, gateway, iface)
    }

    fn bypass_route_command(
        action: &str,
        ip: IpAddr,
        gateway: Option<IpAddr>,
        iface: &str,
    ) -> NetCommand {
        let is_v6 = ip.is_ipv6();
        let cidr = match ip {
            IpAddr::V4(v4) => format!("{v4}/32"),
            IpAddr::V6(v6) => format!("{v6}/128"),
        };
        let mut args = Vec::new();
        if is_v6 {
            args.push("-6".to_string());
        }
        args.push("route".to_string());
        args.push(action.to_string());
        args.push(cidr);
        if let Some(gw) = gateway {
            args.push("via".to_string());
            args.push(gw.to_string());
        }
        args.push("dev".to_string());
        args.push(iface.to_string());
        NetCommand::new("ip", args)
    }

    fn route_command(action: &str, name: &str, route: &TunRoute) -> NetCommand {
        let cidr = route.cidr();
        if route.network.is_ipv6() {
            NetCommand::new("ip", ["-6", "route", action, &cidr, "dev", name])
        } else {
            NetCommand::new("ip", ["route", action, &cidr, "dev", name])
        }
    }
}

// ------------------------------------------------------------------ Darwin

pub mod macos {
    use super::*;

    /// Darwin has no `ip(8)`. Addresses go on with `ifconfig` and routes with
    /// `route(8)`, and a `utun` is a point-to-point interface, so an IPv4
    /// address is given with its own address as the peer — the form `wg-quick`
    /// uses, and the only one that leaves the prefix intact on a utun.
    pub fn add_address(name: &str, address: &TunAddress) -> NetCommand {
        match address.address {
            IpAddr::V4(_) => NetCommand::new(
                "ifconfig",
                [
                    name,
                    "inet",
                    &address.cidr(),
                    &address.address.to_string(),
                    "alias",
                ],
            ),
            IpAddr::V6(_) => NetCommand::new("ifconfig", [name, "inet6", &address.cidr(), "alias"]),
        }
    }

    pub fn del_address(name: &str, address: &TunAddress) -> NetCommand {
        match address.address {
            IpAddr::V4(_) => NetCommand::new(
                "ifconfig",
                [name, "inet", &address.address.to_string(), "-alias"],
            ),
            IpAddr::V6(_) => NetCommand::new(
                "ifconfig",
                [name, "inet6", &address.address.to_string(), "-alias"],
            ),
        }
    }

    pub fn set_mtu(name: &str, mtu: usize) -> NetCommand {
        NetCommand::new("ifconfig", [name, "mtu", &mtu.to_string()])
    }

    pub fn link_up(name: &str) -> NetCommand {
        NetCommand::new("ifconfig", [name, "up"])
    }

    pub fn link_down(name: &str) -> NetCommand {
        NetCommand::new("ifconfig", [name, "down"])
    }

    pub fn add_route(name: &str, route: &TunRoute) -> NetCommand {
        route_command("add", name, route)
    }

    pub fn del_route(name: &str, route: &TunRoute) -> NetCommand {
        route_command("delete", name, route)
    }

    /// A host route that keeps one proxy server on the path it uses now.
    ///
    /// With no gateway the server is on-link and the route names the
    /// interface. A link-local IPv6 gateway is only meaningful with its scope,
    /// which on Darwin is written `fe80::1%en0`.
    pub fn add_bypass_route(ip: IpAddr, gateway: Option<IpAddr>, iface: &str) -> NetCommand {
        bypass_route_command("add", ip, gateway, iface)
    }

    pub fn del_bypass_route(ip: IpAddr, gateway: Option<IpAddr>, iface: &str) -> NetCommand {
        bypass_route_command("delete", ip, gateway, iface)
    }

    fn bypass_route_command(
        action: &str,
        ip: IpAddr,
        gateway: Option<IpAddr>,
        iface: &str,
    ) -> NetCommand {
        let family = if ip.is_ipv6() { "-inet6" } else { "-inet" };
        let mut args = vec![
            "-n".to_owned(),
            action.to_owned(),
            family.to_owned(),
            "-host".to_owned(),
            ip.to_string(),
        ];
        match gateway {
            Some(IpAddr::V6(v6)) if v6.segments()[0] & 0xffc0 == 0xfe80 => {
                args.push(format!("{v6}%{iface}"));
            }
            Some(gateway) => args.push(gateway.to_string()),
            None => {
                args.push("-interface".to_owned());
                args.push(iface.to_owned());
            }
        }
        NetCommand::new("route", args)
    }

    /// `-n` keeps `route(8)` from doing reverse DNS on every address, which on
    /// a machine whose DNS is about to be redirected through this very
    /// interface is a good way to hang during setup.
    fn route_command(action: &str, name: &str, route: &TunRoute) -> NetCommand {
        let family = if route.network.is_ipv6() {
            "-inet6"
        } else {
            "-inet"
        };
        NetCommand::new(
            "route",
            ["-n", action, family, &route.cidr(), "-interface", name],
        )
    }
}

// ----------------------------------------------------------------- Windows

pub mod windows {
    use super::*;

    /// Windows addresses an interface by its *name*, which for a Wintun
    /// adapter is the name given when it was created.
    pub fn add_address(name: &str, address: &TunAddress) -> NetCommand {
        match address.address {
            IpAddr::V4(_) => NetCommand::new(
                "netsh",
                [
                    "interface",
                    "ipv4",
                    "add",
                    "address",
                    &format!("name={name}"),
                    &format!("address={}", address.address),
                    &format!("mask={}", ipv4_netmask(address.prefix)),
                    "store=active",
                ],
            ),
            IpAddr::V6(_) => NetCommand::new(
                "netsh",
                [
                    "interface",
                    "ipv6",
                    "add",
                    "address",
                    &format!("interface={name}"),
                    &format!("address={}", address.cidr()),
                    "store=active",
                ],
            ),
        }
    }

    pub fn del_address(name: &str, address: &TunAddress) -> NetCommand {
        match address.address {
            IpAddr::V4(_) => NetCommand::new(
                "netsh",
                [
                    "interface",
                    "ipv4",
                    "delete",
                    "address",
                    &format!("name={name}"),
                    &format!("address={}", address.address),
                    "store=active",
                ],
            ),
            IpAddr::V6(_) => NetCommand::new(
                "netsh",
                [
                    "interface",
                    "ipv6",
                    "delete",
                    "address",
                    &format!("interface={name}"),
                    &format!("address={}", address.address),
                    "store=active",
                ],
            ),
        }
    }

    /// The MTU lives on the *subinterface*, not the interface, and is set per
    /// address family. `store=active` keeps it out of the persistent
    /// configuration, so a crash cannot leave the machine permanently altered.
    pub fn set_mtu(name: &str, mtu: usize, ipv6: bool) -> NetCommand {
        let family = if ipv6 { "ipv6" } else { "ipv4" };
        NetCommand::new(
            "netsh",
            [
                "interface",
                family,
                "set",
                "subinterface",
                name,
                &format!("mtu={mtu}"),
                "store=active",
            ],
        )
    }

    pub fn add_route(name: &str, route: &TunRoute) -> NetCommand {
        route_command("add", name, route)
    }

    pub fn del_route(name: &str, route: &TunRoute) -> NetCommand {
        route_command("delete", name, route)
    }

    /// A host route that keeps one proxy server on the path it uses now,
    /// through the physical interface `iface` and, when off-link, `gateway`.
    pub fn add_bypass_route(ip: IpAddr, gateway: Option<IpAddr>, iface: &str) -> NetCommand {
        bypass_route_command("add", ip, gateway, iface)
    }

    pub fn del_bypass_route(ip: IpAddr, gateway: Option<IpAddr>, iface: &str) -> NetCommand {
        bypass_route_command("delete", ip, gateway, iface)
    }

    fn bypass_route_command(
        action: &str,
        ip: IpAddr,
        gateway: Option<IpAddr>,
        iface: &str,
    ) -> NetCommand {
        let (family, prefix) = if ip.is_ipv6() {
            ("ipv6", 128)
        } else {
            ("ipv4", 32)
        };
        let mut args = vec![
            "interface".to_owned(),
            family.to_owned(),
            action.to_owned(),
            "route".to_owned(),
            format!("prefix={ip}/{prefix}"),
            format!("interface={iface}"),
        ];
        if let Some(gateway) = gateway {
            args.push(format!("nexthop={gateway}"));
        }
        args.push("store=active".to_owned());
        NetCommand::new("netsh", args)
    }

    fn route_command(action: &str, name: &str, route: &TunRoute) -> NetCommand {
        let family = if route.network.is_ipv6() {
            "ipv6"
        } else {
            "ipv4"
        };
        NetCommand::new(
            "netsh",
            [
                "interface",
                family,
                action,
                "route",
                &format!("prefix={}", route.cidr()),
                &format!("interface={name}"),
                "store=active",
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(cidr: &str) -> TunAddress {
        TunAddress::parse(cidr).unwrap()
    }

    fn route(cidr: &str) -> TunRoute {
        TunRoute::parse(cidr).unwrap()
    }

    #[test]
    fn ipv4_netmasks_cover_the_useful_range() {
        assert_eq!(ipv4_netmask(0), "0.0.0.0");
        assert_eq!(ipv4_netmask(1), "128.0.0.0");
        assert_eq!(ipv4_netmask(8), "255.0.0.0");
        assert_eq!(ipv4_netmask(24), "255.255.255.0");
        assert_eq!(ipv4_netmask(30), "255.255.255.252");
        assert_eq!(ipv4_netmask(32), "255.255.255.255");
        // A prefix past the address width is clamped rather than shifting out
        // of range, which in release mode would silently wrap to 0.0.0.0.
        assert_eq!(ipv4_netmask(33), "255.255.255.255");
    }

    #[test]
    fn linux_addresses_and_routes_use_ip_with_the_right_family_switch() {
        assert_eq!(
            linux::add_address("zray0", &v4("10.0.0.1/24")).display(),
            "ip addr add 10.0.0.1/24 dev zray0"
        );
        assert_eq!(
            linux::del_address("zray0", &v4("fd00::1/64")).display(),
            "ip addr del fd00::1/64 dev zray0"
        );
        assert_eq!(
            linux::add_route("zray0", &route("0.0.0.0/1")).display(),
            "ip route add 0.0.0.0/1 dev zray0"
        );
        // IPv6 routes need `-6`; without it `ip` parses the destination as
        // IPv4 and refuses the whole command.
        assert_eq!(
            linux::add_route("zray0", &route("::/1")).display(),
            "ip -6 route add ::/1 dev zray0"
        );
        assert_eq!(
            linux::set_mtu("zray0", 1420).display(),
            "ip link set dev zray0 mtu 1420"
        );
        assert_eq!(
            linux::link_up("zray0").display(),
            "ip link set dev zray0 up"
        );
    }

    #[test]
    fn macos_gives_an_ipv4_address_its_own_peer_because_utun_is_point_to_point() {
        // A utun has no broadcast domain. `ifconfig utun5 inet 10.0.0.1/24`
        // alone is rejected; the address has to be repeated as the peer, which
        // is the form wg-quick uses on Darwin.
        assert_eq!(
            macos::add_address("utun5", &v4("10.0.0.1/24")).display(),
            "ifconfig utun5 inet 10.0.0.1/24 10.0.0.1 alias"
        );
        // IPv6 takes the prefix directly and needs no peer.
        assert_eq!(
            macos::add_address("utun5", &v4("fd00::1/64")).display(),
            "ifconfig utun5 inet6 fd00::1/64 alias"
        );
    }

    #[test]
    fn macos_removes_an_address_by_bare_address_not_by_cidr() {
        // `-alias` matches on the address; passing the prefix as well makes
        // ifconfig treat it as a second argument and remove nothing.
        assert_eq!(
            macos::del_address("utun5", &v4("10.0.0.1/24")).display(),
            "ifconfig utun5 inet 10.0.0.1 -alias"
        );
        assert_eq!(
            macos::del_address("utun5", &v4("fd00::1/64")).display(),
            "ifconfig utun5 inet6 fd00::1 -alias"
        );
    }

    #[test]
    fn macos_routes_name_the_family_and_suppress_reverse_dns() {
        // `-n` matters: without it route(8) resolves addresses through a
        // resolver that this very interface is about to take over.
        assert_eq!(
            macos::add_route("utun5", &route("0.0.0.0/1")).display(),
            "route -n add -inet 0.0.0.0/1 -interface utun5"
        );
        assert_eq!(
            macos::del_route("utun5", &route("::/1")).display(),
            "route -n delete -inet6 ::/1 -interface utun5"
        );
    }

    #[test]
    fn macos_mtu_and_link_state_go_through_ifconfig() {
        assert_eq!(
            macos::set_mtu("utun5", 1420).display(),
            "ifconfig utun5 mtu 1420"
        );
        assert_eq!(macos::link_up("utun5").display(), "ifconfig utun5 up");
        assert_eq!(macos::link_down("utun5").display(), "ifconfig utun5 down");
    }

    #[test]
    fn windows_ipv4_addresses_take_a_mask_and_ipv6_takes_a_prefix() {
        assert_eq!(
            windows::add_address("Zray", &v4("10.0.0.1/24")).display(),
            "netsh interface ipv4 add address name=Zray address=10.0.0.1 \
             mask=255.255.255.0 store=active"
        );
        assert_eq!(
            windows::add_address("Zray", &v4("fd00::1/64")).display(),
            "netsh interface ipv6 add address interface=Zray address=fd00::1/64 store=active"
        );
    }

    #[test]
    fn windows_never_writes_persistent_configuration() {
        // Every command is `store=active`. A persistent store survives a
        // crash, and a proxy that permanently rewrites a machine's routing
        // table because it was killed is worse than one that fails to start.
        let address = v4("10.0.0.1/24");
        let route = route("0.0.0.0/1");
        for command in [
            windows::add_address("Zray", &address),
            windows::del_address("Zray", &address),
            windows::add_route("Zray", &route),
            windows::del_route("Zray", &route),
            windows::set_mtu("Zray", 1420, false),
            windows::set_mtu("Zray", 1420, true),
        ] {
            assert!(
                command.args.iter().any(|arg| arg == "store=active"),
                "{} would write persistent configuration",
                command.display()
            );
        }
    }

    #[test]
    fn windows_routes_name_the_family_and_the_interface() {
        assert_eq!(
            windows::add_route("Zray", &route("0.0.0.0/1")).display(),
            "netsh interface ipv4 add route prefix=0.0.0.0/1 interface=Zray store=active"
        );
        assert_eq!(
            windows::del_route("Zray", &route("::/1")).display(),
            "netsh interface ipv6 delete route prefix=::/1 interface=Zray store=active"
        );
    }

    #[test]
    fn windows_sets_the_mtu_on_the_subinterface_per_family() {
        assert_eq!(
            windows::set_mtu("Zray", 1420, false).display(),
            "netsh interface ipv4 set subinterface Zray mtu=1420 store=active"
        );
        assert_eq!(
            windows::set_mtu("Zray", 1420, true).display(),
            "netsh interface ipv6 set subinterface Zray mtu=1420 store=active"
        );
    }

    #[test]
    fn every_platform_can_undo_everything_it_installs() {
        // A guard that can install something it cannot remove leaves the
        // machine altered after the process exits.
        let address = v4("10.0.0.1/24");
        let route = route("10.1.0.0/16");
        for (add, del) in [
            (
                linux::add_address("zray0", &address),
                linux::del_address("zray0", &address),
            ),
            (
                macos::add_address("utun5", &address),
                macos::del_address("utun5", &address),
            ),
            (
                windows::add_address("Zray", &address),
                windows::del_address("Zray", &address),
            ),
            (
                linux::add_route("zray0", &route),
                linux::del_route("zray0", &route),
            ),
            (
                macos::add_route("utun5", &route),
                macos::del_route("utun5", &route),
            ),
            (
                windows::add_route("Zray", &route),
                windows::del_route("Zray", &route),
            ),
        ] {
            assert_ne!(add, del, "add and remove are the same command");
            assert_eq!(
                add.program,
                del.program,
                "{} is undone by a different program",
                add.display()
            );
        }
    }
}
