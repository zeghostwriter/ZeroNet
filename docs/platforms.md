# Platform support

What the packet device and the link configuration do on each platform, what
each one needs from the operator or the host application, and how each is
tested. PLAN-01 phase 11 asks for the adapters to be isolated; this is the
map of that isolation.

| Platform | Packet device | Link configuration | Tested by |
|---|---|---|---|
| Linux | `/dev/net/tun`, `IFF_TUN\|IFF_NO_PI` | `ip(8)` | unit tests, the netem harness, the TUN handover harness |
| macOS | `utun` control socket, 4-byte framing | `ifconfig`/`route` | command-shape tests everywhere, unit tests on the Apple CI job |
| Windows | Wintun, dynamically loaded | `netsh` | command-shape tests everywhere, compiled on the cross job |
| Android | descriptor from `VpnService`, no framing | **none** — the platform owns it | the TUN handover harness, plus a real `.so` built on the mobile CI job |
| iOS | descriptor from `NEPacketTunnelProvider`, 4-byte framing | **none** — the platform owns it | the same handover path; a real static archive built on the Apple CI job |

## How the layers split

* `netcmd` builds the commands as data and runs nothing. Every platform's
  exact argument vector is asserted from a unit test on any host, which is
  what makes a macOS or Windows flag reviewable without that machine.
* `platform` runs them, and owns the one thing that genuinely differs per
  system: what a tool says when the state being asked for already holds. The
  install-and-roll-back sequence itself is shared, because getting it wrong
  is the same mistake everywhere.
* `wintun` is the only platform-specific *device*, because Windows is the only
  platform without one of its own.

## Windows

`wintun.dll` is loaded by name at run time. **No driver is bundled**: nothing
links against it, so a build carries no driver, no signing requirement and no
installer. An operator without it gets an error naming the file and where to
get it, rather than a mysterious failure to route.

Creating an adapter needs administrator rights; reopening an existing one does
not, so a service granted the right once does not need it again. All `netsh`
changes are `store=active`, so a crash cannot leave a machine permanently
reconfigured.

Reads run on a dedicated thread — Wintun hands out a Win32 event and tokio has
no `AsyncFd` for one — feeding a bounded channel. A reader that falls behind
drops packets, the way a congested link does, and the count is available from
`TunDevice::dropped`.

## Android and iOS

The proxy never opens a TUN device on either. The platform creates the
interface after the user approves a system dialog, configures its addresses,
routes, MTU and DNS itself, and hands the application a descriptor. Two things
follow, and neither shares code with the desktop path:

1. **The descriptor is adopted, not opened**, and the link is left alone.
   Reaching around a dialog the user agreed to would be wrong even where it is
   possible.
2. **Every outbound socket is protected.** The process now sits behind the
   tunnel it is serving, so an unexempted socket routes back into itself: the
   proxy's traffic to its own server arrives at the proxy. The tunnel does not
   perform badly, it carries nothing.

Socket protection is a process-wide hook (`zero_core::platform`) rather than
configuration, because a socket created deep inside a DNS resolver or a QUIC
endpoint needs the same treatment as one from the dialer, and threading a
handle through every such path would guarantee that the one nobody remembered
is the one that breaks the tunnel. A host that installs nothing gets today's
behaviour exactly.

The C ABI is in `crates/zray-mobile`, with the header at
`crates/zray-mobile/include/zray.h`. Every entry point contains its own
panics: a fault in this library returns `ZRAY_ERR_PANIC` rather than aborting
somebody's application.

### What the host must do

```c
/* Android, from VpnService. */
zray_set_protect_callback(protect_via_vpnservice, NULL);
zray_set_tun_descriptor(tunFd, /* header_len */ 0, /* mtu */ 1500);
zray_start(config_json);
```

On iOS the descriptor comes from the packet-tunnel provider and carries four
bytes of address-family framing, so `header_len` is `4`; protection is usually
unnecessary there, and passing `NULL` is supported.

## What is still not covered

* **Windows and macOS link configuration is not executed in CI.** The commands
  are asserted, the adapters are compiled for their real targets, and the
  macOS unit tests run on a macOS runner — but no job brings up a real `utun`
  or Wintun adapter, because that needs a privileged runner on each OS.
* **No test runs on a phone.** The handover harness exercises the adoption and
  protection paths against a real kernel TUN device, which is the part that is
  reproducible without one; the platform-specific halves — `VpnService.protect`
  itself, `NEPacketTunnelProvider` framing on a device — are not.
