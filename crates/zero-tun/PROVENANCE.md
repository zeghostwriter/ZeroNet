# Provenance

- Implementation: original Zray-Core packet-device boundary and bridge around
  the MIT/Apache-2.0 `netstack-smoltcp` userspace IP stack.
- Behavioral references: Linux TUN/TAP ABI documentation and the platform adapter contracts described in PLAN-01.
- The IPv4/IPv6 UDP packet parser and checksum-correct reply builder are
  original code. Stateful TCP/UDP TUN flows use the isolated userspace
  netstack bridge; policy and proxy selection remain in `zero-runtime`.
- No source files are copied from an upstream proxy core.
- The backend is capability-gated; unsupported platforms return an explicit error rather than silently falling back to a physical interface.
- IPv4/IPv6 TCP and UDP packet metadata parsing is original code. IPv4 and
  IPv6 fragments are rejected until a reassembly layer is present; valid IPv6
  hop-by-hop, routing, destination-options, and AH extension chains are
  walked safely.
- Linux address, route, MTU, and link-state setup is an original, argv-based
  `ip` integration guarded by `TunNetworkGuard`; it never invokes a shell and
  restores the prior MTU/link state and removes only addresses/routes it
  installed. Full-tunnel routes remain explicit in the compiled config because
  they are process-wide privileged changes.
