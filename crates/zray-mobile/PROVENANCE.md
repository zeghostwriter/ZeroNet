# Provenance

- Implementation: original Zray-Core C ABI for mobile host applications. No
  source is copied from an upstream proxy core, and no vendored FFI generator
  is used — the header in `include/zray.h` is maintained by hand alongside the
  Rust entry points and pinned to them by a test.
- Behavioral references: the platform contracts this layer exists to satisfy,
  namely Android's `VpnService` (descriptor handover and `protect`) and
  Apple's `NEPacketTunnelProvider` (descriptor handover with four bytes of
  address-family framing). Those are API contracts, not code.
- The crate holds no proxy, protocol or configuration logic. It converts C
  types to Rust ones, owns the runtime's lifetime between calls, and contains
  every panic at the boundary so a fault in this library cannot abort the
  host's process.
- Socket protection is delegated: the host supplies the callback and this
  crate only adapts it to `zero_core::platform::SocketProtector`. Nothing here
  decides policy.
- The TUN descriptor is adopted, never opened. Link configuration is skipped
  entirely on an adopted interface, because its addresses, routes and MTU came
  from a system dialog the user agreed to.
