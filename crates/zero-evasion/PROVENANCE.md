# Provenance

- License: MPL-2.0, inherited from the workspace.
- Implementation: original fragmentation and noise planning/stream code.
- Behavioral references: Xray `freedom.fragment`/`noises` semantics and the
  BPB finalmask defaults documented in `PLAN-02.md`; no donor source is copied.
- Linux SNI desynchronisation is implemented as a capability-gated raw IPv4
  injector using a fixed-size fake ClientHello shape. `CAP_NET_RAW`, IPv6, and
  injection errors are explicit fallback conditions; the runtime keeps the
  ClientHello-fragment path available for those cases. The hello layout was
  independently reconstructed from the public MIT reference described in
  `PLAN-01.md` and is not copied from that repository.
