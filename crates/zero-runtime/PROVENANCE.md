# Provenance

- License: MPL-2.0, inherited from the workspace.
- Implementation: original generation lifecycle, inbound server, relay, and
  outbound composition code.
- Behavioral references: Xray-compatible config and protocol contracts in the
  plans; no upstream source file is copied into this crate.
- Inbound sniffing, FakeDNS destination restoration, and carrier composition
  are original integration code.
- VMess client/server dispatch is integrated through the protocol crate without
  resolving destination names locally.
- Server-side XHTTP packet-up and stream-up dispatch is symmetric for
  HTTP/1.1 and HTTP/2; the runtime selects the carrier-specific pairing engine
  from the compiled transport model. Packet uploads are sequence-checked and
  bounded before reaching the logical protocol stream.
- HTTP/3 XHTTP stream-one and stream-up are served by a QUIC endpoint with the
  same VLESS session handler; stream-up legs rendezvous by session path.
- AnyTLS v2 is wired for authenticated single-stream client and server
  sessions over ordinary certificate TLS; session pooling and UDP extensions
  remain intentionally outside this first interoperable path.
- Hysteria2 is wired for authenticated TCP-over-QUIC client and server
  sessions plus one-shot authenticated UDP datagrams in both directions.
  Congestion-control negotiation, bandwidth probing, pooled UDP sessions, and
  obfuscation extensions remain explicit future capabilities rather than silent
  no-ops.
- TUIC v5 is wired for authenticated QUIC client and server CONNECT sessions
  and PACKET datagrams, including bounded multi-fragment requests and
  responses. It uses the same routing and relay boundary as the other QUIC
  carriers, so destination names remain remote-only.
- The authenticated management API exposes bounded `/stats` and local-only
  `/health` snapshots; health-aware balancers consume active probe evidence and
  real UDP proxy outcomes without recording destinations or payloads.
- The observatory can also run an operator-supplied, bounded clean-IP candidate
  set. Candidates are ranked by an actual HTTP response through the requested
  Host/path, retained only as local response metadata, and exposed at
  authenticated `/clean-ip`.
- The connection planner applies fingerprint rotation, ClientHello
  fragmentation, measured CDN class selection, alternate-port selection,
  clean-IP substitution, and AmneziaWG UDP class selection when a new
  outbound is materialised. The Linux SNI-desync injector is capability
  gated; when raw injection is unavailable or fails, the same outbound safely
  falls back to ClientHello fragmentation.
- The clean-IP rung now replaces a fronted outbound's measured endpoint while
  preserving the configured TLS SNI and HTTP Host value; it remains inactive
  until the bounded local probe has recorded application-level success.
- Raw/TCP HTTP camouflage is inserted after security and before the protocol
  layer on both outbound and inbound paths, so VLESS/Trojan/VMess retain their
  normal byte contracts.
- VLESS Mux `CMD_MUX` is wired through the Xray control destination and a
  bounded pooled TCP session worker on client and server paths. The runtime
  materialises carriers keyed by the compiled outbound and opens additional
  workers when a concurrency limit is reached. XUDP packet-mode Mux is also
  wired through the existing UDP routing boundary, including global-ID-aware
  NEW frames, session-preserving KEEP responses, and one-shot client/server
  interoperability with Xray.
