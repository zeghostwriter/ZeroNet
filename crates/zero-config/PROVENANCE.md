# Provenance

- License: MIT, inherited from the workspace.
- Implementation: original parser/compiler code written for Zray-Core.
- Behavioral references: Xray JSON/share-link formats and the pinned oracle
  described in `PLAN-01.md`; no upstream source file is copied into this crate.
- Parser policy: unsupported wire-affecting fields fail closed rather than
  being silently ignored.
- Xray ECH config lists are decoded into the compiled model, bounded before
  allocation, and kept separate from the ordinary SNI. When the list is
  omitted, the compiler emits a bounded discovery marker; the runtime must
  resolve an HTTPS/SVCB ECH record through the managed resolver before TLS,
  otherwise it fails closed instead of sending the inner name in plaintext.
- The gRPC and XHTTP model fields are original normalized representations; the
  wire framing lives in `zero-transport`.
- VMess JSON and share-link support is an original normalized model with strict
  rejection of legacy alterId users.
- AnyTLS JSON and `anytls://` share-link support is an original normalized
  model; it requires the raw carrier and verified certificate TLS.
- Hysteria2 JSON and `hysteria2://` support is an original normalized model
  for authenticated TCP-over-QUIC; it requires raw QUIC and verified TLS.
- TUIC v5 JSON and `tuic://uuid:password@host:port` support is an original
  normalized model for authenticated QUIC CONNECT/PACKET sessions; it requires
  raw QUIC and verified TLS.
- WireGuard/AmneziaWG JSON accepts both the compact endpoint form and the
  Xray/BPB `secretKey` + `address[]` + `peers[]` form, including optional
  pre-shared keys. Amnezia Jc/Jmin/Jmax, S1-S4 and H1-H4 values are bounded
  and validated before runtime use.
- Xray raw/TCP `header.type: "http"` is compiled into a bounded one-shot
  request/response camouflage model; malformed or mismatched headers are
  rejected rather than treated as protocol payload.
