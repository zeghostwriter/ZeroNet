# Provenance

- License: MIT, inherited from the workspace.
- Ordinary TLS uses rustls. The minimal TLS 1.3/REALITY substrate is original
  Zray-Core Rust code whose wire behavior is checked against the MIT/MPL oracle
  material named in `PLAN-01.md`; no upstream REALITY or TLS 1.3 substrate source
  file is copied here.
- Ordinary TLS fingerprinting uses the pinned MPL-2.0 shaped-rustls revision
  `3a131beaef0183b0cb61e5a9070a703b6be39ed3` and the product-owned uTLS profile
  registry in `utls_profiles.rs`/`utls_shaping.rs`. The registry is the Xray
  profile corpus with its random-profile selection kept deterministic per
  process; the adapter is responsible for provider capability filtering and
  for suppressing profile ECH GREASE when managed ECH is active.
  Historical TLS 1.2 CBC-only profiles are retained for config recognition but
  fail closed because rustls intentionally does not implement those suites.
- Ordinary TLS ECH uses rustls 0.23's public HPKE path with the aws-lc-rs
  provider. The inner SNI is passed only to the encrypted handshake, and the
  cache is keyed by the serialized public ECH configuration. The ring provider
  remains explicit for non-ECH paths so enabling HPKE cannot trigger rustls'
  ambiguous process-default provider.
- REALITY and Vision compatibility are protocol behavior, not a dependency on
  any AGPL project.
- REALITY certificate authentication includes an original, fail-closed
  ML-DSA-65 certificate-extension verifier and an opt-in X25519MLKEM768
  handshake path. The default handshake remains the classic X25519 path for
  compatibility with the pinned Xray 26.3.27 baseline.
- The custom REALITY client/server path was exercised against Xray 26.3.27,
  including a Vision direct-splice inner TLS record path and a local
  certificate-backed proxy round trip; the direct handoff is recognized only
  after a failed outer record authentication and a valid TLS record-shaped
  prefix. The classic default path completed a live local Xray interop check;
  the hybrid path is covered by the local server tests and is not enabled by
  default because the pinned Xray peer rejected that offer.
