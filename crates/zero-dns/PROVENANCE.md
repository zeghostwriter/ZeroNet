# Provenance

- License: MIT, inherited from the workspace.
- Implementation: original Zray-Core resolver, cache, FakeDNS, and DNS wire
  code; behavior is checked against the DNS requirements in the plans.
- External behavioral references: Hickory DNS message conventions and Xray
  resolver behavior; no upstream source file is copied into this crate.
- FakeDNS reverse lookup is an internal TUN-bridge API and never performs a
  real DNS query.
- DoH3 uses the workspace QUIC/H3 stack with verified certificate roots, and
  DoQ uses RFC 9250 length-prefixed bidirectional streams. Both transports are
  bounded to one DNS response per connection in the resolver path.
- HTTPS/SVCB records are parsed for the standard ECH service parameter (key 5)
  so ECH discovery stays inside the configured encrypted/leak-aware resolver
  policy instead of falling back to system DNS.
