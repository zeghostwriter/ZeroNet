# Provenance

- License: MPL-2.0, inherited from the workspace.
- Implementation: original protocol framing and stream adapters for VLESS,
  Trojan, legacy Shadowsocks AEAD TCP, VMess AEAD TCP, AnyTLS v2,
  SOCKS5/HTTP, and Vision.
- Behavioral references: Xray protocol documentation and the pinned oracle;
  Shadowsocks construction follows the public AEAD specification. VMess was
  reimplemented from the documented AEAD header/framing contract with a
  permitted MIT behavioral reference; no upstream source file is copied into
  this crate.
- VMess's legacy nested KDF was checked against a pinned Xray process before
  claiming interoperability; the external check covered an AES-128-GCM
  VMess client through a SOCKS listener.
- AnyTLS framing follows the public v2 contract: SHA-256 password
  authentication, settings/SYN/target frames, bounded PSH frames, FIN, and
  stream-id isolation. The implementation is a single logical stream and does
  not claim session pooling or UDP-over-TCP support.
- AmneziaWG 2.x packet obfuscation is implemented independently: validated,
  non-overlapping H1-H4 ranges, S1-S4 prefixes, dynamic little-endian magic
  headers, bounded Jc/Jmin/Jmax junk packets, and fail-closed decoding of
  unrelated datagrams. A persistent IPv4/IPv6 UDP session is wired through
  boringtun, including optional WireGuard pre-shared keys, for the runtime's
  UDP proxy boundary; TCP-over-WireGuard and a full TUN carrier remain
  separate concerns.
- Xray/V2Ray Mux metadata framing and bounded pooled VLESS Mux sessions are
  independently implemented from the public frame contract. The client and
  server carrier workers isolate session IDs, serialize carrier writes, and
  enforce the compiled `mux.enabled`/`concurrency` limit. XUDP packet-mode
  frames preserve the zero session ID, eight-byte global ID, UDP source target,
  and packet payload contract, with one-shot exchange support for the runtime
  datagram boundary.
