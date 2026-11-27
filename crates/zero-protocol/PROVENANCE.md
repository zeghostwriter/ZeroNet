# Provenance

- License: MIT, inherited from the workspace.
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
- MasterDnsVPN is a Rust port of the deterministic wire core of
  `masterking32/MasterDnsVPN` (MIT), pinned to the server release
  `v2026.06.13.234407-7de2476`. This crate carries only the parts that must be
  byte-identical to the server to interoperate: the raw packet layout and its
  one-byte header check, the lower-base36 DNS-label codec (with the base32 and
  raw-base64 alternates the server can be configured for), the AES-GCM/XOR/none
  encryption methods and their key derivation, the SESSION_ACCEPT payload, and
  the packed-control-block list. It also carries the pure framing that rides on
  top of those: the DNS `TXT` carrier (building the tunnel question name and
  recovering the raw frame from `TXT` answers, including chunk reassembly), the
  compression type vocabulary and its packed upload/download pair, the
  SESSION_INIT request payload, and the SOCKS target address codec. Every
  encoded value is checked against vectors generated from the upstream Go
  packages (`internal/vpnproto`, `internal/basecodec`, `internal/security`,
  `internal/dnsparser`, `internal/compression`, `internal/socksproto`) at the
  pinned commit, so a passing test run means the two agree on the wire. Method 2
  (ChaCha20, which upstream runs unauthenticated) is understood but not built:
  it returns an error rather than carry a cipher that is never a safe choice.
  What stays out of this crate: the sockets that send the DNS queries, the
  compression codecs themselves (deflate/zstd/lz4), the reliable (ARQ) layer,
  the session handshake orchestration and SOCKS stream management. They need
  sockets, timing, and heavier dependencies and belong in
  `zero-transport`/`zero-runtime`, the same split the `tide` protocol uses.
  `zero-masterdns/tests/live_go_server.rs` runs these parts against the real Go
  server built from the pinned commit (MTU probes, handshake, ping, a stream
  open and a data round trip, for every supported encryption method); it is
  opt-in because it needs the server binary.
