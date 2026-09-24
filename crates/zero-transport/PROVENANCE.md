# Provenance

- License: MPL-2.0, inherited from the workspace.
- Implementation: original WebSocket, HTTP Upgrade, gRPC, and XHTTP stream
  code.
- Behavioral references: RFC 6455 and the Xray transport contracts described in
  `PLAN-01.md`; no upstream source file is copied into this crate.
- XHTTP packet-up and stream-up are implemented symmetrically over HTTP/1.1 and
  HTTP/2. Packet-up uses fixed-length POSTs, bounded contiguous-sequence
  reordering, and native HTTP/2 DATA streams; stream-up uses a shared session
  rendezvous. No HTTP/1.1 framing is injected into an H2 body.
- XHTTP HTTP/3 stream-one, stream-up, and packet-up use `h3`/`h3-quinn` over
  QUIC with ordinary verified certificate TLS. Stream-up pairs independent
  POST/GET legs by a session path; packet-up uses fixed-length POSTs, bounded
  contiguous sequence handling, and concurrent requests on one QUIC
  connection.
- gRPC framing follows the public five-byte message envelope and Xray's
  `Hunk { bytes data = 1; }` protobuf schema, with bounded gzip decoding for
  compressed messages.
- Hysteria2 framing follows the public protocol contract: HTTP/3 password
  authentication, QUIC varint target negotiation, bounded request/response
  padding, a bidirectional TCP stream bridge, and the session/packet/fragment
  UDP datagram header. UDP is currently one authenticated exchange per QUIC
  connection; bandwidth probing and pooled sessions are not exposed.
- TUIC v5 follows the public command contract and the MIT-licensed `shoes`
  reference: keying-material authentication on a unidirectional stream,
  bidirectional CONNECT streams, and PACKET datagrams with bounded address and
  payload parsing. PACKET messages support the protocol's bounded multi-
  fragment format, including out-of-order reassembly and the continuation
  address marker. The implementation is independently written; no source file
  is copied.
- XHTTP HTTP/2 handshakes explicitly advertise 4 MiB stream and connection
  windows so one logical flow cannot consume the default 65,535-byte
  connection credit and starve its siblings.
- The raw/TCP HTTP header wrapper follows Xray's one-time request/response
  authenticator boundary, with an 8 KiB header cap and coalesced-payload
  preservation on both client and server sides.
