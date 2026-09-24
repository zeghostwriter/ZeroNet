# Local patches to netstack-smoltcp 0.2.4

Vendored from crates.io (MIT OR Apache-2.0) and wired in through
`[patch.crates-io]` in the workspace `Cargo.toml`. 0.2.4 is the latest
release. Everything changed is in `src/tcp.rs`:

1. **Retransmitted SYNs no longer create sockets.** Every SYN without ACK
   built a new smoltcp socket, a new stream for the proxy to dial out for,
   and four buffers, even when the connection already existed. The spare
   never saw traffic and lived for the two-hour idle timeout. A set of live
   four-tuples now makes the first SYN create the socket and the rest go to
   it.
2. **Dropped streams are reclaimed.** After the application dropped a stream
   the socket waited for the local peer's FIN for up to two hours, buffering
   whatever arrived. Incoming data is now discarded once nobody can read it,
   and the connection is reset after `ORPHAN_LINGER` (30 s). The socket
   loop never sleeps past the earliest such deadline; it otherwise waited for
   the next packet or keepalive (28 s) and let orphans overstay.
3. **Staging rings are half the socket buffer size.** They only smooth the
   hand-off between the smoltcp socket and the stream.

With the socket buffer sizes the TUN inbound sets (64 KiB), a connection
costs about 192 KB instead of the 1.3 MB the defaults allocated.
4. **Shutdown completes when the FIN is queued.** `poll_shutdown` returned
   `Pending` until the socket was fully closed, which needs the local peer's
   FIN too. A half-close therefore never finished while the application
   kept its end open, and the relay above could not start its half-close
   timer, holding the connection for the full idle timeout instead.
