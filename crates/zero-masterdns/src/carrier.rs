//! The UDP resolver carrier: the sockets that actually carry the tunnel.
//!
//! Everything above this module deals in bytes — a sealed packet, a label
//! string, a `TXT` question (see [`zero_protocol::masterdns`]). This module is
//! the one place that touches a socket: it sends those questions to a DNS
//! resolver (or straight to the server on UDP/53 in the fallback mode) and
//! reads the answers back.
//!
//! It is deliberately thin. The Go client runs a pool of identical UDP sockets
//! with a reader loop and a writer loop each; the matching of a reply to the
//! request it answers is **not** done here at the DNS layer, it is done higher
//! up by the VPN session and sequence numbers, because one resolver answer can
//! carry data for any stream. So this module only does three things: open a
//! socket, send a datagram, and hand back the next datagram that actually looks
//! like a DNS response. The shallow "is this a response" filter mirrors the Go
//! reader worker exactly (a short datagram or one without the QR bit is
//! dropped), so junk and stray requests never reach the parser.
//!
//! Invariant worth knowing: [`TunnelSocket::recv_response`] loops until a datagram
//! passes the filter, so a caller that needs to give up must wrap it in a
//! timeout — [`exchange`] does that for the request/reply uses (MTU probing and
//! the session handshake), where a single send really does expect a single
//! answer.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;

/// A good receive-buffer size for one answer: the EDNS0 UDP payload size the
/// client advertises. A resolver should never send more than this in one
/// datagram. Matches [`zero_protocol::masterdns::dns::EDNS_SAFE_UDP_SIZE`].
pub const RECV_BUFFER_SIZE: usize = 4096;

/// The fixed DNS header length; a datagram shorter than this cannot be a reply.
const DNS_HEADER_SIZE: usize = 12;

/// The QR (query/response) bit lives in the top bit of the third header byte.
const DNS_QR_RESPONSE_BIT: u8 = 0x80;

/// Whether a received datagram is worth parsing as a DNS response: at least a
/// full header, and the QR bit set. This is the same shallow screen the Go
/// reader worker does before queueing a packet (`n < 12` and `buf[2] & 0x80`),
/// kept here as a pure function so it can be tested without a socket.
#[inline]
pub fn is_dns_response(datagram: &[u8]) -> bool {
    datagram.len() >= DNS_HEADER_SIZE && (datagram[2] & DNS_QR_RESPONSE_BIT) != 0
}

/// A source of DNS transaction ids, matching the Go `nextDNSRequestID`: a
/// counter seeded once at random, then incremented for each query. The id only
/// has to vary so a resolver tells concurrent queries apart; it is not a
/// security value, so a plain relaxed atomic is enough.
///
/// The returned id is the *incremented* value (Go's `Add(1)` returns the new
/// count), so the very first id off a seed of `s` is `(s + 1) as u16`.
pub struct DnsRequestIds {
    counter: AtomicU32,
}

impl DnsRequestIds {
    /// Seed the counter explicitly. Useful in tests for a deterministic id.
    pub fn seeded(seed: u32) -> Self {
        DnsRequestIds {
            counter: AtomicU32::new(seed),
        }
    }

    /// Seed the counter from the system RNG, the way the Go client does on
    /// first use.
    pub fn random() -> Self {
        Self::seeded(rand::random())
    }

    /// The next transaction id, truncated to 16 bits.
    pub fn next(&self) -> u16 {
        self.counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1) as u16
    }
}

impl Default for DnsRequestIds {
    fn default() -> Self {
        Self::random()
    }
}

/// One tunnel UDP socket, bound to an ephemeral local port on all interfaces,
/// exactly like one of the Go client's RX/TX worker sockets. The client opens
/// several of these and spreads sends across them; each one is independent.
pub struct TunnelSocket {
    socket: UdpSocket,
}

impl TunnelSocket {
    /// Open a socket bound to `0.0.0.0:0` (any port, any interface), matching
    /// the Go `net.ListenUDP("udp", {IPv4zero, 0})`.
    pub async fn bind() -> io::Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        Ok(TunnelSocket { socket })
    }

    /// Wrap a socket that was bound elsewhere (used by tests and by callers
    /// that set socket options before handing it over).
    pub fn from_socket(socket: UdpSocket) -> Self {
        TunnelSocket { socket }
    }

    /// The local address the socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Send one prepared DNS question to `resolver`.
    pub async fn send_to(&self, question: &[u8], resolver: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(question, resolver).await
    }

    /// Read datagrams into `buf` until one passes [`is_dns_response`], then
    /// return its length and source. Keeps reading past anything that fails the
    /// filter, so a caller that must give up has to bound this with a timeout.
    pub async fn recv_response(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let (n, addr) = self.socket.recv_from(buf).await?;
            if is_dns_response(&buf[..n]) {
                return Ok((n, addr));
            }
        }
    }
}

/// What came back from a single [`exchange`].
#[derive(Debug)]
pub enum Exchange {
    /// A DNS response arrived; `len` bytes of `buf` are valid, from `from`.
    Response { len: usize, from: SocketAddr },
    /// No response passed the filter before the timeout elapsed.
    TimedOut,
}

/// Send `question` to `resolver` and wait up to `timeout` for the first valid
/// DNS response, writing it into `buf`. This is the request/reply shape the MTU
/// probe and the session handshake use, where one query really does expect one
/// answer; the steady tunnel traffic instead uses [`TunnelSocket::send_to`] and
/// [`TunnelSocket::recv_response`] on separate tasks.
///
/// A timeout is reported as [`Exchange::TimedOut`], not an error, since timing
/// one resolver out and trying another is normal operation, not a failure.
pub async fn exchange(
    socket: &TunnelSocket,
    question: &[u8],
    resolver: SocketAddr,
    timeout: Duration,
    buf: &mut [u8],
) -> io::Result<Exchange> {
    socket.send_to(question, resolver).await?;
    match tokio::time::timeout(timeout, socket.recv_response(buf)).await {
        Ok(Ok((len, from))) => Ok(Exchange::Response { len, from }),
        Ok(Err(e)) => Err(e),
        Err(_elapsed) => Ok(Exchange::TimedOut),
    }
}

#[cfg(test)]
mod tests;
