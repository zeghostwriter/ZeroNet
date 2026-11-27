//! A MasterDnsVPN client: open connections to anywhere through a MasterDNS
//! server, over plain DNS queries.
//!
//! How it works: [`Client::connect`] finds which resolvers pass the tunnel's
//! queries and how big they may be, agrees a session with the server, and starts
//! a pool of workers that exchange one DNS question and one answer each. Every
//! stream is reliable and ordered (the ARQ layer in [`crate::arq`]) and is
//! handed back as a [`Stream`] the caller reads and writes like a socket.
//!
//! The parts, bottom up: `wire` (packets in and out of DNS), `bringup`
//! (resolver probes and the handshake), `core` (all stream state, no I/O) and
//! `runtime` (workers and stream tasks). Only AES-256-GCM, XOR and no
//! encryption are offered by the key codec; the shipping choice is AES-256-GCM.
//!
//! Not here: SOCKS or DNS listeners, tunnelled DNS queries, UDP, packing of
//! several acks into one query, payload compression (it is negotiated off) and
//! restoring a session the server dropped (the caller connects again).

mod bringup;
mod core;
mod runtime;
mod wire;

use std::net::SocketAddr;
use std::time::Duration;

pub use self::core::Mode;
pub use self::runtime::{Client, Stream};

/// What can go wrong, in words a person can be shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The settings cannot work (a bad key, a domain too long for any query).
    Config(String),
    /// A socket failed.
    Io(String),
    /// The server's answer made no sense.
    Protocol(String),
    /// No resolver answered the probes: wrong domain, blocked, or no DNS path.
    NoResolver,
    /// The server never accepted a session (wrong key or domain, or it is down).
    NoSession,
    /// The server is full, or every stream id is in use.
    Busy,
    /// The server stopped knowing this session; connect again.
    SessionLost,
    /// The server could not connect to the destination.
    Connect(String),
    /// The stream ended before it could be used.
    Closed,
    /// Nothing happened in time.
    Timeout,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Config(why) => write!(f, "MasterDNS settings: {why}"),
            Error::Io(why) => write!(f, "MasterDNS socket: {why}"),
            Error::Protocol(why) => write!(f, "MasterDNS protocol: {why}"),
            Error::NoResolver => f.write_str(
                "No DNS resolver passed the tunnel's test queries. Check the domain and its two DNS records, or try another resolver.",
            ),
            Error::NoSession => f.write_str(
                "The server did not accept a session. Check the key and the domain, and that the server is running.",
            ),
            Error::Busy => f.write_str("The server is full right now."),
            Error::SessionLost => f.write_str("The server dropped the session."),
            Error::Connect(why) => write!(f, "The server could not connect: {why}."),
            Error::Closed => f.write_str("The connection closed."),
            Error::Timeout => f.write_str("The connection timed out."),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        let kind = match e {
            Error::Timeout => std::io::ErrorKind::TimedOut,
            Error::Closed => std::io::ErrorKind::BrokenPipe,
            Error::Connect(_) => std::io::ErrorKind::ConnectionRefused,
            _ => std::io::ErrorKind::Other,
        };
        std::io::Error::new(kind, e.to_string())
    }
}

/// How to reach one MasterDNS server.
#[derive(Debug, Clone)]
pub struct Config {
    /// The tunnel domain, delegated to the server (`t.example.com`).
    pub domain: String,
    /// The shared key, as the server's `encrypt_key.txt` holds it.
    pub key: String,
    /// The encryption method id (5 = AES-256-GCM).
    pub method: u8,
    /// Resolvers to send queries through; the server's own address works too
    /// when it is reachable on UDP 53.
    pub resolvers: Vec<SocketAddr>,
    /// How the server picks destinations.
    pub mode: Mode,
    /// Queries in flight at once. More is faster and louder.
    pub workers: usize,
    pub min_upload_mtu: i32,
    pub max_upload_mtu: i32,
    pub min_download_mtu: i32,
    pub max_download_mtu: i32,
    /// How long one probe or handshake query waits for its answer.
    pub probe_timeout: Duration,
    /// Attempts per candidate size in the MTU search.
    pub probe_retries: u32,
    /// How many times the handshake is tried before giving up.
    pub session_attempts: u32,
    /// Ask the server to answer in base64 text instead of raw bytes.
    pub base64_replies: bool,
}

impl Config {
    /// The upstream client's defaults for everything but the server itself.
    pub fn new(domain: &str, key: &str, resolvers: Vec<SocketAddr>) -> Self {
        Config {
            domain: domain.to_string(),
            key: key.to_string(),
            method: zero_protocol::masterdns::enums::METHOD_AES_256_GCM,
            resolvers,
            mode: Mode::Socks5,
            workers: 4,
            min_upload_mtu: 38,
            max_upload_mtu: 150,
            min_download_mtu: 100,
            max_download_mtu: 500,
            probe_timeout: Duration::from_secs(2),
            probe_retries: 2,
            session_attempts: 5,
            base64_replies: false,
        }
    }
}
