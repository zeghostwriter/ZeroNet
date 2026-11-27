//! Tide: a session protocol made to ride inside ordinary HTTP requests.
//!
//! How the pieces fit, bottom up:
//!
//!  * [`noise`] agrees the keys: one handshake per session, against a server
//!    key the client already has from its share link.
//!  * [`session`] is the protocol proper: streams with flow control, cut into
//!    encrypted chunks that can travel over any mix of one-way pipes and
//!    survive a pipe dying.
//!  * this file is what goes *in* the handshake: who is asking and when, and
//!    how the server tells a fresh request from a recording played back.
//!
//! How the bytes are carried (HTTP/2 request and response bodies) lives in
//! `zero-transport`; nothing here knows about HTTP.
//!
//! The rule this file keeps: a first message is accepted only if its user is
//! known, its time is close to the server's, and its client key has not been
//! seen before. A message that fails any of these gets the same answer as
//! garbage would, so replaying a recorded first message teaches nothing.

pub mod noise;
pub mod session;
pub mod shape;

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rand::RngCore;
use zero_core::{Address, Destination};

pub use session::{ChunkParser, Role, Session, TideStream, LANE_BODY_MAX};
pub use shape::ShapeLevel;

/// Mixed into the handshake, so a Tide message is never valid as anything
/// else and a later version cannot be confused with this one.
const PROLOGUE: &[u8] = b"tide/1";
const VERSION: u8 = 1;
/// Capability bit: the session also carries the datagram lane (UDP). A client
/// that wants it sets the bit in its hello; the server answers with the bits
/// it will honour. A hello without the extra byte means "no extensions", so
/// servers and clients that predate the lane still talk to newer ones.
pub const FLAG_LANE: u8 = 1;
/// How far a client's stated time may be from the server's clock. The client
/// takes its time from the server's own `Date` header before the handshake,
/// so this only has to cover the delay between the two requests.
pub const TIME_WINDOW: u64 = 120;
/// A user's identifier: sixteen random bytes, shared by client and server.
pub type UserId = [u8; 16];

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "tide handshake refused")
}

fn fresh_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// A new server key pair: `(secret, public)`. The public half goes in links.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = fresh_key();
    let public = noise::public_key(&secret);
    (secret, public)
}

/// The client's first message, for the body of the request that opens a
/// session. `time` is seconds since 1970 by the *server's* clock.
pub fn client_hello(
    server_public: &[u8; 32],
    user: &UserId,
    time: u64,
) -> io::Result<(Vec<u8>, ClientHandshake)> {
    client_hello_with(server_public, user, time, 0)
}

/// [`client_hello`] asking for the extensions in `flags` (see [`FLAG_LANE`]).
/// With no flags the message is byte for byte what it always was.
pub fn client_hello_with(
    server_public: &[u8; 32],
    user: &UserId,
    time: u64,
    flags: u8,
) -> io::Result<(Vec<u8>, ClientHandshake)> {
    let mut payload = Vec::with_capacity(1 + 8 + 16 + 1);
    payload.push(VERSION);
    payload.extend_from_slice(&time.to_be_bytes());
    payload.extend_from_slice(user);
    if flags != 0 {
        payload.push(flags);
    }
    let (message, initiator) =
        noise::initiate(PROLOGUE, server_public, fresh_key(), &payload).map_err(|_| refused())?;
    Ok((message, ClientHandshake(initiator, flags)))
}

/// The client between its first message and the server's answer.
pub struct ClientHandshake(noise::Initiator, u8);

impl ClientHandshake {
    /// Read the server's answer and start the session. An extension is on
    /// only if it was asked for and the server's answer confirms it.
    pub fn finish(self, reply: &[u8]) -> io::Result<Arc<Session>> {
        let (payload, keys) = self.0.finish(reply).map_err(|_| refused())?;
        if payload.first() != Some(&VERSION) {
            return Err(refused());
        }
        let granted = payload.get(1).copied().unwrap_or(0) & self.1;
        Ok(Session::new(Role::Client, keys, granted & FLAG_LANE != 0))
    }
}

/// A first message the server could decrypt. Nothing about it is trusted
/// until [`Offer::user`] is known and [`ReplayGuard::admit`] has passed.
pub struct Offer {
    pub user: UserId,
    pub time: u64,
    /// The extensions the client asked for.
    pub flags: u8,
    responder: noise::Responder,
}

/// Decrypt a client's first message with the server's secret key.
pub fn server_read(server_secret: &[u8; 32], message: &[u8]) -> io::Result<Offer> {
    let (payload, responder) =
        noise::respond(PROLOGUE, server_secret, message).map_err(|_| refused())?;
    if !(25..=26).contains(&payload.len()) || payload[0] != VERSION {
        return Err(refused());
    }
    Ok(Offer {
        time: u64::from_be_bytes(payload[1..9].try_into().expect("8 bytes")),
        user: payload[9..25].try_into().expect("16 bytes"),
        flags: payload.get(25).copied().unwrap_or(0),
        responder,
    })
}

impl Offer {
    /// The client's one-time key: what a replay would repeat.
    pub fn client_key(&self) -> [u8; 32] {
        *self.responder.client_public()
    }

    /// Answer the client and start the session, with every extension the
    /// client asked for that this build knows.
    pub fn accept(self) -> io::Result<(Vec<u8>, Arc<Session>)> {
        self.accept_with(FLAG_LANE)
    }

    /// [`Offer::accept`], honouring only the extensions in `supported`.
    pub fn accept_with(self, supported: u8) -> io::Result<(Vec<u8>, Arc<Session>)> {
        let granted = self.flags & supported;
        let mut answer = vec![VERSION];
        if granted != 0 {
            answer.push(granted);
        }
        let (reply, keys) = self
            .responder
            .reply(fresh_key(), &answer)
            .map_err(|_| refused())?;
        Ok((
            reply,
            Session::new(Role::Server, keys, granted & FLAG_LANE != 0),
        ))
    }
}

/// Remembers the client keys of recent handshakes so that a recorded first
/// message cannot be used twice.
///
/// A message is only valid within [`TIME_WINDOW`] of the server's clock, so a
/// key has to be remembered for just that long on either side: after that the
/// timestamp alone refuses it. The memory this needs is therefore bounded by
/// how many sessions start in a few minutes, not by how long the server runs.
#[derive(Default)]
pub struct ReplayGuard {
    seen: Mutex<HashMap<[u8; 32], u64>>,
}

impl ReplayGuard {
    /// True when `offer` is fresh: its time is near `now` and its client key
    /// is new. A fresh offer is remembered, so the same call again is false.
    pub fn admit(&self, offer: &Offer, now: u64) -> bool {
        if offer.time.abs_diff(now) > TIME_WINDOW {
            return false;
        }
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        // Entries older than two windows can no longer pass the time check.
        if seen.len() >= 4096 {
            seen.retain(|_, time| now.saturating_sub(*time) <= 2 * TIME_WINDOW);
        }
        seen.insert(offer.client_key(), offer.time).is_none()
    }
}

/// One UDP flow over a session's datagram lane: the stream that opened it
/// (its opening and closing are the flow's) plus the destination each
/// datagram is addressed to, so one local UDP socket can reach many peers
/// through one flow, as a "full cone" NAT would let it.
///
/// A datagram's body is `type, address, port, payload`: type 1 = IPv4 (4
/// bytes), 4 = IPv6 (16 bytes), 3 = name (length byte, then the name).
pub struct UdpFlow {
    stream: TideStream,
}

impl UdpFlow {
    pub fn new(stream: TideStream) -> Self {
        Self { stream }
    }

    /// Send `payload` to `to`. Like UDP it may be dropped; an error means the
    /// flow is over.
    pub fn send(&self, to: &Destination, payload: &[u8]) -> io::Result<()> {
        let mut body = Vec::with_capacity(payload.len() + 20);
        match &to.address {
            Address::Ip(std::net::IpAddr::V4(ip)) => {
                body.push(1);
                body.extend_from_slice(&ip.octets());
            }
            Address::Ip(std::net::IpAddr::V6(ip)) => {
                body.push(4);
                body.extend_from_slice(&ip.octets());
            }
            Address::Domain(name) => {
                let name = &name.as_bytes()[..name.len().min(255)];
                body.push(3);
                body.push(name.len() as u8);
                body.extend_from_slice(name);
            }
        }
        body.extend_from_slice(&to.port.to_be_bytes());
        body.extend_from_slice(payload);
        self.stream.send_datagram(&body)
    }

    /// The next datagram of the flow and where it came from (or, on the
    /// server, where it is to go). An error ends the flow.
    pub async fn recv(&self) -> io::Result<(Destination, Bytes)> {
        loop {
            let body = self.stream.recv_datagram().await?;
            if let Some(parsed) = parse_udp_body(&body) {
                return Ok(parsed);
            }
            // A body that does not parse is dropped, as a bad packet is.
        }
    }
}

fn parse_udp_body(body: &Bytes) -> Option<(Destination, Bytes)> {
    let (address, rest) = match *body.first()? {
        1 => {
            let octets: [u8; 4] = body.get(1..5)?.try_into().ok()?;
            (Address::Ip(octets.into()), 5)
        }
        4 => {
            let octets: [u8; 16] = body.get(1..17)?.try_into().ok()?;
            (Address::Ip(octets.into()), 17)
        }
        3 => {
            let length = *body.get(1)? as usize;
            let name = std::str::from_utf8(body.get(2..2 + length)?).ok()?;
            (Address::domain(name), 2 + length)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(body.get(rest..rest + 2)?.try_into().ok()?);
    Some((Destination::udp(address, port), body.slice(rest + 2..)))
}

/// A key or user id as it is written in links and configs.
pub fn encode_key(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The reverse of [`encode_key`], for exactly `N` bytes.
pub fn decode_key<const N: usize>(text: &str) -> Option<[u8; N]> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim())
        .ok()?
        .try_into()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handshake_gives_both_sides_a_working_session() {
        let (secret, public) = generate_keypair();
        let user = [7u8; 16];
        let (hello, client) = client_hello(&public, &user, 1_000).unwrap();
        let offer = server_read(&secret, &hello).unwrap();
        assert_eq!(offer.user, user);
        assert_eq!(offer.time, 1_000);
        let (reply, server) = offer.accept().unwrap();
        let client = client.finish(&reply).unwrap();
        assert_eq!(client.binding(), server.binding());
    }

    #[test]
    fn a_replayed_or_stale_first_message_is_not_admitted() {
        let (secret, public) = generate_keypair();
        let guard = ReplayGuard::default();
        let (hello, _) = client_hello(&public, &[1; 16], 5_000).unwrap();
        assert!(guard.admit(&server_read(&secret, &hello).unwrap(), 5_010));
        assert!(
            !guard.admit(&server_read(&secret, &hello).unwrap(), 5_011),
            "the same message again"
        );
        let (late, _) = client_hello(&public, &[1; 16], 5_000).unwrap();
        assert!(
            !guard.admit(
                &server_read(&secret, &late).unwrap(),
                5_000 + TIME_WINDOW + 1
            ),
            "too old"
        );
        let (early, _) = client_hello(&public, &[1; 16], 9_000).unwrap();
        assert!(
            !guard.admit(&server_read(&secret, &early).unwrap(), 5_000),
            "from the future"
        );
    }

    #[test]
    fn the_wrong_server_key_reads_nothing() {
        let (_, public) = generate_keypair();
        let (other_secret, _) = generate_keypair();
        let (hello, _) = client_hello(&public, &[1; 16], 1).unwrap();
        assert!(server_read(&other_secret, &hello).is_err());
    }

    #[tokio::test]
    async fn a_udp_flow_names_where_each_datagram_goes_and_a_hello_can_ask_for_the_lane() {
        let (secret, public) = generate_keypair();
        let (hello, client) = client_hello_with(&public, &[7; 16], 1_000, FLAG_LANE).unwrap();
        let offer = server_read(&secret, &hello).unwrap();
        assert_eq!(offer.flags, FLAG_LANE);
        let (reply, server) = offer.accept().unwrap();
        let client = client.finish(&reply).unwrap();
        let flow = UdpFlow::new(
            client
                .open(Destination::udp(Address::domain("a.b"), 1))
                .unwrap(),
        );
        let targets = [
            Destination::udp(Address::Ip("192.0.2.9".parse().unwrap()), 3478),
            Destination::udp(Address::Ip("2001:db8::1".parse().unwrap()), 53),
            Destination::udp(Address::domain("stun.example.org"), 19302),
        ];
        for (index, target) in targets.iter().enumerate() {
            flow.send(target, &[index as u8; 30]).unwrap();
        }
        let mut parser = ChunkParser::default();
        while let Some(chunk) = client.try_next_chunk(1, session::CHUNK_PLAIN_MAX) {
            server.receive(&mut parser, &chunk).unwrap();
        }
        let (_, accepted) = server.accept().await.unwrap();
        let accepted = UdpFlow::new(accepted);
        for (index, target) in targets.iter().enumerate() {
            let (to, payload) = accepted.recv().await.unwrap();
            assert_eq!(&to, target);
            assert_eq!(payload[..], [index as u8; 30]);
        }
    }

    #[test]
    fn a_hello_without_flags_is_what_it_always_was_and_gets_no_lane() {
        let (secret, public) = generate_keypair();
        let (hello, client) = client_hello(&public, &[7; 16], 5).unwrap();
        let offer = server_read(&secret, &hello).unwrap();
        assert_eq!(offer.flags, 0);
        let (reply, server) = offer.accept().unwrap();
        let client = client.finish(&reply).unwrap();
        let udp = Destination::udp(Address::domain("a.b"), 1);
        assert!(client.open(udp.clone()).is_err());
        assert!(server.open(udp).is_err());
        // A server that does not know the lane never grants it.
        let (hello, client) = client_hello_with(&public, &[7; 16], 5, FLAG_LANE).unwrap();
        let (reply, _) = server_read(&secret, &hello)
            .unwrap()
            .accept_with(0)
            .unwrap();
        let client = client.finish(&reply).unwrap();
        assert!(client
            .open(Destination::udp(Address::domain("a.b"), 1))
            .is_err());
    }

    #[test]
    fn keys_survive_being_written_down() {
        let (_, public) = generate_keypair();
        let text = encode_key(&public);
        assert_eq!(decode_key::<32>(&text), Some(public));
        assert_eq!(decode_key::<16>(&text), None);
        assert_eq!(decode_key::<32>("not a key"), None);
    }
}
