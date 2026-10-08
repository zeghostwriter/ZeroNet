//! Which way to hide a server name, picked per server from what happened on
//! the last connections to it.
//!
//! There are two ways of hiding a name from a socket without root: the
//! urgent byte ([`crate::urgent`]) and the decoy ([`crate::decoy`]). They
//! cost very different amounts:
//!
//! * the urgent byte costs nothing: one extra byte, no wait;
//! * the decoy costs every connection one round trip and a bit more, because
//!   the real hello only leaves once the server has said it is missing (about
//!   0.33 s per connection measured from Tehran, against 0.35 s for the whole
//!   plain handshake).
//!
//! But they do not get past the same things. Some servers read the urgent
//! byte badly: the handshake completes and then the server never answers
//! again. So the rule here is "urgent byte first, decoy where the urgent byte
//! has been seen to fail":
//!
//! ```text
//! connection to 1.2.3.4:443   urgent byte → answered twice → stays urgent
//! connection to 5.6.7.8:443   urgent byte → went silent    → 1 strike
//! connection to 5.6.7.8:443   urgent byte → went silent    → 2 strikes:
//!                             decoy for this server for the next 10 minutes
//! ```
//!
//! A connection is *answered* when the server replied to the client's second
//! flight, not just to the first: that is the point the bad case stops at
//! (handshake done, nothing after). It *went silent* when it waited
//! [`SILENT_AFTER`] for a reply, or was dropped while waiting. Anything else
//! (dropped right after a reply, before the client wrote again) says nothing
//! and is not counted. The wait is timed so a stuck connection counts while
//! the user is still looking at it, not only once something gives up on it.
//!
//! Two strikes in a row, and a strike is wiped by any answered connection, so
//! one page the user closed early does not move a server to the slow way.
//! After [`DECOY_FOR`] the server gets the urgent byte again: filters and
//! servers change, and the cheap way is worth a new try. The table holds at
//! most [`MAX_SERVERS`] servers; the oldest are forgotten first.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// How long a server whose connections went silent with the urgent byte
/// gets the decoy instead.
pub const DECOY_FOR: Duration = Duration::from_secs(10 * 60);
/// Silent connections in a row that move a server to the decoy.
const STRIKES: u8 = 2;
/// Most servers remembered at once.
const MAX_SERVERS: usize = 256;
/// How long a reply may take before the connection counts as silent. Well
/// above a slow line's round trip, well below the time a person waits.
pub const SILENT_AFTER: Duration = Duration::from_secs(5);

/// The two ways of hiding a name from the socket itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Way {
    Urgent,
    Decoy,
}

#[derive(Clone, Copy)]
struct Record {
    strikes: u8,
    decoy_until: Option<Instant>,
    touched: Instant,
}

static SERVERS: Mutex<Option<HashMap<SocketAddr, Record>>> = Mutex::new(None);

fn with_table<T>(f: impl FnOnce(&mut HashMap<SocketAddr, Record>) -> T) -> T {
    let mut guard = SERVERS.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(HashMap::new))
}

/// The way to use towards `server`, given which ways this device has.
/// `None` when it has neither.
pub fn pick(server: SocketAddr, urgent: bool, decoy: bool) -> Option<Way> {
    let now = Instant::now();
    let wants_decoy = with_table(|table| {
        table
            .get(&server)
            .and_then(|record| record.decoy_until)
            .is_some_and(|until| until > now)
    });
    match (urgent, decoy) {
        (true, true) if wants_decoy => Some(Way::Decoy),
        (true, _) => Some(Way::Urgent),
        (false, true) => Some(Way::Decoy),
        (false, false) => None,
    }
}

/// What one connection that used the urgent byte showed about `server`.
fn report(server: SocketAddr, answered: bool) {
    let now = Instant::now();
    with_table(|table| {
        if !answered && table.len() >= MAX_SERVERS && !table.contains_key(&server) {
            // Forget the server least recently heard of.
            if let Some(oldest) = table
                .iter()
                .min_by_key(|(_, record)| record.touched)
                .map(|(addr, _)| *addr)
            {
                table.remove(&oldest);
            }
        }
        if answered {
            // Nothing to keep for a server the cheap way works for.
            table.remove(&server);
            return;
        }
        let record = table.entry(server).or_insert(Record {
            strikes: 0,
            decoy_until: None,
            touched: now,
        });
        record.touched = now;
        record.strikes = record.strikes.saturating_add(1);
        if record.strikes >= STRIKES {
            record.strikes = 0;
            record.decoy_until = Some(now + DECOY_FOR);
            tracing::info!(%server, "urgent byte went unanswered; using the decoy for this server");
        }
    });
}

/// Where a watched connection is in its exchange with the server.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Nothing written yet.
    Idle,
    /// The first flight (the hello) is out; waiting for the answer.
    FirstOut,
    /// The server answered the first flight.
    FirstAnswered,
    /// The second flight is out; waiting for the answer.
    SecondOut,
    /// The server answered the second flight too. Final.
    Answered,
}

/// `inner` (a stream sending the urgent byte) with a note kept of whether
/// the server answered, reported for `server` when it is dropped. Reads and
/// writes pass straight through.
pub struct Watched<S> {
    inner: S,
    server: SocketAddr,
    phase: Phase,
    /// Set once the verdict has been reported, so it is reported once.
    reported: bool,
    /// Runs while a flight waits for its reply ([`SILENT_AFTER`]).
    waiting: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> Watched<S> {
    pub fn new(inner: S, server: SocketAddr) -> Self {
        Self {
            inner,
            server,
            phase: Phase::Idle,
            reported: false,
            waiting: None,
        }
    }

    fn verdict(&mut self, answered: bool) {
        if !std::mem::replace(&mut self.reported, true) {
            report(self.server, answered);
        }
    }

    /// Move to `phase`; a flight that went out starts the reply clock.
    fn enter(&mut self, phase: Phase) {
        self.phase = phase;
        self.waiting = matches!(phase, Phase::FirstOut | Phase::SecondOut)
            .then(|| Box::pin(tokio::time::sleep(SILENT_AFTER)));
        if phase == Phase::Answered {
            self.verdict(true);
        }
    }
}

impl<S> Drop for Watched<S> {
    fn drop(&mut self) {
        if matches!(self.phase, Phase::FirstOut | Phase::SecondOut) {
            self.verdict(false);
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = std::task::ready!(Pin::new(&mut this.inner).poll_write(cx, buf));
        if matches!(written, Ok(n) if n > 0) {
            match this.phase {
                Phase::Idle => this.enter(Phase::FirstOut),
                Phase::FirstAnswered => this.enter(Phase::SecondOut),
                _ => {}
            }
        }
        Poll::Ready(written)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let Poll::Ready(read) = Pin::new(&mut this.inner).poll_read(cx, buf) else {
            // Nothing yet: a reply that is overdue is a strike now, while the
            // connection is still open.
            if let Some(waiting) = this.waiting.as_mut() {
                if waiting.as_mut().poll(cx).is_ready() {
                    this.waiting = None;
                    this.verdict(false);
                }
            }
            return Poll::Pending;
        };
        if read.is_ok() && buf.filled().len() > before {
            match this.phase {
                Phase::FirstOut => this.enter(Phase::FirstAnswered),
                Phase::SecondOut => this.enter(Phase::Answered),
                _ => {}
            }
        }
        Poll::Ready(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn server(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }

    /// Two silent connections move a server to the decoy; one answered
    /// connection in between wipes the strike.
    #[test]
    fn two_silent_connections_in_a_row_move_a_server_to_the_decoy() {
        let s = server(1001);
        assert_eq!(pick(s, true, true), Some(Way::Urgent));
        report(s, false);
        report(s, true);
        report(s, false);
        assert_eq!(pick(s, true, true), Some(Way::Urgent), "strike was wiped");
        report(s, false);
        assert_eq!(pick(s, true, true), Some(Way::Decoy));
        // Without the decoy on this device it stays on the urgent byte.
        assert_eq!(pick(s, true, false), Some(Way::Urgent));
        assert_eq!(pick(server(1002), false, true), Some(Way::Decoy));
        assert_eq!(pick(server(1002), false, false), None);
    }

    /// The phases: a connection that got its second answer counts as
    /// answered, one dropped while waiting counts as silent.
    #[tokio::test]
    async fn a_connection_is_judged_by_the_answer_to_its_second_flight() {
        let (client, mut far) = tokio::io::duplex(64);
        let s = server(1003);
        let mut watched = Watched::new(client, s);
        watched.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        far.read_exact(&mut got).await.unwrap();
        far.write_all(b"answer").await.unwrap();
        let mut back = [0u8; 6];
        watched.read_exact(&mut back).await.unwrap();
        watched.write_all(b"finished").await.unwrap();
        // Dropped while the second flight waits: a strike.
        drop(watched);
        report(s, false);
        assert_eq!(pick(s, true, true), Some(Way::Decoy));

        let (client, mut far) = tokio::io::duplex(64);
        let s = server(1004);
        report(s, false);
        let mut watched = Watched::new(client, s);
        watched.write_all(b"hello").await.unwrap();
        far.write_all(b"a").await.unwrap();
        watched.read_exact(&mut [0u8; 1]).await.unwrap();
        watched.write_all(b"request").await.unwrap();
        far.write_all(b"b").await.unwrap();
        watched.read_exact(&mut [0u8; 1]).await.unwrap();
        drop(watched);
        // The answered connection wiped the earlier strike.
        report(s, false);
        assert_eq!(pick(s, true, true), Some(Way::Urgent));
    }

    /// A reply that never comes is a strike once it is overdue, before the
    /// connection is closed, and only one.
    #[tokio::test(start_paused = true)]
    async fn an_overdue_reply_is_a_strike_while_the_connection_is_open() {
        let (client, _far) = tokio::io::duplex(64);
        let s = server(1005);
        let mut watched = Watched::new(client, s);
        watched.write_all(b"hello").await.unwrap();
        let read = tokio::time::timeout(SILENT_AFTER * 2, watched.read(&mut [0u8; 1])).await;
        assert!(read.is_err(), "no reply came");
        report(s, false);
        assert_eq!(pick(s, true, true), Some(Way::Decoy));
        drop(watched);
        // Dropping it afterwards did not count it a second time: one more
        // strike after the move is the first of a new pair.
        with_table(|table| assert_eq!(table[&s].strikes, 0));
    }
}
