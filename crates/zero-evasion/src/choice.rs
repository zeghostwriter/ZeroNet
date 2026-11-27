//! Which way to hide a server name, picked per server from what happened on
//! the last connections to it.
//!
//! There are five ways of hiding a name from a socket without root: the
//! urgent byte ([`crate::urgent`]), another version in the record header and
//! an empty record ahead of the hello ([`crate::record`]), TCP Fast Open (the hello rides in the SYN,
//! `zero_net::fastopen`) and the decoy ([`crate::decoy`]). They cost very
//! different amounts:
//!
//! * the urgent byte costs nothing: one extra byte, no wait;
//! * the record version and the empty record cost nothing and need nothing
//!   from the system; they come after the urgent byte because the filter in
//!   front of the Cloudflare ranges judges the connection afterwards and
//!   leaves it silent;
//! * Fast Open costs nothing either (it saves a round trip) once the
//!   kernel holds the server's cookie; the first connection to a server only
//!   fetches that cookie;
//! * the decoy costs every connection one round trip and a bit more, because
//!   the real hello only leaves once the server has said it is missing (about
//!   0.33 s per connection measured from Center, against 0.35 s for the whole
//!   plain handshake).
//!
//! But they do not get past the same things. Some servers read the urgent
//! byte badly: the handshake completes and then the server never answers
//! again. Some servers do not do Fast Open, and some paths drop a SYN that
//! carries data. So the rule here is "the free ways first, the decoy where
//! they have been seen to fail", one rung at a time:
//!
//! ```text
//! connection to 1.2.3.4:443   urgent byte → answered twice → stays urgent
//! connection to 5.6.7.8:443   urgent byte → went silent    → 1 strike
//! connection to 5.6.7.8:443   urgent byte → went silent    → 2 strikes:
//!                             Fast Open for this server for the next 10 minutes
//! connection to 5.6.7.8:443   Fast Open   → went silent    → 1, then 2 strikes:
//!                             the decoy for the next 10 minutes
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
//! After [`DECOY_FOR`] the server gets the cheap way again: filters and
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

/// How long a server whose connections went silent stays on the next way
/// down the ladder.
pub const DECOY_FOR: Duration = Duration::from_secs(10 * 60);
/// How long a server that gave no Fast Open is left alone by it.
const NO_FAST_FOR: Duration = Duration::from_secs(60 * 60);
/// Silent connections in a row that move a server one way down.
const STRIKES: u8 = 2;
/// Most servers remembered at once.
const MAX_SERVERS: usize = 256;
/// How long a reply may take before the connection counts as silent. Well
/// above a slow line's round trip, well below the time a person waits.
pub const SILENT_AFTER: Duration = Duration::from_secs(5);

/// The ways of hiding a name from the socket itself, cheapest first: this
/// is the order of the ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Way {
    Urgent,
    /// The first record header carries another version (`crate::record`).
    Record,
    /// An empty handshake record goes ahead of the hello (`crate::record`).
    Empty,
    /// The hello rides in the SYN (`zero_net::fastopen`).
    Fast,
    Decoy,
}

const LADDER: [Way; 5] = [Way::Urgent, Way::Record, Way::Empty, Way::Fast, Way::Decoy];

fn rung_of(way: Way) -> u8 {
    LADDER.iter().position(|&w| w == way).unwrap_or(0) as u8
}

/// Which ways this device has.
#[derive(Debug, Clone, Copy)]
pub struct Have {
    pub urgent: bool,
    pub record: bool,
    /// The empty record: not for a handshake that checks the first record
    /// itself (REALITY, ShadowTLS), which drops the connection.
    pub empty: bool,
    pub fast: bool,
    pub decoy: bool,
}

impl Have {
    fn has(self, way: Way) -> bool {
        match way {
            Way::Urgent => self.urgent,
            Way::Record => self.record,
            Way::Empty => self.empty,
            Way::Fast => self.fast,
            Way::Decoy => self.decoy,
        }
    }
}

#[derive(Clone, Copy)]
struct Record {
    strikes: u8,
    /// The rung of [`LADDER`] this server is on, while `until` is ahead.
    rung: u8,
    until: Option<Instant>,
    touched: Instant,
}

static SERVERS: Mutex<Option<HashMap<SocketAddr, Record>>> = Mutex::new(None);
/// The rung most servers on this network ended up on, and until when: where a
/// server nobody has tried yet starts.
static PRIOR: Mutex<Option<(u8, Instant)>> = Mutex::new(None);
static NO_FAST: Mutex<Option<HashMap<SocketAddr, Instant>>> = Mutex::new(None);

fn with_table<T>(f: impl FnOnce(&mut HashMap<SocketAddr, Record>) -> T) -> T {
    let mut guard = SERVERS.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(HashMap::new))
}

/// Note that `server` took no Fast Open (the connection to it was not
/// deferred even with a cookie fetched), so [`pick`] leaves it alone for an
/// hour.
pub fn no_fast(server: SocketAddr) {
    let mut guard = NO_FAST.lock().unwrap_or_else(|e| e.into_inner());
    let table = guard.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    table.retain(|_, until| *until > now);
    if table.len() < MAX_SERVERS {
        table.insert(server, now + NO_FAST_FOR);
    }
}

fn fast_refused(server: SocketAddr) -> bool {
    let guard = NO_FAST.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .and_then(|table| table.get(&server))
        .is_some_and(|until| *until > Instant::now())
}

/// The way to use towards `server`, given which ways this device has.
/// `None` when it has none.
///
/// A server starts on the first way it can use, or on the rung that worked
/// for the last servers when two of them had to move down. Each pair of silent
/// connections moves it one rung down for [`DECOY_FOR`]; a rung this device
/// lacks is skipped, and past the last one it has it stays there.
pub fn pick(server: SocketAddr, have: Have) -> Option<Way> {
    let have = Have {
        fast: have.fast && !fast_refused(server),
        ..have
    };
    let now = Instant::now();
    let prior = PRIOR
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .filter(|(_, until)| *until > now)
        .map_or(0, |(rung, _)| usize::from(rung));
    let rung = with_table(|table| {
        table
            .get(&server)
            .filter(|record| record.until.is_some_and(|until| until > now))
            .map_or(prior, |record| usize::from(record.rung))
    });
    LADDER[rung..]
        .iter()
        .chain(LADDER[..rung].iter().rev())
        .copied()
        .find(|&way| have.has(way))
}

/// Whether a dial to `server` should put the hello in the SYN. The question
/// [`zero_net::SocketOptions::fast_open_if`] asks before each candidate:
/// Fast Open is picked when the ladder says so. `others` is the same set of
/// ways the caller will pick from once the connection is open (it must be
/// the same, or the dial and the pick disagree about where the ladder is).
pub fn wants_fast(server: SocketAddr, others: Have) -> bool {
    server.ip().is_ipv4()
        && pick(
            server,
            Have {
                fast: true,
                ..others
            },
        ) == Some(Way::Fast)
}

/// What one connection that used `way` showed about `server`.
fn report(server: SocketAddr, way: Way, answered: bool) {
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
        let held = |record: &Record| record.until.is_some_and(|until| until > now);
        if answered {
            let rung = rung_of(way);
            match table.get_mut(&server) {
                // A late answer from a way the server has moved down from.
                Some(record) if held(record) && rung < record.rung => {}
                // The way it moved to works: keep it, so the cheap way is not
                // tried again at every third connection.
                Some(record) if held(record) => {
                    record.strikes = 0;
                    record.until = Some(now + DECOY_FOR);
                    // Two servers on this network got somewhere only below
                    // the cheap way: the next one starts there.
                    if table
                        .values()
                        .filter(|r| r.until.is_some_and(|u| u > now))
                        .count()
                        >= 2
                    {
                        *PRIOR.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some((rung, now + DECOY_FOR));
                    }
                }
                // Nothing to keep for a server the cheap way works for.
                _ => {
                    table.remove(&server);
                }
            }
            return;
        }
        let record = table.entry(server).or_insert(Record {
            strikes: 0,
            rung: 0,
            until: None,
            touched: now,
        });
        record.touched = now;
        // A connection from before the server moved down says nothing new.
        if record.until.is_some_and(|until| until > now) && rung_of(way) < record.rung {
            return;
        }
        record.strikes = record.strikes.saturating_add(1);
        if record.strikes >= STRIKES {
            record.strikes = 0;
            record.rung = (rung_of(way) + 1).min(LADDER.len() as u8 - 1);
            record.until = Some(now + DECOY_FOR);
            tracing::info!(%server, ?way, "no answer; moving this server down to {:?}", LADDER[usize::from(record.rung)]);
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
    way: Way,
    phase: Phase,
    /// Set once the verdict has been reported, so it is reported once.
    reported: bool,
    /// Runs while a flight waits for its reply ([`SILENT_AFTER`]).
    waiting: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> Watched<S> {
    pub fn new(inner: S, server: SocketAddr, way: Way) -> Self {
        Self {
            inner,
            server,
            way,
            phase: Phase::Idle,
            reported: false,
            waiting: None,
        }
    }

    fn verdict(&mut self, answered: bool) {
        if !std::mem::replace(&mut self.reported, true) {
            report(self.server, self.way, answered);
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

    /// The learned starting rung is shared by every server, so tests that
    /// pick a way take turns and start without one.
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static TURN: Mutex<()> = Mutex::new(());
        let guard = TURN.lock().unwrap_or_else(|e| e.into_inner());
        *PRIOR.lock().unwrap_or_else(|e| e.into_inner()) = None;
        guard
    }

    fn have(urgent: bool, fast: bool, decoy: bool) -> Have {
        Have {
            urgent,
            record: false,
            empty: false,
            fast,
            decoy,
        }
    }

    /// The record-version and empty-record rungs sit between the urgent byte
    /// and Fast Open, and a device without them skips both.
    #[test]
    fn the_record_rungs_come_after_the_urgent_byte() {
        let _turn = lock();
        let s = server(1090);
        let all = Have {
            record: true,
            empty: true,
            ..have(true, true, true)
        };
        report(s, Way::Urgent, false);
        report(s, Way::Urgent, false);
        assert_eq!(pick(s, all), Some(Way::Record));
        report(s, Way::Record, false);
        report(s, Way::Record, false);
        assert_eq!(pick(s, all), Some(Way::Empty));
        report(s, Way::Empty, false);
        report(s, Way::Empty, false);
        assert_eq!(pick(s, all), Some(Way::Fast));
        assert_eq!(pick(s, have(true, true, true)), Some(Way::Fast));
    }

    /// With Fast Open on the device the ladder has a rung between the urgent
    /// byte and the decoy; a server that gives no Fast Open skips it.
    #[test]
    fn fast_open_is_the_rung_between_the_urgent_byte_and_the_decoy() {
        let _turn = lock();
        let s = server(1010);
        let all = have(true, true, true);
        assert_eq!(pick(s, all), Some(Way::Urgent));
        report(s, Way::Urgent, false);
        report(s, Way::Urgent, false);
        assert_eq!(pick(s, all), Some(Way::Fast));
        // A late strike from a connection that used the urgent byte changes
        // nothing now.
        report(s, Way::Urgent, false);
        report(s, Way::Urgent, false);
        assert_eq!(pick(s, all), Some(Way::Fast));
        report(s, Way::Fast, false);
        report(s, Way::Fast, false);
        assert_eq!(pick(s, all), Some(Way::Decoy));
        // Without Fast Open on the device the urgent byte goes straight to
        // the decoy, as before.
        let t = server(1011);
        report(t, Way::Urgent, false);
        report(t, Way::Urgent, false);
        assert_eq!(pick(t, have(true, true, true)), Some(Way::Fast));
        assert_eq!(pick(t, have(true, false, true)), Some(Way::Decoy));
    }

    /// A connection that gets an answer on the rung a server moved to keeps it
    /// there, and two servers that ended up on the same rung send the next
    /// one straight to it.
    #[test]
    fn the_rung_that_works_is_kept_and_learned() {
        let _turn = lock();
        let all = have(true, true, true);
        let (a, b, c) = (server(1020), server(1021), server(1022));
        for s in [a, b] {
            report(s, Way::Urgent, false);
            report(s, Way::Urgent, false);
            report(s, Way::Fast, true);
            assert_eq!(pick(s, all), Some(Way::Fast), "kept after an answer");
        }
        // c was never tried, and starts on Fast.
        assert_eq!(pick(c, all), Some(Way::Fast));
        // A server the urgent byte works for is forgotten as before.
        report(c, Way::Urgent, true);
        assert_eq!(pick(c, all), Some(Way::Fast), "prior still holds");
        *PRIOR.lock().unwrap() = None;
        assert_eq!(pick(c, all), Some(Way::Urgent));
    }

    /// A server that answered no Fast Open is not offered it, and the next
    /// rung is used instead.
    #[test]
    fn a_server_without_fast_open_skips_that_rung() {
        let _turn = lock();
        let s = server(1012);
        report(s, Way::Urgent, false);
        report(s, Way::Urgent, false);
        no_fast(s);
        assert_eq!(pick(s, have(true, true, true)), Some(Way::Decoy));
        assert_eq!(pick(s, have(true, true, false)), Some(Way::Urgent));
    }

    /// Two silent connections move a server to the decoy; one answered
    /// connection in between wipes the strike.
    #[test]
    fn two_silent_connections_in_a_row_move_a_server_to_the_decoy() {
        let _turn = lock();
        let s = server(1001);
        assert_eq!(pick(s, have(true, false, true)), Some(Way::Urgent));
        report(s, Way::Urgent, false);
        report(s, Way::Urgent, true);
        report(s, Way::Urgent, false);
        assert_eq!(
            pick(s, have(true, false, true)),
            Some(Way::Urgent),
            "strike was wiped"
        );
        report(s, Way::Urgent, false);
        assert_eq!(pick(s, have(true, false, true)), Some(Way::Decoy));
        // Without the decoy on this device it stays on the urgent byte.
        assert_eq!(pick(s, have(true, false, false)), Some(Way::Urgent));
        assert_eq!(
            pick(server(1002), have(false, false, true)),
            Some(Way::Decoy)
        );
        assert_eq!(pick(server(1002), have(false, false, false)), None);
    }

    /// The phases: a connection that got its second answer counts as
    /// answered, one dropped while waiting counts as silent.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn a_connection_is_judged_by_the_answer_to_its_second_flight() {
        let _turn = lock();
        let (client, mut far) = tokio::io::duplex(64);
        let s = server(1003);
        let mut watched = Watched::new(client, s, Way::Urgent);
        watched.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        far.read_exact(&mut got).await.unwrap();
        far.write_all(b"answer").await.unwrap();
        let mut back = [0u8; 6];
        watched.read_exact(&mut back).await.unwrap();
        watched.write_all(b"finished").await.unwrap();
        // Dropped while the second flight waits: a strike.
        drop(watched);
        report(s, Way::Urgent, false);
        assert_eq!(pick(s, have(true, false, true)), Some(Way::Decoy));

        let (client, mut far) = tokio::io::duplex(64);
        let s = server(1004);
        report(s, Way::Urgent, false);
        let mut watched = Watched::new(client, s, Way::Urgent);
        watched.write_all(b"hello").await.unwrap();
        far.write_all(b"a").await.unwrap();
        watched.read_exact(&mut [0u8; 1]).await.unwrap();
        watched.write_all(b"request").await.unwrap();
        far.write_all(b"b").await.unwrap();
        watched.read_exact(&mut [0u8; 1]).await.unwrap();
        drop(watched);
        // The answered connection wiped the earlier strike.
        report(s, Way::Urgent, false);
        assert_eq!(pick(s, have(true, false, true)), Some(Way::Urgent));
    }

    /// A reply that never comes is a strike once it is overdue, before the
    /// connection is closed, and only one.
    #[tokio::test(start_paused = true)]
    #[allow(clippy::await_holding_lock)]
    async fn an_overdue_reply_is_a_strike_while_the_connection_is_open() {
        let _turn = lock();
        let (client, _far) = tokio::io::duplex(64);
        let s = server(1005);
        let mut watched = Watched::new(client, s, Way::Urgent);
        watched.write_all(b"hello").await.unwrap();
        let read = tokio::time::timeout(SILENT_AFTER * 2, watched.read(&mut [0u8; 1])).await;
        assert!(read.is_err(), "no reply came");
        report(s, Way::Urgent, false);
        assert_eq!(pick(s, have(true, false, true)), Some(Way::Decoy));
        drop(watched);
        // Dropping it afterwards did not count it a second time: one more
        // strike after the move is the first of a new pair.
        with_table(|table| assert_eq!(table[&s].strikes, 0));
    }
}
