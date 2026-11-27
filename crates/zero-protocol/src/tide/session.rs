//! A Tide session: many streams, carried over whatever pipes are alive.
//!
//! How this works, bottom up. A *pipe* is anything that moves bytes one way
//! and may die at any time (an HTTP request body, a response body). The
//! session never trusts a pipe to finish.
//!
//!  * **Bond.** Everything one side sends is one long byte stream, cut into
//!    *chunks*. A chunk says where in that stream it starts
//!    (`offset: u64, length: u16`, then the encrypted bytes) and is sealed
//!    with the session key using the offset as the nonce. The receiver puts
//!    chunks back in order by offset, whichever pipe they came on, and now and
//!    then says how far it has got (an `ACK` frame travelling the other way).
//!    The sender keeps each sealed chunk until it is acknowledged; when a
//!    pipe dies, its unacknowledged chunks go out again, byte for byte the
//!    same, on another pipe. So directions can use different connections,
//!    pipes can be short-lived, and a cut connection loses nothing.
//!  * **Streams.** The byte stream is a sequence of *frames*: open a stream
//!    to a destination, data, finish, and so on. Each stream may only send
//!    what the other side has granted it credit for, so one slow stream
//!    cannot fill the receiver's memory or block the others.
//!  * **Scheduling.** A chunk is built at the moment a pipe is ready to take
//!    it, never earlier, and the stream that has sent the least so far goes
//!    first. A new or small stream (a page, a DNS lookup) is therefore not
//!    stuck behind a download.
//!
//!  * **Padding.** The first few kilobytes of a stream are where what it
//!    carries shows its sizes (a TLS hello, a short reply). A chunk holding
//!    such early data is filled up to the next step of [`PAD_STEP`] bytes
//!    plus a small random extra, with a frame the receiver skips. So an
//!    observer learns which step a size fell in and nothing finer, and no two
//!    connections show the same exact numbers. Later data is not padded.
//!
//!  * **Lane.** UDP does not want a reliable, ordered byte stream: a late
//!    voice packet is worse than a lost one. When both sides ask for it, the
//!    session also carries *datagrams*, built the way WireGuard builds its
//!    transport packets. Each is sealed on its own with a counter nonce (under
//!    a key of its own), carries no offset into the byte stream, is never
//!    resent, and is checked against a sliding replay window, so records may
//!    arrive in any order over any mix of pipes and a duplicate is dropped.
//!    A datagram belongs to a stream (the stream is the UDP flow: it opens and
//!    closes it, and its id names it), is padded in size classes, and is
//!    dropped rather than queued for long when the pipe cannot keep up.
//!    A lane record is told from a chunk by the top bit of its first field.
//!
//! The rules it keeps:
//!  * a nonce (the offset) is used for exactly one chunk, which is why a
//!    resent chunk is the stored bytes, never a re-cut of the stream;
//!  * a receiver never holds more than it granted: a stream's window of data,
//!    and a bounded amount of out-of-order chunks;
//!  * acknowledgements and credit are never held back by the data limit, or
//!    two full sides would wait on each other for ever;
//!  * a chunk never holds more than [`CHUNK_PLAIN_MAX`] plaintext bytes,
//!    whatever frames were cut into it: the receiver closes the session over
//!    a longer one;
//!  * a lane counter is used once, and a lane record that fails to open ends
//!    the session just as a bad chunk does, while a repeated or too old one is
//!    quietly dropped.
//!
//! The surprise: nothing here does I/O or knows what a pipe is made of. A
//! pipe writer asks [`Session::next_chunk`] for bytes to send; a pipe reader
//! hands what it received to [`Session::receive`]. That is the whole
//! interface, which is what lets the same session run over HTTP bodies today
//! and something else tomorrow.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use zero_core::{Address, Destination, Network};

use super::noise::{self, Cipher, Keys, TAG_LEN};
use super::shape::{ShapeLevel, Shaper};

/// Bytes in front of a chunk's ciphertext: its offset and its length.
pub const CHUNK_HEADER: usize = 10;
/// The most plaintext one chunk carries.
pub const CHUNK_PLAIN_MAX: usize = 16 * 1024;
/// What a stream may send before the receiver has read any of it.
const STREAM_WINDOW: usize = 256 * 1024;
/// A stream that has received this much is a bulk transfer, and may be given
/// the larger window below: a window caps a stream at window / round trip
/// (256 KiB over 160 ms is 13 Mbit/s whatever the link can do).
const BULK_AFTER: u64 = 1024 * 1024;
const BULK_WINDOW: usize = 4 * 1024 * 1024;
/// Most window, beyond the base one, that all of a session's bulk streams
/// together may be given. This is what a peer could make the receiver hold
/// if it stopped reading, so it bounds a session's memory, not just a stream's.
const WINDOW_BUDGET: usize = 16 * 1024 * 1024;
/// What an application may queue on a stream before its writes wait.
const STREAM_SEND_BUFFER: usize = 64 * 1024;
/// Sent but unacknowledged bytes above which no new data is cut. Control
/// frames (acknowledgements, credit) are still sent.
const UNACKED_LIMIT: usize = 4 * 1024 * 1024;
/// How far ahead of the next expected byte a chunk may arrive.
const REORDER_LIMIT: u64 = 8 * 1024 * 1024;
/// An acknowledgement is queued once this much has arrived since the last.
const ACK_EVERY: u64 = 64 * 1024;
/// Streams a peer may have open at once.
const MAX_STREAMS: usize = 512;
/// A chunk whose pipe has gone and which is still unacknowledged after this
/// long is sent again. Covers a pipe that ended cleanly but whose bytes never
/// arrived (a middlebox that swallowed them).
const RESEND_AFTER: Duration = Duration::from_secs(6);
/// How often [`Session::run_timers`] looks while there is something pending.
const TICK: Duration = Duration::from_millis(100);

/// A stream's data counts as early, and is padded, until it has sent this
/// much. A TLS handshake inside the stream is over well before.
const EARLY_BYTES: u64 = 4 * 1024;
/// Chunks with early data are padded up to a multiple of this, then by a
/// random amount below [`PAD_JITTER`]. 640 and not 512, so that a padded
/// small write is never the size of a TLS ClientHello on the wire (the Mux
/// padding in `mux.rs` learned this from the shape benchmark).
const PAD_STEP: usize = 640;
const PAD_JITTER: usize = 128;

/// Set in the first field of a record that belongs to the datagram lane. A
/// chunk's first field is a stream offset, which never gets near this bit.
const LANE_FLAG: u64 = 1 << 63;
/// How far behind the newest counter a lane record may arrive and still be
/// accepted, if not seen before. WireGuard's window is about twice this.
const LANE_WINDOW: u64 = 4096;
/// Most plaintext bytes of datagrams waiting to be sent. More than a pipe can
/// drain in a moment is just delay, so the rest is dropped, like a full UDP
/// socket buffer would.
const LANE_QUEUE_BYTES: usize = 256 * 1024;
/// A datagram that waited this long is dropped unsent: a game or call packet
/// that late is worse than none.
const LANE_MAX_AGE: Duration = Duration::from_millis(300);
/// Datagrams a stream keeps for its reader.
const LANE_INBOX: usize = 256;
/// Most wire bytes of lane records added to one write.
const LANE_BATCH: usize = 8 * 1024;
/// Inside a lane record, before the body: the stream id and the padding length.
const LANE_PLAIN_HEADER: usize = 6;
/// The largest datagram body: a whole chunk less the lane's own header.
pub const LANE_BODY_MAX: usize = CHUNK_PLAIN_MAX - LANE_PLAIN_HEADER;
/// A flow's first datagrams are padded like a stream's early data.
const LANE_EARLY: u32 = 8;
/// Later datagrams are rounded up to a multiple of this, plus a little.
const LANE_ROUND: usize = 32;

const FRAME_OPEN: u8 = 1;
const FRAME_DATA: u8 = 2;
const FRAME_FIN: u8 = 3;
const FRAME_RESET: u8 = 4;
const FRAME_CREDIT: u8 = 5;
const FRAME_ACK: u8 = 6;
const FRAME_PAD: u8 = 7;
const FRAME_STOP: u8 = 8;
/// A data frame's own header: type, stream id, length.
const DATA_HEADER: usize = 7;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Client,
    Server,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "tide session is closed")
}

/// One stream's state. Present from open until its handle is dropped and
/// everything it queued has gone out.
#[derive(Default)]
struct StreamState {
    /// Set until the OPEN frame has been written.
    open_pending: Option<Destination>,
    send_buffer: BytesMut,
    /// Bytes the peer will still accept.
    send_credit: usize,
    /// Bytes sent so far; the scheduler serves the smallest first.
    sent: u64,
    fin_queued: bool,
    fin_sent: bool,
    /// The peer asked us to stop, or reset the stream: writes fail.
    send_stopped: bool,
    receive_buffer: BytesMut,
    receive_fin: bool,
    /// Reads fail: the peer reset the stream.
    receive_reset: bool,
    /// Bytes the application has read that the peer has not been credited.
    unreported: usize,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    /// The application dropped its handle; only queued output remains.
    orphan: bool,
    /// Datagrams received for this stream and not yet read.
    lane_inbox: VecDeque<Bytes>,
    lane_waker: Option<Waker>,
    /// Datagrams sent so far, to tell a flow's early ones.
    lane_sent: u32,
    /// What this side lets the peer send before it has read any (zero means
    /// the base [`STREAM_WINDOW`]), and how much has been received in all.
    window: usize,
    receive_total: u64,
}

impl StreamState {
    fn wake(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.lane_waker.take() {
            waker.wake();
        }
    }

    fn window(&self) -> usize {
        if self.window == 0 {
            STREAM_WINDOW
        } else {
            self.window
        }
    }

    fn wants_to_send(&self) -> bool {
        self.open_pending.is_some()
            || (!self.send_buffer.is_empty() && self.send_credit > 0 && !self.send_stopped)
            || (self.fin_queued && !self.fin_sent && self.send_buffer.is_empty())
    }
}

/// A sealed chunk kept until the peer acknowledges it.
struct Sent {
    offset: u64,
    end: u64,
    wire: Bytes,
    /// The pipe it last went out on.
    pipe: u64,
    at: Instant,
}

/// A datagram waiting for a pipe.
struct LaneOut {
    stream: u32,
    body: Vec<u8>,
    at: Instant,
}

/// The sliding record of which lane counters have been seen: WireGuard's
/// replay filter. `check` is asked before the (costly) decryption and
/// `update` only after it succeeded, so forged records cannot move it.
struct ReplayWindow {
    /// One bit per counter, indexed by counter modulo the window.
    bits: Vec<u64>,
    /// The highest counter accepted; meaningful once `any` is set.
    newest: u64,
    any: bool,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            bits: vec![0; (LANE_WINDOW / 64) as usize],
            newest: 0,
            any: false,
        }
    }

    fn slot(counter: u64) -> (usize, u64) {
        let index = counter % LANE_WINDOW;
        ((index / 64) as usize, 1 << (index % 64))
    }

    fn check(&self, counter: u64) -> bool {
        if !self.any || counter > self.newest {
            return true;
        }
        if self.newest - counter >= LANE_WINDOW {
            return false;
        }
        let (word, bit) = Self::slot(counter);
        self.bits[word] & bit == 0
    }

    fn update(&mut self, counter: u64) {
        if !self.any || counter > self.newest {
            // Counters between the old newest and this one have not been
            // seen: clear the slots they reuse.
            let behind = if self.any {
                counter - self.newest
            } else {
                LANE_WINDOW
            };
            if behind >= LANE_WINDOW {
                self.bits.iter_mut().for_each(|word| *word = 0);
            } else {
                for gap in self.newest + 1..=counter {
                    let (word, bit) = Self::slot(gap);
                    self.bits[word] &= !bit;
                }
            }
            self.newest = counter;
            self.any = true;
        }
        let (word, bit) = Self::slot(counter);
        self.bits[word] |= bit;
    }
}

/// The datagram lane's state: keys, counter, replay filter and send queue.
struct Lane {
    send: Cipher,
    receive: Cipher,
    next: u64,
    window: ReplayWindow,
    queue: VecDeque<LaneOut>,
    queue_bytes: usize,
}

struct Core {
    role: Role,
    send: Cipher,
    receive: Cipher,
    streams: HashMap<u32, StreamState>,
    next_stream: u32,
    /// Small frames that jump the queue: credit, acknowledgements, resets.
    control: VecDeque<Vec<u8>>,
    // ---- bond, sending
    next_offset: u64,
    unacked: VecDeque<Sent>,
    unacked_bytes: usize,
    /// Offsets of unacknowledged chunks waiting to go out again.
    resend: VecDeque<u64>,
    live_send_pipes: HashSet<u64>,
    // ---- bond, receiving
    expected: u64,
    reorder: BTreeMap<u64, Vec<u8>>,
    reorder_bytes: u64,
    acknowledged: u64,
    /// Something other than an acknowledgement arrived since the last one
    /// went out. Acknowledgements are not themselves acknowledged: if they
    /// were, two idle sides would trade them for ever.
    ack_due: bool,
    /// Decrypted bytes not yet a whole frame.
    partial: BytesMut,
    // ---- server side: streams opened by the client, not yet accepted
    incoming: VecDeque<(u32, Destination)>,
    closed: Option<io::ErrorKind>,
    last_activity: Instant,
    /// `None` unless both sides agreed to carry datagrams.
    lane: Option<Lane>,
    /// Window granted to bulk streams beyond the base, in all.
    window_extra: usize,
    /// Keeps the up/down ratio browsing-like by padding the downstream; set
    /// only on a server that asks for it (see [`Session::shape`]).
    shaper: Option<Shaper>,
}

/// Bytes of the OPEN frame for `destination`.
fn open_size(destination: &Destination) -> usize {
    9 + match &destination.address {
        Address::Ip(std::net::IpAddr::V4(_)) => 4,
        Address::Ip(std::net::IpAddr::V6(_)) => 16,
        Address::Domain(name) => 1 + name.len().min(255),
    }
}

/// How many padding bytes a lane record of `plain_len` plaintext bytes gets.
fn lane_padding(plain_len: usize, early: bool) -> usize {
    let target = if early {
        (plain_len / PAD_STEP + 1) * PAD_STEP + rand::random::<usize>() % PAD_JITTER
    } else {
        plain_len.next_multiple_of(LANE_ROUND) + rand::random::<usize>() % (LANE_ROUND / 2)
    };
    target
        .saturating_sub(plain_len)
        .min(CHUNK_PLAIN_MAX.saturating_sub(plain_len))
        .min(u16::MAX as usize)
}

impl Core {
    fn queue_control(&mut self, frame: Vec<u8>) {
        self.control.push_back(frame);
    }

    fn stream_frame(kind: u8, id: u32) -> Vec<u8> {
        let mut frame = Vec::with_capacity(5);
        frame.push(kind);
        frame.extend_from_slice(&id.to_be_bytes());
        frame
    }

    /// Fill `out` with up to `max` bytes of frames. Control frames first,
    /// then stream data, least-served stream first. Returns whether any of
    /// the data was a stream's early data.
    fn build_plain(&mut self, max: usize, out: &mut Vec<u8>) -> bool {
        let mut early = false;
        while let Some(frame) = self.control.front() {
            if !out.is_empty() && out.len() + frame.len() > max {
                return early;
            }
            out.extend_from_slice(frame);
            self.control.pop_front();
        }
        if self.unacked_bytes >= UNACKED_LIMIT {
            return early;
        }
        while out.len() + DATA_HEADER + 1 < max {
            let Some(id) = self
                .streams
                .iter()
                .filter(|(_, stream)| stream.wants_to_send())
                .min_by_key(|(id, stream)| (stream.sent, **id))
                .map(|(id, _)| *id)
            else {
                return early;
            };
            let stream = self.streams.get_mut(&id).expect("just found");
            // The OPEN frame (and a FIN that may follow it) goes out whole or
            // not at all in this chunk, so a chunk never outgrows `max`.
            let reserve = if stream.fin_queued { 5 } else { 0 };
            if let Some(destination) = &stream.open_pending {
                if !out.is_empty() && out.len() + open_size(destination) + reserve > max {
                    return early;
                }
            }
            early |= stream.sent < EARLY_BYTES;
            if let Some(destination) = stream.open_pending.take() {
                encode_open(id, &destination, out);
            }
            let room = max.saturating_sub(out.len() + DATA_HEADER + reserve);
            let take = stream
                .send_buffer
                .len()
                .min(stream.send_credit)
                .min(room)
                .min(u16::MAX as usize);
            if take > 0 && !stream.send_stopped {
                out.push(FRAME_DATA);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&(take as u16).to_be_bytes());
                out.extend_from_slice(&stream.send_buffer[..take]);
                stream.send_buffer.advance(take);
                stream.send_credit -= take;
                stream.sent += take as u64;
                if let Some(waker) = stream.write_waker.take() {
                    waker.wake();
                }
            }
            if stream.fin_queued && !stream.fin_sent && stream.send_buffer.is_empty() {
                out.extend_from_slice(&Self::stream_frame(FRAME_FIN, id));
                stream.fin_sent = true;
            }
            self.reap(id);
            if take == 0 && room == 0 {
                return early;
            }
        }
        early
    }

    /// Fill a chunk that holds early data up to the next size step, plus a
    /// random extra, with a padding frame. See the module notes.
    fn pad(plain: &mut Vec<u8>) {
        let jitter = rand::random::<usize>() % PAD_JITTER;
        let target = (plain.len() / PAD_STEP + 1) * PAD_STEP + jitter;
        // A padding frame is at least its three-byte header.
        let filler = target.saturating_sub(plain.len() + 3);
        if plain.len() + 3 + filler > CHUNK_PLAIN_MAX {
            return;
        }
        plain.push(FRAME_PAD);
        plain.extend_from_slice(&(filler as u16).to_be_bytes());
        plain.resize(plain.len() + filler, 0);
    }

    /// Drop a stream's state, returning its extra window to the budget.
    fn remove_stream(&mut self, id: u32) {
        if let Some(stream) = self.streams.remove(&id) {
            self.window_extra -= stream.window().saturating_sub(STREAM_WINDOW);
        }
    }

    /// Forget a stream whose handle is gone and whose output has all left.
    fn reap(&mut self, id: u32) {
        let Some(stream) = self.streams.get(&id) else {
            return;
        };
        let drained = stream.send_buffer.is_empty() && (stream.fin_sent || stream.send_stopped);
        if stream.orphan && drained && stream.open_pending.is_none() {
            let finished = stream.receive_fin || stream.receive_reset;
            self.remove_stream(id);
            if !finished {
                // Nobody will read what the peer still sends: tell it to stop.
                self.queue_control(Self::stream_frame(FRAME_STOP, id));
            }
        }
    }

    /// The next chunk for `pipe`: a resend if one is waiting, else a new one
    /// cut from whatever is ready. `None` when there is nothing to send.
    fn next_chunk(&mut self, pipe: u64, max_plain: usize) -> Option<Bytes> {
        while let Some(offset) = self.resend.pop_front() {
            if let Ok(index) = self
                .unacked
                .binary_search_by_key(&offset, |sent| sent.offset)
            {
                let sent = &mut self.unacked[index];
                sent.pipe = pipe;
                sent.at = Instant::now();
                let wire = sent.wire.clone();
                if let Some(shaper) = &mut self.shaper {
                    shaper.sent(wire.len(), sent.at);
                }
                return Some(wire);
            }
        }
        let mut plain = Vec::new();
        let early = self.build_plain(max_plain.min(CHUNK_PLAIN_MAX), &mut plain);
        // Datagrams follow the chunk, so the OPEN frame of a flow that has
        // just been cut into it reaches the far side before its datagrams.
        let mut lane = Vec::new();
        self.drain_lane(&mut lane, LANE_BATCH);
        if let (Some(shaper), false) = (&mut self.shaper, lane.is_empty()) {
            shaper.sent(lane.len(), Instant::now());
        }
        if early {
            Self::pad(&mut plain);
        }
        // Ratio padding rides on a chunk being cut, or stands alone when the
        // peer is uploading and there is nothing to answer with.
        if let Some(shaper) = &mut self.shaper {
            let room = max_plain
                .min(CHUNK_PLAIN_MAX)
                .saturating_sub(plain.len() + 3);
            if (!plain.is_empty() || self.unacked_bytes < UNACKED_LIMIT) && room > 0 {
                let filler = shaper.pad_wanted(room, Instant::now());
                if filler > 0 {
                    plain.push(FRAME_PAD);
                    plain.extend_from_slice(&(filler as u16).to_be_bytes());
                    plain.resize(plain.len() + filler, 0);
                }
            }
        }
        if plain.is_empty() {
            return (!lane.is_empty()).then(|| Bytes::from(lane));
        }
        let offset = self.next_offset;
        let end = offset + plain.len() as u64;
        let mut header = [0u8; CHUNK_HEADER];
        header[..8].copy_from_slice(&offset.to_be_bytes());
        header[8..].copy_from_slice(&((plain.len() + TAG_LEN) as u16).to_be_bytes());
        self.send.seal(offset, &header, &mut plain);
        let mut wire = BytesMut::with_capacity(CHUNK_HEADER + plain.len());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&plain);
        let wire = wire.freeze();
        self.next_offset = end;
        if let Some(shaper) = &mut self.shaper {
            shaper.sent(wire.len(), Instant::now());
        }
        self.unacked_bytes += wire.len();
        self.unacked.push_back(Sent {
            offset,
            end,
            wire: wire.clone(),
            pipe,
            at: Instant::now(),
        });
        self.last_activity = Instant::now();
        if lane.is_empty() {
            return Some(wire);
        }
        let mut both = BytesMut::with_capacity(wire.len() + lane.len());
        both.extend_from_slice(&wire);
        both.extend_from_slice(&lane);
        Some(both.freeze())
    }

    /// Seal queued datagrams into `out`, up to `budget` wire bytes. Late ones
    /// are dropped; one whose stream has not been opened on the wire yet
    /// waits (its OPEN frame is cut into the chunk before this runs).
    fn drain_lane(&mut self, out: &mut Vec<u8>, budget: usize) {
        loop {
            let Some(lane) = self.lane.as_mut() else {
                return;
            };
            let Some(front) = lane.queue.front() else {
                return;
            };
            let stale = front.at.elapsed() > LANE_MAX_AGE;
            let stream = self.streams.get_mut(&front.stream);
            let usable = stream
                .as_ref()
                .is_some_and(|stream| !stream.send_stopped && !stream.orphan);
            if stale || !usable || lane.next >= LANE_FLAG - 1 {
                let gone = lane.queue.pop_front().expect("peeked");
                lane.queue_bytes -= gone.body.len();
                continue;
            }
            let stream = stream.expect("usable");
            if stream.open_pending.is_some() {
                return;
            }
            let plain_len = LANE_PLAIN_HEADER + front.body.len();
            let early = stream.lane_sent < LANE_EARLY;
            let padding = lane_padding(plain_len, early);
            let wire_len = CHUNK_HEADER + plain_len + padding + TAG_LEN;
            if !out.is_empty() && out.len() + wire_len > budget {
                return;
            }
            let item = lane.queue.pop_front().expect("peeked");
            lane.queue_bytes -= item.body.len();
            stream.lane_sent = stream.lane_sent.saturating_add(1);
            let mut plain = Vec::with_capacity(plain_len + padding + TAG_LEN);
            plain.extend_from_slice(&item.stream.to_be_bytes());
            plain.extend_from_slice(&(padding as u16).to_be_bytes());
            plain.extend_from_slice(&item.body);
            plain.resize(plain_len + padding, 0);
            let counter = lane.next;
            lane.next += 1;
            let mut header = [0u8; CHUNK_HEADER];
            header[..8].copy_from_slice(&(LANE_FLAG | counter).to_be_bytes());
            header[8..].copy_from_slice(&((plain.len() + TAG_LEN) as u16).to_be_bytes());
            lane.send.seal(counter, &header, &mut plain);
            out.extend_from_slice(&header);
            out.extend_from_slice(&plain);
            self.last_activity = Instant::now();
        }
    }

    /// One lane record off a pipe: check the replay window, open it, and hand
    /// the datagram to its stream.
    fn on_lane(&mut self, header: &[u8; CHUNK_HEADER], mut body: Vec<u8>) -> io::Result<()> {
        let Some(lane) = self.lane.as_mut() else {
            return Err(invalid("tide datagram lane was not agreed"));
        };
        let counter = u64::from_be_bytes(header[..8].try_into().expect("8 bytes")) & !LANE_FLAG;
        if !lane.window.check(counter) {
            return Ok(());
        }
        lane.receive
            .open(counter, header, &mut body)
            .map_err(|_| invalid("tide datagram failed authentication"))?;
        lane.window.update(counter);
        if body.len() < LANE_PLAIN_HEADER {
            return Err(invalid("tide datagram is too short"));
        }
        let flow = u32::from_be_bytes(body[..4].try_into().expect("4 bytes"));
        let padding = u16::from_be_bytes([body[4], body[5]]) as usize;
        if LANE_PLAIN_HEADER + padding > body.len() {
            return Err(invalid("tide datagram padding is longer than it"));
        }
        let end = body.len() - padding;
        // Stream 0 is never a stream: a record for it is cover traffic.
        if let Some(stream) = self.streams.get_mut(&flow) {
            if !stream.orphan && stream.lane_inbox.len() < LANE_INBOX {
                stream
                    .lane_inbox
                    .push_back(Bytes::copy_from_slice(&body[LANE_PLAIN_HEADER..end]));
                if let Some(waker) = stream.lane_waker.take() {
                    waker.wake();
                }
            }
        }
        self.last_activity = Instant::now();
        Ok(())
    }

    fn on_ack(&mut self, offset: u64) {
        while self.unacked.front().is_some_and(|sent| sent.end <= offset) {
            let sent = self.unacked.pop_front().expect("checked");
            self.unacked_bytes -= sent.wire.len();
        }
    }

    /// Queue again every unacknowledged chunk that last went out on `pipe`.
    fn requeue_pipe(&mut self, pipe: u64) {
        for sent in &self.unacked {
            if sent.pipe == pipe && !self.resend.contains(&sent.offset) {
                self.resend.push_back(sent.offset);
            }
        }
    }

    /// One chunk off a pipe: `header` is its ten bytes, `body` the ciphertext.
    fn on_chunk(&mut self, header: &[u8; CHUNK_HEADER], body: Vec<u8>) -> io::Result<()> {
        if header[0] & 0x80 != 0 {
            return self.on_lane(header, body);
        }
        let offset = u64::from_be_bytes(header[..8].try_into().expect("8 bytes"));
        if let Some(shaper) = &mut self.shaper {
            shaper.received(CHUNK_HEADER + body.len(), Instant::now());
        }
        if offset < self.expected || self.reorder.contains_key(&offset) {
            // Already have it. The sender is resending, so it does not know
            // how far we got: tell it now rather than at the next timer, or
            // it keeps spending a new pipe's first chunks on old news.
            if self.acknowledged < self.expected || offset < self.expected {
                self.queue_ack();
            }
            return Ok(());
        }
        if offset - self.expected > REORDER_LIMIT || self.reorder_bytes > REORDER_LIMIT {
            return Err(invalid("tide chunk is too far ahead"));
        }
        self.reorder_bytes += body.len() as u64;
        self.reorder.insert(offset, body);
        while let Some(mut body) = self.reorder.remove(&self.expected) {
            self.reorder_bytes -= body.len() as u64;
            let mut header = [0u8; CHUNK_HEADER];
            header[..8].copy_from_slice(&self.expected.to_be_bytes());
            header[8..].copy_from_slice(&(body.len() as u16).to_be_bytes());
            self.receive
                .open(self.expected, &header, &mut body)
                .map_err(|_| invalid("tide chunk failed authentication"))?;
            self.expected += body.len() as u64;
            self.partial.extend_from_slice(&body);
            self.parse_frames()?;
        }
        if self.ack_due && self.expected - self.acknowledged >= ACK_EVERY {
            self.queue_ack();
        }
        self.last_activity = Instant::now();
        Ok(())
    }

    fn queue_ack(&mut self) {
        let mut frame = Vec::with_capacity(9);
        frame.push(FRAME_ACK);
        frame.extend_from_slice(&self.expected.to_be_bytes());
        self.queue_control(frame);
        self.acknowledged = self.expected;
        self.ack_due = false;
    }

    fn parse_frames(&mut self) -> io::Result<()> {
        loop {
            let buffer = &self.partial[..];
            let Some(&kind) = buffer.first() else {
                return Ok(());
            };
            let id_of = |buffer: &[u8]| u32::from_be_bytes(buffer[1..5].try_into().expect("4"));
            let needed = match kind {
                FRAME_FIN | FRAME_RESET | FRAME_STOP => 5,
                FRAME_CREDIT | FRAME_ACK => 9,
                FRAME_PAD if buffer.len() >= 3 => {
                    3 + u16::from_be_bytes([buffer[1], buffer[2]]) as usize
                }
                FRAME_DATA if buffer.len() >= DATA_HEADER => {
                    DATA_HEADER + u16::from_be_bytes([buffer[5], buffer[6]]) as usize
                }
                FRAME_OPEN => match open_length(buffer)? {
                    Some(length) => length,
                    None => return Ok(()),
                },
                FRAME_PAD | FRAME_DATA => return Ok(()),
                _ => return Err(invalid("unknown tide frame")),
            };
            if buffer.len() < needed {
                return Ok(());
            }
            self.ack_due |= kind != FRAME_ACK;
            match kind {
                FRAME_OPEN => {
                    let id = id_of(buffer);
                    let destination = decode_open(&buffer[..needed])?;
                    // Clients open odd ids; anything else is a broken peer.
                    let acceptable = self.role == Role::Server
                        && id % 2 == 1
                        && !self.streams.contains_key(&id)
                        && self.streams.len() < MAX_STREAMS;
                    if acceptable {
                        self.streams.insert(
                            id,
                            StreamState {
                                send_credit: STREAM_WINDOW,
                                ..StreamState::default()
                            },
                        );
                        self.incoming.push_back((id, destination));
                    } else if self.role == Role::Server {
                        self.queue_control(Self::stream_frame(FRAME_RESET, id));
                    } else {
                        return Err(invalid("a tide server may not open streams"));
                    }
                }
                FRAME_DATA => {
                    let id = id_of(buffer);
                    if let Some(stream) = self.streams.get_mut(&id) {
                        let data = &buffer[DATA_HEADER..needed];
                        if stream.receive_buffer.len() + data.len() > stream.window() {
                            return Err(invalid("tide peer sent past its credit"));
                        }
                        if !stream.orphan {
                            stream.receive_buffer.extend_from_slice(data);
                        }
                        if let Some(waker) = stream.read_waker.take() {
                            waker.wake();
                        }
                    }
                }
                FRAME_FIN => {
                    let id = id_of(buffer);
                    if let Some(stream) = self.streams.get_mut(&id) {
                        stream.receive_fin = true;
                        stream.wake();
                    }
                    self.reap(id);
                }
                FRAME_RESET => {
                    if let Some(stream) = self.streams.get_mut(&id_of(buffer)) {
                        stream.receive_reset = true;
                        stream.send_stopped = true;
                        stream.send_buffer.clear();
                        stream.receive_buffer.clear();
                        stream.wake();
                    }
                    let id = id_of(buffer);
                    self.reap(id);
                }
                FRAME_STOP => {
                    let id = id_of(buffer);
                    if let Some(stream) = self.streams.get_mut(&id) {
                        stream.send_stopped = true;
                        stream.send_buffer.clear();
                        stream.wake();
                    }
                    self.reap(id);
                }
                FRAME_CREDIT => {
                    let amount = u32::from_be_bytes(buffer[5..9].try_into().expect("4")) as usize;
                    if let Some(stream) = self.streams.get_mut(&id_of(buffer)) {
                        stream.send_credit = stream.send_credit.saturating_add(amount);
                    }
                }
                FRAME_ACK => {
                    let offset = u64::from_be_bytes(buffer[1..9].try_into().expect("8"));
                    self.on_ack(offset);
                }
                _ => {} // Padding carries nothing.
            }
            self.partial.advance(needed);
        }
    }

    fn close(&mut self, kind: io::ErrorKind) {
        if self.closed.is_none() {
            tracing::debug!(?kind, streams = self.streams.len(), "tide session closing");
            self.closed = Some(kind);
        }
        for stream in self.streams.values_mut() {
            stream.receive_reset = true;
            stream.send_stopped = true;
            stream.wake();
        }
    }
}

fn encode_open(id: u32, destination: &Destination, out: &mut Vec<u8>) {
    out.push(FRAME_OPEN);
    out.extend_from_slice(&id.to_be_bytes());
    out.push(match destination.network {
        Network::Tcp => 1,
        Network::Udp => 2,
    });
    match &destination.address {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(name) => {
            let name = &name.as_bytes()[..name.len().min(255)];
            out.push(3);
            out.push(name.len() as u8);
            out.extend_from_slice(name);
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
}

/// The whole length of the OPEN frame at the front of `buffer`, or `None`
/// while too little of it has arrived to tell.
fn open_length(buffer: &[u8]) -> io::Result<Option<usize>> {
    if buffer.len() < 8 {
        return Ok(None);
    }
    let address = match buffer[6] {
        1 => 4,
        4 => 16,
        3 => 1 + buffer[7] as usize,
        _ => return Err(invalid("unknown tide address type")),
    };
    Ok(Some(7 + address + 2))
}

fn decode_open(frame: &[u8]) -> io::Result<Destination> {
    let network = match frame[5] {
        1 => Network::Tcp,
        2 => Network::Udp,
        _ => return Err(invalid("unknown tide network")),
    };
    let body = &frame[7..frame.len() - 2];
    let address = match frame[6] {
        1 => Address::Ip(<[u8; 4]>::try_from(body).expect("4").into()),
        4 => Address::Ip(<[u8; 16]>::try_from(body).expect("16").into()),
        _ => Address::domain(
            std::str::from_utf8(&body[1..]).map_err(|_| invalid("tide host is not UTF-8"))?,
        ),
    };
    let port = u16::from_be_bytes([frame[frame.len() - 2], frame[frame.len() - 1]]);
    Ok(Destination::new(address, port, network))
}

/// A running session. Cheap to share: pipes and stream handles all hold one.
pub struct Session {
    core: Mutex<Core>,
    /// Something became sendable (or the session closed).
    sendable: Notify,
    /// A stream arrived for [`Session::accept`].
    arrived: Notify,
    /// Proves a later request belongs to this session (see [`pipe_tag`]).
    binding: [u8; 32],
}

impl Session {
    pub fn new(role: Role, keys: Keys, lane: bool) -> Arc<Self> {
        let lane = lane.then(|| Lane {
            send: noise::lane_cipher(&keys.binding, role == Role::Client),
            receive: noise::lane_cipher(&keys.binding, role == Role::Server),
            next: 0,
            window: ReplayWindow::new(),
            queue: VecDeque::new(),
            queue_bytes: 0,
        });
        Arc::new(Self {
            binding: keys.binding,
            core: Mutex::new(Core {
                role,
                send: keys.send,
                receive: keys.receive,
                streams: HashMap::new(),
                next_stream: 1,
                control: VecDeque::new(),
                next_offset: 0,
                unacked: VecDeque::new(),
                unacked_bytes: 0,
                resend: VecDeque::new(),
                live_send_pipes: HashSet::new(),
                expected: 0,
                reorder: BTreeMap::new(),
                reorder_bytes: 0,
                acknowledged: 0,
                ack_due: false,
                partial: BytesMut::new(),
                incoming: VecDeque::new(),
                closed: None,
                last_activity: Instant::now(),
                lane,
                window_extra: 0,
                shaper: None,
            }),
            sendable: Notify::new(),
            arrived: Notify::new(),
        })
    }

    /// Have this side pad its sending to keep the up/down ratio inside the
    /// band set by `level`. Meant for a server: it is the side that can
    /// answer an upload with more download. Takes effect from now on and
    /// needs nothing from the peer, which skips padding frames anyway.
    pub fn shape(&self, level: ShapeLevel) {
        self.lock().shaper = Shaper::new(level, Instant::now());
    }

    fn lock(&self) -> MutexGuard<'_, Core> {
        self.core
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn binding(&self) -> &[u8; 32] {
        &self.binding
    }

    /// Open a stream to `destination`. Nothing is sent until the first chunk
    /// is cut, which carries the open and the first data together.
    pub fn open(self: &Arc<Self>, destination: Destination) -> io::Result<TideStream> {
        let mut core = self.lock();
        if core.closed.is_some() {
            return Err(closed());
        }
        if core.streams.len() >= MAX_STREAMS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "tide session has too many streams",
            ));
        }
        if destination.network == Network::Udp && core.lane.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this tide server does not carry UDP",
            ));
        }
        let id = core.next_stream;
        core.next_stream += 2;
        core.streams.insert(
            id,
            StreamState {
                open_pending: Some(destination),
                send_credit: STREAM_WINDOW,
                ..StreamState::default()
            },
        );
        drop(core);
        self.sendable.notify_waiters();
        Ok(TideStream {
            session: Arc::clone(self),
            id,
        })
    }

    /// The next stream the client opened, with where it wants to go.
    pub async fn accept(self: &Arc<Self>) -> io::Result<(Destination, TideStream)> {
        loop {
            let arrived = self.arrived.notified();
            tokio::pin!(arrived);
            arrived.as_mut().enable();
            {
                let mut core = self.lock();
                if let Some((id, destination)) = core.incoming.pop_front() {
                    return Ok((
                        destination,
                        TideStream {
                            session: Arc::clone(self),
                            id,
                        },
                    ));
                }
                if core.closed.is_some() {
                    return Err(closed());
                }
            }
            arrived.await;
        }
    }

    /// A pipe that can send announces itself, so its chunks can be told from
    /// those of pipes that have gone.
    pub fn pipe_opened(&self, pipe: u64) {
        self.lock().live_send_pipes.insert(pipe);
    }

    /// A sending pipe ended. `delivered` is false when it failed, in which
    /// case what it carried and was not acknowledged goes out again at once.
    pub fn pipe_closed(&self, pipe: u64, delivered: bool) {
        let mut core = self.lock();
        core.live_send_pipes.remove(&pipe);
        if !delivered {
            core.requeue_pipe(pipe);
        }
        drop(core);
        self.sendable.notify_waiters();
    }

    /// Wait for the next chunk to send on `pipe`, of at most `max_plain`
    /// plaintext bytes. The returned bytes are a whole chunk, ready to write.
    pub async fn next_chunk(&self, pipe: u64, max_plain: usize) -> io::Result<Bytes> {
        loop {
            let sendable = self.sendable.notified();
            tokio::pin!(sendable);
            sendable.as_mut().enable();
            {
                let mut core = self.lock();
                if let Some(kind) = core.closed {
                    return Err(kind.into());
                }
                if let Some(chunk) = core.next_chunk(pipe, max_plain) {
                    return Ok(chunk);
                }
            }
            sendable.await;
        }
    }

    /// A chunk without waiting, for a pipe that wants to batch what is ready.
    pub fn try_next_chunk(&self, pipe: u64, max_plain: usize) -> Option<Bytes> {
        let mut core = self.lock();
        if core.closed.is_some() {
            return None;
        }
        core.next_chunk(pipe, max_plain)
    }

    /// Hand over bytes read from a pipe. `parser` belongs to that pipe and
    /// remembers a chunk cut across two reads.
    pub fn receive(&self, parser: &mut ChunkParser, data: &[u8]) -> io::Result<()> {
        parser.buffer.extend_from_slice(data);
        let mut core = self.lock();
        let before = (core.control.len(), core.incoming.len());
        let result = (|| {
            while parser.buffer.len() >= CHUNK_HEADER {
                let header: [u8; CHUNK_HEADER] =
                    parser.buffer[..CHUNK_HEADER].try_into().expect("ten bytes");
                let length = u16::from_be_bytes([header[8], header[9]]) as usize;
                if !(TAG_LEN..=CHUNK_PLAIN_MAX + TAG_LEN).contains(&length) {
                    return Err(invalid("tide chunk has an impossible length"));
                }
                if parser.buffer.len() < CHUNK_HEADER + length {
                    break;
                }
                parser.buffer.advance(CHUNK_HEADER);
                let body = parser.buffer.split_to(length).to_vec();
                core.on_chunk(&header, body)?;
            }
            Ok(())
        })();
        if let Err(error) = &result {
            // The one reason a session ends that nothing else reports.
            tracing::debug!(%error, "tide session closed by a bad chunk");
            core.close(error.kind());
        }
        let woke_accept = core.incoming.len() != before.1;
        drop(core);
        // Credit or an ack may have freed data to send; cheap to announce.
        self.sendable.notify_waiters();
        if woke_accept || result.is_err() {
            self.arrived.notify_waiters();
        }
        result
    }

    /// End the session: every stream fails and every waiter returns.
    pub fn close(&self) {
        self.lock().close(io::ErrorKind::BrokenPipe);
        self.sendable.notify_waiters();
        self.arrived.notify_waiters();
    }

    pub fn is_closed(&self) -> bool {
        self.lock().closed.is_some()
    }

    /// Streams currently open.
    pub fn streams(&self) -> usize {
        self.lock().streams.len()
    }

    /// How long since a chunk was last sent or received.
    pub fn idle_for(&self) -> Duration {
        self.lock().last_activity.elapsed()
    }

    /// Whether anything is waiting to go out, for a pipe deciding to stay.
    pub fn has_output(&self) -> bool {
        let core = self.lock();
        !core.control.is_empty()
            || !core.resend.is_empty()
            || core
                .lane
                .as_ref()
                .is_some_and(|lane| !lane.queue.is_empty())
            || core.streams.values().any(StreamState::wants_to_send)
    }

    /// The periodic work: acknowledge what has arrived even when little did,
    /// and resend chunks whose pipe vanished without a word. Run one of these
    /// per session; it ends when the session closes.
    pub async fn run_timers(self: Arc<Self>) {
        loop {
            tokio::time::sleep(TICK).await;
            let mut core = self.lock();
            if core.closed.is_some() {
                return;
            }
            let mut wake = false;
            if core.ack_due && core.expected > core.acknowledged {
                core.queue_ack();
                wake = true;
            }
            let now = Instant::now();
            let stale: Vec<u64> = core
                .unacked
                .iter()
                .filter(|sent| {
                    !core.live_send_pipes.contains(&sent.pipe)
                        && now.duration_since(sent.at) > RESEND_AFTER
                        && !core.resend.contains(&sent.offset)
                })
                .map(|sent| sent.offset)
                .collect();
            if !stale.is_empty() {
                core.resend.extend(stale);
                wake = true;
            }
            drop(core);
            if wake {
                self.sendable.notify_waiters();
            }
        }
    }
}

/// Reassembles chunks from the bytes of one pipe.
#[derive(Default)]
pub struct ChunkParser {
    buffer: BytesMut,
}

/// One stream of a session, as an ordinary byte stream.
pub struct TideStream {
    session: Arc<Session>,
    id: u32,
}

impl TideStream {
    /// Send one datagram on this stream. Like UDP it may be lost: it is
    /// dropped, with `Ok`, when the queue is full, and unsent if it waits too
    /// long for a pipe. An error means the stream or session is gone, or the
    /// session carries no lane, or the datagram is larger than
    /// [`LANE_BODY_MAX`].
    pub fn send_datagram(&self, body: &[u8]) -> io::Result<()> {
        let mut core = self.session.lock();
        if core.closed.is_some() {
            return Err(closed());
        }
        let alive = core
            .streams
            .get(&self.id)
            .is_some_and(|stream| !stream.send_stopped && !stream.receive_reset);
        if !alive {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let Some(lane) = core.lane.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this tide session has no datagram lane",
            ));
        };
        if body.len() > LANE_BODY_MAX {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if lane.queue_bytes + body.len() > LANE_QUEUE_BYTES {
            return Ok(());
        }
        lane.queue_bytes += body.len();
        lane.queue.push_back(LaneOut {
            stream: self.id,
            body: body.to_vec(),
            at: Instant::now(),
        });
        drop(core);
        self.session.sendable.notify_waiters();
        Ok(())
    }

    /// Poll for the next datagram of this stream.
    pub fn poll_recv_datagram(&self, cx: &mut Context<'_>) -> Poll<io::Result<Bytes>> {
        let mut core = self.session.lock();
        let Some(stream) = core.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(closed()));
        };
        if stream.receive_reset {
            return Poll::Ready(Err(io::Error::other("the tide peer ended this stream")));
        }
        if let Some(datagram) = stream.lane_inbox.pop_front() {
            return Poll::Ready(Ok(datagram));
        }
        if stream.receive_fin {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        stream.lane_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// The next datagram of this stream; an error once the stream is over.
    pub async fn recv_datagram(&self) -> io::Result<Bytes> {
        std::future::poll_fn(|cx| self.poll_recv_datagram(cx)).await
    }
}

impl AsyncRead for TideStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut core = self.session.lock();
        let Some(stream) = core.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(closed()));
        };
        if stream.receive_reset {
            // Deliberately not `ConnectionReset`: the far end gave this one
            // stream up (it could not reach the destination, say). Callers
            // read a reset as the network cutting a connection, and react to
            // that as interference, which this is not.
            return Poll::Ready(Err(io::Error::other("the tide peer ended this stream")));
        }
        if stream.receive_buffer.is_empty() {
            if stream.receive_fin {
                return Poll::Ready(Ok(()));
            }
            stream.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let take = stream.receive_buffer.len().min(buf.remaining());
        buf.put_slice(&stream.receive_buffer[..take]);
        stream.receive_buffer.advance(take);
        stream.unreported += take;
        stream.receive_total += take as u64;
        // A stream that proves to be a bulk transfer gets a bigger window if
        // the session's budget has room; the difference is granted at once.
        let mut widened = 0;
        let Core {
            streams,
            window_extra,
            ..
        } = &mut *core;
        let stream = streams.get_mut(&self.id).expect("read just above");
        let more = BULK_WINDOW - STREAM_WINDOW;
        if stream.window() == STREAM_WINDOW
            && stream.receive_total >= BULK_AFTER
            && !stream.receive_fin
            && *window_extra + more <= WINDOW_BUDGET
        {
            stream.window = BULK_WINDOW;
            *window_extra += more;
            widened = more;
        }
        // Credit goes back in quarter-window steps: often enough that the
        // sender never stalls, rarely enough to cost almost nothing.
        if stream.unreported >= stream.window() / 4 || widened > 0 {
            let mut frame = Core::stream_frame(FRAME_CREDIT, self.id);
            let amount = stream.unreported + widened;
            frame.extend_from_slice(&(amount as u32).to_be_bytes());
            stream.unreported = 0;
            core.queue_control(frame);
            drop(core);
            self.session.sendable.notify_waiters();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TideStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut core = self.session.lock();
        let Some(stream) = core.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(closed()));
        };
        if stream.send_stopped || stream.fin_queued {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let room = STREAM_SEND_BUFFER.saturating_sub(stream.send_buffer.len());
        if room == 0 {
            stream.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let take = room.min(buf.len());
        stream.send_buffer.extend_from_slice(&buf[..take]);
        drop(core);
        self.session.sendable.notify_waiters();
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut core = self.session.lock();
        if let Some(stream) = core.streams.get_mut(&self.id) {
            stream.fin_queued = true;
        }
        drop(core);
        self.session.sendable.notify_waiters();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TideStream {
    fn drop(&mut self) {
        let mut core = self.session.lock();
        let Some(stream) = core.streams.get_mut(&self.id) else {
            return;
        };
        stream.orphan = true;
        stream.receive_buffer.clear();
        if !stream.fin_queued {
            // Dropped without a clean finish: abandon both directions.
            let unopened = stream.open_pending.is_some();
            core.remove_stream(self.id);
            if !unopened {
                core.queue_control(Core::stream_frame(FRAME_RESET, self.id));
            }
        } else {
            core.reap(self.id);
        }
        drop(core);
        self.session.sendable.notify_waiters();
    }
}

/// A short proof that a request for pipe `number` in direction `direction`
/// comes from someone holding the session's keys. It rides in the request
/// path, so a party that only learned the session's name cannot attach a
/// pipe of its own.
pub fn pipe_tag(binding: &[u8; 32], direction: u8, number: u64) -> String {
    use hmac::Mac;
    let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(binding)
        .expect("HMAC takes any key length");
    mac.update(&[direction]);
    mac.update(&number.to_be_bytes());
    hex::encode(&mac.finalize().into_bytes()[..8])
}

#[cfg(test)]
mod tests {
    use super::super::noise;
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn pair() -> (Arc<Session>, Arc<Session>) {
        let server_secret = [3u8; 32];
        let (hello, initiator) =
            noise::initiate(b"t", &noise::public_key(&server_secret), [4u8; 32], b"").unwrap();
        let (_, responder) = noise::respond(b"t", &server_secret, &hello).unwrap();
        let (reply, server_keys) = responder.reply([5u8; 32], b"").unwrap();
        let (_, client_keys) = initiator.finish(&reply).unwrap();
        (
            Session::new(Role::Client, client_keys, true),
            Session::new(Role::Server, server_keys, true),
        )
    }

    fn destination() -> Destination {
        Destination::tcp(Address::domain("example.com"), 443)
    }

    /// Carry chunks from `from` to `to` as one pipe would, until told to
    /// stop. `drop_after` makes the pipe die after that many chunks, losing
    /// the one in flight.
    fn pipe(
        from: Arc<Session>,
        to: Arc<Session>,
        id: u64,
        drop_after: Option<usize>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            from.pipe_opened(id);
            let mut parser = ChunkParser::default();
            let mut carried = 0;
            while let Ok(chunk) = from.next_chunk(id, CHUNK_PLAIN_MAX).await {
                // A pipe takes time; this also lets the paused clock move, so
                // the sessions' timers run as they would on a real link.
                tokio::time::sleep(Duration::from_millis(5)).await;
                if drop_after == Some(carried) {
                    from.pipe_closed(id, false);
                    return;
                }
                carried += 1;
                // Deliver in two pieces, as a real read might.
                let cut = chunk.len() / 2;
                to.receive(&mut parser, &chunk[..cut]).unwrap();
                to.receive(&mut parser, &chunk[cut..]).unwrap();
            }
        })
    }

    async fn echo_server(server: Arc<Session>) {
        while let Ok((_, mut stream)) = server.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => stream.write_all(&buffer[..n]).await.unwrap(),
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    }

    fn pattern(length: usize, seed: u8) -> Vec<u8> {
        (0..length)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[tokio::test]
    async fn a_stream_round_trips_and_finishes_cleanly() {
        let (client, server) = pair();
        pipe(client.clone(), server.clone(), 1, None);
        pipe(server.clone(), client.clone(), 2, None);
        tokio::spawn(client.clone().run_timers());
        tokio::spawn(server.clone().run_timers());
        tokio::spawn(echo_server(server.clone()));

        let mut stream = client.open(destination()).unwrap();
        let payload = pattern(600_000, 1);
        let (mut reader, mut writer) = tokio::io::split(stream_box(&mut stream));
        let send = async {
            writer.write_all(&payload).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let receive = async {
            let mut got = Vec::new();
            reader.read_to_end(&mut got).await.unwrap();
            got
        };
        let ((), got) = tokio::join!(send, receive);
        assert_eq!(got.len(), payload.len());
        assert!(got == payload, "bytes came back altered");
    }

    /// `tokio::io::split` wants an owned stream; this lends one.
    fn stream_box(stream: &mut TideStream) -> &mut TideStream {
        stream
    }

    #[tokio::test]
    async fn the_destination_reaches_the_server_with_the_first_data() {
        let (client, server) = pair();
        let mut stream = client.open(destination()).unwrap();
        stream.write_all(b"first").await.unwrap();
        // One chunk carries the open and the data: no round trip between.
        let chunk = client.try_next_chunk(1, CHUNK_PLAIN_MAX).unwrap();
        assert!(client.try_next_chunk(1, CHUNK_PLAIN_MAX).is_none());
        server.receive(&mut ChunkParser::default(), &chunk).unwrap();
        let (to, mut accepted) = server.accept().await.unwrap();
        assert_eq!(to, destination());
        let mut first = [0u8; 5];
        accepted.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"first");
    }

    /// The upload pipe dies again and again mid-transfer. Everything still
    /// arrives, once and in order, over the pipes that replace it.
    #[tokio::test(start_paused = true)]
    async fn a_dying_pipe_loses_nothing() {
        let (client, server) = pair();
        tokio::spawn(client.clone().run_timers());
        tokio::spawn(server.clone().run_timers());
        tokio::spawn(echo_server(server.clone()));
        pipe(server.clone(), client.clone(), 1000, None);
        let replacer = {
            let (client, server) = (client.clone(), server.clone());
            tokio::spawn(async move {
                for id in 1..200u64 {
                    // Each upload pipe carries three chunks, then drops one.
                    let _ = pipe(client.clone(), server.clone(), id, Some(3)).await;
                }
            })
        };
        let mut stream = client.open(destination()).unwrap();
        let payload = pattern(400_000, 9);
        let (mut reader, mut writer) = tokio::io::split(stream_box(&mut stream));
        let send = async {
            writer.write_all(&payload).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let receive = async {
            let mut got = Vec::new();
            reader.read_to_end(&mut got).await.unwrap();
            got
        };
        let ((), got) = tokio::join!(send, receive);
        assert!(got == payload, "a dropped pipe lost or reordered data");
        replacer.abort();
    }

    /// Two pipes in the same direction deliver out of order; the receiver
    /// still reads the stream in order.
    #[tokio::test]
    async fn chunks_arriving_out_of_order_are_put_back_in_order() {
        let (client, server) = pair();
        let mut stream = client.open(destination()).unwrap();
        let payload = pattern(50_000, 3);
        let mut chunks = Vec::new();
        let mut sent = 0;
        while sent < payload.len() {
            let take = (payload.len() - sent).min(STREAM_SEND_BUFFER);
            stream.write_all(&payload[sent..sent + take]).await.unwrap();
            sent += take;
            while let Some(chunk) = client.try_next_chunk(1, 4000) {
                chunks.push(chunk);
            }
        }
        assert!(chunks.len() > 5);
        chunks.reverse();
        let mut parser = ChunkParser::default();
        for chunk in &chunks {
            server.receive(&mut parser, chunk).unwrap();
        }
        let (_, mut accepted) = server.accept().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        accepted.read_exact(&mut got).await.unwrap();
        assert!(got == payload);
        // A duplicate of something already delivered changes nothing.
        server.receive(&mut parser, &chunks[0]).unwrap();
    }

    /// A download in progress does not hold up a stream that starts later:
    /// the newcomer has sent less, so its bytes are cut first.
    #[tokio::test]
    async fn a_new_stream_is_served_ahead_of_a_busy_one() {
        let (client, _server) = pair();
        let mut busy = client.open(destination()).unwrap();
        busy.write_all(&pattern(STREAM_SEND_BUFFER, 1))
            .await
            .unwrap();
        let first = client.try_next_chunk(1, CHUNK_PLAIN_MAX).unwrap();
        assert!(first.len() > 16_000, "the busy stream filled a chunk");
        busy.write_all(&pattern(10_000, 1)).await.unwrap();

        let mut small = client.open(destination()).unwrap();
        small.write_all(b"quick").await.unwrap();
        let mut plain = Vec::new();
        client.lock().build_plain(CHUNK_PLAIN_MAX, &mut plain);
        // The small stream's open frame is the first thing in the chunk.
        assert_eq!(plain[0], FRAME_OPEN);
        assert_eq!(u32::from_be_bytes(plain[1..5].try_into().unwrap()), 3);
    }

    /// A stream nobody reads stops being sent to once its window is full,
    /// while another stream on the same session keeps flowing.
    #[tokio::test]
    async fn an_unread_stream_does_not_block_the_others() {
        let (client, server) = pair();
        pipe(client.clone(), server.clone(), 1, None);
        pipe(server.clone(), client.clone(), 2, None);
        let mut stuck = client.open(destination()).unwrap();
        let filler = pattern(STREAM_WINDOW * 2, 5);
        let writer = tokio::spawn(async move {
            let _ = stuck.write_all(&filler).await;
            stuck
        });
        let (_, _unread) = server.accept().await.unwrap();

        let mut lively = client.open(destination()).unwrap();
        let (_, mut accepted) = {
            lively.write_all(b"hello").await.unwrap();
            server.accept().await.unwrap()
        };
        let mut hello = [0u8; 5];
        accepted.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
        // The stuck stream's receiver holds exactly one window, no more.
        tokio::task::yield_now().await;
        let held = server
            .lock()
            .streams
            .values()
            .map(|s| s.receive_buffer.len())
            .max()
            .unwrap();
        assert!(held <= STREAM_WINDOW);
        writer.abort();
    }

    #[tokio::test]
    async fn a_forged_chunk_closes_the_session_rather_than_being_read() {
        let (client, server) = pair();
        let mut stream = client.open(destination()).unwrap();
        stream.write_all(b"data").await.unwrap();
        let mut chunk = client.try_next_chunk(1, CHUNK_PLAIN_MAX).unwrap().to_vec();
        *chunk.last_mut().unwrap() ^= 1;
        assert!(server.receive(&mut ChunkParser::default(), &chunk).is_err());
        assert!(server.is_closed());
    }

    #[tokio::test]
    async fn dropping_a_stream_tells_the_other_side() {
        let (client, server) = pair();
        pipe(client.clone(), server.clone(), 1, None);
        pipe(server.clone(), client.clone(), 2, None);
        let mut stream = client.open(destination()).unwrap();
        stream.write_all(b"x").await.unwrap();
        let (_, mut accepted) = server.accept().await.unwrap();
        let mut byte = [0u8; 1];
        accepted.read_exact(&mut byte).await.unwrap();
        drop(stream);
        assert!(
            accepted.read(&mut byte).await.is_err(),
            "reset reaches the reader"
        );
        assert_eq!(client.streams(), 0);
    }

    /// An early chunk's size says which step its content fell in
    /// and nothing finer; a stream past its first kilobytes is not padded.
    /// A pipe like [`pipe`] that also adds what it carried to `count`.
    fn counting_pipe(
        from: Arc<Session>,
        to: Arc<Session>,
        id: u64,
        delay: Duration,
        count: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        tokio::spawn(async move {
            from.pipe_opened(id);
            let mut parser = ChunkParser::default();
            while let Ok(chunk) = from.next_chunk(id, CHUNK_PLAIN_MAX).await {
                tokio::time::sleep(delay).await;
                count.fetch_add(chunk.len(), std::sync::atomic::Ordering::SeqCst);
                to.receive(&mut parser, &chunk).unwrap();
            }
        });
    }

    /// Upload `size` bytes to a server that only reads, and return
    /// `(up, down)` wire bytes, with the server shaping at `level`.
    async fn upload_only(level: ShapeLevel, size: usize) -> (usize, usize) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (client, server) = pair();
        server.shape(level);
        let (up, down) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        // The way down is faster than the way up, as on a real line, so
        // the padding is not limited by the test's pipe.
        counting_pipe(
            client.clone(),
            server.clone(),
            1,
            Duration::from_millis(2),
            up.clone(),
        );
        counting_pipe(
            server.clone(),
            client.clone(),
            2,
            Duration::ZERO,
            down.clone(),
        );
        tokio::spawn(client.clone().run_timers());
        tokio::spawn(server.clone().run_timers());
        let sink = tokio::spawn({
            let server = server.clone();
            async move {
                let (_, mut stream) = server.accept().await.unwrap();
                let mut total = 0;
                let mut buffer = vec![0u8; 16 * 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break total,
                        Ok(n) => total += n,
                    }
                }
            }
        });
        let mut stream = client.open(destination()).unwrap();
        stream.write_all(&pattern(size, 7)).await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(sink.await.unwrap(), size, "the upload arrived whole");
        // Let the padding still owed go out: stop when nothing more moves.
        loop {
            let before = down.load(Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(150)).await;
            if down.load(Ordering::SeqCst) == before {
                break;
            }
        }
        (up.load(Ordering::SeqCst), down.load(Ordering::SeqCst))
    }

    /// The server's answer to an upload is kept near the level's ratio, the
    /// upload itself is untouched, and with shaping off it stays at the
    /// acknowledgements alone.
    #[tokio::test]
    async fn an_upload_is_answered_with_padding_up_to_the_level() {
        let (up, down) = upload_only(ShapeLevel::Off, 1_500_000).await;
        assert!(down * 10 < up, "off: {down} down for {up} up");
        let (up, down) = upload_only(ShapeLevel::Light, 1_500_000).await;
        let ratio = down as f64 / up as f64;
        assert!((0.3..0.7).contains(&ratio), "light: ratio {ratio:.2}");
        let (up, down) = upload_only(ShapeLevel::Full, 1_500_000).await;
        let ratio = down as f64 / up as f64;
        assert!((1.2..2.3).contains(&ratio), "full: ratio {ratio:.2}");
    }

    /// A download-only session is not padded at all, whatever the level.
    #[tokio::test]
    async fn a_download_is_not_padded() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (client, server) = pair();
        server.shape(ShapeLevel::Full);
        let down = Arc::new(AtomicUsize::new(0));
        pipe(client.clone(), server.clone(), 1, None);
        counting_pipe(
            server.clone(),
            client.clone(),
            2,
            Duration::ZERO,
            down.clone(),
        );
        tokio::spawn(client.clone().run_timers());
        tokio::spawn(server.clone().run_timers());
        tokio::spawn(async move {
            let (_, mut stream) = server.accept().await.unwrap();
            stream.write_all(&pattern(800_000, 3)).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut stream = client.open(destination()).unwrap();
        stream.write_all(b"GET").await.unwrap();
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got.len(), 800_000);
        assert!(down.load(Ordering::SeqCst) < 800_000 * 11 / 10);
    }

    /// Once everything has been delivered and acknowledged, neither side
    /// keeps sending: an idle session is silent, not an endless exchange of
    /// acknowledgements of acknowledgements.
    #[tokio::test]
    async fn an_idle_session_goes_quiet() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (client, server) = pair();
        let (up, down) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        counting_pipe(
            client.clone(),
            server.clone(),
            1,
            Duration::from_millis(1),
            up.clone(),
        );
        counting_pipe(
            server.clone(),
            client.clone(),
            2,
            Duration::from_millis(1),
            down.clone(),
        );
        tokio::spawn(client.clone().run_timers());
        tokio::spawn(server.clone().run_timers());
        tokio::spawn(echo_server(server.clone()));
        let mut stream = client.open(destination()).unwrap();
        stream.write_all(&pattern(300_000, 5)).await.unwrap();
        let mut got = vec![0u8; 300_000];
        stream.read_exact(&mut got).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        let before = up.load(Ordering::SeqCst) + down.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
        let after = up.load(Ordering::SeqCst) + down.load(Ordering::SeqCst);
        assert_eq!(
            before,
            after,
            "{} bytes moved on an idle session",
            after - before
        );
    }

    #[tokio::test]
    async fn early_data_is_padded_to_a_step_and_later_data_is_not() {
        let (client, server) = pair();
        let mut stream = client.open(destination()).unwrap();
        let mut sizes = std::collections::HashSet::new();
        for length in [1usize, 80, 300, 480] {
            stream.write_all(&pattern(length, 1)).await.unwrap();
            let chunk = client.try_next_chunk(1, CHUNK_PLAIN_MAX).unwrap();
            let plain = chunk.len() - CHUNK_HEADER - TAG_LEN;
            assert!(
                (PAD_STEP..2 * PAD_STEP + PAD_JITTER).contains(&plain),
                "{length} -> {plain}"
            );
            sizes.insert(plain);
            server.receive(&mut ChunkParser::default(), &chunk).unwrap();
        }
        assert!(sizes.len() > 1, "the random extra varies");
        // The padding is invisible to the stream's reader.
        let (_, mut accepted) = server.accept().await.unwrap();
        let mut got = vec![0u8; 861];
        accepted.read_exact(&mut got).await.unwrap();

        stream.write_all(&pattern(8000, 2)).await.unwrap();
        while client.try_next_chunk(1, CHUNK_PLAIN_MAX).is_some() {}
        stream.write_all(&pattern(100, 3)).await.unwrap();
        let late = client.try_next_chunk(1, CHUNK_PLAIN_MAX).unwrap();
        assert_eq!(late.len() - CHUNK_HEADER - TAG_LEN, DATA_HEADER + 100);
    }

    fn udp_destination() -> Destination {
        Destination::udp(Address::domain("example.com"), 3478)
    }

    /// Cut every chunk `session` has ready, as one pipe's writer would.
    fn drain(session: &Session) -> Vec<Bytes> {
        std::iter::from_fn(|| session.try_next_chunk(1, CHUNK_PLAIN_MAX)).collect()
    }

    fn parse(session: &Session, wire: &[u8]) -> io::Result<()> {
        session.receive(&mut ChunkParser::default(), wire)
    }

    /// A chunk that is nearly full must not take an OPEN frame that does not
    /// fit, nor a FIN after data that filled it exactly: the receiver closes
    /// the whole session over a chunk longer than the limit.
    #[tokio::test]
    async fn a_chunk_never_outgrows_the_limit() {
        let (client, server) = pair();
        let mut first = client.open(destination()).unwrap();
        // OPEN (21) + data header (7) + 16347 bytes = 16375 of 16384.
        first
            .write_all(&pattern(CHUNK_PLAIN_MAX - 37, 1))
            .await
            .unwrap();
        let _second = client.open(destination()).unwrap();
        for chunk in drain(&client) {
            assert!(chunk.len() <= CHUNK_HEADER + CHUNK_PLAIN_MAX + TAG_LEN);
            parse(&server, &chunk).expect("the receiver takes every chunk");
        }

        // Data that exactly fills a chunk, then a FIN.
        let (client, server) = pair();
        let mut stream = client.open(destination()).unwrap();
        stream
            .write_all(&pattern(CHUNK_PLAIN_MAX - 21 - DATA_HEADER, 2))
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        for chunk in drain(&client) {
            assert!(chunk.len() <= CHUNK_HEADER + CHUNK_PLAIN_MAX + TAG_LEN);
            parse(&server, &chunk).expect("the receiver takes every chunk");
        }
        assert!(!server.is_closed());
    }

    #[test]
    fn the_replay_window_accepts_each_counter_once_and_forgets_the_old() {
        let mut window = ReplayWindow::new();
        assert!(window.check(0));
        window.update(0);
        assert!(!window.check(0), "a repeat");
        // Out of order inside the window is fine, once.
        window.update(10);
        assert!(window.check(7));
        window.update(7);
        assert!(!window.check(7));
        assert!(window.check(9));
        // Far ahead: everything behind the window is refused, and slots the
        // jump reused are clean.
        window.update(10 + LANE_WINDOW * 3);
        assert!(!window.check(10), "too old");
        assert!(!window.check(10 + LANE_WINDOW * 3));
        assert!(window.check(10 + LANE_WINDOW * 3 - 1));
        // Just inside the edge.
        let edge = 10 + LANE_WINDOW * 3 - (LANE_WINDOW - 1);
        assert!(window.check(edge));
        assert!(!window.check(edge - 1));
    }

    #[tokio::test]
    async fn datagrams_cross_in_both_directions_and_are_padded() {
        let (client, server) = pair();
        let flow = client.open(udp_destination()).unwrap();
        flow.send_datagram(b"hello").unwrap();
        let wire = drain(&client);
        for chunk in &wire {
            parse(&server, chunk).unwrap();
        }
        let (destination, accepted) = server.accept().await.unwrap();
        assert_eq!(destination, udp_destination());
        assert_eq!(&accepted.recv_datagram().await.unwrap()[..], b"hello");

        // The flow's early records show a size class, not their length.
        let mut sizes = std::collections::HashSet::new();
        for length in [1usize, 50, 200, 400] {
            accepted.send_datagram(&pattern(length, 9)).unwrap();
            let chunk = server.try_next_chunk(1, CHUNK_PLAIN_MAX).unwrap();
            let plain = chunk.len() - CHUNK_HEADER - TAG_LEN;
            assert!(
                (PAD_STEP..2 * PAD_STEP + PAD_JITTER).contains(&plain),
                "{length} -> {plain}"
            );
            sizes.insert(plain);
            parse(&client, &chunk).unwrap();
            assert_eq!(
                flow.recv_datagram().await.unwrap()[..],
                pattern(length, 9)[..]
            );
        }
        assert!(sizes.len() > 1, "the random extra varies");
    }

    #[tokio::test]
    async fn a_repeated_or_reordered_record_is_dropped_or_taken_once() {
        let (client, server) = pair();
        let flow = client.open(udp_destination()).unwrap();
        // The OPEN has to get there first.
        flow.send_datagram(b"zero").unwrap();
        for chunk in drain(&client) {
            parse(&server, &chunk).unwrap();
        }
        let (_, accepted) = server.accept().await.unwrap();
        assert_eq!(&accepted.recv_datagram().await.unwrap()[..], b"zero");

        // Three records cut one after another, delivered 3, 1, 2, 1 again.
        let mut records = Vec::new();
        for body in [&b"one"[..], b"two", b"three"] {
            flow.send_datagram(body).unwrap();
            records.push(client.try_next_chunk(1, CHUNK_PLAIN_MAX).unwrap());
        }
        for index in [2usize, 0, 1, 0, 2] {
            parse(&server, &records[index]).unwrap();
        }
        let mut got = Vec::new();
        while let Ok(Ok(datagram)) =
            tokio::time::timeout(Duration::from_millis(50), accepted.recv_datagram()).await
        {
            got.push(datagram);
        }
        assert_eq!(got, vec![&b"three"[..], b"one", b"two"], "once each");
        assert!(!server.is_closed(), "repeats are not an error");
    }

    #[tokio::test]
    async fn a_forged_lane_record_ends_the_session() {
        let (client, server) = pair();
        let flow = client.open(udp_destination()).unwrap();
        flow.send_datagram(b"x").unwrap();
        let chunks = drain(&client);
        let mut lane = chunks.last().unwrap().to_vec();
        let last = lane.len() - 1;
        lane[last] ^= 1;
        for chunk in &chunks[..chunks.len() - 1] {
            parse(&server, chunk).unwrap();
        }
        assert!(parse(&server, &lane).is_err());
        assert!(server.is_closed());
    }

    #[tokio::test]
    async fn datagrams_follow_the_open_and_are_not_resent_when_a_pipe_dies() {
        let (client, server) = pair();
        let flow = client.open(udp_destination()).unwrap();
        for index in 0..5u8 {
            flow.send_datagram(&[index; 40]).unwrap();
        }
        // The first write holds the OPEN, then the datagrams, in that order.
        let first = client.try_next_chunk(7, CHUNK_PLAIN_MAX).unwrap();
        parse(&server, &first).unwrap();
        let (_, accepted) = server.accept().await.unwrap();
        for index in 0..5u8 {
            assert_eq!(accepted.recv_datagram().await.unwrap()[..], [index; 40]);
        }
        // That pipe is lost with a datagram on it: nothing is queued again.
        flow.send_datagram(b"lost").unwrap();
        client.pipe_opened(8);
        let _gone = client.try_next_chunk(8, CHUNK_PLAIN_MAX).unwrap();
        client.pipe_closed(8, false);
        assert!(client.try_next_chunk(9, CHUNK_PLAIN_MAX).is_none());
    }

    #[tokio::test]
    async fn datagrams_that_wait_too_long_or_overfill_the_queue_are_dropped() {
        let (client, _server) = pair();
        let flow = client.open(udp_destination()).unwrap();
        // The open goes out first; then only the queue's limit is in play.
        let _ = drain(&client);
        let big = vec![0u8; 8000];
        let mut accepted = 0;
        for _ in 0..100 {
            flow.send_datagram(&big).unwrap();
            accepted += 1;
        }
        assert!(accepted > 0);
        assert!(client.has_output());
        tokio::time::sleep(LANE_MAX_AGE + Duration::from_millis(50)).await;
        assert!(
            client.try_next_chunk(1, CHUNK_PLAIN_MAX).is_none(),
            "late datagrams are not worth sending"
        );
        assert!(flow.send_datagram(&vec![0u8; LANE_BODY_MAX + 1]).is_err());
    }

    #[tokio::test]
    async fn a_session_without_the_lane_refuses_udp() {
        let server_secret = [3u8; 32];
        let (hello, initiator) =
            noise::initiate(b"t", &noise::public_key(&server_secret), [4u8; 32], b"").unwrap();
        let (_, responder) = noise::respond(b"t", &server_secret, &hello).unwrap();
        let (reply, _) = responder.reply([5u8; 32], b"").unwrap();
        let (_, keys) = initiator.finish(&reply).unwrap();
        let client = Session::new(Role::Client, keys, false);
        let error = client.open(udp_destination()).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(client.open(destination()).is_ok(), "TCP is unaffected");
    }

    /// Datagrams over two pipes at once, a stream's bytes over a third, the
    /// way a bonded session runs: everything arrives.
    #[tokio::test]
    async fn the_lane_and_the_byte_stream_share_pipes() {
        let (client, server) = pair();
        pipe(client.clone(), server.clone(), 1, None);
        pipe(server.clone(), client.clone(), 2, None);
        tokio::spawn(client.clone().run_timers());
        tokio::spawn(server.clone().run_timers());
        let mut tcp = client.open(destination()).unwrap();
        let udp = client.open(udp_destination()).unwrap();
        let echo = tokio::spawn({
            let server = server.clone();
            async move {
                while let Ok((destination, stream)) = server.accept().await {
                    if destination.network == Network::Udp {
                        tokio::spawn(async move {
                            while let Ok(datagram) = stream.recv_datagram().await {
                                stream.send_datagram(&datagram).unwrap();
                            }
                        });
                    } else {
                        tokio::spawn(async move {
                            let mut stream = stream;
                            let mut buffer = vec![0u8; 8192];
                            while let Ok(n @ 1..) = stream.read(&mut buffer).await {
                                stream.write_all(&buffer[..n]).await.unwrap();
                            }
                        });
                    }
                }
            }
        });
        let payload = pattern(100_000, 4);
        let writer = {
            let payload = payload.clone();
            tokio::spawn(async move {
                tcp.write_all(&payload).await.unwrap();
                let mut back = vec![0u8; payload.len()];
                tcp.read_exact(&mut back).await.unwrap();
                back
            })
        };
        for round in 0..20u8 {
            udp.send_datagram(&[round; 120]).unwrap();
            let echoed = tokio::time::timeout(Duration::from_secs(5), udp.recv_datagram())
                .await
                .expect("an echo")
                .unwrap();
            assert_eq!(echoed[..], [round; 120]);
        }
        assert_eq!(writer.await.unwrap(), payload);
        echo.abort();
    }

    #[test]
    fn pipe_tags_differ_by_direction_number_and_session() {
        let tag = pipe_tag(&[1; 32], b'u', 7);
        assert_eq!(tag.len(), 16);
        assert_ne!(tag, pipe_tag(&[1; 32], b'd', 7));
        assert_ne!(tag, pipe_tag(&[1; 32], b'u', 8));
        assert_ne!(tag, pipe_tag(&[2; 32], b'u', 7));
    }
}
