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
//! The rules it keeps:
//!  * a nonce (the offset) is used for exactly one chunk, which is why a
//!    resent chunk is the stored bytes, never a re-cut of the stream;
//!  * a receiver never holds more than it granted: a stream's window of data,
//!    and a bounded amount of out-of-order chunks;
//!  * acknowledgements and credit are never held back by the data limit, or
//!    two full sides would wait on each other for ever.
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

use super::noise::{Cipher, Keys, TAG_LEN};

/// Bytes in front of a chunk's ciphertext: its offset and its length.
pub const CHUNK_HEADER: usize = 10;
/// The most plaintext one chunk carries.
pub const CHUNK_PLAIN_MAX: usize = 16 * 1024;
/// What a stream may send before the receiver has read any of it.
const STREAM_WINDOW: usize = 256 * 1024;
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
}

impl StreamState {
    fn wake(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
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
    /// Decrypted bytes not yet a whole frame.
    partial: BytesMut,
    // ---- server side: streams opened by the client, not yet accepted
    incoming: VecDeque<(u32, Destination)>,
    closed: Option<io::ErrorKind>,
    last_activity: Instant,
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
            early |= stream.sent < EARLY_BYTES;
            if let Some(destination) = stream.open_pending.take() {
                encode_open(id, &destination, out);
            }
            let room = max.saturating_sub(out.len() + DATA_HEADER);
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

    /// Forget a stream whose handle is gone and whose output has all left.
    fn reap(&mut self, id: u32) {
        let Some(stream) = self.streams.get(&id) else {
            return;
        };
        let drained = stream.send_buffer.is_empty() && (stream.fin_sent || stream.send_stopped);
        if stream.orphan && drained && stream.open_pending.is_none() {
            let finished = stream.receive_fin || stream.receive_reset;
            self.streams.remove(&id);
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
                return Some(sent.wire.clone());
            }
        }
        let mut plain = Vec::new();
        let early = self.build_plain(max_plain.min(CHUNK_PLAIN_MAX), &mut plain);
        if plain.is_empty() {
            return None;
        }
        if early {
            Self::pad(&mut plain);
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
        self.unacked_bytes += wire.len();
        self.unacked.push_back(Sent {
            offset,
            end,
            wire: wire.clone(),
            pipe,
            at: Instant::now(),
        });
        self.last_activity = Instant::now();
        Some(wire)
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
        let offset = u64::from_be_bytes(header[..8].try_into().expect("8 bytes"));
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
        if self.expected - self.acknowledged >= ACK_EVERY {
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
                        if stream.receive_buffer.len() + data.len() > STREAM_WINDOW {
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
    pub fn new(role: Role, keys: Keys) -> Arc<Self> {
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
                partial: BytesMut::new(),
                incoming: VecDeque::new(),
                closed: None,
                last_activity: Instant::now(),
            }),
            sendable: Notify::new(),
            arrived: Notify::new(),
        })
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
            if core.expected > core.acknowledged {
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
        // Credit goes back in quarter-window steps: often enough that the
        // sender never stalls, rarely enough to cost almost nothing.
        if stream.unreported >= STREAM_WINDOW / 4 {
            let mut frame = Core::stream_frame(FRAME_CREDIT, self.id);
            frame.extend_from_slice(&(stream.unreported as u32).to_be_bytes());
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
            core.streams.remove(&self.id);
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
            Session::new(Role::Client, client_keys),
            Session::new(Role::Server, server_keys),
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

    #[test]
    fn pipe_tags_differ_by_direction_number_and_session() {
        let tag = pipe_tag(&[1; 32], b'u', 7);
        assert_eq!(tag.len(), 16);
        assert_ne!(tag, pipe_tag(&[1; 32], b'd', 7));
        assert_ne!(tag, pipe_tag(&[1; 32], b'u', 8));
        assert_ne!(tag, pipe_tag(&[2; 32], b'u', 7));
    }
}
