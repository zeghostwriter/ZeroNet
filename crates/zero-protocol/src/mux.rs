//! The Xray/V2Ray Mux wire framing used by VLESS `CMD_MUX` requests.
//!
//! A mux carrier is a VLESS stream addressed to `v1.mux.cool:9527`; each
//! logical stream is then described by a bounded metadata frame.  The codec is
//! deliberately independent from pooling: callers may use one worker for one
//! logical stream first, and add a session manager without changing these
//! bytes.

use std::collections::HashMap;
use std::io;
use std::sync::{
    atomic::{AtomicBool, AtomicU16, Ordering},
    Arc, Mutex,
};

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use zero_core::{boxed, BoxStream, Destination, Network};

pub const CONTROL_HOST: &str = "v1.mux.cool";
pub const CONTROL_PORT: u16 = 9527;

pub const STATUS_NEW: u8 = 0x01;
pub const STATUS_KEEP: u8 = 0x02;
pub const STATUS_END: u8 = 0x03;
pub const STATUS_KEEP_ALIVE: u8 = 0x04;

pub const OPTION_DATA: u8 = 0x01;
pub const OPTION_ERROR: u8 = 0x02;

const NETWORK_TCP: u8 = 0x01;
const NETWORK_UDP: u8 = 0x02;
const MAX_METADATA: usize = 512;
const MAX_PAYLOAD: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub session_id: u16,
    pub status: u8,
    pub option: u8,
    pub target: Option<Destination>,
    /// XUDP's first UDP frame may carry an opaque eight-byte global id after
    /// the target. It is used for source correlation by Xray's cone mode and
    /// must survive decoding even when this runtime does not need it.
    pub global_id: Option<[u8; 8]>,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(session_id: u16, target: Destination, payload: Vec<u8>) -> Self {
        Self {
            session_id,
            status: STATUS_NEW,
            option: if payload.is_empty() { 0 } else { OPTION_DATA },
            target: Some(target),
            global_id: None,
            payload,
        }
    }

    pub fn keep(session_id: u16, payload: Vec<u8>) -> Self {
        Self {
            session_id,
            status: STATUS_KEEP,
            option: if payload.is_empty() { 0 } else { OPTION_DATA },
            target: None,
            global_id: None,
            payload,
        }
    }

    pub fn end(session_id: u16, error: bool) -> Self {
        Self {
            session_id,
            status: STATUS_END,
            option: if error { OPTION_ERROR } else { 0 },
            target: None,
            global_id: None,
            payload: Vec::new(),
        }
    }

    /// Build the first XUDP packet on a VLESS Mux carrier. Xray uses session
    /// id zero for this packet-oriented mode and carries the logical target in
    /// the metadata, not in the outer VLESS command.
    pub fn udp_new(target: Destination, payload: Vec<u8>, global_id: Option<[u8; 8]>) -> Self {
        let mut frame = Self::new(0, target, payload);
        frame.global_id = global_id;
        frame
    }

    /// Build a follow-up XUDP packet. The target is optional on the wire, but
    /// retaining it lets callers preserve the response source when required.
    pub fn udp_keep(session_id: u16, target: Option<Destination>, payload: Vec<u8>) -> Self {
        let mut frame = Self::keep(session_id, payload);
        frame.target = target;
        frame
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn encode_target(target: &Destination, metadata: &mut Vec<u8>) -> io::Result<()> {
    metadata.push(match target.network {
        Network::Tcp => NETWORK_TCP,
        Network::Udp => NETWORK_UDP,
    });
    metadata.extend_from_slice(&target.port.to_be_bytes());
    match &target.address {
        zero_core::Address::Ip(std::net::IpAddr::V4(ip)) => {
            metadata.push(1);
            metadata.extend_from_slice(&ip.octets());
        }
        zero_core::Address::Domain(domain) => {
            if domain.len() > u8::MAX as usize {
                return Err(invalid("mux target domain is too long"));
            }
            metadata.push(2);
            metadata.push(domain.len() as u8);
            metadata.extend_from_slice(domain.as_bytes());
        }
        zero_core::Address::Ip(std::net::IpAddr::V6(ip)) => {
            metadata.push(3);
            metadata.extend_from_slice(&ip.octets());
        }
    }
    Ok(())
}

fn decode_target(bytes: &[u8], offset: &mut usize) -> io::Result<Destination> {
    let network = *bytes
        .get(*offset)
        .ok_or_else(|| invalid("mux metadata is missing its network"))?;
    *offset += 1;
    let port = read_u16(bytes, offset)?;
    let kind = *bytes
        .get(*offset)
        .ok_or_else(|| invalid("mux metadata is missing its address type"))?;
    *offset += 1;
    let address = match kind {
        1 => {
            let end = checked_end(*offset, 4, bytes.len())?;
            let ip = std::net::Ipv4Addr::new(
                bytes[*offset],
                bytes[*offset + 1],
                bytes[*offset + 2],
                bytes[*offset + 3],
            );
            *offset = end;
            zero_core::Address::from(ip)
        }
        2 => {
            let length = *bytes
                .get(*offset)
                .ok_or_else(|| invalid("mux metadata is missing domain length"))?
                as usize;
            *offset += 1;
            let end = checked_end(*offset, length, bytes.len())?;
            let domain = std::str::from_utf8(&bytes[*offset..end])
                .map_err(|_| invalid("mux target domain is not UTF-8"))?;
            *offset = end;
            zero_core::Address::domain(domain)
        }
        3 => {
            let end = checked_end(*offset, 16, bytes.len())?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[*offset..end]);
            *offset = end;
            zero_core::Address::from(std::net::Ipv6Addr::from(octets))
        }
        other => return Err(invalid(format!("unknown mux address type {other}"))),
    };
    let network = match network {
        NETWORK_TCP => Network::Tcp,
        NETWORK_UDP => Network::Udp,
        other => return Err(invalid(format!("unknown mux network {other}"))),
    };
    Ok(Destination::new(address, port, network))
}

fn checked_end(offset: usize, length: usize, total: usize) -> io::Result<usize> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid("mux metadata length overflow"))?;
    if end > total {
        return Err(invalid("truncated mux metadata"));
    }
    Ok(end)
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> io::Result<u16> {
    let end = checked_end(*offset, 2, bytes.len())?;
    let value = u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]);
    *offset = end;
    Ok(value)
}

/// Append `u16 length || metadata` for `frame` to `out`.
fn encode_metadata_into(frame: &Frame, out: &mut Vec<u8>) -> io::Result<()> {
    if !matches!(
        frame.status,
        STATUS_NEW | STATUS_KEEP | STATUS_END | STATUS_KEEP_ALIVE
    ) {
        return Err(invalid(format!("unknown mux status {}", frame.status)));
    }
    let length_at = out.len();
    out.extend_from_slice(&[0, 0]);
    let metadata_at = out.len();
    out.extend_from_slice(&frame.session_id.to_be_bytes());
    out.push(frame.status);
    out.push(frame.option & (OPTION_DATA | OPTION_ERROR));
    let result = (|| {
        if frame.status == STATUS_NEW {
            let target = frame
                .target
                .as_ref()
                .ok_or_else(|| invalid("new mux frame has no target"))?;
            encode_target(target, out)?;
            if target.network == Network::Udp {
                if let Some(global_id) = frame.global_id {
                    out.extend_from_slice(&global_id);
                }
            } else if frame.global_id.is_some() {
                return Err(invalid("global id is valid only on UDP NEW frames"));
            }
        } else if let Some(target) = &frame.target {
            // Xray permits a target on a KEEP frame for packet-oriented sessions.
            encode_target(target, out)?;
            if frame.global_id.is_some() {
                return Err(invalid("global id is valid only on UDP NEW frames"));
            }
        } else if frame.global_id.is_some() {
            return Err(invalid("global id requires a UDP NEW target"));
        }
        Ok(())
    })();
    let metadata_len = out.len() - metadata_at;
    if result.is_err() || metadata_len > MAX_METADATA {
        out.truncate(length_at);
        result?;
        return Err(invalid("mux metadata exceeds 512 bytes"));
    }
    out[length_at..metadata_at].copy_from_slice(&(metadata_len as u16).to_be_bytes());
    Ok(())
}

/// Append one complete frame, including the optional data length and payload.
fn encode_frame_into(frame: &Frame, out: &mut Vec<u8>) -> io::Result<()> {
    if frame.payload.len() > MAX_PAYLOAD {
        return Err(invalid("mux payload exceeds 65535 bytes"));
    }
    if frame.payload.is_empty() && frame.option & OPTION_DATA != 0 {
        return Err(invalid("mux data option has an empty payload"));
    }
    encode_metadata_into(frame, out)?;
    if frame.option & OPTION_DATA != 0 {
        out.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&frame.payload);
    }
    Ok(())
}

/// Encode one complete frame, including the optional data length and payload.
pub fn encode_frame(frame: &Frame) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2 + 64 + 2 + frame.payload.len());
    encode_frame_into(frame, &mut out)?;
    Ok(out)
}

/// Decode the metadata block (without its length prefix) into a frame whose
/// payload is still empty.
fn decode_metadata(metadata: &[u8]) -> io::Result<Frame> {
    if metadata.len() < 4 {
        return Err(invalid("mux metadata is too short"));
    }
    let session_id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    let option = metadata[3];
    if !matches!(
        status,
        STATUS_NEW | STATUS_KEEP | STATUS_END | STATUS_KEEP_ALIVE
    ) {
        return Err(invalid(format!("unknown mux status {status}")));
    }
    if option & !(OPTION_DATA | OPTION_ERROR) != 0 {
        return Err(invalid("mux metadata has unknown option bits"));
    }
    let mut offset = 4;
    let target = if status == STATUS_NEW || offset < metadata.len() {
        Some(decode_target(metadata, &mut offset)?)
    } else {
        None
    };
    if status == STATUS_NEW && target.is_none() {
        return Err(invalid("new mux frame has no target"));
    }
    let global_id = if status == STATUS_NEW
        && target
            .as_ref()
            .is_some_and(|target| target.network == Network::Udp)
        && metadata.len().saturating_sub(offset) == 8
    {
        let mut global_id = [0u8; 8];
        global_id.copy_from_slice(&metadata[offset..]);
        offset = metadata.len();
        Some(global_id)
    } else {
        None
    };
    if offset != metadata.len() {
        return Err(invalid("mux metadata has trailing bytes"));
    }
    Ok(Frame {
        session_id,
        status,
        option,
        target,
        global_id,
        payload: Vec::new(),
    })
}

/// Decode exactly one complete frame from a byte slice.
pub fn decode_frame(bytes: &[u8]) -> io::Result<(Frame, usize)> {
    if bytes.len() < 2 {
        return Err(invalid("incomplete mux metadata length"));
    }
    let metadata_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if metadata_len == 0 || metadata_len > MAX_METADATA {
        return Err(invalid("invalid mux metadata length"));
    }
    let metadata_end = checked_end(2, metadata_len, bytes.len())?;
    let mut frame = decode_metadata(&bytes[2..metadata_end])?;
    let consumed = if frame.option & OPTION_DATA != 0 {
        let end = checked_end(metadata_end, 2, bytes.len())?;
        let payload_len =
            u16::from_be_bytes([bytes[metadata_end], bytes[metadata_end + 1]]) as usize;
        let payload_end = checked_end(end, payload_len, bytes.len())?;
        frame.payload = bytes[end..payload_end].to_vec();
        payload_end
    } else {
        metadata_end
    };
    Ok((frame, consumed))
}

/// Read one frame. The payload is read straight into the frame's own buffer.
///
/// Each call issues a few small reads, so callers reading many frames from a
/// raw transport should wrap it in a `BufReader` (the pools here do).
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Frame> {
    let metadata_len = reader.read_u16().await? as usize;
    if metadata_len == 0 || metadata_len > MAX_METADATA {
        return Err(invalid("invalid mux metadata length"));
    }
    let mut metadata = [0u8; MAX_METADATA];
    reader.read_exact(&mut metadata[..metadata_len]).await?;
    let mut frame = decode_metadata(&metadata[..metadata_len])?;
    if frame.option & OPTION_DATA != 0 {
        let payload_len = reader.read_u16().await? as usize;
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;
        frame.payload = payload;
    }
    Ok(frame)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> io::Result<()> {
    writer.write_all(&encode_frame(frame)?).await
}

/// Frames queued behind the current one are coalesced into one transport
/// write (and one flush) up to this many bytes.
const WRITE_COALESCE_LIMIT: usize = 64 * 1024;
/// Carrier read buffer: frame headers are tiny, so unbuffered reads would cost
/// several reads per frame.
const CARRIER_READ_BUFFER: usize = 64 * 1024;
/// How long one logical session may keep the shared carrier reader blocked
/// because its consumer is not draining. Mux.cool has no per-session flow
/// control, so a full session queue either stalls every session (Xray's
/// behaviour, indefinitely) or that session has to go; after this grace
/// period the stalled session is reset and the others keep flowing.
const SESSION_STALL_TIMEOUT: Duration = Duration::from_secs(5);
/// Xray's client worker closes a carrier that has had no sessions at one of
/// its 16-second checks.
const CLIENT_IDLE_CHECK: Duration = Duration::from_secs(16);
/// Most concurrent sessions accepted on one server carrier. Xray clients cap
/// a carrier at 1024 concurrent sessions.
const MAX_SERVER_SESSIONS: usize = 1024;
/// Frames buffered per logical session in each direction.
const SESSION_QUEUE: usize = 32;

/// Sole writer of a carrier: encodes queued frames into one reusable buffer,
/// coalescing whatever is already queued, then writes and flushes once.
async fn run_carrier_writer<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frames: &mut mpsc::Receiver<Frame>,
) -> io::Result<()> {
    let mut out = Vec::with_capacity(WRITE_COALESCE_LIMIT);
    while let Some(frame) = frames.recv().await {
        out.clear();
        encode_frame_into(&frame, &mut out)?;
        while out.len() < WRITE_COALESCE_LIMIT {
            match frames.try_recv() {
                Ok(frame) => encode_frame_into(&frame, &mut out)?,
                Err(_) => break,
            }
        }
        writer.write_all(&out).await?;
        writer.flush().await?;
        if out.capacity() > 4 * WRITE_COALESCE_LIMIT {
            out = Vec::with_capacity(WRITE_COALESCE_LIMIT);
        }
    }
    Ok(())
}

/// Hand `item` to a session queue. A full queue gets
/// [`SESSION_STALL_TIMEOUT`] to drain; `false` means the session is gone or
/// stalled and must be reset.
async fn deliver<T>(sender: &mpsc::Sender<T>, item: T) -> bool {
    match sender.try_send(item) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Closed(_)) => false,
        Err(mpsc::error::TrySendError::Full(item)) => matches!(
            tokio::time::timeout(SESSION_STALL_TIMEOUT, sender.send(item)).await,
            Ok(Ok(()))
        ),
    }
}

async fn strip_vless_response<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<()> {
    let version = reader.read_u8().await?;
    let addons = reader.read_u8().await? as usize;
    if version != 0 {
        return Err(invalid(format!(
            "unexpected VLESS response version {version}"
        )));
    }
    let mut discard = vec![0u8; addons];
    reader.read_exact(&mut discard).await?;
    Ok(())
}

/// Send one UDP datagram over a VLESS Mux/XUDP carrier and read its response.
///
/// This is intentionally one-shot: the runtime's existing UDP boundary is a
/// request/response datagram API. The wire codec still accepts session id zero,
/// global ids, and source targets exactly as Xray does, so a future persistent
/// association can reuse the same frames without changing compatibility.
pub async fn exchange_udp<S>(
    mut carrier: S,
    destination: Destination,
    payload: &[u8],
    global_id: [u8; 8],
) -> io::Result<(Option<Destination>, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if destination.network != Network::Udp {
        return Err(invalid("XUDP destination must be UDP"));
    }
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(invalid("XUDP payload must be 1..=65535 bytes"));
    }
    write_frame(
        &mut carrier,
        &Frame::udp_new(destination, payload.to_vec(), Some(global_id)),
    )
    .await?;
    carrier.flush().await?;
    strip_vless_response(&mut carrier).await?;
    let session_id = 0;
    loop {
        let frame = read_frame(&mut carrier).await?;
        if frame.session_id != session_id {
            return Err(invalid(format!(
                "XUDP response session {} does not match request {}",
                frame.session_id, session_id
            )));
        }
        match frame.status {
            STATUS_NEW | STATUS_KEEP | STATUS_KEEP_ALIVE
                if frame.option & OPTION_DATA != 0 && !frame.payload.is_empty() =>
            {
                return Ok((frame.target, frame.payload));
            }
            STATUS_END => return Err(invalid("XUDP carrier ended before a response")),
            STATUS_NEW | STATUS_KEEP | STATUS_KEEP_ALIVE => continue,
            other => return Err(invalid(format!("unexpected XUDP response status {other}"))),
        }
    }
}

#[derive(Debug)]
enum Downlink {
    Data(Vec<u8>),
    End,
}

struct ClientPoolState {
    closed: AtomicBool,
    next_id: AtomicU16,
    max_concurrency: usize,
    frames: mpsc::Sender<Frame>,
    sessions: Mutex<HashMap<u16, mpsc::Sender<Downlink>>>,
    /// Set once the carrier is closing; wakes the carrier reader and writer.
    shutdown: watch::Sender<bool>,
}

/// A bounded Xray Mux carrier pool.
///
/// One carrier is shared by up to `max_concurrency` logical TCP sessions. The
/// writer task is the sole owner of the carrier's write half, while the reader
/// task dispatches response frames to per-session channels. This preserves
/// frame ordering without putting a mutex around application I/O. A carrier
/// with no sessions at an idle check is closed, as Xray's client does.
pub struct ClientPool {
    state: Arc<ClientPoolState>,
}

impl ClientPool {
    pub fn new<S>(inner: S, max_concurrency: u16) -> Arc<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (frame_tx, mut frame_rx) = mpsc::channel(128);
        let (shutdown, _) = watch::channel(false);
        let state = Arc::new(ClientPoolState {
            closed: AtomicBool::new(false),
            next_id: AtomicU16::new(1),
            max_concurrency: if max_concurrency == 0 {
                u16::MAX as usize
            } else {
                max_concurrency as usize
            },
            frames: frame_tx,
            sessions: Mutex::new(HashMap::new()),
            shutdown,
        });
        let pool = Arc::new(Self {
            state: state.clone(),
        });
        let (reader, mut writer) = tokio::io::split(inner);

        let writer_state = state.clone();
        let mut writer_shutdown = state.shutdown.subscribe();
        tokio::spawn(async move {
            let closing = tokio::select! {
                _ = run_carrier_writer(&mut writer, &mut frame_rx) => false,
                _ = writer_shutdown.wait_for(|closing| *closing) => true,
            };
            close_client_sessions(&writer_state);
            if closing {
                // A graceful close (idle or reader EOF): let the peer see FIN.
                let _ = tokio::time::timeout(Duration::from_secs(2), writer.shutdown()).await;
            }
        });

        let reader_state = state.clone();
        let mut reader_shutdown = state.shutdown.subscribe();
        tokio::spawn(async move {
            let mut reader = BufReader::with_capacity(CARRIER_READ_BUFFER, reader);
            tokio::select! {
                _ = run_client_reader(&mut reader, &reader_state) => {}
                _ = reader_shutdown.wait_for(|closing| *closing) => {}
            }
            close_client_sessions(&reader_state);
        });

        let monitor_state = Arc::downgrade(&state);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(CLIENT_IDLE_CHECK);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(state) = monitor_state.upgrade() else {
                    return;
                };
                if state.closed.load(Ordering::Acquire) {
                    return;
                }
                let idle = state
                    .sessions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .is_empty();
                if idle {
                    close_client_sessions(&state);
                    return;
                }
            }
        });
        pool
    }

    pub fn open(&self, destination: Destination) -> io::Result<BoxStream> {
        // Reject a target the codec cannot encode here: failing inside the
        // shared writer would take every session on the carrier down with it.
        encode_frame(&Frame::new(1, destination.clone(), vec![0]))?;
        let (local, bridge) = tokio::io::duplex(64 * 1024);
        let (mut local_read, local_write) = tokio::io::split(local);
        let (events_tx, events_rx) = mpsc::channel(SESSION_QUEUE);
        let session_id = {
            let mut sessions = self
                .state
                .sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Checked under the lock: closing drains the map under the same
            // lock, so no session can be registered on a closed carrier.
            if self.state.closed.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mux carrier is closed",
                ));
            }
            if sessions.len() >= self.state.max_concurrency {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "mux carrier reached its concurrency limit",
                ));
            }
            let mut selected = 0;
            for _ in 0..u16::MAX {
                let candidate = self.state.next_id.fetch_add(1, Ordering::Relaxed);
                if candidate != 0 && !sessions.contains_key(&candidate) {
                    selected = candidate;
                    break;
                }
            }
            if selected == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "mux session id space is exhausted",
                ));
            }
            sessions.insert(selected, events_tx);
            selected
        };

        let state = self.state.clone();
        tokio::spawn(async move {
            let mut first = true;
            let mut buf = vec![0u8; 16 * 1024];
            let result = async {
                loop {
                    let n = local_read.read(&mut buf).await?;
                    if n == 0 {
                        state
                            .frames
                            .send(Frame::end(session_id, false))
                            .await
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::BrokenPipe, "mux writer closed")
                            })?;
                        return Ok::<(), io::Error>(());
                    }
                    let frame = if first {
                        first = false;
                        Frame::new(session_id, destination.clone(), buf[..n].to_vec())
                    } else {
                        Frame::keep(session_id, buf[..n].to_vec())
                    };
                    state.frames.send(frame).await.map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "mux writer closed")
                    })?;
                }
            }
            .await;
            if result.is_err() {
                if let Some(sender) = remove_client_session(&state, session_id) {
                    let _ = sender.try_send(Downlink::End);
                }
            }
        });

        let state = self.state.clone();
        tokio::spawn(async move {
            let mut local_write = local_write;
            let mut events = events_rx;
            let mut local_failed = false;
            while let Some(event) = events.recv().await {
                match event {
                    Downlink::Data(payload) => {
                        if local_write.write_all(&payload).await.is_err() {
                            local_failed = true;
                            break;
                        }
                    }
                    Downlink::End => break,
                }
            }
            let _ = local_write.shutdown().await;
            if remove_client_session(&state, session_id).is_some() && local_failed {
                // The application stopped reading: stop the server sending.
                let _ = state.frames.send(Frame::end(session_id, true)).await;
            }
        });
        Ok(boxed(bridge))
    }
}

async fn run_client_reader<R: AsyncRead + Unpin>(
    reader: &mut R,
    state: &ClientPoolState,
) -> io::Result<()> {
    strip_vless_response(reader).await?;
    loop {
        let frame = read_frame(reader).await?;
        match frame.status {
            STATUS_KEEP | STATUS_NEW | STATUS_KEEP_ALIVE => {
                if frame.option & OPTION_DATA == 0 {
                    continue;
                }
                let sender = state
                    .sessions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(&frame.session_id)
                    .cloned();
                match sender {
                    Some(sender) => {
                        if !deliver(&sender, Downlink::Data(frame.payload)).await {
                            // Gone or stalled: reset just this session.
                            remove_client_session(state, frame.session_id);
                            let _ = sender.try_send(Downlink::End);
                            let _ = state.frames.send(Frame::end(frame.session_id, true)).await;
                        }
                    }
                    None if frame.status != STATUS_KEEP_ALIVE => {
                        // Data for a session we no longer have: ask the server
                        // to stop, as Xray's client does.
                        let _ = state.frames.send(Frame::end(frame.session_id, true)).await;
                    }
                    None => {}
                }
            }
            STATUS_END => {
                if let Some(sender) = remove_client_session(state, frame.session_id) {
                    let _ = deliver(&sender, Downlink::End).await;
                }
            }
            other => return Err(invalid(format!("unexpected server mux status {other}"))),
        }
    }
}

fn remove_client_session(
    state: &ClientPoolState,
    session_id: u16,
) -> Option<mpsc::Sender<Downlink>> {
    state
        .sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&session_id)
}

/// Mark the carrier closed, end every session and stop the carrier tasks.
fn close_client_sessions(state: &ClientPoolState) {
    let sessions = {
        let mut sessions = state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closed.store(true, Ordering::Release);
        sessions
            .drain()
            .map(|(_, sender)| sender)
            .collect::<Vec<_>>()
    };
    for sender in sessions {
        let _ = sender.try_send(Downlink::End);
    }
    state.shutdown.send_replace(true);
}

/// Bridge one logical local stream through a VLESS Mux carrier.
pub async fn spawn_client<S>(inner: S, destination: Destination) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    ClientPool::new(inner, 1).open(destination)
}

/// Relay one server-side logical Mux session after the VLESS response header.
pub async fn relay_server<S, R>(outer: S, first: Frame, remote: R) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if first.status != STATUS_NEW || first.session_id == 0 {
        return Err(invalid("mux session must start with a nonzero NEW frame"));
    }
    if first.option & OPTION_DATA != 0 && first.payload.is_empty() {
        return Err(invalid("mux NEW data frame is empty"));
    }
    let (outer_read, mut outer_write) = tokio::io::split(outer);
    let mut outer_read = BufReader::with_capacity(CARRIER_READ_BUFFER, outer_read);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);
    if first.option & OPTION_DATA != 0 {
        remote_write.write_all(&first.payload).await?;
        remote_write.flush().await?;
    }
    let session_id = first.session_id;
    let uplink = async {
        loop {
            let frame = read_frame(&mut outer_read).await?;
            if frame.session_id != session_id {
                return Err(invalid("mux session id changed on one logical stream"));
            }
            match frame.status {
                STATUS_KEEP | STATUS_NEW => {
                    if frame.option & OPTION_DATA != 0 {
                        remote_write.write_all(&frame.payload).await?;
                        remote_write.flush().await?;
                    }
                }
                STATUS_END => {
                    remote_write.shutdown().await?;
                    return Ok::<(), io::Error>(());
                }
                other => return Err(invalid(format!("unexpected client mux status {other}"))),
            }
        }
    };
    let downlink = async {
        let mut buf = vec![0u8; 16 * 1024];
        let mut out = Vec::with_capacity(16 * 1024 + 16);
        loop {
            let n = remote_read.read(&mut buf).await?;
            out.clear();
            if n == 0 {
                encode_frame_into(&Frame::end(session_id, false), &mut out)?;
                outer_write.write_all(&out).await?;
                outer_write.shutdown().await?;
                return Ok::<(), io::Error>(());
            }
            encode_frame_into(&Frame::keep(session_id, buf[..n].to_vec()), &mut out)?;
            outer_write.write_all(&out).await?;
            outer_write.flush().await?;
        }
    };
    let _ = tokio::join!(uplink, downlink);
    Ok(())
}

#[derive(Debug)]
enum Uplink {
    Data(Vec<u8>),
    End,
}

type ServerSessions = Arc<Mutex<HashMap<u16, mpsc::Sender<Uplink>>>>;

/// Relay a pooled Mux carrier on the server side.
///
/// `first_remote` is the already-routed first logical TCP session. Further
/// NEW frames are passed to `route`, which must return a fresh remote stream.
/// Routing runs inside the new session's task, so a slow or failing dial
/// affects only that session: it is answered with an error END while the
/// carrier keeps serving the others. Each remote has an isolated writer
/// queue; only the carrier writer task emits frames, so multiple concurrent
/// sessions cannot interleave bytes. Every session task is owned by this call
/// and aborted when the carrier ends.
pub async fn relay_server_pool<F, Fut>(
    outer: ChainedMuxStream,
    first: Frame,
    first_remote: BoxStream,
    route: F,
) -> io::Result<()>
where
    F: Fn(Destination) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = io::Result<BoxStream>> + Send + 'static,
{
    if first.status != STATUS_NEW || first.session_id == 0 {
        return Err(invalid("mux pool must start with a nonzero NEW frame"));
    }
    let first_target = first
        .target
        .clone()
        .ok_or_else(|| invalid("mux pool first frame has no target"))?;
    if first_target.network != Network::Tcp {
        return Err(invalid("mux pool currently accepts TCP sessions only"));
    }

    let (frame_tx, mut frame_rx) = mpsc::channel(128);
    let sessions: ServerSessions = Arc::new(Mutex::new(HashMap::new()));
    let (outer_read, mut outer_write) = tokio::io::split(outer);
    let mut outer_read = BufReader::with_capacity(CARRIER_READ_BUFFER, outer_read);
    let writer_task =
        tokio::spawn(async move { run_carrier_writer(&mut outer_write, &mut frame_rx).await });
    let mut tasks = JoinSet::new();

    start_server_session(
        &mut tasks,
        first.session_id,
        async move { Ok(first_remote) },
        first.payload,
        frame_tx.clone(),
        sessions.clone(),
    )?;

    let result = loop {
        // Reap finished session tasks so the set does not grow unbounded on
        // a long-lived carrier.
        while tasks.try_join_next().is_some() {}
        let frame = match read_frame(&mut outer_read).await {
            Ok(frame) => frame,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break Ok(()),
            Err(error) => break Err(error),
        };
        if frame.session_id == 0 {
            break Err(invalid("mux session id must be nonzero"));
        }
        let reject = |session_id| {
            let frame_tx = frame_tx.clone();
            async move {
                frame_tx
                    .send(Frame::end(session_id, true))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux writer closed"))
            }
        };
        match frame.status {
            STATUS_NEW => {
                let Some(target) = frame.target.clone() else {
                    break Err(invalid("mux NEW frame has no target"));
                };
                let active = sessions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .len();
                if target.network != Network::Tcp || active >= MAX_SERVER_SESSIONS {
                    // Refuse this one session; the carrier stays up.
                    if let Err(error) = reject(frame.session_id).await {
                        break Err(error);
                    }
                    continue;
                }
                let route = route.clone();
                if let Err(error) = start_server_session(
                    &mut tasks,
                    frame.session_id,
                    async move { route(target).await },
                    frame.payload,
                    frame_tx.clone(),
                    sessions.clone(),
                ) {
                    break Err(error);
                }
            }
            STATUS_KEEP => {
                if frame.option & OPTION_DATA == 0 {
                    continue;
                }
                let sender = sessions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(&frame.session_id)
                    .cloned();
                let delivered = match sender {
                    Some(sender) => deliver(&sender, Uplink::Data(frame.payload)).await,
                    None => false,
                };
                if !delivered {
                    remove_server_session(&sessions, frame.session_id);
                    if let Err(error) = reject(frame.session_id).await {
                        break Err(error);
                    }
                }
            }
            STATUS_END => {
                if let Some(sender) = remove_server_session(&sessions, frame.session_id) {
                    let _ = deliver(&sender, Uplink::End).await;
                }
            }
            STATUS_KEEP_ALIVE => {
                // Keep-alive payloads are intentionally discarded, as in
                // Xray's worker. They are carrier liveness, not a stream.
            }
            other => break Err(invalid(format!("unknown mux status {other}"))),
        }
    };

    close_server_sessions(&sessions);
    writer_task.abort();
    tasks.abort_all();
    result
}

/// A stream whose first Mux frame has already been consumed by the VLESS
/// request parser. The wrapper is kept public so runtime code can preserve
/// those buffered bytes without exposing the internal framing codec.
pub type ChainedMuxStream = BoxStream;

fn start_server_session<D>(
    tasks: &mut JoinSet<()>,
    session_id: u16,
    dial: D,
    first_payload: Vec<u8>,
    frame_tx: mpsc::Sender<Frame>,
    sessions: ServerSessions,
) -> io::Result<()>
where
    D: std::future::Future<Output = io::Result<BoxStream>> + Send + 'static,
{
    let (uplink_tx, mut uplink_rx) = mpsc::channel(SESSION_QUEUE);
    {
        let mut active = sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if active.contains_key(&session_id) {
            return Err(invalid("duplicate mux session id"));
        }
        active.insert(session_id, uplink_tx);
    }
    tasks.spawn(async move {
        let remote = match dial.await {
            Ok(remote) => remote,
            Err(_) => {
                remove_server_session(&sessions, session_id);
                let _ = frame_tx.send(Frame::end(session_id, true)).await;
                return;
            }
        };
        let (mut remote_read, mut remote_write) = tokio::io::split(remote);
        let uplink = async {
            if !first_payload.is_empty() {
                remote_write.write_all(&first_payload).await?;
                remote_write.flush().await?;
            }
            while let Some(command) = uplink_rx.recv().await {
                match command {
                    Uplink::Data(payload) => {
                        remote_write.write_all(&payload).await?;
                        remote_write.flush().await?;
                    }
                    Uplink::End => {
                        remote_write.shutdown().await?;
                        break;
                    }
                }
            }
            Ok::<(), io::Error>(())
        };
        let downlink = async {
            let mut buffer = vec![0u8; 16 * 1024];
            loop {
                let size = match remote_read.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(size) => size,
                };
                if frame_tx
                    .send(Frame::keep(session_id, buffer[..size].to_vec()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = frame_tx.send(Frame::end(session_id, false)).await;
            // END closes the whole logical session in mux.cool; dropping the
            // queue sender here ends the uplink half too.
            remove_server_session(&sessions, session_id);
        };
        let (_, ()) = tokio::join!(uplink, downlink);
        remove_server_session(&sessions, session_id);
    });
    Ok(())
}

fn remove_server_session(
    sessions: &ServerSessions,
    session_id: u16,
) -> Option<mpsc::Sender<Uplink>> {
    sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&session_id)
}

fn close_server_sessions(sessions: &ServerSessions) {
    let active = sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .drain()
        .map(|(_, sender)| sender)
        .collect::<Vec<_>>();
    for sender in active {
        let _ = sender.try_send(Uplink::End);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn destination() -> Destination {
        Destination::tcp(zero_core::Address::domain("example.com"), 443)
    }

    #[test]
    fn stream_frame_roundtrips_target_and_payload() {
        let original = Frame::new(7, destination(), b"hello".to_vec());
        let bytes = encode_frame(&original).unwrap();
        let (decoded, consumed) = decode_frame(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, original);
    }

    #[test]
    fn keep_and_end_frames_have_no_implicit_target() {
        for frame in [Frame::keep(7, b"data".to_vec()), Frame::end(7, false)] {
            let bytes = encode_frame(&frame).unwrap();
            let (decoded, consumed) = decode_frame(&bytes).unwrap();
            assert_eq!(consumed, bytes.len());
            assert_eq!(decoded, frame);
        }
    }

    #[test]
    fn udp_new_roundtrips_global_id() {
        let target = Destination::udp(zero_core::Address::domain("resolver.example"), 53);
        let frame = Frame::udp_new(target, b"query".to_vec(), Some([1, 2, 3, 4, 5, 6, 7, 8]));
        let bytes = encode_frame(&frame).unwrap();
        let (decoded, consumed) = decode_frame(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, frame);
        assert_eq!(decoded.session_id, 0);
        assert_eq!(decoded.global_id, Some([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn rejects_unknown_options_and_oversized_metadata() {
        let mut bytes = encode_frame(&Frame::end(1, false)).unwrap();
        bytes[2 + 3] = 0x80;
        assert!(decode_frame(&bytes).is_err());
        bytes[2 + 3] = 0;
        bytes[2 + 2] = 0x7f;
        assert!(decode_frame(&bytes).is_err());
        let domain = "a".repeat(255);
        let frame = Frame::new(
            1,
            Destination::tcp(zero_core::Address::domain(&domain), 443),
            vec![],
        );
        assert!(encode_frame(&frame).is_err() || encode_frame(&frame).unwrap().len() <= 516);
    }

    #[tokio::test]
    async fn client_bridge_strips_vless_response_and_roundtrips_payload() {
        let (client_carrier, mut server_carrier) = tokio::io::duplex(64 * 1024);
        let mut local = spawn_client(client_carrier, destination()).await.unwrap();
        let server = tokio::spawn(async move {
            let first = read_frame(&mut server_carrier).await.unwrap();
            assert_eq!(first.status, STATUS_NEW);
            assert_eq!(first.target, Some(destination()));
            assert_eq!(first.payload, b"ping");
            server_carrier.write_all(&[0, 0]).await.unwrap();
            write_frame(&mut server_carrier, &Frame::keep(1, b"pong".to_vec()))
                .await
                .unwrap();
            write_frame(&mut server_carrier, &Frame::end(1, false))
                .await
                .unwrap();
            server_carrier.flush().await.unwrap();
        });

        local.write_all(b"ping").await.unwrap();
        local.flush().await.unwrap();
        let mut response = [0u8; 4];
        local.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn exchange_udp_roundtrips_xudp_source_and_payload() {
        let (client_carrier, mut server_carrier) = tokio::io::duplex(64 * 1024);
        let target = Destination::udp(zero_core::Address::domain("example.com"), 443);
        let source = Destination::udp(
            zero_core::Address::from(std::net::Ipv4Addr::new(192, 0, 2, 9)),
            5353,
        );
        let server_target = target.clone();
        let server_source = source.clone();
        let server = tokio::spawn(async move {
            let first = read_frame(&mut server_carrier).await.unwrap();
            assert_eq!(first.status, STATUS_NEW);
            assert_eq!(first.session_id, 0);
            assert_eq!(first.target, Some(server_target));
            assert_eq!(first.global_id, Some([9, 8, 7, 6, 5, 4, 3, 2]));
            assert_eq!(first.payload, b"request");
            server_carrier.write_all(&[0, 0]).await.unwrap();
            write_frame(
                &mut server_carrier,
                &Frame::udp_keep(first.session_id, Some(server_source), b"response".to_vec()),
            )
            .await
            .unwrap();
            server_carrier.flush().await.unwrap();
        });

        let result = exchange_udp(client_carrier, target, b"request", [9, 8, 7, 6, 5, 4, 3, 2])
            .await
            .unwrap();
        assert_eq!(result, (Some(source), b"response".to_vec()));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn client_pool_routes_two_logical_sessions_without_interleaving() {
        let (client_carrier, mut server_carrier) = tokio::io::duplex(64 * 1024);
        let pool = ClientPool::new(client_carrier, 2);
        let mut first = pool.open(destination()).unwrap();
        let mut second = pool.open(destination()).unwrap();
        let server = tokio::spawn(async move {
            server_carrier.write_all(&[0, 0]).await.unwrap();
            let a = read_frame(&mut server_carrier).await.unwrap();
            let b = read_frame(&mut server_carrier).await.unwrap();
            assert_ne!(a.session_id, b.session_id);
            assert_eq!(a.status, STATUS_NEW);
            assert_eq!(b.status, STATUS_NEW);
            assert_eq!(a.payload, b"one");
            assert_eq!(b.payload, b"two");
            write_frame(
                &mut server_carrier,
                &Frame::keep(a.session_id, b"first".to_vec()),
            )
            .await
            .unwrap();
            write_frame(
                &mut server_carrier,
                &Frame::keep(b.session_id, b"second".to_vec()),
            )
            .await
            .unwrap();
            write_frame(&mut server_carrier, &Frame::end(a.session_id, false))
                .await
                .unwrap();
            write_frame(&mut server_carrier, &Frame::end(b.session_id, false))
                .await
                .unwrap();
        });
        first.write_all(b"one").await.unwrap();
        second.write_all(b"two").await.unwrap();
        let mut first_response = [0u8; 5];
        let mut second_response = [0u8; 6];
        first.read_exact(&mut first_response).await.unwrap();
        second.read_exact(&mut second_response).await.unwrap();
        assert_eq!(&first_response, b"first");
        assert_eq!(&second_response, b"second");
        server.await.unwrap();
    }

    /// Regression: the server pool awaited `route()` inside the carrier read
    /// loop and propagated its error with `?`, so one unreachable target
    /// stalled and then tore down every session on the carrier.
    #[tokio::test]
    async fn a_failed_dial_resets_only_that_session() {
        let (mut client, server_side) = tokio::io::duplex(64 * 1024);
        let (first_remote, mut first_peer) = tokio::io::duplex(64 * 1024);
        let first = Frame::new(1, destination(), b"a".to_vec());
        let route = |_target: Destination| async {
            Err::<BoxStream, _>(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
        };
        let pool = tokio::spawn(relay_server_pool(
            boxed(server_side),
            first,
            boxed(first_remote),
            route,
        ));
        write_frame(&mut client, &Frame::new(2, destination(), b"x".to_vec()))
            .await
            .unwrap();
        let reset = read_frame(&mut client).await.unwrap();
        assert_eq!((reset.session_id, reset.status), (2, STATUS_END));
        assert_ne!(reset.option & OPTION_ERROR, 0);

        write_frame(&mut client, &Frame::keep(1, b"b".to_vec()))
            .await
            .unwrap();
        let mut got = [0u8; 2];
        first_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ab");
        first_peer.write_all(b"reply").await.unwrap();
        let reply = read_frame(&mut client).await.unwrap();
        assert_eq!(
            (reply.session_id, reply.payload.as_slice()),
            (1, &b"reply"[..])
        );
        drop(client);
        pool.await.unwrap().unwrap();
    }

    /// Regression: one session whose consumer stopped reading blocked the
    /// carrier reader forever, freezing every other session on the carrier.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_session_is_reset_without_freezing_the_others() {
        let (client_carrier, server_carrier) = tokio::io::duplex(64 * 1024);
        let pool = ClientPool::new(client_carrier, 2);
        let mut stalled = pool.open(destination()).unwrap();
        let mut healthy = pool.open(destination()).unwrap();
        stalled.write_all(b"one").await.unwrap();
        healthy.write_all(b"two").await.unwrap();

        let (mut server_read, mut server_write) = tokio::io::split(server_carrier);
        let a = read_frame(&mut server_read).await.unwrap();
        let b = read_frame(&mut server_read).await.unwrap();
        let (stalled_id, healthy_id) = if a.payload == b"one" {
            (a.session_id, b.session_id)
        } else {
            (b.session_id, a.session_id)
        };
        // Keep draining the carrier so the client writer never blocks.
        let collector = tokio::spawn(async move {
            while let Ok(frame) = read_frame(&mut server_read).await {
                if frame.status == STATUS_END && frame.session_id == stalled_id {
                    return frame.option & OPTION_ERROR != 0;
                }
            }
            false
        });
        let writer = tokio::spawn(async move {
            server_write.write_all(&[0, 0]).await.unwrap();
            for _ in 0..200 {
                write_frame(&mut server_write, &Frame::keep(stalled_id, vec![7; 8192]))
                    .await
                    .unwrap();
            }
            write_frame(
                &mut server_write,
                &Frame::keep(healthy_id, b"hello".to_vec()),
            )
            .await
            .unwrap();
            server_write
        });
        let mut got = [0u8; 5];
        healthy.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        assert!(collector.await.unwrap(), "the stalled session is reset");
        drop((stalled, healthy, pool, writer));
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_client_carrier_is_closed() {
        let (client_carrier, mut server_carrier) = tokio::io::duplex(64 * 1024);
        let pool = ClientPool::new(client_carrier, 0);
        tokio::time::sleep(CLIENT_IDLE_CHECK * 2).await;
        let mut rest = Vec::new();
        server_carrier.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        let error = pool.open(destination()).err().expect("closed pool");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
}
