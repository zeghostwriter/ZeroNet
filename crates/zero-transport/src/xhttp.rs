//! XHTTP stream-one and split carriers over HTTP/1.1 and HTTP/2.
//!
//! The carrier uses one persistent chunked POST for the uplink and consumes a
//! chunked response for the downlink. It is intentionally independent of
//! VLESS/Trojan so either protocol can ride it. HTTP/2 and HTTP/3 need their
//! HTTP/2 uses native DATA frames and flow-control credit; HTTP/3 remains a
//! separate QUIC carrier.

use bytes::{Buf, Bytes, BytesMut};
use http::Request;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{oneshot, Mutex};
use zero_core::BoxStream;

use crate::ws::WsConfig;
use crate::xhttp_request::{build_request, RequestKind, XhttpRequest};

const MAX_RESPONSE_HEAD: usize = 64 * 1024;
const MAX_CHUNK_LINE: usize = 128;
const MAX_PACKET_POST_BYTES: usize = 1_000_000;
const MAX_BUFFERED_PACKET_POSTS: usize = 30;
/// Largest packet-up upload. Xray's default `scMaxEachPostBytes` is
/// 1,000,000; a POST gathers what arrives during the posting interval, so a
/// busy upload reaches this size while a quiet one stays small.
const PACKET_UPLOAD_BUFFER: usize = MAX_PACKET_POST_BYTES;
/// Capacity an idle session's upload buffer shrinks back to.
const PACKET_IDLE_BUFFER: usize = 64 * 1024;
/// Keep the connection-level credit at the same scale as the per-stream
/// credit. h2's default connection window is only 65,535 bytes, which lets a
/// busy logical flow starve unrelated XHTTP streams on the same connection.
const H2_FLOW_CONTROL_WINDOW: u32 = 4 * 1024 * 1024;

/// Shared rendezvous for XHTTP stream-up's independent upload and download
/// connections. The HTTP listener creates one instance and gives it to every
/// accepted XHTTP connection. A logical session is only exposed to the
/// protocol layer after both legs have arrived.
#[derive(Default)]
pub struct SplitHub {
    sessions: Mutex<HashMap<String, PendingSession>>,
}

struct PendingSession {
    first_leg: BoxStream,
    get_ready: Option<oneshot::Sender<BoxStream>>,
    upload_done: Option<oneshot::Sender<()>>,
}

impl SplitHub {
    pub fn new() -> Self {
        Self::default()
    }
}

pub type SharedSplitHub = Arc<SplitHub>;

pub type PacketDialer = Arc<dyn Fn() -> PacketDialFuture + Send + Sync>;
pub type PacketDialFuture = Pin<Box<dyn Future<Output = Result<BoxStream, String>> + Send>>;

#[derive(Default)]
pub struct PacketHub {
    sessions: Mutex<HashMap<String, PacketSession>>,
}

struct PacketSession {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    next_sequence: u64,
    pending: BTreeMap<u64, Vec<u8>>,
}

pub type SharedPacketHub = Arc<PacketHub>;

impl PacketHub {
    pub fn new() -> Self {
        Self::default()
    }

    async fn open(&self, session: String) -> Result<tokio::sync::mpsc::Receiver<Vec<u8>>, String> {
        let (sender, receiver) = tokio::sync::mpsc::channel(32);
        let mut sessions = self.sessions.lock().await;
        if sessions.contains_key(&session) {
            return Err("XHTTP packet-up session already exists".into());
        }
        sessions.insert(
            session,
            PacketSession {
                sender,
                next_sequence: 0,
                pending: BTreeMap::new(),
            },
        );
        Ok(receiver)
    }

    async fn deliver(&self, session: &str, sequence: u64, payload: Vec<u8>) -> Result<(), String> {
        let (sender, ready) = {
            let mut sessions = self.sessions.lock().await;
            let state = sessions
                .get_mut(session)
                .ok_or_else(|| "XHTTP packet-up session is not open".to_string())?;
            if sequence < state.next_sequence {
                return Err("XHTTP packet-up sequence was already delivered".into());
            }
            if state.pending.contains_key(&sequence) {
                return Err("XHTTP packet-up sequence was duplicated".into());
            }
            if sequence.saturating_sub(state.next_sequence) > MAX_BUFFERED_PACKET_POSTS as u64
                || (state.pending.len() >= MAX_BUFFERED_PACKET_POSTS
                    && sequence != state.next_sequence)
            {
                return Err("XHTTP packet-up sequence gap exceeds the buffer limit".into());
            }
            state.pending.insert(sequence, payload);
            let mut ready = Vec::new();
            while let Some(payload) = state.pending.remove(&state.next_sequence) {
                ready.push(payload);
                state.next_sequence = state.next_sequence.wrapping_add(1);
            }
            (state.sender.clone(), ready)
        };
        for payload in ready {
            sender
                .send(payload)
                .await
                .map_err(|_| "XHTTP packet-up download leg is closed".to_string())?;
        }
        Ok(())
    }
}

/// Open XHTTP packet-up over a persistent bodyless download GET. Each write
/// from the logical stream becomes one fixed-length POST on a fresh protected
/// upload connection, matching Xray's packet-up resource ownership model.
pub async fn connect_packet_up(
    mut download: BoxStream,
    download_config: &WsConfig,
    upload_config: &WsConfig,
    dialer: PacketDialer,
) -> Result<BoxStream, String> {
    let session = download_config.xhttp.new_session_id();
    write_request(
        &mut download,
        download_config,
        RequestKind::StreamDown,
        Some(&session),
    )
    .await?;

    // Wait for the download leg's response head before returning.
    //
    // The server registers the session while it handles this GET and only
    // answers afterwards, so a head in hand is proof the session exists. Doing
    // this asynchronously inside the exchange — as this used to — let the
    // first POST overtake the GET: the server had no session to deliver it to,
    // rejected it, and the flow's uplink died silently while its downlink kept
    // the stream open, so the caller waited forever instead of failing. It
    // only lost that race under load, which is the worst way to lose one.
    let head = read_head(&mut download).await?;
    let status = response_status(&head)
        .ok_or_else(|| "XHTTP packet-up download response has no status".to_string())?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "XHTTP packet-up download leg rejected with status {status}"
        ));
    }
    let (app, worker) = tokio::io::duplex(64 * 1024);
    let download_config = download_config.clone();
    let upload_config = upload_config.clone();
    tokio::spawn(run_packet_exchange(
        download,
        worker,
        download_config,
        upload_config,
        session,
        dialer,
        head,
    ));
    Ok(zero_core::boxed(app))
}

/// The numeric status from a response head, if it has a valid status line.
fn response_status(head: &str) -> Option<u16> {
    head.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

/// Open XHTTP packet-up over HTTP/2. The download leg is one persistent GET;
/// each uplink read becomes a fixed-length POST on the same connection, as
/// Xray multiplexes them.
///
/// `upload` is a separate connection for the uploads when the download comes
/// from another server (`downloadSettings`); otherwise the uploads share the
/// download's connection.
pub async fn connect_packet_up_h2(
    download: BoxStream,
    download_config: &WsConfig,
    upload_config: &WsConfig,
    upload: Option<BoxStream>,
) -> Result<BoxStream, String> {
    let session = download_config.xhttp.new_session_id();
    let (mut sender, connection) = h2::client::Builder::new()
        .initial_window_size(H2_FLOW_CONTROL_WINDOW)
        .initial_connection_window_size(H2_FLOW_CONTROL_WINDOW)
        .handshake::<_, Bytes>(download)
        .await
        .map_err(|error| format!("XHTTP H2 packet download handshake: {error}"))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "XHTTP H2 packet download connection ended");
        }
    });
    sender = sender
        .ready()
        .await
        .map_err(|error| format!("XHTTP H2 packet download capacity: {error}"))?;
    let request = h2_request(download_config, RequestKind::StreamDown, Some(&session))?;
    let (response, _send) = sender
        .send_request(request, true)
        .map_err(|error| format!("XHTTP H2 packet download request: {error}"))?;

    // Await the response before returning: the server opens the packet
    // session while handling this GET and answers only afterwards, so the
    // response is what makes it safe for the first POST to go out. See the
    // HTTP/1.1 path for the failure this avoids.
    let response = response
        .await
        .map_err(|error| format!("XHTTP H2 packet download response: {error}"))?;
    if response.status() != http::StatusCode::OK
        && response.status() != http::StatusCode::PARTIAL_CONTENT
    {
        return Err(format!(
            "XHTTP H2 packet download leg rejected with status {}",
            response.status()
        ));
    }

    let upload_sender = match upload {
        None => sender,
        Some(upload) => {
            let (upload_sender, connection) = h2::client::Builder::new()
                .initial_window_size(H2_FLOW_CONTROL_WINDOW)
                .initial_connection_window_size(H2_FLOW_CONTROL_WINDOW)
                .handshake::<_, Bytes>(upload)
                .await
                .map_err(|error| format!("XHTTP H2 packet upload handshake: {error}"))?;
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    tracing::debug!(%error, "XHTTP H2 packet upload connection ended");
                }
            });
            upload_sender
        }
    };
    let (app, worker) = tokio::io::duplex(128 * 1024);
    let upload_config = upload_config.clone();
    tokio::spawn(run_packet_exchange_h2(
        response.into_body(),
        worker,
        upload_config,
        session,
        upload_sender,
    ));
    Ok(zero_core::boxed(app))
}

async fn run_packet_exchange_h2(
    body: h2::RecvStream,
    app: tokio::io::DuplexStream,
    upload_config: WsConfig,
    session: String,
    sender: h2::client::SendRequest<Bytes>,
) {
    let (mut app_read, app_write) = tokio::io::split(app);
    let download = h2_download_body(body, app_write);
    let upload = async move {
        let mut sequence = 0u64;
        let mut buffer = Vec::new();
        let mut last = None;
        let scheme = if upload_config.secure {
            "https"
        } else {
            "http"
        };
        // Responses are collected off the send path, as Xray does: the next
        // POST goes out once this one is written, and any non-200 ends the
        // stream.
        let (failed_tx, mut failed_rx) = tokio::sync::mpsc::channel::<String>(1);
        loop {
            let more = tokio::select! {
                more = next_packet(&mut app_read, &mut buffer, &upload_config, &mut last) => more?,
                Some(error) = failed_rx.recv() => return Err(error),
            };
            if !more {
                return Ok::<(), String>(());
            }
            let n = buffer.len();
            let request = xhttp_request(
                &upload_config,
                RequestKind::Packet(sequence),
                Some(&session),
                Some(&buffer[..n]),
            );
            let body_len = if request.body { n } else { 0 };
            let request = http_request(&upload_config, &request, Some(body_len), scheme)?;
            let mut sender = sender
                .clone()
                .ready()
                .await
                .map_err(|error| format!("XHTTP H2 packet upload capacity: {error}"))?;
            let (response, mut send) = sender
                .send_request(request, body_len == 0)
                .map_err(|error| format!("XHTTP H2 packet upload request: {error}"))?;
            if body_len > 0 {
                send.send_data(Bytes::copy_from_slice(&buffer[..n]), true)
                    .map_err(|error| format!("XHTTP H2 packet upload body: {error}"))?;
            }
            let failed = failed_tx.clone();
            tokio::spawn(async move {
                let outcome = async {
                    let response = response
                        .await
                        .map_err(|error| format!("XHTTP H2 packet upload response: {error}"))?;
                    if response.status() != http::StatusCode::OK {
                        return Err(format!(
                            "XHTTP H2 packet upload unexpected status {}",
                            response.status()
                        ));
                    }
                    let mut body = response.into_body();
                    while let Some(result) = body.data().await {
                        let chunk = result.map_err(|error| {
                            format!("XHTTP H2 packet upload response body: {error}")
                        })?;
                        let _ = body.flow_control().release_capacity(chunk.len());
                    }
                    Ok(())
                }
                .await;
                if let Err(error) = outcome {
                    let _ = failed.try_send(error);
                }
            });
            sequence = sequence.wrapping_add(1);
        }
    };
    // As on the HTTP/1.1 path: a failed uplink has to close this logical
    // stream, or the caller waits on a downlink that can never complete the
    // exchange.
    crate::relay::drive_both("XHTTP H2 packet", upload, download).await;
}

/// Accept XHTTP packet-up's persistent download leg or one fixed-length
/// upload POST. Upload requests are consumed entirely by this function and
/// return `Ok(None)`; the GET leg returns the logical protocol stream.
pub async fn accept_packet_up(
    mut stream: BoxStream,
    config: &WsConfig,
    hub: &SharedPacketHub,
) -> Result<Option<BoxStream>, String> {
    let head = read_request_head(&mut stream).await?;
    let (method, target, chunked) = parse_request(&head)?;
    if method == "GET" && !chunked {
        let session = packet_download_session_from_path(target, &config.path)
            .ok_or_else(|| "XHTTP packet-up GET has no valid session path".to_string())?;
        let (app, worker) = tokio::io::duplex(64 * 1024);
        let packet_rx = hub.open(session.clone()).await?;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n",
            )
            .await
            .map_err(|error| format!("XHTTP packet download response: {error}"))?;
        stream
            .flush()
            .await
            .map_err(|error| format!("XHTTP packet download flush: {error}"))?;
        let hub = Arc::clone(hub);
        tokio::spawn(async move {
            run_packet_server_exchange(packet_rx, worker, stream).await;
            hub.sessions.lock().await.remove(&session);
        });
        Ok(Some(zero_core::boxed(app)))
    } else if method == "POST" && !chunked {
        let session = packet_session_from_path(target, &config.path)
            .ok_or_else(|| "XHTTP packet-up POST has no valid session path".to_string())?;
        let length = content_length(&head)
            .ok_or_else(|| "XHTTP packet-up POST requires Content-Length".to_string())?;
        if length > MAX_PACKET_POST_BYTES {
            return Err("XHTTP packet-up POST exceeds the 1 MiB limit".into());
        }
        let mut payload = vec![0u8; length];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|error| format!("XHTTP packet body: {error}"))?;
        let sequence = packet_sequence_from_path(target, &config.path)
            .ok_or_else(|| "XHTTP packet-up POST has no valid sequence".to_string())?;
        hub.deliver(&session, sequence, payload).await?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|error| format!("XHTTP packet response: {error}"))?;
        stream
            .flush()
            .await
            .map_err(|error| format!("XHTTP packet response flush: {error}"))?;
        Ok(None)
    } else {
        Err("XHTTP packet-up request must be a bodyless GET or fixed-length POST".into())
    }
}

/// Accept one H2 packet-up GET or fixed-length POST. The GET exposes the
/// logical stream; POST bodies are delivered to its packet channel.
pub async fn accept_packet_up_h2(
    stream: BoxStream,
    config: &WsConfig,
    hub: &SharedPacketHub,
) -> Result<Option<BoxStream>, String> {
    Ok(
        accept_h2_multi(stream, config, H2Server::PacketUp(Arc::clone(hub)))
            .await?
            .map(|(first, _more)| first),
    )
}

async fn h2_packet_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    config: &WsConfig,
    hub: &SharedPacketHub,
) -> Result<Option<BoxStream>, String> {
    let path = request.uri().path().to_owned();
    let is_get = request.method() == http::Method::GET;
    let is_post = request.method() == http::Method::POST;
    if !is_get && !is_post {
        return Err("XHTTP H2 packet request must be GET or POST".into());
    }
    let session = packet_session_from_path(&path, &config.path)
        .ok_or_else(|| "XHTTP H2 packet request has no valid session path".to_string())?;
    if is_get {
        if packet_sequence_from_path(&path, &config.path).is_some() {
            return Err("XHTTP H2 packet GET must not include a sequence".into());
        }
        if !request.body().is_end_stream() {
            return Err("XHTTP H2 packet GET must not have a request body".into());
        }
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(())
            .map_err(|error| format!("XHTTP H2 packet download response: {error}"))?;
        let send = respond
            .send_response(response, false)
            .map_err(|error| format!("XHTTP H2 packet download response: {error}"))?;
        let packet_rx = hub.open(session.clone()).await?;
        let (app, worker) = tokio::io::duplex(128 * 1024);
        let hub = Arc::clone(hub);
        tokio::spawn(async move {
            run_packet_server_exchange_h2(packet_rx, worker, send).await;
            hub.sessions.lock().await.remove(&session);
        });
        Ok(Some(zero_core::boxed(app)))
    } else {
        let declared_length = request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| "XHTTP H2 packet POST requires Content-Length".to_string())?;
        if declared_length > MAX_PACKET_POST_BYTES {
            return Err("XHTTP H2 packet POST exceeds the 1 MiB limit".into());
        }
        let mut body = request.into_body();
        let mut payload = Vec::new();
        while let Some(result) = body.data().await {
            let chunk = result.map_err(|error| format!("XHTTP H2 packet upload body: {error}"))?;
            let _ = body.flow_control().release_capacity(chunk.len());
            payload.extend_from_slice(&chunk);
            if payload.len() > declared_length || payload.len() > MAX_PACKET_POST_BYTES {
                return Err("XHTTP H2 packet upload exceeds the 1 MiB limit".into());
            }
        }
        if payload.len() != declared_length {
            return Err("XHTTP H2 packet POST body length does not match Content-Length".into());
        }
        let sequence = packet_sequence_from_path(&path, &config.path)
            .ok_or_else(|| "XHTTP H2 packet POST has no valid sequence".to_string())?;
        hub.deliver(&session, sequence, payload).await?;
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("content-length", "0")
            .body(())
            .map_err(|error| format!("XHTTP H2 packet upload response: {error}"))?;
        let _ = respond
            .send_response(response, true)
            .map_err(|error| format!("XHTTP H2 packet upload response: {error}"))?;
        Ok(None)
    }
}

async fn run_packet_server_exchange_h2(
    mut packets: tokio::sync::mpsc::Receiver<Vec<u8>>,
    app: tokio::io::DuplexStream,
    mut send: h2::SendStream<Bytes>,
) {
    let (mut app_read, mut app_write) = tokio::io::split(app);
    let uplink = async {
        while let Some(packet) = packets.recv().await {
            app_write
                .write_all(&packet)
                .await
                .map_err(|error| format!("XHTTP H2 packet server app write: {error}"))?;
        }
        app_write
            .shutdown()
            .await
            .map_err(|error| format!("XHTTP H2 packet server app close: {error}"))
    };
    let downlink = h2_upload(&mut app_read, &mut send);
    crate::relay::drive_both("XHTTP H2 packet server", uplink, downlink).await;
}

async fn run_packet_exchange(
    download_stream: BoxStream,
    app: tokio::io::DuplexStream,
    _download_config: WsConfig,
    upload_config: WsConfig,
    session: String,
    dialer: PacketDialer,
    download_head: String,
) {
    let (mut app_read, app_write) = tokio::io::split(app);
    let (download_read, _) = tokio::io::split(download_stream);
    let download_task = download_body(download_read, app_write, &download_head);
    let upload_task = async move {
        let mut sequence = 0u64;
        let mut buffer = Vec::new();
        let mut last = None;
        loop {
            if !next_packet(&mut app_read, &mut buffer, &upload_config, &mut last).await? {
                return Ok::<(), String>(());
            }
            let n = buffer.len();
            let mut upload = dialer().await?;
            write_packet_request(
                &mut upload,
                &upload_config,
                &session,
                sequence,
                &buffer[..n],
            )
            .await?;
            let head = read_head(&mut upload).await?;
            if response_status(&head) != Some(200) {
                return Err(format!(
                    "XHTTP packet upload rejected: {}",
                    head.lines().next().unwrap_or_default()
                ));
            }
            upload
                .shutdown()
                .await
                .map_err(|error| format!("XHTTP packet upload close: {error}"))?;
            sequence = sequence.wrapping_add(1);
        }
    };
    // A dead uplink means this logical stream can no longer carry the
    // session, and waiting for the downlink to notice keeps the app-side
    // duplex open indefinitely: `drive_both` tears everything down on the
    // first error, and treats a clean finish of either side as a half-close.
    crate::relay::drive_both("XHTTP packet", upload_task, download_task).await;
}

async fn run_packet_server_exchange(
    mut packets: tokio::sync::mpsc::Receiver<Vec<u8>>,
    worker: tokio::io::DuplexStream,
    mut download: BoxStream,
) {
    let (mut app_read, mut app_write) = tokio::io::split(worker);
    let uplink = async move {
        while let Some(packet) = packets.recv().await {
            app_write
                .write_all(&packet)
                .await
                .map_err(|error| format!("XHTTP packet server write: {error}"))?;
        }
        app_write
            .shutdown()
            .await
            .map_err(|error| format!("XHTTP packet server close: {error}"))
    };
    let downlink = upload_response(&mut app_read, &mut download);
    crate::relay::drive_both("XHTTP packet server", uplink, downlink).await;
}

/// Open XHTTP stream-up over two already protected HTTP/1.1 sockets.
///
/// The download request is issued first, matching Xray's server-first
/// behavior. Both requests carry the same session in the path; the returned
/// stream is the logical protocol byte stream.
pub async fn connect_stream_up(
    mut upload: BoxStream,
    mut download: BoxStream,
    upload_config: &WsConfig,
    download_config: &WsConfig,
) -> Result<BoxStream, String> {
    let session = upload_config.xhttp.new_session_id();
    write_request(
        &mut download,
        download_config,
        RequestKind::StreamDown,
        Some(&session),
    )
    .await?;
    write_request(
        &mut upload,
        upload_config,
        RequestKind::StreamUp,
        Some(&session),
    )
    .await?;

    let (app, worker) = tokio::io::duplex(64 * 1024);
    tokio::spawn(run_split_exchange(upload, download, worker));
    Ok(zero_core::boxed(app))
}

/// Accept one leg of XHTTP stream-up. The upload leg returns `Ok(None)` after
/// it has been paired and is owned by the download leg's worker; the download
/// leg returns the single logical stream that the protocol handler should use.
pub async fn accept_stream_up(
    mut stream: BoxStream,
    config: &WsConfig,
    hub: &SharedSplitHub,
) -> Result<Option<BoxStream>, String> {
    let head = read_request_head(&mut stream).await?;
    let (method, target, chunked) = parse_request(&head)?;
    let session = session_from_path(target, &config.path)
        .ok_or_else(|| "XHTTP split request has no valid session path".to_string())?;

    let kind = if method == "GET" && !chunked {
        H2LegKind::Download
    } else if method == "POST" && chunked {
        H2LegKind::Upload
    } else {
        return Err("XHTTP split request must be a bodyless GET or chunked POST".into());
    };
    split_rendezvous(hub, kind, session, stream, pair_server_legs, "XHTTP").await
}

/// Pair the two legs of a stream-up session through the shared hub.
///
/// Whichever leg arrives first parks in the hub for up to 30 s; the second
/// one pairs them with `pair(upload, download)`. The download leg's call
/// returns the logical stream, the upload leg's returns `Ok(None)`.
///
/// A second leg of the *same* kind for a parked session is refused without
/// disturbing the parked one. It used to evict it: the parked leg was
/// removed, dropped, and its waiter failed, so one stray duplicate request
/// killed a session that was otherwise about to pair.
async fn split_rendezvous<P, F>(
    hub: &SharedSplitHub,
    kind: H2LegKind,
    session: String,
    leg: BoxStream,
    pair: P,
    label: &str,
) -> Result<Option<BoxStream>, String>
where
    P: FnOnce(BoxStream, BoxStream) -> F,
    F: Future<Output = Result<BoxStream, String>>,
{
    let mut sessions = hub.sessions.lock().await;
    if let Some(mut pending) = sessions.remove(&session) {
        let parked_is_download = pending.get_ready.is_some();
        match (kind, parked_is_download) {
            (H2LegKind::Download, false) => {
                let upload_done = pending
                    .upload_done
                    .take()
                    .ok_or_else(|| format!("{label} session has an invalid upload leg"))?;
                drop(sessions);
                let app = pair(pending.first_leg, leg).await?;
                let _ = upload_done.send(());
                return Ok(Some(app));
            }
            (H2LegKind::Upload, true) => {
                let ready = pending
                    .get_ready
                    .take()
                    .ok_or_else(|| format!("{label} session is missing its download waiter"))?;
                drop(sessions);
                let app = pair(leg, pending.first_leg).await?;
                ready
                    .send(app)
                    .map_err(|_| format!("{label} download leg disappeared"))?;
                return Ok(None);
            }
            _ => {
                sessions.insert(session, pending);
                return Err(format!("{label} split session already has this leg"));
            }
        }
    }

    match kind {
        H2LegKind::Download => {
            let (ready_tx, ready_rx) = oneshot::channel();
            sessions.insert(
                session.clone(),
                PendingSession {
                    first_leg: leg,
                    get_ready: Some(ready_tx),
                    upload_done: None,
                },
            );
            drop(sessions);
            match tokio::time::timeout(SPLIT_PAIRING_TIMEOUT, ready_rx).await {
                Ok(Ok(app)) => Ok(Some(app)),
                Ok(Err(_)) => Err(format!("{label} upload leg disappeared")),
                Err(_) => {
                    hub.sessions.lock().await.remove(&session);
                    Err(format!(
                        "{label} split session timed out waiting for upload"
                    ))
                }
            }
        }
        H2LegKind::Upload => {
            let (done_tx, done_rx) = oneshot::channel();
            sessions.insert(
                session.clone(),
                PendingSession {
                    first_leg: leg,
                    get_ready: None,
                    upload_done: Some(done_tx),
                },
            );
            drop(sessions);
            match tokio::time::timeout(SPLIT_PAIRING_TIMEOUT, done_rx).await {
                Ok(_) => Ok(None),
                Err(_) => {
                    hub.sessions.lock().await.remove(&session);
                    Err(format!(
                        "{label} split session timed out waiting for download"
                    ))
                }
            }
        }
    }
}

/// How long the first leg of a stream-up session waits for its partner.
const SPLIT_PAIRING_TIMEOUT: Duration = Duration::from_secs(30);

async fn pair_server_legs(
    mut upload: BoxStream,
    mut download: BoxStream,
) -> Result<BoxStream, String> {
    download
        .write_all(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .map_err(|error| format!("XHTTP split download response: {error}"))?;
    download
        .flush()
        .await
        .map_err(|error| format!("XHTTP split download flush: {error}"))?;
    upload
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|error| format!("XHTTP split upload response: {error}"))?;
    upload
        .flush()
        .await
        .map_err(|error| format!("XHTTP split upload flush: {error}"))?;

    let (app, worker) = tokio::io::duplex(64 * 1024);
    tokio::spawn(run_server_split_exchange(upload, download, worker));
    Ok(zero_core::boxed(app))
}

async fn run_split_exchange(
    upload_stream: BoxStream,
    download_stream: BoxStream,
    app: tokio::io::DuplexStream,
) {
    let (app_read, app_write) = tokio::io::split(app);
    let (_, upload_write) = tokio::io::split(upload_stream);
    let (download_read, _) = tokio::io::split(download_stream);
    crate::relay::drive_both(
        "XHTTP split",
        upload(app_read, upload_write, true),
        download(download_read, app_write),
    )
    .await;
}

async fn run_server_split_exchange(
    upload: BoxStream,
    download: BoxStream,
    app: tokio::io::DuplexStream,
) {
    let (app_read, app_write) = tokio::io::split(app);
    let (upload_read, _) = tokio::io::split(upload);
    let (_, download_write) = tokio::io::split(download);
    crate::relay::drive_both(
        "XHTTP split server",
        download_request(upload_read, app_write),
        upload_response(app_read, download_write),
    )
    .await;
}

/// The next XHTTP request for this carrier, shaped as Xray 26 shapes it.
fn xhttp_request(
    config: &WsConfig,
    kind: RequestKind,
    session: Option<&str>,
    payload: Option<&[u8]>,
) -> XhttpRequest {
    let headers: Vec<(String, String)> = config
        .headers
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    let scheme = if config.secure { "https" } else { "http" };
    build_request(
        &config.xhttp,
        scheme,
        &config.host,
        &config.path,
        &headers,
        kind,
        session,
        payload,
    )
}

/// How an HTTP/1.1 request body is framed.
enum H1Body {
    None,
    Chunked,
    Length(usize),
}

/// An HTTP/1.1 request head. Always `Connection: close`, as Xray's client
/// sends it (see [`write_request`]).
fn h1_head(config: &WsConfig, request: &XhttpRequest, body: H1Body) -> String {
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        request.method, request.target, config.host
    );
    for (name, value) in &request.headers.0 {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    match body {
        H1Body::None => {}
        H1Body::Chunked => head.push_str("Transfer-Encoding: chunked\r\n"),
        H1Body::Length(n) => head.push_str(&format!("Content-Length: {n}\r\n")),
    }
    head.push_str("Connection: close\r\n\r\n");
    head
}

async fn write_request(
    stream: &mut BoxStream,
    config: &WsConfig,
    kind: RequestKind,
    session: Option<&str>,
) -> Result<(), String> {
    let request = xhttp_request(config, kind, session, None);
    let body = if kind == RequestKind::StreamDown {
        H1Body::None
    } else {
        H1Body::Chunked
    };
    // Xray's HTTP/1.1 client disables keep-alive, and Go's server depends on
    // it: with `Connection: close` it leaves an unread streaming body open
    // after the response starts; with keep-alive it closes the body, which
    // ends a stream-one or stream-up upload at its first byte.
    let head = h1_head(config, &request, body);
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|error| format!("XHTTP request: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("XHTTP request flush: {error}"))
}

/// An HTTP/2 or HTTP/3 request for `request`, with an absolute URI so the
/// `:scheme` and `:authority` pseudo-headers are set as a browser sets them.
fn http_request(
    config: &WsConfig,
    request: &XhttpRequest,
    content_length: Option<usize>,
    scheme: &str,
) -> Result<Request<()>, String> {
    let mut builder = Request::builder()
        .method(request.method.as_str())
        .uri(format!("{scheme}://{}{}", config.host, request.target));
    for (name, value) in &request.headers.0 {
        builder = builder.header(name.as_str(), value.as_str());
    }
    if let Some(length) = content_length {
        builder = builder.header(http::header::CONTENT_LENGTH, length);
    }
    builder
        .body(())
        .map_err(|error| format!("XHTTP request headers: {error}"))
}

fn h2_request(
    config: &WsConfig,
    kind: RequestKind,
    session: Option<&str>,
) -> Result<Request<()>, String> {
    let scheme = if config.secure { "https" } else { "http" };
    http_request(
        config,
        &xhttp_request(config, kind, session, None),
        None,
        scheme,
    )
}

fn parse_request(head: &str) -> Result<(&str, &str, bool), String> {
    let mut lines = head.lines();
    let mut parts = lines.next().unwrap_or_default().split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "XHTTP missing method".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "XHTTP missing target".to_string())?;
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(key, value)| {
            key.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    Ok((method, target, chunked))
}

fn content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

/// Send one packet-up upload and its data.
async fn write_packet_request(
    stream: &mut BoxStream,
    config: &WsConfig,
    session: &str,
    sequence: u64,
    payload: &[u8],
) -> Result<(), String> {
    let request = xhttp_request(
        config,
        RequestKind::Packet(sequence),
        Some(session),
        Some(payload),
    );
    let body: &[u8] = if request.body { payload } else { &[] };
    let head = h1_head(config, &request, H1Body::Length(body.len()));
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|error| format!("XHTTP packet request: {error}"))?;
    stream
        .write_all(body)
        .await
        .map_err(|error| format!("XHTTP packet body: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("XHTTP packet request flush: {error}"))
}

/// Xray's `scMinPostsIntervalMs`: space packet uploads out so writes that
/// arrive together travel in one POST.
async fn pace_upload(config: &WsConfig, last: &mut Option<tokio::time::Instant>) {
    let interval = u64::from(config.xhttp.sc_min_posts_interval_ms.sample());
    if let Some(previous) = *last {
        let due = previous + Duration::from_millis(interval);
        tokio::time::sleep_until(due).await;
    }
    *last = Some(tokio::time::Instant::now());
}

/// Largest packet carried in headers or cookies. Base64 makes it about
/// 5.5 KB of header, inside the ~12 KB Go's HTTP server accepts by default
/// (Xray's `serverMaxHeaderBytes` of 8192 plus Go's slack).
const MAX_HEADER_PACKET: usize = 4 * 1024;

/// Gather the next packet-up upload into `buffer`: wait for data, wait out
/// the posting interval, then take whatever else arrived meanwhile, up to
/// the size limit (Xray batches its upload pipe the same way). `false` at
/// the end of the stream.
async fn next_packet<R>(
    app: &mut R,
    buffer: &mut Vec<u8>,
    config: &WsConfig,
    last: &mut Option<tokio::time::Instant>,
) -> Result<bool, String>
where
    R: AsyncRead + Unpin,
{
    if buffer.capacity() > PACKET_IDLE_BUFFER && buffer.len() < PACKET_IDLE_BUFFER {
        // The previous packet was small; give back a burst's worth of memory.
        buffer.clear();
        buffer.shrink_to(PACKET_IDLE_BUFFER);
    }
    buffer.clear();
    let limit = max_post_bytes(config);
    if read_packet_part(app, buffer, limit).await? == 0 {
        return Ok(false);
    }
    pace_upload(config, last).await;
    while buffer.len() < limit {
        // Only what is already there: a zero timeout polls the read once.
        match tokio::time::timeout(Duration::ZERO, read_packet_part(app, buffer, limit)).await {
            Ok(Ok(n)) if n > 0 => {}
            Ok(Err(error)) => return Err(error),
            _ => break,
        }
    }
    Ok(true)
}

async fn read_packet_part<R>(
    app: &mut R,
    buffer: &mut Vec<u8>,
    limit: usize,
) -> Result<usize, String>
where
    R: AsyncRead + Unpin,
{
    let room = limit - buffer.len();
    buffer.reserve(room.min(PACKET_IDLE_BUFFER));
    (&mut *app)
        .take(room as u64)
        .read_buf(buffer)
        .await
        .map_err(|error| format!("XHTTP packet app read: {error}"))
}

/// The largest packet-up upload (Xray's `scMaxEachPostBytes`). When the data
/// travels in headers or cookies it is capped further: Xray's client sends
/// up to a megabyte there, and a server with default limits answers 431.
fn max_post_bytes(config: &WsConfig) -> usize {
    let limit =
        (config.xhttp.sc_max_each_post_bytes.sample() as usize).clamp(1, PACKET_UPLOAD_BUFFER);
    if config.xhttp.packet_data_in_body() {
        limit
    } else {
        limit.min(MAX_HEADER_PACKET)
    }
}

/// Xray treats the configured XHTTP path as a prefix. Some HTTP/3 clients
/// normalize a configured `/service` to `/service/`, while split-leg modes
/// append session and sequence components below it. Keep the boundary check
/// explicit so `/service-evil` is not accepted accidentally.
fn path_matches(configured: &str, requested: &str) -> bool {
    if configured == "/" {
        return requested.starts_with('/');
    }
    requested == configured
        || requested
            .strip_prefix(configured)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn session_from_path(target: &str, base: &str) -> Option<String> {
    let target_path = target.split_once('?').map_or(target, |(path, _)| path);
    let prefix = format!("{}/", base.trim_end_matches('/'));
    target_path
        .strip_prefix(&prefix)
        .filter(|id| !id.contains('/'))
        .map(str::to_owned)
}

fn packet_parts_from_path(target: &str, base: &str) -> Option<(String, Option<u64>)> {
    let target_path = target.split_once('?').map_or(target, |(path, _)| path);
    let base_path = base.split_once('?').map_or(base, |(path, _)| path);
    let prefix = format!("{}/", base_path.trim_end_matches('/'));
    let mut parts = target_path.strip_prefix(&prefix)?.split('/');
    let session = parts.next()?.to_owned();
    if session.is_empty() {
        return None;
    }
    let sequence = parts.next().and_then(|value| value.parse().ok());
    if parts.next().is_some() || (sequence.is_none() && target_path != prefix + &session) {
        return None;
    }
    Some((session, sequence))
}

fn packet_session_from_path(target: &str, base: &str) -> Option<String> {
    packet_parts_from_path(target, base).map(|(session, _)| session)
}

fn packet_download_session_from_path(target: &str, base: &str) -> Option<String> {
    packet_parts_from_path(target, base)
        .and_then(|(session, sequence)| sequence.is_none().then_some(session))
}

fn packet_sequence_from_path(target: &str, base: &str) -> Option<u64> {
    packet_parts_from_path(target, base).and_then(|(_, sequence)| sequence)
}

pub async fn connect(mut stream: BoxStream, config: &WsConfig) -> Result<BoxStream, String> {
    write_request(&mut stream, config, RequestKind::StreamOne, None).await?;

    let (app, worker) = tokio::io::duplex(64 * 1024);
    tokio::spawn(run_exchange(stream, worker));
    Ok(zero_core::boxed(app))
}

/// Accept XHTTP stream-one over HTTP/1.1. The request body is the client to
/// server byte stream and the chunked response body is the server to client
/// stream. HTTP/2 has a separate implementation because its flow-control
/// model cannot be represented by HTTP/1.1 chunk markers.
pub async fn accept(mut stream: BoxStream, config: &WsConfig) -> Result<BoxStream, String> {
    let head = read_request_head(&mut stream).await?;
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    if parts.next() != Some("POST") {
        return Err("XHTTP request is not POST".into());
    }
    let path = parts.next().unwrap_or("");
    let path = path.split_once('?').map_or(path, |(base, _)| base);
    if !path_matches(&config.path, path) {
        return Err("XHTTP request path does not match".into());
    }
    let mut chunked = false;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    if !chunked {
        return Err("XHTTP request must use chunked transfer encoding".into());
    }
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .map_err(|error| format!("XHTTP response: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("XHTTP response flush: {error}"))?;
    let (app, worker) = tokio::io::duplex(64 * 1024);
    tokio::spawn(run_server_exchange(stream, worker));
    Ok(zero_core::boxed(app))
}

/// Open XHTTP's stream-one carrier over HTTP/2.
///
/// The HTTP/2 request stream is deliberately kept behind the same byte-stream
/// seam as the H1 implementation. Upload and download run concurrently and
/// release the peer's flow-control credit as soon as application bytes are
/// copied, so one stalled logical flow cannot consume the connection window.
pub async fn connect_h2(stream: BoxStream, config: &WsConfig) -> Result<BoxStream, String> {
    let (mut sender, connection) = h2::client::Builder::new()
        .initial_window_size(H2_FLOW_CONTROL_WINDOW)
        .initial_connection_window_size(H2_FLOW_CONTROL_WINDOW)
        .handshake::<_, Bytes>(stream)
        .await
        .map_err(|error| format!("XHTTP HTTP/2 handshake: {error}"))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "XHTTP HTTP/2 connection ended");
        }
    });

    sender = sender
        .ready()
        .await
        .map_err(|error| format!("XHTTP HTTP/2 stream capacity: {error}"))?;

    let request = h2_request(config, RequestKind::StreamOne, None)?;
    let (response, send_stream) = sender
        .send_request(request, false)
        .map_err(|error| format!("XHTTP HTTP/2 request: {error}"))?;

    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(run_h2_exchange(response, send_stream, worker));
    Ok(zero_core::boxed(app))
}

/// Accept XHTTP stream-one over HTTP/2. The request body is the uplink and the
/// response body is the downlink, mirroring [`connect_h2`].
pub async fn accept_h2(stream: BoxStream, config: &WsConfig) -> Result<BoxStream, String> {
    match accept_h2_multi(stream, config, H2Server::StreamOne).await? {
        Some((first, _more)) => Ok(first),
        None => Err("XHTTP HTTP/2 client closed before opening a stream".into()),
    }
}

fn h2_stream_one(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    config: &WsConfig,
) -> Result<BoxStream, String> {
    if request.method() == http::Method::GET || !path_matches(&config.path, request.uri().path()) {
        return Err("XHTTP HTTP/2 request method or path does not match".into());
    }
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(())
        .map_err(|error| format!("XHTTP HTTP/2 response: {error}"))?;
    let send = respond
        .send_response(response, false)
        .map_err(|error| format!("XHTTP HTTP/2 response: {error}"))?;
    let body = request.into_body();
    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(async move {
        let (app_read, app_write) = tokio::io::split(worker);
        let upload = h2_body_to_app(body, app_write);
        let download = async {
            let mut send = send;
            h2_upload(app_read, &mut send).await
        };
        crate::relay::drive_both("XHTTP HTTP/2 server", upload, download).await;
    });
    Ok(zero_core::boxed(app))
}

/// Which XHTTP requests an HTTP/2 inbound serves.
#[derive(Clone)]
pub enum H2Server {
    StreamOne,
    StreamUp(SharedSplitHub),
    PacketUp(SharedPacketHub),
}

/// How many logical streams one HTTP/2 connection may have waiting for the
/// inbound to pick them up.
const H2_PENDING_STREAMS: usize = 64;

/// Serve every XHTTP request on one HTTP/2 connection.
///
/// Xray's clients put many requests on a connection: packet-up's uploads
/// ride the download's connection, and XMUX reuses connections across
/// sessions. Each request is handled on its own task; the logical streams
/// they open come back in order of arrival. Returns the first one and a
/// receiver for the rest, or `None` when the connection closed without
/// opening one (an upload-only connection).
pub async fn accept_h2_multi(
    stream: BoxStream,
    config: &WsConfig,
    server: H2Server,
) -> Result<Option<(BoxStream, tokio::sync::mpsc::Receiver<BoxStream>)>, String> {
    let mut connection = h2::server::Builder::new()
        .initial_window_size(H2_FLOW_CONTROL_WINDOW)
        .initial_connection_window_size(H2_FLOW_CONTROL_WINDOW)
        .max_concurrent_streams(256)
        .handshake::<_, Bytes>(stream)
        .await
        .map_err(|error| format!("XHTTP HTTP/2 server handshake: {error}"))?;
    let (tx, mut rx) = tokio::sync::mpsc::channel(H2_PENDING_STREAMS);
    let config = config.clone();
    tokio::spawn(async move {
        while let Some(result) = connection.accept().await {
            let (request, respond) = match result {
                Ok(pair) => pair,
                Err(error) => {
                    tracing::debug!(%error, "XHTTP HTTP/2 server connection ended");
                    break;
                }
            };
            let tx = tx.clone();
            let config = config.clone();
            let server = server.clone();
            tokio::spawn(async move {
                let opened = match server {
                    H2Server::StreamOne => h2_stream_one(request, respond, &config).map(Some),
                    H2Server::PacketUp(hub) => {
                        h2_packet_request(request, respond, &config, &hub).await
                    }
                    H2Server::StreamUp(hub) => match h2_split_leg(request, respond, &config) {
                        Ok((kind, session, leg)) => {
                            split_rendezvous(
                                &hub,
                                kind,
                                session,
                                leg,
                                pair_h2_server_legs,
                                "XHTTP H2",
                            )
                            .await
                        }
                        Err(error) => Err(error),
                    },
                };
                match opened {
                    Ok(Some(stream)) => {
                        let _ = tx.send(stream).await;
                    }
                    Ok(None) => {}
                    Err(error) => tracing::debug!(%error, "XHTTP HTTP/2 request rejected"),
                }
            });
        }
    });
    Ok(rx.recv().await.map(|first| (first, rx)))
}

/// Open XHTTP stream-one over HTTP/3/QUIC.
///
/// The QUIC endpoint is deliberately owned by the exchange task so dropping
/// the setup future cannot close the UDP socket while application bytes are
/// still in flight. Certificate verification is inherited from the ordinary
/// TLS profile; this carrier never enables an insecure verifier.
pub async fn connect_h3(
    addrs: &[SocketAddr],
    config: &WsConfig,
    tls: &zero_security::TlsParams,
) -> Result<BoxStream, String> {
    let (endpoint, connection) = h3_connect(addrs, tls, "XHTTP HTTP/3").await?;
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|error| format!("XHTTP HTTP/3 setup: {error}"))?;
    let request = http_request(
        config,
        &xhttp_request(config, RequestKind::StreamOne, None, None),
        None,
        "https",
    )?;
    let request_stream = send_request
        .send_request(request)
        .await
        .map_err(|error| format!("XHTTP HTTP/3 request: {error}"))?;
    let (mut request_send, mut request_recv) = request_stream.split();
    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(async move {
        let _endpoint = endpoint;
        let _connection = connection;
        let (app_read, mut app_write) = tokio::io::split(worker);
        let upload = async {
            let mut app = app_read;
            let mut buffer = BytesMut::with_capacity(H2_UPLOAD_CHUNK);
            loop {
                buffer.reserve(H2_UPLOAD_CHUNK);
                let n = app
                    .read_buf(&mut buffer)
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 upload read: {error}"))?;
                if n == 0 {
                    request_send
                        .finish()
                        .await
                        .map_err(|error| format!("XHTTP HTTP/3 upload finish: {error}"))?;
                    return Ok::<(), String>(());
                }
                request_send
                    .send_data(buffer.split().freeze())
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 upload: {error}"))?;
            }
        };
        let download = async {
            let response = request_recv
                .recv_response()
                .await
                .map_err(|error| format!("XHTTP HTTP/3 response: {error}"))?;
            if response.status() != http::StatusCode::OK
                && response.status() != http::StatusCode::PARTIAL_CONTENT
            {
                return Err(format!(
                    "XHTTP HTTP/3 unexpected status {}",
                    response.status()
                ));
            }
            while let Some(mut chunk) = request_recv
                .recv_data()
                .await
                .map_err(|error| format!("XHTTP HTTP/3 response body: {error}"))?
            {
                app_write
                    .write_all_buf(&mut chunk)
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 app write: {error}"))?;
            }
            app_write
                .shutdown()
                .await
                .map_err(|error| format!("XHTTP HTTP/3 app close: {error}"))
        };
        run_with_h3_driver(
            &mut driver,
            crate::relay::drive_both("XHTTP HTTP/3", upload, download),
        )
        .await;
        // Dropping the last request handle closes the connection (H3_NO_ERROR).
        drop(send_request);
    });
    Ok(zero_core::boxed(app))
}

/// Open XHTTP stream-up over two independent HTTP/3 requests. The upload is
/// a POST body and the download is a GET response body, paired by a session
/// path just like the H1/H2 split implementations.
pub async fn connect_stream_up_h3(
    addrs: &[SocketAddr],
    config: &WsConfig,
    tls: &zero_security::TlsParams,
) -> Result<BoxStream, String> {
    let session = config.xhttp.new_session_id();
    let upload = connect_h3_split_leg(addrs, config, tls, &session, true).await?;
    let download = connect_h3_split_leg(addrs, config, tls, &session, false).await?;
    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(run_h3_split_exchange(upload, download, worker));
    Ok(zero_core::boxed(app))
}

/// Open XHTTP packet-up over one HTTP/3 connection. The download is a
/// persistent GET and every logical uplink write is a fixed-length POST on a
/// fresh request stream. Unlike H1/H2, QUIC gives all requests one connection
/// without head-of-line blocking, while the path sequence still provides the
/// packet-up ordering contract.
pub async fn connect_packet_up_h3(
    addrs: &[SocketAddr],
    download_config: &WsConfig,
    upload_config: &WsConfig,
    tls: &zero_security::TlsParams,
) -> Result<BoxStream, String> {
    let (endpoint, connection) = h3_connect(addrs, tls, "XHTTP HTTP/3 packet").await?;
    let (mut driver, mut requests) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|error| format!("XHTTP HTTP/3 packet setup: {error}"))?;

    let session = download_config.xhttp.new_session_id();
    let request = http_request(
        download_config,
        &xhttp_request(
            download_config,
            RequestKind::StreamDown,
            Some(&session),
            None,
        ),
        None,
        "https",
    )?;
    let request_stream = requests
        .send_request(request)
        .await
        .map_err(|error| format!("XHTTP HTTP/3 packet download request: {error}"))?;
    let (mut request_send, mut request_recv) = request_stream.split();
    request_send
        .finish()
        .await
        .map_err(|error| format!("XHTTP HTTP/3 packet download finish: {error}"))?;
    let response = request_recv
        .recv_response()
        .await
        .map_err(|error| format!("XHTTP HTTP/3 packet download response: {error}"))?;
    if response.status() != http::StatusCode::OK {
        return Err(format!(
            "XHTTP HTTP/3 packet download unexpected status {}",
            response.status()
        ));
    }

    let (app, worker) = tokio::io::duplex(128 * 1024);
    let upload_requests = requests.clone();
    let download_config = download_config.clone();
    let upload_config = upload_config.clone();
    tokio::spawn(async move {
        let _endpoint = endpoint;
        let _connection = connection;
        let (mut app_read, app_write) = tokio::io::split(worker);
        let download = async {
            let mut app = app_write;
            while let Some(mut chunk) = request_recv
                .recv_data()
                .await
                .map_err(|error| format!("XHTTP HTTP/3 packet download body: {error}"))?
            {
                app.write_all_buf(&mut chunk)
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 packet app write: {error}"))?;
            }
            app.shutdown()
                .await
                .map_err(|error| format!("XHTTP HTTP/3 packet app close: {error}"))
        };
        let upload = async move {
            let mut requests = upload_requests;
            let mut sequence = 0u64;
            let mut buffer = Vec::new();
            let mut last = None;
            loop {
                if !next_packet(&mut app_read, &mut buffer, &upload_config, &mut last).await? {
                    return Ok::<(), String>(());
                }
                let n = buffer.len();
                let request = xhttp_request(
                    &upload_config,
                    RequestKind::Packet(sequence),
                    Some(&session),
                    Some(&buffer[..n]),
                );
                let body_len = if request.body { n } else { 0 };
                let request = http_request(&upload_config, &request, Some(body_len), "https")?;
                let request_stream = requests
                    .send_request(request)
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 packet upload request: {error}"))?;
                let (mut send, mut recv) = request_stream.split();
                if body_len > 0 {
                    send.send_data(Bytes::copy_from_slice(&buffer[..n]))
                        .await
                        .map_err(|error| format!("XHTTP HTTP/3 packet upload body: {error}"))?;
                }
                send.finish()
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 packet upload finish: {error}"))?;
                let response = recv
                    .recv_response()
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 packet upload response: {error}"))?;
                if response.status() != http::StatusCode::OK {
                    return Err(format!(
                        "XHTTP HTTP/3 packet upload unexpected status {}",
                        response.status()
                    ));
                }
                while recv
                    .recv_data()
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 packet upload response body: {error}"))?
                    .is_some()
                {}
                sequence = sequence.wrapping_add(1);
            }
        };
        run_with_h3_driver(
            &mut driver,
            crate::relay::drive_both("XHTTP HTTP/3 packet", upload, download),
        )
        .await;
        drop(requests);
        drop(download_config);
    });
    Ok(zero_core::boxed(app))
}

async fn connect_h3_split_leg(
    addrs: &[SocketAddr],
    config: &WsConfig,
    tls: &zero_security::TlsParams,
    session: &str,
    upload_leg: bool,
) -> Result<BoxStream, String> {
    let (endpoint, connection) = h3_connect(addrs, tls, "XHTTP HTTP/3").await?;
    let (mut driver, mut requests) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|error| format!("XHTTP HTTP/3 split setup: {error}"))?;
    let kind = if upload_leg {
        RequestKind::StreamUp
    } else {
        RequestKind::StreamDown
    };
    let request = http_request(
        config,
        &xhttp_request(config, kind, Some(session), None),
        None,
        "https",
    )?;
    let request_stream = requests
        .send_request(request)
        .await
        .map_err(|error| format!("XHTTP HTTP/3 split request: {error}"))?;
    let (mut request_send, mut request_recv) = request_stream.split();
    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(async move {
        let _endpoint = endpoint;
        let _connection = connection;
        if upload_leg {
            let (app_read, _) = tokio::io::split(worker);
            let upload = async {
                let mut app = app_read;
                let mut buffer = BytesMut::with_capacity(H2_UPLOAD_CHUNK);
                loop {
                    buffer.reserve(H2_UPLOAD_CHUNK);
                    let n = app
                        .read_buf(&mut buffer)
                        .await
                        .map_err(|error| format!("XHTTP HTTP/3 split upload read: {error}"))?;
                    if n == 0 {
                        request_send.finish().await.map_err(|error| {
                            format!("XHTTP HTTP/3 split upload finish: {error}")
                        })?;
                        return Ok::<(), String>(());
                    }
                    request_send
                        .send_data(buffer.split().freeze())
                        .await
                        .map_err(|error| format!("XHTTP HTTP/3 split upload: {error}"))?;
                }
            };
            let response = async {
                let response = request_recv
                    .recv_response()
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 split upload response: {error}"))?;
                if response.status() != http::StatusCode::OK {
                    return Err(format!(
                        "XHTTP HTTP/3 split upload status {}",
                        response.status()
                    ));
                }
                while request_recv
                    .recv_data()
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 split upload body: {error}"))?
                    .is_some()
                {}
                Ok::<(), String>(())
            };
            run_with_h3_driver(
                &mut driver,
                crate::relay::drive_both("XHTTP HTTP/3 split upload", upload, response),
            )
            .await;
        } else {
            let (_, app_write) = tokio::io::split(worker);
            let request = async {
                request_send
                    .finish()
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 split download finish: {error}"))?;
                let response = request_recv
                    .recv_response()
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 split download response: {error}"))?;
                if response.status() != http::StatusCode::OK {
                    return Err(format!(
                        "XHTTP HTTP/3 split download status {}",
                        response.status()
                    ));
                }
                let mut app = app_write;
                while let Some(mut chunk) = request_recv
                    .recv_data()
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 split download body: {error}"))?
                {
                    app.write_all_buf(&mut chunk)
                        .await
                        .map_err(|error| format!("XHTTP HTTP/3 split download app: {error}"))?;
                }
                app.shutdown()
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 split download close: {error}"))
            };
            run_with_h3_driver(&mut driver, async {
                if let Err(error) = request.await {
                    tracing::debug!(%error, "XHTTP HTTP/3 split download ended");
                }
            })
            .await;
        }
        drop(requests);
    });
    Ok(zero_core::boxed(app))
}

async fn run_h3_split_exchange(
    upload: BoxStream,
    download: BoxStream,
    app: tokio::io::DuplexStream,
) {
    let (app_read, app_write) = tokio::io::split(app);
    let (_, upload_write) = tokio::io::split(upload);
    let (download_read, _) = tokio::io::split(download);
    crate::relay::drive_both(
        "XHTTP H3 split",
        crate::relay::copy_then_shutdown(app_read, upload_write),
        crate::relay::copy_then_shutdown(download_read, app_write),
    )
    .await;
}

/// Idle timeout of the QUIC server endpoints (XHTTP/3, Hysteria2, TUIC).
const SERVER_QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Build a QUIC endpoint for an HTTP/3 XHTTP inbound. The caller owns the
/// endpoint and should keep it alive for the listener lifetime.
pub fn h3_server_endpoint(
    listen: SocketAddr,
    certificate: &[u8],
    private_key: &[u8],
) -> Result<h3_quinn::quinn::Endpoint, String> {
    let tls =
        zero_security::server::server_config(certificate, private_key, &[Box::<str>::from("h3")])?;
    let crypto = h3_quinn::quinn::crypto::rustls::QuicServerConfig::try_from((*tls).clone())
        .map_err(|error| format!("XHTTP HTTP/3 server TLS configuration: {error}"))?;
    let mut server_config = h3_quinn::quinn::ServerConfig::with_crypto(Arc::new(crypto));
    // Clients keep connections alive (10 s), so the server needs no pings of
    // its own; the idle timeout only has to outlast them. Hysteria2 and TUIC
    // multiplex every proxied connection of a client over one QUIC connection,
    // so quinn's default of 100 concurrent streams is too low for a browser.
    let mut transport = crate::relay::quic_transport(SERVER_QUIC_IDLE_TIMEOUT, None);
    transport.max_concurrent_bidi_streams(1024u32.into());
    server_config.transport_config(Arc::new(transport));
    h3_quinn::quinn::Endpoint::server(server_config, listen)
        .map_err(|error| format!("XHTTP HTTP/3 server endpoint: {error}"))
}

/// Turn one accepted HTTP/3 POST request into the byte stream consumed by the
/// protocol layer. The HTTP/3 connection driver remains with the caller; this
/// function owns only the request/response body bridge.
pub async fn accept_h3_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    config: &WsConfig,
) -> Result<BoxStream, String> {
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|error| format!("XHTTP HTTP/3 request: {error}"))?;
    if request.method() != http::Method::POST || !path_matches(&config.path, request.uri().path()) {
        return Err(format!(
            "XHTTP HTTP/3 request method or path does not match: {} {} (expected POST {})",
            request.method(),
            request.uri(),
            config.path
        ));
    }
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(())
        .map_err(|error| format!("XHTTP HTTP/3 response: {error}"))?;
    stream
        .send_response(response)
        .await
        .map_err(|error| format!("XHTTP HTTP/3 response: {error}"))?;
    let (mut send, mut recv) = stream.split();
    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(async move {
        let (mut app_read, mut app_write) = tokio::io::split(worker);
        let upload = async {
            while let Some(mut chunk) = recv
                .recv_data()
                .await
                .map_err(|error| format!("XHTTP HTTP/3 request body: {error}"))?
            {
                app_write
                    .write_all_buf(&mut chunk)
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 request app write: {error}"))?;
            }
            app_write
                .shutdown()
                .await
                .map_err(|error| format!("XHTTP HTTP/3 request app close: {error}"))?;
            Ok::<(), String>(())
        };
        let download = async {
            let mut buffer = BytesMut::with_capacity(H2_UPLOAD_CHUNK);
            loop {
                buffer.reserve(H2_UPLOAD_CHUNK);
                let n = app_read
                    .read_buf(&mut buffer)
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 response app read: {error}"))?;
                if n == 0 {
                    send.finish()
                        .await
                        .map_err(|error| format!("XHTTP HTTP/3 response finish: {error}"))?;
                    return Ok::<(), String>(());
                }
                send.send_data(buffer.split().freeze())
                    .await
                    .map_err(|error| format!("XHTTP HTTP/3 response body: {error}"))?;
            }
        };
        crate::relay::drive_both("XHTTP HTTP/3 server", upload, download).await;
    });
    Ok(zero_core::boxed(app))
}

/// Accept one HTTP/3 packet-up GET or fixed-length POST. A GET owns the
/// persistent downlink; each POST is a separate request stream carrying one
/// bounded, ordered packet.
pub async fn accept_packet_up_h3(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    config: &WsConfig,
    hub: &SharedPacketHub,
) -> Result<Option<BoxStream>, String> {
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|error| format!("XHTTP HTTP/3 packet request: {error}"))?;
    let path = request.uri().path();
    if request.method() == http::Method::GET {
        let session = packet_download_session_from_path(path, &config.path)
            .ok_or_else(|| "XHTTP HTTP/3 packet GET has no valid session path".to_string())?;
        if request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .is_some_and(|value| value != "0")
        {
            return Err("XHTTP HTTP/3 packet GET must not have a request body".into());
        }
        let packet_rx = hub.open(session.clone()).await?;
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(())
            .map_err(|error| format!("XHTTP HTTP/3 packet download response: {error}"))?;
        stream
            .send_response(response)
            .await
            .map_err(|error| format!("XHTTP HTTP/3 packet download response: {error}"))?;
        let (mut send, mut recv) = stream.split();
        let (app, worker) = tokio::io::duplex(128 * 1024);
        let hub = Arc::clone(hub);
        tokio::spawn(async move {
            run_packet_server_exchange_h3(packet_rx, worker, &mut send, &mut recv).await;
            hub.sessions.lock().await.remove(&session);
        });
        Ok(Some(zero_core::boxed(app)))
    } else if request.method() == http::Method::POST {
        let session = packet_session_from_path(path, &config.path)
            .ok_or_else(|| "XHTTP HTTP/3 packet POST has no valid session path".to_string())?;
        let sequence = packet_sequence_from_path(path, &config.path)
            .ok_or_else(|| "XHTTP HTTP/3 packet POST has no valid sequence".to_string())?;
        let expected = request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| "XHTTP HTTP/3 packet POST requires Content-Length".to_string())?;
        if expected > MAX_PACKET_POST_BYTES {
            return Err("XHTTP HTTP/3 packet POST exceeds the 1 MiB limit".into());
        }
        let mut payload = Vec::with_capacity(expected);
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|error| format!("XHTTP HTTP/3 packet POST body: {error}"))?
        {
            let chunk_len = chunk.remaining();
            if payload.len().saturating_add(chunk_len) > MAX_PACKET_POST_BYTES {
                return Err("XHTTP HTTP/3 packet POST exceeds the 1 MiB limit".into());
            }
            let chunk = chunk.copy_to_bytes(chunk_len);
            payload.extend_from_slice(&chunk);
        }
        if payload.len() != expected {
            return Err(
                "XHTTP HTTP/3 packet POST body length does not match Content-Length".into(),
            );
        }
        hub.deliver(&session, sequence, payload).await?;
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("content-length", "0")
            .body(())
            .map_err(|error| format!("XHTTP HTTP/3 packet response: {error}"))?;
        stream
            .send_response(response)
            .await
            .map_err(|error| format!("XHTTP HTTP/3 packet response: {error}"))?;
        Ok(None)
    } else {
        Err("XHTTP HTTP/3 packet request must be a bodyless GET or fixed-length POST".into())
    }
}

/// Bridge an HTTP/3 packet-up session to the protocol stream.
///
/// The uplink is the sequence of POST bodies (delivered in order through
/// `packets`) and goes *to* the application; the downlink is whatever the
/// application writes and goes out as the GET response body. This used to be
/// wired the other way round — POST payloads were echoed back to the client
/// in the GET response while the application's output was never read — so
/// packet-up over HTTP/3 carried no traffic at all.
async fn run_packet_server_exchange_h3(
    mut packets: tokio::sync::mpsc::Receiver<Vec<u8>>,
    worker: tokio::io::DuplexStream,
    send: &mut h3::server::RequestStream<impl h3::quic::SendStream<Bytes>, Bytes>,
    _recv: &mut h3::server::RequestStream<impl h3::quic::RecvStream<Buf = Bytes>, Bytes>,
) {
    let (mut app_read, mut app_write) = tokio::io::split(worker);
    let uplink = async {
        while let Some(packet) = packets.recv().await {
            app_write
                .write_all(&packet)
                .await
                .map_err(|error| format!("XHTTP H3 packet server app write: {error}"))?;
        }
        app_write
            .shutdown()
            .await
            .map_err(|error| format!("XHTTP H3 packet server app close: {error}"))
    };
    let downlink = async {
        let mut buffer = BytesMut::with_capacity(H2_UPLOAD_CHUNK);
        loop {
            buffer.reserve(H2_UPLOAD_CHUNK);
            let n = app_read
                .read_buf(&mut buffer)
                .await
                .map_err(|error| format!("XHTTP H3 packet server app read: {error}"))?;
            if n == 0 {
                return send
                    .finish()
                    .await
                    .map_err(|error| format!("XHTTP H3 packet response finish: {error}"));
            }
            send.send_data(buffer.split().freeze())
                .await
                .map_err(|error| format!("XHTTP H3 packet response body: {error}"))?;
        }
    };
    crate::relay::drive_both("XHTTP H3 packet server", uplink, downlink).await;
}

/// Accept one HTTP/3 stream-up leg and pair it through the shared split hub.
pub async fn accept_stream_up_h3(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    config: &WsConfig,
    hub: &SharedSplitHub,
) -> Result<Option<BoxStream>, String> {
    let (kind, session, leg) = accept_h3_leg(resolver, config).await?;
    split_rendezvous(
        hub,
        kind,
        session,
        leg,
        |upload, download| async move { Ok(pair_h3_server_legs(upload, download).await) },
        "XHTTP H3",
    )
    .await
}

async fn accept_h3_leg(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    config: &WsConfig,
) -> Result<(H2LegKind, String, BoxStream), String> {
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|error| format!("XHTTP H3 split request: {error}"))?;
    let session = session_from_path(request.uri().path(), &config.path)
        .ok_or_else(|| "XHTTP H3 split request has no valid session path".to_string())?;
    let kind = if request.method() == http::Method::GET {
        H2LegKind::Download
    } else if request.method() == http::Method::POST {
        H2LegKind::Upload
    } else {
        return Err("XHTTP H3 split request must be GET or POST".into());
    };
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(())
        .map_err(|error| format!("XHTTP H3 split response: {error}"))?;
    stream
        .send_response(response)
        .await
        .map_err(|error| format!("XHTTP H3 split response: {error}"))?;
    let (mut send, mut recv) = stream.split();
    let (app, worker) = tokio::io::duplex(128 * 1024);
    match kind {
        H2LegKind::Download => {
            let (worker_read, _) = tokio::io::split(worker);
            tokio::spawn(async move {
                let mut buffer = [0u8; 16 * 1024];
                let mut app = worker_read;
                loop {
                    let n = match app.read(&mut buffer).await {
                        Ok(n) => n,
                        Err(error) => {
                            tracing::debug!(%error, "XHTTP H3 server download read failed");
                            return;
                        }
                    };
                    if n == 0 {
                        let _ = send.finish().await;
                        return;
                    }
                    if let Err(error) = send.send_data(Bytes::copy_from_slice(&buffer[..n])).await {
                        tracing::debug!(%error, "XHTTP H3 server download ended");
                        return;
                    }
                }
            });
        }
        H2LegKind::Upload => {
            let (_, worker_write) = tokio::io::split(worker);
            tokio::spawn(async move {
                let mut app = worker_write;
                while let Ok(Some(mut chunk)) = recv.recv_data().await {
                    if let Err(error) = app.write_all_buf(&mut chunk).await {
                        tracing::debug!(%error, "XHTTP H3 server upload ended");
                        return;
                    }
                }
                let _ = app.shutdown().await;
            });
        }
    }
    Ok((kind, session, zero_core::boxed(app)))
}

async fn pair_h3_server_legs(upload: BoxStream, download: BoxStream) -> BoxStream {
    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(async move {
        let (app_read, app_write) = tokio::io::split(worker);
        let (upload_read, _) = tokio::io::split(upload);
        let (_, download_write) = tokio::io::split(download);
        crate::relay::drive_both(
            "XHTTP H3 split server",
            crate::relay::copy_then_shutdown(upload_read, app_write),
            crate::relay::copy_then_shutdown(app_read, download_write),
        )
        .await;
    });
    zero_core::boxed(app)
}

/// Open XHTTP stream-up over two independent HTTP/2 connections.
///
/// The upload leg is a POST whose request body is the logical uplink. The
/// download leg is a GET whose response body is the logical downlink. Each
/// leg owns its own HTTP/2 connection, matching Xray's split resource model.
pub async fn connect_stream_up_h2(
    upload: BoxStream,
    download: BoxStream,
    upload_config: &WsConfig,
    download_config: &WsConfig,
) -> Result<BoxStream, String> {
    let session = upload_config.xhttp.new_session_id();
    let download = connect_h2_download_leg(download, download_config, &session).await?;
    let upload = connect_h2_upload_leg(upload, upload_config, &session).await?;
    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(run_h2_split_exchange(upload, download, worker));
    Ok(zero_core::boxed(app))
}

/// Accept one XHTTP stream-up HTTP/2 leg and pair it through the same hub as
/// the HTTP/1.1 implementation. The HTTP/2 response is committed before the
/// leg enters the rendezvous, so pairing never writes HTTP/1.1 bytes into an
/// HTTP/2 body.
pub async fn accept_stream_up_h2(
    stream: BoxStream,
    config: &WsConfig,
    hub: &SharedSplitHub,
) -> Result<Option<BoxStream>, String> {
    Ok(
        accept_h2_multi(stream, config, H2Server::StreamUp(Arc::clone(hub)))
            .await?
            .map(|(first, _more)| first),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H2LegKind {
    Upload,
    Download,
}

async fn connect_h2_upload_leg(
    stream: BoxStream,
    config: &WsConfig,
    session: &str,
) -> Result<BoxStream, String> {
    let (mut sender, connection) = h2::client::Builder::new()
        .initial_window_size(H2_FLOW_CONTROL_WINDOW)
        .initial_connection_window_size(H2_FLOW_CONTROL_WINDOW)
        .handshake::<_, Bytes>(stream)
        .await
        .map_err(|error| format!("XHTTP H2 upload handshake: {error}"))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "XHTTP H2 upload connection ended");
        }
    });
    sender = sender
        .ready()
        .await
        .map_err(|error| format!("XHTTP H2 upload capacity: {error}"))?;
    let request = h2_request(config, RequestKind::StreamUp, Some(session))?;
    let (response, send) = sender
        .send_request(request, false)
        .map_err(|error| format!("XHTTP H2 upload request: {error}"))?;
    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(async move {
        let (app_read, _) = tokio::io::split(worker);
        let mut send = send;
        let upload = h2_upload(app_read, &mut send);
        let response = async {
            let response = response
                .await
                .map_err(|error| format!("XHTTP H2 upload response: {error}"))?;
            if response.status() != http::StatusCode::OK {
                return Err(format!(
                    "XHTTP H2 upload unexpected status {}",
                    response.status()
                ));
            }
            Ok::<(), String>(())
        };
        let (upload, response) = tokio::join!(upload, response);
        if let Err(error) = upload {
            tracing::debug!(%error, "XHTTP H2 upload leg ended");
        }
        if let Err(error) = response {
            tracing::debug!(%error, "XHTTP H2 upload response ended");
        }
    });
    Ok(zero_core::boxed(app))
}

async fn connect_h2_download_leg(
    stream: BoxStream,
    config: &WsConfig,
    session: &str,
) -> Result<BoxStream, String> {
    let (mut sender, connection) = h2::client::Builder::new()
        .initial_window_size(H2_FLOW_CONTROL_WINDOW)
        .initial_connection_window_size(H2_FLOW_CONTROL_WINDOW)
        .handshake::<_, Bytes>(stream)
        .await
        .map_err(|error| format!("XHTTP H2 download handshake: {error}"))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "XHTTP H2 download connection ended");
        }
    });
    sender = sender
        .ready()
        .await
        .map_err(|error| format!("XHTTP H2 download capacity: {error}"))?;
    let request = h2_request(config, RequestKind::StreamDown, Some(session))?;
    let (response, _send) = sender
        .send_request(request, true)
        .map_err(|error| format!("XHTTP H2 download request: {error}"))?;
    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(async move {
        let (_, app_write) = tokio::io::split(worker);
        if let Err(error) = h2_download(response, app_write).await {
            tracing::debug!(%error, "XHTTP H2 download leg ended");
        }
    });
    Ok(zero_core::boxed(app))
}

fn h2_split_leg(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    config: &WsConfig,
) -> Result<(H2LegKind, String, BoxStream), String> {
    let path = request.uri().path();
    let session = session_from_path(path, &config.path)
        .ok_or_else(|| "XHTTP H2 split request has no valid session path".to_string())?;
    let (kind, body, send) = if request.method() == http::Method::GET {
        if !request.body().is_end_stream() {
            return Err("XHTTP H2 download GET must not have a request body".into());
        }
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(())
            .map_err(|error| format!("XHTTP H2 download response: {error}"))?;
        let send = respond
            .send_response(response, false)
            .map_err(|error| format!("XHTTP H2 download response: {error}"))?;
        (H2LegKind::Download, None, send)
    } else if request.method() == http::Method::POST {
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(())
            .map_err(|error| format!("XHTTP H2 upload response: {error}"))?;
        let send = respond
            .send_response(response, true)
            .map_err(|error| format!("XHTTP H2 upload response: {error}"))?;
        (H2LegKind::Upload, Some(request.into_body()), send)
    } else {
        return Err("XHTTP H2 split request must be GET or POST".into());
    };

    let (app, worker) = tokio::io::duplex(128 * 1024);
    match kind {
        H2LegKind::Download => {
            let (worker_read, _) = tokio::io::split(worker);
            tokio::spawn(async move {
                let mut send = send;
                if let Err(error) = h2_upload(worker_read, &mut send).await {
                    tracing::debug!(%error, "XHTTP H2 server download ended");
                }
            });
        }
        H2LegKind::Upload => {
            let body = body.expect("POST body");
            let (_, worker_write) = tokio::io::split(worker);
            tokio::spawn(async move {
                if let Err(error) = h2_body_to_app(body, worker_write).await {
                    tracing::debug!(%error, "XHTTP H2 server upload ended");
                }
            });
        }
    }
    Ok((kind, session, zero_core::boxed(app)))
}

async fn h2_body_to_app<W>(mut body: h2::RecvStream, mut app: W) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|error| format!("XHTTP H2 request body: {error}"))?;
        let length = chunk.len();
        app.write_all(&chunk)
            .await
            .map_err(|error| format!("XHTTP H2 request app write: {error}"))?;
        body.flow_control()
            .release_capacity(length)
            .map_err(|error| format!("XHTTP H2 request flow control: {error}"))?;
    }
    app.shutdown()
        .await
        .map_err(|error| format!("XHTTP H2 request app close: {error}"))
}

async fn run_h2_split_exchange(
    upload: BoxStream,
    download: BoxStream,
    app: tokio::io::DuplexStream,
) {
    let (app_read, app_write) = tokio::io::split(app);
    let (_, upload_write) = tokio::io::split(upload);
    let (download_read, _) = tokio::io::split(download);
    crate::relay::drive_both(
        "XHTTP H2 split",
        crate::relay::copy_then_shutdown(app_read, upload_write),
        crate::relay::copy_then_shutdown(download_read, app_write),
    )
    .await;
}

async fn pair_h2_server_legs(upload: BoxStream, download: BoxStream) -> Result<BoxStream, String> {
    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(run_h2_server_split_exchange(upload, download, worker));
    Ok(zero_core::boxed(app))
}

async fn run_h2_server_split_exchange(
    upload: BoxStream,
    download: BoxStream,
    app: tokio::io::DuplexStream,
) {
    let (app_read, app_write) = tokio::io::split(app);
    let (upload_read, _) = tokio::io::split(upload);
    let (_, download_write) = tokio::io::split(download);
    crate::relay::drive_both(
        "XHTTP H2 split server",
        crate::relay::copy_then_shutdown(upload_read, app_write),
        crate::relay::copy_then_shutdown(app_read, download_write),
    )
    .await;
}

async fn run_h2_exchange(
    response: h2::client::ResponseFuture,
    mut send_stream: h2::SendStream<Bytes>,
    app: tokio::io::DuplexStream,
) {
    let (app_read, app_write) = tokio::io::split(app);
    let upload = h2_upload(app_read, &mut send_stream);
    let download = h2_download(response, app_write);
    crate::relay::drive_both("XHTTP HTTP/2", upload, download).await;
}

async fn h2_upload<R>(mut app: R, send_stream: &mut h2::SendStream<Bytes>) -> Result<(), String>
where
    R: AsyncRead + Unpin,
{
    // Read straight into a `BytesMut` and hand frozen slices of it to h2: one
    // copy per chunk instead of a stack buffer plus `Bytes::copy_from_slice`.
    // Once h2 has written and released a chunk, `reserve` reclaims the same
    // allocation.
    let mut buffer = BytesMut::with_capacity(H2_UPLOAD_CHUNK);
    loop {
        buffer.reserve(H2_UPLOAD_CHUNK);
        let n = app
            .read_buf(&mut buffer)
            .await
            .map_err(|error| format!("XHTTP HTTP/2 upload read: {error}"))?;
        if n == 0 {
            send_stream
                .send_data(Bytes::new(), true)
                .map_err(|error| format!("XHTTP HTTP/2 upload close: {error}"))?;
            return Ok(());
        }
        crate::relay::send_with_capacity(send_stream, buffer.split().freeze())
            .await
            .map_err(|error| format!("XHTTP HTTP/2 upload: {error}"))?;
    }
}

/// Bytes read from the application per HTTP/2 upload step.
const H2_UPLOAD_CHUNK: usize = 16 * 1024;

async fn h2_download<W>(response: h2::client::ResponseFuture, app: W) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let response = response
        .await
        .map_err(|error| format!("XHTTP HTTP/2 response: {error}"))?;
    if response.status() != http::StatusCode::OK
        && response.status() != http::StatusCode::PARTIAL_CONTENT
    {
        return Err(format!(
            "XHTTP HTTP/2 unexpected status {}",
            response.status()
        ));
    }
    h2_download_body(response.into_body(), app).await
}

/// Stream an HTTP/2 response body whose head has already been accepted.
async fn h2_download_body<W>(mut body: h2::RecvStream, mut app: W) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|error| format!("XHTTP HTTP/2 response body: {error}"))?;
        let length = chunk.len();
        app.write_all(&chunk)
            .await
            .map_err(|error| format!("XHTTP HTTP/2 app write: {error}"))?;
        body.flow_control()
            .release_capacity(length)
            .map_err(|error| format!("XHTTP HTTP/2 flow control: {error}"))?;
    }
    // Pass the end of the response on as EOF; see `download_body`.
    app.shutdown()
        .await
        .map_err(|error| format!("XHTTP HTTP/2 app close: {error}"))
}

async fn run_exchange(stream: BoxStream, app: tokio::io::DuplexStream) {
    let (app_read, app_write) = tokio::io::split(app);
    let (net_read, net_write) = tokio::io::split(stream);
    // Stream-one: the response shares this socket, so the uplink must not
    // half-close it.
    crate::relay::drive_both(
        "XHTTP",
        upload(app_read, net_write, false),
        download(net_read, app_write),
    )
    .await;
}

async fn run_server_exchange(stream: BoxStream, app: tokio::io::DuplexStream) {
    let (app_read, app_write) = tokio::io::split(app);
    let (net_read, net_write) = tokio::io::split(stream);
    crate::relay::drive_both(
        "XHTTP server",
        download_request(net_read, app_write),
        upload_response(app_read, net_write),
    )
    .await;
}

async fn download_request<R, W>(net: R, mut app: W) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    copy_chunked(net, &mut app, "request").await?;
    app.shutdown()
        .await
        .map_err(|error| format!("XHTTP request close: {error}"))
}

/// Largest payload one outgoing HTTP/1.1 chunk carries.
const CHUNK_PAYLOAD: usize = 16 * 1024;
/// Room in front of the payload for the hex size line (16 digits + CRLF).
const CHUNK_HEAD_ROOM: usize = 18;

/// Decode an HTTP/1.1 chunked body from `net` into `app`, up to and including
/// the terminating zero-size chunk.
///
/// The chunk size is peer-controlled. It used to size a `vec![0; size]`, so a
/// single `ffffffffffff` size line made the process try to allocate
/// terabytes and abort; chunk data is now streamed through a fixed buffer.
/// `net` is wrapped in a `BufReader` because the size lines are parsed a byte
/// at a time, which on a raw socket was one syscall per byte.
async fn copy_chunked<R, W>(net: R, app: &mut W, what: &str) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut net = tokio::io::BufReader::with_capacity(32 * 1024, net);
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        let size_line = read_line(&mut net).await?;
        let size = u64::from_str_radix(size_line.split(';').next().unwrap_or_default().trim(), 16)
            .map_err(|_| format!("XHTTP invalid {what} chunk size"))?;
        if size == 0 {
            // Trailer section: header lines until the empty line.
            while !read_line(&mut net).await?.is_empty() {}
            return Ok(());
        }
        let mut remaining = size;
        while remaining > 0 {
            let want = buffer
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            let n = net
                .read(&mut buffer[..want])
                .await
                .map_err(|error| format!("XHTTP {what} chunk body: {error}"))?;
            if n == 0 {
                return Err(format!("XHTTP {what} chunk body ended early"));
            }
            app.write_all(&buffer[..n])
                .await
                .map_err(|error| format!("XHTTP {what} app write: {error}"))?;
            remaining -= n as u64;
        }
        let mut crlf = [0u8; 2];
        net.read_exact(&mut crlf)
            .await
            .map_err(|error| format!("XHTTP {what} chunk terminator: {error}"))?;
        if crlf != *b"\r\n" {
            return Err(format!("XHTTP {what} chunk missing CRLF"));
        }
    }
}

/// Encode `app` as an HTTP/1.1 chunked body on `net`, ending with the zero
/// chunk once `app` reaches EOF.
///
/// Each chunk goes out as a single write — size line, payload and CRLF
/// together. Three separate writes put three TLS records (one of them a six
/// byte size line) on the wire per chunk: triple the record overhead and a
/// very recognisable pattern.
async fn copy_to_chunked<R, W>(mut app: R, net: &mut W, what: &str) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut frame = vec![0u8; CHUNK_HEAD_ROOM + CHUNK_PAYLOAD + 2];
    loop {
        let n = app
            .read(&mut frame[CHUNK_HEAD_ROOM..CHUNK_HEAD_ROOM + CHUNK_PAYLOAD])
            .await
            .map_err(|error| format!("XHTTP {what} read: {error}"))?;
        if n == 0 {
            net.write_all(b"0\r\n\r\n")
                .await
                .map_err(|error| format!("XHTTP {what} close: {error}"))?;
            return net
                .flush()
                .await
                .map_err(|error| format!("XHTTP {what} flush: {error}"));
        }
        let head = format!("{n:X}\r\n");
        let start = CHUNK_HEAD_ROOM - head.len();
        frame[start..CHUNK_HEAD_ROOM].copy_from_slice(head.as_bytes());
        let end = CHUNK_HEAD_ROOM + n;
        frame[end..end + 2].copy_from_slice(b"\r\n");
        net.write_all(&frame[start..end + 2])
            .await
            .map_err(|error| format!("XHTTP {what} chunk: {error}"))?;
        net.flush()
            .await
            .map_err(|error| format!("XHTTP {what} flush: {error}"))?;
    }
}

async fn upload_response<R, W>(app: R, mut net: W) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    copy_to_chunked(app, &mut net, "response").await
}

/// Stream the uplink as a chunked request body.
///
/// `shutdown_after` half-closes the socket once the terminating chunk is out.
/// That is only right when the socket carries nothing else: on stream-one the
/// same connection still carries the response, and a Go `net/http` server
/// (Xray) treats the client's FIN/close_notify as a disconnect and cancels
/// the download the moment the client finished uploading.
async fn upload<R, W>(app: R, mut net: W, shutdown_after: bool) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    copy_to_chunked(app, &mut net, "uplink").await?;
    if shutdown_after {
        net.shutdown()
            .await
            .map_err(|error| format!("XHTTP uplink shutdown: {error}"))?;
    }
    Ok(())
}

async fn download<R, W>(mut net: R, app: W) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let head = read_head(&mut net).await?;
    download_body(net, app, &head).await
}

/// Whether a response head announces chunked transfer encoding.
fn response_is_chunked(head: &str) -> bool {
    head.lines().any(|line| {
        line.split_once(':')
            .map(|(key, value)| {
                key.eq_ignore_ascii_case("transfer-encoding")
                    && value.to_ascii_lowercase().contains("chunked")
            })
            .unwrap_or(false)
    })
}

/// Stream a response body whose head has already been consumed.
///
/// The head is still needed here: it carries the framing, and losing it would
/// leave a `Content-Length` response with no way to know where it ends.
async fn download_body<R, W>(mut net: R, mut app: W, head: &str) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if response_is_chunked(head) {
        copy_chunked(net, &mut app, "downlink").await?;
    } else {
        let length = head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<u64>().ok())
                .flatten()
        });
        if let Some(length) = length {
            // Streamed, not preallocated: the length is the server's to pick.
            let copied = tokio::io::copy(&mut (&mut net).take(length), &mut app)
                .await
                .map_err(|error| format!("XHTTP fixed downlink: {error}"))?;
            if copied != length {
                return Err("XHTTP fixed response ended early".into());
            }
        } else {
            tokio::io::copy(&mut net, &mut app)
                .await
                .map_err(|error| format!("XHTTP raw downlink: {error}"))?;
        }
    }
    // The response is complete: pass the EOF on. Without this the application
    // never learns the server finished, and the logical stream hangs until
    // the application itself closes its uplink.
    app.shutdown()
        .await
        .map_err(|error| format!("XHTTP downlink close: {error}"))
}

async fn read_head<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String, String> {
    let mut bytes = Vec::with_capacity(1024);
    let mut one = [0u8; 1];
    loop {
        let n = reader
            .read(&mut one)
            .await
            .map_err(|error| format!("XHTTP response head: {error}"))?;
        if n == 0 {
            return Err("XHTTP closed before response headers".into());
        }
        bytes.extend_from_slice(&one[..n]);
        // Bytes arrive one at a time, so the terminator can only ever be at the
        // end. Rescanning the whole buffer per byte was quadratic in the head
        // size — a CPU sink for any peer that drips a long header.
        if bytes.ends_with(b"\r\n\r\n") {
            let position = bytes.len() - 4;
            let head = String::from_utf8(bytes[..position].to_vec())
                .map_err(|_| "XHTTP response headers are not UTF-8".to_string())?;
            let status = head.lines().next().unwrap_or_default();
            if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.1 206 ") {
                return Err(format!("XHTTP unexpected response status: {status}"));
            }
            return Ok(head);
        }
        if bytes.len() > MAX_RESPONSE_HEAD {
            return Err("XHTTP response headers exceed 64 KiB".into());
        }
    }
}

async fn read_request_head<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String, String> {
    let mut bytes = Vec::with_capacity(1024);
    let mut one = [0u8; 1];
    loop {
        reader
            .read_exact(&mut one)
            .await
            .map_err(|error| format!("XHTTP request head: {error}"))?;
        bytes.push(one[0]);
        // See `read_head`: only the tail can complete the terminator. This
        // runs before authentication, so the quadratic rescan it replaces was
        // reachable by anyone who could open a connection.
        if bytes.ends_with(b"\r\n\r\n") {
            let position = bytes.len() - 4;
            return String::from_utf8(bytes[..position].to_vec())
                .map_err(|_| "XHTTP request headers are not UTF-8".into());
        }
        if bytes.len() > MAX_RESPONSE_HEAD {
            return Err("XHTTP request headers exceed 64 KiB".into());
        }
    }
}

async fn read_line<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader
            .read_exact(&mut byte)
            .await
            .map_err(|error| format!("XHTTP chunk line: {error}"))?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return String::from_utf8(line).map_err(|_| "XHTTP chunk line is not UTF-8".into());
        }
        if line.len() > MAX_CHUNK_LINE {
            return Err("XHTTP chunk line exceeds the limit".into());
        }
    }
}

// Keep the stream type visibly AsyncRead/AsyncWrite in rustdoc and prevent a
// future refactor from accidentally turning this into a message protocol.
#[allow(dead_code)]
fn _stream_contract<T: AsyncRead + AsyncWrite + Unpin>(_: &T) {}

/// Keep-alive for XHTTP's HTTP/3 connections, matching Xray's
/// `QuicgoH3KeepAlivePeriod`.
const H3_KEEP_ALIVE: Duration = Duration::from_secs(10);
/// Idle timeout for XHTTP's HTTP/3 connections, matching Xray's
/// `ConnIdleTimeout`. quinn's default is 30 s with no keep-alive, which
/// dropped any proxied connection that stayed quiet for half a minute.
const H3_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Open a QUIC connection for an HTTP/3 XHTTP leg, trying each address.
async fn h3_connect(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    label: &str,
) -> Result<(h3_quinn::quinn::Endpoint, h3_quinn::quinn::Connection), String> {
    let first = addrs
        .first()
        .ok_or_else(|| format!("{label} has no resolved endpoint"))?;
    let mut tls = tls.clone();
    tls.alpn = vec![b"h3".to_vec()];
    let rustls = zero_security::try_client_config(&tls)
        .map_err(|error| format!("{label} TLS configuration: {error}"))?;
    let crypto = h3_quinn::quinn::crypto::rustls::QuicClientConfig::try_from((*rustls).clone())
        .map_err(|error| format!("{label} TLS configuration: {error}"))?;
    let mut client_config = h3_quinn::quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(crate::relay::quic_transport(
        H3_IDLE_TIMEOUT,
        Some(H3_KEEP_ALIVE),
    )));
    let bind: SocketAddr = if first.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = crate::relay::protected_client_endpoint(bind)
        .map_err(|error| format!("{label} endpoint: {error}"))?;
    endpoint.set_default_client_config(client_config);
    let mut last_error = None;
    for address in addrs {
        match endpoint.connect(*address, &tls.server_name) {
            Ok(connecting) => match connecting.await {
                Ok(connection) => return Ok((endpoint, connection)),
                Err(error) => last_error = Some(error.to_string()),
            },
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    Err(format!(
        "{label} connect failed: {}",
        last_error.unwrap_or_else(|| "no candidate succeeded".into())
    ))
}

/// Run an HTTP/3 client's request work alongside its connection driver.
///
/// The driver only resolves once the connection closes, and h3 closes the
/// connection when the last `SendRequest` is dropped. Joining the two — as
/// this used to — meant the handle could only be dropped after the driver
/// finished, so every finished stream kept its task, QUIC connection and UDP
/// socket alive until the idle timeout. Here the work runs to completion
/// (or the connection dies first) and then the caller drops the handle.
async fn run_with_h3_driver<C, B, F>(driver: &mut h3::client::Connection<C, B>, work: F)
where
    C: h3::quic::Connection<B>,
    B: Buf,
    F: Future<Output = ()>,
{
    tokio::select! {
        () = work => {}
        error = driver.wait_idle() => {
            tracing::debug!(%error, "XHTTP HTTP/3 connection closed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn path_matching_accepts_xray_prefix_forms_without_crossing_a_name_boundary() {
        assert!(path_matches("/service", "/service"));
        assert!(path_matches("/service", "/service/"));
        assert!(path_matches("/service", "/service/session"));
        assert!(path_matches("/", "/anything"));
        assert!(!path_matches("/service", "/service-evil"));
    }

    #[test]
    fn packet_paths_require_one_session_and_optional_decimal_sequence() {
        assert_eq!(
            packet_parts_from_path("/packet/session", "/packet"),
            Some(("session".to_string(), None))
        );
        assert_eq!(
            packet_parts_from_path("/packet/session/7", "/packet"),
            Some(("session".to_string(), Some(7)))
        );
        assert_eq!(
            packet_download_session_from_path("/packet/session", "/packet"),
            Some("session".to_string())
        );
        assert!(packet_download_session_from_path("/packet/session/7", "/packet").is_none());
        assert!(packet_parts_from_path("/packet/session/nope", "/packet").is_none());
        assert!(packet_parts_from_path("/packet/session/1/extra", "/packet").is_none());
    }

    #[tokio::test]
    async fn packet_hub_reorders_and_rejects_duplicate_sequences() {
        let hub = PacketHub::new();
        let mut received = hub.open("session".into()).await.unwrap();
        assert!(hub.open("session".into()).await.is_err());
        hub.deliver("session", 1, b"second".to_vec()).await.unwrap();
        hub.deliver("session", 0, b"first".to_vec()).await.unwrap();
        assert_eq!(received.recv().await.as_deref(), Some(b"first".as_slice()));
        assert_eq!(received.recv().await.as_deref(), Some(b"second".as_slice()));
        assert!(hub
            .deliver("session", 1, b"duplicate".to_vec())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn streams_chunked_upload_and_download() {
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            assert!(std::str::from_utf8(&request)
                .unwrap()
                .starts_with("POST /x"));
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                server.read_exact(&mut byte).await.unwrap();
                line.push(byte[0]);
            }
            assert_eq!(&line[..line.len() - 2], b"4");
            let mut body = [0u8; 6];
            server.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"ping\r\n");
            server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nreply\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let mut stream = connect(
            zero_core::boxed(client),
            &WsConfig::new("/x", "example.com"),
        )
        .await
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"reply");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn stream_one_response_end_reaches_the_application_as_eof() {
        // The server finishes its response while the client's upload is still
        // open. The application must see EOF on the download instead of
        // waiting for its own uplink to close first.
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            let head = read_request_head(&mut server).await.unwrap();
            assert!(head.starts_with("POST /x"));
            server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nreply\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
            // Hold the connection open, and prove the client did not
            // half-close it just because the download ended.
            let mut byte = [0u8; 1];
            tokio::select! {
                _ = release_rx => {}
                read = server.read(&mut byte) => panic!("unexpected client read: {read:?}"),
            }
        });
        let mut stream = connect(
            zero_core::boxed(client),
            &WsConfig::new("/x", "example.com"),
        )
        .await
        .unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut got))
            .await
            .expect("download EOF must reach the application")
            .unwrap();
        assert_eq!(got, b"reply");
        release_tx.send(()).unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn h2_stream_one_response_end_reaches_the_application_as_eof() {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
            let response = http::Response::builder().status(200).body(()).unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from_static(b"reply"), true).unwrap();
            // Keep driving the connection; the request body stays open.
            while let Some(result) = connection.accept().await {
                drop(result);
            }
        });
        let mut stream = connect_h2(
            zero_core::boxed(client),
            &WsConfig::new("/x", "example.com"),
        )
        .await
        .unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut got))
            .await
            .expect("download EOF must reach the application")
            .unwrap();
        assert_eq!(got, b"reply");
        server_task.abort();
    }

    #[tokio::test]
    async fn hostile_chunk_size_is_streamed_not_allocated() {
        // A chunk size of ~140 TB used to become `vec![0; size]` and abort
        // the process. It must now fail as a short body.
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let accept_task = tokio::spawn(async move {
            accept(zero_core::boxed(server), &WsConfig::new("/x", "h"))
                .await
                .unwrap()
        });
        client
            .write_all(
                b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n7fffffffffff\r\nabc",
            )
            .await
            .unwrap();
        let mut app = accept_task.await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), app.read_to_end(&mut got))
            .await
            .expect("a truncated hostile chunk must end the stream");
        assert_eq!(got, b"abc");
    }

    #[tokio::test]
    async fn duplicate_split_leg_does_not_evict_the_parked_one() {
        let hub: SharedSplitHub = Arc::new(SplitHub::new());
        let session = "s1".to_string();
        let pair = |upload: BoxStream, _download: BoxStream| async move { Ok(upload) };

        let parked_hub = Arc::clone(&hub);
        let parked_session = session.clone();
        let parked = tokio::spawn(async move {
            let (leg, _peer) = tokio::io::duplex(64);
            let result = split_rendezvous(
                &parked_hub,
                H2LegKind::Download,
                parked_session,
                zero_core::boxed(leg),
                pair,
                "test",
            )
            .await;
            (result.map(|app| app.is_some()), _peer)
        });
        while !hub.sessions.lock().await.contains_key(&session) {
            tokio::task::yield_now().await;
        }

        let (duplicate, _d) = tokio::io::duplex(64);
        let error = split_rendezvous(
            &hub,
            H2LegKind::Download,
            session.clone(),
            zero_core::boxed(duplicate),
            pair,
            "test",
        )
        .await;
        assert!(error.is_err(), "a second download leg must be refused");

        let (upload, _u) = tokio::io::duplex(64);
        let paired = split_rendezvous(
            &hub,
            H2LegKind::Upload,
            session.clone(),
            zero_core::boxed(upload),
            pair,
            "test",
        )
        .await
        .unwrap();
        assert!(paired.is_none());
        let (parked_result, _peer) = parked.await.unwrap();
        assert_eq!(parked_result, Ok(true), "the parked leg must still pair");
    }

    #[tokio::test]
    async fn h2_stream_one_preserves_bidirectional_bytes_and_flow_control() {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            while let Some(result) = connection.accept().await {
                tokio::spawn(async move {
                    let (request, mut respond) = result.unwrap();
                    assert_eq!(request.method(), "POST");
                    // Xray normalises the path with a trailing slash.
                    assert_eq!(request.uri().path(), "/x/");
                    let mut body = request.into_body();
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        let length = chunk.len();
                        body.flow_control().release_capacity(length).unwrap();
                        if !chunk.is_empty() {
                            send.send_data(Bytes::from_static(b"reply"), true).unwrap();
                            break;
                        }
                    }
                });
            }
        });

        let mut stream = connect_h2(
            zero_core::boxed(client),
            &WsConfig::new("/x", "example.com"),
        )
        .await
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        server_task.abort();
    }

    #[tokio::test]
    async fn accepts_h2_stream_one_and_relays_bidirectional_bytes() {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let server_config = WsConfig::new("/x", "edge.example");
        let server_task = tokio::spawn(async move {
            let mut app = accept_h2(zero_core::boxed(server), &server_config)
                .await
                .unwrap();
            let mut request = [0u8; 4];
            app.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            app.write_all(b"reply").await.unwrap();
            app.flush().await.unwrap();
        });
        let mut app = connect_h2(
            zero_core::boxed(client),
            &WsConfig::new("/x", "edge.example"),
        )
        .await
        .unwrap();
        app.write_all(b"ping").await.unwrap();
        app.flush().await.unwrap();
        let mut response = [0u8; 5];
        app.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"reply");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn accepts_stream_one_and_relays_chunked_body() {
        let (client, server) = tokio::io::duplex(32 * 1024);
        let server_config = WsConfig::new("/x", "edge.example");
        let server_task = tokio::spawn(async move {
            let mut app = accept(zero_core::boxed(server), &server_config)
                .await
                .unwrap();
            let mut request = [0u8; 4];
            app.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            app.write_all(b"reply").await.unwrap();
            app.shutdown().await.unwrap();
        });

        let mut app = connect(
            zero_core::boxed(client),
            &WsConfig::new("/x", "edge.example"),
        )
        .await
        .unwrap();
        app.write_all(b"ping").await.unwrap();
        app.flush().await.unwrap();
        let mut response = [0u8; 5];
        app.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"reply");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn stream_up_pairs_independent_get_and_post_legs() {
        let (client_upload, server_upload) = tokio::io::duplex(32 * 1024);
        let (client_download, server_download) = tokio::io::duplex(32 * 1024);
        let config = WsConfig::new("/split", "edge.example");
        let hub = Arc::new(SplitHub::new());
        let server_config = config.clone();
        let server_hub = Arc::clone(&hub);
        let upload_task = tokio::spawn(async move {
            accept_stream_up(zero_core::boxed(server_upload), &server_config, &server_hub)
                .await
                .unwrap()
        });
        let server_config = config.clone();
        let server_hub = Arc::clone(&hub);
        let download_task = tokio::spawn(async move {
            accept_stream_up(
                zero_core::boxed(server_download),
                &server_config,
                &server_hub,
            )
            .await
            .unwrap()
        });

        let mut client = connect_stream_up(
            zero_core::boxed(client_upload),
            zero_core::boxed(client_download),
            &config,
            &config,
        )
        .await
        .unwrap();
        let upload_result = upload_task.await.unwrap();
        let download_result = download_task.await.unwrap();
        let mut server = upload_result.or(download_result).expect("download leg");

        let server_task = tokio::spawn(async move {
            let mut request = [0u8; 4];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            server.write_all(b"pong").await.unwrap();
            server.flush().await.unwrap();
        });
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn h2_stream_up_pairs_independent_get_and_post_legs() {
        let (client_upload, server_upload) = tokio::io::duplex(64 * 1024);
        let (client_download, server_download) = tokio::io::duplex(64 * 1024);
        let config = WsConfig::new("/split", "edge.example");
        let hub = Arc::new(SplitHub::new());
        let server_config = config.clone();
        let server_hub = Arc::clone(&hub);
        let upload_task = tokio::spawn(async move {
            accept_stream_up_h2(zero_core::boxed(server_upload), &server_config, &server_hub)
                .await
                .unwrap()
        });
        let server_config = config.clone();
        let server_hub = Arc::clone(&hub);
        let download_task = tokio::spawn(async move {
            accept_stream_up_h2(
                zero_core::boxed(server_download),
                &server_config,
                &server_hub,
            )
            .await
            .unwrap()
        });

        let mut client = connect_stream_up_h2(
            zero_core::boxed(client_upload),
            zero_core::boxed(client_download),
            &config,
            &config,
        )
        .await
        .unwrap();
        // The paired stream comes out of the download leg's connection; the
        // upload leg's connection stays open for further requests.
        let mut server = download_task.await.unwrap().expect("download leg");
        let _upload_connection = upload_task;

        let server_task = tokio::spawn(async move {
            let mut request = [0u8; 4];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            server.write_all(b"pong").await.unwrap();
            server.flush().await.unwrap();
        });
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn packet_up_uses_fixed_length_posts_and_persistent_download() {
        let (client_download, server_download) = tokio::io::duplex(32 * 1024);
        let config = WsConfig::new("/packet", "edge.example");
        let hub = Arc::new(PacketHub::new());
        let server_config = config.clone();
        let server_hub = Arc::clone(&hub);
        let download_task = tokio::spawn(async move {
            accept_packet_up(
                zero_core::boxed(server_download),
                &server_config,
                &server_hub,
            )
            .await
            .unwrap()
            .expect("download leg")
        });
        let dial_config = config.clone();
        let dial_hub = Arc::clone(&hub);
        let dialer: PacketDialer = Arc::new(move || {
            let config = dial_config.clone();
            let hub = Arc::clone(&dial_hub);
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(16 * 1024);
                tokio::spawn(async move {
                    accept_packet_up(zero_core::boxed(server), &config, &hub)
                        .await
                        .unwrap();
                });
                Ok(zero_core::boxed(client))
            })
        });
        let mut client =
            connect_packet_up(zero_core::boxed(client_download), &config, &config, dialer)
                .await
                .unwrap();
        let mut server = download_task.await.unwrap();
        let server_task = tokio::spawn(async move {
            let mut request = [0u8; 4];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            server.write_all(b"pong").await.unwrap();
            server.flush().await.unwrap();
        });
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn h2_packet_up_posts_ride_the_download_connection() {
        let (client_download, server_download) = tokio::io::duplex(64 * 1024);
        let config = WsConfig::new("/packet", "edge.example");
        let hub = Arc::new(PacketHub::new());
        let server_config = config.clone();
        let server_hub = Arc::clone(&hub);
        let download_task = tokio::spawn(async move {
            accept_packet_up_h2(
                zero_core::boxed(server_download),
                &server_config,
                &server_hub,
            )
            .await
            .unwrap()
            .expect("download leg")
        });
        // Uploads share the download's connection, as Xray's do.
        let mut client =
            connect_packet_up_h2(zero_core::boxed(client_download), &config, &config, None)
                .await
                .unwrap();
        let mut server = download_task.await.unwrap();
        let server_task = tokio::spawn(async move {
            let mut request = [0u8; 4];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            server.write_all(b"pong").await.unwrap();
            server.flush().await.unwrap();
        });
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server_task.await.unwrap();
    }
}
