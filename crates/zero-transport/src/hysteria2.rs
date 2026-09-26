//! Hysteria2 TCP-over-QUIC control and stream framing.
//!
//! This module owns the QUIC carrier and the small HTTP/3 authentication
//! exchange. The runtime supplies routing after the target is announced.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::Request;
use tokio::io::duplex;
use tokio::time::{timeout, Duration};
use zero_core::{boxed, BoxStream, Destination};

const TCP_REQUEST: u64 = 0x401;
const UDP_SESSION_HEADER: usize = 8;
const AUTH_URI: &str = "https://hysteria/auth";
const AUTH_STATUS: u16 = 233;

fn encode_varint(value: u64) -> Result<Vec<u8>, String> {
    if value < (1 << 6) {
        Ok(vec![value as u8])
    } else if value < (1 << 14) {
        let mut bytes = (value as u16).to_be_bytes();
        bytes[0] |= 0x40;
        Ok(bytes.to_vec())
    } else if value < (1 << 30) {
        let mut bytes = (value as u32).to_be_bytes();
        bytes[0] |= 0x80;
        Ok(bytes.to_vec())
    } else if value < (1 << 62) {
        let mut bytes = value.to_be_bytes();
        bytes[0] |= 0xc0;
        Ok(bytes.to_vec())
    } else {
        Err("Hysteria2 varint is too large".into())
    }
}

async fn read_byte(stream: &mut h3_quinn::quinn::RecvStream) -> Result<u8, String> {
    let mut byte = [0u8; 1];
    match stream.read(&mut byte).await {
        Ok(Some(1)) => Ok(byte[0]),
        Ok(Some(_)) => Err("Hysteria2 QUIC read returned an invalid length".into()),
        Ok(None) => Err("Hysteria2 stream ended while reading a varint".into()),
        Err(error) => Err(format!("Hysteria2 QUIC read: {error}")),
    }
}

async fn read_varint(stream: &mut h3_quinn::quinn::RecvStream) -> Result<u64, String> {
    let first = read_byte(stream).await?;
    let width = 1usize << (first >> 6);
    let mut value = (first & 0x3f) as u64;
    for _ in 1..width {
        value = (value << 8) | read_byte(stream).await? as u64;
    }
    Ok(value)
}

fn target_text(destination: &Destination) -> String {
    destination.authority()
}

pub fn encode_udp_datagram(
    session_id: u32,
    packet_id: u16,
    destination: &Destination,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if destination.network != zero_core::Network::Udp {
        return Err("Hysteria2 UDP framing requires a UDP destination".into());
    }
    let address = target_text(destination);
    if address.len() > 2048 {
        return Err("Hysteria2 UDP target authority is too long".into());
    }
    let address_len = encode_varint(address.len() as u64)?;
    let mut output =
        Vec::with_capacity(UDP_SESSION_HEADER + address_len.len() + address.len() + payload.len());
    output.extend_from_slice(&session_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.extend_from_slice(&[0, 1]);
    output.extend_from_slice(&address_len);
    output.extend_from_slice(address.as_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

fn decode_udp_datagram(bytes: &[u8]) -> Result<(u32, u16, Destination, Vec<u8>), String> {
    if bytes.len() < UDP_SESSION_HEADER {
        return Err("Hysteria2 UDP datagram is too short".into());
    }
    let session_id = u32::from_be_bytes(bytes[..4].try_into().unwrap());
    let packet_id = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
    let fragment_id = bytes[6];
    let fragment_count = bytes[7];
    if fragment_count == 0 || fragment_id >= fragment_count {
        return Err("Hysteria2 UDP fragment header is invalid".into());
    }
    if fragment_count != 1 {
        return Err("fragmented Hysteria2 UDP responses need a session reassembler".into());
    }
    let body = &bytes[UDP_SESSION_HEADER..];
    let (address_len, address_offset) = decode_varint_slice(body)?;
    // Offsets are relative to `body`. The bound check used to compare a
    // body-relative end against the length of the whole datagram, so an
    // address length reaching into the last eight bytes passed the check and
    // then panicked on the slice — from a single hostile datagram.
    let address_end = usize::try_from(address_len)
        .ok()
        .and_then(|len| address_offset.checked_add(len))
        .ok_or_else(|| "Hysteria2 UDP address length overflow".to_string())?;
    let address = body
        .get(address_offset..address_end)
        .ok_or_else(|| "Hysteria2 UDP address is truncated".to_string())?;
    let address = std::str::from_utf8(address).map_err(|_| "Hysteria2 UDP address is not UTF-8")?;
    let destination = Destination::parse(address, zero_core::Network::Udp)
        .ok_or_else(|| "Hysteria2 UDP address is invalid".to_string())?;
    Ok((
        session_id,
        packet_id,
        destination,
        body[address_end..].to_vec(),
    ))
}

fn decode_varint_slice(bytes: &[u8]) -> Result<(u64, usize), String> {
    let first = *bytes
        .first()
        .ok_or_else(|| "Hysteria2 UDP address length is missing".to_string())?;
    let width = 1usize << (first >> 6);
    if bytes.len() < width {
        return Err("Hysteria2 UDP address length is truncated".into());
    }
    let mut value = (first & 0x3f) as u64;
    for byte in &bytes[1..width] {
        value = (value << 8) | *byte as u64;
    }
    Ok((value, width))
}

/// The pooled, authenticated connection to a Hysteria2 server (see
/// [`crate::quic_pool`]).
async fn pooled(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    password: &str,
) -> Result<(String, std::sync::Arc<crate::quic_pool::Pooled>), String> {
    let key = crate::quic_pool::key("hysteria2", addrs, tls, password.as_bytes());
    let pooled = crate::quic_pool::get(&key, || connect_resumed(addrs, tls, password)).await?;
    Ok((key, pooled))
}

/// Connect and authenticate, in 0-RTT when a session ticket from an earlier
/// connection allows it: the QUIC handshake and the HTTP/3 authentication
/// then share the first flight, and the connection is usable one round trip
/// sooner. A server that rejects the early data costs one more attempt, in
/// ordinary 1-RTT.
async fn connect_resumed(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    password: &str,
) -> Result<(h3_quinn::quinn::Endpoint, h3_quinn::quinn::Connection), String> {
    match connect_authenticated_with(addrs, tls, password, true).await {
        Err(error) if error.contains(ZERO_RTT_REJECTED) => {
            tracing::debug!(%error, "Hysteria2 0-RTT rejected; reconnecting in 1-RTT");
            connect_authenticated_with(addrs, tls, password, false).await
        }
        other => other,
    }
}

/// Marker in the error of an attempt whose early data the server refused.
const ZERO_RTT_REJECTED: &str = "0-RTT rejected";

static ZERO_RTT_ACCEPTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Connections that were set up in 0-RTT and whose early data the server
/// took, since the process started (for tests and diagnostics).
pub fn zero_rtt_accepted() -> usize {
    ZERO_RTT_ACCEPTED.load(std::sync::atomic::Ordering::Relaxed)
}

async fn connect_authenticated_with(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    password: &str,
    early: bool,
) -> Result<(h3_quinn::quinn::Endpoint, h3_quinn::quinn::Connection), String> {
    if addrs.is_empty() {
        return Err("Hysteria2 has no resolved endpoint".into());
    }
    let mut tls = tls.clone();
    tls.alpn = vec![b"h3".to_vec()];
    let rustls = zero_security::try_client_config(&tls)
        .map_err(|error| format!("Hysteria2 TLS configuration: {error}"))?;
    // The cached configuration shares its session store with every clone,
    // so a ticket from one connection resumes the next.
    let mut rustls = (*rustls).clone();
    rustls.enable_early_data = early;
    let crypto = h3_quinn::quinn::crypto::rustls::QuicClientConfig::try_from(rustls)
        .map_err(|error| format!("Hysteria2 TLS configuration: {error}"))?;
    let mut client_config = h3_quinn::quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(crate::relay::quic_transport(
        CLIENT_IDLE_TIMEOUT,
        Some(CLIENT_KEEP_ALIVE),
    )));
    let bind: SocketAddr = if addrs.first().is_some_and(SocketAddr::is_ipv6) {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = crate::relay::protected_client_endpoint(bind)
        .map_err(|error| format!("Hysteria2 endpoint: {error}"))?;
    endpoint.set_default_client_config(client_config);
    let mut last_error = None;
    let mut connection = None;
    // Resolves to whether the server took the early data, when there was any.
    let mut zero_rtt = None;
    for address in addrs {
        match endpoint.connect(*address, &tls.server_name) {
            Ok(connecting) => {
                let connecting = if early {
                    match connecting.into_0rtt() {
                        Ok((value, accepted)) => {
                            zero_rtt = Some(accepted);
                            connection = Some(value);
                            break;
                        }
                        // No ticket (yet): an ordinary handshake.
                        Err(connecting) => connecting,
                    }
                } else {
                    connecting
                };
                match connecting.await {
                    Ok(value) => {
                        connection = Some(value);
                        break;
                    }
                    Err(error) => last_error = Some(error.to_string()),
                }
            }
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    let connection = connection.ok_or_else(|| {
        format!(
            "Hysteria2 QUIC connect failed: {}",
            last_error.unwrap_or_else(|| "no candidate succeeded".into())
        )
    })?;
    let result = authenticate_client(&connection, password).await;
    if let Some(accepted) = zero_rtt {
        // The authentication went out as early data; it only counts if the
        // server took it. Rejected, the streams it used are gone.
        if !accepted.await {
            connection.close(0u32.into(), b"0-RTT rejected");
            return Err(format!("Hysteria2 {ZERO_RTT_REJECTED}"));
        }
        ZERO_RTT_ACCEPTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    result?;
    Ok((endpoint, connection))
}

/// The HTTP/3 authentication exchange on a fresh connection.
async fn authenticate_client(connection: &h3_quinn::quinn::Connection, password: &str) -> Result<(), String> {

    let (mut driver, mut requests) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|error| format!("Hysteria2 HTTP/3 setup: {error}"))?;
    let driver_hold = connection.clone();
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
        // Continuing to own `driver` past the idle point is the whole purpose
        // of this task. HTTP/3 goes idle as soon as the auth exchange ends, and
        // dropping the driver there shuts down the QUIC connection — the same
        // connection the proxied streams are about to use. Hold it until the
        // connection itself is finished.
        driver_hold.closed().await;
    });
    let request = Request::builder()
        .method("POST")
        .uri(AUTH_URI)
        .header("hysteria-auth", password)
        .body(())
        .map_err(|error| format!("Hysteria2 auth request: {error}"))?;
    let mut request_stream = requests
        .send_request(request)
        .await
        .map_err(|error| format!("Hysteria2 auth request: {error}"))?;
    request_stream
        .finish()
        .await
        .map_err(|error| format!("Hysteria2 auth finish: {error}"))?;
    let response = request_stream
        .recv_response()
        .await
        .map_err(|error| format!("Hysteria2 auth response: {error}"))?;
    if response.status() != http::StatusCode::from_u16(AUTH_STATUS).unwrap() {
        return Err(format!(
            "Hysteria2 authentication rejected: {}",
            response.status()
        ));
    }
    while request_stream
        .recv_data()
        .await
        .map_err(|error| format!("Hysteria2 auth response body: {error}"))?
        .is_some()
    {}

    // Hold the HTTP/3 request handle for as long as the QUIC connection lives.
    // Dropping the last `SendRequest` makes h3 shut the connection down, which
    // would take the proxied streams with it the instant authentication
    // succeeded.
    let held = connection.clone();
    tokio::spawn(async move {
        let _requests = requests;
        held.closed().await;
    });
    Ok(())
}

/// Send one Hysteria2 UDP datagram and wait for the matching response.
///
/// The QUIC connection is intentionally scoped to this exchange until the
/// runtime gains a per-outbound UDP session pool. The wire format still uses
/// the real session/packet/fragment header, so it interoperates with a peer
/// that accepts independent authenticated datagrams.
pub async fn exchange_udp(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    password: &str,
    destination: &Destination,
    payload: &[u8],
) -> Result<(Destination, Vec<u8>), String> {
    let mut last = String::new();
    // Once more on a fresh connection if the pooled one turns out dead.
    for attempt in 0..2 {
        let (key, pooled) = pooled(addrs, tls, password).await?;
        match exchange_on(&pooled, destination, payload).await {
            Ok(response) => return Ok(response),
            Err((error, retry)) => {
                if retry && attempt == 0 {
                    crate::quic_pool::evict(&key, &pooled);
                    last = error;
                    continue;
                }
                return Err(error);
            }
        }
    }
    Err(last)
}

/// The session a Hysteria2 UDP datagram belongs to.
fn udp_session(datagram: &[u8]) -> Option<u32> {
    datagram.get(..4).map(|id| u32::from_be_bytes(id.try_into().unwrap()))
}

/// One datagram exchange on a pooled connection. The error says whether a
/// fresh connection is worth trying (the connection itself failed).
async fn exchange_on(
    pooled: &std::sync::Arc<crate::quic_pool::Pooled>,
    destination: &Destination,
    payload: &[u8],
) -> Result<(Destination, Vec<u8>), (String, bool)> {
    let connection = &pooled.connection;
    let max_size = connection
        .max_datagram_size()
        .ok_or_else(|| ("Hysteria2 peer does not support QUIC datagrams".to_string(), false))?;
    let session_id = rand::random::<u32>();
    let packet_id = rand::random::<u16>();
    let datagram = encode_udp_datagram(session_id, packet_id, destination, payload).map_err(|e| (e, false))?;
    if datagram.len() > max_size {
        return Err(("Hysteria2 UDP payload exceeds the negotiated datagram size".into(), false));
    }
    let mut registration = pooled.register(session_id, udp_session);
    connection
        .send_datagram(Bytes::from(datagram))
        .map_err(|error| (format!("Hysteria2 UDP send: {error}"), true))?;
    timeout(Duration::from_secs(5), async {
        while let Some(response) = registration.receiver.recv().await {
            if let Ok((sid, _, destination, payload)) = decode_udp_datagram(&response) {
                if sid == session_id {
                    return Ok((destination, payload));
                }
            }
        }
        Err(("Hysteria2 connection closed before the UDP response".to_string(), true))
    })
    .await
    .map_err(|_| ("Hysteria2 UDP response timed out".to_string(), false))?
}

/// Open one authenticated Hysteria2 TCP stream.
pub async fn connect(
    addrs: &[SocketAddr],
    tls: &zero_security::TlsParams,
    password: &str,
    destination: &Destination,
) -> Result<BoxStream, String> {
    if destination.network != zero_core::Network::Tcp {
        return Err("Hysteria2 TCP connect received a non-TCP destination".into());
    }
    // One implementation of the authenticated handshake, shared with the UDP
    // path. It was duplicated here, which is how a fix to one of them left the
    // other broken.
    // A stream on the server's pooled connection; a fresh connection when
    // the pooled one has died since it was last used.
    let mut opened = None;
    for attempt in 0..2 {
        let (key, pooled) = pooled(addrs, tls, password).await?;
        match pooled.connection.open_bi().await {
            Ok(pair) => {
                opened = Some((pooled.stream_guard(), pair));
                break;
            }
            Err(error) if attempt == 0 => {
                tracing::debug!(%error, "Hysteria2 pooled connection is gone; dialling anew");
                crate::quic_pool::evict(&key, &pooled);
            }
            Err(error) => return Err(format!("Hysteria2 TCP stream: {error}")),
        }
    }
    let (guard, (mut send, mut recv)) = opened.ok_or("Hysteria2 TCP stream: no connection")?;
    let target = target_text(destination);
    let target = target.as_bytes();
    if target.len() > 2048 {
        return Err("Hysteria2 target authority is too long".into());
    }
    let mut header = encode_varint(TCP_REQUEST)?;
    header.extend_from_slice(&encode_varint(target.len() as u64)?);
    header.extend_from_slice(target);
    header.extend_from_slice(&encode_varint(0)?);
    send.write_all(&header)
        .await
        .map_err(|error| format!("Hysteria2 TCP request: {error}"))?;
    let status = read_byte(&mut recv).await?;
    let message_len = read_varint(&mut recv).await?;
    if message_len > 4096 {
        return Err("Hysteria2 response message is too large".into());
    }
    let mut message = vec![0u8; message_len as usize];
    recv.read_exact(&mut message)
        .await
        .map_err(|error| format!("Hysteria2 response message: {error}"))?;
    let padding_len = read_varint(&mut recv).await?;
    if padding_len > 4096 {
        return Err("Hysteria2 response padding is too large".into());
    }
    let mut padding = vec![0u8; padding_len as usize];
    recv.read_exact(&mut padding)
        .await
        .map_err(|error| format!("Hysteria2 response padding: {error}"))?;
    if status != 0 {
        return Err(format!(
            "Hysteria2 TCP request rejected: {}",
            String::from_utf8_lossy(&message)
        ));
    }
    let (app, worker) = duplex(128 * 1024);
    tokio::spawn(async move {
        crate::relay::bridge_quic_stream(worker, send, recv, "Hysteria2").await;
        // The connection stays in the pool for the next stream.
        drop(guard);
    });
    Ok(boxed(app))
}

pub enum Accepted {
    Tcp {
        stream: BoxStream,
        destination: Destination,
        peer: SocketAddr,
    },
    Udp {
        connection: h3_quinn::quinn::Connection,
        session_id: u32,
        packet_id: u16,
        destination: Destination,
        payload: Vec<u8>,
        peer: SocketAddr,
    },
}

/// Client keep-alive; the Hysteria2 reference client uses 10 s.
const CLIENT_KEEP_ALIVE: Duration = Duration::from_secs(10);
/// Client idle timeout.
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Bound on the QUIC handshake plus HTTP/3 authentication of one connection.
const SERVER_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on reading one TCP request header once its stream is open.
const SERVER_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Accepted streams and datagrams queued for the runtime.
const ACCEPT_QUEUE: usize = 64;

/// Accepts Hysteria2 connections and yields every proxy stream and UDP
/// datagram they carry.
///
/// Each QUIC connection is handshaken, authenticated and served on its own
/// task. The previous free `accept` function did all of that inline and only
/// ever took the *first* stream or datagram of a connection: one client that
/// completed the QUIC handshake and then went quiet stalled the whole
/// inbound (there was no timeout), and a spec-conforming client multiplexing
/// several streams over one connection had all but the first ignored.
pub struct Acceptor {
    endpoint: h3_quinn::quinn::Endpoint,
    accepted: tokio::sync::mpsc::Receiver<Result<Accepted, String>>,
    sender: tokio::sync::mpsc::Sender<Result<Accepted, String>>,
}

impl Acceptor {
    pub fn new(endpoint: h3_quinn::quinn::Endpoint) -> Self {
        let (sender, accepted) = tokio::sync::mpsc::channel(ACCEPT_QUEUE);
        Self {
            endpoint,
            accepted,
            sender,
        }
    }

    /// Wait for the next proxy stream or datagram. `Err` reports one rejected
    /// connection or request and is not fatal; `Ok(None)` means the endpoint
    /// closed. `passwords` applies to connections accepted from this call on.
    pub async fn accept(&mut self, passwords: &[Box<str>]) -> Result<Option<Accepted>, String> {
        let passwords: Arc<[Box<str>]> = passwords.into();
        loop {
            tokio::select! {
                biased;
                item = self.accepted.recv() => {
                    // `self.sender` keeps the channel open, so `None` cannot
                    // happen; treat it as a closed endpoint regardless.
                    return match item {
                        Some(item) => item.map(Some),
                        None => Ok(None),
                    };
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return Ok(None);
                    };
                    tokio::spawn(serve_connection(
                        incoming,
                        Arc::clone(&passwords),
                        self.sender.clone(),
                    ));
                }
            }
        }
    }
}

async fn serve_connection(
    incoming: h3_quinn::quinn::Incoming,
    passwords: Arc<[Box<str>]>,
    out: tokio::sync::mpsc::Sender<Result<Accepted, String>>,
) {
    let authenticated = timeout(
        SERVER_AUTH_TIMEOUT,
        authenticate_connection(incoming, &passwords),
    )
    .await
    .unwrap_or_else(|_| Err("Hysteria2 handshake or authentication timed out".into()));
    let connection = match authenticated {
        Ok(connection) => connection,
        Err(error) => {
            let _ = out.send(Err(error)).await;
            return;
        }
    };
    let peer = connection.remote_address();
    loop {
        tokio::select! {
            result = connection.accept_bi() => {
                let Ok((send, recv)) = result else {
                    // The connection is closed or lost; its streams are done.
                    return;
                };
                let out = out.clone();
                tokio::spawn(async move {
                    let accepted =
                        timeout(SERVER_REQUEST_TIMEOUT, accept_tcp_stream(send, recv, peer))
                            .await
                            .unwrap_or_else(|_| Err("Hysteria2 TCP request timed out".into()));
                    let _ = out.send(accepted).await;
                });
            }
            result = connection.read_datagram() => {
                let Ok(data) = result else {
                    return;
                };
                let accepted = decode_udp_datagram(&data).map(
                    |(session_id, packet_id, destination, payload)| Accepted::Udp {
                        connection: connection.clone(),
                        session_id,
                        packet_id,
                        destination,
                        payload,
                        peer,
                    },
                );
                if out.send(accepted).await.is_err() {
                    return;
                }
            }
            () = out.closed() => {
                connection.close(0u32.into(), b"server stopped");
                return;
            }
        }
    }
}

/// Complete the QUIC handshake and the HTTP/3 authentication exchange.
async fn authenticate_connection(
    incoming: h3_quinn::quinn::Incoming,
    passwords: &[Box<str>],
) -> Result<h3_quinn::quinn::Connection, String> {
    let connection = incoming
        .await
        .map_err(|error| format!("Hysteria2 QUIC handshake: {error}"))?;
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
        h3::server::Connection::new(h3_connection)
            .await
            .map_err(|error| format!("Hysteria2 HTTP/3 setup: {error}"))?;
    let resolver = h3_conn
        .accept()
        .await
        .map_err(|error| format!("Hysteria2 auth accept: {error}"))?
        .ok_or_else(|| "Hysteria2 auth stream ended".to_string())?;
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|error| format!("Hysteria2 auth request: {error}"))?;
    let valid = request.method() == http::Method::POST
        && request.uri() == AUTH_URI
        && request
            .headers()
            .get("hysteria-auth")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| passwords.iter().any(|password| password.as_ref() == value));
    let response = http::Response::builder()
        .status(if valid { AUTH_STATUS } else { 404 })
        .body(())
        .map_err(|error| format!("Hysteria2 auth response: {error}"))?;
    stream
        .send_response(response)
        .await
        .map_err(|error| format!("Hysteria2 auth response: {error}"))?;
    stream
        .finish()
        .await
        .map_err(|error| format!("Hysteria2 auth finish: {error}"))?;
    if !valid {
        return Err("Hysteria2 authentication failed".into());
    }
    // Authentication is the only thing HTTP/3 is used for. From here on, every
    // bidirectional stream on this connection is a Hysteria2 proxy stream, so
    // the HTTP/3 side must stop accepting: a `Connection::accept` loop and the
    // protocol's own `accept_bi` are two consumers of the *same* quinn accept
    // queue, and whichever wins decides whether the tunnel works.
    //
    // The object is still held rather than dropped, because dropping it closes
    // the QUIC connection that the proxy streams need.
    let h3_hold = connection.clone();
    tokio::spawn(async move {
        let _h3_conn = h3_conn;
        h3_hold.closed().await;
    });
    Ok(connection)
}

/// Read one TCP request from a freshly accepted stream and answer it.
async fn accept_tcp_stream(
    mut send: h3_quinn::quinn::SendStream,
    mut recv: h3_quinn::quinn::RecvStream,
    peer: SocketAddr,
) -> Result<Accepted, String> {
    if read_varint(&mut recv).await? != TCP_REQUEST {
        return Err("invalid Hysteria2 TCP request type".into());
    }
    let address_len = read_varint(&mut recv).await?;
    if address_len > 2048 {
        return Err("Hysteria2 target authority is too long".into());
    }
    let mut address = vec![0u8; address_len as usize];
    recv.read_exact(&mut address)
        .await
        .map_err(|error| format!("Hysteria2 target: {error}"))?;
    let address = std::str::from_utf8(&address)
        .map_err(|_| "Hysteria2 target authority is not UTF-8".to_string())?;
    let destination = Destination::parse(address, zero_core::Network::Tcp)
        .ok_or_else(|| "Hysteria2 target authority is invalid".to_string())?;
    let padding_len = read_varint(&mut recv).await?;
    if padding_len > 4096 {
        return Err("Hysteria2 request padding is too large".into());
    }
    let mut padding = vec![0u8; padding_len as usize];
    recv.read_exact(&mut padding)
        .await
        .map_err(|error| format!("Hysteria2 request padding: {error}"))?;
    let response = [0u8, 0u8, 0u8];
    send.write_all(&response)
        .await
        .map_err(|error| format!("Hysteria2 TCP response: {error}"))?;
    let (app, worker) = duplex(128 * 1024);
    // The connection is shared by every stream the client opens, so the
    // bridge must not close it when this one stream ends.
    tokio::spawn(crate::relay::bridge_quic_stream(
        worker,
        send,
        recv,
        "Hysteria2 server",
    ));
    Ok(Accepted::Tcp {
        stream: boxed(app),
        destination,
        peer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_hysteria_varints_in_the_shortest_form() {
        assert_eq!(encode_varint(0x3f).unwrap(), vec![0x3f]);
        assert_eq!(encode_varint(0x40).unwrap(), vec![0x40, 0x40]);
        assert_eq!(encode_varint(0x401).unwrap(), vec![0x44, 0x01]);
        assert_eq!(
            encode_varint(1 << 14).unwrap(),
            vec![0x80, 0x00, 0x40, 0x00]
        );
    }

    #[test]
    fn target_authority_preserves_domains_and_ipv6_brackets() {
        assert_eq!(
            target_text(&Destination::tcp(
                zero_core::Address::domain("example.com"),
                443
            )),
            "example.com:443"
        );
        assert_eq!(
            target_text(&Destination::tcp(
                zero_core::Address::from(std::net::Ipv6Addr::LOCALHOST),
                443
            )),
            "[::1]:443"
        );
    }

    #[test]
    fn udp_datagram_roundtrips_target_and_payload() {
        let destination = Destination::udp(zero_core::Address::domain("dns.example"), 53);
        let frame = encode_udp_datagram(0x1234_5678, 9, &destination, b"query").unwrap();
        let (session, packet, decoded, payload) = decode_udp_datagram(&frame).unwrap();
        assert_eq!(session, 0x1234_5678);
        assert_eq!(packet, 9);
        assert_eq!(decoded, destination);
        assert_eq!(payload, b"query");
    }

    #[test]
    fn udp_address_length_reaching_into_the_header_is_rejected_not_a_panic() {
        // 8 header bytes, length varint 15, then 11 bytes: the address end
        // (1 + 15 = 16) is within the 20-byte datagram but not within the
        // 12-byte body that follows the header.
        let mut frame = vec![0, 0, 0, 1, 0, 1, 0, 1, 15];
        frame.extend_from_slice(b"example.co:");
        assert_eq!(frame.len(), 20);
        assert!(decode_udp_datagram(&frame).is_err());
        // Every truncation of a valid datagram must fail cleanly too.
        let destination = Destination::udp(zero_core::Address::domain("dns.example"), 53);
        let valid = encode_udp_datagram(1, 1, &destination, b"").unwrap();
        for cut in 0..valid.len() {
            let _ = decode_udp_datagram(&valid[..cut]);
        }
    }

    #[test]
    fn udp_fragmented_response_is_rejected_until_reassembly_exists() {
        let destination = Destination::udp(zero_core::Address::domain("dns.example"), 53);
        let mut frame = encode_udp_datagram(1, 1, &destination, b"part").unwrap();
        frame[7] = 2;
        assert!(decode_udp_datagram(&frame).is_err());
    }
}
