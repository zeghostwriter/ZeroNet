//! A bounded gRPC byte-stream carrier over HTTP/2.
//!
//! Xray's gRPC transport carries the protocol stream in protobuf `Hunk`
//! messages. The application sees a normal `AsyncRead + AsyncWrite` stream;
//! this module owns HTTP/2, the five-byte gRPC envelope, and the `Hunk` wire
//! format.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::read::GzDecoder;
use http::Request;
use std::io::Read;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zero_core::BoxStream;

use crate::ws::WsConfig;

const MAX_MESSAGE: usize = 16 * 1024 * 1024;
const H2_FLOW_CONTROL_WINDOW: u32 = 4 * 1024 * 1024;

pub async fn connect(stream: BoxStream, config: &WsConfig) -> Result<BoxStream, String> {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(H2_FLOW_CONTROL_WINDOW)
        .initial_connection_window_size(H2_FLOW_CONTROL_WINDOW);
    let (mut sender, connection) = builder
        .handshake(stream)
        .await
        .map_err(|error| format!("gRPC HTTP/2 handshake: {error}"))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "gRPC HTTP/2 connection ended");
        }
    });
    sender = sender
        .ready()
        .await
        .map_err(|error| format!("gRPC stream capacity: {error}"))?;
    let request = Request::builder()
        .method("POST")
        .uri(&config.path)
        .header("host", &config.host)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-encoding", "identity")
        .header("grpc-accept-encoding", "gzip,identity")
        .body(())
        .map_err(|error| format!("gRPC request: {error}"))?;
    let (response, send) = sender
        .send_request(request, false)
        .map_err(|error| format!("gRPC request: {error}"))?;
    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(run_client(response, send, worker));
    Ok(zero_core::boxed(app))
}

/// Most streams one client may have open at once on a gRPC connection.
const MAX_CONCURRENT_STREAMS: u32 = 128;
/// Later streams waiting for the server to pick them up.
const PENDING_STREAMS: usize = 64;

/// Accept the first gRPC stream on a connection and nothing else.
///
/// Later streams are refused. Use [`accept_multi`] to serve them.
pub async fn accept(stream: BoxStream, config: &WsConfig) -> Result<BoxStream, String> {
    accept_multi(stream, config).await.map(|(first, _)| first)
}

/// Accept a gRPC connection: its first stream, plus every later one.
///
/// Xray's client keeps one HTTP/2 connection per server and opens a new
/// stream for every tunnel, so a server that only answered the first stream
/// broke every connection after it. Later streams arrive on the returned
/// channel, each already validated and bridged to a byte stream; dropping
/// the receiver refuses any further ones.
pub async fn accept_multi(
    stream: BoxStream,
    config: &WsConfig,
) -> Result<(BoxStream, tokio::sync::mpsc::Receiver<BoxStream>), String> {
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(H2_FLOW_CONTROL_WINDOW)
        .initial_connection_window_size(H2_FLOW_CONTROL_WINDOW)
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS);
    let mut connection = builder
        .handshake(stream)
        .await
        .map_err(|error| format!("gRPC HTTP/2 handshake: {error}"))?;
    let Some(result) = connection.accept().await else {
        return Err("gRPC client closed before opening a stream".into());
    };
    let (request, respond) = result.map_err(|error| format!("gRPC request: {error}"))?;
    let first = open_stream(request, respond, config)?;

    let (more_tx, more_rx) = tokio::sync::mpsc::channel(PENDING_STREAMS);
    let config = config.clone();
    // The driver must keep polling `accept` for the connection to make
    // progress at all, so it never waits on the channel: a stream nobody is
    // ready to take is refused rather than stalling every stream beside it.
    tokio::spawn(async move {
        while let Some(result) = connection.accept().await {
            let (request, mut respond) = match result {
                Ok(pair) => pair,
                Err(error) => {
                    tracing::debug!(%error, "gRPC server connection ended");
                    break;
                }
            };
            if more_tx.is_closed() {
                respond.send_reset(h2::Reason::REFUSED_STREAM);
                continue;
            }
            match open_stream(request, respond, &config) {
                Ok(stream) => {
                    if let Err(error) = more_tx.try_send(stream) {
                        tracing::debug!(%error, "gRPC stream refused: server busy");
                    }
                }
                Err(error) => tracing::debug!(%error, "gRPC stream rejected"),
            }
        }
    });
    Ok((first, more_rx))
}

/// Validate one gRPC request and bridge it to a byte stream.
fn open_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    config: &WsConfig,
) -> Result<BoxStream, String> {
    if request.method() != http::Method::POST || request.uri().path() != config.path {
        respond.send_reset(h2::Reason::REFUSED_STREAM);
        return Err("gRPC request method or path does not match".into());
    }
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !content_type.starts_with("application/grpc") {
        respond.send_reset(h2::Reason::REFUSED_STREAM);
        return Err("gRPC content-type is missing".into());
    }
    let request_encoding = request
        .headers()
        .get("grpc-encoding")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("identity")
        .to_owned();
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("content-type", "application/grpc")
        .header("grpc-encoding", "identity")
        .body(())
        .map_err(|error| format!("gRPC response: {error}"))?;
    let send = respond
        .send_response(response, false)
        .map_err(|error| format!("gRPC response: {error}"))?;
    let body = request.into_body();
    let (app, worker) = tokio::io::duplex(128 * 1024);
    tokio::spawn(run_server(body, send, worker, request_encoding));
    Ok(zero_core::boxed(app))
}

async fn run_client(
    response: h2::client::ResponseFuture,
    send: h2::SendStream<Bytes>,
    app: tokio::io::DuplexStream,
) {
    let (app_read, app_write) = tokio::io::split(app);
    crate::relay::drive_both(
        "gRPC",
        upload_messages(app_read, send),
        download_messages(response, app_write),
    )
    .await;
}

async fn run_server(
    body: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    app: tokio::io::DuplexStream,
    request_encoding: String,
) {
    let (app_read, app_write) = tokio::io::split(app);
    crate::relay::drive_both(
        "gRPC server",
        upload_messages(app_read, send),
        download_body(body, app_write, &request_encoding),
    )
    .await;
}

/// Application bytes carried per gRPC message.
const HUNK_PAYLOAD: usize = 16 * 1024;
/// gRPC envelope (5) + Hunk field tag (1) + length varint (at most 3 for
/// `HUNK_PAYLOAD`).
const HUNK_OVERHEAD: usize = 5 + 1 + 3;

async fn upload_messages<R>(mut app: R, mut send: h2::SendStream<Bytes>) -> Result<(), String>
where
    R: AsyncRead + Unpin,
{
    // Each message is assembled once, in place, in a buffer whose frozen
    // slices go straight to h2: the payload is copied exactly once, where it
    // used to be copied into a Hunk, then an envelope, then once more per
    // flow-control window. The allocation is reclaimed once h2 releases it.
    let mut payload = vec![0u8; HUNK_PAYLOAD];
    let mut frame = BytesMut::with_capacity(HUNK_OVERHEAD + HUNK_PAYLOAD);
    loop {
        let n = app
            .read(&mut payload)
            .await
            .map_err(|error| format!("gRPC application read: {error}"))?;
        if n == 0 {
            send.send_data(Bytes::new(), true)
                .map_err(|error| format!("gRPC upload close: {error}"))?;
            return Ok(());
        }
        frame.reserve(HUNK_OVERHEAD + n);
        encode_message(&payload[..n], &mut frame);
        crate::relay::send_with_capacity(&mut send, frame.split().freeze())
            .await
            .map_err(|error| format!("gRPC upload: {error}"))?;
    }
}

/// Append one gRPC message (uncompressed envelope + `Hunk`) to `out`.
fn encode_message(data: &[u8], out: &mut BytesMut) {
    let hunk_len = 1 + varint_len(data.len() as u64) + data.len();
    out.put_u8(0);
    out.put_u32(hunk_len as u32);
    out.put_u8(0x0a); // field 1, length-delimited
    let mut value = data.len() as u64;
    while value >= 0x80 {
        out.put_u8((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.put_u8(value as u8);
    out.put_slice(data);
}

async fn download_messages<W>(
    response: h2::client::ResponseFuture,
    mut app: W,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let response = response
        .await
        .map_err(|error| format!("gRPC response: {error}"))?;
    if response.status() != http::StatusCode::OK {
        return Err(format!("gRPC unexpected status {}", response.status()));
    }
    let encoding = response
        .headers()
        .get("grpc-encoding")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("identity")
        .to_owned();
    let mut body = response.into_body();
    read_messages_with_encoding(&mut body, &mut app, &encoding).await?;
    // The response is complete: pass the EOF on, or the application waits
    // for bytes that will never come until it closes its own uplink.
    app.shutdown()
        .await
        .map_err(|error| format!("gRPC application close: {error}"))
}

async fn download_body<W>(body: h2::RecvStream, mut app: W, encoding: &str) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let mut body = body;
    let result = read_messages_with_encoding(&mut body, &mut app, encoding).await;
    if result.is_ok() {
        app.shutdown()
            .await
            .map_err(|error| format!("gRPC application close: {error}"))?;
    }
    result
}

async fn read_messages_with_encoding<R, W>(
    body: &mut R,
    app: &mut W,
    encoding: &str,
) -> Result<(), String>
where
    R: MessageBody,
    W: AsyncWrite + Unpin,
{
    let mut pending = BytesMut::new();
    while let Some((chunk, capacity)) = body.next_chunk().await? {
        pending.extend_from_slice(&chunk);
        body.release_capacity(capacity)?;
        // Messages are consumed from the front with `advance`, which is O(1);
        // `Vec::drain` shifted the whole remainder for every message.
        while pending.len() >= 5 {
            if pending[0] > 1 {
                return Err("invalid gRPC compression flag".into());
            }
            let compressed = pending[0] != 0;
            let length =
                u32::from_be_bytes([pending[1], pending[2], pending[3], pending[4]]) as usize;
            if length > MAX_MESSAGE {
                return Err("gRPC message exceeds the size limit".into());
            }
            if pending.len() < 5 + length {
                break;
            }
            let message = decode_message(&pending[5..5 + length], compressed, encoding)?;
            let payload = decode_hunk(&message)?;
            app.write_all(payload)
                .await
                .map_err(|error| format!("gRPC application write: {error}"))?;
            pending.advance(5 + length);
        }
    }
    if pending.is_empty() {
        Ok(())
    } else {
        Err("gRPC body ended in an incomplete message".into())
    }
}

fn decode_message<'a>(
    payload: &'a [u8],
    compressed: bool,
    encoding: &str,
) -> Result<std::borrow::Cow<'a, [u8]>, String> {
    if !compressed {
        return Ok(std::borrow::Cow::Borrowed(payload));
    }
    match encoding.trim().to_ascii_lowercase().as_str() {
        "gzip" => {
            let decoder = GzDecoder::new(payload);
            let mut decoded = Vec::with_capacity(payload.len().saturating_mul(2));
            decoder
                .take((MAX_MESSAGE + 1) as u64)
                .read_to_end(&mut decoded)
                .map_err(|error| format!("gRPC gzip decode: {error}"))?;
            if decoded.len() > MAX_MESSAGE {
                return Err("decompressed gRPC message exceeds the size limit".into());
            }
            Ok(std::borrow::Cow::Owned(decoded))
        }
        "identity" | "" => Err("compressed gRPC message has no compression encoding".into()),
        other => Err(format!("unsupported gRPC compression encoding {other:?}")),
    }
}

/// Encode `xray.transport.internet.grpc.encoding.Hunk { bytes data = 1; }`.
#[cfg(test)]
fn encode_hunk(data: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(1 + varint_len(data.len() as u64) + data.len());
    message.push(0x0a); // field 1, length-delimited
    push_varint(&mut message, data.len() as u64);
    message.extend_from_slice(data);
    message
}

/// Decode a protobuf `Hunk`, retaining protobuf's last-value-wins behavior for
/// a singular field and ignoring well-formed non-group unknown fields.
fn decode_hunk(message: &[u8]) -> Result<&[u8], String> {
    let mut cursor = 0;
    let mut data: &[u8] = &[];
    while cursor < message.len() {
        let key = read_varint(message, &mut cursor)?;
        let field = key >> 3;
        let wire_type = (key & 0x07) as u8;
        if field == 0 {
            return Err("gRPC Hunk contains an invalid protobuf field number".into());
        }
        if field == 1 {
            if wire_type != 2 {
                return Err("gRPC Hunk data has the wrong protobuf wire type".into());
            }
            let length = read_length(message, &mut cursor)?;
            let end = cursor
                .checked_add(length)
                .ok_or_else(|| "gRPC Hunk data length overflow".to_string())?;
            let value = message
                .get(cursor..end)
                .ok_or_else(|| "gRPC Hunk data is truncated".to_string())?;
            data = value;
            cursor = end;
        } else {
            skip_field(message, &mut cursor, wire_type)?;
        }
    }
    Ok(data)
}

fn varint_len(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

#[cfg(test)]
fn push_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn read_varint(input: &[u8], cursor: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    for index in 0..10 {
        let byte = *input
            .get(*cursor)
            .ok_or_else(|| "gRPC Hunk contains a truncated protobuf varint".to_string())?;
        *cursor += 1;
        if index == 9 && byte > 1 {
            return Err("gRPC Hunk contains an overflowing protobuf varint".into());
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("gRPC Hunk contains an overflowing protobuf varint".into())
}

fn read_length(input: &[u8], cursor: &mut usize) -> Result<usize, String> {
    usize::try_from(read_varint(input, cursor)?)
        .map_err(|_| "gRPC Hunk length does not fit this platform".into())
}

fn skip_field(input: &[u8], cursor: &mut usize, wire_type: u8) -> Result<(), String> {
    let fixed = match wire_type {
        0 => {
            read_varint(input, cursor)?;
            return Ok(());
        }
        1 => 8,
        2 => read_length(input, cursor)?,
        // Groups are deprecated, absent from Hunk's schema, and recursive
        // skipping would expose the pre-authentication parser to adversarial
        // nesting depth.
        3 | 4 => return Err("gRPC Hunk contains an unsupported protobuf group".into()),
        5 => 4,
        _ => return Err("gRPC Hunk contains an invalid protobuf wire type".into()),
    };
    let end = cursor
        .checked_add(fixed)
        .ok_or_else(|| "gRPC Hunk field length overflow".to_string())?;
    if end > input.len() {
        return Err("gRPC Hunk contains a truncated protobuf field".into());
    }
    *cursor = end;
    Ok(())
}

trait MessageBody {
    fn next_chunk(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Option<(Bytes, usize)>, String>> + Send;
    fn release_capacity(&mut self, capacity: usize) -> Result<(), String>;
}

impl MessageBody for h2::RecvStream {
    async fn next_chunk(&mut self) -> Result<Option<(Bytes, usize)>, String> {
        self.data()
            .await
            .map(|chunk| {
                chunk.map(|chunk| {
                    let length = chunk.len();
                    (chunk, length)
                })
            })
            .transpose()
            .map_err(|error| format!("gRPC body: {error}"))
    }

    fn release_capacity(&mut self, capacity: usize) -> Result<(), String> {
        self.flow_control()
            .release_capacity(capacity)
            .map_err(|error| format!("gRPC flow control: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    /// Frame `data` as one uncompressed gRPC message carrying a `Hunk`.
    fn grpc_message(data: &[u8]) -> Bytes {
        let hunk = encode_hunk(data);
        let mut framed = Vec::with_capacity(5 + hunk.len());
        framed.push(0);
        framed.extend_from_slice(&(hunk.len() as u32).to_be_bytes());
        framed.extend_from_slice(&hunk);
        Bytes::from(framed)
    }

    #[tokio::test]
    async fn every_stream_on_one_connection_is_served() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let config = WsConfig::new("/tunnel/Tun", "example.com");
        let server = tokio::spawn({
            let config = config.clone();
            async move {
                let (first, mut more) = accept_multi(zero_core::boxed(server_io), &config)
                    .await
                    .unwrap();
                let second = more.recv().await.expect("second stream reaches the server");
                let mut got = Vec::new();
                for mut stream in [first, second] {
                    let mut buf = [0u8; 5];
                    stream.read_exact(&mut buf).await.unwrap();
                    got.push(buf);
                    stream.write_all(b"ack").await.unwrap();
                    stream.flush().await.unwrap();
                    // Keep the stream open until the client has read.
                    tokio::spawn(async move {
                        let mut rest = [0u8; 1];
                        let _ = stream.read(&mut rest).await;
                    });
                }
                got
            }
        });

        let (sender, connection) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(connection);
        let mut responses = Vec::new();
        for payload in [b"first", b"secnd"] {
            let mut sender = sender.clone().ready().await.unwrap();
            let request = http::Request::builder()
                .method("POST")
                .uri("https://example.com/tunnel/Tun")
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let (response, mut send) = sender.send_request(request, false).unwrap();
            send.send_data(grpc_message(payload), false).unwrap();
            responses.push((response, send));
        }
        let received = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("both streams served in time")
            .unwrap();
        assert_eq!(received, [*b"first", *b"secnd"]);
        for (response, _send) in responses {
            let response = response.await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn client_and_server_roundtrip_framed_bytes() {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let config = WsConfig::new("/svc", "edge.example");
        let server_config = config.clone();
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
        let mut app = connect(zero_core::boxed(client), &config).await.unwrap();
        app.write_all(b"ping").await.unwrap();
        app.flush().await.unwrap();
        let mut response = [0u8; 5];
        app.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"reply");
        server_task.await.unwrap();
    }

    #[test]
    fn decodes_bounded_gzip_messages() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"compressed payload").unwrap();
        let encoded = encoder.finish().unwrap();
        assert_eq!(
            &decode_message(&encoded, true, "gzip").unwrap()[..],
            b"compressed payload"
        );
        assert!(decode_message(&encoded, true, "identity").is_err());
    }

    #[test]
    fn hunk_encoding_matches_the_xray_protobuf_schema() {
        assert_eq!(encode_hunk(b"ping"), b"\x0a\x04ping");

        let payload = vec![0x5a; 128];
        let encoded = encode_hunk(&payload);
        assert_eq!(&encoded[..3], &[0x0a, 0x80, 0x01]);
        assert_eq!(decode_hunk(&encoded).unwrap(), payload);
    }

    #[test]
    fn message_encoder_matches_envelope_plus_hunk() {
        for len in [0usize, 1, 127, 128, 16_384] {
            let data = vec![0x33; len];
            let hunk = encode_hunk(&data);
            let mut expected = vec![0u8];
            expected.extend_from_slice(&(hunk.len() as u32).to_be_bytes());
            expected.extend_from_slice(&hunk);
            let mut out = BytesMut::new();
            encode_message(&data, &mut out);
            assert_eq!(&out[..], &expected[..], "len {len}");
        }
    }

    #[tokio::test]
    async fn server_end_of_stream_reaches_the_client_application_as_eof() {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let config = WsConfig::new("/svc", "edge.example");
        let server_config = config.clone();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            let mut app = accept(zero_core::boxed(server), &server_config)
                .await
                .unwrap();
            app.write_all(b"bye").await.unwrap();
            app.shutdown().await.unwrap();
            // Keep reading side open until the client is done checking.
            let _ = release_rx.await;
            drop(app);
        });
        let mut app = connect(zero_core::boxed(client), &config).await.unwrap();
        // Opening the stream needs at least one request frame on the wire.
        app.write_all(b"x").await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), app.read_to_end(&mut got))
            .await
            .expect("the end of the gRPC response must reach the application")
            .unwrap();
        assert_eq!(got, b"bye");
        release_tx.send(()).unwrap();
        server_task.await.unwrap();
    }

    #[test]
    fn hunk_decoder_handles_protobuf_compatibility_rules() {
        // Unknown varint field 2 is ignored. A repeated singular field keeps
        // its last value, matching ordinary proto3 decoders.
        let message = b"\x10\x2a\x0a\x03old\x0a\x03new";
        assert_eq!(decode_hunk(message).unwrap(), b"new");
        assert_eq!(decode_hunk(&[]).unwrap(), b"");
    }

    #[test]
    fn hunk_decoder_rejects_malformed_messages() {
        assert!(decode_hunk(b"raw payload").is_err());
        assert!(decode_hunk(b"\x0a\x80").is_err());
        assert!(decode_hunk(b"\x0a\x04no").is_err());
        assert!(decode_hunk(b"\x0f").is_err());
        assert!(decode_hunk(b"\x13\x14").is_err());
    }
}
