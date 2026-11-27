//! HTTP/1.1 in front of the Tide server.
//!
//! How this works. The Tide server speaks HTTP/2. A reverse proxy or a CDN
//! between the app and the server (nginx, a Cloudflare Worker's `fetch`)
//! often cannot: it talks HTTP/1.1 to its origin. So the server looks at the
//! first four bytes of every connection. HTTP/2 starts with `PRI `; anything
//! else is treated as HTTP/1.1 and handled here.
//!
//! This module is a *gateway*, not a second server. For an HTTP/1.1
//! connection it makes an in-memory HTTP/2 connection to the real server and
//! turns each request into an HTTP/2 request and each answer back into an
//! HTTP/1.1 one, streaming both ways. Every rule the server keeps (decoy
//! pages, session proofs, replay checks, pipe numbering) therefore applies
//! unchanged, because the same code answers.
//!
//! The rules it keeps:
//!  * bodies are streamed, never collected: a download reaches the proxy as
//!    it is produced, an upload reaches the session as it arrives;
//!  * an HTTP/1.1 connection carries one request at a time (no pipelining);
//!    a client that wants more opens more connections;
//!  * a request it cannot parse, or whose head is over 16 KiB, ends the
//!    connection without an answer of its own.
//!
//! The surprise: a long download holds its connection for as long as it
//! lasts, so a proxy must be willing to keep several connections open to the
//! server (HTTP/2 needs only one).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{Method, Request};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zero_core::{boxed, BoxStream};

use crate::tide::{other, send_all, Server};

/// The most a request's head (line and headers) may be.
const HEAD_MAX: usize = 16 * 1024;
/// How long an idle connection waits for its next request, and how long a
/// request may take to finish arriving once started.
const IDLE: Duration = Duration::from_secs(120);
const HEAD_TIME: Duration = Duration::from_secs(30);
/// Response headers passed back to the proxy.
const PASSED_BACK: [&str; 10] = [
    "date",
    "content-type",
    "content-length",
    "cache-control",
    "x-accel-buffering",
    "location",
    "referrer-policy",
    "x-robots-tag",
    "x-frame-options",
    "set-cookie",
];

/// A stream that gives back bytes already read from it before the rest.
pub(crate) struct Prefixed {
    head: Bytes,
    inner: BoxStream,
}

impl Prefixed {
    pub(crate) fn new(head: &[u8], inner: BoxStream) -> Self {
        Self {
            head: Bytes::copy_from_slice(head),
            inner,
        }
    }
}

impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.head.is_empty() {
            let take = self.head.len().min(buf.remaining());
            buf.put_slice(&self.head.split_to(take));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// How a request's body is framed.
enum Framing {
    None,
    Length(u64),
    Chunked,
}

struct Head {
    method: Method,
    target: String,
    content_type: Option<String>,
    framing: Framing,
    /// Whether the connection can carry another request after this one.
    keep_alive: bool,
}

/// Read bytes into `buf` until `done` finds the end of what it is looking
/// for; returns what `done` returns.
async fn fill_until<T>(
    reader: &mut (impl AsyncRead + Unpin),
    buf: &mut BytesMut,
    mut done: impl FnMut(&[u8]) -> io::Result<Option<T>>,
) -> io::Result<T> {
    loop {
        if let Some(found) = done(buf)? {
            return Ok(found);
        }
        if buf.len() > HEAD_MAX {
            return Err(other("http/1.1 head too large"));
        }
        if reader.read_buf(buf).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }
}

/// Read and parse one request head, removing it from `buf`.
async fn read_head(reader: &mut (impl AsyncRead + Unpin), buf: &mut BytesMut) -> io::Result<Head> {
    let (used, head) = fill_until(reader, buf, |data| {
        let mut headers = [httparse::EMPTY_HEADER; 48];
        let mut parsed = httparse::Request::new(&mut headers);
        let used = match parsed.parse(data).map_err(other)? {
            httparse::Status::Complete(used) => used,
            httparse::Status::Partial => return Ok(None),
        };
        let method = Method::from_bytes(parsed.method.unwrap_or("").as_bytes()).map_err(other)?;
        let target = parsed.path.unwrap_or("/").to_string();
        let find = |name: &str| {
            parsed
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case(name))
                .and_then(|header| std::str::from_utf8(header.value).ok())
        };
        let framing = if find("transfer-encoding")
            .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
        {
            Framing::Chunked
        } else if let Some(length) = find("content-length") {
            match length.trim().parse::<u64>().map_err(other)? {
                0 => Framing::None,
                n => Framing::Length(n),
            }
        } else {
            Framing::None
        };
        let close = find("connection").is_some_and(|v| v.to_ascii_lowercase().contains("close"));
        let keep_alive = !close && parsed.version == Some(1);
        Ok(Some((
            used,
            Head {
                method,
                target,
                content_type: find("content-type").map(str::to_string),
                framing,
                keep_alive,
            },
        )))
    })
    .await?;
    let _ = buf.split_to(used);
    Ok(head)
}

/// One line (without its CRLF) from the front of `buf`.
async fn read_line(reader: &mut (impl AsyncRead + Unpin), buf: &mut BytesMut) -> io::Result<Bytes> {
    let end = fill_until(reader, buf, |data| {
        Ok(data.windows(2).position(|pair| pair == b"\r\n"))
    })
    .await?;
    let line = buf.split_to(end).freeze();
    let _ = buf.split_to(2);
    Ok(line)
}

/// Copy a request body from the client into the HTTP/2 request.
async fn pump_body(
    reader: &mut (impl AsyncRead + Unpin),
    buf: &mut BytesMut,
    framing: Framing,
    out: &mut h2::SendStream<Bytes>,
) -> io::Result<()> {
    async fn take(
        reader: &mut (impl AsyncRead + Unpin),
        buf: &mut BytesMut,
        mut count: u64,
        out: &mut h2::SendStream<Bytes>,
    ) -> io::Result<()> {
        while count > 0 {
            if buf.is_empty() && reader.read_buf(buf).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let part = buf.split_to(buf.len().min(count as usize)).freeze();
            count -= part.len() as u64;
            send_all(out, part).await?;
        }
        Ok(())
    }
    match framing {
        Framing::None => {}
        Framing::Length(count) => take(reader, buf, count, out).await?,
        Framing::Chunked => loop {
            let line = read_line(reader, buf).await?;
            let hex = line.split(|b| *b == b';').next().unwrap_or(&[]);
            let size = std::str::from_utf8(hex)
                .ok()
                .and_then(|text| u64::from_str_radix(text.trim(), 16).ok())
                .ok_or_else(|| other("bad chunk size"))?;
            if size == 0 {
                // Trailers, if any, up to the empty line.
                while !read_line(reader, buf).await?.is_empty() {}
                break;
            }
            take(reader, buf, size, out).await?;
            if !read_line(reader, buf).await?.is_empty() {
                return Err(other("bad chunk end"));
            }
        },
    }
    out.send_data(Bytes::new(), true).map_err(other)
}

/// Whether a response to this status and method has a body.
fn has_body(method: &Method, status: u16) -> bool {
    method != Method::HEAD && !matches!(status, 100..=199 | 204 | 304)
}

/// Serve an HTTP/1.1 connection through an in-memory HTTP/2 one to `server`.
pub(crate) async fn serve(server: &Arc<Server>, io: Prefixed) -> io::Result<()> {
    let (near, far) = tokio::io::duplex(256 * 1024);
    let inner = Arc::clone(server);
    let backend = tokio::spawn(async move { inner.serve_h2(boxed(far)).await });
    let (sender, connection) = h2::client::handshake(near).await.map_err(other)?;
    tokio::spawn(connection);
    let (mut reader, mut writer) = tokio::io::split(io);
    let mut buf = BytesMut::new();
    let result = async {
        loop {
            // Wait for the first byte of the next request, then the head.
            if buf.is_empty() {
                match tokio::time::timeout(IDLE, reader.read_buf(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) => return Ok(()),
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => return Err(error),
                }
            }
            let head = tokio::time::timeout(HEAD_TIME, read_head(&mut reader, &mut buf))
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
            let keep = exchange(&sender, &mut reader, &mut writer, &mut buf, head).await?;
            if !keep {
                return Ok(());
            }
        }
    }
    .await;
    backend.abort();
    result
}

/// One request and its answer. Returns whether the connection may be reused.
async fn exchange(
    sender: &h2::client::SendRequest<Bytes>,
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    buf: &mut BytesMut,
    head: Head,
) -> io::Result<bool> {
    let Head {
        method,
        target,
        content_type,
        framing,
        keep_alive,
    } = head;
    let mut request = Request::builder()
        .method(method.clone())
        .uri(format!("https://tide.invalid{target}"));
    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }
    let request = request.body(()).map_err(other)?;
    let has_request_body = !matches!(framing, Framing::None);
    let mut sender = sender.clone().ready().await.map_err(other)?;
    let (response, mut body) = sender
        .send_request(request, !has_request_body)
        .map_err(other)?;
    let upload = async {
        if has_request_body {
            let sent = pump_body(reader, buf, framing, &mut body).await;
            if sent.is_err() {
                body.send_reset(h2::Reason::CANCEL);
            }
            sent
        } else {
            Ok(())
        }
    };
    let (uploaded, response) = tokio::join!(upload, response);
    uploaded?;
    let response = response.map_err(other)?;
    let status = response.status();
    let chunked =
        has_body(&method, status.as_u16()) && !response.headers().contains_key("content-length");
    let mut text = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    );
    for name in PASSED_BACK {
        for value in response.headers().get_all(name) {
            if let Ok(value) = value.to_str() {
                text.push_str(&format!("{name}: {value}\r\n"));
            }
        }
    }
    if chunked {
        text.push_str("transfer-encoding: chunked\r\n");
    }
    if !keep_alive {
        text.push_str("connection: close\r\n");
    }
    text.push_str("\r\n");
    writer.write_all(text.as_bytes()).await?;
    let mut down = response.into_body();
    if has_body(&method, status.as_u16()) {
        while let Some(data) = down.data().await {
            let data = data.map_err(other)?;
            let size = data.len();
            // An empty piece is HTTP/2's way of ending a body; as a chunk it
            // would end this one early.
            if size == 0 {
                continue;
            }
            if chunked {
                writer.write_all(format!("{size:x}\r\n").as_bytes()).await?;
                writer.write_all(&data).await?;
                writer.write_all(b"\r\n").await?;
            } else {
                writer.write_all(&data).await?;
            }
            // A download is read by someone waiting for it: do not hold it.
            writer.flush().await?;
            let _ = down.flow_control().release_capacity(size);
        }
        if chunked {
            writer.write_all(b"0\r\n\r\n").await?;
        }
    }
    writer.flush().await?;
    Ok(keep_alive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tide::{Decoy, ServerConfig};
    use std::collections::HashMap;
    use std::os::unix::process::CommandExt;
    use std::sync::RwLock;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zero_core::{Address, Destination};
    use zero_protocol::tide::{self, ChunkParser, ShapeLevel};

    const PATH: &str = "/static/app";

    fn server(
        known: bool,
    ) -> (
        Arc<Server>,
        tokio::sync::mpsc::Receiver<crate::tide::Incoming>,
        [u8; 32],
    ) {
        let (secret, public) = tide::generate_keypair();
        let users = Arc::new(RwLock::new(HashMap::new()));
        if known {
            users.write().unwrap().insert([5u8; 16], "t".to_string());
        }
        let (server, streams) = Server::new(ServerConfig {
            path: PATH.into(),
            admin: None,
            secret,
            users,
            decoy: Decoy::default(),
            shape: ShapeLevel::Off,
        });
        (server, streams, public)
    }

    /// A new HTTP/1.1 connection to the server.
    fn connect(server: &Arc<Server>) -> BoxStream {
        let (near, far) = tokio::io::duplex(256 * 1024);
        let server = server.clone();
        tokio::spawn(async move { server.serve_connection(boxed(far)).await });
        boxed(near)
    }

    /// A response head: status, lowercase header names, and the bytes read
    /// past it.
    async fn response_head(io: &mut BoxStream) -> (u16, HashMap<String, String>, BytesMut) {
        let mut buf = BytesMut::new();
        loop {
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut parsed = httparse::Response::new(&mut headers);
            if let httparse::Status::Complete(used) = parsed.parse(&buf).unwrap() {
                let status = parsed.code.unwrap();
                let map = parsed
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_ascii_lowercase(),
                            String::from_utf8_lossy(h.value).to_string(),
                        )
                    })
                    .collect();
                let _ = buf.split_to(used);
                return (status, map, buf);
            }
            assert!(io.read_buf(&mut buf).await.unwrap() > 0, "closed in a head");
        }
    }

    /// Read a response body to its end, whichever way it is framed.
    async fn read_body(
        io: &mut BoxStream,
        headers: &HashMap<String, String>,
        mut buf: BytesMut,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(length) = headers.get("content-length") {
            let length: usize = length.parse().unwrap();
            while buf.len() < length {
                assert!(io.read_buf(&mut buf).await.unwrap() > 0);
            }
            return buf[..length].to_vec();
        }
        assert_eq!(
            headers.get("transfer-encoding").map(String::as_str),
            Some("chunked")
        );
        loop {
            let line = read_line(io, &mut buf).await.unwrap();
            let size = usize::from_str_radix(std::str::from_utf8(&line).unwrap(), 16).unwrap();
            if size == 0 {
                read_line(io, &mut buf).await.unwrap();
                return out;
            }
            while buf.len() < size + 2 {
                assert!(io.read_buf(&mut buf).await.unwrap() > 0);
            }
            out.extend_from_slice(&buf.split_to(size));
            let _ = buf.split_to(2);
        }
    }

    async fn get(io: &mut BoxStream, path: &str) -> (u16, Vec<u8>) {
        io.write_all(format!("GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let (status, headers, rest) = response_head(io).await;
        (status, read_body(io, &headers, rest).await)
    }

    #[tokio::test]
    async fn an_http1_visitor_sees_the_same_site_and_can_reuse_the_connection() {
        let (server, _streams, _) = server(true);
        let mut io = connect(&server);
        let (status, page) = get(&mut io, "/").await;
        assert_eq!(status, 200);
        assert!(page.starts_with(b"<!doctype html>"));
        // Same connection, second request.
        let (status, missing) = get(&mut io, "/nothing").await;
        assert_eq!(status, 404);
        // Garbage to a Tide path gets exactly the missing page.
        let name = "0123456789abcdef0123456789abcdef";
        io.write_all(
            format!(
                "POST {PATH}/{name}/open HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\nhello"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let (status, headers, rest) = response_head(&mut io).await;
        assert_eq!(status, 404);
        assert_eq!(read_body(&mut io, &headers, rest).await, missing);
    }

    /// The whole protocol, by hand, over HTTP/1.1 connections made by `dial`:
    /// open, a download pipe, an upload pipe with a chunked body. What the
    /// client writes is echoed back by whatever sits behind the server.
    async fn session_over<F: std::future::Future<Output = BoxStream>>(
        dial: impl Fn() -> F,
        public: [u8; 32],
        host: &str,
    ) {
        // 1. open
        let (hello, handshake) =
            tide::client_hello(&public, &[5u8; 16], crate::tide::now()).unwrap();
        let mut open = dial().await;
        let name = "fedcba9876543210fedcba9876543210";
        open.write_all(
            format!(
                "POST {PATH}/{name}/open HTTP/1.1\r\nhost: {host}\r\ncontent-length: {}\r\n\r\n",
                hello.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        open.write_all(&hello).await.unwrap();
        let (status, headers, rest) = response_head(&mut open).await;
        assert_eq!(status, 200);
        let reply = read_body(&mut open, &headers, rest).await;
        let session = handshake.finish(&reply).unwrap();
        // The connection that carried a chunked answer is still in step, so
        // a proxy that reuses it gets a clean second answer.
        let (status, page) = get(&mut open, "/").await;
        assert_eq!(status, 200);
        assert!(page.starts_with(b"<!doctype html>"));

        // 2. a download pipe, read as it streams
        let tag = tide::session::pipe_tag(session.binding(), b'd', 1);
        let mut down = dial().await;
        down.write_all(
            format!("GET {PATH}/{name}/d/1?t={tag} HTTP/1.1\r\nhost: {host}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let reader = tokio::spawn({
            let session = session.clone();
            async move {
                let (status, headers, mut buf) = response_head(&mut down).await;
                assert_eq!(status, 200);
                assert_eq!(
                    headers.get("transfer-encoding").map(String::as_str),
                    Some("chunked")
                );
                let mut parser = ChunkParser::default();
                loop {
                    let line = read_line(&mut down, &mut buf).await.unwrap();
                    let size =
                        usize::from_str_radix(std::str::from_utf8(&line).unwrap(), 16).unwrap();
                    if size == 0 {
                        return;
                    }
                    while buf.len() < size + 2 {
                        if down.read_buf(&mut buf).await.unwrap() == 0 {
                            return;
                        }
                    }
                    session.receive(&mut parser, &buf.split_to(size)).unwrap();
                    let _ = buf.split_to(2);
                }
            }
        });

        // 3. a stream and an upload pipe with a chunked body
        let mut stream = session
            .open(Destination::tcp(Address::domain("example.com"), 443))
            .unwrap();
        let payload: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        let tag = tide::session::pipe_tag(session.binding(), b'u', 1);
        let mut up = dial().await;
        up.write_all(
            format!(
                "POST {PATH}/{name}/u/1?t={tag} HTTP/1.1\r\nhost: {host}\r\ncontent-type: application/octet-stream\r\ntransfer-encoding: chunked\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        session.pipe_opened(1);
        while let Some(chunk) = session.try_next_chunk(1, tide::session::CHUNK_PLAIN_MAX) {
            up.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .unwrap();
            up.write_all(&chunk).await.unwrap();
            up.write_all(b"\r\n").await.unwrap();
        }
        up.write_all(b"0\r\n\r\n").await.unwrap();
        let (status, headers, rest) = response_head(&mut up).await;
        assert_eq!(status, 200);
        assert!(read_body(&mut up, &headers, rest).await.is_empty());
        session.pipe_closed(1, true);

        // 4. the echo arrives down the other connection
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut got))
            .await
            .expect("the echo never came")
            .unwrap();
        assert!(got == payload);
        reader.abort();
    }

    /// An echo behind the server, for the streams clients open.
    fn echo(mut streams: tokio::sync::mpsc::Receiver<crate::tide::Incoming>) {
        tokio::spawn(async move {
            while let Some((_, _, mut stream)) = streams.recv().await {
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 16 * 1024];
                    while let Ok(n @ 1..) = stream.read(&mut buffer).await {
                        if stream.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }

    #[tokio::test]
    async fn a_full_tide_session_runs_over_http1() {
        let (server, streams, public) = server(true);
        echo(streams);
        session_over(|| std::future::ready(connect(&server)), public, "x").await;
    }

    /// The same session, through the edge relay Worker running under
    /// wrangler's local workerd, to a server on a plain TCP port. Needs
    /// `wrangler` on the PATH, so it is not run by default:
    /// `cargo test -p zero-transport --lib through_the_worker -- --ignored`.
    #[tokio::test]
    #[ignore = "needs wrangler (workerd) installed"]
    async fn a_full_tide_session_runs_through_the_edge_worker() {
        let (server, streams, public) = server(true);
        echo(streams);
        let egress = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let egress_port = egress.local_addr().unwrap().port();
        tokio::spawn({
            let server = server.clone();
            async move {
                while let Ok((tcp, _)) = egress.accept().await {
                    let server = server.clone();
                    tokio::spawn(async move { server.serve_connection(boxed(tcp)).await });
                }
            }
        });
        let port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let worker =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/edge-relay");
        // wrangler starts helpers of its own; they share its process group,
        // so the whole group is ended, not just wrangler.
        struct Kill(std::process::Child);
        impl Drop for Kill {
            fn drop(&mut self) {
                let _ = std::process::Command::new("kill")
                    .arg("-TERM")
                    .arg(format!("-{}", self.0.id()))
                    .status();
                let _ = self.0.kill();
            }
        }
        let _worker = std::process::Command::new("wrangler")
            .process_group(0)
            .args(["dev", "--port", &port.to_string(), "--ip", "127.0.0.1"])
            .args(["--var", &format!("ORIGIN:http://127.0.0.1:{egress_port}")])
            .args(["--var", &format!("PATH_PREFIX:{PATH}")])
            .current_dir(worker)
            .env("CI", "1")
            .env("WRANGLER_SEND_METRICS", "false")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(Kill)
            .unwrap();
        // Ready when the Worker answers its decoy page.
        let ready = async {
            loop {
                if let Ok(mut tcp) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                    tcp.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
                        .await
                        .unwrap();
                    let mut got = Vec::new();
                    let _ = tcp.read_to_end(&mut got).await;
                    if got.starts_with(b"HTTP/1.1 200") {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(90), ready)
            .await
            .expect("the Worker never came up");
        session_over(
            || async move {
                boxed(
                    tokio::net::TcpStream::connect(("127.0.0.1", port))
                        .await
                        .unwrap(),
                )
            },
            public,
            "worker.test",
        )
        .await;
    }

    #[tokio::test]
    async fn a_request_that_is_not_http_ends_the_connection() {
        let (server, _streams, _) = server(true);
        let mut io = connect(&server);
        io.write_all(&[0xff; 600]).await.unwrap();
        let mut rest = Vec::new();
        let result = tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut rest)).await;
        assert!(result.is_ok(), "the connection was left open");
        assert!(rest.is_empty());
    }
}
