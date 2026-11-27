//! Xray's one-shot raw/TCP HTTP camouflage header.
//!
//! The header is deliberately a byte-stream wrapper: the client emits one
//! HTTP request before its first protocol bytes, the server validates and
//! consumes that request, and the server emits one HTTP response before its
//! first response bytes. After that exchange the stream is opaque protocol
//! data. Keeping this separate from the HTTP proxy inbound avoids accidentally
//! parsing or rewriting the tunneled payload.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_HEADER: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeaderConfig {
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub version: Box<str>,
    pub method: Box<str>,
    pub path: Box<str>,
    pub headers: Vec<(Box<str>, Box<str>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub version: Box<str>,
    pub status: u16,
    pub reason: Box<str>,
    pub headers: Vec<(Box<str>, Box<str>)>,
}

pub struct HttpHeaderStream<S> {
    inner: S,
    /// The client reads a response head, the server a request head.
    is_client: bool,
    expected_request: Option<HttpRequest>,
    expected_response: Option<HttpResponse>,
    read_enabled: bool,
    read_done: bool,
    read_buffer: Vec<u8>,
    payload: Vec<u8>,
    write_buffer: Option<Vec<u8>>,
    write_offset: usize,
}

impl<S> HttpHeaderStream<S> {
    pub fn client(inner: S, config: &HttpHeaderConfig) -> Self {
        Self {
            inner,
            is_client: true,
            expected_request: None,
            expected_response: config.response.clone(),
            // An Xray server with HTTP camouflage answers with a response
            // head whether or not the client's config describes one, so the
            // client always strips it; the config only narrows what counts
            // as a valid head. Skipping it handed "HTTP/1.1 200 OK…" to
            // VMess as its response header.
            read_enabled: true,
            read_done: false,
            read_buffer: Vec::new(),
            payload: Vec::new(),
            write_buffer: Some(encode_request(&config.request)),
            write_offset: 0,
        }
    }

    pub fn server(inner: S, config: &HttpHeaderConfig) -> Self {
        Self {
            inner,
            is_client: false,
            expected_request: Some(config.request.clone()),
            expected_response: None,
            read_enabled: true,
            read_done: false,
            read_buffer: Vec::new(),
            payload: Vec::new(),
            write_buffer: config.response.as_ref().map(encode_response),
            write_offset: 0,
        }
    }

    fn copy_payload(&mut self, dst: &mut ReadBuf<'_>) -> bool {
        if self.payload.is_empty() || dst.remaining() == 0 {
            return false;
        }
        let amount = self.payload.len().min(dst.remaining());
        dst.put_slice(&self.payload[..amount]);
        self.payload.drain(..amount);
        true
    }

    fn ensure_write_buffer(&mut self) {
        if self.write_buffer.is_none() {
            self.write_buffer = Some(Vec::new());
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HttpHeaderStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_enabled || self.read_done {
            return Pin::new(&mut self.inner).poll_read(cx, dst);
        }
        if self.copy_payload(dst) {
            return Poll::Ready(Ok(()));
        }

        loop {
            if let Some(end) = find_header_end(&self.read_buffer) {
                let header = self.read_buffer[..end].to_vec();
                let remainder = self.read_buffer[end + 4..].to_vec();
                self.read_buffer.clear();
                self.payload = remainder;
                let validation = if self.is_client {
                    validate_response(&header, self.expected_response.as_ref())
                } else {
                    validate_request(&header, self.expected_request.as_ref())
                };
                if let Err(error) = validation {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
                }
                self.read_done = true;
                if self.copy_payload(dst) {
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut self.inner).poll_read(cx, dst);
            }
            if self.read_buffer.len() >= MAX_HEADER {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "raw HTTP camouflage header is too long",
                )));
            }

            let mut scratch = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {
                    let bytes = read_buf.filled();
                    if bytes.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "raw HTTP camouflage header ended before the blank line",
                        )));
                    }
                    self.read_buffer.extend_from_slice(bytes);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for HttpHeaderStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.ensure_write_buffer();
        let this = &mut *self;
        while let Some(pending) = this
            .write_buffer
            .as_deref()
            .and_then(|header| header.get(this.write_offset..))
            .filter(|pending| !pending.is_empty())
        {
            // Borrowed, not copied: this runs on every poll until the header
            // is out.
            match Pin::new(&mut this.inner).poll_write(cx, pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "raw HTTP camouflage header write made no progress",
                    )))
                }
                Poll::Ready(Ok(written)) => this.write_offset += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.ensure_write_buffer();
        let this = &mut *self;
        while let Some(pending) = this
            .write_buffer
            .as_deref()
            .and_then(|header| header.get(this.write_offset..))
            .filter(|pending| !pending.is_empty())
        {
            // Borrowed, not copied: this runs on every poll until the header
            // is out.
            match Pin::new(&mut this.inner).poll_write(cx, pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "raw HTTP camouflage header flush made no progress",
                    )))
                }
                Poll::Ready(Ok(written)) => this.write_offset += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

fn encode_request(request: &HttpRequest) -> Vec<u8> {
    let mut output = format!(
        "{} {} HTTP/{}\r\n",
        request.method, request.path, request.version
    );
    for (name, value) in &request.headers {
        output.push_str(name);
        output.push_str(": ");
        output.push_str(value);
        output.push_str("\r\n");
    }
    output.push_str("\r\n");
    output.into_bytes()
}

fn encode_response(response: &HttpResponse) -> Vec<u8> {
    let mut output = format!(
        "HTTP/{} {} {}\r\n",
        response.version, response.status, response.reason
    );
    for (name, value) in &response.headers {
        output.push_str(name);
        output.push_str(": ");
        output.push_str(value);
        output.push_str("\r\n");
    }
    output.push_str("\r\n");
    output.into_bytes()
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn validate_request(bytes: &[u8], expected: Option<&HttpRequest>) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "raw HTTP header is not UTF-8")?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or("raw HTTP request line is missing")?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next().ok_or("raw HTTP method is missing")?;
    let path = parts.next().ok_or("raw HTTP path is missing")?;
    let version = parts.next().ok_or("raw HTTP version is missing")?;
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return Err("raw HTTP request line is malformed".into());
    }
    if let Some(expected) = expected {
        if method != expected.method.as_ref() || path != expected.path.as_ref() {
            return Err("raw HTTP request does not match the configured camouflage".into());
        }
        let expected_version = format!("HTTP/{}", expected.version);
        if version != expected_version {
            return Err("raw HTTP request version does not match the configured camouflage".into());
        }
    }
    Ok(())
}

fn validate_response(bytes: &[u8], expected: Option<&HttpResponse>) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "raw HTTP header is not UTF-8")?;
    let status_line = text
        .split("\r\n")
        .next()
        .ok_or("raw HTTP response line is missing")?;
    let mut parts = status_line.split_ascii_whitespace();
    let version = parts.next().ok_or("raw HTTP version is missing")?;
    let status = parts.next().ok_or("raw HTTP status is missing")?;
    let status = status
        .parse::<u16>()
        .map_err(|_| "raw HTTP status is malformed")?;
    if parts.next().is_none() || !version.starts_with("HTTP/") {
        return Err("raw HTTP response line is malformed".into());
    }
    if let Some(expected) = expected {
        if version != format!("HTTP/{}", expected.version) || status != expected.status {
            return Err("raw HTTP response does not match the configured camouflage".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn config() -> HttpHeaderConfig {
        HttpHeaderConfig {
            request: HttpRequest {
                version: "1.1".into(),
                method: "GET".into(),
                path: "/cdn-cgi/trace".into(),
                headers: vec![("Host".into(), "example.test".into())],
            },
            response: Some(HttpResponse {
                version: "1.1".into(),
                status: 200,
                reason: "OK".into(),
                headers: vec![("Content-Type".into(), "text/plain".into())],
            }),
        }
    }

    #[tokio::test]
    async fn client_and_server_strip_headers_and_preserve_coalesced_payload() {
        let config = config();
        let (left, right) = tokio::io::duplex(1024);
        let mut client = HttpHeaderStream::client(left, &config);
        let mut server = HttpHeaderStream::server(right, &config);
        let server_task = tokio::spawn(async move {
            let mut request = [0u8; 5];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"hello");
            server.write_all(b"world").await.unwrap();
            server.flush().await.unwrap();
        });
        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();
        let mut response = [0u8; 5];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"world");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn a_client_without_a_response_config_still_strips_the_servers_head() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let config = HttpHeaderConfig {
            request: HttpRequest {
                version: "1.1".into(),
                method: "GET".into(),
                path: "/cam".into(),
                headers: Vec::new(),
            },
            response: None,
        };
        let mut client = HttpHeaderStream::client(client_io, &config);
        client.write_all(b"payload").await.unwrap();
        client.flush().await.unwrap();
        server_io
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nreply")
            .await
            .unwrap();
        let mut got = [0u8; 5];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"reply");
    }

    #[tokio::test]
    async fn server_rejects_wrong_path() {
        let config = config();
        let (mut left, right) = tokio::io::duplex(1024);
        let mut server = HttpHeaderStream::server(right, &config);
        left.write_all(b"GET /wrong HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let error = server.read(&mut byte).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
