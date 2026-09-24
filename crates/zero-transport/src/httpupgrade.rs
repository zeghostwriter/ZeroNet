//! Xray HTTPUpgrade carrier.
//!
//! HTTPUpgrade stops after the HTTP 101 response: the bytes after the header
//! are raw stream data, with no WebSocket framing or close handshake.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zero_core::BoxStream;

use crate::ws::WsConfig;

const MAX_RESPONSE_HEAD: usize = 64 * 1024;

pub async fn connect(mut stream: BoxStream, config: &WsConfig) -> Result<BoxStream, String> {
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
        escape_path(&config.path),
        config.host
    );
    for (name, value) in &config.headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("HTTPUpgrade request: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("HTTPUpgrade flush: {error}"))?;

    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let mut scanned = 0;
    let head_end = loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("HTTPUpgrade response: {error}"))?;
        if n == 0 {
            return Err("HTTPUpgrade closed before response headers".into());
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(position) = find_head_end(&buffer, &mut scanned) {
            break position;
        }
        if buffer.len() > MAX_RESPONSE_HEAD {
            return Err("HTTPUpgrade response headers exceed 64 KiB".into());
        }
    };
    validate_response(&buffer[..head_end])?;
    Ok(zero_core::boxed(PrefixedStream {
        inner: stream,
        prefix: BytesMut::from(&buffer[head_end + 4..]),
    }))
}

/// Accept the server side of an HTTPUpgrade carrier. Unlike WebSocket this
/// returns the post-101 bytes as a raw stream, without message framing.
pub async fn accept(mut stream: BoxStream, config: &WsConfig) -> Result<BoxStream, String> {
    let mut buffer = Vec::with_capacity(1024);
    let mut scanned = 0;
    let head_end = loop {
        if let Some(position) = find_head_end(&buffer, &mut scanned) {
            break position + 4;
        }
        if buffer.len() >= MAX_RESPONSE_HEAD {
            return Err("HTTPUpgrade request headers exceed 64 KiB".into());
        }
        let mut chunk = [0u8; 2048];
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("HTTPUpgrade request: {error}"))?;
        if n == 0 {
            return Err("HTTPUpgrade closed before request headers".into());
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let head = &buffer[..head_end];
    let text = std::str::from_utf8(head).map_err(|_| "HTTPUpgrade request is not UTF-8")?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or("HTTPUpgrade request has no request line")?;
    let mut parts = request_line.split_whitespace();
    if parts.next() != Some("GET") {
        return Err("HTTPUpgrade request is not GET".into());
    }
    let path = parts.next().unwrap_or("");
    if path.split_once('?').map_or(path, |(base, _)| base) != config.path {
        return Err("HTTPUpgrade request path does not match".into());
    }
    let mut connection = false;
    let mut upgrade = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("connection") {
            connection = value.trim().eq_ignore_ascii_case("upgrade");
        } else if name.eq_ignore_ascii_case("upgrade") {
            upgrade = value.trim().eq_ignore_ascii_case("websocket");
        }
    }
    if !connection || !upgrade {
        return Err("HTTPUpgrade request lacks upgrade headers".into());
    }
    stream
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .await
        .map_err(|error| format!("HTTPUpgrade response: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("HTTPUpgrade flush: {error}"))?;
    Ok(zero_core::boxed(PrefixedStream {
        inner: stream,
        prefix: BytesMut::from(&buffer[head_end..]),
    }))
}

/// Find the `\r\n\r\n` that ends an HTTP head, searching only bytes not
/// already scanned (plus three for a terminator split across reads). A full
/// rescan per read was quadratic, and the server side runs this before any
/// authentication, so a client dripping one byte per packet could make each
/// connection cost billions of comparisons.
fn find_head_end(buffer: &[u8], scanned: &mut usize) -> Option<usize> {
    let start = (*scanned).min(buffer.len());
    let found = buffer[start..]
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| start + position);
    *scanned = buffer.len().saturating_sub(3);
    found
}

fn escape_path(path: &str) -> String {
    path.replace('?', "%3F")
}

fn validate_response(head: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(head).map_err(|_| "HTTPUpgrade response is not UTF-8")?;
    let mut lines = text.split("\r\n");
    if lines.next() != Some("HTTP/1.1 101 Switching Protocols") {
        return Err("HTTPUpgrade status is not 101 Switching Protocols".into());
    }
    let mut connection = None;
    let mut upgrade = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("connection") {
            connection = Some(value.trim().to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case("upgrade") {
            upgrade = Some(value.trim().to_ascii_lowercase());
        }
    }
    if connection.as_deref() != Some("upgrade") {
        return Err("HTTPUpgrade Connection must equal upgrade".into());
    }
    if upgrade.as_deref() != Some("websocket") {
        return Err("HTTPUpgrade Upgrade must equal websocket".into());
    }
    Ok(())
}

struct PrefixedStream {
    inner: BoxStream,
    prefix: BytesMut,
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let count = self.prefix.len().min(output.remaining());
            output.put_slice(&self.prefix[..count]);
            self.prefix.advance(count);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn validates_exact_upgrade_headers() {
        let valid =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket";
        assert!(validate_response(valid).is_ok());
        let invalid = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade, keep-alive\r\nUpgrade: websocket";
        assert!(validate_response(invalid).is_err());
    }

    #[test]
    fn head_end_is_found_across_split_reads() {
        let mut scanned = 0;
        let mut buffer = b"GET / HTTP/1.1\r\nHost: x\r\n\r".to_vec();
        assert_eq!(find_head_end(&buffer, &mut scanned), None);
        buffer.extend_from_slice(b"\nrest");
        assert_eq!(find_head_end(&buffer, &mut scanned), Some(23));
    }

    #[tokio::test]
    async fn completes_upgrade_and_preserves_coalesced_payload() {
        let (client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let mut request = vec![0u8; 256];
            let n = server.read(&mut request).await.unwrap();
            assert!(std::str::from_utf8(&request[..n])
                .unwrap()
                .contains("GET /x%3Fy"));
            server
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nreply")
                .await
                .unwrap();
        });
        let stream = zero_core::boxed(client);
        let cfg = WsConfig::new("/x?y", "example.com");
        let mut upgraded = connect(stream, &cfg).await.unwrap();
        let mut reply = [0u8; 5];
        upgraded.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        task.await.unwrap();
    }
}
