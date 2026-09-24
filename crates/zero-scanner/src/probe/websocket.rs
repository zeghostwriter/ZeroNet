use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub async fn probe_websocket_upgrade(
    tls_stream: &mut TlsStream<TcpStream>,
    host: &str,
    path: &str,
    timeout: Duration,
) -> bool {
    let normalized_path = if path.starts_with('/') { path } else { "/" };

    let req = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: c2VucGFpc2Nhbm5lcg==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        normalized_path, host
    );

    let write_fut = tls_stream.write_all(req.as_bytes());
    if tokio::time::timeout(timeout / 2, write_fut).await.is_err() {
        return false;
    }

    let mut buf = [0u8; 1024];
    let read_fut = tls_stream.read(&mut buf);
    match tokio::time::timeout(timeout / 2, read_fut).await {
        Ok(Ok(n)) if n > 0 => {
            // Any HTTP response proves Cloudflare processed the request and DPI didn't RST
            buf[..n].starts_with(b"HTTP/1.")
        }
        _ => false,
    }
}
