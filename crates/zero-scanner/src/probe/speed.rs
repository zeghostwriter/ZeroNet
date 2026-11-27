use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Upper bound on a single download sample. The requested size comes from
/// the user; without a cap a typo could pull gigabytes per probed IP.
pub const MAX_DOWNLOAD_SAMPLE_BYTES: usize = 64 * 1024 * 1024;

/// Response headers larger than this are treated as a failed sample.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Read buffer size: several TLS records (16 KiB each) per `read` call.
const READ_BUF_BYTES: usize = 64 * 1024;

/// Result of one download sample.
#[derive(Debug, Clone, Copy)]
pub struct DownloadSample {
    /// Request sent to first response byte.
    pub ttfb: Duration,
    /// Body bytes received (headers excluded).
    pub body_bytes: usize,
    /// Throughput in megabits per second.
    pub mbps: f64,
}

/// Downloads `bytes` from Cloudflare's `/__down` endpoint over `stream` and
/// returns the throughput in Mbps, or `0.0` if the sample failed.
pub async fn probe_download<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    host: &str,
    bytes: usize,
    timeout: Duration,
) -> f64 {
    probe_download_detailed(stream, host, bytes, timeout)
        .await
        .map_or(0.0, |s| s.mbps)
}

/// Downloads `bytes` (capped at [`MAX_DOWNLOAD_SAMPLE_BYTES`]) from
/// Cloudflare's `/__down` endpoint over an already established `stream`.
///
/// Throughput is measured over the body only, from the arrival of the first
/// body chunk to the last one, so neither the connection/TLS handshake (done
/// by the caller) nor the request round trip and server think time inflate
/// the transfer time. A sample whose body arrived in a single read has no
/// transfer window; it falls back to body bytes over request-to-last-byte.
///
/// Returns `None` on write failure, a non-2xx response or an empty body.
/// Hitting `timeout` is not a failure: the partial transfer is measured.
pub async fn probe_download_detailed<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    host: &str,
    bytes: usize,
    timeout: Duration,
) -> Option<DownloadSample> {
    let bytes = bytes.min(MAX_DOWNLOAD_SAMPLE_BYTES);
    if bytes == 0 {
        return None;
    }

    let req = format!(
        "GET /__down?bytes={} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Zero-IP-Scanner/0.1\r\n\
         Connection: close\r\n\r\n",
        bytes, host
    );

    let start = Instant::now();
    match tokio::time::timeout(timeout, stream.write_all(req.as_bytes())).await {
        Ok(Ok(())) => {}
        _ => return None,
    }

    let mut buf = vec![0u8; READ_BUF_BYTES];
    let mut header: Vec<u8> = Vec::new();
    let mut status_ok = false;
    let mut headers_done = false;
    let mut ttfb = None;
    let mut body_total = 0usize;
    // Body bytes that arrived after the first body chunk, and when.
    let mut first_body_at: Option<Instant> = None;
    let mut body_after_first = 0usize;
    let mut last_body_at = start;

    let read_loop = async {
        loop {
            let n = match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let now = Instant::now();
            ttfb.get_or_insert_with(|| now - start);

            let body_part = if headers_done {
                n
            } else {
                // Headers may straddle reads, so they are accumulated until
                // the blank line shows up.
                let prev = header.len();
                header.extend_from_slice(&buf[..n]);
                let search_from = prev.saturating_sub(3);
                match find_subslice(&header[search_from..], b"\r\n\r\n") {
                    Some(pos) => {
                        let end = search_from + pos + 4;
                        status_ok = matches!(parse_status(&header[..end]), Some(200..=299));
                        if !status_ok {
                            return;
                        }
                        headers_done = true;
                        header.len() - end
                    }
                    None if header.len() > MAX_HEADER_BYTES => return,
                    None => 0,
                }
            };

            if body_part > 0 {
                if first_body_at.is_none() {
                    first_body_at = Some(now);
                } else {
                    body_after_first += body_part;
                }
                body_total += body_part;
                last_body_at = now;
            }

            if body_total >= bytes {
                break;
            }
        }
    };

    let _ = tokio::time::timeout(timeout, read_loop).await;

    if !status_ok || body_total == 0 {
        return None;
    }

    let window = first_body_at.map(|t| last_body_at.saturating_duration_since(t));
    let mbps = match window {
        Some(w) if body_after_first > 0 && w >= Duration::from_millis(1) => {
            to_mbps(body_after_first, w)
        }
        _ => to_mbps(
            body_total,
            last_body_at
                .saturating_duration_since(start)
                .max(Duration::from_micros(100)),
        ),
    };

    Some(DownloadSample {
        ttfb: ttfb.unwrap_or_default(),
        body_bytes: body_total,
        mbps,
    })
}

fn to_mbps(bytes: usize, elapsed: Duration) -> f64 {
    (bytes as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000.0)
}

pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parses the status code from an HTTP/1.x status line.
pub(crate) fn parse_status(data: &[u8]) -> Option<u16> {
    let rest = data.strip_prefix(b"HTTP/1.")?;
    let code = rest.get(2..5)?;
    if rest.get(1) != Some(&b' ') || !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(code).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn serve(response: Vec<u8>, chunk: usize) -> tokio::io::DuplexStream {
        let (client, mut server) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let mut req = [0u8; 1024];
            let _ = server.read(&mut req).await;
            for part in response.chunks(chunk) {
                if server.write_all(part).await.is_err() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        });
        client
    }

    #[tokio::test]
    async fn counts_body_bytes_when_headers_straddle_reads() {
        let body = vec![b'x'; 50_000];
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Length: 50000\r\n\r\n".to_vec();
        resp.extend_from_slice(&body);
        // 7-byte chunks split the header terminator across reads.
        let mut s = serve(resp, 7).await;
        let sample = probe_download_detailed(&mut s, "h", 50_000, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(sample.body_bytes, 50_000);
        assert!(sample.mbps > 0.0);
    }

    #[tokio::test]
    async fn error_pages_are_not_throughput() {
        let mut resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 1000\r\n\r\n".to_vec();
        resp.extend_from_slice(&[b'e'; 1000]);
        let mut s = serve(resp, 4096).await;
        assert!(
            probe_download_detailed(&mut s, "h", 1000, Duration::from_secs(5))
                .await
                .is_none()
        );
    }

    #[test]
    fn status_line_parsing() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.0 403 Forbidden"), Some(403));
        assert_eq!(parse_status(b"HTTP/1.1 2x0 OK"), None);
        assert_eq!(parse_status(b"HTTP/1.1"), None);
        assert_eq!(parse_status(b"garbage"), None);
    }
}
