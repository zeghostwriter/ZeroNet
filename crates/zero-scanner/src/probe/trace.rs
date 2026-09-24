use super::speed::{find_subslice, parse_status};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// `/cdn-cgi/trace` responses are well under 1 KiB; anything beyond this is
/// an error page we only need the head of.
const TRACE_BUF_BYTES: usize = 4096;

pub struct TraceResult {
    pub status: u16,
    pub colo: Option<String>,
    pub client_ip: Option<String>,
    /// Time from sending the request to the first response byte (TTFB).
    ///
    /// Earlier versions measured until the whole trace body had been read,
    /// which made IPs that answered with a larger error page look slower
    /// than they are.
    pub latency: Duration,
}

pub async fn probe_trace<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    host: &str,
    timeout: Duration,
) -> Result<TraceResult, std::io::Error> {
    let req = format!(
        "GET /cdn-cgi/trace HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: curl/7.88.1\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\r\n",
        host
    );

    let start = Instant::now();
    match tokio::time::timeout(timeout, stream.write_all(req.as_bytes())).await {
        Ok(res) => res?,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "trace request write timed out",
            ))
        }
    }

    let mut buf = vec![0u8; TRACE_BUF_BYTES];
    let mut total_read = 0;
    let mut first_byte_at = None;

    let read_fut = async {
        while total_read < buf.len() {
            let n = stream.read(&mut buf[total_read..]).await?;
            if n == 0 {
                break;
            }
            first_byte_at.get_or_insert_with(Instant::now);
            total_read += n;
            if trace_complete(&buf[..total_read]) {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    };

    // A read error or timeout after some bytes arrived still leaves a
    // response worth parsing; the caller judges it by status and colo.
    let _ = tokio::time::timeout(timeout, read_fut).await;
    let data = &buf[..total_read];
    let latency = first_byte_at.map_or_else(|| start.elapsed(), |t| t - start);

    Ok(parse_trace_response(data, latency))
}

/// True once the response holds the full `colo=` line, which is all the
/// probe needs; waiting for the rest of the body or for the server to close
/// would only add latency.
fn trace_complete(data: &[u8]) -> bool {
    let Some(head_end) = find_subslice(data, b"\r\n\r\n") else {
        return false;
    };
    let body = &data[head_end + 4..];
    match find_subslice(body, b"colo=") {
        Some(pos) => body[pos..].contains(&b'\n'),
        None => false,
    }
}

/// Extracts `key=value` from a trace body line, e.g. `colo=FRA`.
fn trace_field<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    body.lines().find_map(|line| {
        let v = line.trim().strip_prefix(key)?.strip_prefix('=')?.trim();
        (!v.is_empty()).then_some(v)
    })
}

/// Parses the colo code out of a raw `/cdn-cgi/trace` response (or any
/// response whose body contains a `colo=` line).
pub(crate) fn extract_colo(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let colo = trace_field(&text, "colo")?;
    // IATA codes are 3 letters; be lenient but never keep junk.
    let colo: String = colo
        .chars()
        .take(5)
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    (!colo.is_empty()).then(|| colo.to_ascii_uppercase())
}

fn parse_trace_response(data: &[u8], latency: Duration) -> TraceResult {
    let status = parse_status(data).unwrap_or(0);

    let text = String::from_utf8_lossy(data);
    let mut colo = extract_colo(data);
    let client_ip = trace_field(&text, "ip").map(str::to_string);

    let head_end = find_subslice(data, b"\r\n\r\n").map_or(data.len(), |p| p + 2);
    let head = String::from_utf8_lossy(&data[..head_end]);

    // If colo was not in the body (e.g. a redirect), take it from the
    // CF-RAY header: "CF-RAY: 8a1b2c3d4e5f6a7b-FRA".
    if colo.is_none() {
        colo = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if !name.trim().eq_ignore_ascii_case("cf-ray") {
                return None;
            }
            let code = value.trim().rsplit_once('-')?.1.trim();
            ((3..=4).contains(&code.len()) && code.chars().all(|c| c.is_ascii_alphanumeric()))
                .then(|| code.to_ascii_uppercase())
        });
    }

    // Last resort: a Cloudflare-served 200/301 without a colo still proves
    // the edge answered.
    if colo.is_none() && (status == 200 || status == 301) {
        let is_cf = head.lines().any(|line| {
            line.split_once(':').is_some_and(|(n, v)| {
                n.trim().eq_ignore_ascii_case("server")
                    && v.trim().eq_ignore_ascii_case("cloudflare")
            })
        });
        if is_cf {
            colo = Some("CF".to_string());
        }
    }

    TraceResult {
        status,
        colo,
        client_ip,
        latency,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE: &[u8] = b"HTTP/1.1 200 OK\r\nServer: cloudflare\r\nCF-RAY: 8a1b2c3d4e5f6a7b-AMS\r\n\r\n\
fl=470f330\nh=speed.cloudflare.com\nip=203.0.113.9\nts=1.0\nvisit_scheme=https\nuag=curl\ncolo=FRA\nsliver=none\n";

    #[test]
    fn parses_body_fields_not_neighbouring_lines() {
        let r = parse_trace_response(TRACE, Duration::ZERO);
        assert_eq!(r.status, 200);
        // The body wins over the CF-RAY header, and the value is not taken
        // from an earlier `key=` line such as `fl=`.
        assert_eq!(r.colo.as_deref(), Some("FRA"));
        assert_eq!(r.client_ip.as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn falls_back_to_cf_ray_then_server_header() {
        let redirect = b"HTTP/1.1 301 Moved\r\ncf-ray: 8a1b2c3d4e5f6a7b-lhr\r\n\r\n";
        assert_eq!(
            parse_trace_response(redirect, Duration::ZERO)
                .colo
                .as_deref(),
            Some("LHR")
        );
        let bare = b"HTTP/1.1 301 Moved\r\nServer: cloudflare\r\n\r\n";
        assert_eq!(
            parse_trace_response(bare, Duration::ZERO).colo.as_deref(),
            Some("CF")
        );
        let other = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nhello";
        assert!(parse_trace_response(other, Duration::ZERO).colo.is_none());
    }

    #[test]
    fn completion_waits_for_the_whole_colo_line() {
        assert!(!trace_complete(b"HTTP/1.1 200 OK\r\n\r\nfl=1\ncolo=FR"));
        assert!(trace_complete(b"HTTP/1.1 200 OK\r\n\r\nfl=1\ncolo=FRA\n"));
        // "colo=" inside a header does not count.
        assert!(!trace_complete(b"HTTP/1.1 200 OK\r\nX: colo=FRA\n\r\n"));
    }

    #[test]
    fn garbage_never_panics() {
        for data in [
            &b""[..],
            b"HTTP/1.",
            b"\xff\xfe\r\n\r\ncolo=",
            b"colo=\n",
            b"HTTP/1.1 200",
        ] {
            let _ = parse_trace_response(data, Duration::ZERO);
            let _ = extract_colo(data);
        }
    }
}
