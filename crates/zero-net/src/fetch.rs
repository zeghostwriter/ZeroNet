//! A small, bounded HTTP/HTTPS GET client for rule-set and asset downloads.
//!
//! This is deliberately not a general HTTP client. It exists so the asset
//! pipeline can refresh geosite/geoip data without pulling a full client stack
//! into the release graph, and every property that matters for that job is
//! enforced here rather than left to the caller:
//!
//! * a hard byte ceiling, applied while reading, so a hostile or broken origin
//!   cannot exhaust memory;
//! * a whole-request deadline, so a stalled transfer fails instead of hanging
//!   a refresh task forever;
//! * conditional requests, so an unchanged asset costs one 304 round trip;
//! * a truncation check, so a short read is reported as an error instead of
//!   being handed upward as a valid but incomplete file. That last property is
//!   the entire reason a cached rule-set can otherwise fail to parse with a
//!   bare "unexpected EOF" long after the download that caused it.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Bounds applied to one fetch, redirects included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchLimits {
    pub max_bytes: usize,
    pub timeout: Duration,
    pub max_redirects: u8,
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            timeout: Duration::from_secs(60),
            max_redirects: 5,
        }
    }
}

/// Validators from a previous fetch, replayed so an unchanged asset is not
/// downloaded again.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl Validators {
    pub fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// The origin confirmed the cached copy is current.
    NotModified,
    Body {
        body: Vec<u8>,
        validators: Validators,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("unsupported URL: {0}")]
    Url(String),
    #[error("connecting to {host}: {source}")]
    Connect {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("TLS to {host}: {source}")]
    Tls {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("transport: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed HTTP response: {0}")]
    Protocol(String),
    #[error("HTTP {0}")]
    Status(u16),
    #[error("too many redirects")]
    TooManyRedirects,
    /// The origin announced a length it did not deliver. Reporting this here is
    /// what stops a half-written file from reaching the cache.
    #[error("truncated response: expected {expected} bytes, received {received}")]
    Truncated { expected: usize, received: usize },
    #[error("response exceeds the {limit} byte ceiling")]
    TooLarge { limit: usize },
    #[error("timed out after {0:?}")]
    Timeout(Duration),
}

/// Per-request options beyond the limits.
///
/// Kept apart from [`FetchLimits`] so adding an option never changes the
/// shape of a struct existing callers build literally.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FetchOptions {
    /// Offer `Accept-Encoding: gzip` and transparently inflate a gzip body.
    ///
    /// Off by default: rule-set assets are already compressed and gain
    /// nothing. Text feeds (subscription lists) shrink five- to tenfold, which
    /// on a metered mobile link is the difference that matters.
    ///
    /// [`FetchLimits::max_bytes`] then bounds *both* the bytes on the wire and
    /// the inflated body, so a small hostile body cannot expand past the
    /// ceiling (a "zip bomb").
    pub accept_gzip: bool,
}

/// Fetch one URL, following redirects within the configured budget.
pub async fn fetch(
    url: &str,
    limits: &FetchLimits,
    validators: &Validators,
) -> Result<Fetched, FetchError> {
    fetch_with(url, limits, validators, &FetchOptions::default()).await
}

/// [`fetch`] with explicit [`FetchOptions`].
pub async fn fetch_with(
    url: &str,
    limits: &FetchLimits,
    validators: &Validators,
    options: &FetchOptions,
) -> Result<Fetched, FetchError> {
    let deadline = tokio::time::Instant::now() + limits.timeout;
    let mut current = url.to_string();
    for _ in 0..=limits.max_redirects {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(FetchError::Timeout(limits.timeout));
        }
        match timeout(remaining, fetch_once(&current, limits, validators, options)).await {
            Err(_) => return Err(FetchError::Timeout(limits.timeout)),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(Outcome::Done(fetched))) => return Ok(fetched),
            Ok(Ok(Outcome::Redirect(location))) => {
                current = resolve_redirect(&current, &location)?;
            }
        }
    }
    Err(FetchError::TooManyRedirects)
}

enum Outcome {
    Done(Fetched),
    Redirect(String),
}

struct Target {
    tls: bool,
    host: String,
    port: u16,
    request_target: String,
}

fn parse_target(url: &str) -> Result<Target, FetchError> {
    let parsed = url::Url::parse(url).map_err(|error| FetchError::Url(error.to_string()))?;
    let tls = match parsed.scheme() {
        "http" => false,
        "https" => true,
        other => return Err(FetchError::Url(format!("unsupported scheme `{other}`"))),
    };
    let host = parsed
        .host_str()
        .ok_or_else(|| FetchError::Url("missing host".into()))?
        .to_string();
    let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
    let mut request_target = parsed.path().to_string();
    if request_target.is_empty() {
        request_target.push('/');
    }
    if let Some(query) = parsed.query() {
        request_target.push('?');
        request_target.push_str(query);
    }
    Ok(Target {
        tls,
        host,
        port,
        request_target,
    })
}

fn resolve_redirect(base: &str, location: &str) -> Result<String, FetchError> {
    let base = url::Url::parse(base).map_err(|error| FetchError::Url(error.to_string()))?;
    let next = base
        .join(location)
        .map_err(|error| FetchError::Url(error.to_string()))?;
    match next.scheme() {
        "http" | "https" => Ok(next.to_string()),
        other => Err(FetchError::Url(format!(
            "redirect to unsupported scheme `{other}`"
        ))),
    }
}

fn request_bytes(target: &Target, validators: &Validators, options: &FetchOptions) -> Vec<u8> {
    let encoding = if options.accept_gzip {
        "gzip"
    } else {
        "identity"
    };
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: zray-core/{}\r\nAccept: */*\r\nAccept-Encoding: {encoding}\r\nConnection: close\r\n",
        target.request_target,
        host_header(target),
        env!("CARGO_PKG_VERSION"),
    );
    if let Some(etag) = validators.etag.as_deref() {
        request.push_str(&format!("If-None-Match: {etag}\r\n"));
    }
    if let Some(modified) = validators.last_modified.as_deref() {
        request.push_str(&format!("If-Modified-Since: {modified}\r\n"));
    }
    request.push_str("\r\n");
    request.into_bytes()
}

fn host_header(target: &Target) -> String {
    let default_port = if target.tls { 443 } else { 80 };
    let host = if target.host.contains(':') {
        format!("[{}]", target.host)
    } else {
        target.host.clone()
    };
    if target.port == default_port {
        host
    } else {
        format!("{host}:{}", target.port)
    }
}

/// POST `body` to `url` and return the response body. Redirects are not
/// followed (a redirected POST would have to be re-sent, which is the
/// caller's decision); a 3xx is reported as [`FetchError::Status`].
pub async fn post(
    url: &str,
    content_type: &str,
    body: &[u8],
    limits: &FetchLimits,
) -> Result<Vec<u8>, FetchError> {
    post_with_headers(url, content_type, &[], body, limits).await
}

/// [`post`] with extra request headers (a `User-Agent` among them replaces
/// the default one). Header names and values must not contain line breaks.
pub async fn post_with_headers(
    url: &str,
    content_type: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    limits: &FetchLimits,
) -> Result<Vec<u8>, FetchError> {
    let target = parse_target(url)?;
    if headers.iter().any(|(k, v)| k.contains(['\r', '\n']) || v.contains(['\r', '\n'])) {
        return Err(FetchError::Protocol("header contains a line break".into()));
    }
    let agent = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map_or_else(|| format!("zray-core/{}", env!("CARGO_PKG_VERSION")), |(_, v)| (*v).to_string());
    let mut head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {agent}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        target.request_target,
        host_header(&target),
        body.len(),
    );
    for (name, value) in headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("user-agent")) {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let mut request = head.into_bytes();
    request.extend_from_slice(body);
    match timeout(limits.timeout, send_once(&target, &request, limits)).await {
        Err(_) => Err(FetchError::Timeout(limits.timeout)),
        Ok(Err(error)) => Err(error),
        Ok(Ok(Outcome::Done(Fetched::Body { body, .. }))) => Ok(body),
        Ok(Ok(Outcome::Done(Fetched::NotModified))) => Err(FetchError::Status(304)),
        Ok(Ok(Outcome::Redirect(_))) => Err(FetchError::Status(302)),
    }
}

async fn fetch_once(
    url: &str,
    limits: &FetchLimits,
    validators: &Validators,
    options: &FetchOptions,
) -> Result<Outcome, FetchError> {
    let target = parse_target(url)?;
    let request = request_bytes(&target, validators, options);
    send_once(&target, &request, limits).await
}

/// Connect to `target` (TLS when it is https) and exchange one request.
async fn send_once(target: &Target, request: &[u8], limits: &FetchLimits) -> Result<Outcome, FetchError> {
    // Resolved first so the socket exists before it connects: the host has to
    // be given the chance to exempt it from the tunnel, and
    // `TcpStream::connect` offers no such moment (`zero_core::platform`).
    let resolved: Vec<std::net::SocketAddr> =
        tokio::net::lookup_host((target.host.as_str(), target.port))
            .await
            .map_err(|source| FetchError::Connect {
                host: target.host.clone(),
                source,
            })?
            .collect();
    // Raced with per-candidate timeouts (and protected sockets) rather than
    // tried one by one: a single blackholed address used to consume the
    // whole fetch deadline before the next one was even attempted.
    let stream = crate::dial::dial_tcp(
        &resolved,
        &crate::dial::RacePolicy::default(),
        &crate::dial::SocketOptions::default(),
    )
    .await
    .map_err(|failure| FetchError::Connect {
        host: target.host.clone(),
        source: std::io::Error::other(failure.to_string()),
    })?
    .stream;
    if target.tls {
        let connector = tokio_rustls::TlsConnector::from(tls_config());
        let server_name = rustls_pki_types::ServerName::try_from(target.host.clone())
            .map_err(|error| FetchError::Url(error.to_string()))?;
        let stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|source| FetchError::Tls {
                host: target.host.clone(),
                source,
            })?;
        exchange(stream, request, limits).await
    } else {
        exchange(stream, request, limits).await
    }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }))
}

async fn exchange<S>(
    mut stream: S,
    request: &[u8],
    limits: &FetchLimits,
) -> Result<Outcome, FetchError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
    stream.flush().await?;

    // Headers first: read until the terminator, bounded so a origin that never
    // closes the header block cannot grow the buffer without limit.
    const MAX_HEADERS: usize = 64 * 1024;
    let mut buffer = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    // Resume the terminator search where the last one stopped (less three
    // bytes for a terminator split across reads) instead of rescanning the
    // whole buffer after every read.
    let mut scanned = 0usize;
    let header_end = loop {
        if let Some(position) = find_header_end(&buffer[scanned..]) {
            break scanned + position;
        }
        scanned = buffer.len().saturating_sub(3);
        if buffer.len() > MAX_HEADERS {
            return Err(FetchError::Protocol("header block is too large".into()));
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(FetchError::Protocol(
                "connection closed before the response headers completed".into(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut headers);
    let parsed = response
        .parse(&buffer[..header_end])
        .map_err(|error| FetchError::Protocol(error.to_string()))?;
    if parsed.is_partial() {
        return Err(FetchError::Protocol("incomplete response head".into()));
    }
    let status = response
        .code
        .ok_or_else(|| FetchError::Protocol("response has no status code".into()))?;

    // Copy out every header this function needs before the buffer is split,
    // so the body handling below owns its storage outright.
    let header = |name: &str| -> Option<String> {
        response
            .headers
            .iter()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(name))
            .and_then(|candidate| std::str::from_utf8(candidate.value).ok())
            .map(|value| value.trim().to_string())
    };
    let location = header("location");
    let transfer_encoding = header("transfer-encoding");
    let declared_length = header("content-length");
    let content_encoding = header("content-encoding");
    let validators = Validators {
        etag: header("etag"),
        last_modified: header("last-modified"),
    };

    if status == 304 {
        return Ok(Outcome::Done(Fetched::NotModified));
    }
    if (300..400).contains(&status) {
        let location =
            location.ok_or_else(|| FetchError::Protocol("redirect without a Location".into()))?;
        return Ok(Outcome::Redirect(location));
    }
    if !(200..300).contains(&status) {
        return Err(FetchError::Status(status));
    }

    let chunked =
        transfer_encoding.is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    let content_length = declared_length.and_then(|value| value.parse::<usize>().ok());
    if let Some(length) = content_length {
        if length > limits.max_bytes {
            return Err(FetchError::TooLarge {
                limit: limits.max_bytes,
            });
        }
    }

    let mut body = buffer.split_off(header_end);
    // With a declared length, stop as soon as it has arrived: an origin that
    // ignores `Connection: close` would otherwise hold the fetch open until
    // the deadline and turn a complete download into a timeout.
    let stop_at = content_length.filter(|_| !chunked);
    read_body(&mut stream, &mut body, limits.max_bytes, stop_at).await?;

    let body = if chunked {
        decode_chunked(&body)?
    } else {
        body
    };

    // A `Content-Length` the origin did not honour is the failure mode that
    // silently produces a corrupt cached rule-set, so it is an error here and
    // never a short success.
    if let Some(expected) = content_length {
        if !chunked && body.len() != expected {
            return Err(FetchError::Truncated {
                expected,
                received: body.len(),
            });
        }
    } else if !chunked && body.is_empty() {
        return Err(FetchError::Protocol("response body is empty".into()));
    }

    // Only gzip is ever offered, so it is the only coding to undo. Anything
    // else was not asked for, and passing it upward as if it were the body
    // would hand the caller bytes it cannot read.
    let body = match content_encoding
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("") | Some("identity") => body,
        Some("gzip") | Some("x-gzip") => inflate_gzip(&body, limits.max_bytes)?,
        Some(other) => {
            return Err(FetchError::Protocol(format!(
                "unrequested content encoding `{other}`"
            )))
        }
    };

    Ok(Outcome::Done(Fetched::Body { validators, body }))
}

async fn read_body<S>(
    stream: &mut S,
    body: &mut Vec<u8>,
    max_bytes: usize,
    expected: Option<usize>,
) -> Result<(), FetchError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    if let Some(expected) = expected {
        body.reserve(expected.saturating_sub(body.len()));
    }
    let mut chunk = [0u8; 32 * 1024];
    loop {
        if body.len() > max_bytes {
            return Err(FetchError::TooLarge { limit: max_bytes });
        }
        if expected.is_some_and(|expected| body.len() >= expected) {
            return Ok(());
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        body.extend_from_slice(&chunk[..read]);
    }
}

/// Inflate a gzip body, refusing to produce more than `max_bytes`.
///
/// The ceiling is enforced while decoding, not after: reading through a
/// `take` of one byte more than the limit means an oversized body is detected
/// having allocated at most the limit.
fn inflate_gzip(body: &[u8], max_bytes: usize) -> Result<Vec<u8>, FetchError> {
    use std::io::Read as _;
    let mut decoder = flate2::read::MultiGzDecoder::new(body).take(
        u64::try_from(max_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    );
    let mut out = Vec::with_capacity(body.len().saturating_mul(4).min(max_bytes));
    decoder
        .read_to_end(&mut out)
        .map_err(|error| FetchError::Protocol(format!("invalid gzip body: {error}")))?;
    if out.len() > max_bytes {
        return Err(FetchError::TooLarge { limit: max_bytes });
    }
    Ok(out)
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, FetchError> {
    let mut out = Vec::with_capacity(body.len());
    let mut at = 0usize;
    loop {
        let line_end = body[at..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|position| at + position)
            .ok_or_else(|| FetchError::Protocol("chunk size line is unterminated".into()))?;
        let line = std::str::from_utf8(&body[at..line_end])
            .map_err(|_| FetchError::Protocol("chunk size line is not UTF-8".into()))?;
        let size_text = line.split(';').next().unwrap_or(line).trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| FetchError::Protocol(format!("invalid chunk size `{size_text}`")))?;
        at = line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        // Every step is checked: the size is attacker-controlled hex, and
        // `ffffffffffffffff` must be a clean error, not an overflow panic.
        let end = at
            .checked_add(size)
            .filter(|end| end.checked_add(2).is_some_and(|after| after <= body.len()))
            .ok_or_else(|| FetchError::Truncated {
                expected: at.saturating_add(size).saturating_add(2),
                received: body.len(),
            })?;
        out.extend_from_slice(&body[at..end]);
        at = end + 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn serve(response: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request).await;
                let _ = stream.write_all(response).await;
                let _ = stream.shutdown().await;
            }
        });
        format!("http://{address}/asset")
    }

    #[tokio::test]
    async fn reads_a_content_length_body() {
        let url = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"v1\"\r\n\r\nhello").await;
        let fetched = fetch(&url, &FetchLimits::default(), &Validators::default())
            .await
            .unwrap();
        match fetched {
            Fetched::Body { body, validators } => {
                assert_eq!(body, b"hello");
                assert_eq!(validators.etag.as_deref(), Some("\"v1\""));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// The regression that matters: a short body must not reach the caller as
    /// a successful but incomplete download.
    #[tokio::test]
    async fn short_body_is_an_error_not_a_partial_success() {
        let url = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\ntruncated").await;
        let error = fetch(&url, &FetchLimits::default(), &Validators::default())
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                FetchError::Truncated {
                    expected: 64,
                    received: 9
                }
            ),
            "unexpected {error:?}"
        );
    }

    #[tokio::test]
    async fn decodes_chunked_bodies() {
        let url = serve(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nzray\r\n5\r\n-core\r\n0\r\n\r\n",
        )
        .await;
        let fetched = fetch(&url, &FetchLimits::default(), &Validators::default())
            .await
            .unwrap();
        match fetched {
            Fetched::Body { body, .. } => assert_eq!(body, b"zray-core"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn truncated_chunked_body_is_rejected() {
        let url =
            serve(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n16\r\nshort\r\n").await;
        let error = fetch(&url, &FetchLimits::default(), &Validators::default())
            .await
            .unwrap_err();
        assert!(matches!(error, FetchError::Truncated { .. }), "{error:?}");
    }

    #[tokio::test]
    async fn not_modified_is_reported_without_a_body() {
        let url = serve(b"HTTP/1.1 304 Not Modified\r\n\r\n").await;
        let fetched = fetch(
            &url,
            &FetchLimits::default(),
            &Validators {
                etag: Some("\"v1\"".into()),
                last_modified: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(fetched, Fetched::NotModified);
    }

    #[tokio::test]
    async fn oversized_declared_length_is_refused_before_reading() {
        let url = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n").await;
        let error = fetch(
            &url,
            &FetchLimits {
                max_bytes: 1024,
                ..FetchLimits::default()
            },
            &Validators::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, FetchError::TooLarge { limit: 1024 }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn error_statuses_do_not_become_assets() {
        let url = serve(b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nno!").await;
        let error = fetch(&url, &FetchLimits::default(), &Validators::default())
            .await
            .unwrap_err();
        assert!(matches!(error, FetchError::Status(404)), "{error:?}");
    }

    #[test]
    fn an_absurd_chunk_size_is_an_error_not_an_overflow() {
        let error = decode_chunked(b"ffffffffffffffff\r\nabc\r\n0\r\n\r\n").unwrap_err();
        assert!(matches!(error, FetchError::Truncated { .. }), "{error:?}");
        let error = decode_chunked(b"fffffffffffffffe\r\nabc").unwrap_err();
        assert!(matches!(error, FetchError::Truncated { .. }), "{error:?}");
    }

    /// An origin that keeps the connection open after a complete
    /// Content-Length body must not turn the fetch into a timeout.
    #[tokio::test]
    async fn a_complete_body_finishes_without_waiting_for_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .unwrap();
            // Hold the connection open well past the fetch deadline.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let fetched = fetch(
            &format!("http://{address}/asset"),
            &FetchLimits {
                timeout: Duration::from_secs(2),
                ..FetchLimits::default()
            },
            &Validators::default(),
        )
        .await
        .unwrap();
        assert!(matches!(fetched, Fetched::Body { ref body, .. } if body == b"hello"));
    }

    /// Serve one gzip-encoded response, recording whether the request
    /// offered gzip.
    async fn serve_gzip(body: &'static [u8]) -> (String, tokio::sync::oneshot::Receiver<String>) {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(body).unwrap();
        let compressed = encoder.finish().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (seen, request_text) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 2048];
            let n = stream.read(&mut request).await.unwrap();
            let _ = seen.send(String::from_utf8_lossy(&request[..n]).into_owned());
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                compressed.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(&compressed).await.unwrap();
            let _ = stream.shutdown().await;
        });
        (format!("http://{address}/feed"), request_text)
    }

    #[tokio::test]
    async fn gzip_is_offered_only_when_asked_and_inflated_transparently() {
        let (url, request) = serve_gzip(b"vless://one\nvless://two\n").await;
        let fetched = fetch_with(
            &url,
            &FetchLimits::default(),
            &Validators::default(),
            &FetchOptions { accept_gzip: true },
        )
        .await
        .unwrap();
        assert!(
            matches!(fetched, Fetched::Body { ref body, .. } if body == b"vless://one\nvless://two\n")
        );
        assert!(request.await.unwrap().contains("Accept-Encoding: gzip"));

        // The plain entry point still asks for identity.
        let url = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let target = parse_target(&url).unwrap();
        let text = String::from_utf8(request_bytes(
            &target,
            &Validators::default(),
            &FetchOptions::default(),
        ))
        .unwrap();
        assert!(text.contains("Accept-Encoding: identity"));
    }

    #[tokio::test]
    async fn an_inflated_body_is_held_to_the_byte_ceiling() {
        static BIG: [u8; 64 * 1024] = [b'a'; 64 * 1024];
        let (url, _request) = serve_gzip(&BIG).await;
        let error = fetch_with(
            &url,
            &FetchLimits {
                max_bytes: 4096,
                ..FetchLimits::default()
            },
            &Validators::default(),
            &FetchOptions { accept_gzip: true },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, FetchError::TooLarge { limit: 4096 }),
            "{error:?}"
        );
    }

    #[test]
    fn redirects_resolve_relative_locations_and_reject_other_schemes() {
        assert_eq!(
            resolve_redirect("https://example.com/a/b", "../c").unwrap(),
            "https://example.com/c"
        );
        assert!(resolve_redirect("https://example.com/a", "file:///etc/passwd").is_err());
    }
}
