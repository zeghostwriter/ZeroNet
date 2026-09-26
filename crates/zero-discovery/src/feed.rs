//! Fetching subscription feeds with an on-disk conditional cache.
//!
//! Public feeds are large (hundreds of kilobytes of text), change a few times
//! a day, and are fetched over metered, filtered mobile links. Three things
//! keep that cheap and robust:
//!
//! * **gzip.** Share links compress five- to tenfold; `raw.githubusercontent.com`
//!   serves gzip when offered it.
//! * **Validators.** The previous response's `ETag` and `Last-Modified` are
//!   replayed, so an unchanged feed costs one `304` round trip.
//! * **A fallback.** When the network fails — the common case on a censored
//!   link, and the reason discovery is being run at all — the last good body
//!   is used rather than nothing.
//!
//! Each source `id` owns two files in the cache directory: `<id>.txt` (the
//! decoded body) and `<id>.meta` (JSON validators plus the URL they belong
//! to). Both are replaced atomically, write-then-rename, so a process killed
//! mid-write never leaves a torn body that parses as half a feed.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zero_net::{FetchLimits, FetchOptions, Fetched, Validators};

/// Upper bound on a decoded feed body.
pub const MAX_FEED_BYTES: usize = 16 * 1024 * 1024;

/// One subscription source.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FeedSource {
    pub id: String,
    pub url: String,
    #[serde(default = "default_tier")]
    pub tier: u32,
    /// A detached-signature URL (`<url>.sig`, an `ed25519:<hex>` line). When
    /// set and a signing key is compiled in ([`crate::sign`]), a freshly
    /// downloaded body is verified against it and dropped if it does not
    /// verify: the tested list the app trusts first cannot be swapped by a
    /// CDN or a network in the middle. Feeds without a signature are
    /// unaffected, and so is a build with no key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_url: Option<String>,
}

fn default_tier() -> u32 {
    1
}

/// How a feed body was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedStatus {
    /// Downloaded fresh.
    Ok,
    /// The network failed; the cached body was used.
    Cached,
    /// The origin confirmed the cached body is current.
    NotModified,
    /// Nothing usable: the network failed and there is no cache.
    Error,
}

impl FeedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FeedStatus::Ok => "ok",
            FeedStatus::Cached => "cached",
            FeedStatus::NotModified => "not_modified",
            FeedStatus::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FeedResult {
    pub status: FeedStatus,
    /// The body to parse; `None` only with [`FeedStatus::Error`].
    pub body: Option<String>,
    /// Decoded size of the body.
    pub bytes: usize,
    /// Why the network fetch failed, when it did (also set for `Cached`).
    pub error: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct Meta {
    url: String,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    last_modified: Option<String>,
}

/// A file name derived from a source id that cannot escape the cache
/// directory: ids come from a remote-updatable source list, so `../x` must not
/// become a path.
fn cache_stem(id: &str) -> String {
    let clean = !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
    if clean {
        id.to_string()
    } else {
        format!("feed-{}", &blake3::hash(id.as_bytes()).to_hex()[..16])
    }
}

fn paths(cache_dir: &Path, id: &str) -> (PathBuf, PathBuf) {
    let stem = cache_stem(id);
    (
        cache_dir.join(format!("{stem}.txt")),
        cache_dir.join(format!("{stem}.meta")),
    )
}

fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, contents)?;
    std::fs::rename(&temporary, path)
}

/// Fetch a detached signature (`<url>.sig`, an `ed25519:<hex>` line) and
/// check it over `body` against the compiled-in key. A short body, fetched
/// with no cache and no gzip.
async fn verify_body(sig_url: &str, body: &[u8], timeout: Duration) -> Result<bool, String> {
    let limits = FetchLimits {
        max_bytes: 4096,
        timeout,
        max_redirects: 5,
    };
    match zero_net::fetch_with(sig_url, &limits, &Validators::default(), &FetchOptions::default())
        .await
    {
        Ok(Fetched::Body { body: sig, .. }) => {
            let line = String::from_utf8_lossy(&sig);
            Ok(crate::sign::verify(body, &line))
        }
        Ok(Fetched::NotModified) => Err("unexpected 304 without validators".into()),
        Err(error) => Err(error.to_string()),
    }
}

/// Fetch one feed, consulting and updating the cache in `cache_dir` (if any).
pub async fn fetch_feed(
    source: &FeedSource,
    cache_dir: Option<&Path>,
    timeout: Duration,
) -> FeedResult {
    let files = cache_dir.map(|dir| paths(dir, &source.id));
    let cached_body = files
        .as_ref()
        .and_then(|(body, _)| std::fs::read(body).ok())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    // Validators are only replayed for the URL they were issued by: a source
    // that moved must not be told "not modified" about a different file.
    let validators = match (&files, &cached_body) {
        (Some((_, meta)), Some(_)) => std::fs::read(meta)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Meta>(&bytes).ok())
            .filter(|meta| meta.url == source.url)
            .map(|meta| Validators {
                etag: meta.etag,
                last_modified: meta.last_modified,
            })
            .unwrap_or_default(),
        _ => Validators::default(),
    };

    let limits = FetchLimits {
        max_bytes: MAX_FEED_BYTES,
        timeout,
        max_redirects: 5,
    };
    let fetched = zero_net::fetch_with(
        &source.url,
        &limits,
        &validators,
        &FetchOptions { accept_gzip: true },
    )
    .await;

    match fetched {
        Ok(Fetched::NotModified) => match cached_body {
            Some(body) => FeedResult {
                status: FeedStatus::NotModified,
                bytes: body.len(),
                body: Some(body),
                error: None,
            },
            // Validators are only sent alongside a cached body, so a 304
            // without one is an origin misbehaving.
            None => FeedResult {
                status: FeedStatus::Error,
                body: None,
                bytes: 0,
                error: Some("304 without a cached body".into()),
            },
        },
        Ok(Fetched::Body { body, validators }) => {
            let text = String::from_utf8_lossy(&body).into_owned();
            // A signed source: a freshly downloaded body must match the
            // detached signature, or it is refused and the cached copy (if
            // any) kept. Skipped when no key is compiled in, so a keyless
            // build still works. NotModified/Cached bodies were verified when
            // first stored, so they are not re-checked.
            if let Some(sig_url) = source.sig_url.as_deref() {
                if crate::sign::key_configured() {
                    match verify_body(sig_url, text.as_bytes(), timeout).await {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::warn!(id = %source.id, "feed signature did not verify; refusing it");
                            return match cached_body {
                                Some(body) => FeedResult {
                                    status: FeedStatus::Cached,
                                    bytes: body.len(),
                                    body: Some(body),
                                    error: Some("signature did not verify".into()),
                                },
                                None => FeedResult {
                                    status: FeedStatus::Error,
                                    body: None,
                                    bytes: 0,
                                    error: Some("signature did not verify".into()),
                                },
                            };
                        }
                        Err(error) => {
                            // Could not fetch the signature: treat the body as
                            // unverified and fall back rather than trust it.
                            tracing::warn!(id = %source.id, %error, "could not fetch feed signature; refusing the body");
                            return match cached_body {
                                Some(body) => FeedResult {
                                    status: FeedStatus::Cached,
                                    bytes: body.len(),
                                    body: Some(body),
                                    error: Some(format!("signature unavailable: {error}")),
                                },
                                None => FeedResult {
                                    status: FeedStatus::Error,
                                    body: None,
                                    bytes: 0,
                                    error: Some(format!("signature unavailable: {error}")),
                                },
                            };
                        }
                    }
                }
            }
            if let (Some(dir), Some((body_path, meta_path))) = (cache_dir, &files) {
                let stored = std::fs::create_dir_all(dir)
                    .and_then(|()| write_atomic(body_path, text.as_bytes()))
                    .and_then(|()| {
                        let meta = Meta {
                            url: source.url.clone(),
                            etag: validators.etag,
                            last_modified: validators.last_modified,
                        };
                        write_atomic(meta_path, &serde_json::to_vec(&meta).unwrap_or_default())
                    });
                if let Err(error) = stored {
                    tracing::warn!(id = %source.id, %error, "could not cache a feed");
                }
            }
            FeedResult {
                status: FeedStatus::Ok,
                bytes: text.len(),
                body: Some(text),
                error: None,
            }
        }
        Err(error) => {
            let message = error.to_string();
            match cached_body {
                Some(body) => FeedResult {
                    status: FeedStatus::Cached,
                    bytes: body.len(),
                    body: Some(body),
                    error: Some(message),
                },
                None => FeedResult {
                    status: FeedStatus::Error,
                    body: None,
                    bytes: 0,
                    error: Some(message),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A feed origin that serves gzip with an ETag, answers a matching
    /// `If-None-Match` with 304, and records what it was asked.
    async fn origin(body: &'static str) -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(body.as_bytes()).unwrap();
        let compressed = Arc::new(encoder.finish().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let full = Arc::new(AtomicUsize::new(0));
        let not_modified = Arc::new(AtomicUsize::new(0));
        let (full_count, not_modified_count) = (Arc::clone(&full), Arc::clone(&not_modified));
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let compressed = Arc::clone(&compressed);
                let full = Arc::clone(&full_count);
                let not_modified = Arc::clone(&not_modified_count);
                tokio::spawn(async move {
                    let mut request = vec![0u8; 4096];
                    let n = stream.read(&mut request).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&request[..n]).to_string();
                    assert!(request.contains("Accept-Encoding: gzip"), "{request}");
                    if request.contains("If-None-Match: \"v1\"") {
                        not_modified.fetch_add(1, Ordering::SeqCst);
                        let _ = stream
                            .write_all(b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n")
                            .await;
                    } else {
                        full.fetch_add(1, Ordering::SeqCst);
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nETag: \"v1\"\r\nContent-Length: {}\r\n\r\n",
                            compressed.len()
                        );
                        let _ = stream.write_all(head.as_bytes()).await;
                        let _ = stream.write_all(&compressed).await;
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        (format!("http://{address}/feed.txt"), full, not_modified)
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zero-discovery-{name}-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[tokio::test]
    async fn gzip_body_is_cached_then_revalidated_with_its_etag() {
        let (url, full, not_modified) = origin("vless://a\nvless://b\n").await;
        let dir = scratch("etag");
        let source = FeedSource {
            id: "limilco".into(),
            url,
            tier: 1,
            sig_url: None,
        };

        let first = fetch_feed(&source, Some(&dir), Duration::from_secs(5)).await;
        assert_eq!(first.status, FeedStatus::Ok);
        assert_eq!(first.body.as_deref(), Some("vless://a\nvless://b\n"));
        assert!(dir.join("limilco.txt").exists());
        assert!(dir.join("limilco.meta").exists());

        let second = fetch_feed(&source, Some(&dir), Duration::from_secs(5)).await;
        assert_eq!(second.status, FeedStatus::NotModified);
        assert_eq!(second.body.as_deref(), Some("vless://a\nvless://b\n"));
        assert_eq!(full.load(Ordering::SeqCst), 1);
        assert_eq!(not_modified.load(Ordering::SeqCst), 1);

        // A source that moved gets a full fetch, not a 304 about another file.
        let moved = FeedSource {
            url: source.url.replace("feed.txt", "other.txt"),
            ..source.clone()
        };
        let third = fetch_feed(&moved, Some(&dir), Duration::from_secs(5)).await;
        assert_eq!(third.status, FeedStatus::Ok);
        assert_eq!(full.load(Ordering::SeqCst), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_network_failure_falls_back_to_the_cache() {
        let dir = scratch("fallback");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("src.txt"), "trojan://cached\n").unwrap();
        // A port nothing listens on.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let source = FeedSource {
            id: "src".into(),
            url: format!("http://127.0.0.1:{port}/feed"),
            tier: 1,
            sig_url: None,
        };
        let result = fetch_feed(&source, Some(&dir), Duration::from_secs(3)).await;
        assert_eq!(result.status, FeedStatus::Cached);
        assert_eq!(result.body.as_deref(), Some("trojan://cached\n"));
        assert!(result.error.is_some());

        std::fs::remove_file(dir.join("src.txt")).unwrap();
        let result = fetch_feed(&source, Some(&dir), Duration::from_secs(3)).await;
        assert_eq!(result.status, FeedStatus::Error);
        assert!(result.body.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hostile_ids_cannot_leave_the_cache_directory() {
        assert_eq!(cache_stem("limilco_1"), "limilco_1");
        let stem = cache_stem("../../etc/passwd");
        assert!(stem.starts_with("feed-"));
        assert!(!stem.contains('/'));
        assert!(cache_stem("").starts_with("feed-"));
    }
}
