//! What a Hysteria2 server answers to a visitor who is not a Hysteria2 client.
//!
//! A Hysteria2 server is an HTTP/3 server whose special request is the login.
//! Anyone else who reaches it (a browser, a scanner) is, to a careful prober,
//! the test of whether it is one: a server that answers every unknown request
//! with the same bare 404 and then hangs up is not a website. This module
//! gives it a website to be, in the three forms Xray and Hysteria offer:
//!
//! * **string**: one fixed response (status, headers, body) to every request;
//! * **file**: a directory served as static files, `index.html` for a
//!   directory, 404 for anything outside it;
//! * **proxy**: another site's pages, fetched on request (GET and HEAD only).
//!
//! After the first request the visitor's connection stays open and is served
//! request after request, as a web server would, until it closes.
//!
//! The rule it must keep: nothing outside the served directory is readable,
//! whatever the path says (`..`, encoded dots, symlinks).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response};

type H3Conn = h3::server::Connection<h3_quinn::Connection, Bytes>;
type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Largest file or proxied page that is sent.
const MAX_BODY: u64 = 16 * 1024 * 1024;

/// What the proxy fetcher returns: status, headers and body of the page.
pub type Page = (u16, Vec<(String, String)>, Vec<u8>);

/// Fetches `path_and_query` from the proxied site; `true` is a HEAD request.
pub type ProxyFetch =
    Arc<dyn Fn(String, bool) -> Pin<Box<dyn Future<Output = Page> + Send>> + Send + Sync>;

#[derive(Clone)]
pub enum Masquerade {
    /// A fixed response.
    Text {
        status: u16,
        headers: Vec<(String, String)>,
        content: Vec<u8>,
    },
    /// Static files from a directory.
    Files { dir: PathBuf },
    /// Another site, fetched on request.
    Proxy(ProxyFetch),
}

impl std::fmt::Debug for Masquerade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Masquerade::Text { status, .. } => write!(f, "Masquerade::Text({status})"),
            Masquerade::Files { dir } => write!(f, "Masquerade::Files({dir:?})"),
            Masquerade::Proxy(_) => write!(f, "Masquerade::Proxy"),
        }
    }
}

impl Masquerade {
    /// The answer to `request`.
    pub async fn respond(&self, method: &Method, target: &http::Uri) -> Page {
        match self {
            Masquerade::Text {
                status,
                headers,
                content,
            } => (*status, headers.clone(), content.clone()),
            Masquerade::Files { dir } => serve_file(dir, target.path()).await,
            Masquerade::Proxy(fetch) => {
                if !matches!(*method, Method::GET | Method::HEAD) {
                    return (405, vec![("allow".into(), "GET, HEAD".into())], Vec::new());
                }
                let path = target
                    .path_and_query()
                    .map_or("/", http::uri::PathAndQuery::as_str);
                fetch(path.to_string(), *method == Method::HEAD).await
            }
        }
    }
}

/// Serve one HTTP/3 connection of a visitor: the request already read, then
/// every request that follows, until it closes.
pub async fn serve_connection(
    mut connection: H3Conn,
    first: (Request<()>, H3Stream),
    masquerade: Arc<Masquerade>,
) {
    answer(first.0, first.1, &masquerade).await;
    while let Ok(Some(resolver)) = connection.accept().await {
        let Ok((request, stream)) = resolver.resolve_request().await else {
            break;
        };
        answer(request, stream, &masquerade).await;
    }
}

async fn answer(request: Request<()>, mut stream: H3Stream, masquerade: &Masquerade) {
    let (status, headers, body) = masquerade.respond(request.method(), request.uri()).await;
    let mut response = Response::builder().status(status);
    for (name, value) in &headers {
        response = response.header(name.as_str(), value.as_str());
    }
    let Ok(response) = response.body(()) else {
        return;
    };
    if stream.send_response(response).await.is_err() {
        return;
    }
    if request.method() != Method::HEAD && !body.is_empty() {
        let _ = stream.send_data(Bytes::from(body)).await;
    }
    let _ = stream.finish().await;
}

fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// Percent-decode a URL path; `None` for a malformed escape or invalid UTF-8.
fn decode_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn not_found() -> Page {
    (
        404,
        vec![("content-type".into(), "text/html; charset=utf-8".into())],
        b"<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center></body></html>\n"
            .to_vec(),
    )
}

/// The file `request_path` names under `dir`, or a 404.
async fn serve_file(dir: &Path, request_path: &str) -> Page {
    let (dir, request_path) = (dir.to_path_buf(), request_path.to_string());
    tokio::task::spawn_blocking(move || read_file(&dir, &request_path))
        .await
        .unwrap_or_else(|_| not_found())
}

fn read_file(dir: &Path, request_path: &str) -> Page {
    let Some(decoded) = decode_path(request_path) else {
        return not_found();
    };
    let mut relative = PathBuf::new();
    for segment in decoded.split('/').filter(|segment| !segment.is_empty()) {
        if segment == ".." || segment == "." || segment.contains(['\\', '\0']) {
            return not_found();
        }
        relative.push(segment);
    }
    let (Ok(root), Ok(mut target)) = (
        std::fs::canonicalize(dir),
        std::fs::canonicalize(dir.join(&relative)),
    ) else {
        return not_found();
    };
    if target.is_dir() {
        target.push("index.html");
    }
    // A symlink may lead anywhere; only what resolves inside the directory
    // is served.
    let Ok(target) = std::fs::canonicalize(&target) else {
        return not_found();
    };
    if !target.starts_with(&root) {
        return not_found();
    }
    match std::fs::metadata(&target) {
        Ok(meta) if meta.is_file() && meta.len() <= MAX_BODY => {}
        _ => return not_found(),
    }
    match std::fs::read(&target) {
        Ok(body) => (
            200,
            vec![("content-type".into(), content_type(&target).into())],
            body,
        ),
        Err(_) => not_found(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zray-masq-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        dir
    }

    #[tokio::test]
    async fn files_are_served_and_nothing_outside_the_directory() {
        let dir = temp_dir("files");
        std::fs::write(dir.join("index.html"), "<h1>home</h1>").unwrap();
        std::fs::write(dir.join("sub").join("a.css"), "a{}").unwrap();
        let secret = dir
            .parent()
            .unwrap()
            .join(format!("zray-secret-{}", std::process::id()));
        std::fs::write(&secret, "secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&secret, dir.join("link")).unwrap();

        assert_eq!(
            serve_file(&dir, "/").await.0,
            200,
            "a directory serves its index"
        );
        let css = serve_file(&dir, "/sub/a.css").await;
        assert_eq!((css.0, css.2.as_slice()), (200, &b"a{}"[..]));
        assert_eq!(css.1[0].1, "text/css; charset=utf-8");
        for escape in [
            "/../zray-secret",
            "/%2e%2e/zray-secret",
            "/sub/../../zray-secret",
            "/..%2fzray-secret",
            "/link",
            "/missing",
            "/sub/%zz",
        ] {
            assert_eq!(serve_file(&dir, escape).await.0, 404, "{escape}");
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(secret);
    }

    #[tokio::test]
    async fn a_text_masquerade_answers_everything_the_same() {
        let masquerade = Masquerade::Text {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
            content: b"hello".to_vec(),
        };
        for method in [Method::GET, Method::POST] {
            let page = masquerade
                .respond(&method, &"/anything?x=1".parse().unwrap())
                .await;
            assert_eq!((page.0, page.2.as_slice()), (200, &b"hello"[..]));
        }
    }

    #[tokio::test]
    async fn a_proxy_masquerade_only_reads() {
        let fetch: ProxyFetch = Arc::new(|path, head| {
            Box::pin(async move {
                let body = if head {
                    Vec::new()
                } else {
                    path.clone().into_bytes()
                };
                (200, vec![], body)
            })
        });
        let masquerade = Masquerade::Proxy(fetch);
        let get = masquerade
            .respond(&Method::GET, &"/a?b=c".parse().unwrap())
            .await;
        assert_eq!(get.2, b"/a?b=c");
        let post = masquerade
            .respond(&Method::POST, &"/a".parse().unwrap())
            .await;
        assert_eq!(post.0, 405);
    }
}
