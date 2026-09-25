//! Updating ZeroNet from inside the app.
//!
//! The latest GitHub release is compared with this build's version. When it
//! is newer, the download for this platform is streamed next to the running
//! program, checked against the release's `SHA256SUMS.txt`, and swapped in
//! with a rename, so a failed or interrupted download never leaves a broken
//! program behind. The new version runs from the next start; the dialog
//! offers to restart straight away.
//!
//! What gets replaced depends on how ZeroNet was installed:
//!
//! - an AppImage: the `.AppImage` file itself (`$APPIMAGE`), with the new
//!   AppImage;
//! - anything else: the running executable, with the plain binary the
//!   release also carries (`ZeroNet-Windows-x64.exe`, `ZeroNet-Linux-<arch>`,
//!   `ZeroNet-macOS-universal`).
//!
//! GitHub is often slow or filtered where ZeroNet is used, so while a
//! connection is up every request goes through the app's own HTTP proxy
//! first, and straight out only if that fails.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Where releases are published.
pub const REPO: &str = "zeghostwriter/ZeroNet";

/// This build's version. Release builds get it from the tag
/// (`ZERONET_VERSION`, set by the release workflow, via `build.rs`); a local
/// build reports the crate version.
pub const CURRENT_VERSION: &str = match option_env!("ZERONET_APP_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Whether this is a published build. Only those check for updates on
/// their own: a developer's build would otherwise always look out of date.
pub fn is_release_build() -> bool {
    option_env!("ZERONET_APP_VERSION").is_some()
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;
/// Cap on API answers and checksum files, which are a few kilobytes.
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
/// Cap on a download: the desktop app is about 20 MB.
const MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;
/// Release notes lines shown in the dialog.
const MAX_NOTES: usize = 6;

// ------------------------------------------------------------------ versions

/// A release version, `major.minor.patch`, compared numerically. A
/// pre-release (`1.2.0-beta`) sorts before the release it leads up to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    /// 1 for a release, 0 for a pre-release, so releases sort after.
    release: u8,
}

impl Version {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim().trim_start_matches(['v', 'V']);
        let (core, pre) = match text.find(['-', '+']) {
            Some(at) => (&text[..at], text[at..].starts_with('-')),
            None => (text, false),
        };
        let mut parts = core.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next().map_or(Some(0), |p| p.parse().ok())?;
        let patch = parts.next().map_or(Some(0), |p| p.parse().ok())?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
            release: u8::from(!pre),
        })
    }
}

/// Whether `candidate` is newer than `current`. Unparseable versions are
/// never newer: a malformed tag must not start an update loop.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (Version::parse(candidate), Version::parse(current)) {
        (Some(c), Some(cur)) => c > cur,
        _ => false,
    }
}

/// What the settings page says about updates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Status {
    #[default]
    Idle,
    Checking,
    UpToDate,
    /// This version is out and not yet installed.
    Available(String),
    /// Downloading, percent done.
    Downloading(u8),
    /// This version is in place and runs from the next start.
    Installed(String),
    Failed,
}

// ------------------------------------------------------------------ releases

/// A release newer than this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// Version without the leading `v`.
    pub version: String,
    /// The release page, for installing by hand.
    pub page: String,
    /// What changed, one short line each.
    pub notes: Vec<String>,
    /// The file that updates this installation, when the release has one.
    pub asset: Option<Asset>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub url: String,
    pub size: u64,
    /// From the release's `SHA256SUMS.txt`, lowercase hex.
    pub sha256: Option<String>,
}

/// What this installation is and where the update goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The file the update replaces.
    pub path: PathBuf,
    /// The release file that replaces it.
    pub asset: String,
}

impl Target {
    /// This installation, or `None` on a platform releases are not built
    /// for.
    pub fn current() -> Option<Self> {
        let arch = std::env::consts::ARCH;
        if cfg!(target_os = "linux") {
            if let Some(appimage) = std::env::var_os("APPIMAGE").filter(|p| !p.is_empty()) {
                return Some(Self {
                    path: PathBuf::from(appimage),
                    asset: format!("ZeroNet-Linux-{arch}.AppImage"),
                });
            }
        }
        let asset = if cfg!(windows) && arch == "x86_64" {
            "ZeroNet-Windows-x64.exe".to_string()
        } else if cfg!(target_os = "linux") && matches!(arch, "x86_64" | "aarch64") {
            format!("ZeroNet-Linux-{arch}")
        } else if cfg!(target_os = "macos") {
            "ZeroNet-macOS-universal".to_string()
        } else {
            return None;
        };
        let exe = std::env::current_exe().ok()?;
        let path = std::fs::canonicalize(&exe).unwrap_or(exe);
        Some(Self { path, asset })
    }
}

/// Read the GitHub API's answer for a release. `asset` names the file this
/// installation updates from; `None` when the platform has none.
pub fn parse_release(json: &str, asset: Option<&str>) -> Result<Release, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("unreadable release data: {e}"))?;
    let tag = value["tag_name"]
        .as_str()
        .ok_or("the release has no version tag")?;
    let version = tag.trim_start_matches(['v', 'V']).to_string();
    let page = value["html_url"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://github.com/{REPO}/releases/latest"));
    let notes = release_notes(value["body"].as_str().unwrap_or(""));
    let asset = asset.and_then(|wanted| {
        value["assets"].as_array()?.iter().find_map(|a| {
            if a["name"].as_str()? != wanted {
                return None;
            }
            Some(Asset {
                name: wanted.to_string(),
                url: a["browser_download_url"].as_str()?.to_string(),
                size: a["size"].as_u64().unwrap_or(0),
                sha256: None,
            })
        })
    });
    Ok(Release {
        version,
        page,
        notes,
        asset,
    })
}

/// The URL of the release's checksum file, if it has one.
fn checksums_url(json: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    value["assets"].as_array()?.iter().find_map(|a| {
        (a["name"].as_str()? == "SHA256SUMS.txt")
            .then(|| a["browser_download_url"].as_str().map(str::to_string))
            .flatten()
    })
}

/// The change list out of a release body: its bullet points, without the
/// "by @someone in <link>" GitHub appends and without the download table.
pub fn release_notes(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| {
            let item = line
                .trim()
                .strip_prefix("* ")
                .or_else(|| line.trim().strip_prefix("- "))?;
            if item.contains("made their first contribution") {
                return None;
            }
            let item = match item.rfind(" by @") {
                Some(at) => &item[..at],
                None => item,
            };
            let item = item.trim();
            (!item.is_empty()).then(|| item.to_string())
        })
        .take(MAX_NOTES)
        .collect()
}

/// Find `name`'s hash in a `sha256sum` listing.
pub fn checksum_for(listing: &str, name: &str) -> Option<String> {
    listing.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let file = parts.next()?.trim_start_matches('*');
        (file == name && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    })
}

/// Ask GitHub for the latest release. `Ok(None)` when this build is
/// current. Returns the proxy port that worked, for the download to use.
pub async fn check(proxy: Option<u16>) -> Result<(Option<Release>, Option<u16>), String> {
    let api = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let (json, route) = on_any_route(proxy, |route| {
        let api = api.clone();
        async move { fetch_text(&api, route).await }
    })
    .await?;
    let target = Target::current();
    let mut release = parse_release(&json, target.as_ref().map(|t| t.asset.as_str()))?;
    if !is_newer(&release.version, CURRENT_VERSION) {
        return Ok((None, route));
    }
    if let (Some(asset), Some(url)) = (release.asset.as_mut(), checksums_url(&json)) {
        if let Ok(listing) = fetch_text(&url, route).await {
            asset.sha256 = checksum_for(&listing, &asset.name);
        }
    }
    Ok((Some(release), route))
}

/// Run `attempt` through the local proxy first (when connected), then
/// directly.
async fn on_any_route<T, F, Fut>(proxy: Option<u16>, attempt: F) -> Result<(T, Option<u16>), String>
where
    F: Fn(Option<u16>) -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let routes: Vec<Option<u16>> = match proxy {
        Some(port) => vec![Some(port), None],
        None => vec![None],
    };
    let mut last = String::new();
    for route in routes {
        match attempt(route).await {
            Ok(value) => return Ok((value, route)),
            Err(e) => last = e,
        }
    }
    Err(last)
}

// ------------------------------------------------------------------ install

/// Download `release` over this installation. `progress` gets
/// `(received, total)` as bytes arrive. Returns the path now holding the
/// new version.
pub async fn download_and_install(
    release: &Release,
    target: &Target,
    proxy: Option<u16>,
    progress: impl Fn(u64, u64) + Clone,
) -> Result<PathBuf, String> {
    let asset = release
        .asset
        .as_ref()
        .ok_or("this release has no download for this system")?;
    let staging = staging_path(&target.path);
    let (_, _) = on_any_route(proxy, |route| {
        let progress = progress.clone();
        let staging = staging.clone();
        async move { download(asset, &staging, route, progress).await }
    })
    .await
    .inspect_err(|_| {
        let _ = std::fs::remove_file(&staging);
    })?;
    let installed = swap_in(&staging, &target.path);
    if installed.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
    installed?;
    finish_platform(&target.path, &release.version);
    Ok(target.path.clone())
}

/// Where a download is written: beside the file it replaces, so the swap
/// is a rename within one directory.
fn staging_path(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "zeronet".into());
    target.with_file_name(format!(".{name}.update"))
}

/// Files an earlier update left behind: the program it replaced on
/// Windows (which cannot delete itself while running) and an interrupted
/// download.
pub fn clean_leftovers() {
    let Some(target) = Target::current() else {
        return;
    };
    let _ = std::fs::remove_file(staging_path(&target.path));
    let _ = std::fs::remove_file(retired_path(&target.path));
}

fn retired_path(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_os_string();
    name.push(".old");
    PathBuf::from(name)
}

async fn download(
    asset: &Asset,
    dest: &Path,
    route: Option<u16>,
    progress: impl Fn(u64, u64),
) -> Result<(), String> {
    let mut file = std::fs::File::create(dest).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "ZeroNet cannot write to {}. Download the update from the release page instead.",
                dest.parent().unwrap_or(dest).display()
            )
        } else {
            format!("cannot save the download: {e}")
        }
    })?;
    let mut response = get_following_redirects(&asset.url, route).await?;
    if response.chunked {
        return Err("the download server sent an unexpected response".into());
    }
    let total = response.length.unwrap_or(asset.size);
    if total > MAX_DOWNLOAD_BYTES {
        return Err("the download is unexpectedly large".into());
    }
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    let mut write = |chunk: &[u8], received: &mut u64| -> Result<(), String> {
        hasher.update(chunk);
        file.write_all(chunk)
            .map_err(|e| format!("cannot save the download: {e}"))?;
        *received += chunk.len() as u64;
        progress(*received, total);
        Ok(())
    };
    let early = std::mem::take(&mut response.body_start);
    write(&early, &mut received)?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if response.length.is_some_and(|len| received >= len) {
            break;
        }
        let n = match tokio::time::timeout(READ_TIMEOUT, response.stream.read(&mut buf)).await {
            Err(_) => return Err("the download stalled".into()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Ok(Err(e)) => return Err(format!("the download was cut off: {e}")),
        };
        if n == 0 {
            break;
        }
        write(&buf[..n], &mut received)?;
        if received > MAX_DOWNLOAD_BYTES {
            return Err("the download is unexpectedly large".into());
        }
    }
    if response.length.is_some_and(|len| received < len)
        || (asset.size > 0 && received != asset.size)
    {
        return Err("the download was cut off before it finished".into());
    }
    file.sync_all()
        .map_err(|e| format!("cannot save the download: {e}"))?;
    let digest = hex(&hasher.finalize());
    if let Some(expected) = &asset.sha256 {
        if &digest != expected {
            return Err("the download is damaged (its checksum does not match)".into());
        }
    }
    Ok(())
}

/// Put the staged download where the program lives.
fn swap_in(staging: &Path, target: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(staging, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("cannot make the update executable: {e}"))?;
        std::fs::rename(staging, target)
            .map_err(|e| format!("cannot replace {}: {e}", target.display()))
    }
    #[cfg(windows)]
    {
        // A running program cannot be overwritten on Windows, but it can be
        // renamed: move it aside, put the new one in its place, and delete
        // the old one on the next start (`clean_leftovers`).
        let retired = retired_path(target);
        let _ = std::fs::remove_file(&retired);
        std::fs::rename(target, &retired)
            .map_err(|e| format!("cannot replace {}: {e}", target.display()))?;
        if let Err(e) = std::fs::rename(staging, target) {
            let _ = std::fs::rename(&retired, target);
            return Err(format!("cannot replace {}: {e}", target.display()));
        }
        Ok(())
    }
}

/// Platform upkeep after a swap. On macOS the program sits in a signed
/// `.app` bundle whose seal covers it: the bundle is re-signed (ad hoc, as
/// the release does) and its version updated, so Finder keeps opening it.
fn finish_platform(target: &Path, version: &str) {
    if !cfg!(target_os = "macos") {
        let _ = (target, version);
        return;
    }
    let Some(bundle) = target
        .ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
    else {
        return;
    };
    let plist = bundle.join("Contents/Info.plist");
    for key in ["CFBundleShortVersionString", "CFBundleVersion"] {
        let _ = std::process::Command::new("/usr/bin/plutil")
            .args(["-replace", key, "-string", version])
            .arg(&plist)
            .output();
    }
    let _ = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--deep", "--sign", "-"])
        .arg(bundle)
        .output();
}

/// Start the updated program in place of this one, with the same
/// arguments. Only returns if that fails.
pub fn relaunch(path: &Path) -> std::io::Error {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        std::process::Command::new(path).args(args).exec()
    }
    #[cfg(not(unix))]
    {
        match std::process::Command::new(path).args(args).status() {
            Ok(status) => std::process::exit(status.code().unwrap_or(0)),
            Err(e) => e,
        }
    }
}

/// Open a web page in the default browser.
pub fn open_in_browser(url: &str) -> std::io::Result<()> {
    let mut command = if cfg!(windows) {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else {
        std::process::Command::new("xdg-open")
    };
    command
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------------ HTTP

/// An `https://` URL, split.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpsUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_https(url: &str) -> Result<HttpsUrl, String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("not an https address: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => match p.parse() {
            Ok(port) => (h, port),
            Err(_) => (authority, 443),
        },
        _ => (authority, 443),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(format!("no host in {url}"));
    }
    Ok(HttpsUrl {
        host: host.to_string(),
        port,
        path: path.to_string(),
    })
}

type Tls = tokio_rustls::client::TlsStream<TcpStream>;

struct Response {
    status: u16,
    location: Option<String>,
    length: Option<u64>,
    chunked: bool,
    /// Body bytes that arrived with the headers.
    body_start: Vec<u8>,
    stream: Tls,
}

/// Open a TLS connection to `url`, through the local HTTP proxy when
/// `route` names its port.
async fn connect(url: &HttpsUrl, route: Option<u16>) -> Result<Tls, String> {
    let reach = |e: std::io::Error| format!("cannot reach {}: {e}", url.host);
    let tcp = match route {
        None => tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((url.host.as_str(), url.port)),
        )
        .await
        .map_err(|_| format!("cannot reach {}: timed out", url.host))?
        .map_err(reach)?,
        Some(port) => {
            let mut tcp =
                tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
                    .await
                    .map_err(|_| "the local proxy did not answer".to_string())?
                    .map_err(|e| format!("the local proxy did not answer: {e}"))?;
            let authority = if url.host.contains(':') {
                format!("[{}]:{}", url.host, url.port)
            } else {
                format!("{}:{}", url.host, url.port)
            };
            let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
            tcp.write_all(request.as_bytes()).await.map_err(reach)?;
            let (head, _) = read_head(&mut tcp).await?;
            let status = status_of(&head)?;
            if !(200..300).contains(&status) {
                return Err(format!(
                    "the local proxy refused the connection (HTTP {status})"
                ));
            }
            tcp
        }
    };
    let name = rustls_pki_types::ServerName::try_from(url.host.clone())
        .map_err(|_| format!("{:?} is not a valid server name", url.host))?;
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_rustls::TlsConnector::from(tls_config()).connect(name, tcp),
    )
    .await
    .map_err(|_| format!("cannot reach {}: timed out", url.host))?
    .map_err(|e| format!("secure connection to {} failed: {e}", url.host))
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// Read up to the blank line ending an HTTP head. Returns the head and any
/// body bytes read past it.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(String, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..at]).into_owned();
            return Ok((head, buf[at + 4..].to_vec()));
        }
        if buf.len() > 64 * 1024 {
            return Err("the server sent an oversized header".into());
        }
        let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut chunk))
            .await
            .map_err(|_| "the server stopped answering".to_string())?
            .map_err(|e| format!("the connection failed: {e}"))?;
        if n == 0 {
            return Err("the server closed the connection".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn status_of(head: &str) -> Result<u16, String> {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| "the server sent a malformed answer".to_string())
}

async fn get_once(url: &HttpsUrl, route: Option<u16>) -> Result<Response, String> {
    let mut stream = connect(url, route).await?;
    let host = if url.port == 443 {
        url.host.clone()
    } else {
        format!("{}:{}", url.host, url.port)
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ZeroNet/{CURRENT_VERSION}\r\n\
         Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        url.path
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("cannot reach {}: {e}", url.host))?;
    let (head, body_start) = read_head(&mut stream).await?;
    let status = status_of(&head)?;
    let mut location = None;
    let mut length = None;
    let mut chunked = false;
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "location" => location = Some(value.to_string()),
            "content-length" => length = value.parse().ok(),
            "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
            _ => {}
        }
    }
    Ok(Response {
        status,
        location,
        length,
        chunked,
        body_start,
        stream,
    })
}

async fn get_following_redirects(url: &str, route: Option<u16>) -> Result<Response, String> {
    let mut url = parse_https(url)?;
    for _ in 0..=MAX_REDIRECTS {
        let response = get_once(&url, route).await?;
        match response.status {
            200..=299 => return Ok(response),
            301 | 302 | 303 | 307 | 308 => {
                let location = response.location.ok_or("the server redirected nowhere")?;
                url = if location.starts_with('/') {
                    HttpsUrl {
                        path: location,
                        ..url
                    }
                } else {
                    parse_https(&location)?
                };
            }
            403 | 429 => return Err("GitHub is limiting requests; try again in a while".into()),
            404 => return Err("no release was found".into()),
            status => return Err(format!("the server answered HTTP {status}")),
        }
    }
    Err("too many redirects".into())
}

async fn fetch_text(url: &str, route: Option<u16>) -> Result<String, String> {
    let mut response = get_following_redirects(url, route).await?;
    let mut body = std::mem::take(&mut response.body_start);
    let mut buf = [0u8; 16 * 1024];
    loop {
        if response.length.is_some_and(|len| body.len() as u64 >= len) {
            break;
        }
        let n = match tokio::time::timeout(READ_TIMEOUT, response.stream.read(&mut buf)).await {
            Err(_) => return Err("the server stopped answering".into()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Ok(Err(e)) => return Err(format!("the connection failed: {e}")),
        };
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
        if body.len() > MAX_TEXT_BYTES {
            return Err("the answer is unexpectedly large".into());
        }
    }
    if response.chunked {
        body = decode_chunked(&body)?;
    } else if let Some(len) = response.length {
        body.truncate(len as usize);
    }
    String::from_utf8(body).map_err(|_| "the answer is not text".to_string())
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let end = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("truncated answer")?;
        let size_text = String::from_utf8_lossy(&input[..end]);
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| "malformed answer".to_string())?;
        input = &input[end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if input.len() < size {
            return Err("truncated answer".into());
        }
        out.extend_from_slice(&input[..size]);
        input = input.get(size + 2..).unwrap_or(&[]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_numerically() {
        assert!(is_newer("v0.1.10", "0.1.9"));
        assert!(is_newer("0.2.0", "0.1.99"));
        assert!(is_newer("1.0.0", "1.0.0-beta"));
        assert!(!is_newer("1.0.0-beta", "1.0.0"));
        assert!(!is_newer("v0.1.4", "0.1.4"));
        assert!(!is_newer("v0.1.3", "0.1.4"));
        assert!(!is_newer("nightly", "0.1.4"));
        assert!(is_newer("0.2", "0.1.4"));
    }

    const RELEASE: &str = r###"{
        "tag_name": "v0.1.5",
        "html_url": "https://github.com/zeghostwriter/ZeroNet/releases/tag/v0.1.5",
        "body": "## Download\n\n| | |\n|---|---|\n| Windows | `x.zip` |\n\n## What's Changed\n* Server tests: survive forged DNS by @someone in https://github.com/x/y/pull/10\n* README: fix layout by @someone in https://github.com/x/y/pull/11\n\n## New Contributors\n* @a made their first contribution in https://github.com/x/y/pull/1\n\n**Full Changelog**: https://github.com/x/y/compare/v0.1.4...v0.1.5",
        "assets": [
            {"name": "ZeroNet-Windows-x64.exe", "size": 123, "browser_download_url": "https://github.com/x/y/releases/download/v0.1.5/ZeroNet-Windows-x64.exe"},
            {"name": "SHA256SUMS.txt", "size": 10, "browser_download_url": "https://github.com/x/y/releases/download/v0.1.5/SHA256SUMS.txt"}
        ]
    }"###;

    #[test]
    fn a_release_yields_its_version_notes_and_file() {
        let release = parse_release(RELEASE, Some("ZeroNet-Windows-x64.exe")).unwrap();
        assert_eq!(release.version, "0.1.5");
        assert_eq!(
            release.notes,
            vec!["Server tests: survive forged DNS", "README: fix layout"]
        );
        let asset = release.asset.unwrap();
        assert_eq!(asset.size, 123);
        assert!(asset.url.ends_with("/ZeroNet-Windows-x64.exe"));
        assert_eq!(
            checksums_url(RELEASE).as_deref(),
            Some("https://github.com/x/y/releases/download/v0.1.5/SHA256SUMS.txt")
        );
    }

    #[test]
    fn a_release_without_this_platforms_file_has_no_asset() {
        let release = parse_release(RELEASE, Some("ZeroNet-macOS-universal")).unwrap();
        assert!(release.asset.is_none());
        assert!(parse_release(RELEASE, None).unwrap().asset.is_none());
    }

    #[test]
    fn checksums_are_found_by_file_name() {
        let hash = "a".repeat(64);
        let listing = format!(
            "{hash}  ZeroNet-Linux-x86_64\n{}  ZeroNet-Linux-x86_64.AppImage\n",
            "b".repeat(64)
        );
        assert_eq!(checksum_for(&listing, "ZeroNet-Linux-x86_64"), Some(hash));
        assert_eq!(
            checksum_for(&listing, "ZeroNet-Linux-x86_64.AppImage"),
            Some("b".repeat(64))
        );
        assert_eq!(checksum_for(&listing, "ZeroNet-Linux"), None);
        assert_eq!(checksum_for("short  ZeroNet-Linux", "ZeroNet-Linux"), None);
    }

    #[test]
    fn https_urls_split_into_host_port_and_path() {
        assert_eq!(
            parse_https("https://api.github.com/repos/a/b").unwrap(),
            HttpsUrl {
                host: "api.github.com".into(),
                port: 443,
                path: "/repos/a/b".into()
            }
        );
        assert_eq!(parse_https("https://h:8443").unwrap().port, 8443);
        assert_eq!(parse_https("https://h:8443").unwrap().path, "/");
        assert!(parse_https("http://h/").is_err());
    }

    #[test]
    fn chunked_answers_are_decoded() {
        assert_eq!(
            decode_chunked(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").unwrap(),
            b"abcde"
        );
        assert!(decode_chunked(b"5\r\nab").is_err());
    }

    #[test]
    fn staging_sits_beside_the_target() {
        let staged = staging_path(Path::new("/opt/zeronet/ZeroNet.AppImage"));
        assert_eq!(staged, Path::new("/opt/zeronet/.ZeroNet.AppImage.update"));
        assert_eq!(
            retired_path(Path::new("C:/ZeroNet/ZeroNet.exe")),
            Path::new("C:/ZeroNet/ZeroNet.exe.old")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_staged_file_replaces_the_target() {
        let dir = std::env::temp_dir().join(format!("zeronet-update-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("zeronet");
        std::fs::write(&target, b"old").unwrap();
        let staged = staging_path(&target);
        std::fs::write(&staged, b"new").unwrap();
        swap_in(&staged, &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert!(!staged.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
