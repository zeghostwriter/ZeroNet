//! Rule-set asset acquisition: download, validate, cache, refresh.
//!
//! Routing data is the one input that arrives over the same network the router
//! is trying to escape, which makes every interesting failure a *content*
//! failure rather than a transport one. A captive portal answers 200 with an
//! HTML login page; a throttled CDN closes mid-transfer; a mirror serves a
//! sing-box `.srs` where an Xray `.dat` was expected. All three produce a file
//! on disk, and all three surface much later as an opaque parse error — the
//! classic "unexpected EOF" on a rule set that downloaded "successfully".
//!
//! The rule this module enforces is therefore: **a byte sequence becomes the
//! live rule set only after it has been parsed**. Validation happens before the
//! install, the install is atomic, and a file that fails validation is moved
//! aside with its reason recorded rather than left in place to fail again.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};
use zero_net::fetch::{fetch, FetchLimits, Fetched, Validators};

use crate::matcher::GeoData;

/// Which container a cached file is expected to hold. Validation is per kind,
/// so a geosite mirror that starts serving geoip data is rejected instead of
/// quietly producing a router with no domain rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetKind {
    Geosite,
    Geoip,
}

impl AssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Geosite => "geosite",
            Self::Geoip => "geoip",
        }
    }
}

/// One asset and where it can be obtained. Mirrors are tried in order; the
/// first that both downloads *and* validates wins.
#[derive(Debug, Clone)]
pub struct AssetSpec {
    pub name: String,
    pub kind: AssetKind,
    pub urls: Vec<String>,
    /// Optional content pin. When present a mirror whose bytes do not match is
    /// rejected even if it parses, which is what makes an untrusted mirror
    /// usable at all.
    pub sha256: Option<[u8; 32]>,
}

impl AssetSpec {
    pub fn new(name: impl Into<String>, kind: AssetKind, urls: Vec<String>) -> Self {
        Self {
            name: name.into(),
            kind,
            urls,
            sha256: None,
        }
    }

    pub fn with_sha256(mut self, digest: [u8; 32]) -> Self {
        self.sha256 = Some(digest);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetPolicy {
    /// How long a validated file is considered current.
    pub refresh_interval: Duration,
    /// How long to wait before retrying after every mirror failed. Without
    /// this a permanently blocked mirror is re-dialled on every tick.
    pub retry_interval: Duration,
    pub limits: FetchLimits,
}

impl Default for AssetPolicy {
    fn default() -> Self {
        Self {
            refresh_interval: Duration::from_secs(24 * 60 * 60),
            retry_interval: Duration::from_secs(15 * 60),
            limits: FetchLimits {
                max_bytes: 64 * 1024 * 1024,
                timeout: Duration::from_secs(120),
                max_redirects: 5,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// Cache is current; nothing was fetched.
    Fresh,
    /// The origin confirmed the cached copy is still current.
    Unchanged,
    Updated {
        bytes: usize,
        entries: usize,
    },
    /// Every mirror failed. The cached copy, if any, is still serving.
    Failed {
        reasons: Vec<String>,
    },
}

impl RefreshOutcome {
    pub fn changed(&self) -> bool {
        matches!(self, Self::Updated { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AssetMetadata {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub sha256: Option<String>,
    pub fetched_at: Option<SystemTime>,
    pub len: Option<usize>,
    pub entries: Option<usize>,
    pub source: Option<String>,
}

/// A validated on-disk rule-set cache.
#[derive(Debug, Clone)]
pub struct AssetStore {
    dir: PathBuf,
    policy: AssetPolicy,
}

impl AssetStore {
    pub fn new(dir: impl Into<PathBuf>, policy: AssetPolicy) -> Self {
        Self {
            dir: dir.into(),
            policy,
        }
    }

    /// Resolve the cache directory the host application should use. An
    /// explicit override always wins so a sandboxed or read-only deployment
    /// can place the cache where it actually has write access.
    pub fn default_dir() -> PathBuf {
        if let Some(explicit) = std::env::var_os("ZRAY_ASSET_DIR") {
            return PathBuf::from(explicit);
        }
        if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(state).join("zray").join("assets");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("zray")
                .join("assets");
        }
        std::env::temp_dir().join("zray-assets")
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn policy(&self) -> &AssetPolicy {
        &self.policy
    }

    fn data_path(&self, spec: &AssetSpec) -> PathBuf {
        self.dir.join(&spec.name)
    }

    fn meta_path(&self, spec: &AssetSpec) -> PathBuf {
        self.dir.join(format!("{}.meta", spec.name))
    }

    /// Read and validate the cached copy. A file that fails validation is
    /// quarantined rather than returned, so the router starts with no data for
    /// that tag — which it reports — instead of with wrong data, which it
    /// could not report.
    pub fn load(&self, spec: &AssetSpec) -> Result<Vec<u8>, String> {
        self.load_validated(spec).map(|(bytes, _)| bytes)
    }

    /// Read the cached copy and parse it exactly once, returning both the raw
    /// bytes and the decoded data. Validation *is* decoding, so a caller that
    /// wants the data must not pay for the parse twice — on a 60 MB geosite
    /// container that second pass is most of the startup cost.
    fn load_validated(&self, spec: &AssetSpec) -> Result<(Vec<u8>, GeoData), String> {
        let path = self.data_path(spec);
        let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        match validate_decoded(spec.kind, &bytes) {
            Ok((data, _)) => Ok((bytes, data)),
            Err(reason) => {
                self.quarantine(spec, &reason);
                Err(reason)
            }
        }
    }

    /// Load every spec that has a usable cached copy, merged into one dataset.
    /// Specs with no valid cache are reported by name; the caller decides
    /// whether that is fatal.
    pub fn load_geodata(&self, specs: &[AssetSpec]) -> (GeoData, Vec<String>) {
        let mut data = GeoData::default();
        let mut problems = Vec::new();
        for spec in specs {
            match self.load_validated(spec) {
                Ok((_, parsed)) => data.merge(parsed),
                Err(reason) => problems.push(format!("{}: {reason}", spec.name)),
            }
        }
        (data, problems)
    }

    pub fn metadata(&self, spec: &AssetSpec) -> AssetMetadata {
        read_metadata(&self.meta_path(spec)).unwrap_or_default()
    }

    /// Whether a refresh is due. A cache that exists but never validated has no
    /// metadata, so it is always due.
    pub fn is_stale(&self, spec: &AssetSpec) -> bool {
        if !self.data_path(spec).exists() {
            return true;
        }
        let metadata = self.metadata(spec);
        let Some(fetched_at) = metadata.fetched_at else {
            return true;
        };
        match SystemTime::now().duration_since(fetched_at) {
            Ok(age) => age >= self.policy.refresh_interval,
            // A clock that moved backwards must not pin the cache as fresh
            // forever; treat it as due and let validation gate the result.
            Err(_) => true,
        }
    }

    /// Download, validate and install if due. `force` bypasses the TTL but not
    /// validation.
    pub async fn refresh(&self, spec: &AssetSpec, force: bool) -> RefreshOutcome {
        if !force && !self.is_stale(spec) {
            return RefreshOutcome::Fresh;
        }
        if spec.urls.is_empty() {
            return RefreshOutcome::Failed {
                reasons: vec![format!("{}: no mirrors configured", spec.name)],
            };
        }
        if let Err(error) = std::fs::create_dir_all(&self.dir) {
            return RefreshOutcome::Failed {
                reasons: vec![format!("{}: {error}", self.dir.display())],
            };
        }

        let cached = self.data_path(spec).exists();
        let metadata = self.metadata(spec);
        let mut reasons = Vec::new();

        for url in &spec.urls {
            // Conditional requests only make sense against the mirror that
            // issued the validators, and only while the cached file is still
            // there to be revalidated.
            let validators = if cached && metadata.source.as_deref() == Some(url.as_str()) {
                Validators {
                    etag: metadata.etag.clone(),
                    last_modified: metadata.last_modified.clone(),
                }
            } else {
                Validators::default()
            };

            let fetched = match fetch(url, &self.policy.limits, &validators).await {
                Ok(fetched) => fetched,
                Err(error) => {
                    reasons.push(format!("{url}: {error}"));
                    continue;
                }
            };

            // Hashing, parsing and the fsync'd install are CPU- and
            // disk-bound: tens of milliseconds to a second on a full geosite
            // container. They run on the blocking pool so a refresh never
            // stalls the runtime worker that is also relaying traffic.
            let store = self.clone();
            let task_spec = spec.clone();
            let task_url = url.clone();
            let task_metadata = metadata.clone();
            let installed = tokio::task::spawn_blocking(move || match fetched {
                Fetched::NotModified => store.restamp_unchanged(&task_spec, task_metadata),
                Fetched::Body { body, validators } => {
                    store.install_fetched(&task_spec, &task_url, body, validators)
                }
            })
            .await
            .unwrap_or_else(|error| Err(format!("validation task failed: {error}")));
            match installed {
                Ok(outcome) => return outcome,
                Err(reason) => reasons.push(format!("{url}: {reason}")),
            }
        }

        RefreshOutcome::Failed { reasons }
    }

    /// Re-stamp an asset the origin reported unchanged, so it does not
    /// re-probe every tick — but only if what is on disk still parses.
    fn restamp_unchanged(
        &self,
        spec: &AssetSpec,
        mut metadata: AssetMetadata,
    ) -> Result<RefreshOutcome, String> {
        self.load_validated(spec)
            .map_err(|reason| format!("cached copy is unusable ({reason})"))?;
        metadata.fetched_at = Some(SystemTime::now());
        let _ = write_metadata(&self.meta_path(spec), &metadata);
        Ok(RefreshOutcome::Unchanged)
    }

    /// Pin-check, validate and atomically install one downloaded body.
    fn install_fetched(
        &self,
        spec: &AssetSpec,
        url: &str,
        body: Vec<u8>,
        validators: Validators,
    ) -> Result<RefreshOutcome, String> {
        let digest: [u8; 32] = Sha256::digest(&body).into();
        if let Some(expected) = spec.sha256 {
            if digest != expected {
                return Err(format!(
                    "sha256 is {} but {} was pinned",
                    hex_lower(&digest),
                    hex_lower(&expected)
                ));
            }
        }

        // The gate. Parse before install, never after.
        let entries = validate(spec.kind, &body)?;

        install_atomically(&self.data_path(spec), &body)
            .map_err(|error| format!("installing: {error}"))?;
        let _ = write_metadata(
            &self.meta_path(spec),
            &AssetMetadata {
                etag: validators.etag,
                last_modified: validators.last_modified,
                sha256: Some(hex_lower(&digest)),
                fetched_at: Some(SystemTime::now()),
                len: Some(body.len()),
                entries: Some(entries),
                source: Some(url.to_owned()),
            },
        );
        Ok(RefreshOutcome::Updated {
            bytes: body.len(),
            entries,
        })
    }

    /// Refresh every spec, reporting per-asset outcomes in input order.
    pub async fn refresh_all(
        &self,
        specs: &[AssetSpec],
        force: bool,
    ) -> Vec<(String, RefreshOutcome)> {
        let mut outcomes = Vec::with_capacity(specs.len());
        for spec in specs {
            outcomes.push((spec.name.clone(), self.refresh(spec, force).await));
        }
        outcomes
    }

    /// Move a file that failed validation aside so the next start does not
    /// retry the same broken bytes, and record why next to it.
    fn quarantine(&self, spec: &AssetSpec, reason: &str) {
        let path = self.data_path(spec);
        let rejected = self.dir.join(format!("{}.rejected", spec.name));
        let _ = std::fs::rename(&path, &rejected);
        let _ = std::fs::write(
            self.dir.join(format!("{}.rejected.reason", spec.name)),
            reason.as_bytes(),
        );
        let _ = std::fs::remove_file(self.meta_path(spec));
    }
}

/// Write via a temporary file in the same directory, then rename. A rename
/// within one filesystem is atomic, so a reader either sees the whole previous
/// file or the whole new one — never the partial write that produces an
/// "unexpected EOF" on the next start.
fn install_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "asset".into()),
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default(),
    ));
    let result = (|| {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        // Durability before visibility: the rename must not be able to expose
        // a name whose contents have not reached the disk.
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Parse `bytes` as `kind`, returning the entry count. Every rejection names
/// the actual shape found, because "unexpected EOF" on a rule set is almost
/// never a truncation — it is usually an HTML error page or the wrong format.
pub fn validate(kind: AssetKind, bytes: &[u8]) -> Result<usize, String> {
    validate_decoded(kind, bytes).map(|(_, entries)| entries)
}

/// [`validate`], keeping the decoded data for callers that need it.
fn validate_decoded(kind: AssetKind, bytes: &[u8]) -> Result<(GeoData, usize), String> {
    if bytes.is_empty() {
        return Err("file is empty".into());
    }
    if let Some(shape) = recognise_foreign_shape(bytes) {
        return Err(shape);
    }
    let data = decode(kind, bytes)?;
    let entries = match kind {
        AssetKind::Geosite => data.geosite.len(),
        AssetKind::Geoip => data.geoip.len(),
    };
    if entries == 0 {
        return Err(format!("{} container holds no entries", kind.as_str()));
    }
    Ok((data, entries))
}

/// Decode a validated container into matcher data. Xray's protobuf form is
/// tried first, then the line-oriented form.
pub fn decode(kind: AssetKind, bytes: &[u8]) -> Result<GeoData, String> {
    let protobuf = match kind {
        AssetKind::Geosite => GeoData::from_xray_geosite(bytes),
        AssetKind::Geoip => GeoData::from_xray_geoip(bytes),
    };
    let protobuf_error = match protobuf {
        Ok(data) => return Ok(data),
        Err(error) => error,
    };
    let text = std::str::from_utf8(bytes).map_err(|_| {
        format!(
            "not an Xray {} container ({protobuf_error}) and not UTF-8 text",
            kind.as_str()
        )
    })?;
    // The line-oriented form is checked strictly before it is parsed. The
    // permissive parser used at runtime would otherwise accept the tail of a
    // truncated binary container as a list of tags, which is exactly the way a
    // corrupt download turns into a silently wrong routing table.
    check_line_format(kind, text).map_err(|reason| {
        format!(
            "not an Xray {} container ({protobuf_error}); as a text rule set: {reason}",
            kind.as_str()
        )
    })?;
    let data = match kind {
        AssetKind::Geosite => GeoData::from_lines(text, ""),
        AssetKind::Geoip => GeoData::from_lines("", text),
    };
    if data.is_empty() {
        return Err(format!(
            "not an Xray {} container ({protobuf_error}) and the text form parsed to nothing",
            kind.as_str()
        ));
    }
    Ok(data)
}

/// Strict syntax check for the line-oriented rule-set form: `<tag> <pattern>`,
/// one per line, `#` comments allowed. Any control byte or malformed line
/// rejects the whole file — a rule set is not a best-effort document.
fn check_line_format(kind: AssetKind, text: &str) -> Result<(), String> {
    if let Some(bad) = text
        .chars()
        .find(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(format!(
            "contains the control byte {:#04x}, so it is binary data rather than a text rule set",
            bad as u32
        ));
    }
    let mut accepted = 0usize;
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let tag = fields.next().unwrap_or_default();
        let pattern = fields
            .next()
            .ok_or_else(|| format!("line {} has no pattern", number + 1))?;
        if fields.next().is_some() {
            return Err(format!("line {} has more than two fields", number + 1));
        }
        if tag.is_empty()
            || !tag
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!("line {} has an invalid tag `{tag}`", number + 1));
        }
        match kind {
            AssetKind::Geoip => {
                let accepted_cidr = pattern.parse::<ipnet::IpNet>().is_ok()
                    || pattern.parse::<std::net::IpAddr>().is_ok();
                if !accepted_cidr {
                    return Err(format!(
                        "line {} pattern `{pattern}` is not a CIDR or address",
                        number + 1
                    ));
                }
            }
            AssetKind::Geosite => {
                let value = pattern
                    .split_once(':')
                    .map(|(prefix, rest)| {
                        if matches!(prefix, "domain" | "full" | "keyword" | "regexp") {
                            rest
                        } else {
                            pattern
                        }
                    })
                    .unwrap_or(pattern);
                if value.is_empty() {
                    return Err(format!("line {} has an empty pattern", number + 1));
                }
            }
        }
        accepted += 1;
    }
    if accepted == 0 {
        return Err("no rule lines".into());
    }
    Ok(())
}

/// Name the format when the bytes are clearly something other than a rule set.
/// This is what turns a silent downstream parse failure into an actionable
/// message at the point of download.
fn recognise_foreign_shape(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(b"SRS") {
        let version = bytes.get(3).copied().unwrap_or(0);
        return Some(format!(
            "this is a sing-box binary rule-set (SRS v{version}), not an Xray geodata container; \
             point the mirror at a `.dat` container or a sing-box source `.json` rule set"
        ));
    }
    if bytes.starts_with(b"\x1f\x8b") {
        return Some("this is gzip-compressed; the mirror must serve the container itself".into());
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return Some("this is a ZIP archive, not a rule-set container".into());
    }
    if bytes.starts_with(b"\x28\xb5\x2f\xfd") {
        return Some("this is zstd-compressed, not a rule-set container".into());
    }
    let head = &bytes[..bytes.len().min(512)];
    let text = String::from_utf8_lossy(head);
    let trimmed = text.trim_start();
    let lowered = trimmed.to_ascii_lowercase();
    if lowered.starts_with("<!doctype html") || lowered.starts_with("<html") {
        return Some(
            "the mirror returned an HTML page, not a rule set — this is what a captive portal, \
             a block page or an expired link looks like"
                .into(),
        );
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return Some(
            "the mirror returned JSON, not an Xray geodata container — a sing-box source rule set \
             must be converted before use"
                .into(),
        );
    }
    None
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Parse a sha256 pin written as 64 hex characters.
pub fn parse_sha256(value: &str) -> Result<[u8; 32], String> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("sha256 pin must be 64 hexadecimal characters".into());
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| error.to_string())?;
    }
    Ok(out)
}

fn write_metadata(path: &Path, metadata: &AssetMetadata) -> std::io::Result<()> {
    let mut body = String::new();
    let mut push = |key: &str, value: Option<String>| {
        if let Some(value) = value {
            if !value.contains('\n') {
                body.push_str(key);
                body.push('=');
                body.push_str(&value);
                body.push('\n');
            }
        }
    };
    push("etag", metadata.etag.clone());
    push("last-modified", metadata.last_modified.clone());
    push("sha256", metadata.sha256.clone());
    push("source", metadata.source.clone());
    push("len", metadata.len.map(|value| value.to_string()));
    push("entries", metadata.entries.map(|value| value.to_string()));
    push(
        "fetched-at",
        metadata.fetched_at.and_then(|at| {
            at.duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .map(|since| since.as_secs().to_string())
        }),
    );
    install_atomically(path, body.as_bytes())
}

fn read_metadata(path: &Path) -> Option<AssetMetadata> {
    let text = std::fs::read_to_string(path).ok()?;
    let fields: BTreeMap<&str, &str> = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    Some(AssetMetadata {
        etag: fields.get("etag").map(|value| (*value).to_string()),
        last_modified: fields
            .get("last-modified")
            .map(|value| (*value).to_string()),
        sha256: fields.get("sha256").map(|value| (*value).to_string()),
        source: fields.get("source").map(|value| (*value).to_string()),
        len: fields.get("len").and_then(|value| value.parse().ok()),
        entries: fields.get("entries").and_then(|value| value.parse().ok()),
        fetched_at: fields
            .get("fetched-at")
            .and_then(|value| value.parse::<u64>().ok())
            .map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// GeoSiteList{entry:{country_code:"ir", domain:{type:RootDomain, value:"example.com"}}}
    fn geosite_fixture() -> Vec<u8> {
        vec![
            0x0a, 0x15, 0x0a, 0x02, b'i', b'r', 0x12, 0x0f, 0x08, 0x02, 0x12, 0x0b, b'e', b'x',
            b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        ]
    }

    /// GeoIPList{entry:{country_code:"ir", cidr:{ip:203.0.113.0, prefix:24}}}
    fn geoip_fixture() -> Vec<u8> {
        vec![
            0x0a, 0x0e, 0x0a, 0x02, b'i', b'r', 0x12, 0x08, 0x0a, 0x04, 203, 0, 113, 0, 0x10, 0x18,
        ]
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zray-assets-{}-{}-{name}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Serve one canned response per connection.
    async fn serve(
        responses: Vec<Vec<u8>>,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&hits);
        tokio::spawn(async move {
            let mut index = 0usize;
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let response = responses
                    .get(index)
                    .cloned()
                    .unwrap_or_else(|| responses.last().cloned().unwrap_or_default());
                index += 1;
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            }
        });
        (format!("http://{address}/geosite.dat"), hits)
    }

    fn ok_response(body: &[u8], extra: &str) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{extra}\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn a_truncated_container_never_validates() {
        let full = geosite_fixture();
        assert!(validate(AssetKind::Geosite, &full).is_ok());
        let truncated = &full[..full.len() - 4];
        assert!(validate(AssetKind::Geosite, truncated).is_err());
    }

    #[test]
    fn foreign_shapes_are_named_rather_than_reported_as_eof() {
        let html = b"<!DOCTYPE html>\n<html><body>Access denied</body></html>";
        let error = validate(AssetKind::Geosite, html).unwrap_err();
        assert!(error.contains("HTML"), "{error}");

        let srs = b"SRS\x03\x78\x9c\x00";
        let error = validate(AssetKind::Geosite, srs).unwrap_err();
        assert!(error.contains("sing-box"), "{error}");
        assert!(error.contains("SRS v3"), "{error}");

        let gzip = b"\x1f\x8b\x08\x00zzzz";
        assert!(validate(AssetKind::Geoip, gzip)
            .unwrap_err()
            .contains("gzip"));

        let json = br#"{"version":1,"rules":[]}"#;
        assert!(validate(AssetKind::Geoip, json)
            .unwrap_err()
            .contains("JSON"));

        assert!(validate(AssetKind::Geosite, b"")
            .unwrap_err()
            .contains("empty"));
    }

    #[test]
    fn a_geoip_container_is_refused_where_geosite_was_expected() {
        let error = validate(AssetKind::Geosite, &geoip_fixture()).unwrap_err();
        assert!(!error.is_empty());
    }

    #[test]
    fn line_oriented_rule_sets_are_accepted() {
        let entries =
            validate(AssetKind::Geoip, b"ir 203.0.113.0/24\nir 198.51.100.0/24\n").unwrap();
        assert_eq!(entries, 1);
    }

    #[tokio::test]
    async fn a_validated_download_is_installed_and_then_considered_fresh() {
        let dir = temp_dir("install");
        let (url, hits) = serve(vec![ok_response(&geosite_fixture(), "ETag: \"a\"\r\n")]).await;
        let store = AssetStore::new(&dir, AssetPolicy::default());
        let spec = AssetSpec::new("geosite.dat", AssetKind::Geosite, vec![url]);

        let outcome = store.refresh(&spec, false).await;
        assert!(
            matches!(outcome, RefreshOutcome::Updated { entries: 1, .. }),
            "{outcome:?}"
        );
        assert!(store.load(&spec).is_ok());
        assert!(!store.is_stale(&spec));

        // A second refresh inside the TTL must not touch the network at all.
        assert_eq!(store.refresh(&spec, false).await, RefreshOutcome::Fresh);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_corrupt_download_leaves_the_previous_cache_serving() {
        let dir = temp_dir("keep-good");
        let good = ok_response(&geosite_fixture(), "");
        let bad = ok_response(b"<html>blocked</html>", "");
        let (url, _) = serve(vec![good, bad]).await;
        let store = AssetStore::new(&dir, AssetPolicy::default());
        let spec = AssetSpec::new("geosite.dat", AssetKind::Geosite, vec![url]);

        assert!(store.refresh(&spec, false).await.changed());
        let installed = store.load(&spec).unwrap();

        let outcome = store.refresh(&spec, true).await;
        match &outcome {
            RefreshOutcome::Failed { reasons } => {
                assert!(
                    reasons.iter().any(|reason| reason.contains("HTML")),
                    "{reasons:?}"
                )
            }
            other => panic!("unexpected {other:?}"),
        }
        // The point of the exercise: the good copy is untouched.
        assert_eq!(store.load(&spec).unwrap(), installed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_second_mirror_recovers_from_a_broken_first() {
        let dir = temp_dir("mirror");
        let (broken, _) = serve(vec![ok_response(b"<html>captive portal</html>", "")]).await;
        let (working, _) = serve(vec![ok_response(&geoip_fixture(), "")]).await;
        let store = AssetStore::new(&dir, AssetPolicy::default());
        let spec = AssetSpec::new("geoip.dat", AssetKind::Geoip, vec![broken, working]);

        let outcome = store.refresh(&spec, false).await;
        assert!(
            matches!(outcome, RefreshOutcome::Updated { entries: 1, .. }),
            "{outcome:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_mismatched_sha256_pin_is_refused_even_when_it_parses() {
        let dir = temp_dir("pin");
        let (url, _) = serve(vec![ok_response(&geosite_fixture(), "")]).await;
        let store = AssetStore::new(&dir, AssetPolicy::default());
        let spec =
            AssetSpec::new("geosite.dat", AssetKind::Geosite, vec![url]).with_sha256([0u8; 32]);

        match store.refresh(&spec, false).await {
            RefreshOutcome::Failed { reasons } => {
                assert!(
                    reasons.iter().any(|reason| reason.contains("sha256")),
                    "{reasons:?}"
                )
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(store.load(&spec).is_err());

        // The matching pin is accepted.
        let digest: [u8; 32] = Sha256::digest(geosite_fixture()).into();
        let (url, _) = serve(vec![ok_response(&geosite_fixture(), "")]).await;
        let spec = AssetSpec::new("geosite.dat", AssetKind::Geosite, vec![url]).with_sha256(digest);
        assert!(store.refresh(&spec, true).await.changed());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_conditional_revalidation_costs_no_download() {
        let dir = temp_dir("conditional");
        let (url, hits) = serve(vec![
            ok_response(&geosite_fixture(), "ETag: \"v1\"\r\n"),
            b"HTTP/1.1 304 Not Modified\r\n\r\n".to_vec(),
        ])
        .await;
        let store = AssetStore::new(&dir, AssetPolicy::default());
        let spec = AssetSpec::new("geosite.dat", AssetKind::Geosite, vec![url]);
        assert!(store.refresh(&spec, false).await.changed());
        assert_eq!(store.refresh(&spec, true).await, RefreshOutcome::Unchanged);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pre_existing_corrupt_cache_is_quarantined_instead_of_loaded() {
        let dir = temp_dir("quarantine");
        let store = AssetStore::new(&dir, AssetPolicy::default());
        let spec = AssetSpec::new("geosite.dat", AssetKind::Geosite, vec![]);
        // Exactly what a half-finished download leaves behind.
        std::fs::write(dir.join("geosite.dat"), &geosite_fixture()[..8]).unwrap();

        assert!(store.load(&spec).is_err());
        assert!(!dir.join("geosite.dat").exists());
        assert!(dir.join("geosite.dat.rejected").exists());
        assert!(dir.join("geosite.dat.rejected.reason").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loading_merges_every_valid_spec_and_names_the_rest() {
        let dir = temp_dir("merge");
        std::fs::write(dir.join("geosite.dat"), geosite_fixture()).unwrap();
        std::fs::write(dir.join("geoip.dat"), geoip_fixture()).unwrap();
        let store = AssetStore::new(&dir, AssetPolicy::default());
        let specs = vec![
            AssetSpec::new("geosite.dat", AssetKind::Geosite, vec![]),
            AssetSpec::new("geoip.dat", AssetKind::Geoip, vec![]),
            AssetSpec::new("absent.dat", AssetKind::Geoip, vec![]),
        ];
        let (data, problems) = store.load_geodata(&specs);
        assert!(data.geosite.contains_key("ir"));
        assert!(data.geoip.contains_key("ir"));
        assert_eq!(problems.len(), 1);
        assert!(problems[0].starts_with("absent.dat"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_install_is_atomic_and_never_exposes_a_partial_file() {
        let dir = temp_dir("atomic");
        let path = dir.join("asset.bin");
        install_atomically(&path, b"first").unwrap();
        install_atomically(&path, b"second-and-longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second-and-longer");
        // No temporary files survive a successful install.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sha256_pins_round_trip() {
        let digest: [u8; 32] = Sha256::digest(b"zray").into();
        assert_eq!(parse_sha256(&hex_lower(&digest)).unwrap(), digest);
        assert!(parse_sha256("short").is_err());
        assert!(parse_sha256(&"z".repeat(64)).is_err());
    }
}
