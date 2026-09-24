//! XHTTP request shaping, as Xray 26 builds it.
//!
//! Every XHTTP request carries padding the server validates (a request
//! without it is answered `400`), and the session ID, sequence number and
//! packet data can each be moved between the path, the query, a header or a
//! cookie. [`XhttpOptions`] holds those settings with Xray's defaults, and
//! [`build_request`] produces the method, target and headers for one request.
//!
//! Mirrors Xray-core `transport/internet/splithttp` (`config.go`
//! `FillStreamRequest`/`FillPacketRequest`/`ApplyMetaToRequest`,
//! `xpadding.go`) and `common/utils/browser.go` for the browser headers.

use std::sync::OnceLock;

use base64::Engine;
use rand::Rng;

/// Where a value travels in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Path,
    Query,
    Header,
    Cookie,
    /// A header whose value is a URL carrying the value as a query parameter
    /// (the default for padding: `Referer: https://host/path?x_padding=XXX`).
    QueryInHeader,
    Body,
    /// Packet data: the server accepts header, cookie and body at once; the
    /// client sends the body.
    Auto,
}

impl Placement {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "path" => Self::Path,
            "query" => Self::Query,
            "header" => Self::Header,
            "cookie" => Self::Cookie,
            "queryInHeader" => Self::QueryInHeader,
            "body" => Self::Body,
            "auto" => Self::Auto,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaddingMethod {
    /// A run of `X`: HPACK/QPACK give `X` an 8-bit code, so the padding
    /// keeps its length on the wire.
    #[default]
    RepeatX,
    /// Random base62 sized by its HPACK Huffman length.
    Tokenish,
}

/// An inclusive random range, Xray's `RangeConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub from: u32,
    pub to: u32,
}

impl Range {
    pub const fn fixed(value: u32) -> Self {
        Self {
            from: value,
            to: value,
        }
    }

    /// Xray's `crypto.RandBetween`: uniform in `[from, to)`, or `from` when
    /// the range is empty or one wide.
    pub fn sample(&self) -> u32 {
        let (from, to) = (self.from.min(self.to), self.from.max(self.to));
        if to - from <= 1 {
            return from;
        }
        rand::thread_rng().gen_range(from..to)
    }
}

/// XHTTP settings beyond host, path and headers, normalised to Xray's
/// defaults (`SplitHTTPConfig.Build` plus the `GetNormalized*` getters).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpOptions {
    pub x_padding_bytes: Range,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_placement: Placement,
    pub x_padding_method: PaddingMethod,
    pub uplink_http_method: String,
    pub session_placement: Placement,
    pub session_key: String,
    /// Alphabet and length for session IDs; empty means a UUID.
    pub session_id_table: String,
    pub session_id_length: Range,
    pub seq_placement: Placement,
    pub seq_key: String,
    pub uplink_data_placement: Placement,
    pub uplink_data_key: String,
    /// Base64 characters per header or cookie when packet data is carried
    /// outside the body; `None` uses Xray's per-placement default.
    pub uplink_chunk_size: Option<Range>,
    pub no_grpc_header: bool,
    pub no_sse_header: bool,
    pub sc_max_each_post_bytes: Range,
    pub sc_min_posts_interval_ms: Range,
}

impl Default for XhttpOptions {
    fn default() -> Self {
        Self {
            x_padding_bytes: Range {
                from: 100,
                to: 1000,
            },
            x_padding_obfs_mode: false,
            x_padding_key: "x_padding".into(),
            x_padding_header: "X-Padding".into(),
            x_padding_placement: Placement::QueryInHeader,
            x_padding_method: PaddingMethod::RepeatX,
            uplink_http_method: "POST".into(),
            session_placement: Placement::Path,
            session_key: String::new(),
            session_id_table: String::new(),
            session_id_length: Range::fixed(0),
            seq_placement: Placement::Path,
            seq_key: String::new(),
            uplink_data_placement: Placement::Auto,
            uplink_data_key: "X-Data".into(),
            uplink_chunk_size: None,
            no_grpc_header: false,
            no_sse_header: false,
            sc_max_each_post_bytes: Range::fixed(1_000_000),
            sc_min_posts_interval_ms: Range::fixed(30),
        }
    }
}

impl XhttpOptions {
    /// Xray's `GetNormalizedPath`: a leading `/`, and a trailing one when the
    /// session ID or sequence number is appended to the path.
    pub fn normalized_path(&self, configured: &str) -> String {
        let path = configured.split('?').next().unwrap_or("");
        let mut path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        if (self.session_placement == Placement::Path || self.seq_placement == Placement::Path)
            && !path.ends_with('/')
        {
            path.push('/');
        }
        path
    }

    /// Xray's `GenerateSessionID`.
    pub fn new_session_id(&self) -> String {
        let table = predefined_table(&self.session_id_table).unwrap_or(&self.session_id_table);
        let length = self.session_id_length.sample() as usize;
        if !table.is_empty() && length > 0 {
            let table = table.as_bytes();
            let mut rng = rand::thread_rng();
            return (0..length)
                .map(|_| table[rng.gen_range(0..table.len())] as char)
                .collect();
        }
        uuid_v4()
    }

    /// Xray's `GetNormalizedUplinkChunkSize`.
    fn uplink_chunk_size(&self) -> Range {
        match self.uplink_chunk_size {
            Some(range) if range.to > 0 => {
                if range.from < 64 {
                    Range {
                        from: 64,
                        to: range.to.max(64),
                    }
                } else {
                    range
                }
            }
            _ => match self.uplink_data_placement {
                Placement::Cookie => Range {
                    from: 2 * 1024,
                    to: 3 * 1024,
                },
                Placement::Header => Range {
                    from: 3000,
                    to: 4000,
                },
                _ => self.sc_max_each_post_bytes,
            },
        }
    }

    /// Whether packet data goes in the request body.
    pub fn packet_data_in_body(&self) -> bool {
        matches!(
            self.uplink_data_placement,
            Placement::Body | Placement::Auto
        )
    }
}

/// Xray's `PredefinedTable`.
pub fn predefined_table(name: &str) -> Option<&'static str> {
    Some(match name {
        "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "HEX" => "0123456789ABCDEF",
        "alphabet" => "abcdefghijklmnopqrstuvwxyz",
        "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
        "hex" => "0123456789abcdef",
        "number" => "0123456789",
        _ => return None,
    })
}

fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

// ------------------------------------------------------------------ padding

/// HPACK Huffman code lengths in bits for ASCII (RFC 7541 Appendix B).
const HUFFMAN_BITS: [u8; 128] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
];

/// `hpack.HuffmanEncodeLength` for ASCII text.
pub fn huffman_len(text: &str) -> usize {
    let bits: usize = text
        .bytes()
        .map(|b| usize::from(HUFFMAN_BITS[usize::from(b & 0x7f)]))
        .sum();
    bits.div_ceil(8)
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// Xray's `validationTolerance`.
const TOKENISH_TOLERANCE: usize = 2;

/// Xray's `GenerateTokenishPaddingBase62`.
fn tokenish(target: usize) -> String {
    let n = ((target as f64) / 0.8).ceil().max(1.0) as usize;
    let mut rng = rand::thread_rng();
    let mut value: String = (0..n)
        .map(|_| BASE62[rng.gen_range(0..BASE62.len())] as char)
        .collect();
    let mut adjust = 'X';
    for _ in 0..150 {
        let length = huffman_len(&value);
        if length.abs_diff(target) <= TOKENISH_TOLERANCE {
            break;
        }
        if length < target {
            value.push(adjust);
            adjust = if adjust == 'X' { 'Z' } else { 'X' };
        } else {
            if value.len() <= 1 {
                break;
            }
            value.pop();
        }
    }
    value
}

/// Xray's `GeneratePadding`.
pub fn padding(method: PaddingMethod, length: usize) -> String {
    if length == 0 {
        return String::new();
    }
    match method {
        PaddingMethod::RepeatX => "X".repeat(length),
        PaddingMethod::Tokenish => tokenish(length),
    }
}

// ------------------------------------------------------------- browser look

/// Chrome's major version as Xray estimates it: 144 on 2026-01-13, one
/// release every 35 days, lagging by a random 35-140 days per process.
fn chrome_version() -> u32 {
    static VERSION: OnceLock<u32> = OnceLock::new();
    *VERSION.get_or_init(|| {
        let today = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() / 86_400) as i64;
        let start = 20_466; // 2026-01-13 in days since the epoch
        let r: f64 = rand::thread_rng().gen();
        let diff = today - start - 35 - (r * r * 105.0).floor() as i64;
        (144 + diff.div_euclid(35)).max(144) as u32
    })
}

/// `Sec-CH-UA` with Chromium's GREASE brand, as Xray builds it.
fn chrome_client_hints(version: u32) -> String {
    const GREASE: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
    const GREASE_VERSION: [&str; 3] = ["8", "99", "24"];
    const SHUFFLE3: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let seed = version as usize;
    let brands = [
        format!(
            "\"Not{}A{}Brand\";v=\"{}\"",
            GREASE[seed % GREASE.len()],
            GREASE[(seed + 1) % GREASE.len()],
            GREASE_VERSION[seed % GREASE_VERSION.len()]
        ),
        format!("\"Chromium\";v=\"{version}\""),
        format!("\"Google Chrome\";v=\"{version}\""),
    ];
    let order = SHUFFLE3[seed % SHUFFLE3.len()];
    let mut shuffled = vec![String::new(); 3];
    for (i, e) in order.iter().enumerate() {
        shuffled[*e] = brands[i].clone();
    }
    shuffled.join(", ")
}

/// Xray's `TryDefaultHeadersWith(header, "fetch")` for a browser the user
/// did not override: Chrome on Windows making a same-origin `fetch()`.
fn apply_fetch_headers(headers: &mut Headers) {
    let chosen = headers.get("User-Agent").map(str::to_owned);
    let browser = match chosen.as_deref() {
        None => "chrome",
        Some(ua @ ("chrome" | "firefox" | "safari" | "edge" | "curl" | "golang")) => ua,
        // A real User-Agent string from the config stays as it is.
        Some(_) => return,
    };
    let version = chrome_version();
    match browser {
        "chrome" | "edge" => {
            let ua = format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36"
            );
            headers.set("Sec-CH-UA", chrome_client_hints(version));
            headers.set("Sec-CH-UA-Mobile", "?0".into());
            headers.set("Sec-CH-UA-Platform", "\"Windows\"".into());
            headers.set("DNT", "1".into());
            headers.set(
                "User-Agent",
                if browser == "edge" {
                    format!("{ua}Edg/{version}.0.0.0")
                } else {
                    ua
                },
            );
            headers.set("Accept-Language", "en-US,en;q=0.9".into());
        }
        "firefox" => {
            headers.set(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"
                    .into(),
            );
            headers.set("DNT", "1".into());
            headers.set("Accept-Language", "en-US,en;q=0.5".into());
        }
        "safari" => {
            headers.set(
                "User-Agent",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15"
                    .into(),
            );
            headers.set("Accept-Language", "en-US,en;q=0.9".into());
        }
        "golang" => {
            headers.remove("User-Agent");
            return;
        }
        "curl" => {
            headers.set("User-Agent", "curl/8.16.0".into());
            return;
        }
        _ => unreachable!(),
    }
    headers.set("Sec-Fetch-Mode", "cors".into());
    headers.set("Sec-Fetch-Dest", "empty".into());
    headers.set("Sec-Fetch-Site", "same-origin".into());
    if headers.get("Priority").is_none() {
        let priority = match browser {
            "firefox" => "u=4",
            "safari" => "u=3, i",
            _ => "u=1, i",
        };
        headers.set("Priority", priority.into());
    }
    for (name, value) in [
        ("Cache-Control", "no-cache"),
        ("Pragma", "no-cache"),
        ("Accept", "*/*"),
    ] {
        if headers.get(name).is_none() {
            headers.set(name, value.into());
        }
    }
}

// ----------------------------------------------------------------- requests

/// An ordered, case-insensitive header list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(pub Vec<(String, String)>);

impl Headers {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn set(&mut self, name: &str, value: String) {
        if let Some(slot) = self
            .0
            .iter_mut()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
        {
            slot.1 = value;
        } else {
            self.0.push((name.to_string(), value));
        }
    }

    pub fn remove(&mut self, name: &str) {
        self.0.retain(|(key, _)| !key.eq_ignore_ascii_case(name));
    }

    /// Go's `Request.AddCookie`: cookies share one `Cookie` header.
    fn add_cookie(&mut self, name: &str, value: &str) {
        let pair = format!("{name}={}", cookie_value(value));
        match self
            .0
            .iter_mut()
            .find(|(key, _)| key.eq_ignore_ascii_case("cookie"))
        {
            Some(slot) => {
                slot.1.push_str("; ");
                slot.1.push_str(&pair);
            }
            None => self.0.push(("Cookie".into(), pair)),
        }
    }
}

/// Go's `sanitizeCookieValue`: quote values with a space or comma.
fn cookie_value(value: &str) -> String {
    let clean: String = value
        .chars()
        .filter(|c| (0x20..0x7f).contains(&(*c as u32)) && !matches!(c, '"' | ';' | '\\'))
        .collect();
    if clean.contains([' ', ',']) {
        format!("\"{clean}\"")
    } else {
        clean
    }
}

/// Which XHTTP request this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// One request carrying both directions.
    StreamOne,
    /// The long-lived upload of stream-up.
    StreamUp,
    /// The download GET of stream-up and packet-up.
    StreamDown,
    /// One packet-up upload.
    Packet(u64),
}

/// A request ready to serialise for HTTP/1.1, 2 or 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpRequest {
    pub method: String,
    /// Path and query, the HTTP/1.1 request target and HTTP/2 `:path`.
    pub target: String,
    pub headers: Headers,
    /// `false` when packet data travels in headers or cookies instead.
    pub body: bool,
}

/// A URL query kept as parsed pairs once anything is added, re-encoded
/// the way Go's `url.Values.Encode` does (sorted by key).
struct Query {
    raw: String,
    pairs: Option<Vec<(String, String)>>,
}

impl Query {
    fn new(raw: &str) -> Self {
        Self {
            raw: raw.to_string(),
            pairs: None,
        }
    }

    fn set(&mut self, key: &str, value: &str) {
        let pairs = self.pairs.get_or_insert_with(|| {
            url_form_decode(&self.raw)
                .into_iter()
                .filter(|(k, _)| !k.is_empty())
                .collect()
        });
        pairs.retain(|(k, _)| k != key);
        pairs.push((key.to_string(), value.to_string()));
    }

    fn encode(&self) -> String {
        match &self.pairs {
            None => self.raw.clone(),
            Some(pairs) => {
                let mut sorted = pairs.clone();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                sorted
                    .iter()
                    .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
                    .collect::<Vec<_>>()
                    .join("&")
            }
        }
    }
}

fn url_form_decode(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

fn percent_decode(text: &str) -> String {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(high), Some(low)) => {
                    out.push(high << 4 | low);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Go's `url.QueryEscape`.
fn query_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn append_to_path(path: &mut String, value: &str) {
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(value);
}

/// Build one XHTTP request (Xray's `FillStreamRequest` or
/// `FillPacketRequest` followed by the transport's own headers).
///
/// `scheme` and `host` form the URL that padding in a header refers to;
/// `path` is the configured path, query included. `payload` is the packet
/// data when it travels in headers or cookies.
#[allow(clippy::too_many_arguments)]
pub fn build_request(
    options: &XhttpOptions,
    scheme: &str,
    host: &str,
    path: &str,
    extra_headers: &[(String, String)],
    kind: RequestKind,
    session: Option<&str>,
    payload: Option<&[u8]>,
) -> XhttpRequest {
    let mut path_part = options.normalized_path(path);
    let mut query = Query::new(path.split_once('?').map_or("", |(_, q)| q));

    let mut headers = Headers::default();
    // Packet data in headers comes first, as Xray builds that header set
    // before the rest.
    let mut body = true;
    if let (RequestKind::Packet(_), Some(data), false) =
        (kind, payload, options.packet_data_in_body())
    {
        body = false;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
        let chunk = options.uplink_chunk_size();
        let mut rest = encoded.as_str();
        let mut i = 0;
        let mut cookies = Vec::new();
        while !rest.is_empty() {
            let size = (chunk.sample().max(1) as usize).min(rest.len());
            let (part, tail) = rest.split_at(size);
            rest = tail;
            match options.uplink_data_placement {
                Placement::Header => {
                    headers.set(&format!("{}-{i}", options.uplink_data_key), part.into())
                }
                _ => cookies.push((format!("{}_{i}", options.uplink_data_key), part.to_string())),
            }
            i += 1;
        }
        for (name, value) in &extra_headers_filtered(extra_headers) {
            headers.set(name, value.clone());
        }
        apply_fetch_headers(&mut headers);
        for (name, value) in cookies {
            headers.add_cookie(&name, &value);
        }
    } else {
        for (name, value) in &extra_headers_filtered(extra_headers) {
            headers.set(name, value.clone());
        }
        apply_fetch_headers(&mut headers);
    }

    // Padding, against the URL as it stands before the session and
    // sequence are added.
    let url = {
        let q = query.encode();
        if q.is_empty() {
            format!("{scheme}://{host}{path_part}")
        } else {
            format!("{scheme}://{host}{path_part}?{q}")
        }
    };
    let length = options.x_padding_bytes.sample() as usize;
    let (placement, key, header, method) = if options.x_padding_obfs_mode {
        (
            options.x_padding_placement,
            options.x_padding_key.as_str(),
            options.x_padding_header.as_str(),
            options.x_padding_method,
        )
    } else {
        (
            Placement::QueryInHeader,
            "x_padding",
            "Referer",
            PaddingMethod::RepeatX,
        )
    };
    let value = padding(method, length);
    match placement {
        Placement::Header => headers.set(header, value),
        Placement::QueryInHeader => {
            let base = url.split('?').next().unwrap_or(&url);
            headers.set(header, format!("{base}?{key}={value}"));
        }
        Placement::Cookie if !key.is_empty() && !value.is_empty() => {
            headers.add_cookie(key, &value)
        }
        Placement::Query if !key.is_empty() && !value.is_empty() => query.set(key, &value),
        _ => {}
    }

    // Session ID and sequence number.
    let seq = match kind {
        RequestKind::Packet(seq) => Some(seq.to_string()),
        _ => None,
    };
    for (value, placement, key) in [
        (
            session.filter(|s| !s.is_empty()).map(str::to_owned),
            options.session_placement,
            session_key(options),
        ),
        (seq, options.seq_placement, seq_key(options)),
    ] {
        let Some(value) = value else { continue };
        match placement {
            Placement::Path => append_to_path(&mut path_part, &value),
            Placement::Query => query.set(&key, &value),
            Placement::Header => headers.set(&key, value),
            Placement::Cookie => headers.add_cookie(&key, &value),
            _ => {}
        }
    }

    let method = match kind {
        RequestKind::StreamDown => "GET".to_string(),
        _ => options.uplink_http_method.clone(),
    };
    if matches!(kind, RequestKind::StreamOne | RequestKind::StreamUp) && !options.no_grpc_header {
        headers.set("Content-Type", "application/grpc".into());
    }
    let q = query.encode();
    let target = if q.is_empty() {
        path_part
    } else {
        format!("{path_part}?{q}")
    };
    XhttpRequest {
        method,
        target,
        headers,
        body,
    }
}

fn extra_headers_filtered(extra: &[(String, String)]) -> Vec<(String, String)> {
    extra
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.to_ascii_lowercase().as_str(),
                "host" | "connection" | "content-length" | "transfer-encoding"
            )
        })
        .cloned()
        .collect()
}

fn session_key(options: &XhttpOptions) -> String {
    if !options.session_key.is_empty() {
        return options.session_key.clone();
    }
    match options.session_placement {
        Placement::Header => "X-Session".into(),
        _ => "x_session".into(),
    }
}

fn seq_key(options: &XhttpOptions) -> String {
    if !options.seq_key.is_empty() {
        return options.seq_key.clone();
    }
    match options.seq_placement {
        Placement::Header => "X-Seq".into(),
        _ => "x_seq".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(options: &XhttpOptions, kind: RequestKind, session: Option<&str>) -> XhttpRequest {
        build_request(
            options,
            "https",
            "example.com",
            "/x",
            &[],
            kind,
            session,
            None,
        )
    }

    #[test]
    fn defaults_match_xray_path_and_referer_padding() {
        let options = XhttpOptions::default();
        let one = build(&options, RequestKind::StreamOne, None);
        assert_eq!(one.method, "POST");
        assert_eq!(one.target, "/x/");
        let referer = one.headers.get("Referer").unwrap();
        let padding = referer
            .strip_prefix("https://example.com/x/?x_padding=")
            .unwrap();
        assert!((100..1000).contains(&padding.len()) && padding.bytes().all(|b| b == b'X'));
        assert_eq!(one.headers.get("Content-Type"), Some("application/grpc"));
        assert!(one.headers.get("User-Agent").unwrap().contains("Chrome/"));

        let down = build(&options, RequestKind::StreamDown, Some("abc"));
        assert_eq!(
            (down.method.as_str(), down.target.as_str()),
            ("GET", "/x/abc")
        );
        assert_eq!(down.headers.get("Content-Type"), None);

        let packet = build(&options, RequestKind::Packet(7), Some("abc"));
        assert_eq!(packet.target, "/x/abc/7");
        // The Referer names the URL before the session was appended.
        assert!(packet
            .headers
            .get("Referer")
            .unwrap()
            .starts_with("https://example.com/x/?x_padding="));
    }

    #[test]
    fn obfuscated_header_placement_like_the_field_links() {
        // The shape of the `extra` in the 01 report's working links.
        let options = XhttpOptions {
            x_padding_bytes: Range::fixed(1),
            x_padding_obfs_mode: true,
            x_padding_key: "ctx".into(),
            x_padding_header: "x-grpc-context".into(),
            x_padding_method: PaddingMethod::Tokenish,
            session_placement: Placement::Header,
            session_key: "Idempotency-Key".into(),
            seq_placement: Placement::Header,
            seq_key: "Upload-Offset".into(),
            ..XhttpOptions::default()
        };
        let packet = build(&options, RequestKind::Packet(3), Some("sid"));
        // No path placement, so the path keeps no trailing slash.
        assert_eq!(packet.target, "/x");
        assert_eq!(packet.headers.get("Idempotency-Key"), Some("sid"));
        assert_eq!(packet.headers.get("Upload-Offset"), Some("3"));
        let context = packet.headers.get("x-grpc-context").unwrap();
        let token = context.strip_prefix("https://example.com/x?ctx=").unwrap();
        // Xray's check: Huffman length within the range, give or take 2.
        assert!(huffman_len(token) <= 3, "{token}");
    }

    #[test]
    fn query_and_cookie_placements() {
        let options = XhttpOptions {
            x_padding_obfs_mode: true,
            x_padding_placement: Placement::Cookie,
            session_placement: Placement::Query,
            seq_placement: Placement::Cookie,
            uplink_data_placement: Placement::Cookie,
            ..XhttpOptions::default()
        };
        let request = build_request(
            &options,
            "http",
            "h",
            "/p?a=1",
            &[],
            RequestKind::Packet(0),
            Some("s"),
            Some(b"hello"),
        );
        assert!(!request.body);
        assert_eq!(request.target, "/p?a=1&x_session=s");
        let cookie = request.headers.get("Cookie").unwrap();
        assert!(
            cookie.starts_with("X-Data_0=aGVsbG8; x_padding=X"),
            "{cookie}"
        );
        assert!(cookie.ends_with("; x_seq=0"), "{cookie}");
    }

    #[test]
    fn header_payload_chunks_decode_back() {
        let options = XhttpOptions {
            uplink_data_placement: Placement::Header,
            uplink_chunk_size: Some(Range::fixed(64)),
            ..XhttpOptions::default()
        };
        let data: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let request = build_request(
            &options,
            "https",
            "h",
            "/",
            &[],
            RequestKind::Packet(1),
            Some("s"),
            Some(&data),
        );
        let mut encoded = String::new();
        for i in 0.. {
            match request.headers.get(&format!("X-Data-{i}")) {
                Some(part) => encoded.push_str(part),
                None => break,
            }
        }
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn user_agent_names_select_a_browser_and_real_strings_are_kept() {
        let mut headers = Headers::default();
        headers.set("User-Agent", "firefox".into());
        apply_fetch_headers(&mut headers);
        assert!(headers.get("User-Agent").unwrap().contains("Firefox/"));
        assert_eq!(headers.get("Priority"), Some("u=4"));

        let mut headers = Headers::default();
        headers.set("User-Agent", "MyAgent/1".into());
        apply_fetch_headers(&mut headers);
        assert_eq!(headers.0, vec![("User-Agent".into(), "MyAgent/1".into())]);
    }

    #[test]
    fn huffman_lengths_follow_rfc_7541() {
        // "www.example.com" is 12 bytes in RFC 7541 C.4.1.
        assert_eq!(huffman_len("www.example.com"), 12);
        assert_eq!(huffman_len("no-cache"), 6);
    }

    #[test]
    fn session_ids_use_the_configured_table() {
        let options = XhttpOptions {
            session_id_table: "hex".into(),
            session_id_length: Range { from: 8, to: 9 },
            ..XhttpOptions::default()
        };
        let id = options.new_session_id();
        assert_eq!(id.len(), 8);
        assert!(id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(XhttpOptions::default().new_session_id().len(), 36);
    }
}
