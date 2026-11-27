//! XHTTP request-shaping settings (`xhttpSettings` and its `extra`).
//!
//! Parsed and normalised the way Xray's `SplitHTTPConfig.Build` does, so a
//! setting Xray rejects is rejected here, and an omitted one gets Xray's
//! default. Share links carry the same object, URL-encoded, in `extra`.

use serde_json::{Map, Value};

use crate::model::XhttpMode;

/// Normalised XHTTP settings. Placement and method names are kept as Xray
/// spells them (`queryInHeader`, `tokenish`, ...), already validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpSettings {
    pub x_padding_bytes: (u32, u32),
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: Box<str>,
    pub x_padding_header: Box<str>,
    pub x_padding_placement: Box<str>,
    pub x_padding_method: Box<str>,
    pub uplink_http_method: Box<str>,
    pub session_placement: Box<str>,
    pub session_key: Box<str>,
    pub session_id_table: Box<str>,
    pub session_id_length: (u32, u32),
    pub seq_placement: Box<str>,
    pub seq_key: Box<str>,
    pub uplink_data_placement: Box<str>,
    pub uplink_data_key: Box<str>,
    /// `(0, 0)` means Xray's per-placement default.
    pub uplink_chunk_size: (u32, u32),
    pub no_grpc_header: bool,
    pub no_sse_header: bool,
    pub sc_max_each_post_bytes: (u32, u32),
    pub sc_min_posts_interval_ms: (u32, u32),
    pub xmux: XmuxConfig,
}

impl Default for XhttpSettings {
    fn default() -> Self {
        Self {
            x_padding_bytes: (100, 1000),
            x_padding_obfs_mode: false,
            x_padding_key: "x_padding".into(),
            x_padding_header: "X-Padding".into(),
            x_padding_placement: "queryInHeader".into(),
            x_padding_method: "repeat-x".into(),
            uplink_http_method: "POST".into(),
            session_placement: "path".into(),
            session_key: "".into(),
            session_id_table: "".into(),
            session_id_length: (0, 0),
            seq_placement: "path".into(),
            seq_key: "".into(),
            uplink_data_placement: "auto".into(),
            uplink_data_key: "X-Data".into(),
            uplink_chunk_size: (0, 0),
            no_grpc_header: false,
            no_sse_header: false,
            sc_max_each_post_bytes: (1_000_000, 1_000_000),
            sc_min_posts_interval_ms: (30, 30),
            xmux: XmuxConfig::DEFAULTS,
        }
    }
}

/// XHTTP's connection-reuse controls: `extra.xmux`.
///
/// Xray rotates its connections on purpose, and for two reasons that both
/// matter here.
///
/// The first is reliability. A reverse proxy caps a reused connection —
/// Nginx allows about 1000 requests on one connection and retires it after
/// about an hour — so a connection held past that is cut by something the
/// client cannot see, which arrives as a stalled session rather than an
/// error. A middlebox that expires flows kills it too.
///
/// The second is that a connection which never rotates is a fingerprint.
/// Xray draws these limits as ranges, so two connections from one client
/// roll over at different moments and the start times never line up.
///
/// `(0, 0)` and `0` mean "no limit" for every field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmuxConfig {
    /// Proxied requests one connection may carry at once. When a connection
    /// reaches this the next request opens a new connection. The alternative
    /// to [`Self::max_connections`], which caps how many are open instead;
    /// the two cannot both be set.
    pub max_concurrency: (u32, u32),
    /// Connections open at once. While below this, every new proxied request
    /// opens a new connection; from here on connections are reused.
    pub max_connections: (u32, u32),
    /// How many times one connection may be handed out.
    pub c_max_reuse_times: (u32, u32),
    /// HTTP requests one connection may serve before it stops taking more.
    pub h_max_request_times: (u32, u32),
    /// Seconds one connection may be reused for.
    pub h_max_reusable_secs: (u32, u32),
    /// Seconds between keepalive PINGs on HTTP/2 or HTTP/3. Negative turns
    /// them off, zero means the browser's own (45 s for HTTP/2, 10 s for
    /// HTTP/3). The one field that takes no range.
    pub h_keep_alive_period: i32,
}

impl XmuxConfig {
    /// What a config that leaves every field at zero gets, which is Xray's
    /// rule: an `xmux` that is absent, empty or all zeros is the same thing.
    pub const DEFAULTS: Self = Self {
        max_concurrency: (0, 0),
        max_connections: (3, 3),
        c_max_reuse_times: (0, 0),
        h_max_request_times: (600, 900),
        h_max_reusable_secs: (1800, 3000),
        h_keep_alive_period: 0,
    };

    /// No reuse at all: every proxied request gets a connection of its own,
    /// handed out once, with no keepalive PINGs. Not something Xray can
    /// spell in one word; the app's switch for "do not reuse" writes this.
    pub const OFF: Self = Self {
        max_concurrency: (0, 0),
        max_connections: (0, 0),
        c_max_reuse_times: (0, 0),
        h_max_request_times: (1, 1),
        h_max_reusable_secs: (0, 0),
        h_keep_alive_period: -1,
    };

    /// Every field at zero: nothing limits anything.
    pub const NONE: Self = Self {
        max_concurrency: (0, 0),
        max_connections: (0, 0),
        c_max_reuse_times: (0, 0),
        h_max_request_times: (0, 0),
        h_max_reusable_secs: (0, 0),
        h_keep_alive_period: 0,
    };
}

impl XmuxConfig {
    /// Whether a connection may ever carry a second proxied request. False
    /// when it may serve only one HTTP request, which is no reuse at all and
    /// needs no pool. (`cMaxReuseTimes` of one still allows a second use:
    /// Xray does not count the first.)
    pub fn reuses(&self) -> bool {
        self.h_max_request_times != (1, 1)
    }

    /// The `xmux` overlay on a link outbound: `false` for no reuse, `true`
    /// for what the link says (or Xray's defaults), an object for those
    /// settings instead. A link cannot say how this network wants its
    /// connections reused, so the app lays it on, as it does `evasion`.
    pub fn overlay(&self, value: &Value) -> Result<Self, String> {
        match value {
            Value::Bool(false) => Ok(Self::OFF),
            Value::Bool(true) => Ok(*self),
            Value::Object(object) => parse_xmux(object),
            _ => Err("xmux must be true, false or an object".into()),
        }
    }
}

impl Default for XmuxConfig {
    fn default() -> Self {
        Self::DEFAULTS
    }
}

/// Parse `extra.xmux` the way Xray does.
///
/// Every field starts at zero and takes what the object names. A result that
/// is still all zeros (an empty object, or one that names only zeros) takes
/// [`XmuxConfig::DEFAULTS`]; anything else is used as written, so a config
/// that names one field gets no limits on the others. `maxConnections` and
/// `maxConcurrency` cannot both be above zero.
///
/// ```text
/// {}                         -> DEFAULTS (3 connections, rotated)
/// {"maxConcurrency": "4-8"}  -> 4 to 8 requests per connection, nothing else
/// ```
fn parse_xmux(o: &Map<String, Value>) -> Result<XmuxConfig, String> {
    let mut x = XmuxConfig::NONE;
    let ranges = [
        (
            "maxConcurrency",
            "xmux.maxConcurrency",
            &mut x.max_concurrency,
        ),
        (
            "maxConnections",
            "xmux.maxConnections",
            &mut x.max_connections,
        ),
        (
            "cMaxReuseTimes",
            "xmux.cMaxReuseTimes",
            &mut x.c_max_reuse_times,
        ),
        (
            "hMaxRequestTimes",
            "xmux.hMaxRequestTimes",
            &mut x.h_max_request_times,
        ),
        (
            "hMaxReusableSecs",
            "xmux.hMaxReusableSecs",
            &mut x.h_max_reusable_secs,
        ),
    ];
    for (key, name, field) in ranges {
        if let Some(v) = o.get(key) {
            *field = range(v, name)?;
        }
    }
    if let Some(v) = o.get("hKeepAlivePeriod") {
        let n = v.as_i64().ok_or("xmux.hKeepAlivePeriod must be a number")?;
        x.h_keep_alive_period = n.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
    }
    if x.max_connections.1 > 0 && x.max_concurrency.1 > 0 {
        return Err("xmux.maxConnections cannot be set together with xmux.maxConcurrency".into());
    }
    Ok(if x == XmuxConfig::NONE {
        XmuxConfig::DEFAULTS
    } else {
        x
    })
}

/// Xray's `Int32Range`: a number, a `"from-to"` string, or `{from, to}`.
/// Negative values are clamped to zero (no XHTTP range means anything below).
fn range(v: &Value, name: &str) -> Result<(u32, u32), String> {
    let clamp = |n: i64| n.clamp(0, i64::from(u32::MAX)) as u32;
    let (a, b) = match v {
        Value::Number(n) => {
            let n = n
                .as_i64()
                .ok_or_else(|| format!("{name} must be an integer"))?;
            (n, n)
        }
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                (0, 0)
            } else if let Ok(n) = s.parse::<i64>() {
                (n, n)
            } else {
                // "-114-514" style: split at the dash that ends the first number.
                let split = s[1..]
                    .find('-')
                    .map(|i| i + 1)
                    .ok_or_else(|| format!("{name}: invalid range {s:?}"))?;
                let a = s[..split].trim().parse::<i64>();
                let b = s[split + 1..].trim().parse::<i64>();
                match (a, b) {
                    (Ok(a), Ok(b)) => (a, b),
                    _ => return Err(format!("{name}: invalid range {s:?}")),
                }
            }
        }
        Value::Object(o) => {
            let get = |k: &str| o.get(k).and_then(Value::as_i64).unwrap_or(0);
            (get("from"), get("to"))
        }
        Value::Null => (0, 0),
        _ => return Err(format!("{name} must be a number or a \"from-to\" string")),
    };
    let (a, b) = (clamp(a), clamp(b));
    Ok((a.min(b), a.max(b)))
}

fn string<'a>(o: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(format!("xhttpSettings.{key} must be a string")),
    }
}

fn boolean(o: &Map<String, Value>, key: &str) -> Result<bool, String> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("xhttpSettings.{key} must be true or false")),
    }
}

fn opt_range(o: &Map<String, Value>, key: &str) -> Result<(u32, u32), String> {
    match o.get(key) {
        None => Ok((0, 0)),
        Some(v) => range(v, &format!("xhttpSettings.{key}")),
    }
}

/// Xray's `SplitHTTPConfig.Build` for the settings object that applies
/// (the `extra` object when there is one). `mode` is already resolved from
/// the outer object, as in Xray.
pub fn parse_settings(o: &Map<String, Value>, mode: XhttpMode) -> Result<XhttpSettings, String> {
    let defaults = XhttpSettings::default();
    let mut s = XhttpSettings::default();

    let padding = opt_range(o, "xPaddingBytes")?;
    if padding != (0, 0) {
        if padding.0 == 0 {
            return Err("xhttpSettings.xPaddingBytes cannot be disabled".into());
        }
        s.x_padding_bytes = padding;
    }
    s.x_padding_obfs_mode = boolean(o, "xPaddingObfsMode")?;
    for (key, slot) in [
        ("xPaddingKey", &mut s.x_padding_key),
        ("xPaddingHeader", &mut s.x_padding_header),
    ] {
        let value = string(o, key)?;
        if !value.is_empty() {
            *slot = value.into();
        }
    }
    match string(o, "xPaddingPlacement")? {
        "" => {}
        p @ ("cookie" | "header" | "query" | "queryInHeader") => s.x_padding_placement = p.into(),
        p => return Err(format!("unsupported XHTTP padding placement {p:?}")),
    }
    match string(o, "xPaddingMethod")? {
        "" => {}
        m @ ("repeat-x" | "tokenish") => s.x_padding_method = m.into(),
        m => return Err(format!("unsupported XHTTP padding method {m:?}")),
    }

    let packet_up = mode == XhttpMode::PacketUp;
    match string(o, "uplinkDataPlacement")? {
        "" => {}
        p @ ("auto" | "body") => s.uplink_data_placement = p.into(),
        p @ ("cookie" | "header") => {
            if !packet_up {
                return Err(format!(
                    "XHTTP uplinkDataPlacement {p:?} is only allowed in packet-up mode"
                ));
            }
            s.uplink_data_placement = p.into();
        }
        p => return Err(format!("unsupported XHTTP uplink data placement {p:?}")),
    }
    let method = string(o, "uplinkHTTPMethod")?.to_ascii_uppercase();
    if !method.is_empty() {
        if method == "GET" && !packet_up {
            return Err("XHTTP uplinkHTTPMethod GET is only allowed in packet-up mode".into());
        }
        if !method.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(format!("invalid XHTTP uplinkHTTPMethod {method:?}"));
        }
        s.uplink_http_method = method.into();
    }

    for (key, slot) in [
        ("sessionIDPlacement", &mut s.session_placement),
        ("seqPlacement", &mut s.seq_placement),
    ] {
        match string(o, key)? {
            "" => {}
            p @ ("path" | "cookie" | "header" | "query") => *slot = p.into(),
            p => return Err(format!("unsupported XHTTP {key} {p:?}")),
        }
    }
    s.session_key = string(o, "sessionIDKey")?.into();
    s.seq_key = string(o, "seqKey")?.into();
    if s.session_key.is_empty() {
        s.session_key = match &*s.session_placement {
            "cookie" | "query" => "x_session".into(),
            "header" => "X-Session".into(),
            _ => "".into(),
        };
    }
    if s.seq_key.is_empty() {
        s.seq_key = match &*s.seq_placement {
            "cookie" | "query" => "x_seq".into(),
            "header" => "X-Seq".into(),
            _ => "".into(),
        };
    }

    let table = string(o, "sessionIDTable")?;
    s.session_id_length = opt_range(o, "sessionIDLength")?;
    if !table.is_empty() {
        let alphabet = predefined_len(table).unwrap_or(table.len());
        if !table.is_ascii() {
            return Err("XHTTP sessionIDTable must contain only ASCII characters".into());
        }
        if s.session_id_length.0 == 0 {
            return Err("XHTTP sessionIDLength.from must be greater than 0".into());
        }
        // Xray requires at least 2^31 possible IDs.
        let room: f64 = (s.session_id_length.0..=s.session_id_length.1)
            .map(|k| (alphabet as f64).powi(k as i32))
            .sum();
        if room < f64::from(2u32 << 30) {
            return Err("XHTTP sessionIDTable or sessionIDLength is too small".into());
        }
        s.session_id_table = table.into();
    }

    let data_key = string(o, "uplinkDataKey")?;
    s.uplink_data_key = if !data_key.is_empty() {
        data_key.into()
    } else if &*s.uplink_data_placement == "cookie" {
        "x_data".into()
    } else {
        defaults.uplink_data_key.clone()
    };
    s.uplink_chunk_size = opt_range(o, "uplinkChunkSize")?;
    s.no_grpc_header = boolean(o, "noGRPCHeader")?;
    s.no_sse_header = boolean(o, "noSSEHeader")?;
    let post = opt_range(o, "scMaxEachPostBytes")?;
    if post.1 > 0 {
        if post.0 == 0 {
            return Err("XHTTP scMaxEachPostBytes must be bigger than 0".into());
        }
        s.sc_max_each_post_bytes = post;
    }
    let interval = opt_range(o, "scMinPostsIntervalMs")?;
    if interval.1 > 0 {
        s.sc_min_posts_interval_ms = interval;
    }
    if let Some(xmux) = o.get("xmux") {
        let object = xmux
            .as_object()
            .ok_or("xhttpSettings.xmux must be an object")?;
        s.xmux = parse_xmux(object)?;
    }
    Ok(s)
}

fn predefined_len(name: &str) -> Option<usize> {
    Some(match name {
        "ALPHABET" | "alphabet" => 26,
        "Alphabet" => 52,
        "BASE36" | "base36" => 36,
        "Base62" => 62,
        "HEX" | "hex" => 16,
        "number" => 10,
        _ => return None,
    })
}

/// The settings object Xray builds from: `extra` replaces everything but
/// host, path and mode when present.
pub fn effective_object(settings: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    match settings.get("extra") {
        None | Some(Value::Null) => Ok(settings.clone()),
        Some(Value::Object(extra)) => Ok(extra.clone()),
        Some(Value::String(text)) => match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(extra)) => Ok(extra),
            _ => Err("XHTTP extra is not a JSON object".into()),
        },
        Some(_) => Err("XHTTP extra must be a JSON object".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str, mode: XhttpMode) -> Result<XhttpSettings, String> {
        let v: Value = serde_json::from_str(json).unwrap();
        parse_settings(v.as_object().unwrap(), mode)
    }

    #[test]
    fn the_field_links_extra_parses() {
        let s = parse(
            r#"{"mode":"auto","xPaddingBytes":"1-1","xPaddingObfsMode":true,"xPaddingKey":"ctx",
                "xPaddingHeader":"x-grpc-context","xPaddingMethod":"tokenish",
                "sessionIDPlacement":"header","sessionIDKey":"Idempotency-Key",
                "seqPlacement":"header","seqKey":"Upload-Offset",
                "sessionPlacement":"header","sessionKey":"Idempotency-Key"}"#,
            XhttpMode::PacketUp,
        )
        .unwrap();
        assert_eq!(s.x_padding_bytes, (1, 1));
        assert!(s.x_padding_obfs_mode);
        assert_eq!(&*s.x_padding_header, "x-grpc-context");
        assert_eq!(&*s.x_padding_method, "tokenish");
        assert_eq!(&*s.x_padding_placement, "queryInHeader");
        assert_eq!(
            (&*s.session_placement, &*s.session_key),
            ("header", "Idempotency-Key")
        );
        assert_eq!(
            (&*s.seq_placement, &*s.seq_key),
            ("header", "Upload-Offset")
        );
    }

    /// Xray's rule: absent, empty and all-zero `xmux` are the defaults; one
    /// named field takes away the defaults of the others.
    #[test]
    fn xmux_follows_xray_defaults() {
        let m = XhttpMode::StreamOne;
        assert_eq!(parse("{}", m).unwrap().xmux, XmuxConfig::DEFAULTS);
        assert_eq!(
            parse(r#"{"xmux":{}}"#, m).unwrap().xmux,
            XmuxConfig::DEFAULTS
        );
        assert_eq!(
            parse(r#"{"xmux":{"maxConnections":0}}"#, m).unwrap().xmux,
            XmuxConfig::DEFAULTS
        );
        let x = parse(r#"{"xmux":{"maxConcurrency":"4-8"}}"#, m)
            .unwrap()
            .xmux;
        assert_eq!(x.max_concurrency, (4, 8));
        assert_eq!(x.max_connections, (0, 0));
        assert_eq!(x.h_max_request_times, (0, 0));
        let x = parse(r#"{"xmux":{"hKeepAlivePeriod":-1}}"#, m)
            .unwrap()
            .xmux;
        assert_eq!(x.h_keep_alive_period, -1);
        assert_eq!(x.max_connections, (0, 0));
        // Zero on one side of the pair is not "set".
        assert!(parse(r#"{"xmux":{"maxConcurrency":8,"maxConnections":0}}"#, m).is_ok());
        assert!(parse(r#"{"xmux":{"maxConcurrency":8,"maxConnections":2}}"#, m).is_err());
        assert!(parse(r#"{"xmux":5}"#, m).is_err());
        assert!(parse(r#"{"xmux":{"hKeepAlivePeriod":"x"}}"#, m).is_err());
    }

    #[test]
    fn the_xmux_overlay_switches_reuse_off_and_on() {
        let own = XmuxConfig {
            max_concurrency: (2, 4),
            ..XmuxConfig::NONE
        };
        assert_eq!(own.overlay(&Value::Bool(false)).unwrap(), XmuxConfig::OFF);
        assert!(!XmuxConfig::OFF.reuses());
        assert_eq!(own.overlay(&Value::Bool(true)).unwrap(), own);
        assert!(own.reuses() && XmuxConfig::DEFAULTS.reuses());
        let custom: Value = serde_json::from_str(r#"{"maxConnections": 2}"#).unwrap();
        assert_eq!(own.overlay(&custom).unwrap().max_connections, (2, 2));
        assert!(own.overlay(&Value::from(3)).is_err());
    }

    #[test]
    fn defaults_and_ranges() {
        let s = parse("{}", XhttpMode::StreamOne).unwrap();
        assert_eq!(s, XhttpSettings::default());
        let s = parse(
            r#"{"xPaddingBytes":{"from":20,"to":10},"scMaxEachPostBytes":500000}"#,
            XhttpMode::PacketUp,
        )
        .unwrap();
        assert_eq!(s.x_padding_bytes, (10, 20));
        assert_eq!(s.sc_max_each_post_bytes, (500000, 500000));
        let s = parse(r#"{"xPaddingBytes":"300"}"#, XhttpMode::PacketUp).unwrap();
        assert_eq!(s.x_padding_bytes, (300, 300));
    }

    #[test]
    fn rejects_what_xray_rejects() {
        assert!(parse(r#"{"xPaddingPlacement":"body"}"#, XhttpMode::PacketUp).is_err());
        assert!(parse(r#"{"uplinkDataPlacement":"header"}"#, XhttpMode::StreamOne).is_err());
        assert!(parse(r#"{"uplinkHTTPMethod":"get"}"#, XhttpMode::StreamUp).is_err());
        assert!(parse(
            r#"{"sessionIDTable":"hex","sessionIDLength":4}"#,
            XhttpMode::PacketUp
        )
        .is_err());
        assert!(parse(
            r#"{"sessionIDTable":"hex","sessionIDLength":8}"#,
            XhttpMode::PacketUp
        )
        .is_ok());
        assert!(parse(r#"{"xPaddingBytes":"0-10"}"#, XhttpMode::PacketUp).is_err());
    }

    #[test]
    fn extra_replaces_the_settings_object() {
        let outer: Value = serde_json::from_str(
            r#"{"path":"/p","extra":"{\"xPaddingBytes\":\"5-9\",\"headers\":{\"A\":\"b\"}}"}"#,
        )
        .unwrap();
        let effective = effective_object(outer.as_object().unwrap()).unwrap();
        assert!(effective.get("path").is_none());
        assert_eq!(effective["headers"]["A"], "b");
    }
}
